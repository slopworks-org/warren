//! `warren run`: keep the tunnel matching the server's desired state.
//!
//! The loop blocks in a long-poll on the control channel (inside the tunnel),
//! so an idle agent wakes up roughly once per [`LONG_POLL_SECS`].

use crate::cli::Args;
use crate::error::{Error, Result};
use crate::state::{self, Saved};
use crate::up::{hostname, os_tag};
use crate::{http, log, selfupdate, stopping, tunnel};
use std::fmt::Write as _;
use std::time::{Duration, Instant};
use warren_proto::{AgentConfig, CONFIG_PATH, Kv, LONG_POLL_SECS};
use warren_wgctl as wg;

/// After this long without a handshake the server's address is re-resolved.
const STALE_HANDSHAKE: Duration = Duration::from_secs(180);
const MAX_BACKOFF: u64 = 60;
/// A long-poll that returns sooner than this was not held by the server
/// (e.g. a misbehaving proxy); pausing keeps the loop from spinning.
const MIN_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// A failed update to the same version is tried again after this long.
const UPDATE_RETRY: Duration = Duration::from_secs(3600);

/// Sleeps in one-second steps so a stop signal is noticed promptly.
fn sleep(secs: u64) {
    for _ in 0..secs {
        if stopping() {
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

enum Poll {
    Changed(AgentConfig),
    Unchanged,
}

fn poll(saved: &Saved, wait: u64) -> Result<Poll> {
    let path = format!(
        "{CONFIG_PATH}?v={}&wait={wait}&agent={}&os={}&hostname={}",
        saved.tunnel.version,
        warren_proto::VERSION,
        percent_encode(&os_tag()),
        percent_encode(&hostname()),
    );
    let control = &saved.tunnel.control;
    let resp = http::request(control, control, "GET", &path, None, Duration::from_secs(wait + 15))
        .map_err(Error::io(format!("polling {control}")))?;
    match resp.status {
        200 => {
            let kv = Kv::parse(&resp.body).map_err(|source| Error::Format { what: "config", source })?;
            let cfg = AgentConfig::from_kv(&kv).map_err(|source| Error::Format { what: "config", source })?;
            Ok(if cfg == saved.tunnel { Poll::Unchanged } else { Poll::Changed(cfg) })
        }
        204 | 304 => Ok(Poll::Unchanged),
        status => Err(Error::Server { status, message: resp.body.trim().chars().take(200).collect() }),
    }
}

struct Status {
    state: &'static str,
    last_contact: u64,
    last_error: String,
}

fn write_status(args: &Args, saved: &Saved, st: &Status) {
    let mut kv = Kv::new();
    kv.push("updated", log::now().to_string());
    kv.push("state", st.state);
    kv.push("last_contact", st.last_contact.to_string());
    kv.push("config_version", saved.tunnel.version.to_string());
    kv.push("pid", std::process::id().to_string());
    kv.push("last_error", &st.last_error);
    if let Err(e) = state::write_public(&args.paths.status(), kv.encode().as_bytes()) {
        log!(Debug, "cannot write status file", error = e);
    }
}

/// Applies a config pushed by the server and saves it only if it works, so
/// a bad config can never wedge the agent: the previous one stays in place
/// and the agent keeps polling for a fix.
fn apply_new_config(args: &Args, saved: &mut Saved, cfg: AgentConfig, key: &[u8; 32], st: &mut Status) {
    log!(Info, "config changed", version = cfg.version);
    let candidate = Saved { tunnel: cfg, ..saved.clone() };
    if let Err(e) = tunnel::apply(&candidate, key) {
        log!(Error, "rejected new config; keeping the previous one", error = e);
        st.last_error = format!("rejected new config: {e}");
        // Restore the previous state on the interface.
        if let Err(e) = tunnel::apply(saved, key) {
            log!(Error, "cannot restore the previous config", error = e);
        }
        return;
    }
    *saved = candidate;
    if let Err(e) = saved.store(&args.paths.config()) {
        // The tunnel already runs the new config; it is re-sent after a restart.
        log!(Error, "cannot save config", error = e);
        st.last_error = e.to_string();
    }
}

pub fn run(args: &Args) -> Result<()> {
    let mut saved = Saved::load(&args.paths.config())?;
    let key = state::load_key(&args.paths.key())?;
    log!(Info, "starting", version = warren_proto::VERSION, iface = saved.interface, device = saved.tunnel.name);

    let mut st = Status { state: "starting", last_contact: 0, last_error: String::new() };
    let mut applied = false;
    let mut backoff = 0;
    let mut last_refresh: Option<Instant> = None;
    let mut failed_update: Option<(String, Instant)> = None;
    // The first poll returns at once, so `warren status` shows the
    // connection right after start instead of after the first long-poll.
    let mut first = true;

    while !stopping() {
        // (Re)create the interface if it is missing, e.g. after `ifdown`.
        if !applied || wg::link_index(&saved.interface).is_none() {
            match tunnel::apply(&saved, &key) {
                Ok(()) => {
                    applied = true;
                    log!(Info, "tunnel configured", address = saved.tunnel.address);
                }
                Err(e) => {
                    log!(Error, "cannot configure tunnel", error = e);
                    st.state = "error";
                    st.last_error = e.to_string();
                    write_status(args, &saved, &st);
                    sleep(30);
                    continue;
                }
            }
        }

        let wait = if backoff == 0 && !first { LONG_POLL_SECS } else { 0 };
        first = false;
        let started = Instant::now();
        match poll(&saved, wait) {
            Ok(result) => {
                backoff = 0;
                st.state = "connected";
                st.last_contact = log::now();
                st.last_error.clear();
                if let Poll::Changed(cfg) = result {
                    apply_new_config(args, &mut saved, cfg, &key, &mut st);
                } else if wait > 0 && started.elapsed() < MIN_POLL_INTERVAL {
                    sleep(MIN_POLL_INTERVAL.as_secs());
                }
                let target = &saved.tunnel.update;
                let retry = failed_update.as_ref().is_none_or(|(v, at)| v != target || at.elapsed() > UPDATE_RETRY);
                if warren_proto::is_newer(target, warren_proto::VERSION) && retry {
                    log!(Info, "updating the agent", version = target);
                    let e = selfupdate::update(&saved.tunnel.control, target);
                    log!(Error, "cannot update the agent", error = e);
                    st.last_error = format!("cannot update to {target}: {e}");
                    failed_update = Some((target.clone(), Instant::now()));
                }
            }
            Err(_) if stopping() => break,
            Err(e) => {
                backoff = (backoff * 2).clamp(2, MAX_BACKOFF);
                st.state = "disconnected";
                st.last_error = e.to_string();
                log!(Warn, "control channel unavailable", error = e, retry_in = backoff);
            }
        }

        if let Ok(dev) = wg::get_device(&saved.interface) {
            let stale = tunnel::handshake_age(&dev).is_none_or(|age| age > STALE_HANDSHAKE);
            let due = last_refresh.is_none_or(|t| t.elapsed() > Duration::from_secs(60));
            if stale && due {
                last_refresh = Some(Instant::now());
                if let Err(e) = tunnel::refresh_endpoints(&saved, &dev) {
                    log!(Warn, "cannot refresh endpoints", error = e);
                }
            }
        }
        write_status(args, &saved, &st);
        sleep(backoff);
    }

    log!(Info, "stopping; removing interface", iface = saved.interface);
    if wg::link_index(&saved.interface).is_some() {
        wg::delete_link(&saved.interface)?;
    }
    let _ = std::fs::remove_file(args.paths.status());
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn percent_encoding() {
        assert_eq!(super::percent_encode("a b/ü"), "a%20b%2F%C3%BC");
        assert_eq!(super::percent_encode("linux-aarch64"), "linux-aarch64");
    }
}
