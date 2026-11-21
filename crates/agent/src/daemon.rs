//! `warren run`: keep the tunnel matching the server's desired state.
//!
//! The loop blocks in a long-poll on the control channel (inside the tunnel),
//! so an idle agent wakes up roughly once per [`LONG_POLL_SECS`].

use crate::cli::Args;
use crate::error::{Error, Result};
use crate::state::{self, Paths, Saved, StatusFile};
use crate::up::{hostname, os_tag};
use crate::update_service::{self, Installation};
use crate::{http, lan, log, selfupdate, stopping, tunnel};
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
const AUTO_CHECK_INTERVAL: Duration = Duration::from_hours(24);
const UPDATE_RETRY: Duration = Duration::from_hours(1);

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

/// Reports where devices on the same LAN can reach this one directly.
fn lan_query(saved: &Saved) -> String {
    let port = wg::get_device(&lan::interface(&saved.interface)).map_or(0, |d| d.listen_port);
    let addrs: Vec<String> = lan::addresses(&saved.interface).iter().map(ToString::to_string).collect();
    if port == 0 || addrs.is_empty() {
        return String::new();
    }
    format!("&lan={}&port={port}&mesh=2", percent_encode(&addrs.join(",")))
}

fn poll(saved: &Saved, wait: u64, generation: Option<&str>) -> Result<Poll> {
    let consent = generation.map_or_else(String::new, |g| format!("&update_generation={}", percent_encode(g)));
    let path = format!(
        "{CONFIG_PATH}?v={}&wait={wait}&agent={}&os={}&hostname={}&remote_updates={}{consent}{}",
        saved.tunnel.version,
        warren_proto::VERSION,
        percent_encode(&os_tag()),
        percent_encode(&hostname()),
        u8::from(generation.is_some()),
        lan_query(saved),
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

fn write_status(status: Option<&mut StatusFile>, saved: &Saved, st: &Status) {
    let Some(status) = status else { return };
    let mut kv = Kv::new();
    kv.push("updated", log::now().to_string());
    kv.push("state", st.state);
    kv.push("last_contact", st.last_contact.to_string());
    kv.push("config_version", saved.tunnel.version.to_string());
    kv.push("pid", std::process::id().to_string());
    kv.push("agent_version", warren_proto::VERSION);
    #[cfg(target_os = "macos")]
    kv.push("boot_id", status.boot_id());
    kv.push("last_error", &st.last_error);
    if let Err(e) = status.write_public(kv.encode().as_bytes()) {
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

struct UpdateSchedule {
    last_check: Option<(Instant, Duration)>,
    last_request: String,
}

impl UpdateSchedule {
    fn new(cooldown: Option<String>) -> Self {
        Self {
            last_check: cooldown.as_ref().map(|_| (Instant::now(), UPDATE_RETRY)),
            last_request: cooldown.unwrap_or_default(),
        }
    }

    fn due(&self, target: &str, now: Instant) -> bool {
        let requested = target != self.last_request && warren_proto::is_newer(target, warren_proto::VERSION);
        self.last_check
            .is_none_or(|(at, interval)| now.duration_since(at) >= if requested { UPDATE_RETRY } else { interval })
    }

    fn check(&mut self, install: &Installation, paths: &Paths, generation: &str, config: &AgentConfig) -> Result<()> {
        let target = update_hint(config, generation);
        if !self.due(target, Instant::now()) {
            return Ok(());
        }
        self.last_request = target.to_string();
        let result = selfupdate::auto_update(install, paths, generation);
        let interval = if result.is_ok() { AUTO_CHECK_INTERVAL } else { UPDATE_RETRY };
        self.last_check = Some((Instant::now(), interval));
        result
    }
}

fn update_hint<'a>(config: &'a AgentConfig, generation: &str) -> &'a str {
    if config.update_generation.as_deref() == Some(generation) { &config.update } else { "" }
}

pub fn run(args: &Args, install: Option<&Installation>, mut trial: bool, cooldown: Option<String>) -> Result<()> {
    let mut saved = Saved::load(&args.paths.config())?;
    let key = state::load_key(&args.paths.key())?;
    log!(Info, "starting", version = warren_proto::VERSION, iface = saved.interface, device = saved.tunnel.name);

    tunnel::remove_direct(&saved.interface)?;
    lan::spawn_watcher();
    let mut status = StatusFile::open(&args.paths.run_dir)
        .inspect_err(|e| log!(Debug, "cannot open the status directory", error = e))
        .ok();
    let mut st = Status { state: "starting", last_contact: 0, last_error: String::new() };
    let mut applied = false;
    let mut backoff = 0;
    let mut last_refresh: Option<Instant> = None;
    let mut updates = UpdateSchedule::new(cooldown);
    if !trial {
        write_status(status.as_mut(), &saved, &st);
    }
    // The first poll returns at once, so `warren status` shows the
    // connection right after start instead of after the first long-poll.
    let mut first = true;
    let mut trial_result = Ok(());

    while !stopping() {
        // (Re)create the interface if it is missing, e.g. after `ifdown`.
        if !applied
            || wg::link_index(&saved.interface).is_none()
            || wg::link_index(&lan::interface(&saved.interface)).is_none()
        {
            match tunnel::apply(&saved, &key) {
                Ok(()) => {
                    applied = true;
                    log!(Info, "tunnel configured", address = saved.tunnel.address);
                    if trial {
                        trial_result = update_service::acknowledge_ready();
                        if trial_result.is_err() {
                            break;
                        }
                        trial = false;
                    }
                }
                Err(e) => {
                    log!(Error, "cannot configure tunnel", error = e);
                    if trial {
                        return Err(e);
                    }
                    st.state = "error";
                    st.last_error = e.to_string();
                    write_status(status.as_mut(), &saved, &st);
                    sleep(30);
                    continue;
                }
            }
        }

        let wait = if backoff == 0 && !first { LONG_POLL_SECS } else { 0 };
        first = false;
        let started = Instant::now();
        let generation = install.and_then(|_| selfupdate::remote_generation(&args.paths));
        match poll(&saved, wait, generation.as_deref()) {
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
            }
            Err(_) if stopping() => break,
            Err(e) => {
                backoff = (backoff * 2).clamp(2, MAX_BACKOFF);
                st.state = "disconnected";
                st.last_error = e.to_string();
                log!(Warn, "control channel unavailable", error = e, retry_in = backoff);
            }
        }

        if let Some(install) = install
            && !stopping()
            && let Some(generation) = generation.as_deref()
            && let Err(e) = updates.check(install, &args.paths, generation, &saved.tunnel)
        {
            log!(Warn, "cannot update the agent", error = e);
            st.last_error = format!("cannot update the agent: {e}");
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
        write_status(status.as_mut(), &saved, &st);
        sleep(backoff);
    }

    log!(Info, "stopping; removing interface", iface = saved.interface);
    if wg::link_index(&saved.interface).is_some() {
        wg::delete_link(&saved.interface)?;
    }
    tunnel::remove_direct(&saved.interface).and(trial_result)
}

#[cfg(test)]
mod tests {
    #[test]
    fn dashboard_hints_require_the_current_consent_generation() {
        let mut config = super::AgentConfig { update: "9.0.0".into(), ..Default::default() };
        assert_eq!(super::update_hint(&config, "epoch:1"), "");
        config.update_generation = Some("epoch:1".into());
        assert_eq!(super::update_hint(&config, "epoch:1"), "9.0.0");
        assert_eq!(super::update_hint(&config, "epoch:3"), "");
    }

    #[test]
    fn percent_encoding() {
        assert_eq!(super::percent_encode("a b/ü"), "a%20b%2F%C3%BC");
        assert_eq!(super::percent_encode("linux-aarch64"), "linux-aarch64");
    }
    #[test]
    fn changing_server_hints_cannot_skip_the_minimum_update_interval() {
        use super::{AUTO_CHECK_INTERVAL, Duration, Instant, UPDATE_RETRY, UpdateSchedule};

        let last = Instant::now();
        let schedule = UpdateSchedule { last_check: Some((last, AUTO_CHECK_INTERVAL)), last_request: "9.0.0".into() };
        assert!(!schedule.due("9.0.1", last + Duration::from_secs(1)));
        assert!(!schedule.due("9.0.2", last + Duration::from_secs(UPDATE_RETRY.as_secs() - 1)));
        assert!(schedule.due("9.0.2", last + UPDATE_RETRY));
        assert!(!schedule.due("9.0.0", last + UPDATE_RETRY));
        assert!(schedule.due("9.0.0", last + AUTO_CHECK_INTERVAL));
    }

    #[test]
    fn interrupted_release_waits_for_the_retry_interval() {
        use super::{Duration, UPDATE_RETRY, UpdateSchedule};

        let schedule = UpdateSchedule::new(Some("9.0.0".into()));
        let (last, _) = schedule.last_check.unwrap();
        assert_eq!(schedule.last_request, "9.0.0");
        for target in ["", "9.0.0", "9.0.1"] {
            assert!(!schedule.due(target, last + Duration::from_secs(UPDATE_RETRY.as_secs() - 1)));
            assert!(schedule.due(target, last + UPDATE_RETRY));
        }
    }
}
