//! `warren status` and `warren down`.

use crate::cli::Args;
use crate::error::Result;
use crate::state::Saved;
use crate::{log, tunnel};
use std::time::Duration;
use warren_proto::Kv;
use warren_wgctl as wg;

/// "12s", "5m", "3h", "2d".
fn ago(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        0..60 => format!("{s}s"),
        60..3600 => format!("{}m", s / 60),
        3600..86_400 => format!("{}h", s / 3600),
        _ => format!("{}d", s / 86_400),
    }
}

/// "1.5 MiB".
fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut unit = 0;
    let mut whole = n;
    let mut tenths = 0;
    while whole >= 1024 && unit < UNITS.len() - 1 {
        tenths = (whole % 1024) * 10 / 1024;
        whole /= 1024;
        unit += 1;
    }
    if unit == 0 { format!("{n} B") } else { format!("{whole}.{tenths} {}", UNITS[unit]) }
}

pub fn status(args: &Args) -> Result<()> {
    let saved = Saved::load(&args.paths.config())?;
    let t = &saved.tunnel;
    println!("Device:     {} (#{})", t.name, t.device_id);
    println!("Address:    {}", t.address);
    println!("Interface:  {}", saved.interface);
    for p in &t.peers {
        let resolved = tunnel::resolve(&p.endpoint).map(|a| format!(" ({a})")).unwrap_or_default();
        println!("Server:     {}{resolved}", p.endpoint);
    }
    match wg::get_device(&saved.interface) {
        Ok(dev) => {
            let hs = tunnel::handshake_age(&dev).map_or_else(|| "never".to_string(), |a| format!("{} ago", ago(a)));
            let (rx, tx) = dev.peers.iter().fold((0, 0), |(r, t), p| (r + p.rx_bytes, t + p.tx_bytes));
            println!("Handshake:  {hs}");
            println!("Traffic:    received {}, sent {}", bytes(rx), bytes(tx));
            for p in &t.lan_peers {
                let direct = dev.peers.iter().any(|d| tunnel::same_key(p, &d.public_key) && !d.allowed_ips.is_empty());
                let path = if direct { "direct" } else { "through the server" };
                println!("LAN peer:   {} at {}, {path}", p.allowed_ips.join(","), p.endpoint);
            }
        }
        Err(e) if wg::link_index(&saved.interface).is_none() => println!("Tunnel:     down ({e})"),
        Err(e) => println!("Tunnel:     unknown ({e}; run as root for details)"),
    }
    match std::fs::read_to_string(args.paths.status()).ok().and_then(|s| Kv::parse(&s).ok()) {
        Some(kv) => {
            let state = kv.get("state").unwrap_or("unknown");
            let contact = kv.get("last_contact").and_then(|v| v.parse::<u64>().ok()).filter(|&v| v > 0).map_or_else(
                || "never".to_string(),
                |v| format!("{} ago", ago(Duration::from_secs(log::now().saturating_sub(v)))),
            );
            println!("Control:    {state}, last contact {contact} (config v{})", t.version);
            if let Some(err) = kv.get("last_error").filter(|e| !e.is_empty()) {
                println!("Last error: {err}");
            }
        }
        None => println!("Control:    agent is not running"),
    }
    Ok(())
}

pub fn down(args: &Args) -> Result<()> {
    let iface = Saved::load(&args.paths.config()).map_or_else(|_| args.interface.clone(), |s| s.interface);
    if wg::link_index(&iface).is_some() {
        wg::delete_link(&iface)?;
        println!("Removed interface {iface}.");
    } else {
        println!("Interface {iface} is not present.");
    }
    if args.forget {
        for path in [args.paths.config(), args.paths.key()] {
            match std::fs::remove_file(&path) {
                Ok(()) => println!("Deleted {}.", path.display()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(crate::error::Error::Io { what: format!("deleting {}", path.display()), source: e });
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_units() {
        assert_eq!(ago(Duration::from_secs(5)), "5s");
        assert_eq!(ago(Duration::from_secs(125)), "2m");
        assert_eq!(ago(Duration::from_hours(25)), "1d");
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(1536), "1.5 KiB");
        assert_eq!(bytes(3 * 1024 * 1024), "3.0 MiB");
    }
}
