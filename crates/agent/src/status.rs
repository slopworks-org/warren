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

pub fn status(args: &Args) {
    let available = crate::selfupdate::latest(Duration::from_secs(3))
        .ok()
        .filter(|version| warren_proto::is_newer(version, warren_proto::VERSION))
        .map_or_else(String::new, |version| format!(" (v{version} available)"));
    println!("Version:    v{}{available}", warren_proto::VERSION);
    if let Ok(saved) = Saved::load(&args.paths.config()) {
        println!(
            "Automatic and dashboard updates: {}",
            if crate::selfupdate::remote_enabled(&args.paths) { "on" } else { "off" }
        );
        tunnel_status(&saved);
    }
    control_status(&args.paths.status());
}

fn tunnel_status(saved: &Saved) {
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
                let direct = p.allowed_ips.first().and_then(|ip| ip.parse::<wg::AllowedIp>().ok()).is_some_and(|ip| {
                    wg::routes_to(&crate::lan::interface(&saved.interface), ip.addr).unwrap_or(false)
                });
                let path = if direct { "direct" } else { "through the server" };
                println!("LAN peer:   {} at {}, {path}", p.allowed_ips.join(","), p.endpoint);
            }
        }
        Err(e) if wg::link_index(&saved.interface).is_none() => println!("Tunnel:     down ({e})"),
        Err(e) => println!("Tunnel:     unknown ({e}; run as root for details)"),
    }
}

fn control_status(path: &std::path::Path) {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("Control:    agent is not running");
            return;
        }
        Err(e) => {
            println!("Control:    status unavailable ({e})");
            return;
        }
    };
    let Ok(kv) = Kv::parse(&text) else {
        println!("Control:    status unavailable");
        return;
    };
    #[cfg(target_os = "macos")]
    if !status_is_current(&kv) {
        println!("Control:    agent is not running");
        return;
    }
    let state = kv.get("state").unwrap_or("unknown");
    let contact = kv.get("last_contact").and_then(|v| v.parse::<u64>().ok()).filter(|&v| v > 0).map_or_else(
        || "never".to_string(),
        |v| format!("{} ago", ago(Duration::from_secs(log::now().saturating_sub(v)))),
    );
    let version = kv.get("config_version").map_or_else(String::new, |v| format!(" (config v{v})"));
    println!("Control:    {state}, last contact {contact}{version}");
    if let Some(err) = kv.get("last_error").filter(|e| !e.is_empty()) {
        println!("Last error: {err}");
    }
}

#[cfg(target_os = "macos")]
fn status_is_current(kv: &Kv) -> bool {
    crate::state::boot_id().is_ok_and(|boot_id| kv.get("boot_id") == Some(boot_id.as_str()))
}

pub fn down(args: &Args) -> Result<()> {
    let registration = if args.forget { crate::selfupdate::Forget::open(&args.paths)? } else { None };
    let saved = if args.forget {
        registration.as_ref().and_then(|registration| registration.load_config().ok())
    } else {
        Saved::load(&args.paths.config()).ok()
    };
    let iface = saved.map_or_else(|| args.interface.clone(), |s| s.interface);
    if wg::link_index(&iface).is_some() {
        wg::delete_link(&iface)?;
        println!("Removed interface {iface}.");
    } else {
        println!("Interface {iface} is not present.");
    }
    crate::tunnel::remove_direct(&iface)?;
    if let Some(registration) = registration {
        registration.revoke()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    #[test]
    fn status_from_another_boot_is_stale() {
        let mut kv = Kv::new();
        kv.push("state", "connected");
        assert!(!status_is_current(&kv));
        let mut stale = kv.clone();
        stale.push("boot_id", "00000000-0000-0000-0000-000000000000");
        assert!(!status_is_current(&stale));
        kv.push("boot_id", crate::state::boot_id().unwrap());
        assert!(status_is_current(&kv));
    }

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

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires the privileged runtime lock directory"]
    fn forget_removes_credentials_from_a_custom_config_directory() {
        let suffix = warren_proto::codec::hex_encode(&crate::state::random_bytes::<4>().unwrap());
        let dir = std::env::temp_dir().join(format!("warren-forget-{suffix}"));
        let args = Args::parse(
            ["down", "--forget", "--interface", &format!("wf{suffix}"), "--config-dir", dir.to_str().unwrap()]
                .into_iter()
                .map(str::to_owned),
        )
        .unwrap();
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(args.paths.config(), "test config").unwrap();
        std::fs::write(args.paths.key(), "test key").unwrap();
        std::fs::write(args.paths.update_policy(), "on\n").unwrap();

        let result = down(&args);
        let forgotten =
            !args.paths.config().exists() && !args.paths.key().exists() && !args.paths.update_policy().exists();
        std::fs::remove_dir_all(dir).unwrap();
        result.unwrap();
        assert!(forgotten);
    }
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root-owned update fixtures"]
    fn forget_uses_the_policy_lock_and_unlinks_entries_through_a_directory_alias() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let fixture = crate::update_service::tests::Fixture::new();
        let alias = fixture.dir.join("alias");
        symlink(&fixture.dir, &alias).unwrap();
        let args = Args::parse(
            ["down", "--forget", "--interface", "wf-forget-alias", "--config-dir", alias.to_str().unwrap()]
                .into_iter()
                .map(str::to_owned),
        )
        .unwrap();

        let paths = fixture.paths();
        let dir = std::fs::File::open(&fixture.dir).unwrap();
        let lock_path = crate::selfupdate::policy_lock_path(&dir).unwrap();
        let lock = crate::update_files::open_lock(&lock_path).unwrap();
        std::fs::write(paths.config(), "test config").unwrap();
        std::fs::write(paths.update_policy(), "on\n").unwrap();
        let target_key = fixture.dir.join("untouched");
        std::fs::write(&target_key, "test key").unwrap();
        std::fs::remove_file(paths.key()).unwrap();
        symlink(&target_key, paths.key()).unwrap();

        // A reused directory inode can already have a policy lock file.
        let permissions = lock.metadata().unwrap().permissions();
        lock.set_permissions(std::fs::Permissions::from_mode(permissions.mode() | 0o020)).unwrap();
        let result = down(&args);
        lock.set_permissions(permissions).unwrap();
        assert!(matches!(
            result,
            Err(crate::error::Error::Io { what, source })
                if what == format!("opening lock {}", lock_path.display())
                    && source.kind() == std::io::ErrorKind::PermissionDenied
        ));
        assert!(paths.config().exists() && paths.key().exists());
        assert_eq!(std::fs::read_to_string(paths.update_policy()).unwrap(), "on\n");

        // A revocation failure must also leave the credentials alone.
        std::fs::remove_file(paths.update_policy()).unwrap();
        std::fs::create_dir(paths.update_policy()).unwrap();
        assert!(down(&args).is_err());
        assert!(paths.config().exists() && paths.key().exists());
        std::fs::remove_dir(paths.update_policy()).unwrap();
        std::fs::write(paths.update_policy(), "on\n").unwrap();

        down(&args).unwrap();
        assert!(!paths.update_policy().exists() && !paths.config().exists());
        assert!(std::fs::symlink_metadata(paths.key()).is_err());
        assert_eq!(std::fs::read_to_string(&target_key).unwrap(), "test key");
    }
}
