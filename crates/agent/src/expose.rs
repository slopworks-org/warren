//! Local grants. Atomic replacement of one file per name also revokes open streams.
use crate::cli::{Args, Command};
use crate::error::{Error, Result};
use crate::state::{self, Paths};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use warren_proto::Kv;

#[derive(Debug, PartialEq, Eq)]
pub struct Service {
    pub scheme: String,
    pub target: String,
}

impl Service {
    pub fn parse(text: &str, option: Option<&str>) -> Result<Self> {
        let (prefix, target) = text.split_once("://").map_or((None, text), |(s, t)| (Some(s), t));
        let scheme = option.or(prefix).unwrap_or("http");
        if !matches!(scheme, "http" | "https") || prefix.is_some_and(|v| v != scheme) {
            return Err(Error::Usage("choose one scheme, http or https".into()));
        }
        let bad = || Error::Usage("target needs a host and port, or a loopback port".into());
        let target = if let Ok(port) = target.parse::<u16>() {
            if port == 0 {
                return Err(bad());
            }
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)).to_string()
        } else if let Ok(addr) = target.parse::<SocketAddr>() {
            if addr.port() == 0 || addr.ip().is_unspecified() {
                return Err(bad());
            }
            addr.to_string()
        } else {
            let (host, port) = target.rsplit_once(':').ok_or_else(bad)?;
            let port = port.parse::<u16>().ok().filter(|&p| p > 0).ok_or_else(bad)?;
            let host = host.to_ascii_lowercase();
            if host.len() > 253 || !host.split('.').all(warren_proto::service_name) {
                return Err(bad());
            }
            format!("{host}:{port}")
        };
        Ok(Self { scheme: scheme.into(), target })
    }
}

pub fn services(dir: &Path) -> Result<BTreeMap<String, Service>> {
    let mut services = BTreeMap::new();
    let entries = match fs::read_dir(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(services),
        other => other.map_err(Error::io("reading exposed services"))?,
    };
    for entry in entries {
        let entry = entry.map_err(Error::io("reading service entry"))?;
        let name = entry.file_name();
        let Some(name) = name.to_str().filter(|s| warren_proto::service_name(s)) else { continue };
        let text = fs::read_to_string(entry.path()).map_err(Error::io("reading service target"))?;
        services.insert(name.into(), Service::parse(text.trim(), None)?);
    }
    Ok(services)
}

pub fn command(args: &Args) -> Result<()> {
    if args.command == Command::Expose
        && (args.operands.is_empty() || args.operands == ["--list"])
        && args.scheme.is_none()
    {
        return list(&args.paths);
    }
    let name = args.operands.first().filter(|n| warren_proto::service_name(n)).ok_or_else(|| {
        Error::Usage("use a service name of 1 to 63 lowercase letters, digits or internal hyphens".into())
    })?;
    let dir = args.paths.config_dir.join("services");
    fs::create_dir_all(&dir).map_err(Error::io("creating service directory"))?;
    let lock = fs::File::open(&dir).map_err(Error::io("opening service directory"))?;
    lock.lock().map_err(Error::io("locking service directory"))?;
    let path = dir.join(name);
    match (&args.command, args.operands.as_slice()) {
        (Command::Expose, [_, target]) => {
            let s = Service::parse(target, args.scheme.as_deref())?;
            if !path.exists() && services(&dir)?.len() >= warren_proto::MAX_SERVICES {
                return Err(Error::Usage("service limit reached".into()));
            }
            state::write_private(&path, format!("{}://{}\n", s.scheme, s.target).as_bytes())?;
            println!("{name} -> {}://{} (exposed)", s.scheme, s.target);
        }
        (Command::Unexpose, [_]) => {
            fs::remove_file(&path).map_err(Error::io(format!("removing service {name}")))?;
            lock.sync_all().map_err(Error::io("syncing service directory"))?;
            println!("{name} is no longer exposed.");
        }
        _ => return Err(Error::Usage("use expose <name> <target> or unexpose <name>".into())),
    }
    Ok(())
}

pub fn list(paths: &Paths) -> Result<()> {
    let published = fs::read_to_string(paths.run_dir.join("service-status")).ok().and_then(|s| Kv::parse(&s).ok());
    let services = match services(&paths.config_dir.join("services")) {
        Ok(local) => local,
        Err(Error::Io { source, .. }) if source.kind() == io::ErrorKind::PermissionDenied && published.is_some() => {
            let mut local = BTreeMap::new();
            for row in published.iter().flat_map(|kv| kv.get_all("grant")) {
                if let Some((name, target)) = row.split_once(' ') {
                    local.insert(name.to_owned(), Service::parse(target, None)?);
                }
            }
            local
        }
        Err(e) => return Err(e),
    };
    if services.is_empty() {
        println!("No exposed services. Use warren expose <name> <target>.");
        return Ok(());
    }
    for (name, service) in services {
        let urls: Vec<_> = published
            .iter()
            .flat_map(|kv| kv.get_all("published"))
            .filter_map(|s| s.split_once(' '))
            .filter(|(n, u)| *n == name && u.starts_with("https://") && !u.chars().any(char::is_control))
            .map(|(_, u)| u)
            .collect();
        let status = if !urls.is_empty() {
            urls.join(", ")
        } else if published.is_some() {
            "awaiting publication".into()
        } else {
            "publication status unknown".into()
        };
        println!("{name} -> {}://{} ({status})", service.scheme, service.target);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grants_accept_host_ports_and_loopback_shorthand() {
        let local = Service::parse("3000", None).unwrap();
        assert_eq!(local.target, "127.0.0.1:3000");
        assert_eq!(Service::parse("http://127.0.0.1:3000", None).unwrap(), local);
        assert_eq!(Service::parse("[::1]:443", Some("https")).unwrap().scheme, "https");
        assert_eq!(Service::parse("dashboard.lan:3000", None).unwrap().target, "dashboard.lan:3000");
        for value in ["0", "65536", "http://localhost/path", "ftp://3000", "0.0.0.0:80"] {
            assert!(Service::parse(value, None).is_err());
        }
        assert!(Service::parse("https://3000", Some("http")).is_err());
    }
}
