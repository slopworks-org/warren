//! Wire formats shared by the Warren server and agent.
//!
//! The agent is size-critical, so everything here is dependency-light: a
//! line-based `key=value` text format instead of JSON, hand-written base64/hex,
//! and HMAC-SHA256 for authenticating registration over plain HTTP.

pub mod codec;
mod error;
pub mod kv;
pub mod register;

pub use error::Error;
pub use kv::Kv;

/// Version string reported by both binaries.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Plain-HTTP path the agent uses once, to register with a token.
pub const REGISTER_PATH: &str = "/agent/v1/register";
/// Control-channel path, served only on the server's tunnel address.
pub const CONFIG_PATH: &str = "/agent/v1/config";
/// Official release repository, where the agent gets executable updates.
pub const RELEASE_REPO: &str = "slopworks-org/warren";

/// Hex-encoded SHA-256 of a release asset.
#[must_use]
pub fn asset_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    codec::hex_encode(&Sha256::digest(data))
}

/// The expected SHA-256 of a file named in a release's SHA256SUMS.
#[must_use]
pub fn asset_checksum<'a>(sums: &'a str, file: &str) -> Option<&'a str> {
    sums.lines().find_map(|l| {
        let (hash, name) = l.split_once(char::is_whitespace)?;
        (name.trim_start().trim_start_matches('*') == file).then_some(hash)
    })
}
/// Release file names of the agent builds.
pub const AGENT_ASSETS: &[&str] = &[
    "warren-linux-aarch64",
    "warren-linux-armv7",
    "warren-linux-x86_64",
    "warren-macos-aarch64",
    "warren-macos-x86_64",
];

/// The release file name of this build, if releases include one.
#[must_use]
pub fn agent_asset() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "aarch64") => Some("warren-linux-aarch64"),
        ("linux", "arm") => Some("warren-linux-armv7"),
        ("linux", "x86_64") => Some("warren-linux-x86_64"),
        ("macos", "aarch64") => Some("warren-macos-aarch64"),
        ("macos", "x86_64") => Some("warren-macos-x86_64"),
        _ => None,
    }
}

/// Parses `1.2.3` or `v1.2.3`; pre-release and build suffixes are refused.
#[must_use]
pub fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let mut parts = s.strip_prefix('v').unwrap_or(s).split('.').map(|p| p.parse::<u64>().ok());
    let v = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(v)
}

/// Whether this is a valid release or prerelease version.
#[must_use]
pub fn valid_version(version: &str) -> bool {
    version_parts(version).is_some()
}

type VersionNumbers = (u64, u64, u64);

fn version_parts(version: &str) -> Option<(VersionNumbers, Option<&str>)> {
    let valid = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    let numeric = |part: &str| part.bytes().all(|b| b.is_ascii_digit());
    let (version, build) = version.split_once('+').map_or((version, None), |(v, b)| (v, Some(b)));
    if build.is_some_and(|b| !b.split('.').all(valid)) {
        return None;
    }
    let (core, pre) = version.split_once('-').map_or((version, None), |(v, p)| (v, Some(p)));
    if pre.is_some_and(|p| !p.split('.').all(|part| valid(part) && !(numeric(part) && leading_zero(part)))) {
        return None;
    }
    let numbers = core.strip_prefix('v').unwrap_or(core);
    if !numbers.split('.').all(|part| !part.is_empty() && numeric(part) && !leading_zero(part)) {
        return None;
    }
    Some((parse_version(core)?, pre))
}

fn leading_zero(part: &str) -> bool {
    part.len() > 1 && part.starts_with('0')
}

fn compare_prereleases(left: &str, right: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let mut right = right.split('.');
    for a in left.split('.') {
        let Some(b) = right.next() else { return Ordering::Greater };
        let numeric = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
        let order = match (numeric(a), numeric(b)) {
            (true, true) => a.len().cmp(&b.len()).then_with(|| a.cmp(b)),
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => a.cmp(b),
        };
        if order != Ordering::Equal {
            return order;
        }
    }
    if right.next().is_some() { Ordering::Less } else { Ordering::Equal }
}

/// Whether `candidate` has higher `SemVer` precedence than `current`.
#[must_use]
pub fn is_newer(candidate: &str, current: &str) -> bool {
    let (Some((candidate, a)), Some((current, b))) = (version_parts(candidate), version_parts(current)) else {
        return false;
    };
    candidate > current
        || (candidate == current
            && match (a, b) {
                (None, Some(_)) => true,
                (Some(a), Some(b)) => compare_prereleases(a, b).is_gt(),
                _ => false,
            })
}
/// TCP port of the control channel on the server's tunnel address.
pub const DEFAULT_CTL_PORT: u16 = 7180;
/// Default UDP port of the WireGuard hub.
pub const DEFAULT_WG_PORT: u16 = 51820;
/// Keepalive the agent asks the kernel for, so NAT mappings stay open.
pub const DEFAULT_KEEPALIVE: u16 = 25;
/// How long the server holds a config long-poll open, in seconds.
pub const LONG_POLL_SECS: u64 = 50;
/// Keepalive of direct peers on the same LAN. Each side then hears from the
/// other at least this often, so a missing reply soon shows a broken path.
pub const LAN_KEEPALIVE: u16 = 10;

/// A WireGuard peer as the server describes it to an agent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerConfig {
    /// Base64 public key.
    pub public_key: String,
    /// `host:port`; resolved by the agent. Empty when the peer has no endpoint.
    pub endpoint: String,
    /// CIDRs routed to this peer.
    pub allowed_ips: Vec<String>,
    /// Persistent keepalive interval in seconds; 0 disables it.
    pub keepalive: u16,
}

impl PeerConfig {
    /// `key endpoint ips keepalive`, with `-` for an empty endpoint.
    fn encode(&self) -> String {
        let endpoint = if self.endpoint.is_empty() { "-" } else { &self.endpoint };
        format!("{} {endpoint} {} {}", self.public_key, self.allowed_ips.join(","), self.keepalive)
    }

    fn parse(line: &str, field: &'static str) -> Result<Self, Error> {
        let mut it = line.split(' ');
        let (Some(key), Some(ep), Some(ips), Some(ka), None) = (it.next(), it.next(), it.next(), it.next(), it.next())
        else {
            return Err(Error::BadField(field));
        };
        codec::decode_key(key).ok_or(Error::BadField(field))?;
        Ok(PeerConfig {
            public_key: key.to_string(),
            endpoint: if ep == "-" { String::new() } else { ep.to_string() },
            allowed_ips: ips.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect(),
            keepalive: ka.parse().map_err(|_| Error::BadField(field))?,
        })
    }
}

/// Desired tunnel state pushed by the server over the control channel.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AgentConfig {
    /// Identifies the content: changes whenever anything else in the config
    /// does. The agent long-polls for a config with a different version.
    pub version: u64,
    /// Server-side id of this device.
    pub device_id: u64,
    /// Display name of this device.
    pub name: String,
    /// The device's tunnel address with the network prefix, e.g. `10.77.0.5/16`.
    pub address: String,
    /// Server address inside the tunnel and control port, e.g. `10.77.0.1:7180`.
    pub control: String,
    /// Peers to configure; in the hub-and-spoke topology, only the server.
    pub peers: Vec<PeerConfig>,
    /// Devices on the same LAN to reach directly. The agent routes a device's
    /// address to it only while the direct path works, and through the server
    /// otherwise.
    pub lan_peers: Vec<PeerConfig>,
    /// Requested agent version, empty when there is no dashboard request.
    /// This is a hint. The agent's local policy and official release decide what runs.
    pub update: String,
    /// Consent generation attached to the dashboard request, when supported.
    pub update_generation: Option<String>,
}

impl AgentConfig {
    /// Serializes into `kv` pairs; peers become repeated `peer` lines and
    /// LAN peers `lan_peer_v2` lines, which older agents ignore.
    #[must_use]
    pub fn to_kv(&self) -> Kv {
        let mut kv = Kv::new();
        self.write_kv(&mut kv);
        kv
    }

    /// Appends this config's pairs to `kv`.
    pub fn write_kv(&self, kv: &mut Kv) {
        kv.push("version", self.version.to_string());
        kv.push("device_id", self.device_id.to_string());
        kv.push("name", &self.name);
        kv.push("address", &self.address);
        kv.push("control", &self.control);
        for p in &self.peers {
            kv.push("peer", p.encode());
        }
        for p in &self.lan_peers {
            kv.push("lan_peer_v2", p.encode());
        }
        if !self.update.is_empty() {
            kv.push("update", &self.update);
            if let Some(generation) = &self.update_generation {
                kv.push("update_generation", generation);
            }
        }
    }

    /// Parses a config written by [`AgentConfig::write_kv`]; other keys are ignored.
    ///
    /// # Errors
    /// When a field is missing or malformed.
    pub fn from_kv(kv: &Kv) -> Result<Self, Error> {
        let peers = |field| kv.get_all(field).map(|l| PeerConfig::parse(l, field)).collect::<Result<Vec<_>, _>>();
        Ok(AgentConfig {
            version: kv.parse_field("version")?,
            device_id: kv.parse_field("device_id")?,
            name: kv.req("name")?.to_string(),
            address: kv.req("address")?.to_string(),
            control: kv.req("control")?.to_string(),
            peers: peers("peer")?,
            lan_peers: peers("lan_peer_v2")?,
            update: kv.get("update").unwrap_or_default().to_string(),
            update_generation: kv.get("update_generation").map(str::to_string),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_config_roundtrip() {
        let cfg = AgentConfig {
            version: 7,
            device_id: 3,
            name: "router".into(),
            address: "10.77.0.5/16".into(),
            control: "10.77.0.1:7180".into(),
            peers: vec![PeerConfig {
                public_key: codec::encode_key(&[7u8; 32]),
                endpoint: "vpn.example.com:51820".into(),
                allowed_ips: vec!["10.77.0.0/16".into()],
                keepalive: 25,
            }],
            lan_peers: vec![PeerConfig {
                public_key: codec::encode_key(&[8u8; 32]),
                endpoint: "192.168.1.10:41000".into(),
                allowed_ips: vec!["10.77.0.6/32".into()],
                keepalive: LAN_KEEPALIVE,
            }],
            update: String::new(),
            update_generation: None,
        };
        let text = cfg.to_kv().encode();
        assert!(!text.contains("update"));
        let back = AgentConfig::from_kv(&Kv::parse(&text).unwrap()).unwrap();
        assert_eq!(cfg, back);
        let legacy = text.replace("lan_peer_v2=", "lan_peer=");
        assert_eq!(AgentConfig::from_kv(&Kv::parse(&legacy).unwrap()).unwrap().lan_peers, []);
        let with_update = AgentConfig { update: "0.2.0".into(), ..cfg.clone() };
        assert_eq!(AgentConfig::from_kv(&with_update.to_kv()).unwrap(), with_update);
        let numbered = AgentConfig { update_generation: Some("epoch:1".into()), ..with_update };
        assert_eq!(AgentConfig::from_kv(&numbered.to_kv()).unwrap(), numbered);
        let mut kv = Kv::parse(&text).unwrap();
        kv.push("peer", "notakey - x 1");
        assert_eq!(AgentConfig::from_kv(&kv), Err(Error::BadField("peer")));
        let mut kv = Kv::parse(&text).unwrap();
        kv.push("lan_peer_v2", "notakey - x 1");
        assert_eq!(AgentConfig::from_kv(&kv), Err(Error::BadField("lan_peer_v2")));
        assert_eq!(AgentConfig::from_kv(&Kv::new()), Err(Error::MissingField("version")));
    }

    #[test]
    fn versions() {
        assert_eq!(parse_version("v0.12.3"), Some((0, 12, 3)));
        assert_eq!(parse_version("1.0.0"), Some((1, 0, 0)));
        assert_eq!(parse_version("v1.0"), None);
        assert_eq!(parse_version("v1.0.0-rc1"), None);
        assert_eq!(parse_version("v1.0.0.1"), None);
        assert!(is_newer("0.10.0", "0.9.9"));
        assert!(is_newer("v1.0.0", "0.99.0"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("0.0.9", "0.1.0"));
        assert!(!is_newer("garbage", "0.1.0"));
        assert!(is_newer("0.5.0", "0.5.0-rc.1"));
        assert!(!is_newer("0.5.0-rc.1", "0.5.0"));
        assert!(is_newer("0.5.0-rc.10", "0.5.0-rc.2"));
        assert!(is_newer("0.5.0-rc.1", "0.5.0-rc"));
        assert!(is_newer("0.5.0-rc.alpha", "0.5.0-rc.1"));
        assert!(!is_newer("0.5.0+build.2", "0.5.0+build.1"));
        assert!(!valid_version("0.5.0-rc.01"));
    }

    #[test]
    fn this_build_has_an_asset() {
        assert!(agent_asset().is_none_or(|a| AGENT_ASSETS.contains(&a)));
    }
}
