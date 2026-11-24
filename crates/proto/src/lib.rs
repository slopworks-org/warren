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
pub const VERSION: &str = match option_env!("WARREN_BUILD_VERSION") {
    Some(v) if !v.is_empty() => v,
    _ => env!("CARGO_PKG_VERSION"),
};

/// Rolling release containing the current main channel manifest.
pub const MAIN_CHANNEL_TAG: &str = "channel-main";
/// Manifest asset on the rolling main channel release.
pub const MAIN_CHANNEL_MANIFEST: &str = "channel.kv";

/// Source of executable updates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum UpdateChannel {
    /// Stable tagged releases.
    #[default]
    Release,
    /// Published builds of commits to main.
    Main,
}

impl UpdateChannel {
    /// Name used in configuration and on the wire.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Main => "main",
        }
    }

    /// Parses a channel name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "release" => Some(Self::Release),
            "main" => Some(Self::Main),
            _ => None,
        }
    }
}

impl std::fmt::Display for UpdateChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

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
    Some((strict_core(numbers)?, pre))
}

fn decimal(s: &str) -> bool {
    !s.is_empty() && !leading_zero(s) && s.bytes().all(|b| b.is_ascii_digit())
}

fn strict_core(s: &str) -> Option<VersionNumbers> {
    if !s.split('.').all(decimal) {
        return None;
    }
    parse_version(s)
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

fn valid_sha(sha: &str) -> bool {
    (7..=40).contains(&sha.len()) && sha.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Parses the base version, first-parent revision and abbreviated commit of a main build.
#[must_use]
pub fn parse_main_version(s: &str) -> Option<(VersionNumbers, u64, &str)> {
    let (base, suffix) = s.split_once("-main.")?;
    let (revision, sha) = suffix.split_once(".g")?;
    if !decimal(revision) || revision == "0" || !valid_sha(sha) {
        return None;
    }
    Some((strict_core(base)?, revision.parse().ok()?, sha))
}

/// Immutable build advertised by the main channel pointer.
#[derive(Debug, PartialEq, Eq)]
pub struct MainManifest {
    /// Version embedded in the executables.
    pub version: String,
    /// Immutable release tag derived from the version.
    pub tag: String,
    /// Source commit, when supplied.
    pub commit: Option<String>,
}

/// Reads a main channel manifest and verifies its release tag and optional commit.
#[must_use]
pub fn parse_main_manifest(text: &str) -> Option<MainManifest> {
    let kv = Kv::parse(text).ok()?;
    if ["version", "tag", "commit"].iter().any(|key| kv.get_all(key).nth(1).is_some()) {
        return None;
    }
    let version = kv.get("version")?;
    let (_, rev, sha) = parse_main_version(version)?;
    let tag = kv.get("tag")?;
    let commit = kv.get("commit");
    if tag != format!("main-{rev}-g{sha}") || commit.is_some_and(|s| !valid_sha(s) || !s.starts_with(sha)) {
        return None;
    }
    Some(MainManifest { version: version.into(), tag: tag.into(), commit: commit.map(str::to_string) })
}

/// Whether a candidate on the selected channel can replace the current version.
#[must_use]
pub fn is_update_available(channel: UpdateChannel, candidate: &str, current: &str) -> bool {
    match channel {
        UpdateChannel::Release => parse_version(candidate).is_some() && is_newer(candidate, current),
        UpdateChannel::Main => {
            let Some((base, rev, _)) = parse_main_version(candidate) else { return false };
            if let Some((current, revision, _)) = parse_main_version(current) {
                (base, rev) > (current, revision)
            } else {
                parse_version(current).or_else(|| version_parts(current).map(|(v, _)| v)).is_some_and(|v| base >= v)
            }
        }
    }
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

/// Maximum number of locally published service names per agent.
pub const MAX_SERVICES: usize = 64;

/// Checks the portable service label used by the allowlist and control protocol.
#[must_use]
pub fn service_name(name: &str) -> bool {
    (1..=63).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-')
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
    fn main_versions_and_channel_transitions() {
        use UpdateChannel::{Main, Release};
        let build = "0.4.0-main.65.g0012345";
        assert_eq!(parse_main_version(build), Some(((0, 4, 0), 65, "0012345")));
        assert!(valid_version(build));
        for invalid in ["v0.4.0", "0.04.0", "0.4", "0.4.0.1", "+0.4.0"] {
            assert!(parse_main_version(&format!("{invalid}-main.65.g0012345")).is_none());
        }
        for suffix in [
            "0.g0012345",
            "01.g0012345",
            "+1.g0012345",
            "18446744073709551616.g0012345",
            "1.0012345",
            "1.g123456",
            "1.g123456A",
            "1.g123456z",
            "1.g1234567+meta",
            "1.g01234567890123456789012345678901234567890",
        ] {
            assert!(parse_main_version(&format!("0.4.0-main.{suffix}")).is_none());
        }
        for current in ["0.4.0", "0.4.0-rc.5", "0.3.9", "0.3.9-main.100.gabcdefa", "0.4.0-main.64.gabcdefa"] {
            assert!(is_update_available(Main, build, current), "{current}");
        }
        for current in [build, "0.4.0-main.65.gabcdefa", "0.4.0-main.66.gabcdefa", "0.5.0", "0.5.0-rc.1", "bad"] {
            assert!(!is_update_available(Main, build, current), "{current}");
        }
        assert!(is_update_available(Release, "0.4.0", build));
        assert!(!is_update_available(Release, "0.3.9", build));
        assert!(!is_update_available(Release, build, "0.3.9"));
        assert!(!is_update_available(Main, "0.4.0", build));
        assert!(!is_update_available(Main, "invalid", "0.3.9"));
    }

    #[test]
    fn manifest_fields_identify_the_same_build() {
        let manifest = "version=0.4.0-main.65.g0012345\ntag=main-65-g0012345\n";
        assert_eq!(parse_main_manifest(manifest).unwrap().commit, None);
        assert_eq!(
            parse_main_manifest(&format!("{manifest}commit=0012345abc")).unwrap().commit.as_deref(),
            Some("0012345abc")
        );
        for invalid in [
            manifest.replace("tag=", "other="),
            manifest.replace("version=", "other="),
            manifest.replace("tag=main-65", "tag=main-66"),
            manifest.replace("tag=main", "tag=../main"),
            manifest.replace("65.g", "065.g"),
            format!("{manifest}commit=abc1234"),
            format!("{manifest}commit=0012345A"),
            format!("{manifest}tag=main-65-g0012345"),
            format!("{manifest}bad line"),
        ] {
            assert!(parse_main_manifest(&invalid).is_none(), "{invalid}");
        }
    }

    #[test]
    fn this_build_has_an_asset() {
        assert!(agent_asset().is_none_or(|a| AGENT_ASSETS.contains(&a)));
    }
}
