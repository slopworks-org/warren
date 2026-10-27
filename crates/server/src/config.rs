//! Server configuration: one short TOML file with sensible defaults.
//!
//! The minimal file is two lines:
//!
//! ```toml
//! domain = "warren.example.com"
//! acme_email = "admin@example.com"
//! ```

use serde::Deserialize;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use thiserror::Error;
use warren_proto::{DEFAULT_CTL_PORT, DEFAULT_WG_PORT};

/// Why the configuration cannot be used.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("reading {path}: {source}")]
    Read {
        /// The configuration file.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The file is not valid TOML or has unknown/mistyped keys.
    #[error("parsing {path}: {source}")]
    Parse {
        /// The configuration file.
        path: PathBuf,
        /// The underlying error.
        source: Box<toml::de::Error>,
    },
    /// A value is out of range or inconsistent with another.
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

/// How TLS certificates are obtained.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TlsMode {
    /// Let's Encrypt (or another ACME CA) via HTTP-01, one certificate per host.
    #[default]
    Acme,
    /// One certificate and key from files, e.g. a wildcard certificate.
    Files,
    /// Self-signed certificates generated on the fly; for tests and LANs.
    SelfSigned,
}

/// Which WireGuard implementation the hub uses.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WgBackendKind {
    /// Kernel module when available (with `nft` for ACLs), userspace otherwise.
    #[default]
    Auto,
    /// The Linux kernel module.
    Kernel,
    /// boringtun on a TUN device.
    Userspace,
    /// No tunnel at all: for UI development on non-Linux systems.
    None,
}

/// Log output format.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LogFormat {
    /// Human-readable lines.
    #[default]
    Text,
    /// One JSON object per line.
    Json,
}

/// `[tls]` section.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    /// Where certificates come from.
    pub mode: TlsMode,
    /// ACME directory URL.
    pub acme_directory: String,
    /// Certificate chain (PEM) for `mode = "files"`.
    pub cert_file: Option<PathBuf>,
    /// Private key (PEM) for `mode = "files"`.
    pub key_file: Option<PathBuf>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        TlsConfig {
            mode: TlsMode::Acme,
            acme_directory: "https://acme-v02.api.letsencrypt.org/directory".into(),
            cert_file: None,
            key_file: None,
        }
    }
}

/// `[wireguard]` section.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WgConfig {
    /// Implementation to use.
    pub backend: WgBackendKind,
    /// Interface name on the server.
    pub interface: String,
    /// UDP port the hub listens on.
    pub port: u16,
    /// Internal network, e.g. `10.77.0.0/16`. The server takes the first host address.
    pub network: String,
    /// `host:port` devices connect to; defaults to the admin host and `port`.
    pub endpoint: Option<String>,
    /// TCP port of the agent control channel on the server's tunnel address.
    pub control_port: u16,
    /// MTU of the tunnel interface.
    pub mtu: u32,
}

impl Default for WgConfig {
    fn default() -> Self {
        WgConfig {
            backend: WgBackendKind::Auto,
            interface: "warren0".into(),
            port: DEFAULT_WG_PORT,
            network: "10.77.0.0/16".into(),
            endpoint: None,
            control_port: DEFAULT_CTL_PORT,
            mtu: 1420,
        }
    }
}

/// `[log]` section.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    /// `tracing` filter, e.g. `info` or `warren_server=debug,info`.
    pub level: String,
    /// Output format.
    pub format: LogFormat,
}

impl Default for LogConfig {
    fn default() -> Self {
        LogConfig { level: "info".into(), format: LogFormat::Text }
    }
}

/// `[update]` section.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpdateConfig {
    /// Look for a new release on GitHub once a day.
    pub check: bool,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        UpdateConfig { check: true }
    }
}

/// The whole configuration file.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Base domain: resources are published as `<name>.<domain>`.
    pub domain: String,
    /// Host of the admin UI and API; defaults to `domain`.
    #[serde(default)]
    pub admin_host: Option<String>,
    /// Contact e-mail for the ACME account.
    #[serde(default)]
    pub acme_email: Option<String>,
    /// Database, keys and certificates.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// Plain HTTP listener (ACME challenges, redirects, agent registration).
    #[serde(default = "default_http")]
    pub listen_http: SocketAddr,
    /// HTTPS listener (admin UI and published resources).
    #[serde(default = "default_https")]
    pub listen_https: SocketAddr,
    /// HTTPS port as seen from the internet, for redirects; defaults to the listener's.
    #[serde(default)]
    pub public_https_port: Option<u16>,
    /// TLS settings.
    #[serde(default)]
    pub tls: TlsConfig,
    /// Tunnel settings.
    #[serde(default)]
    pub wireguard: WgConfig,
    /// Logging settings.
    #[serde(default)]
    pub log: LogConfig,
    /// Release checks.
    #[serde(default)]
    pub update: UpdateConfig,
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/warren")
}

fn default_http() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 80))
}

fn default_https() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 443))
}

/// An IPv4 network in CIDR form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Net4 {
    /// Network address (host bits zero).
    pub addr: Ipv4Addr,
    /// Prefix length.
    pub prefix: u8,
}

impl Net4 {
    /// Parses `a.b.c.d/n`; host bits must be zero and the prefix 8..=30.
    ///
    /// # Errors
    /// [`ConfigError::Invalid`] on malformed or unusable networks.
    pub fn parse(s: &str) -> Result<Net4, ConfigError> {
        let bad =
            || ConfigError::Invalid(format!("wireguard.network {s:?} must look like 10.77.0.0/16 (prefix 8..30)"));
        let (a, p) = s.split_once('/').ok_or_else(bad)?;
        let addr: Ipv4Addr = a.parse().map_err(|_| bad())?;
        let prefix: u8 = p.parse().map_err(|_| bad())?;
        if !(8..=30).contains(&prefix) || u32::from(addr) & !Self::mask_of(prefix) != 0 {
            return Err(bad());
        }
        Ok(Net4 { addr, prefix })
    }

    fn mask_of(prefix: u8) -> u32 {
        u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
    }

    /// Netmask as an integer.
    #[must_use]
    pub fn mask(&self) -> u32 {
        Self::mask_of(self.prefix)
    }

    /// True if `ip` lies inside the network.
    #[must_use]
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask() == u32::from(self.addr)
    }

    /// The server's own address: the first host of the network.
    #[must_use]
    pub fn server_ip(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) + 1)
    }
}

impl std::fmt::Display for Net4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// Lower-cases a host name and checks it is a plausible DNS name.
#[must_use]
pub fn normalize_host(host: &str) -> Option<String> {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let ok = !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    ok.then_some(h)
}

impl Config {
    /// Reads and validates a configuration file.
    ///
    /// # Errors
    /// When the file is unreadable, malformed or inconsistent.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text =
            std::fs::read_to_string(path).map_err(|source| ConfigError::Read { path: path.to_owned(), source })?;
        Self::from_toml(&text).map_err(|e| match e {
            ConfigError::Parse { source, .. } => ConfigError::Parse { path: path.to_owned(), source },
            other => other,
        })
    }

    /// Parses and validates configuration text.
    ///
    /// # Errors
    /// When the text is malformed or inconsistent.
    pub fn from_toml(text: &str) -> Result<Config, ConfigError> {
        let mut cfg: Config = toml::from_str(text)
            .map_err(|e| ConfigError::Parse { path: PathBuf::from("<config>"), source: Box::new(e) })?;
        cfg.domain = normalize_host(&cfg.domain)
            .ok_or_else(|| ConfigError::Invalid(format!("domain {:?} is not a valid host name", cfg.domain)))?;
        if let Some(h) = &cfg.admin_host {
            cfg.admin_host =
                Some(normalize_host(h).ok_or_else(|| ConfigError::Invalid(format!("admin_host {h:?} is not valid")))?);
        }
        Net4::parse(&cfg.wireguard.network)?;
        if cfg.wireguard.interface.is_empty() || cfg.wireguard.interface.len() > 15 {
            return Err(ConfigError::Invalid("wireguard.interface must be 1 to 15 characters".into()));
        }
        if !(1280..=9000).contains(&cfg.wireguard.mtu) {
            return Err(ConfigError::Invalid("wireguard.mtu must be between 1280 and 9000".into()));
        }
        match cfg.tls.mode {
            TlsMode::Acme if cfg.acme_email.as_deref().is_none_or(|e| !e.contains('@')) => {
                return Err(ConfigError::Invalid("acme_email is required with tls.mode = \"acme\"".into()));
            }
            TlsMode::Files if cfg.tls.cert_file.is_none() || cfg.tls.key_file.is_none() => {
                return Err(ConfigError::Invalid(
                    "tls.cert_file and tls.key_file are required with tls.mode = \"files\"".into(),
                ));
            }
            _ => {}
        }
        Ok(cfg)
    }

    /// Host serving the admin UI and API.
    #[must_use]
    pub fn admin_host(&self) -> &str {
        self.admin_host.as_deref().unwrap_or(&self.domain)
    }

    /// The tunnel network.
    #[must_use]
    pub fn network(&self) -> Net4 {
        // Validated in `from_toml`; the fallback is never used.
        Net4::parse(&self.wireguard.network).unwrap_or(Net4 { addr: Ipv4Addr::new(10, 77, 0, 0), prefix: 16 })
    }

    /// `host:port` that devices use to reach the hub.
    #[must_use]
    pub fn wg_endpoint(&self) -> String {
        self.wireguard.endpoint.clone().unwrap_or_else(|| format!("{}:{}", self.admin_host(), self.wireguard.port))
    }

    /// HTTPS port as seen by browsers.
    #[must_use]
    pub fn https_port(&self) -> u16 {
        self.public_https_port.unwrap_or(self.listen_https.port())
    }

    /// `https://host[:port]` for a host served by this server.
    #[must_use]
    pub fn https_origin(&self, host: &str) -> String {
        match self.https_port() {
            443 => format!("https://{host}"),
            p => format!("https://{host}:{p}"),
        }
    }

    /// Expands a resource name: a bare label becomes `<label>.<domain>`.
    #[must_use]
    pub fn resource_host(&self, name: &str) -> Option<String> {
        let h = normalize_host(name)?;
        Some(if h.contains('.') { h } else { format!("{h}.{}", self.domain) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_config() {
        let c = Config::from_toml("domain = \"W.Example.com.\"\nacme_email = \"a@b.c\"\n").unwrap();
        assert_eq!(c.domain, "w.example.com");
        assert_eq!(c.admin_host(), "w.example.com");
        assert_eq!(c.wg_endpoint(), "w.example.com:51820");
        assert_eq!(c.network().server_ip(), Ipv4Addr::new(10, 77, 0, 1));
        assert_eq!(c.https_origin("x.w.example.com"), "https://x.w.example.com");
        assert_eq!(c.resource_host("App").as_deref(), Some("app.w.example.com"));
        assert_eq!(c.resource_host("my.other.org").as_deref(), Some("my.other.org"));
        assert_eq!(c.resource_host("bad_name"), None);
        assert!(c.update.check);
    }

    #[test]
    fn rejects_bad_configs() {
        assert!(Config::from_toml("domain = \"x.com\"\n").is_err(), "acme needs an e-mail");
        assert!(Config::from_toml("domain = \"x.com\"\nbogus = 1\n").is_err());
        let base = "domain = \"x.com\"\n[tls]\nmode = \"self-signed\"\n";
        assert!(Config::from_toml(base).is_ok());
        assert!(Config::from_toml(&format!("{base}[wireguard]\nnetwork = \"10.77.0.1/16\"\n")).is_err());
        assert!(Config::from_toml(&format!("{base}[wireguard]\nnetwork = \"10.0.0.0/31\"\n")).is_err());
        assert!(Config::from_toml("domain = \"x.com\"\n[tls]\nmode = \"files\"\n").is_err());
    }

    #[test]
    fn net4() {
        let n = Net4::parse("192.168.8.0/24").unwrap();
        assert!(n.contains(Ipv4Addr::new(192, 168, 8, 77)));
        assert!(!n.contains(Ipv4Addr::new(192, 168, 9, 1)));
        assert_eq!(n.mask(), 0xffff_ff00);
        assert_eq!(n.to_string(), "192.168.8.0/24");
    }
}
