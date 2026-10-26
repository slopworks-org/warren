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
/// TCP port of the control channel on the server's tunnel address.
pub const DEFAULT_CTL_PORT: u16 = 7180;
/// Default UDP port of the WireGuard hub.
pub const DEFAULT_WG_PORT: u16 = 51820;
/// Keepalive the agent asks the kernel for, so NAT mappings stay open.
pub const DEFAULT_KEEPALIVE: u16 = 25;
/// How long the server holds a config long-poll open, in seconds.
pub const LONG_POLL_SECS: u64 = 50;

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
}

impl AgentConfig {
    /// Serializes into `kv` pairs; peers become repeated `peer` lines.
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
            let endpoint = if p.endpoint.is_empty() { "-" } else { &p.endpoint };
            kv.push("peer", format!("{} {} {} {}", p.public_key, endpoint, p.allowed_ips.join(","), p.keepalive));
        }
    }

    /// Parses a config written by [`AgentConfig::write_kv`]; other keys are ignored.
    ///
    /// # Errors
    /// When a field is missing or malformed.
    pub fn from_kv(kv: &Kv) -> Result<Self, Error> {
        let mut peers = Vec::new();
        for line in kv.get_all("peer") {
            let mut it = line.split(' ');
            let (Some(key), Some(ep), Some(ips), Some(ka), None) =
                (it.next(), it.next(), it.next(), it.next(), it.next())
            else {
                return Err(Error::BadField("peer"));
            };
            codec::decode_key(key).ok_or(Error::BadField("peer"))?;
            peers.push(PeerConfig {
                public_key: key.to_string(),
                endpoint: if ep == "-" { String::new() } else { ep.to_string() },
                allowed_ips: ips.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect(),
                keepalive: ka.parse().map_err(|_| Error::BadField("peer"))?,
            });
        }
        Ok(AgentConfig {
            version: kv.parse_field("version")?,
            device_id: kv.parse_field("device_id")?,
            name: kv.req("name")?.to_string(),
            address: kv.req("address")?.to_string(),
            control: kv.req("control")?.to_string(),
            peers,
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
        };
        let text = cfg.to_kv().encode();
        let back = AgentConfig::from_kv(&Kv::parse(&text).unwrap()).unwrap();
        assert_eq!(cfg, back);
        let mut kv = Kv::parse(&text).unwrap();
        kv.push("peer", "notakey - x 1");
        assert_eq!(AgentConfig::from_kv(&kv), Err(Error::BadField("peer")));
        assert_eq!(AgentConfig::from_kv(&Kv::new()), Err(Error::MissingField("version")));
    }
}
