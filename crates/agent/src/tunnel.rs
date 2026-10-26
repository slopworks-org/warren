//! Applying the server's desired state to the kernel WireGuard interface.

use crate::error::{Error, Result};
use crate::state::Saved;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, SystemTime};
use warren_proto::{PeerConfig, codec};
use warren_wgctl::{self as wg, AllowedIp, DeviceInfo, DeviceSet, PeerSet};

/// Resolves `host:port`, preferring IPv4 (most CGNAT links lack IPv6).
pub fn resolve(endpoint: &str) -> Option<SocketAddr> {
    if endpoint.is_empty() {
        return None;
    }
    let addrs: Vec<SocketAddr> = endpoint.to_socket_addrs().ok()?.collect();
    addrs.iter().find(|a| a.is_ipv4()).or_else(|| addrs.first()).copied()
}

fn peer_key(p: &PeerConfig) -> Result<[u8; 32]> {
    codec::decode_key(&p.public_key).ok_or(Error::InvalidConfig("invalid peer key"))
}

fn parse_ip(s: &str) -> Result<AllowedIp> {
    s.parse().map_err(|_| Error::InvalidConfig("invalid address"))
}

/// Creates the interface if needed and makes it match `saved`.
///
/// Peers are updated in place rather than replaced, so a config change does
/// not drop established sessions.
pub fn apply(saved: &Saved, key: &[u8; 32]) -> Result<()> {
    let iface = saved.interface.as_str();
    if wg::link_index(iface).is_none() {
        wg::create_wireguard_link(iface)?;
        crate::log!(Info, "created interface", iface = iface);
    }
    let current = wg::get_device(iface)?;
    let mut set = DeviceSet { private_key: Some(*key), ..DeviceSet::default() };
    let mut wanted = Vec::new();
    for p in &saved.tunnel.peers {
        let public_key = peer_key(p)?;
        wanted.push(public_key);
        let allowed = p.allowed_ips.iter().map(|s| parse_ip(s)).collect::<Result<Vec<_>>>()?;
        set.peers.push(PeerSet {
            public_key,
            endpoint: resolve(&p.endpoint),
            keepalive: Some(p.keepalive),
            allowed_ips: Some(allowed),
            remove: false,
        });
    }
    for old in current.peers.iter().filter(|p| !wanted.contains(&p.public_key)) {
        set.peers.push(PeerSet { public_key: old.public_key, remove: true, ..PeerSet::default() });
    }
    wg::set_device(iface, &set)?;
    wg::ensure_address(iface, parse_ip(&saved.tunnel.address)?, saved.mtu)?;
    Ok(())
}

/// Age of the most recent handshake with any peer.
pub fn handshake_age(dev: &DeviceInfo) -> Option<Duration> {
    let latest = dev.peers.iter().filter_map(|p| p.last_handshake).max()?;
    SystemTime::now().duration_since(latest).ok()
}

/// Re-resolves peer endpoints and updates any whose address changed, for
/// servers behind dynamic DNS. Returns how many peers were updated.
pub fn refresh_endpoints(saved: &Saved, dev: &DeviceInfo) -> Result<usize> {
    let mut set = DeviceSet::default();
    for p in &saved.tunnel.peers {
        let key = peer_key(p)?;
        let Some(fresh) = resolve(&p.endpoint) else { continue };
        let current = dev.peers.iter().find(|c| c.public_key == key).and_then(|c| c.endpoint);
        if current != Some(fresh) {
            crate::log!(Info, "peer endpoint changed", endpoint = p.endpoint, addr = fresh);
            set.peers.push(PeerSet { public_key: key, endpoint: Some(fresh), ..PeerSet::default() });
        }
    }
    if !set.peers.is_empty() {
        wg::set_device(&saved.interface, &set)?;
    }
    Ok(set.peers.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_prefers_literal_addresses() {
        assert_eq!(resolve("127.0.0.1:51820"), Some("127.0.0.1:51820".parse().unwrap()));
        assert_eq!(resolve(""), None);
        assert_eq!(resolve("no-port"), None);
    }

    #[test]
    fn handshake_age_uses_latest_peer() {
        let mut dev = DeviceInfo::default();
        assert_eq!(handshake_age(&dev), None);
        dev.peers.push(wg::PeerInfo {
            last_handshake: Some(SystemTime::now() - Duration::from_secs(30)),
            ..wg::PeerInfo::default()
        });
        assert!(handshake_age(&dev).unwrap() >= Duration::from_secs(30));
    }
}
