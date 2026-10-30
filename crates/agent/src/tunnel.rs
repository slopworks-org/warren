//! Applying the server's desired state to the kernel WireGuard interface.

use crate::error::{Error, Result};
use crate::lan;
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

/// Whether `key` is the public key of `p`.
pub fn same_key(p: &PeerConfig, key: &[u8; 32]) -> bool {
    peer_key(p).is_ok_and(|k| k == *key)
}

fn allowed_ips(p: &PeerConfig) -> Result<Vec<AllowedIp>> {
    p.allowed_ips.iter().map(|s| parse_ip(s)).collect()
}

fn peer_set(p: &PeerConfig, allowed: Vec<AllowedIp>) -> Result<PeerSet> {
    Ok(PeerSet {
        public_key: peer_key(p)?,
        endpoint: resolve(&p.endpoint),
        keepalive: Some(p.keepalive),
        allowed_ips: Some(allowed),
        remove: false,
    })
}

/// Creates the interface if needed and makes it match `saved`.
///
/// Peers are updated in place rather than replaced, so a config change does
/// not drop established sessions. LAN peers get their addresses only while
/// [`lan`] finds the direct path working.
pub fn apply(saved: &Saved, key: &[u8; 32]) -> Result<()> {
    let iface = saved.interface.as_str();
    if wg::link_index(iface).is_none() {
        wg::create_wireguard_link(iface)?;
        crate::log!(Info, "created interface", iface = iface);
    }
    let current = wg::get_device(iface)?;
    let mut set = DeviceSet { private_key: Some(*key), ..DeviceSet::default() };
    for p in &saved.tunnel.peers {
        set.peers.push(peer_set(p, allowed_ips(p)?)?);
    }
    let mut lan_peers = Vec::new();
    for p in &saved.tunnel.lan_peers {
        lan_peers.push(peer_set(p, allowed_ips(p)?)?);
    }
    let mut links = lan::lock();
    links.track(iface, lan_peers);
    for p in &saved.tunnel.lan_peers {
        if !links.suspended(&peer_key(p)?) {
            set.peers.push(peer_set(p, links.routed(&peer_key(p)?))?);
        }
    }
    let wanted: Vec<_> = set.peers.iter().map(|p| p.public_key).collect();
    for old in current.peers.iter().filter(|p| !wanted.contains(&p.public_key)) {
        set.peers.push(PeerSet { public_key: old.public_key, remove: true, ..PeerSet::default() });
    }
    wg::set_device(iface, &set)?;
    drop(links);
    wg::ensure_address(iface, parse_ip(&saved.tunnel.address)?, saved.mtu)?;
    Ok(())
}

/// Age of the most recent handshake with a configured server peer.
pub fn handshake_age(dev: &DeviceInfo, servers: &[PeerConfig]) -> Option<Duration> {
    let latest = dev
        .peers
        .iter()
        .filter(|p| servers.iter().any(|s| peer_key(s).is_ok_and(|k| k == p.public_key)))
        .filter_map(|p| p.last_handshake)
        .max()?;
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
    fn lan_handshakes_do_not_mask_a_stale_server() {
        let servers = vec![PeerConfig {
            public_key: codec::encode_key(&[1; 32]),
            endpoint: String::new(),
            allowed_ips: vec![],
            keepalive: 0,
        }];
        let mut dev = DeviceInfo::default();
        assert_eq!(handshake_age(&dev, &servers), None);
        dev.peers.push(wg::PeerInfo {
            public_key: [2; 32],
            last_handshake: Some(SystemTime::now()),
            ..wg::PeerInfo::default()
        });
        assert_eq!(handshake_age(&dev, &servers), None);
        dev.peers.push(wg::PeerInfo {
            public_key: [1; 32],
            last_handshake: Some(SystemTime::now() - Duration::from_secs(300)),
            ..wg::PeerInfo::default()
        });
        assert!(handshake_age(&dev, &servers).unwrap() >= Duration::from_secs(300));
        dev.peers[1].last_handshake = Some(SystemTime::now());
        assert!(handshake_age(&dev, &servers).unwrap() < Duration::from_secs(1));
    }
}
