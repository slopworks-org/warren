//! Direct paths to devices on the same LAN.
//!
//! The server lists such devices as LAN peers. Each one gets a short
//! keepalive but no allowed IPs, so WireGuard keeps a session with it and
//! routes nothing there. A watcher thread gives a LAN peer its tunnel address
//! while packets keep arriving from it and takes the address away when they
//! stop. A failed peer is removed for a retry interval to clear its session
//! and stop keepalives that could keep the remote direct route alive. Traffic
//! to that device then goes through the server again, whose peer covers the
//! whole tunnel network.

use crate::log;
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};
use warren_wgctl::{self as wg, AllowedIp, DeviceSet, Key, PeerSet};

const TICK: Duration = Duration::from_secs(2);
/// Silence after which a direct path counts as broken: a few missed
/// [`warren_proto::LAN_KEEPALIVE`]s.
const SILENCE: Duration = Duration::from_secs(25);
/// WireGuard drops a session this long after its handshake. Handshake
/// messages count as received bytes, so traffic alone does not prove that
/// the path works both ways; a completed handshake does.
const SESSION: Duration = Duration::from_secs(180);
// Stop all direct transmissions long enough for the remote silence timer,
// including a watcher tick, to expire before probing with fresh session keys.
const RETRY: Duration = Duration::from_secs(30);
const MAX_ADDRESSES: usize = 8;
/// Bridges and links of containers and VMs. Their addresses repeat on every
/// host that runs the same software, so they do not identify a LAN.
const VIRTUAL_PREFIXES: &[&str] = &["docker", "veth", "virbr", "vnet", "cni", "flannel", "podman", "lxc", "lxd"];

#[derive(Clone)]
struct Peer {
    probe: PeerSet,
    removed: Option<Instant>,
    ips: Vec<AllowedIp>,
    direct: bool,
    rx: Option<u64>,
    heard: Option<Instant>,
}

impl Peer {
    /// Records the peer's received-byte counter and the age of its last
    /// handshake; returns true when the peer must gain or lose its route.
    fn observe(&mut self, rx: u64, handshake: Option<Duration>, now: Instant) -> bool {
        // The counter restarts at zero when the interface is recreated.
        if self.rx.is_some_and(|old| rx > old) {
            self.heard = Some(now);
        }
        self.rx = Some(rx);
        let alive =
            self.heard.is_some_and(|t| now.duration_since(t) < SILENCE) && handshake.is_some_and(|a| a < SESSION);
        let changed = alive != self.direct;
        self.direct = alive;
        changed
    }

    fn update(&mut self, info: Option<&wg::PeerInfo>, now: Instant) -> Option<PeerSet> {
        if let Some(removed) = self.removed {
            if now.duration_since(removed) < RETRY {
                return None;
            }
            self.removed = None;
            self.rx = None;
            self.heard = None;
            let mut probe = self.probe.clone();
            probe.allowed_ips = Some(Vec::new());
            return Some(probe);
        }
        let handshake = info.and_then(|i| i.last_handshake).and_then(|t| SystemTime::now().duration_since(t).ok());
        if !self.observe(info.map_or(0, |i| i.rx_bytes), handshake, now) {
            return None;
        }
        if self.direct {
            Some(PeerSet { public_key: self.probe.public_key, allowed_ips: Some(self.routed()), ..PeerSet::default() })
        } else {
            // Removing only AllowedIPs leaves keepalives flowing in the working
            // direction. The other end would retain its /32 and reject packets
            // from this device forwarded by the hub (source validation).
            // Delete the session too, so neither old keys nor keepalives can
            // preserve that asymmetric ownership during the retry interval.
            self.removed = Some(now);
            Some(PeerSet { public_key: self.probe.public_key, remove: true, ..PeerSet::default() })
        }
    }

    fn routed(&self) -> Vec<AllowedIp> {
        if self.direct { self.ips.clone() } else { Vec::new() }
    }
}

/// LAN peers of the interface and whether each one is reached directly.
pub struct Links {
    iface: String,
    peers: BTreeMap<Key, Peer>,
}

static LINKS: Mutex<Links> = Mutex::new(Links { iface: String::new(), peers: BTreeMap::new() });

/// Hold the guard while changing the interface's peers, so the watcher does
/// not change them at the same time.
pub fn lock() -> MutexGuard<'static, Links> {
    LINKS.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Links {
    /// Starts tracking `peers` of `iface` and forgets all others.
    pub fn track(&mut self, iface: &str, peers: Vec<PeerSet>) {
        if self.iface != iface {
            self.iface = iface.to_string();
            self.peers.clear();
        }
        self.peers.retain(|k, _| peers.iter().any(|p| p.public_key == *k));
        for probe in peers {
            let p = self.peers.entry(probe.public_key).or_insert(Peer {
                probe: probe.clone(),
                removed: None,
                ips: Vec::new(),
                direct: false,
                rx: None,
                heard: None,
            });
            p.ips = probe.allowed_ips.clone().unwrap_or_default();
            p.probe = probe;
        }
    }

    /// Whether a failed peer must remain absent to let the remote fall back.
    pub fn suspended(&self, key: &Key) -> bool {
        self.peers.get(key).is_some_and(|p| p.removed.is_some())
    }

    /// Allowed IPs the LAN peer `key` must have now.
    pub fn routed(&self, key: &Key) -> Vec<AllowedIp> {
        self.peers.get(key).map(Peer::routed).unwrap_or_default()
    }

    /// Routes LAN peers whose direct path came up and unroutes those whose path went down.
    fn tick(&mut self) {
        if self.peers.is_empty() {
            return;
        }
        let Ok(dev) = wg::get_device(&self.iface) else { return };
        let now = Instant::now();
        let mut set = DeviceSet::default();
        let previous = self.peers.clone();
        for (key, p) in &mut self.peers {
            let info = dev.peers.iter().find(|i| i.public_key == *key);
            if let Some(change) = p.update(info, now) {
                log!(Info, "updating direct LAN path", direct = p.direct, removed = change.remove);
                set.peers.push(change);
            }
        }
        if !set.peers.is_empty()
            && let Err(e) = wg::set_device(&self.iface, &set)
        {
            log!(Warn, "cannot update LAN routes", error = e);
            self.peers = previous;
        }
    }
}

/// Starts the thread that switches LAN peers between direct and through the server.
pub fn spawn_watcher() {
    let started = std::thread::Builder::new().name("lan".into()).spawn(|| {
        while !crate::stopping() {
            std::thread::sleep(TICK);
            lock().tick();
        }
    });
    if let Err(e) = started {
        log!(Warn, "cannot watch LAN peers", error = e);
    }
}

fn is_virtual(name: &str) -> bool {
    // Docker names its user-defined bridges br-<12 hex digits>; OpenWrt's br-lan is real.
    let docker_bridge =
        name.strip_prefix("br-").is_some_and(|id| id.len() == 12 && id.bytes().all(|b| b.is_ascii_hexdigit()));
    docker_bridge || VIRTUAL_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Private IPv4 addresses of this host's physical interfaces, other than `skip`.
pub fn addresses(skip: &str) -> Vec<AllowedIp> {
    let mut out = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: on success getifaddrs stores a list that is freed below.
    if unsafe { libc::getifaddrs(&raw mut head) } != 0 {
        return out;
    }
    let want = (libc::IFF_UP | libc::IFF_RUNNING).unsigned_abs();
    let refuse = (libc::IFF_LOOPBACK | libc::IFF_POINTOPOINT).unsigned_abs();
    let mut cur = head;
    while !cur.is_null() && out.len() < MAX_ADDRESSES {
        // SAFETY: `cur` is a non-null node of the list getifaddrs returned.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null()
            || ifa.ifa_netmask.is_null()
            || ifa.ifa_flags & want != want
            || ifa.ifa_flags & refuse != 0
        {
            continue;
        }
        // SAFETY: ifa_addr is non-null and points to a sockaddr.
        if i32::from(unsafe { (*ifa.ifa_addr).sa_family }) != libc::AF_INET {
            continue;
        }
        // SAFETY: ifa_name is a NUL-terminated string owned by the list.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }.to_string_lossy();
        if name == skip || is_virtual(&name) {
            continue;
        }
        // SAFETY: both point to sockaddr_in for an AF_INET entry.
        let (addr, mask) = unsafe {
            let a = &*ifa.ifa_addr.cast::<libc::sockaddr_in>();
            let m = &*ifa.ifa_netmask.cast::<libc::sockaddr_in>();
            (Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)), u32::from_be(m.sin_addr.s_addr))
        };
        if addr.is_private() {
            #[expect(clippy::cast_possible_truncation, reason = "count_ones of a u32 is at most 32")]
            let cidr = mask.count_ones() as u8;
            out.push(AllowedIp { addr: IpAddr::V4(addr), cidr });
        }
    }
    // SAFETY: `head` came from a successful getifaddrs and is freed once.
    unsafe { libc::freeifaddrs(head) };
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(key: Key, ip: AllowedIp) -> PeerSet {
        PeerSet { public_key: key, allowed_ips: Some(vec![ip]), keepalive: Some(5), ..PeerSet::default() }
    }

    #[test]
    fn fallback_deletes_session_and_config_cannot_resurrect_it() {
        let now = Instant::now();
        let mut links = Links { iface: String::new(), peers: BTreeMap::new() };
        let config = probe([1; 32], "10.77.0.5/32".parse().unwrap());
        links.track("wg0", vec![config.clone()]);
        let p = links.peers.get_mut(&[1; 32]).unwrap();
        p.direct = true;
        p.heard = Some(now);
        p.rx = Some(100);
        let info = wg::PeerInfo { rx_bytes: 100, last_handshake: Some(SystemTime::now()), ..wg::PeerInfo::default() };
        let down = now + SILENCE;
        assert!(p.update(Some(&info), down).unwrap().remove);
        assert_eq!(p.routed(), vec![]);
        links.track("wg0", vec![config]);
        assert!(links.suspended(&[1; 32]));
        let p = links.peers.get_mut(&[1; 32]).unwrap();
        assert!(p.update(None, (down + RETRY).checked_sub(TICK).unwrap()).is_none());
        let retry = p.update(None, down + RETRY).unwrap();
        assert!(!retry.remove);
        assert_eq!(retry.allowed_ips, Some(vec![]));
        assert_eq!(retry.keepalive, Some(5));
        assert!(p.rx.is_none() && p.heard.is_none());
        assert!(p.update(Some(&wg::PeerInfo::default()), down + RETRY + TICK).is_none());
        assert!(!p.direct);
    }

    #[test]
    fn peer_is_direct_while_it_is_heard() {
        let t0 = Instant::now();
        let mut p = Peer {
            probe: PeerSet::default(),
            removed: None,
            ips: vec!["10.77.0.5/32".parse().unwrap()],
            direct: false,
            rx: None,
            heard: None,
        };
        let hs = Some(Duration::from_secs(5));
        assert!(!p.observe(500, hs, t0), "the first reading is only a baseline");
        assert!(!p.observe(500, hs, t0 + TICK));
        assert!(!p.observe(600, None, t0 + 2 * TICK), "handshake messages alone are not a working path");
        assert!(p.observe(700, hs, t0 + 3 * TICK) && p.direct);
        assert_eq!(p.routed(), p.ips);
        assert!(!p.observe(700, hs, t0 + 2 * TICK + SILENCE));
        assert!(p.observe(700, hs, t0 + 3 * TICK + SILENCE) && !p.direct);
        assert_eq!(p.routed(), Vec::new());
        assert!(!p.observe(0, hs, t0 + 20 * TICK), "a counter reset is not traffic");
        assert!(p.observe(90, hs, t0 + 21 * TICK) && p.direct);
        assert!(p.observe(95, Some(SESSION), t0 + 22 * TICK) && !p.direct, "the session expired");
    }

    #[test]
    fn track_keeps_state_of_known_peers() {
        let ip: AllowedIp = "10.77.0.5/32".parse().unwrap();
        let mut links = Links { iface: String::new(), peers: BTreeMap::new() };
        links.track("wg0", vec![probe([1; 32], ip), probe([2; 32], ip)]);
        links.peers.get_mut(&[1; 32]).unwrap().direct = true;
        links.track("wg0", vec![probe([1; 32], ip)]);
        assert_eq!(links.routed(&[1; 32]), vec![ip]);
        assert!(links.routed(&[2; 32]).is_empty() && links.peers.len() == 1);
        links.track("wg1", vec![probe([1; 32], ip)]);
        assert!(links.routed(&[1; 32]).is_empty(), "another interface starts over");
    }

    #[test]
    fn virtual_interfaces() {
        for name in ["docker0", "br-3f2a9c1d7e4b", "veth12ab", "virbr0"] {
            assert!(is_virtual(name), "{name}");
        }
        for name in ["br-lan", "eth0", "en0", "wlan0", "br0"] {
            assert!(!is_virtual(name), "{name}");
        }
    }

    #[test]
    fn addresses_are_private_ipv4() {
        for a in addresses("") {
            assert!(matches!(a.addr, IpAddr::V4(v4) if v4.is_private()), "{a}");
        }
    }
}
