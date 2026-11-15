//! Independent direct LAN paths with round-trip liveness and hub fallback.

use crate::{log, mesh_probe};
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use warren_wgctl::{self as wg, AllowedIp, Key};

const TICK: Duration = Duration::from_secs(2);
const MAX_ADDRESSES: usize = 8;
const VIRTUAL_PREFIXES: &[&str] = &["docker", "veth", "virbr", "vnet", "cni", "flannel", "podman", "lxc", "lxd"];

/// Stable auxiliary interface name, within Linux's 15-byte limit.
pub fn interface(hub: &str) -> String {
    let hash = hub.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3));
    format!("wm{:012x}", hash & 0xffff_ffff_ffff)
}

struct Peer {
    ip: Ipv4Addr,
    direct: bool,
    probe: mesh_probe::Probe,
}

/// LAN peers, whose inbound authentication never changes with route choice.
pub struct Links {
    iface: String,
    source: Option<Ipv4Addr>,
    socket: Option<UdpSocket>,
    peers: BTreeMap<Key, Peer>,
}

static LINKS: Mutex<Links> =
    Mutex::new(Links { iface: String::new(), source: None, socket: None, peers: BTreeMap::new() });

/// Serializes configuration and route changes against the watcher.
pub fn lock() -> MutexGuard<'static, Links> {
    LINKS.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Links {
    /// Tracks the configured direct peers and removes stale application routes.
    pub fn track(&mut self, iface: &str, source: Ipv4Addr, peers: Vec<(Key, Ipv4Addr)>) -> wg::Result<()> {
        let reset = self.iface != iface || self.source != Some(source);
        for (key, peer) in &self.peers {
            if peer.direct && (reset || !peers.contains(&(*key, peer.ip))) {
                wg::host_route(&self.iface, peer.ip.into(), self.source.unwrap_or(source).into(), false)?;
            }
        }
        if reset {
            self.peers.clear();
            self.socket = None;
        }
        self.iface = iface.to_string();
        self.source = Some(source);
        self.peers.retain(|key, peer| peers.contains(&(*key, peer.ip)));
        for (key, ip) in peers {
            self.peers.entry(key).or_insert(Peer { ip, direct: false, probe: mesh_probe::Probe::default() });
        }
        if self.socket.is_none() {
            match mesh_probe::socket(source) {
                Ok(socket) => self.socket = Some(socket),
                Err(error) => log!(Warn, "cannot listen for direct path probes", error = error),
            }
        }
        Ok(())
    }

    fn tick(&mut self) {
        let (Some(socket), Some(source)) = (&self.socket, self.source) else { return };
        let now = Instant::now();
        mesh_probe::drain(socket, |sender, packet| {
            if let Some(peer) = self.peers.values_mut().find(|p| sender.ip() == IpAddr::V6(mesh_probe::address(p.ip))) {
                mesh_probe::reply(socket, sender, packet);
                peer.probe.receive(packet, now);
            }
        });
        for peer in self.peers.values_mut() {
            let alive = peer.probe.alive(now);
            if alive != peer.direct {
                match wg::host_route(&self.iface, peer.ip.into(), source.into(), alive) {
                    Ok(()) => {
                        peer.direct = alive;
                        let msg =
                            if alive { "direct LAN path up" } else { "direct LAN path down; going through the server" };
                        log!(Info, msg, peer = peer.ip);
                    }
                    Err(error) => log!(Warn, "cannot update direct LAN route", error = error),
                }
            }
            peer.probe.send(socket, peer.ip, now);
        }
    }
}

/// Starts the direct path responder and route watcher.
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
