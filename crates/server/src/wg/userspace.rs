//! Hub on boringtun and a TUN device, for hosts without the kernel module.
//!
//! Packets between devices never reach the kernel: they are decrypted here,
//! checked against the ACL (with a small connection table for replies) and
//! re-encrypted for the destination peer. Only packets addressed to the hub
//! itself are written to the TUN device, where the kernel's TCP stack serves
//! the proxy and the control channel.

use super::packet::ipv4_flow;
use super::{HubSpec, PeerSpec, PeerStats, WgError};
use crate::acl::Acl;
use crate::util::now;
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use warren_wgctl::{self as wg, AllowedIp};

const BUF: usize = 65_536;
/// Idle lifetime of a connection-table entry.
const FLOW_TTL: Duration = Duration::from_secs(300);
/// Upper bound on tracked flows; new flows are refused beyond it.
const MAX_FLOWS: usize = 65_536;
/// Handshakes per second before boringtun starts answering with cookies.
const HANDSHAKE_RATE: u64 = 100;

struct Peer {
    key: [u8; 32],
    ip: Ipv4Addr,
    /// Session index prefix; boringtun puts it in the top 24 bits.
    index: u32,
    tunn: Mutex<Tunn>,
    endpoint: Mutex<Option<SocketAddr>>,
}

impl Peer {
    fn tunn(&self) -> std::sync::MutexGuard<'_, Tunn> {
        self.tunn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn endpoint(&self) -> Option<SocketAddr> {
        *self.endpoint.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[derive(Default)]
struct Peers {
    keys: HashMap<[u8; 32], Arc<Peer>>,
    sessions: HashMap<u32, Arc<Peer>>,
    addresses: HashMap<Ipv4Addr, Arc<Peer>>,
}

/// (src, dst, proto, src port, dst port) of a flow the ACL allowed.
type FlowKey = (Ipv4Addr, Ipv4Addr, u8, u16, u16);

/// The userspace hub.
pub struct Userspace {
    iface: String,
    server_ip: Ipv4Addr,
    secret: StaticSecret,
    public: PublicKey,
    udp: Arc<UdpSocket>,
    tun: AsyncFd<OwnedFd>,
    limiter: Arc<RateLimiter>,
    peers: RwLock<Peers>,
    acl: RwLock<Acl>,
    flows: Mutex<HashMap<FlowKey, Instant>>,
    next_index: AtomicU32,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

/// Opens `/dev/net/tun` and attaches a TUN interface called `name`.
fn open_tun(name: &str) -> io::Result<OwnedFd> {
    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;

    let path = CString::new("/dev/net/tun").map_err(io::Error::other)?;
    // SAFETY: `path` is a valid NUL-terminated string.
    let raw = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a freshly opened descriptor that nothing else owns.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // struct ifreq: 16-byte name followed by a union whose first member is
    // the short `ifr_flags`; 40 bytes covers the whole struct.
    let mut ifr = [0u8; 40];
    let bytes = name.as_bytes();
    if bytes.len() >= 16 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "interface name too long"));
    }
    ifr[..bytes.len()].copy_from_slice(bytes);
    ifr[16..18].copy_from_slice(&(IFF_TUN | IFF_NO_PI).to_ne_bytes());
    // SAFETY: TUNSETIFF reads and writes a `struct ifreq`, which `ifr` is large enough to hold.
    if unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF as _, ifr.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

fn send(udp: &UdpSocket, data: &[u8], to: Option<SocketAddr>) {
    if let Some(to) = to {
        // UDP has no delivery guarantee anyway; drop on a full socket buffer.
        let _ = udp.try_send_to(data, to);
    }
}

impl Userspace {
    /// Creates the TUN interface, binds the UDP port and starts the packet tasks.
    pub fn start(spec: HubSpec) -> Result<Arc<Userspace>, WgError> {
        let tun = open_tun(&spec.iface).map_err(|source| WgError::Io { what: "creating TUN device", source })?;
        let addr = AllowedIp { addr: IpAddr::V4(spec.network.server_ip()), cidr: spec.network.prefix };
        wg::ensure_address(&spec.iface, addr, spec.mtu)?;
        // Packets the kernel would forward are not ours to route.
        wg::set_forwarding(&spec.iface, false)?;
        let std_udp = std::net::UdpSocket::bind(("0.0.0.0", spec.port))
            .and_then(|s| s.set_nonblocking(true).map(|()| s))
            .map_err(|source| WgError::Io { what: "binding WireGuard UDP port", source })?;
        let udp =
            UdpSocket::from_std(std_udp).map_err(|source| WgError::Io { what: "registering UDP socket", source })?;
        // SAFETY: `tun` is an OwnedFd, so the descriptor stays open and
        // unchanged until the AsyncFd that now owns it is dropped.
        let tun = unsafe { AsyncFd::register(tun) }
            .map_err(|e| WgError::Io { what: "registering TUN device", source: e.into() })?;
        let secret = StaticSecret::from(spec.private_key);
        let public = PublicKey::from(&secret);
        let hub = Arc::new(Userspace {
            iface: spec.iface,
            server_ip: spec.network.server_ip(),
            limiter: Arc::new(RateLimiter::new(&public, HANDSHAKE_RATE)),
            secret,
            public,
            udp: Arc::new(udp),
            tun,
            peers: RwLock::new(Peers::default()),
            acl: RwLock::new(Acl::default()),
            flows: Mutex::new(HashMap::new()),
            next_index: AtomicU32::new(1),
            tasks: Mutex::new(Vec::new()),
        });
        let tasks = vec![
            tokio::spawn(Arc::clone(&hub).udp_loop()),
            tokio::spawn(Arc::clone(&hub).tun_loop()),
            tokio::spawn(Arc::clone(&hub).timer_loop()),
        ];
        *hub.tasks.lock().unwrap_or_else(PoisonError::into_inner) = tasks;
        tracing::info!(iface = %hub.iface, port = spec.port, "userspace WireGuard hub up");
        Ok(hub)
    }

    fn peers(&self) -> std::sync::RwLockReadGuard<'_, Peers> {
        self.peers.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Replaces the peer set, keeping sessions of unchanged peers.
    pub fn apply(&self, specs: &[PeerSpec], acl: &Acl) {
        let mut next = Peers::default();
        {
            let old = self.peers();
            for s in specs {
                let peer = match old.keys.get(&s.key) {
                    Some(p) if p.ip == s.ip => Arc::clone(p),
                    _ => {
                        let index = self.next_index.fetch_add(1, Ordering::Relaxed) & 0x00ff_ffff;
                        let tunn = Tunn::new(
                            self.secret.clone(),
                            PublicKey::from(s.key),
                            None,
                            None,
                            index,
                            Some(Arc::clone(&self.limiter)),
                        );
                        Arc::new(Peer {
                            key: s.key,
                            ip: s.ip,
                            index,
                            tunn: Mutex::new(tunn),
                            endpoint: Mutex::new(None),
                        })
                    }
                };
                next.sessions.insert(peer.index, Arc::clone(&peer));
                next.addresses.insert(peer.ip, Arc::clone(&peer));
                next.keys.insert(peer.key, peer);
            }
        }
        *self.peers.write().unwrap_or_else(PoisonError::into_inner) = next;
        *self.acl.write().unwrap_or_else(PoisonError::into_inner) = acl.clone();
    }

    /// Per-peer handshake time and traffic counters.
    pub fn stats(&self) -> HashMap<[u8; 32], PeerStats> {
        let t = now();
        self.peers()
            .keys
            .values()
            .map(|p| {
                let (since, tx, rx, _, _) = p.tunn().stats();
                let last_handshake = since.and_then(|d| i64::try_from(d.as_secs()).ok()).map(|s| t - s);
                let stats = PeerStats {
                    last_handshake,
                    rx_bytes: u64::try_from(rx).unwrap_or(u64::MAX),
                    tx_bytes: u64::try_from(tx).unwrap_or(u64::MAX),
                    endpoint: p.endpoint(),
                };
                (p.key, stats)
            })
            .collect()
    }

    /// Stops the packet tasks; the TUN interface disappears with its descriptor.
    pub fn shutdown(&self) {
        for t in self.tasks.lock().unwrap_or_else(PoisonError::into_inner).drain(..) {
            t.abort();
        }
    }

    fn find_peer(&self, datagram: &[u8]) -> Option<Arc<Peer>> {
        let peers = self.peers();
        match Tunn::parse_incoming_packet(datagram).ok()? {
            Packet::HandshakeInit(h) => {
                let half = parse_handshake_anon(&self.secret, &self.public, &h).ok()?;
                peers.keys.get(&half.peer_static_public).cloned()
            }
            Packet::HandshakeResponse(p) => peers.sessions.get(&(p.receiver_idx >> 8)).cloned(),
            Packet::PacketCookieReply(p) => peers.sessions.get(&(p.receiver_idx >> 8)).cloned(),
            Packet::PacketData(p) => peers.sessions.get(&(p.receiver_idx >> 8)).cloned(),
        }
    }

    async fn udp_loop(self: Arc<Self>) {
        let mut buf = vec![0u8; BUF];
        let mut out = vec![0u8; BUF];
        loop {
            let (n, src) = match self.udp.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, "WireGuard UDP receive failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            // Cheap MAC checks (and cookie replies under load) before any
            // public-key work, so forged handshakes cannot pin this loop.
            match self.limiter.verify_packet(Some(src.ip()), &buf[..n], &mut out) {
                Ok(_) => {}
                Err(TunnResult::WriteToNetwork(cookie)) => {
                    send(&self.udp, cookie, Some(src));
                    continue;
                }
                Err(_) => continue,
            }
            let Some(peer) = self.find_peer(&buf[..n]) else { continue };
            let mut tunn = peer.tunn();
            match tunn.decapsulate(Some(src.ip()), &buf[..n], &mut out) {
                TunnResult::WriteToNetwork(p) => {
                    send(&self.udp, p, Some(src));
                    // Flush packets queued while the handshake was pending.
                    while let TunnResult::WriteToNetwork(p) = tunn.decapsulate(None, &[], &mut out) {
                        send(&self.udp, p, Some(src));
                    }
                    *peer.endpoint.lock().unwrap_or_else(PoisonError::into_inner) = Some(src);
                }
                TunnResult::WriteToTunnelV4(p, from) => {
                    // Cryptokey routing: a peer may only send from its own address.
                    if from == peer.ip {
                        *peer.endpoint.lock().unwrap_or_else(PoisonError::into_inner) = Some(src);
                        let packet = p.to_vec();
                        drop(tunn);
                        self.route(&peer, &packet, &mut out);
                    }
                }
                TunnResult::WriteToTunnelV6(..) | TunnResult::Done | TunnResult::Err(_) => {}
            }
        }
    }

    /// Delivers a decrypted packet from `from` to the hub or another peer.
    fn route(&self, from: &Peer, packet: &[u8], out: &mut [u8]) {
        let Some(flow) = ipv4_flow(packet) else { return };
        if flow.dst == self.server_ip {
            // A full TUN queue means the kernel is overloaded; drop like a router would.
            // SAFETY: `packet` is a valid buffer of `packet.len()` bytes.
            let _ = unsafe { libc::write(self.tun.get_ref().as_raw_fd(), packet.as_ptr().cast(), packet.len()) };
            return;
        }
        let Some(to) = self.peers().addresses.get(&flow.dst).cloned() else { return };
        let (sport, dport) = flow.ports.unwrap_or((0, 0));
        let key = (flow.src, flow.dst, flow.proto, sport, dport);
        let reverse = (flow.dst, flow.src, flow.proto, dport, sport);
        let allowed = {
            let mut flows = self.flows.lock().unwrap_or_else(PoisonError::into_inner);
            let now = Instant::now();
            let live = |k: &FlowKey, flows: &HashMap<FlowKey, Instant>| {
                flows.get(k).is_some_and(|t| now.duration_since(*t) < FLOW_TTL)
            };
            if live(&reverse, &flows) {
                flows.insert(reverse, now);
                true
            } else if live(&key, &flows) {
                flows.insert(key, now);
                true
            } else if self.acl.read().unwrap_or_else(PoisonError::into_inner).allows(
                from.ip,
                flow.dst,
                flow.proto,
                flow.ports.map(|p| p.1),
            ) {
                // A new flow: keep the table bounded against port sweeps.
                if flows.len() >= MAX_FLOWS {
                    flows.retain(|_, t| now.duration_since(*t) < FLOW_TTL);
                }
                let room = flows.len() < MAX_FLOWS;
                if room {
                    flows.insert(key, now);
                }
                room
            } else {
                false
            }
        };
        if allowed {
            self.encapsulate(&to, packet, out);
        }
    }

    fn encapsulate(&self, to: &Peer, packet: &[u8], out: &mut [u8]) {
        let endpoint = to.endpoint();
        if let TunnResult::WriteToNetwork(p) = to.tunn().encapsulate(packet, out) {
            send(&self.udp, p, endpoint);
        }
    }

    async fn tun_loop(self: Arc<Self>) {
        let mut buf = vec![0u8; BUF];
        let mut out = vec![0u8; BUF];
        loop {
            let Ok(mut guard) = self.tun.readable().await else { return };
            let fd = self.tun.get_ref().as_raw_fd();
            // SAFETY: `buf` is a valid writable buffer of `buf.len()` bytes.
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
            let Ok(n) = usize::try_from(n) else {
                let e = io::Error::last_os_error();
                guard.clear_ready();
                if e.kind() != io::ErrorKind::WouldBlock {
                    tracing::warn!(error = %e, "reading from the TUN device");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                continue;
            };
            let Some(flow) = ipv4_flow(&buf[..n]) else { continue };
            let Some(peer) = self.peers().addresses.get(&flow.dst).cloned() else { continue };
            self.encapsulate(&peer, &buf[..n], &mut out);
        }
    }

    async fn timer_loop(self: Arc<Self>) {
        let mut out = vec![0u8; BUF];
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        let mut n: u32 = 0;
        loop {
            tick.tick().await;
            n = n.wrapping_add(1);
            let peers: Vec<Arc<Peer>> = self.peers().keys.values().cloned().collect();
            for p in peers {
                let endpoint = p.endpoint();
                if let TunnResult::WriteToNetwork(pkt) = p.tunn().update_timers(&mut out) {
                    send(&self.udp, pkt, endpoint);
                }
            }
            if n.is_multiple_of(4) {
                self.limiter.reset_count();
            }
            if n.is_multiple_of(120) {
                let now = Instant::now();
                self.flows
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .retain(|_, t| now.duration_since(*t) < FLOW_TTL);
            }
        }
    }
}
