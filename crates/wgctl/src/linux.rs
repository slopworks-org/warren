//! Linux implementation over raw netlink sockets.

use crate::{AllowedIp, DeviceInfo, DeviceSet, PeerInfo, PeerSet};
use std::ffi::CString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, SystemTime};

const NLMSG_HDR_LEN: usize = 16;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLA_F_NESTED: u16 = 0x8000;
const NLA_TYPE_MASK: u16 = 0x3fff;

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_GETADDR: u16 = 22;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFF_UP: u32 = 1;

const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

const WG_CMD_GET_DEVICE: u8 = 0;
const WG_CMD_SET_DEVICE: u8 = 1;
const WGDEVICE_A_IFNAME: u16 = 2;
const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
const WGDEVICE_A_PUBLIC_KEY: u16 = 4;
const WGDEVICE_A_FLAGS: u16 = 5;
const WGDEVICE_A_LISTEN_PORT: u16 = 6;
const WGDEVICE_A_PEERS: u16 = 8;
const WGDEVICE_F_REPLACE_PEERS: u32 = 1;
const WGPEER_A_PUBLIC_KEY: u16 = 1;
const WGPEER_A_FLAGS: u16 = 3;
const WGPEER_A_ENDPOINT: u16 = 4;
const WGPEER_A_KEEPALIVE: u16 = 5;
const WGPEER_A_LAST_HANDSHAKE_TIME: u16 = 6;
const WGPEER_A_RX_BYTES: u16 = 7;
const WGPEER_A_TX_BYTES: u16 = 8;
const WGPEER_A_ALLOWEDIPS: u16 = 9;
const WGPEER_F_REMOVE_ME: u32 = 1;
const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 2;
const WGALLOWEDIP_A_FAMILY: u16 = 1;
const WGALLOWEDIP_A_IPADDR: u16 = 2;
const WGALLOWEDIP_A_CIDR_MASK: u16 = 3;

/// Peers per SET message, so large hubs stay well under the 64 KiB limit.
const PEERS_PER_MSG: usize = 64;
/// Allowed IPs per SET message (≤ 44 bytes each); a peer with more is split
/// across messages, like `wg(8)` does, keeping every nest under 64 KiB.
const IPS_PER_MSG: usize = 512;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

/// A netlink message under construction: header, fixed part, attributes.
struct Msg {
    buf: Vec<u8>,
    nests: Vec<usize>,
    /// Set when an attribute or nest outgrew netlink's 16-bit length field.
    overflow: bool,
}

impl Msg {
    fn new(fixed: &[u8]) -> Self {
        let mut buf = vec![0u8; NLMSG_HDR_LEN];
        buf.extend_from_slice(fixed);
        pad(&mut buf);
        Msg { buf, nests: Vec::new(), overflow: false }
    }

    fn len16(&mut self, len: usize) -> [u8; 2] {
        u16::try_from(len)
            .unwrap_or_else(|_| {
                self.overflow = true;
                0
            })
            .to_ne_bytes()
    }

    fn attr(&mut self, ty: u16, data: &[u8]) -> &mut Self {
        let len = self.len16(4 + data.len());
        self.buf.extend_from_slice(&len);
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        self.buf.extend_from_slice(data);
        pad(&mut self.buf);
        self
    }

    fn str(&mut self, ty: u16, s: &str) -> &mut Self {
        let mut v = Vec::with_capacity(s.len() + 1);
        v.extend_from_slice(s.as_bytes());
        v.push(0);
        self.attr(ty, &v)
    }

    fn begin(&mut self, ty: u16) -> &mut Self {
        self.nests.push(self.buf.len());
        self.buf.extend_from_slice(&[0, 0]);
        self.buf.extend_from_slice(&(ty | NLA_F_NESTED).to_ne_bytes());
        self
    }

    fn end(&mut self) -> &mut Self {
        // Every `end` in this file is paired with a `begin` on the same message.
        if let Some(start) = self.nests.pop() {
            let len = self.len16(self.buf.len() - start);
            self.buf[start..start + 2].copy_from_slice(&len);
        }
        self
    }

    fn finish(mut self, ty: u16, flags: u16, seq: u32) -> io::Result<Vec<u8>> {
        let len = u32::try_from(self.buf.len()).map_err(|_| invalid("netlink message too large"))?;
        if self.overflow || !self.nests.is_empty() {
            return Err(invalid("netlink attribute too large"));
        }
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.buf[4..6].copy_from_slice(&ty.to_ne_bytes());
        self.buf[6..8].copy_from_slice(&flags.to_ne_bytes());
        self.buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        Ok(self.buf)
    }
}

fn pad(buf: &mut Vec<u8>) {
    buf.resize(buf.len().next_multiple_of(4), 0);
}

/// Iterates `(type, payload)` over an attribute block.
struct Attrs<'a>(&'a [u8]);

impl<'a> Iterator for Attrs<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let len = usize::from(ne_u16(self.0)?);
        let ty = ne_u16(self.0.get(2..)?)? & NLA_TYPE_MASK;
        let data = self.0.get(4..len)?;
        self.0 = self.0.get(len.next_multiple_of(4)..).unwrap_or_default();
        Some((ty, data))
    }
}

fn ne_u16(d: &[u8]) -> Option<u16> {
    Some(u16::from_ne_bytes(d.get(..2)?.try_into().ok()?))
}

fn ne_u32(d: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes(d.get(..4)?.try_into().ok()?))
}

fn ne_u64(d: &[u8]) -> Option<u64> {
    Some(u64::from_ne_bytes(d.get(..8)?.try_into().ok()?))
}

fn ne_i32(d: &[u8]) -> Option<i32> {
    Some(i32::from_ne_bytes(d.get(..4)?.try_into().ok()?))
}

/// Turns the errno carried by `NLMSG_ERROR`/`NLMSG_DONE` into a result.
fn errno(payload: &[u8]) -> io::Result<()> {
    match ne_i32(payload) {
        Some(0) => Ok(()),
        Some(code) => Err(io::Error::from_raw_os_error(code.saturating_neg())),
        None => Err(invalid("short netlink error message")),
    }
}

struct Socket {
    fd: OwnedFd,
    seq: u32,
}

impl Socket {
    fn open(protocol: libc::c_int) -> io::Result<Self> {
        // SAFETY: socket(2) has no memory-safety preconditions.
        let raw = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, protocol) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a freshly created descriptor that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: sockaddr_nl is plain old data; all-zero is a valid value.
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = sa_family(libc::AF_NETLINK);
        // SAFETY: `addr` is a valid sockaddr_nl and the length matches its size.
        let r = unsafe { libc::bind(fd.as_raw_fd(), std::ptr::from_ref(&addr).cast(), socklen::<libc::sockaddr_nl>()) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        let tv = libc::timeval { tv_sec: 5, tv_usec: 0 };
        // SAFETY: `tv` is a valid timeval and the length matches its size.
        let r = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                std::ptr::from_ref(&tv).cast(),
                socklen::<libc::timeval>(),
            )
        };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Socket { fd, seq: 0 })
    }

    /// Sends one request and collects the payloads of its replies.
    /// Non-dump requests carry `NLM_F_ACK` and end at the ACK.
    fn request(&mut self, msg: Msg, ty: u16, flags: u16) -> io::Result<Vec<Vec<u8>>> {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
        let flags = flags | NLM_F_REQUEST | if dump { 0 } else { NLM_F_ACK };
        let data = msg.finish(ty, flags, seq)?;
        // SAFETY: `data` is a valid buffer of `data.len()` bytes.
        let n = unsafe { libc::send(self.fd.as_raw_fd(), data.as_ptr().cast(), data.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut out = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            // SAFETY: `buf` is a valid writable buffer of `buf.len()` bytes.
            let n = unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            let n = usize::try_from(n).map_err(|_| io::Error::last_os_error())?;
            let mut rest = &buf[..n];
            while rest.len() >= NLMSG_HDR_LEN {
                let len = ne_u32(rest).and_then(|l| usize::try_from(l).ok()).unwrap_or(0);
                if len < NLMSG_HDR_LEN || len > rest.len() {
                    return Err(invalid("truncated netlink message"));
                }
                let mty = ne_u16(&rest[4..]).unwrap_or(0);
                let mseq = ne_u32(&rest[8..]).unwrap_or(0);
                let payload = &rest[NLMSG_HDR_LEN..len];
                rest = rest.get(len.next_multiple_of(4)..).unwrap_or_default();
                if mseq != seq {
                    continue;
                }
                match mty {
                    NLMSG_ERROR | NLMSG_DONE => return errno(payload).map(|()| out),
                    _ => out.push(payload.to_vec()),
                }
            }
        }
    }
}

fn sa_family(af: libc::c_int) -> libc::sa_family_t {
    // Address family constants are small positive numbers.
    libc::sa_family_t::try_from(af).unwrap_or_default()
}

fn socklen<T>() -> libc::socklen_t {
    // The structs passed here are a few dozen bytes long.
    libc::socklen_t::try_from(std::mem::size_of::<T>()).unwrap_or_default()
}

fn index(name: &str) -> io::Result<u32> {
    link_index(name).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such interface"))
}

pub fn link_index(name: &str) -> Option<u32> {
    let c = CString::new(name).ok()?;
    // SAFETY: `c` is a valid NUL-terminated string.
    let i = unsafe { libc::if_nametoindex(c.as_ptr()) };
    (i != 0).then_some(i)
}

fn ifinfomsg(index: u32, flags: u32, change: u32) -> [u8; 16] {
    let mut m = [0u8; 16];
    m[4..8].copy_from_slice(&index.to_ne_bytes());
    m[8..12].copy_from_slice(&flags.to_ne_bytes());
    m[12..16].copy_from_slice(&change.to_ne_bytes());
    m
}

pub fn create_wireguard_link(name: &str) -> io::Result<()> {
    let mut s = Socket::open(libc::NETLINK_ROUTE)?;
    let mut m = Msg::new(&ifinfomsg(0, 0, 0));
    m.str(IFLA_IFNAME, name).begin(IFLA_LINKINFO).str(IFLA_INFO_KIND, "wireguard").end();
    s.request(m, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL).map(drop)
}

pub fn delete_link(name: &str) -> io::Result<()> {
    let mut s = Socket::open(libc::NETLINK_ROUTE)?;
    s.request(Msg::new(&ifinfomsg(index(name)?, 0, 0)), RTM_DELLINK, 0).map(drop)
}

pub fn set_link_up(name: &str, mtu: u32) -> io::Result<()> {
    let mut s = Socket::open(libc::NETLINK_ROUTE)?;
    let mut m = Msg::new(&ifinfomsg(index(name)?, IFF_UP, IFF_UP));
    m.attr(IFLA_MTU, &mtu.to_ne_bytes());
    s.request(m, RTM_NEWLINK, 0).map(drop)
}

fn family(addr: &IpAddr) -> u16 {
    if addr.is_ipv4() { AF_INET } else { AF_INET6 }
}

fn ifaddrmsg(a: &AllowedIp, index: u32) -> [u8; 8] {
    // ifaddrmsg stores the family in a u8; AF_INET and AF_INET6 both fit.
    let fam = u8::try_from(family(&a.addr)).unwrap_or_default();
    let mut m = [fam, a.cidr, 0, 0, 0, 0, 0, 0];
    m[4..8].copy_from_slice(&index.to_ne_bytes());
    m
}

fn ip_bytes(ip: &IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v) => v.octets().to_vec(),
        IpAddr::V6(v) => v.octets().to_vec(),
    }
}

fn ip_from(d: &[u8]) -> Option<IpAddr> {
    match d.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(d).ok()?))),
        16 => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(d).ok()?))),
        _ => None,
    }
}

pub fn list_addresses(name: &str) -> io::Result<Vec<AllowedIp>> {
    let idx = index(name)?;
    let mut s = Socket::open(libc::NETLINK_ROUTE)?;
    let replies = s.request(Msg::new(&[0u8; 8]), RTM_GETADDR, NLM_F_DUMP)?;
    let mut out = Vec::new();
    for r in replies {
        let (Some(&fam), Some(&cidr), Some(ifindex)) = (r.first(), r.get(1), r.get(4..).and_then(ne_u32)) else {
            continue;
        };
        if ifindex != idx {
            continue;
        }
        let want = if u16::from(fam) == AF_INET { IFA_LOCAL } else { IFA_ADDRESS };
        let Some(addr) = Attrs(&r[8..]).find(|(t, _)| *t == want).and_then(|(_, d)| ip_from(d)) else {
            continue;
        };
        // Skip IPv6 link-local addresses the kernel adds on its own.
        if matches!(addr, IpAddr::V6(v) if v.is_unicast_link_local()) {
            continue;
        }
        out.push(AllowedIp { addr, cidr });
    }
    Ok(out)
}

pub fn add_address(name: &str, a: AllowedIp) -> io::Result<()> {
    let mut s = Socket::open(libc::NETLINK_ROUTE)?;
    let mut m = Msg::new(&ifaddrmsg(&a, index(name)?));
    let ip = ip_bytes(&a.addr);
    m.attr(IFA_LOCAL, &ip).attr(IFA_ADDRESS, &ip);
    s.request(m, RTM_NEWADDR, NLM_F_CREATE | NLM_F_REPLACE).map(drop)
}

pub fn del_address(name: &str, a: AllowedIp) -> io::Result<()> {
    let mut s = Socket::open(libc::NETLINK_ROUTE)?;
    let mut m = Msg::new(&ifaddrmsg(&a, index(name)?));
    m.attr(IFA_LOCAL, &ip_bytes(&a.addr));
    s.request(m, RTM_DELADDR, 0).map(drop)
}

fn genl_header(cmd: u8) -> [u8; 4] {
    [cmd, 1, 0, 0]
}

fn wireguard_family(s: &mut Socket) -> io::Result<u16> {
    let mut m = Msg::new(&genl_header(CTRL_CMD_GETFAMILY));
    m.str(CTRL_ATTR_FAMILY_NAME, "wireguard");
    let replies = s.request(m, GENL_ID_CTRL, 0)?;
    replies
        .iter()
        .filter_map(|r| r.get(4..))
        .flat_map(Attrs)
        .find(|(t, _)| *t == CTRL_ATTR_FAMILY_ID)
        .and_then(|(_, d)| ne_u16(d))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no wireguard netlink family"))
}

fn sockaddr_from(d: &[u8]) -> Option<SocketAddr> {
    let fam = ne_u16(d)?;
    let port = u16::from_be_bytes(d.get(2..4)?.try_into().ok()?);
    if fam == AF_INET {
        let ip: [u8; 4] = d.get(4..8)?.try_into().ok()?;
        Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)))
    } else if fam == AF_INET6 {
        let ip: [u8; 16] = d.get(8..24)?.try_into().ok()?;
        let scope = ne_u32(d.get(24..)?)?;
        Some(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, scope)))
    } else {
        None
    }
}

fn sockaddr_bytes(a: &SocketAddr) -> Vec<u8> {
    match a {
        SocketAddr::V4(v) => {
            let mut b = vec![0u8; 16];
            b[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
            b[2..4].copy_from_slice(&v.port().to_be_bytes());
            b[4..8].copy_from_slice(&v.ip().octets());
            b
        }
        SocketAddr::V6(v) => {
            let mut b = vec![0u8; 28];
            b[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
            b[2..4].copy_from_slice(&v.port().to_be_bytes());
            b[8..24].copy_from_slice(&v.ip().octets());
            b[24..28].copy_from_slice(&v.scope_id().to_ne_bytes());
            b
        }
    }
}

fn parse_allowed(d: &[u8]) -> Option<AllowedIp> {
    let (mut addr, mut cidr) = (None, None);
    for (t, v) in Attrs(d) {
        match t {
            WGALLOWEDIP_A_IPADDR => addr = ip_from(v),
            WGALLOWEDIP_A_CIDR_MASK => cidr = v.first().copied(),
            _ => {}
        }
    }
    Some(AllowedIp { addr: addr?, cidr: cidr? })
}

fn parse_handshake(v: &[u8]) -> Option<SystemTime> {
    // struct __kernel_timespec { i64 tv_sec; i64 tv_nsec; }; zero means never.
    let sec = ne_u64(v)?;
    let nsec = ne_u64(v.get(8..)?)?;
    if sec == 0 && nsec == 0 {
        return None;
    }
    let nsec = u32::try_from(nsec).ok().filter(|n| *n < 1_000_000_000)?;
    SystemTime::UNIX_EPOCH.checked_add(Duration::new(sec, nsec))
}

/// Parses one peer; `None` if it lacks a well-formed public key.
fn parse_peer(d: &[u8]) -> Option<PeerInfo> {
    let mut p = PeerInfo::default();
    let mut key = None;
    for (t, v) in Attrs(d) {
        match t {
            WGPEER_A_PUBLIC_KEY => key = v.try_into().ok(),
            WGPEER_A_ENDPOINT => p.endpoint = sockaddr_from(v),
            WGPEER_A_KEEPALIVE => p.keepalive = ne_u16(v).unwrap_or(0),
            WGPEER_A_LAST_HANDSHAKE_TIME => p.last_handshake = parse_handshake(v),
            WGPEER_A_RX_BYTES => p.rx_bytes = ne_u64(v).unwrap_or(0),
            WGPEER_A_TX_BYTES => p.tx_bytes = ne_u64(v).unwrap_or(0),
            WGPEER_A_ALLOWEDIPS => p.allowed_ips.extend(Attrs(v).filter_map(|(_, a)| parse_allowed(a))),
            _ => {}
        }
    }
    p.public_key = key?;
    Some(p)
}

pub fn get_device(name: &str) -> io::Result<DeviceInfo> {
    let mut s = Socket::open(libc::NETLINK_GENERIC)?;
    let family = wireguard_family(&mut s)?;
    let mut m = Msg::new(&genl_header(WG_CMD_GET_DEVICE));
    m.str(WGDEVICE_A_IFNAME, name);
    let replies = s.request(m, family, NLM_F_DUMP)?;
    let mut dev = DeviceInfo::default();
    for (t, v) in replies.iter().filter_map(|r| r.get(4..)).flat_map(Attrs) {
        match t {
            WGDEVICE_A_PUBLIC_KEY => dev.public_key = v.try_into().ok(),
            WGDEVICE_A_LISTEN_PORT => dev.listen_port = ne_u16(v).unwrap_or(0),
            WGDEVICE_A_PEERS => {
                for peer in Attrs(v).filter_map(|(_, pd)| parse_peer(pd)) {
                    // A peer with many allowed IPs is split across messages.
                    match dev.peers.last_mut() {
                        Some(last) if last.public_key == peer.public_key => {
                            last.allowed_ips.extend(peer.allowed_ips);
                        }
                        _ => dev.peers.push(peer),
                    }
                }
            }
            _ => {}
        }
    }
    Ok(dev)
}

/// One peer entry of a SET message. A peer whose allowed IPs do not fit in
/// one message is sent as several entries: the first replaces the list, the
/// rest append to it.
struct Entry<'a> {
    peer: &'a PeerSet,
    ips: Option<&'a [AllowedIp]>,
    first: bool,
}

fn entries(peers: &[PeerSet]) -> Vec<Entry<'_>> {
    let mut out = Vec::new();
    for peer in peers {
        match peer.allowed_ips.as_deref() {
            Some(ips) if ips.len() > IPS_PER_MSG => {
                for (i, chunk) in ips.chunks(IPS_PER_MSG).enumerate() {
                    out.push(Entry { peer, ips: Some(chunk), first: i == 0 });
                }
            }
            ips => out.push(Entry { peer, ips, first: true }),
        }
    }
    out
}

/// Groups entries so each message has at most `PEERS_PER_MSG` peers and
/// `IPS_PER_MSG` allowed IPs.
fn batches<'a>(entries: &'a [Entry<'a>]) -> Vec<&'a [Entry<'a>]> {
    let mut out = Vec::new();
    let (mut start, mut ips) = (0, 0);
    for (i, e) in entries.iter().enumerate() {
        let n = e.ips.map_or(0, <[AllowedIp]>::len);
        if i > start && (i - start == PEERS_PER_MSG || ips + n > IPS_PER_MSG) {
            out.push(&entries[start..i]);
            (start, ips) = (i, 0);
        }
        ips += n;
    }
    out.push(&entries[start..]);
    out
}

fn write_peer(m: &mut Msg, index: u16, e: &Entry<'_>) {
    let p = e.peer;
    m.begin(index);
    m.attr(WGPEER_A_PUBLIC_KEY, &p.public_key);
    let mut flags = 0;
    if p.remove {
        flags |= WGPEER_F_REMOVE_ME;
    }
    if e.ips.is_some() && e.first {
        flags |= WGPEER_F_REPLACE_ALLOWEDIPS;
    }
    m.attr(WGPEER_A_FLAGS, &flags.to_ne_bytes());
    if !p.remove {
        if e.first {
            if let Some(ep) = &p.endpoint {
                m.attr(WGPEER_A_ENDPOINT, &sockaddr_bytes(ep));
            }
            if let Some(ka) = p.keepalive {
                m.attr(WGPEER_A_KEEPALIVE, &ka.to_ne_bytes());
            }
        }
        if let Some(ips) = e.ips {
            m.begin(WGPEER_A_ALLOWEDIPS);
            for (k, a) in (0u16..).zip(ips) {
                m.begin(k)
                    .attr(WGALLOWEDIP_A_FAMILY, &family(&a.addr).to_ne_bytes())
                    .attr(WGALLOWEDIP_A_IPADDR, &ip_bytes(&a.addr))
                    .attr(WGALLOWEDIP_A_CIDR_MASK, &[a.cidr])
                    .end();
            }
            m.end();
        }
    }
    m.end();
}

fn set_message(name: &str, set: &DeviceSet, batch: &[Entry<'_>], first: bool) -> Msg {
    let mut m = Msg::new(&genl_header(WG_CMD_SET_DEVICE));
    m.str(WGDEVICE_A_IFNAME, name);
    if first {
        if let Some(k) = &set.private_key {
            m.attr(WGDEVICE_A_PRIVATE_KEY, k);
        }
        if let Some(p) = set.listen_port {
            m.attr(WGDEVICE_A_LISTEN_PORT, &p.to_ne_bytes());
        }
        if set.replace_peers {
            m.attr(WGDEVICE_A_FLAGS, &WGDEVICE_F_REPLACE_PEERS.to_ne_bytes());
        }
    }
    if !batch.is_empty() {
        m.begin(WGDEVICE_A_PEERS);
        for (j, e) in (0u16..).zip(batch) {
            write_peer(&mut m, j, e);
        }
        m.end();
    }
    m
}

pub fn set_device(name: &str, set: &DeviceSet) -> io::Result<()> {
    let mut s = Socket::open(libc::NETLINK_GENERIC)?;
    let family = wireguard_family(&mut s)?;
    let entries = entries(&set.peers);
    for (i, batch) in batches(&entries).into_iter().enumerate() {
        s.request(set_message(name, set, batch, i == 0), family, 0)?;
    }
    Ok(())
}

pub fn set_forwarding(name: &str, on: bool) -> io::Result<()> {
    // The name becomes a /proc path component; accept only real interface names.
    if name.is_empty() || name.len() > 15 || name.contains('/') || name == "." || name == ".." {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid interface name"));
    }
    std::fs::write(format!("/proc/sys/net/ipv4/conf/{name}/forwarding"), if on { "1" } else { "0" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_layout() {
        let mut m = Msg::new(&[1, 2, 3, 4]);
        m.str(3, "ab").begin(7).attr(1, &[9]).end();
        let b = m.finish(16, 5, 42).unwrap();
        assert_eq!(b.len() % 4, 0);
        assert_eq!(ne_u32(&b).unwrap() as usize, b.len());
        let attrs: Vec<_> = Attrs(&b[20..]).collect();
        assert_eq!(attrs[0], (3, &b"ab\0"[..]));
        assert_eq!(attrs[1].0, 7, "nested flag is masked off");
        assert_eq!(Attrs(attrs[1].1).next(), Some((1, &[9u8][..])));
    }

    #[test]
    fn sockaddr_roundtrip() {
        for a in ["1.2.3.4:51820", "[fd00::1]:7"] {
            let a: SocketAddr = a.parse().unwrap();
            assert_eq!(sockaddr_from(&sockaddr_bytes(&a)), Some(a));
        }
        assert_eq!(sockaddr_from(&[0, 0]), None);
    }

    #[test]
    fn large_allowed_ip_lists_are_split() {
        let ip = |i: u32| AllowedIp { addr: IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i)), cidr: 32 };
        let big = PeerSet { public_key: [1; 32], allowed_ips: Some((0..1200).map(ip).collect()), ..PeerSet::default() };
        let small: Vec<PeerSet> = (2..102u8).map(|k| PeerSet { public_key: [k; 32], ..PeerSet::default() }).collect();
        let mut peers = vec![big];
        peers.extend(small);
        let e = entries(&peers);
        assert_eq!(e.iter().filter(|x| x.peer.public_key == [1; 32]).count(), 3);
        assert_eq!(e.iter().filter(|x| x.first && x.ips.is_some()).count(), 1, "only the first entry replaces");
        let set = DeviceSet { peers: peers.clone(), ..DeviceSet::default() };
        for (i, b) in batches(&e).iter().enumerate() {
            assert!(b.len() <= PEERS_PER_MSG);
            assert!(b.iter().map(|x| x.ips.map_or(0, <[AllowedIp]>::len)).sum::<usize>() <= IPS_PER_MSG);
            assert!(set_message("wg0", &set, b, i == 0).finish(1, 0, 1).is_ok(), "fits in netlink lengths");
        }
    }

    #[test]
    fn unbalanced_nest_is_an_error() {
        let mut m = Msg::new(&[]);
        m.begin(1);
        assert!(m.finish(1, 0, 1).is_err());
    }
}
