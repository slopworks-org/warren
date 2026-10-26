//! Minimal netlink control of Linux WireGuard interfaces.
//!
//! Hand-written instead of a netlink crate to keep the agent small: it covers
//! creating/deleting links, bringing them up, managing addresses, and the
//! WireGuard generic-netlink GET/SET device commands. On other systems every
//! call fails with [`std::io::ErrorKind::Unsupported`], so the workspace still
//! builds there.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::SystemTime;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as sys;

#[cfg(test)]
mod uapi;

#[cfg(not(target_os = "linux"))]
mod unsupported;
#[cfg(not(target_os = "linux"))]
use unsupported as sys;

/// A 32-byte Curve25519 key, as WireGuard uses for both halves of a key pair.
pub type Key = [u8; 32];

/// An IP network: address plus prefix length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AllowedIp {
    /// Network or host address.
    pub addr: IpAddr,
    /// Prefix length in bits.
    pub cidr: u8,
}

/// Why a string is not a valid [`AllowedIp`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseAllowedIpError {
    /// The address part is not an IP address.
    Address(String),
    /// The prefix is not a number or is longer than the address.
    Prefix(String),
}

impl fmt::Display for ParseAllowedIpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseAllowedIpError::Address(a) => write!(f, "invalid IP address {a:?}"),
            ParseAllowedIpError::Prefix(p) => write!(f, "invalid prefix length {p:?}"),
        }
    }
}

impl std::error::Error for ParseAllowedIpError {}

impl std::str::FromStr for AllowedIp {
    type Err = ParseAllowedIpError;

    /// Parses `addr/prefix`; a bare address means a single host.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (a, c) = s.split_once('/').unwrap_or((s, ""));
        let addr: IpAddr = a.parse().map_err(|_| ParseAllowedIpError::Address(a.to_string()))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let cidr = if c.is_empty() {
            max
        } else {
            c.parse().ok().filter(|&n| n <= max).ok_or_else(|| ParseAllowedIpError::Prefix(c.to_string()))?
        };
        Ok(AllowedIp { addr, cidr })
    }
}

impl fmt::Display for AllowedIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.cidr)
    }
}

/// A peer change for [`set_device`].
#[derive(Clone, Debug, Default)]
pub struct PeerSet {
    /// Identifies the peer.
    pub public_key: Key,
    /// Remove the peer instead of updating it.
    pub remove: bool,
    /// New endpoint; `None` leaves it unchanged.
    pub endpoint: Option<SocketAddr>,
    /// `Some(0)` disables keepalive; `None` leaves it unchanged.
    pub keepalive: Option<u16>,
    /// When set, the peer's allowed IPs are replaced by this list.
    pub allowed_ips: Option<Vec<AllowedIp>>,
}

/// A device change for [`set_device`].
#[derive(Clone, Debug, Default)]
pub struct DeviceSet {
    /// New private key; the kernel keeps sessions when it is unchanged.
    pub private_key: Option<Key>,
    /// New UDP listen port.
    pub listen_port: Option<u16>,
    /// Remove every peer not listed in `peers`. Drops their sessions.
    pub replace_peers: bool,
    /// Peers to add, update or remove.
    pub peers: Vec<PeerSet>,
}

/// A peer as reported by [`get_device`].
#[derive(Clone, Debug, Default)]
pub struct PeerInfo {
    /// The peer's public key.
    pub public_key: Key,
    /// Last known endpoint.
    pub endpoint: Option<SocketAddr>,
    /// Time of the last completed handshake; `None` if there was none.
    pub last_handshake: Option<SystemTime>,
    /// Bytes received from the peer.
    pub rx_bytes: u64,
    /// Bytes sent to the peer.
    pub tx_bytes: u64,
    /// Persistent keepalive interval in seconds; 0 when off.
    pub keepalive: u16,
    /// Networks routed to the peer.
    pub allowed_ips: Vec<AllowedIp>,
}

/// A WireGuard interface as reported by [`get_device`].
#[derive(Clone, Debug, Default)]
pub struct DeviceInfo {
    /// The interface's public key, if a private key is set.
    pub public_key: Option<Key>,
    /// UDP listen port.
    pub listen_port: u16,
    /// Configured peers.
    pub peers: Vec<PeerInfo>,
}

/// A failed interface operation: what was attempted, on which interface, and why.
#[derive(Debug)]
pub struct Error {
    op: &'static str,
    iface: String,
    source: io::Error,
}

impl Error {
    fn new(op: &'static str, iface: &str, source: io::Error) -> Self {
        Error { op, iface: iface.to_string(), source }
    }

    /// The kind of the underlying OS error.
    #[must_use]
    pub fn kind(&self) -> io::ErrorKind {
        self.source.kind()
    }

    /// The underlying errno, when there is one.
    #[must_use]
    pub fn raw_os_error(&self) -> Option<i32> {
        self.source.raw_os_error()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.op, self.iface, self.source)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Result of an interface operation.
pub type Result<T> = std::result::Result<T, Error>;

/// Returns the interface index of `name`, or `None` if it does not exist.
#[must_use]
pub fn link_index(name: &str) -> Option<u32> {
    sys::link_index(name)
}

/// Creates a WireGuard interface called `name`.
///
/// # Errors
/// When the interface exists, the kernel lacks WireGuard, or the caller lacks
/// `CAP_NET_ADMIN`.
pub fn create_wireguard_link(name: &str) -> Result<()> {
    sys::create_wireguard_link(name).map_err(|e| Error::new("creating WireGuard interface", name, e))
}

/// Deletes the interface `name`.
///
/// # Errors
/// When it does not exist or the caller lacks `CAP_NET_ADMIN`.
pub fn delete_link(name: &str) -> Result<()> {
    sys::delete_link(name).map_err(|e| Error::new("deleting interface", name, e))
}

/// Sets the MTU of `name` and brings it up.
///
/// # Errors
/// When the interface does not exist or the kernel refuses the change.
pub fn set_link_up(name: &str, mtu: u32) -> Result<()> {
    sys::set_link_up(name, mtu).map_err(|e| Error::new("bringing up interface", name, e))
}

/// Lists the addresses on `name`, except IPv6 link-local ones.
///
/// # Errors
/// When the interface does not exist or netlink fails.
pub fn list_addresses(name: &str) -> Result<Vec<AllowedIp>> {
    sys::list_addresses(name).map_err(|e| Error::new("listing addresses of", name, e))
}

/// Adds (or replaces) an address on `name`.
///
/// # Errors
/// When the interface does not exist or the kernel refuses the address.
pub fn add_address(name: &str, addr: AllowedIp) -> Result<()> {
    sys::add_address(name, addr).map_err(|e| Error::new("adding address to", name, e))
}

/// Removes an address from `name`.
///
/// # Errors
/// When the interface or the address does not exist.
pub fn del_address(name: &str, addr: AllowedIp) -> Result<()> {
    sys::del_address(name, addr).map_err(|e| Error::new("removing address from", name, e))
}

/// Reads the WireGuard state of `name`, including per-peer statistics.
///
/// # Errors
/// When `name` is not a WireGuard interface or the caller lacks `CAP_NET_ADMIN`.
pub fn get_device(name: &str) -> Result<DeviceInfo> {
    sys::get_device(name).map_err(|e| Error::new("reading WireGuard device", name, e))
}

/// Applies a WireGuard configuration change to `name`.
///
/// # Errors
/// When `name` is not a WireGuard interface or the kernel rejects the change.
pub fn set_device(name: &str, set: &DeviceSet) -> Result<()> {
    sys::set_device(name, set).map_err(|e| Error::new("configuring WireGuard device", name, e))
}

/// Whether the kernel can create WireGuard interfaces (built in or as a
/// loadable module). Probes by creating and deleting a scratch interface.
///
/// # Errors
/// When the probe fails for another reason than missing support, notably
/// missing privileges, so callers do not mistake that for no module.
pub fn wireguard_supported() -> Result<bool> {
    let probe = format!("wgprobe{}", std::process::id() % 100_000);
    match create_wireguard_link(&probe) {
        Ok(()) => {
            let _ = delete_link(&probe);
            Ok(true)
        }
        // A probe left behind by a crashed run proves support too.
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
            let _ = delete_link(&probe);
            Ok(true)
        }
        Err(e)
            if matches!(e.raw_os_error(), Some(libc::EOPNOTSUPP | libc::ENODEV | libc::ENOENT))
                || e.kind() == io::ErrorKind::Unsupported =>
        {
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

/// Enables or disables IPv4 forwarding of packets arriving on `name`.
///
/// # Errors
/// When the sysctl cannot be written.
pub fn set_forwarding(name: &str, on: bool) -> Result<()> {
    sys::set_forwarding(name, on).map_err(|e| Error::new("setting forwarding on", name, e))
}

/// Makes sure `name` carries exactly `addr` (one address), then brings it up.
///
/// # Errors
/// When any of the underlying address or link operations fails.
pub fn ensure_address(name: &str, addr: AllowedIp, mtu: u32) -> Result<()> {
    let current = list_addresses(name)?;
    for a in current.iter().filter(|a| **a != addr) {
        del_address(name, *a)?;
    }
    if !current.contains(&addr) {
        add_address(name, addr)?;
    }
    set_link_up(name, mtu)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_allowed_ip() {
        let a: AllowedIp = "10.77.0.0/16".parse().unwrap();
        assert_eq!(a.cidr, 16);
        assert_eq!(a.to_string(), "10.77.0.0/16");
        assert_eq!("10.0.0.1".parse::<AllowedIp>().unwrap().cidr, 32);
        assert_eq!("fd00::/8".parse::<AllowedIp>().unwrap().cidr, 8);
        assert_eq!("10.0.0.1/33".parse::<AllowedIp>(), Err(ParseAllowedIpError::Prefix("33".into())));
        assert!(matches!("x/1".parse::<AllowedIp>(), Err(ParseAllowedIpError::Address(_))));
    }
}
