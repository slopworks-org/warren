//! The WireGuard hub.
//!
//! Two implementations behind one enum: the Linux kernel module (preferred;
//! device-to-device ACLs become an nftables table) and boringtun on a TUN
//! device (fallback; ACLs are checked per packet in-process). In both, the
//! server's own sockets (proxy, control channel) use the kernel stack, so the
//! rest of the server does not care which one runs.

#[cfg(target_os = "linux")]
mod kernel;
mod packet;
#[cfg(target_os = "linux")]
mod userspace;

use crate::acl::{Acl, PROTO_TCP, PROTO_UDP};
use crate::config::{Net4, WgBackendKind};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
#[cfg(target_os = "linux")]
use std::sync::Arc;
use thiserror::Error;

pub use packet::ipv4_flow;

/// A tunnel failure.
#[derive(Debug, Error)]
pub enum WgError {
    /// Netlink control of the interface failed.
    #[error(transparent)]
    Netlink(#[from] warren_wgctl::Error),
    /// A system call or helper process failed.
    #[error("{what}: {source}")]
    Io {
        /// What was being done.
        what: &'static str,
        /// The underlying error.
        source: std::io::Error,
    },
    /// `nft` rejected the generated ruleset.
    #[error("nft failed: {0}")]
    Nft(String),
    /// The requested backend cannot run here.
    #[error("{0}")]
    Unsupported(&'static str),
}

/// A device as the hub needs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerSpec {
    /// Device public key.
    pub key: [u8; 32],
    /// Device tunnel address.
    pub ip: Ipv4Addr,
}

/// Live state of a peer.
#[derive(Clone, Copy, Debug, Default)]
pub struct PeerStats {
    /// Unix time of the last handshake.
    pub last_handshake: Option<i64>,
    /// Bytes received from the device.
    pub rx_bytes: u64,
    /// Bytes sent to the device.
    pub tx_bytes: u64,
    /// Where the device's packets come from.
    pub endpoint: Option<SocketAddr>,
}

/// Parameters of the hub interface.
#[derive(Clone)]
pub struct HubSpec {
    /// Interface name.
    pub iface: String,
    /// UDP listen port.
    pub port: u16,
    /// Tunnel network; the hub takes its first host address.
    pub network: Net4,
    /// Hub private key.
    pub private_key: [u8; 32],
    /// Interface MTU.
    pub mtu: u32,
}

/// The running hub.
pub enum Backend {
    /// No tunnel (development on non-Linux systems).
    None,
    /// Linux kernel WireGuard.
    #[cfg(target_os = "linux")]
    Kernel(kernel::Kernel),
    /// boringtun on TUN.
    #[cfg(target_os = "linux")]
    Userspace(Arc<userspace::Userspace>),
}

impl Backend {
    /// Starts the requested backend; `Auto` prefers the kernel module when
    /// it and `nft` are available.
    ///
    /// # Errors
    /// When the backend cannot be set up (missing privileges, module, TUN).
    #[cfg_attr(
        not(target_os = "linux"),
        allow(clippy::unused_async, clippy::unused_async_trait_impl, reason = "only the Linux backends await")
    )]
    pub async fn start(kind: WgBackendKind, spec: HubSpec) -> Result<Backend, WgError> {
        match kind {
            WgBackendKind::None => Ok(Backend::None),
            #[cfg(target_os = "linux")]
            WgBackendKind::Kernel => Ok(Backend::Kernel(kernel::Kernel::start(spec).await?)),
            #[cfg(target_os = "linux")]
            WgBackendKind::Userspace => Ok(Backend::Userspace(userspace::Userspace::start(spec)?)),
            #[cfg(target_os = "linux")]
            WgBackendKind::Auto => {
                if warren_wgctl::wireguard_supported()? && kernel::nft_available().await {
                    Ok(Backend::Kernel(kernel::Kernel::start(spec).await?))
                } else {
                    tracing::info!("kernel WireGuard or nft unavailable; using the userspace implementation");
                    Ok(Backend::Userspace(userspace::Userspace::start(spec)?))
                }
            }
            #[cfg(not(target_os = "linux"))]
            _ => {
                let _ = spec;
                Err(WgError::Unsupported("WireGuard backends need Linux; set wireguard.backend = \"none\""))
            }
        }
    }

    /// Short name for logs and the UI.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Backend::None => "none",
            #[cfg(target_os = "linux")]
            Backend::Kernel(_) => "kernel",
            #[cfg(target_os = "linux")]
            Backend::Userspace(_) => "userspace",
        }
    }

    /// True when devices can actually be reached.
    #[must_use]
    pub fn has_tunnel(&self) -> bool {
        !matches!(self, Backend::None)
    }

    /// Makes the hub's peers and ACL match the given state.
    ///
    /// # Errors
    /// When the kernel or `nft` rejects the change.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(clippy::unused_async, clippy::unused_async_trait_impl, reason = "only the Linux backends await")
    )]
    pub async fn apply(&self, peers: &[PeerSpec], acl: &Acl) -> Result<(), WgError> {
        match self {
            Backend::None => {
                let _ = (peers, acl);
                Ok(())
            }
            #[cfg(target_os = "linux")]
            Backend::Kernel(k) => k.apply(peers, acl).await,
            #[cfg(target_os = "linux")]
            Backend::Userspace(u) => {
                u.apply(peers, acl);
                Ok(())
            }
        }
    }

    /// Per-peer statistics keyed by public key.
    ///
    /// # Errors
    /// When the kernel cannot be queried.
    pub fn stats(&self) -> Result<HashMap<[u8; 32], PeerStats>, WgError> {
        match self {
            Backend::None => Ok(HashMap::new()),
            #[cfg(target_os = "linux")]
            Backend::Kernel(k) => k.stats(),
            #[cfg(target_os = "linux")]
            Backend::Userspace(u) => Ok(u.stats()),
        }
    }

    /// Removes the interface and firewall state.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(clippy::unused_async, clippy::unused_async_trait_impl, reason = "only the Linux backends await")
    )]
    pub async fn shutdown(&self) {
        match self {
            Backend::None => {}
            #[cfg(target_os = "linux")]
            Backend::Kernel(k) => k.shutdown().await,
            #[cfg(target_os = "linux")]
            Backend::Userspace(u) => u.shutdown(),
        }
    }
}

fn proto_name(p: u8) -> &'static str {
    match p {
        PROTO_TCP => "tcp",
        PROTO_UDP => "udp",
        _ => "0",
    }
}

/// Renders the ACL as an nftables script that atomically replaces the
/// `inet warren` table. Traffic between devices through `iface` is dropped
/// unless allowed; replies pass through connection tracking.
#[must_use]
pub fn nft_ruleset(iface: &str, acl: &Acl) -> String {
    let mut s = String::new();
    // Creating first makes the delete succeed on the first run.
    let _ = writeln!(s, "table inet warren\ndelete table inet warren\ntable inet warren {{");
    let _ = writeln!(s, "  set allow_all {{\n    type ipv4_addr . ipv4_addr");
    if !acl.all.is_empty() {
        let elems: Vec<String> = acl.all.iter().map(|(a, b)| format!("{a} . {b}")).collect();
        let _ = writeln!(s, "    elements = {{ {} }}", elems.join(", "));
    }
    let _ = writeln!(
        s,
        "  }}\n  set allow_port {{\n    type ipv4_addr . ipv4_addr . inet_proto . inet_service\n    flags interval"
    );
    let ports: Vec<String> = acl
        .ports
        .iter()
        .flat_map(|((a, b), specs)| {
            specs.iter().map(move |p| {
                let range = if p.from == p.to { p.from.to_string() } else { format!("{}-{}", p.from, p.to) };
                format!("{a} . {b} . {} . {range}", proto_name(p.proto))
            })
        })
        .collect();
    if !ports.is_empty() {
        let _ = writeln!(s, "    elements = {{ {} }}", ports.join(", "));
    }
    let _ = writeln!(
        s,
        "  }}\n  chain forward {{\n    type filter hook forward priority filter - 1; policy accept;\n    \
         iifname \"{iface}\" ct state established,related accept\n    \
         iifname \"{iface}\" oifname \"{iface}\" ip saddr . ip daddr @allow_all accept\n    \
         iifname \"{iface}\" oifname \"{iface}\" ip saddr . ip daddr . meta l4proto . th dport @allow_port accept\n    \
         iifname \"{iface}\" drop\n    oifname \"{iface}\" drop\n  }}\n}}"
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{Node, PortSpec, Rule, Subject};

    #[test]
    fn nft_ruleset_lists_pairs_and_ports() {
        let ip = |n| Ipv4Addr::new(10, 77, 0, n);
        let nodes = [
            Node { device: 1, user: 1, ip: ip(2) },
            Node { device: 2, user: 1, ip: ip(3) },
            Node { device: 3, user: 2, ip: ip(4) },
        ];
        let rules = [Rule {
            src: Subject::Device(3),
            dst: Subject::Device(1),
            ports: PortSpec::parse_list("tcp:22-23").unwrap(),
        }];
        let s = nft_ruleset("warren0", &Acl::compile(&nodes, &rules));
        assert!(s.starts_with("table inet warren\ndelete table inet warren\n"));
        assert!(s.contains("elements = { 10.77.0.2 . 10.77.0.3, 10.77.0.3 . 10.77.0.2 }"));
        assert!(s.contains("elements = { 10.77.0.4 . 10.77.0.2 . tcp . 22-23 }"));
        assert!(s.contains("iifname \"warren0\" drop"));
        let empty = nft_ruleset("warren0", &Acl::default());
        assert!(!empty.contains("elements"), "empty sets must not list elements");
    }
}
