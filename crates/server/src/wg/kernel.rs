//! Hub on the Linux kernel WireGuard module, with ACLs in nftables.

use super::{HubSpec, PeerSpec, PeerStats, WgError, nft_ruleset};
use crate::acl::Acl;
use crate::util::unix;
use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use warren_wgctl::{self as wg, AllowedIp, DeviceSet, PeerSet};

/// True if the `nft` tool runs.
pub async fn nft_available() -> bool {
    Command::new("nft")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .is_ok_and(|s| s.success())
}

async fn nft(script: &str) -> Result<(), WgError> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| WgError::Io { what: "running nft", source })?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script.as_bytes()).await.map_err(|source| WgError::Io { what: "writing to nft", source })?;
    }
    let out = child.wait_with_output().await.map_err(|source| WgError::Io { what: "waiting for nft", source })?;
    if out.status.success() {
        Ok(())
    } else {
        Err(WgError::Nft(String::from_utf8_lossy(&out.stderr).trim().to_string()))
    }
}

/// Docker and some distributions set the iptables FORWARD policy to DROP,
/// which would drop device-to-device traffic our nftables table allowed.
/// Accepting hub-to-hub forwarding there is safe: our table filters it first.
async fn allow_in_iptables(iface: &str) {
    let rule = ["FORWARD", "-i", iface, "-o", iface, "-j", "ACCEPT"];
    let exists = Command::new("iptables").arg("-C").args(rule).stderr(Stdio::null()).status().await;
    if matches!(exists, Ok(s) if !s.success()) {
        match Command::new("iptables").arg("-I").args(rule).status().await {
            Ok(s) if s.success() => tracing::debug!(iface, "added iptables FORWARD accept rule"),
            _ => tracing::debug!(iface, "could not add iptables FORWARD rule"),
        }
    }
}

/// The kernel hub.
pub struct Kernel {
    iface: String,
}

impl Kernel {
    /// Recreates the interface from scratch with no peers and a deny-all ACL.
    pub async fn start(spec: HubSpec) -> Result<Kernel, WgError> {
        let iface = spec.iface.as_str();
        if wg::link_index(iface).is_some() {
            wg::delete_link(iface)?;
        }
        wg::create_wireguard_link(iface)?;
        wg::set_device(
            iface,
            &DeviceSet {
                private_key: Some(spec.private_key),
                listen_port: Some(spec.port),
                replace_peers: true,
                peers: Vec::new(),
            },
        )?;
        let addr = AllowedIp { addr: IpAddr::V4(spec.network.server_ip()), cidr: spec.network.prefix };
        wg::ensure_address(iface, addr, spec.mtu)?;
        nft(&nft_ruleset(iface, &Acl::default())).await?;
        wg::set_forwarding(iface, true)?;
        allow_in_iptables(iface).await;
        tracing::info!(iface, port = spec.port, "kernel WireGuard hub up");
        Ok(Kernel { iface: spec.iface })
    }

    /// Updates peers in place (sessions survive) and replaces the ACL table.
    pub async fn apply(&self, peers: &[PeerSpec], acl: &Acl) -> Result<(), WgError> {
        let current = wg::get_device(&self.iface)?;
        let mut set = DeviceSet::default();
        for old in current.peers.iter().filter(|o| !peers.iter().any(|p| p.key == o.public_key)) {
            set.peers.push(PeerSet { public_key: old.public_key, remove: true, ..PeerSet::default() });
        }
        for p in peers {
            let want = vec![AllowedIp { addr: IpAddr::V4(p.ip), cidr: 32 }];
            let same = current.peers.iter().any(|o| o.public_key == p.key && o.allowed_ips == want);
            if !same {
                set.peers.push(PeerSet { public_key: p.key, allowed_ips: Some(want), ..PeerSet::default() });
            }
        }
        if !set.peers.is_empty() {
            wg::set_device(&self.iface, &set)?;
        }
        nft(&nft_ruleset(&self.iface, acl)).await
    }

    /// Reads per-peer counters from the kernel.
    pub fn stats(&self) -> Result<HashMap<[u8; 32], PeerStats>, WgError> {
        Ok(wg::get_device(&self.iface)?
            .peers
            .into_iter()
            .map(|p| {
                let stats = PeerStats {
                    last_handshake: p.last_handshake.map(unix),
                    rx_bytes: p.rx_bytes,
                    tx_bytes: p.tx_bytes,
                    endpoint: p.endpoint,
                };
                (p.public_key, stats)
            })
            .collect())
    }

    /// Deletes the firewall table and the interface.
    pub async fn shutdown(&self) {
        if let Err(e) = nft("delete table inet warren").await {
            tracing::debug!(error = %e, "removing nft table");
        }
        if let Err(e) = wg::delete_link(&self.iface) {
            tracing::warn!(error = %e, "removing interface");
        }
    }
}
