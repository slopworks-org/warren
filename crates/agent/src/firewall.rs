//! Apply ingress policy before installing a WireGuard peer on either interface.
use crate::error::{Error, Result};
use std::io::{self, Write};
use std::process::{Command, Stdio};

fn rules(program: &str, args: &[&str], input: &str) -> io::Result<()> {
    let mut cmd = Command::new(program).args(args).stdin(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    cmd.stdin.take().ok_or_else(|| io::Error::other("missing firewall stdin"))?.write_all(input.as_bytes())?;
    let result = cmd.wait_with_output()?;
    if result.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(String::from_utf8_lossy(&result.stderr).trim().to_owned()))
    }
}

#[cfg(target_os = "linux")]
pub fn protect(iface: &str) -> Result<()> {
    if !iface.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)) || iface.is_empty() {
        return Err(Error::InvalidConfig("invalid firewall interface name"));
    }
    // One atomic transaction. iifname also covers a recreated interface.
    let table = crate::lan::interface(iface);
    let script = format!(
        "add table inet {table}\nflush table inet {table}\nadd chain inet {table} ingress {{ type filter hook prerouting priority -150; policy accept; }}\n\
        add rule inet {table} ingress iifname != \"{iface}\" return\n\
        add rule inet {table} ingress ct direction reply ct state established return\n\
        add rule inet {table} ingress ip protocol icmp icmp type echo-request return\n\
        add rule inet {table} ingress drop\n"
    );
    rules("nft", &["-f", "-"], &script).map_err(Error::io("installing Warren ingress rules (nftables required)"))
}

#[cfg(target_os = "macos")]
pub fn protect(iface: &str) -> Result<()> {
    let real = warren_wgctl::macos_interface(iface).map_err(Error::io("resolving utun interface"))?;
    let show =
        |option| Command::new("/sbin/pfctl").args(["-s", option]).output().map_err(Error::io("reading PF policy"));
    let info = show("info")?;
    let root = show("rules")?;
    if !info.status.success()
        || !String::from_utf8_lossy(&info.stdout).contains("Status: Enabled")
        || !root.status.success()
        || !String::from_utf8_lossy(&root.stdout)
            .lines()
            .next()
            .is_some_and(|r| r.starts_with("anchor \"warren/*\"") && r.split_whitespace().any(|w| w == "quick"))
    {
        return Err(Error::InvalidConfig(
            "enable PF with anchor \"warren/*\" quick as its first filter rule (see README)",
        ));
    }
    let anchor = format!("warren/{}", crate::lan::interface(iface));
    let script = format!(
        "pass out quick on {real} all keep state (if-bound)\npass in quick on {real} inet proto icmp icmp-type echoreq\nblock drop in quick on {real} all\n"
    );
    rules("/sbin/pfctl", &["-a", &anchor, "-f", "-"], &script).map_err(Error::io("installing Warren PF rules"))
}

pub fn remove(iface: &str) -> Result<()> {
    let table = crate::lan::interface(iface);
    #[cfg(target_os = "linux")]
    return rules("nft", &["-f", "-"], &format!("add table inet {table}\ndelete table inet {table}\n"))
        .map_err(Error::io("removing Warren ingress rules"));
    #[cfg(target_os = "macos")]
    rules("/sbin/pfctl", &["-a", &format!("warren/{table}"), "-F", "rules"], "")
        .map_err(Error::io("removing Warren PF rules"))
}
