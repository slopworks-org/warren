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
const WARREN_ANCHOR_RULE: &str = "anchor \"warren/*\" quick";

#[cfg(target_os = "macos")]
#[derive(Default)]
struct PfState {
    token: Option<String>,
    interfaces: std::collections::BTreeSet<String>,
}

#[cfg(target_os = "macos")]
static PF_STATE: std::sync::Mutex<PfState> =
    std::sync::Mutex::new(PfState { token: None, interfaces: std::collections::BTreeSet::new() });

#[cfg(target_os = "macos")]
fn is_scrub_rule(line: &str) -> bool {
    matches!(line.split_whitespace().next(), Some("scrub" | "scrub-anchor"))
}

#[cfg(target_os = "macos")]
fn has_warren_anchor(rules_output: &str) -> bool {
    rules_output.lines().map(str::trim).find(|line| !line.is_empty() && !is_scrub_rule(line))
        == Some("anchor \"warren/*\" quick all")
}

#[cfg(target_os = "macos")]
fn pf_is_ready() -> Result<bool> {
    let show =
        |option| Command::new("/sbin/pfctl").args(["-s", option]).output().map_err(Error::io("reading PF policy"));
    let info = show("info")?;
    let root = show("rules")?;
    Ok(info.status.success()
        && String::from_utf8_lossy(&info.stdout).contains("Status: Enabled")
        && root.status.success()
        && has_warren_anchor(&String::from_utf8_lossy(&root.stdout)))
}

#[cfg(target_os = "macos")]
fn parse_pf_token(output: &std::process::Output) -> Option<String> {
    [&output.stderr, &output.stdout].into_iter().find_map(|stream| {
        String::from_utf8_lossy(stream).lines().find_map(|line| {
            let token = line.trim().strip_prefix("Token")?.trim_start().strip_prefix(':')?.trim();
            (!token.is_empty()).then(|| token.to_owned())
        })
    })
}

#[cfg(target_os = "macos")]
fn is_filter_rule(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return false;
    }
    matches!(trimmed.split_whitespace().next(), Some("anchor" | "antispoof" | "block" | "load" | "match" | "pass"))
}

#[cfg(target_os = "macos")]
fn with_warren_anchor(conf: &str) -> String {
    let mut out = String::with_capacity(conf.len() + WARREN_ANCHOR_RULE.len() + 2);
    let mut inserted = false;
    for line in conf.lines() {
        if line.trim() == WARREN_ANCHOR_RULE {
            continue;
        }
        if !inserted && is_filter_rule(line) {
            out.push_str(WARREN_ANCHOR_RULE);
            out.push('\n');
            inserted = true;
        }
        out.push_str(line);
        out.push('\n');
    }
    if !inserted {
        out.push_str(WARREN_ANCHOR_RULE);
        out.push('\n');
    }
    out
}

#[cfg(target_os = "macos")]
fn ensure_pf_ready(state: &mut PfState) -> Result<()> {
    let root = Command::new("/sbin/pfctl").args(["-s", "rules"]).output().map_err(Error::io("reading PF policy"))?;
    let has_anchor = root.status.success() && has_warren_anchor(&String::from_utf8_lossy(&root.stdout));
    if !has_anchor {
        let conf = std::fs::read_to_string("/etc/pf.conf").map_err(Error::io("reading /etc/pf.conf"))?;
        let patched = with_warren_anchor(&conf);
        rules("/sbin/pfctl", &["-f", "-"], &patched).map_err(Error::io("loading PF rules with Warren anchor"))?;
    }

    let info = Command::new("/sbin/pfctl").args(["-s", "info"]).output().map_err(Error::io("reading PF status"))?;
    let enabled = info.status.success() && String::from_utf8_lossy(&info.stdout).contains("Status: Enabled");
    if !enabled || state.token.is_none() {
        let enable = Command::new("/sbin/pfctl").arg("-E").output().map_err(Error::io("enabling PF"))?;
        if !enable.status.success() {
            return Err(Error::io("enabling PF")(io::Error::other(
                String::from_utf8_lossy(&enable.stderr).trim().to_owned(),
            )));
        }
        if let Some(token) = parse_pf_token(&enable) {
            state.token = Some(token);
        }
    }

    if !pf_is_ready()? {
        return Err(Error::InvalidConfig(
            "enable PF with anchor \"warren/*\" quick as its first filter rule (see README)",
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn protect(iface: &str) -> Result<()> {
    let real = warren_wgctl::macos_interface(iface).map_err(Error::io("resolving utun interface"))?;
    let mut state = PF_STATE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    ensure_pf_ready(&mut state)?;
    let interface = Command::new("/sbin/pfctl")
        .args(["-v", "-i", &real, "-s", "Interfaces"])
        .output()
        .map_err(Error::io("reading PF interface flags"))?;
    let flags = String::from_utf8_lossy(&interface.stdout);
    if !interface.status.success() || !flags.split_whitespace().any(|word| word == real) || flags.contains("skip") {
        return Err(Error::InvalidConfig("PF must filter the Warren utun interface"));
    }
    let anchor = format!("warren/{}", crate::lan::interface(iface));
    let script = format!(
        "pass out quick on {real} all keep state (if-bound)\npass in quick on {real} inet proto icmp icmp-type echoreq\nblock drop in quick on {real} all\n"
    );
    rules("/sbin/pfctl", &["-a", &anchor, "-f", "-"], &script).map_err(Error::io("installing Warren PF rules"))?;
    state.interfaces.insert(iface.to_owned());
    Ok(())
}

pub fn remove(iface: &str) -> Result<()> {
    let table = crate::lan::interface(iface);
    #[cfg(target_os = "linux")]
    return rules("nft", &["-f", "-"], &format!("add table inet {table}\ndelete table inet {table}\n"))
        .map_err(Error::io("removing Warren ingress rules"));
    #[cfg(target_os = "macos")]
    {
        rules("/sbin/pfctl", &["-a", &format!("warren/{table}"), "-F", "rules"], "")
            .map_err(Error::io("removing Warren PF rules"))?;
        let mut state = PF_STATE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.interfaces.remove(iface);
        if state.interfaces.is_empty()
            && let Some(token) = state.token.take()
        {
            let _ = Command::new("/sbin/pfctl").args(["-X", &token]).output();
        }
        Ok(())
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn inserts_warren_anchor_before_first_filter_rule() {
        let conf = "\
# Default PF configuration
scrub-anchor \"com.apple/*\"
nat-anchor \"com.apple/*\"
rdr-anchor \"com.apple/*\"
dummynet-anchor \"com.apple/*\"
anchor \"com.apple/*\"
load anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\"
";
        let expected = "\
# Default PF configuration
scrub-anchor \"com.apple/*\"
nat-anchor \"com.apple/*\"
rdr-anchor \"com.apple/*\"
dummynet-anchor \"com.apple/*\"
anchor \"warren/*\" quick
anchor \"com.apple/*\"
load anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\"
";
        assert_eq!(with_warren_anchor(conf), expected);
    }

    #[test]
    fn moves_existing_warren_anchor_to_first_filter_rule() {
        let conf = "\
nat-anchor \"com.apple/*\"
anchor \"com.apple/*\"
anchor \"warren/*\" quick
";
        let expected = "\
nat-anchor \"com.apple/*\"
anchor \"warren/*\" quick
anchor \"com.apple/*\"
";
        assert_eq!(with_warren_anchor(conf), expected);
    }

    #[test]
    fn appends_warren_anchor_when_no_filter_rules_exist() {
        let conf = "scrub-anchor \"com.apple/*\"\n";
        let expected = "scrub-anchor \"com.apple/*\"\nanchor \"warren/*\" quick\n";
        assert_eq!(with_warren_anchor(conf), expected);
    }

    #[test]
    fn detects_warren_anchor_after_scrub_rules() {
        let rules = "\
scrub-anchor \"com.apple/*\" all fragment reassemble
anchor \"warren/*\" quick all
anchor \"com.apple/*\" all
dummynet-anchor \"com.apple/*\" all
";
        assert!(has_warren_anchor(rules));
    }

    #[test]
    fn rejects_warren_anchor_after_other_filter_rules() {
        let rules = "\
scrub-anchor \"com.apple/*\" all fragment reassemble
anchor \"com.apple/*\" all
anchor \"warren/*\" quick all
";
        assert!(!has_warren_anchor(rules));
    }
}
