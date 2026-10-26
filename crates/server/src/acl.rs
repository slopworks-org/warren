//! Device-to-device access control.
//!
//! Devices of the same user reach each other freely; anything else needs an
//! administrator rule. Rules are directional ("source may open connections to
//! destination"); replies are allowed by connection tracking in both tunnel
//! backends. The compiled [`Acl`] is what the backends enforce: the kernel
//! backend turns it into an nftables ruleset, the userspace one checks it per
//! packet.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;
use thiserror::Error;

/// IP protocol numbers used by port rules.
pub const PROTO_TCP: u8 = 6;
/// UDP protocol number.
pub const PROTO_UDP: u8 = 17;

/// Who a rule applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Subject {
    /// Every device.
    Any,
    /// Every device of a user.
    User(i64),
    /// One device.
    Device(i64),
}

/// A malformed subject or port specification.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AclParseError {
    /// Not `any`, `user:<id>` or `device:<id>`.
    #[error("invalid subject {0:?}: use any, user:<id> or device:<id>")]
    Subject(String),
    /// Not `tcp:<port>[-<port>]`, `udp:…` or `any:…`.
    #[error("invalid port {0:?}: use tcp:22, udp:53 or tcp:8000-8100")]
    Port(String),
}

impl FromStr for Subject {
    type Err = AclParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = || AclParseError::Subject(s.to_string());
        match s.split_once(':') {
            None if s == "any" => Ok(Subject::Any),
            Some(("user", id)) => id.parse().map(Subject::User).map_err(|_| bad()),
            Some(("device", id)) => id.parse().map(Subject::Device).map_err(|_| bad()),
            _ => Err(bad()),
        }
    }
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Subject::Any => f.write_str("any"),
            Subject::User(id) => write!(f, "user:{id}"),
            Subject::Device(id) => write!(f, "device:{id}"),
        }
    }
}

impl Serialize for Subject {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Subject {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?.parse().map_err(serde::de::Error::custom)
    }
}

/// A protocol and an inclusive destination port range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortSpec {
    /// [`PROTO_TCP`] or [`PROTO_UDP`].
    pub proto: u8,
    /// First port.
    pub from: u16,
    /// Last port, inclusive.
    pub to: u16,
}

impl PortSpec {
    /// Parses a comma-separated list like `tcp:22, any:8000-8100`.
    /// `any:` expands to one TCP and one UDP entry. Empty means "all traffic".
    ///
    /// # Errors
    /// On any malformed item.
    pub fn parse_list(s: &str) -> Result<Vec<PortSpec>, AclParseError> {
        let mut out = Vec::new();
        for item in s.split(',').map(str::trim).filter(|i| !i.is_empty()) {
            let bad = || AclParseError::Port(item.to_string());
            let (proto, range) = item.split_once(':').ok_or_else(bad)?;
            let (a, b) = range.split_once('-').unwrap_or((range, range));
            let from: u16 = a.trim().parse().map_err(|_| bad())?;
            let to: u16 = b.trim().parse().map_err(|_| bad())?;
            if from == 0 || from > to {
                return Err(bad());
            }
            match proto {
                "tcp" => out.push(PortSpec { proto: PROTO_TCP, from, to }),
                "udp" => out.push(PortSpec { proto: PROTO_UDP, from, to }),
                "any" => {
                    out.push(PortSpec { proto: PROTO_TCP, from, to });
                    out.push(PortSpec { proto: PROTO_UDP, from, to });
                }
                _ => return Err(bad()),
            }
        }
        Ok(out)
    }

    /// Formats a list back into [`PortSpec::parse_list`] syntax.
    #[must_use]
    pub fn format_list(list: &[PortSpec]) -> String {
        list.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")
    }

    fn matches(self, proto: u8, port: u16) -> bool {
        self.proto == proto && (self.from..=self.to).contains(&port)
    }
}

impl fmt::Display for PortSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let p = if self.proto == PROTO_TCP { "tcp" } else { "udp" };
        if self.from == self.to { write!(f, "{p}:{}", self.from) } else { write!(f, "{p}:{}-{}", self.from, self.to) }
    }
}

/// An administrator rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// Devices that may open connections.
    pub src: Subject,
    /// Devices they may connect to.
    pub dst: Subject,
    /// Allowed destination ports; empty allows all traffic.
    pub ports: Vec<PortSpec>,
}

/// A device as the ACL sees it.
#[derive(Clone, Copy, Debug)]
pub struct Node {
    /// Device id.
    pub device: i64,
    /// Owner's user id.
    pub user: i64,
    /// Tunnel address.
    pub ip: Ipv4Addr,
}

/// The compiled allow-list, keyed by (source, destination) address.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Acl {
    /// Pairs allowed to exchange any traffic.
    pub all: BTreeSet<(Ipv4Addr, Ipv4Addr)>,
    /// Pairs allowed only on specific ports.
    pub ports: BTreeMap<(Ipv4Addr, Ipv4Addr), BTreeSet<PortSpec>>,
}

fn matches(s: Subject, n: &Node) -> bool {
    match s {
        Subject::Any => true,
        Subject::User(u) => n.user == u,
        Subject::Device(d) => n.device == d,
    }
}

impl Acl {
    /// Expands the default same-user policy and `rules` over `nodes`.
    #[must_use]
    pub fn compile(nodes: &[Node], rules: &[Rule]) -> Acl {
        let mut acl = Acl::default();
        for a in nodes {
            for b in nodes.iter().filter(|b| b.ip != a.ip && b.user == a.user) {
                acl.all.insert((a.ip, b.ip));
            }
        }
        for r in rules {
            for a in nodes.iter().filter(|n| matches(r.src, n)) {
                for b in nodes.iter().filter(|n| n.ip != a.ip && matches(r.dst, n)) {
                    if r.ports.is_empty() {
                        acl.all.insert((a.ip, b.ip));
                    } else {
                        acl.ports.entry((a.ip, b.ip)).or_default().extend(r.ports.iter().copied());
                    }
                }
            }
        }
        // Port rules are redundant for pairs that may exchange everything.
        acl.ports.retain(|pair, _| !acl.all.contains(pair));
        acl
    }

    /// True if `src` may start a flow to `dst`. `port` is the destination
    /// port for TCP/UDP and `None` for other protocols or fragments.
    #[must_use]
    pub fn allows(&self, src: Ipv4Addr, dst: Ipv4Addr, proto: u8, port: Option<u16>) -> bool {
        if self.all.contains(&(src, dst)) {
            return true;
        }
        let Some(port) = port else { return false };
        self.ports.get(&(src, dst)).is_some_and(|specs| specs.iter().any(|s| s.matches(proto, port)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 77, 0, last)
    }

    fn nodes() -> Vec<Node> {
        vec![
            Node { device: 1, user: 1, ip: ip(2) },
            Node { device: 2, user: 1, ip: ip(3) },
            Node { device: 3, user: 2, ip: ip(4) },
            Node { device: 4, user: 3, ip: ip(5) },
        ]
    }

    #[test]
    fn same_user_devices_see_each_other_only() {
        let acl = Acl::compile(&nodes(), &[]);
        assert!(acl.allows(ip(2), ip(3), PROTO_TCP, Some(80)));
        assert!(acl.allows(ip(3), ip(2), 1, None));
        assert!(!acl.allows(ip(2), ip(4), PROTO_TCP, Some(80)));
        assert!(!acl.allows(ip(4), ip(2), PROTO_UDP, Some(53)));
        assert!(!acl.allows(ip(2), ip(2), PROTO_TCP, Some(1)), "no self pairs");
    }

    #[test]
    fn rules_are_directional_and_port_scoped() {
        let rules = [
            Rule { src: Subject::User(2), dst: Subject::Device(1), ports: PortSpec::parse_list("tcp:22").unwrap() },
            Rule { src: Subject::Device(4), dst: Subject::Any, ports: vec![] },
        ];
        let acl = Acl::compile(&nodes(), &rules);
        assert!(acl.allows(ip(4), ip(2), PROTO_TCP, Some(22)));
        assert!(!acl.allows(ip(4), ip(2), PROTO_TCP, Some(23)));
        assert!(!acl.allows(ip(4), ip(2), PROTO_UDP, Some(22)));
        assert!(!acl.allows(ip(4), ip(2), 1, None), "ICMP needs an all-traffic rule");
        assert!(!acl.allows(ip(2), ip(4), PROTO_TCP, Some(22)), "rules are one-way");
        for target in [2, 3, 4] {
            assert!(acl.allows(ip(5), ip(target), 1, None));
        }
    }

    #[test]
    fn port_rules_fold_into_all_traffic_pairs() {
        let rules = [Rule { src: Subject::Any, dst: Subject::Any, ports: PortSpec::parse_list("tcp:80").unwrap() }];
        let acl = Acl::compile(&nodes(), &rules);
        assert!(!acl.ports.contains_key(&(ip(2), ip(3))), "same-user pair already allows everything");
        assert!(acl.ports.contains_key(&(ip(2), ip(4))));
    }

    #[test]
    fn parsing() {
        assert_eq!("any".parse(), Ok(Subject::Any));
        assert_eq!("user:7".parse(), Ok(Subject::User(7)));
        assert_eq!("device:9".parse(), Ok(Subject::Device(9)));
        assert!("user:x".parse::<Subject>().is_err() && "all".parse::<Subject>().is_err());
        let p = PortSpec::parse_list(" tcp:22, any:8000-8100 ").unwrap();
        assert_eq!(p.len(), 3);
        assert_eq!(PortSpec::format_list(&p), "tcp:22,tcp:8000-8100,udp:8000-8100");
        for bad in ["tcp", "icmp:1", "tcp:0", "tcp:9-1", "tcp:70000"] {
            assert!(PortSpec::parse_list(bad).is_err(), "{bad}");
        }
        assert_eq!(PortSpec::parse_list("").unwrap(), Vec::new());
    }
}
