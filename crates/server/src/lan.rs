//! Pairing agents on the same LAN, so they can reach each other directly
//! instead of through the hub.
//!
//! Each agent reports its private LAN addresses and its WireGuard port. Two
//! agents are taken to share a LAN when the hub sees them behind the same
//! public address (or sees both by their LAN addresses) and one has an
//! address inside a subnet of the other. A wrong guess costs nothing: the
//! agents route through the hub until a direct handshake succeeds.

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

const MAX_ADDRESSES: usize = 8;

/// An interface address with its prefix length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LanAddr {
    /// Address.
    pub ip: Ipv4Addr,
    /// Prefix length, 8..=30.
    pub prefix: u8,
}

impl LanAddr {
    fn contains(self, ip: Ipv4Addr) -> bool {
        let mask = u32::MAX << (32 - u32::from(self.prefix));
        u32::from(ip) & mask == u32::from(self.ip) & mask
    }
}

/// What an agent reports about its LAN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LanReport {
    /// Private addresses of its interfaces.
    pub addrs: Vec<LanAddr>,
    /// UDP port of its WireGuard interface.
    pub port: u16,
}

impl LanReport {
    /// Parses the `lan` and `port` poll parameters; `None` when the agent
    /// reported nothing usable.
    #[must_use]
    pub fn parse(lan: &str, port: u16) -> Option<LanReport> {
        let addrs: Vec<LanAddr> = lan
            .split(',')
            .filter_map(|a| {
                let (ip, prefix) = a.trim().split_once('/')?;
                let (ip, prefix) = (ip.parse::<Ipv4Addr>().ok()?, prefix.parse::<u8>().ok()?);
                (ip.is_private() && (8..=30).contains(&prefix)).then_some(LanAddr { ip, prefix })
            })
            .take(MAX_ADDRESSES)
            .collect();
        (port != 0 && !addrs.is_empty()).then_some(LanReport { addrs, port })
    }

    /// The address of `self` that `other` can reach on a shared subnet,
    /// preferring the narrowest subnet. A subnet in which both report the
    /// same address is not shared: such addresses come from software that
    /// uses the same subnet on every host, like container bridges.
    fn reachable_from(&self, other: &LanReport) -> Option<Ipv4Addr> {
        let mut best: Option<(u8, Ipv4Addr)> = None;
        for o in &other.addrs {
            for a in self.addrs.iter().filter(|a| o.contains(a.ip) && a.prefix == o.prefix) {
                if a.ip != o.ip && best.is_none_or(|(p, _)| o.prefix > p) {
                    best = Some((o.prefix, a.ip));
                }
            }
        }
        best.map(|(_, ip)| ip)
    }
}

/// An agent as seen by the hub.
pub struct Seen<'a> {
    /// What the agent reported.
    pub report: &'a LanReport,
    /// Where the hub receives its packets from.
    pub public: IpAddr,
}

impl Seen<'_> {
    fn reached_on_lan(&self) -> bool {
        self.report.addrs.iter().any(|a| IpAddr::V4(a.ip) == self.public)
    }
}

/// The endpoint at which `a` reaches `b` directly, if they share a LAN.
/// Symmetric: `b` gets an endpoint for `a` exactly when `a` gets one for `b`.
#[must_use]
pub fn endpoint(a: &Seen<'_>, b: &Seen<'_>) -> Option<SocketAddrV4> {
    let behind_one_nat = a.public == b.public;
    let both_local = a.reached_on_lan() && b.reached_on_lan();
    if !(behind_one_nat || both_local) {
        return None;
    }
    a.report.reachable_from(b.report)?;
    let ip = b.report.reachable_from(a.report)?;
    Some(SocketAddrV4::new(ip, b.report.port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(lan: &str, port: u16) -> LanReport {
        LanReport::parse(lan, port).unwrap()
    }

    fn seen<'a>(report: &'a LanReport, public: &str) -> Seen<'a> {
        Seen { report, public: public.parse().unwrap() }
    }

    #[test]
    fn parse_keeps_private_addresses() {
        let r = report("192.168.1.10/24, 8.8.8.8/24,10.0.0.1/32,172.16.0.5/12,junk", 41000);
        assert_eq!(r.addrs.len(), 2);
        assert_eq!(r.addrs[1], LanAddr { ip: Ipv4Addr::new(172, 16, 0, 5), prefix: 12 });
        assert_eq!(LanReport::parse("192.168.1.10/24", 0), None);
        assert_eq!(LanReport::parse("8.8.8.8/24", 1), None);
        assert_eq!(LanReport::parse("", 1), None);
    }

    #[test]
    fn same_nat_and_subnet() {
        let router = report("192.168.1.1/24,172.17.0.1/16", 41000);
        let nas = report("192.168.1.10/24,172.17.0.1/16", 42000);
        let (r, n) = (seen(&router, "203.0.113.5"), seen(&nas, "203.0.113.5"));
        assert_eq!(endpoint(&r, &n), Some("192.168.1.10:42000".parse().unwrap()));
        assert_eq!(endpoint(&n, &r), Some("192.168.1.1:41000".parse().unwrap()));
        let elsewhere = seen(&nas, "198.51.100.7");
        assert_eq!(endpoint(&r, &elsewhere), None, "another public address is another LAN");
    }

    #[test]
    fn identical_addresses_are_not_a_lan() {
        let a = report("172.17.0.1/16", 1);
        let b = report("172.17.0.1/16", 2);
        assert_eq!(endpoint(&seen(&a, "203.0.113.5"), &seen(&b, "203.0.113.5")), None);
    }

    #[test]
    fn prefers_the_narrowest_subnet() {
        let a = report("10.0.0.2/8,192.168.1.2/24", 1);
        let b = report("10.1.0.3/8,192.168.1.3/24", 2);
        assert_eq!(
            endpoint(&seen(&a, "203.0.113.5"), &seen(&b, "203.0.113.5")),
            Some("192.168.1.3:2".parse().unwrap())
        );
    }

    #[test]
    fn server_on_the_lan() {
        let a = report("192.168.1.2/24", 1);
        let b = report("192.168.1.3/24", 2);
        let (sa, sb) = (seen(&a, "192.168.1.2"), seen(&b, "192.168.1.3"));
        assert_eq!(endpoint(&sa, &sb), Some("192.168.1.3:2".parse().unwrap()));
        assert_eq!(endpoint(&sa, &seen(&b, "198.51.100.7")), None);
    }

    #[test]
    fn mismatched_prefixes_pair_nobody() {
        let a = report("192.168.0.2/16", 1);
        let b = report("192.168.1.3/24", 2);
        assert_eq!(endpoint(&seen(&a, "203.0.113.5"), &seen(&b, "203.0.113.5")), None);
    }
}
