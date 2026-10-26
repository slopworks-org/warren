//! Tunnel address allocation.

use crate::config::Net4;
use std::collections::HashSet;
use std::hash::BuildHasher;
use std::net::Ipv4Addr;

/// Returns the lowest free device address in `net`.
///
/// The network address, the server's address (first host) and the broadcast
/// address are never handed out.
pub fn allocate<S: BuildHasher>(net: Net4, used: &HashSet<Ipv4Addr, S>) -> Option<Ipv4Addr> {
    let base = u32::from(net.addr);
    let broadcast = base | !net.mask();
    (base + 2..broadcast).map(Ipv4Addr::from).find(|ip| !used.contains(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> Net4 {
        Net4::parse(s).unwrap()
    }

    #[test]
    fn skips_reserved_and_used() {
        let n = net("10.77.0.0/16");
        let mut used = HashSet::new();
        assert_eq!(allocate(n, &used), Some(Ipv4Addr::new(10, 77, 0, 2)));
        used.insert(Ipv4Addr::new(10, 77, 0, 2));
        used.insert(Ipv4Addr::new(10, 77, 0, 3));
        assert_eq!(allocate(n, &used), Some(Ipv4Addr::new(10, 77, 0, 4)));
    }

    #[test]
    fn reuses_freed_addresses_and_crosses_octets() {
        let n = net("10.77.0.0/16");
        let mut used: HashSet<_> = (2..=255).map(|i| Ipv4Addr::new(10, 77, 0, i)).collect();
        assert_eq!(allocate(n, &used), Some(Ipv4Addr::new(10, 77, 1, 0)));
        used.remove(&Ipv4Addr::new(10, 77, 0, 9));
        assert_eq!(allocate(n, &used), Some(Ipv4Addr::new(10, 77, 0, 9)));
    }

    #[test]
    fn exhaustion() {
        let n = net("192.168.5.0/30"); // .0 network, .1 server, .2 device, .3 broadcast
        let mut used = HashSet::new();
        let first = allocate(n, &used).unwrap();
        assert_eq!(first, Ipv4Addr::new(192, 168, 5, 2));
        used.insert(first);
        assert_eq!(allocate(n, &used), None);
    }
}
