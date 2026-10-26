//! Just enough IPv4 parsing for routing and ACL checks.

use std::net::Ipv4Addr;

/// The parts of an IPv4 packet the hub routes and filters on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flow {
    /// Source address.
    pub src: Ipv4Addr,
    /// Destination address.
    pub dst: Ipv4Addr,
    /// IP protocol number.
    pub proto: u8,
    /// `(source, destination)` ports of TCP/UDP packets, `None` for other
    /// protocols and non-first fragments.
    pub ports: Option<(u16, u16)>,
}

/// Parses an IPv4 header; `None` for IPv6 or malformed packets.
#[must_use]
pub fn ipv4_flow(p: &[u8]) -> Option<Flow> {
    let first = *p.first()?;
    if first >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(first & 0x0f) * 4;
    if ihl < 20 || p.len() < ihl {
        return None;
    }
    let src = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
    let dst = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
    let proto = p[9];
    let frag_offset = u16::from_be_bytes([p[6], p[7]]) & 0x1fff;
    let ports = if frag_offset == 0 && (proto == 6 || proto == 17) {
        p.get(ihl..ihl + 4).map(|h| (u16::from_be_bytes([h[0], h[1]]), u16::from_be_bytes([h[2], h[3]])))
    } else {
        None
    };
    Some(Flow { src, dst, proto, ports })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(proto: u8, frag: u16) -> Vec<u8> {
        let mut p = vec![0u8; 24];
        p[0] = 0x45;
        p[6..8].copy_from_slice(&frag.to_be_bytes());
        p[9] = proto;
        p[12..16].copy_from_slice(&[10, 77, 0, 2]);
        p[16..20].copy_from_slice(&[10, 77, 0, 3]);
        p[20..24].copy_from_slice(&[0x30, 0x39, 0x00, 0x50]);
        p
    }

    #[test]
    fn parses_tcp_ports() {
        let f = ipv4_flow(&packet(6, 0)).unwrap();
        assert_eq!(f.src, Ipv4Addr::new(10, 77, 0, 2));
        assert_eq!(f.dst, Ipv4Addr::new(10, 77, 0, 3));
        assert_eq!(f.ports, Some((12345, 80)));
    }

    #[test]
    fn fragments_and_other_protocols_have_no_ports() {
        assert_eq!(ipv4_flow(&packet(6, 5)).unwrap().ports, None);
        assert_eq!(ipv4_flow(&packet(1, 0)).unwrap().ports, None);
        assert_eq!(ipv4_flow(&[0x60; 40]), None, "IPv6");
        assert_eq!(ipv4_flow(&[0x45; 10]), None, "truncated");
    }
}
