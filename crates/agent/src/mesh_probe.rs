//! Round-trip probes carried only by the dedicated direct WireGuard interface.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// A private protocol subnet, separate from the IPv4 application tunnel.
const PREFIX: [u16; 6] = [0xfd77, 0x6172, 0x7265, 0x6e00, 0, 0];
const PORT: u16 = 51821;
const SILENCE: Duration = Duration::from_secs(8);
const PACKET_LEN: usize = 17;

/// A collision-free probe address for an IPv4 tunnel address.
pub fn address(ip: Ipv4Addr) -> Ipv6Addr {
    let [a, b, c, d] = ip.octets();
    Ipv6Addr::new(
        PREFIX[0],
        PREFIX[1],
        PREFIX[2],
        PREFIX[3],
        PREFIX[4],
        PREFIX[5],
        u16::from_be_bytes([a, b]),
        u16::from_be_bytes([c, d]),
    )
}

/// Opens the responder on an address owned only by the direct interface.
pub fn socket(ip: Ipv4Addr) -> std::io::Result<UdpSocket> {
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V6(address(ip)), PORT))?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// One peer's outstanding challenge and last authenticated round trip.
#[derive(Default)]
pub struct Probe {
    pending: Option<([u8; 16], Instant)>,
    heard: Option<Instant>,
}

impl Probe {
    /// Returns whether a recent response proved both directions work.
    pub fn alive(&self, now: Instant) -> bool {
        self.heard.is_some_and(|heard| now.duration_since(heard) < SILENCE)
    }

    /// Sends a new challenge. Failed sends do not prolong the route's lifetime.
    pub fn send(&mut self, socket: &UdpSocket, ip: Ipv4Addr, now: Instant) {
        let Ok(nonce) = crate::state::random_bytes::<16>() else { return };
        let mut packet = [0; PACKET_LEN];
        packet[0] = 1;
        packet[1..].copy_from_slice(&nonce);
        if socket.send_to(&packet, SocketAddr::new(IpAddr::V6(address(ip)), PORT)).is_ok() {
            self.pending = Some((nonce, now));
        }
    }

    /// Validates a response once, only for an unexpired outstanding challenge.
    pub fn receive(&mut self, packet: &[u8], now: Instant) {
        if packet.len() != PACKET_LEN || packet[0] != 2 {
            return;
        }
        if self.pending.is_some_and(|(nonce, sent)| now.duration_since(sent) < SILENCE && packet[1..] == nonce) {
            self.pending = None;
            self.heard = Some(now);
        }
    }
}

/// Drains a bounded batch, echoing requests and dispatching responses.
/// The caller accepts only known WireGuard probe source addresses.
pub fn drain(socket: &UdpSocket, mut receive: impl FnMut(SocketAddr, &[u8])) {
    let mut packet = [0; PACKET_LEN + 1];
    for _ in 0..256 {
        let Ok((len, source)) = socket.recv_from(&mut packet) else { break };
        if len != PACKET_LEN || source.port() != PORT {
            continue;
        }
        receive(source, &packet[..len]);
    }
}

/// Replies to a known peer's request. Responses never trigger responses.
pub fn reply(socket: &UdpSocket, source: SocketAddr, packet: &[u8]) {
    if packet.len() == PACKET_LEN && packet[0] == 1 {
        let mut response = [0; PACKET_LEN];
        response.copy_from_slice(packet);
        response[0] = 2;
        let _ = socket.send_to(&response, source);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_fresh_matching_responses_extend_liveness() {
        let now = Instant::now();
        let nonce = [7; 16];
        let mut p = Probe { pending: Some((nonce, now)), heard: None };
        let mut packet = vec![2];
        packet.extend_from_slice(&[8; 16]);
        p.receive(&packet, now);
        assert!(!p.alive(now));
        packet[1..].copy_from_slice(&nonce);
        packet[0] = 1;
        p.receive(&packet, now);
        assert!(!p.alive(now), "requests do not prove round trips");
        packet[0] = 2;
        p.receive(&packet, now);
        assert!(p.alive(now));
        p.receive(&packet, now + SILENCE);
        assert!(!p.alive(now + SILENCE), "replays do not refresh liveness");
        p.pending = Some((nonce, now));
        p.receive(&packet, now + SILENCE);
        assert!(!p.alive(now + SILENCE), "late responses do not refresh liveness");
    }

    #[test]
    fn addresses_preserve_all_tunnel_bits() {
        assert_eq!(address(Ipv4Addr::new(10, 77, 0, 5)).to_string(), "fd77:6172:7265:6e00::a4d:5");
        assert_ne!(address(Ipv4Addr::new(10, 0, 0, 1)), address(Ipv4Addr::new(10, 1, 0, 1)));
    }
}
