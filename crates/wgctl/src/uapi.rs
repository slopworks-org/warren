//! The cross-platform WireGuard configuration protocol of userspace
//! implementations such as wireguard-go: `key=value` lines over a Unix socket.
//! See <https://www.wireguard.com/xplatform/>.

use crate::{DeviceInfo, DeviceSet, Key, PeerInfo};
use std::fmt::Write as _;
use std::io::{self, BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, SystemTime};

const TIMEOUT: Duration = Duration::from_secs(5);

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn hex(key: &Key) -> String {
    key.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn unhex(s: &str) -> Option<Key> {
    let mut key = [0u8; 32];
    if s.len() != 64 {
        return None;
    }
    for (i, b) in key.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(key)
}

/// Sends one request and returns the reply lines before the blank line that
/// ends it, without the final `errno=` line, which becomes the error.
fn exchange(sock: &Path, request: &str) -> io::Result<Vec<String>> {
    let mut stream = UnixStream::connect(sock)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    stream.write_all(request.as_bytes())?;
    let mut lines = Vec::new();
    for line in BufReader::new(stream).lines() {
        let line = line?;
        if line.is_empty() {
            break;
        }
        lines.push(line);
    }
    match lines.pop().as_deref().and_then(|l| l.strip_prefix("errno=")) {
        Some("0") => Ok(lines),
        Some(n) => Err(n
            .parse::<i32>()
            .map_or_else(|_| invalid(format!("bad errno {n:?}")), |n| io::Error::from_raw_os_error(n.abs()))),
        None => Err(invalid("reply without errno".into())),
    }
}

fn parse_endpoint(s: &str) -> Option<SocketAddr> {
    // An unset endpoint is reported as a zero address on some implementations.
    s.parse().ok().filter(|a: &SocketAddr| !a.ip().is_unspecified())
}

fn parse_get(lines: &[String]) -> io::Result<DeviceInfo> {
    let mut dev = DeviceInfo::default();
    let mut handshake = (0u64, 0u32);
    let bad = |k: &str, v: &str| invalid(format!("bad {k} value {v:?}"));
    for line in lines {
        let (k, v) = line.split_once('=').ok_or_else(|| invalid(format!("bad line {line:?}")))?;
        if k == "public_key" {
            let public_key = unhex(v).ok_or_else(|| bad(k, v))?;
            dev.peers.push(PeerInfo { public_key, ..PeerInfo::default() });
            handshake = (0, 0);
            continue;
        }
        let Some(peer) = dev.peers.last_mut() else {
            if k == "listen_port" {
                dev.listen_port = v.parse().map_err(|_| bad(k, v))?;
            }
            continue;
        };
        match k {
            "endpoint" => peer.endpoint = parse_endpoint(v),
            "rx_bytes" => peer.rx_bytes = v.parse().map_err(|_| bad(k, v))?,
            "tx_bytes" => peer.tx_bytes = v.parse().map_err(|_| bad(k, v))?,
            "persistent_keepalive_interval" => peer.keepalive = v.parse().map_err(|_| bad(k, v))?,
            "allowed_ip" => peer.allowed_ips.push(v.parse().map_err(|_| bad(k, v))?),
            "last_handshake_time_sec" => handshake.0 = v.parse().map_err(|_| bad(k, v))?,
            "last_handshake_time_nsec" => handshake.1 = v.parse().map_err(|_| bad(k, v))?,
            _ => continue,
        }
        peer.last_handshake =
            (handshake != (0, 0)).then(|| SystemTime::UNIX_EPOCH + Duration::new(handshake.0, handshake.1));
    }
    Ok(dev)
}

fn set_request(set: &DeviceSet) -> String {
    let mut r = String::from("set=1\n");
    if let Some(k) = &set.private_key {
        let _ = writeln!(r, "private_key={}", hex(k));
    }
    if let Some(p) = set.listen_port {
        let _ = writeln!(r, "listen_port={p}");
    }
    if set.replace_peers {
        r.push_str("replace_peers=true\n");
    }
    for p in &set.peers {
        let _ = writeln!(r, "public_key={}", hex(&p.public_key));
        if p.remove {
            r.push_str("remove=true\n");
            continue;
        }
        if let Some(e) = p.endpoint {
            let _ = writeln!(r, "endpoint={e}");
        }
        if let Some(k) = p.keepalive {
            let _ = writeln!(r, "persistent_keepalive_interval={k}");
        }
        if let Some(ips) = &p.allowed_ips {
            r.push_str("replace_allowed_ips=true\n");
            for ip in ips {
                let _ = writeln!(r, "allowed_ip={ip}");
            }
        }
    }
    r.push('\n');
    r
}

/// Reads the device behind the UAPI socket `sock`. The device's own public
/// key is not reported: deriving it needs Curve25519, which this crate avoids.
pub fn get_device(sock: &Path) -> io::Result<DeviceInfo> {
    parse_get(&exchange(sock, "get=1\n\n")?)
}

/// Applies `set` to the device behind the UAPI socket `sock`.
pub fn set_device(sock: &Path, set: &DeviceSet) -> io::Result<()> {
    exchange(sock, &set_request(set)).map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PeerSet;

    #[test]
    fn key_hex_roundtrip() {
        let mut k = [0u8; 32];
        k[0] = 0xab;
        k[31] = 0x01;
        let h = hex(&k);
        assert_eq!(h.len(), 64);
        assert!(h.starts_with("ab00"));
        assert_eq!(unhex(&h), Some(k));
        assert_eq!(unhex("zz"), None);
    }

    #[test]
    fn parses_get_reply() {
        let key = hex(&[7u8; 32]);
        let reply = format!(
            "private_key={key}\nlisten_port=51820\npublic_key={key}\nendpoint=[::1]:51820\n\
             last_handshake_time_sec=1700000000\nlast_handshake_time_nsec=5\nrx_bytes=10\ntx_bytes=20\n\
             persistent_keepalive_interval=25\nallowed_ip=10.77.0.0/16\nallowed_ip=fd00::/8\n\
             public_key={key}\nendpoint=0.0.0.0:0\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0"
        );
        let lines: Vec<String> = reply.lines().map(String::from).collect();
        let dev = parse_get(&lines).unwrap();
        assert_eq!(dev.listen_port, 51820);
        assert_eq!(dev.peers.len(), 2);
        let p = &dev.peers[0];
        assert_eq!(p.public_key, [7u8; 32]);
        assert_eq!(p.endpoint, Some("[::1]:51820".parse().unwrap()));
        assert_eq!(p.last_handshake, Some(SystemTime::UNIX_EPOCH + Duration::new(1_700_000_000, 5)));
        assert_eq!((p.rx_bytes, p.tx_bytes, p.keepalive), (10, 20, 25));
        assert_eq!(p.allowed_ips, vec!["10.77.0.0/16".parse().unwrap(), "fd00::/8".parse().unwrap()]);
        assert_eq!(dev.peers[1].endpoint, None);
        assert_eq!(dev.peers[1].last_handshake, None);
    }

    #[test]
    fn builds_set_request() {
        let set = DeviceSet {
            private_key: Some([1u8; 32]),
            peers: vec![
                PeerSet {
                    public_key: [2u8; 32],
                    endpoint: Some("1.2.3.4:51820".parse().unwrap()),
                    keepalive: Some(25),
                    allowed_ips: Some(vec!["10.77.0.0/16".parse().unwrap()]),
                    remove: false,
                },
                PeerSet { public_key: [3u8; 32], remove: true, ..PeerSet::default() },
            ],
            ..DeviceSet::default()
        };
        let want = format!(
            "set=1\nprivate_key={}\npublic_key={}\nendpoint=1.2.3.4:51820\npersistent_keepalive_interval=25\n\
             replace_allowed_ips=true\nallowed_ip=10.77.0.0/16\npublic_key={}\nremove=true\n\n",
            hex(&[1u8; 32]),
            hex(&[2u8; 32]),
            hex(&[3u8; 32]),
        );
        assert_eq!(set_request(&set), want);
    }

    #[test]
    fn talks_over_a_socket() {
        let dir = std::env::temp_dir().join(format!("wgctl-uapi-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("t.sock");
        let _ = std::fs::remove_file(&sock);
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            for reply in ["listen_port=7\nerrno=0\n\n", "errno=22\n\n"] {
                let (s, _) = listener.accept().unwrap();
                let mut r = BufReader::new(s);
                let mut line = String::new();
                while r.read_line(&mut line).unwrap() > 0 && !line.ends_with("\n\n") {}
                r.get_mut().write_all(reply.as_bytes()).unwrap();
            }
        });
        assert_eq!(get_device(&sock).unwrap().listen_port, 7);
        let err = set_device(&sock, &DeviceSet::default()).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(22));
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
