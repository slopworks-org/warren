//! Tiny blocking HTTP/1.0 client: one request per connection.
//!
//! Only plain HTTP is spoken: registration is authenticated by MACs and the
//! control channel runs inside the WireGuard tunnel. HTTP/1.0 keeps servers
//! from using chunked encoding; bodies end at `Content-Length` or EOF.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

const MAX_RESPONSE: usize = 256 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Reads wake up this often to notice a stop signal promptly.
const READ_SLICE: Duration = Duration::from_secs(1);

pub struct Response {
    pub status: u16,
    pub body: String,
}

fn stopped() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "stopping")
}

pub fn request(
    addr: &str,
    host: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
    timeout: Duration,
) -> io::Result<Response> {
    let addrs: Vec<SocketAddr> = addr.to_socket_addrs()?.collect();
    let mut last = io::Error::new(io::ErrorKind::NotFound, format!("{addr} did not resolve"));
    let mut stream = None;
    for a in addrs {
        if crate::stopping() {
            return Err(stopped());
        }
        match TcpStream::connect_timeout(&a, CONNECT_TIMEOUT) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last = e,
        }
    }
    let mut s = stream.ok_or(last)?;
    s.set_read_timeout(Some(READ_SLICE))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))?;

    let body = body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: warren-agent/{}\r\n\
         Content-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{body}",
        warren_proto::VERSION,
        body.len()
    );
    s.write_all(req.as_bytes())?;

    let deadline = Instant::now() + timeout;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > MAX_RESPONSE {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "response too large"));
                }
                if complete(&buf) {
                    break;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
                ) =>
            {
                if crate::stopping() {
                    return Err(stopped());
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "no response in time"));
                }
            }
            Err(e) => return Err(e),
        }
    }
    parse(&buf)
}

fn header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().filter_map(|l| l.split_once(':')).find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim())
}

fn content_length(head: &str) -> Option<usize> {
    header(head, "content-length").and_then(|v| v.parse().ok())
}

fn complete(buf: &[u8]) -> bool {
    let Some(end) = header_end(buf) else { return false };
    let head = String::from_utf8_lossy(&buf[..end]);
    content_length(&head).is_some_and(|n| buf.len() >= end + n)
}

/// Parses a complete response; a body shorter than its `Content-Length`
/// (the connection dropped) is an error, never a silently partial config.
fn parse(buf: &[u8]) -> io::Result<Response> {
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_string());
    let end = header_end(buf).ok_or_else(|| bad("incomplete response head"))?;
    let head = String::from_utf8_lossy(&buf[..end]);
    let status = head.split(' ').nth(1).and_then(|s| s.parse().ok()).ok_or_else(|| bad("bad status line"))?;
    if header(&head, "transfer-encoding").is_some() {
        return Err(bad("unsupported transfer encoding"));
    }
    let mut body = &buf[end..];
    if let Some(n) = content_length(&head) {
        body = body.get(..n).ok_or_else(|| bad("truncated response body"))?;
    }
    Ok(Response { status, body: String::from_utf8_lossy(body).into_owned() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nX: y\r\n\r\nabcdef";
        assert!(complete(raw));
        let r = parse(raw).unwrap();
        assert_eq!((r.status, r.body.as_str()), (200, "abc"));
        assert!(!complete(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc"));
        assert!(parse(b"garbage").is_err());
        assert!(parse(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc").is_err(), "truncated");
        assert!(parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc").is_err());
        assert_eq!(parse(b"HTTP/1.0 304 Not Modified\r\n\r\n").unwrap().status, 304);
    }
}
