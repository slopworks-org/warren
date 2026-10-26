//! Small helpers: randomness, hashing, time, encodings.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use warren_proto::codec::{b64url_encode, hex_encode};

/// Seconds since the Unix epoch.
#[must_use]
pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).ok().and_then(|d| i64::try_from(d.as_secs()).ok()).unwrap_or(0)
}

/// Converts a `SystemTime` to Unix seconds, clamping times before 1970 to 0.
#[must_use]
pub fn unix(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH).ok().and_then(|d| i64::try_from(d.as_secs()).ok()).unwrap_or(0)
}

/// Fills an array from the OS CSPRNG.
///
/// # Panics
/// Never in practice: `getrandom` fails only when the OS has no entropy
/// source at all, and then nothing secure can run, so the process aborts.
#[expect(clippy::panic, reason = "running without an OS RNG would compromise every secret")]
#[must_use]
pub fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    if let Err(e) = getrandom::getrandom(&mut b) {
        panic!("the operating system's random number generator failed: {e}");
    }
    b
}

/// A random URL-safe token with 256 bits of entropy.
#[must_use]
pub fn token() -> String {
    b64url_encode(&random::<32>())
}

/// Hex SHA-256: how bearer tokens are stored, so a database leak reveals none.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    hex_encode(&Sha256::digest(data))
}

/// HMAC-SHA256 of `parts` joined by `|`.
///
/// # Panics
/// Never: HMAC accepts keys of any length.
#[expect(clippy::expect_used, reason = "HMAC accepts keys of any length, so new_from_slice cannot fail")]
#[must_use]
pub fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            m.update(b"|");
        }
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// 64-bit FNV-1a, for cheap content versions (not for security).
#[must_use]
pub fn fnv64(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3))
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 without padding, as authenticator apps expect.
#[must_use]
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(B32[((acc >> bits) & 31) as usize]));
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(B32[((acc << (5 - bits)) & 31) as usize]));
    }
    out
}

/// Decodes base32, ignoring case, spaces and padding.
#[must_use]
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes().filter(|c| *c != b' ' && *c != b'=') {
        let v = B32.iter().position(|&x| x == c.to_ascii_uppercase())?;
        acc = (acc << 5) | u32::try_from(v).ok()?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits).to_le_bytes()[0]);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Escapes text for HTML element content and attribute values.
#[must_use]
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// Percent-encodes a query-string component.
#[must_use]
pub fn url_encode(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// True if `next` is a same-origin relative path safe to redirect to.
#[must_use]
pub fn safe_next(next: &str) -> bool {
    next.starts_with('/') && !next.starts_with("//") && !next.starts_with("/\\") && !next.contains(['\r', '\n'])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_rfc4648() {
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_decode("mzxw6ytboi======").unwrap(), b"foobar");
        assert_eq!(base32_decode("1"), None);
        let r = random::<20>();
        assert_eq!(base32_decode(&base32_encode(&r)).unwrap(), r);
    }

    #[test]
    fn misc() {
        assert_eq!(html_escape("<a href=\"x\">&'"), "&lt;a href=&quot;x&quot;&gt;&amp;&#39;");
        assert!(safe_next("/a?b=c"));
        assert!(!safe_next("//evil.com") && !safe_next("https://evil.com") && !safe_next("/\\evil"));
        assert_ne!(token(), token());
        assert_eq!(sha256_hex(b"abc").len(), 64);
        assert_ne!(fnv64(b"a"), fnv64(b"b"));
        assert_ne!(hmac(b"k", &[b"a", b"b"]), hmac(b"k", &[b"ab"]));
    }
}
