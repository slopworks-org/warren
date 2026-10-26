//! Minimal base64 and hex codecs.

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn encode(input: &[u8], table: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let chars = chunk.len() + 1;
        for i in 0..4 {
            if i < chars {
                out.push(table[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

fn decode(input: &str, table: &[u8; 64]) -> Option<Vec<u8>> {
    let input = input.trim_end_matches('=').as_bytes();
    if input.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for &c in input {
        let v = u32::try_from(table.iter().position(|&t| t == c)?).ok()?;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            // acc holds fewer than 16 bits here, so the low byte is the decoded one.
            out.push((acc >> bits).to_le_bytes()[0]);
            acc &= (1 << bits) - 1;
        }
    }
    // Leftover bits must be zero for a canonical encoding.
    if acc != 0 {
        return None;
    }
    Some(out)
}

/// Standard base64 with padding.
#[must_use]
pub fn b64_encode(input: &[u8]) -> String {
    encode(input, STD, true)
}

/// Decodes standard base64; padding is optional. `None` on invalid or non-canonical input.
#[must_use]
pub fn b64_decode(input: &str) -> Option<Vec<u8>> {
    decode(input, STD)
}

/// URL-safe base64 without padding.
#[must_use]
pub fn b64url_encode(input: &[u8]) -> String {
    encode(input, URL, false)
}

/// Decodes URL-safe base64. `None` on invalid or non-canonical input.
#[must_use]
pub fn b64url_decode(input: &str) -> Option<Vec<u8>> {
    decode(input, URL)
}

/// Encodes a 32-byte WireGuard key the way `wg(8)` prints it.
#[must_use]
pub fn encode_key(key: &[u8; 32]) -> String {
    b64_encode(key)
}

/// Decodes a key printed by [`encode_key`].
#[must_use]
pub fn decode_key(s: &str) -> Option<[u8; 32]> {
    if s.len() != 44 {
        return None;
    }
    b64_decode(s)?.try_into().ok()
}

/// Lowercase hex.
#[must_use]
pub fn hex_encode(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(input.len() * 2);
    for b in input {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}

/// Decodes hex of either case. `None` on odd length or a non-hex digit.
#[must_use]
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    // from_str_radix alone would also accept a sign, e.g. "+f".
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// Constant-time comparison for MACs and secrets.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    subtle::ConstantTimeEq::ct_eq(a, b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648_vectors() {
        let cases = [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foobar", "Zm9vYmFy")];
        for (plain, enc) in cases {
            assert_eq!(b64_encode(plain.as_bytes()), enc);
            assert_eq!(b64_decode(enc).unwrap(), plain.as_bytes());
        }
        assert_eq!(b64url_encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(b64url_decode("-_8").unwrap(), vec![0xfb, 0xff]);
        assert!(b64_decode("Zh==").is_none(), "non-canonical trailing bits");
        assert!(b64_decode("Z").is_none());
        assert!(b64_decode("Zm9v!").is_none());
    }

    #[test]
    fn keys_and_hex() {
        let key = [0xabu8; 32];
        let enc = encode_key(&key);
        assert_eq!(enc.len(), 44);
        assert_eq!(decode_key(&enc), Some(key));
        assert_eq!(decode_key("short"), None);
        assert_eq!(hex_encode(&[0, 15, 255]), "000fff");
        assert_eq!(hex_decode("000fff"), Some(vec![0, 15, 255]));
        assert_eq!(hex_decode("0g"), None);
        assert_eq!(hex_decode("+f"), None, "no signs");
        assert!(ct_eq(b"abc", b"abc") && !ct_eq(b"abc", b"abd") && !ct_eq(b"a", b"ab"));
    }
}
