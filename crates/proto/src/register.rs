//! Registration tokens and the MACs that authenticate registration.
//!
//! The agent registers over plain HTTP so it needs no TLS stack. The token's
//! secret never crosses the wire: the request carries an HMAC of its fields
//! keyed by the secret, and the server answers with an HMAC over the reply and
//! the request's nonce. An on-path attacker can neither register its own key
//! nor substitute the server's key or endpoint in the reply.

use crate::codec::{b64url_decode, b64url_encode, ct_eq, hex_decode, hex_encode};
use crate::kv::Kv;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Prefix that marks a registration token.
pub const TOKEN_PREFIX: &str = "wrt_";
/// Length of the token's public id, in bytes.
pub const TOKEN_ID_LEN: usize = 6;
/// Length of the token's secret, in bytes.
pub const TOKEN_SECRET_LEN: usize = 18;

const REQUEST_LABEL: &[u8] = b"warren-register-request-v1\n";
const REPLY_LABEL: &[u8] = b"warren-register-reply-v1\n";

/// A one-time device registration token: a public id plus a secret.
#[derive(Clone)]
pub struct RegToken {
    /// Public id, sent in the clear.
    pub id: [u8; TOKEN_ID_LEN],
    /// Secret; only ever used as a MAC key.
    pub secret: [u8; TOKEN_SECRET_LEN],
}

impl PartialEq for RegToken {
    /// Constant-time in the secret.
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && ct_eq(&self.secret, &other.secret)
    }
}

impl Eq for RegToken {}

impl Drop for RegToken {
    fn drop(&mut self) {
        // Best effort: volatile writes are not optimized away.
        for b in &mut self.secret {
            // SAFETY: `b` is a valid, aligned, exclusive reference.
            unsafe { std::ptr::write_volatile(b, 0) };
        }
    }
}

impl std::fmt::Debug for RegToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RegToken({})", self.id_hex())
    }
}

impl RegToken {
    /// Encodes as `wrt_` + URL-safe base64 of id and secret.
    #[must_use]
    pub fn encode(&self) -> String {
        let mut raw = [0u8; TOKEN_ID_LEN + TOKEN_SECRET_LEN];
        raw[..TOKEN_ID_LEN].copy_from_slice(&self.id);
        raw[TOKEN_ID_LEN..].copy_from_slice(&self.secret);
        format!("{TOKEN_PREFIX}{}", b64url_encode(&raw))
    }

    /// Parses [`RegToken::encode`] output; surrounding whitespace is ignored.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let raw = b64url_decode(s.trim().strip_prefix(TOKEN_PREFIX)?)?;
        if raw.len() != TOKEN_ID_LEN + TOKEN_SECRET_LEN {
            return None;
        }
        Some(RegToken { id: raw[..TOKEN_ID_LEN].try_into().ok()?, secret: raw[TOKEN_ID_LEN..].try_into().ok()? })
    }

    /// Public half of the token: identifies it in requests and logs.
    #[must_use]
    pub fn id_hex(&self) -> String {
        hex_encode(&self.id)
    }
}

#[expect(clippy::expect_used, reason = "HMAC accepts keys of any length, so new_from_slice cannot fail")]
fn mac(secret: &[u8], label: &[u8], parts: &[&[u8]]) -> Hmac<Sha256> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("HMAC takes any key length");
    m.update(label);
    for p in parts {
        m.update(p);
    }
    m
}

fn tag(m: Hmac<Sha256>) -> String {
    hex_encode(&m.finalize().into_bytes())
}

/// Adds the `mac` field to a registration request.
pub fn sign_request(secret: &[u8], kv: &mut Kv) {
    let t = tag(mac(secret, REQUEST_LABEL, &[kv.encode_without("mac").as_bytes()]));
    kv.push("mac", t);
}

/// Checks the `mac` field of a registration request.
#[must_use]
pub fn verify_request(secret: &[u8], kv: &Kv) -> bool {
    verify(kv, mac(secret, REQUEST_LABEL, &[kv.encode_without("mac").as_bytes()]))
}

/// Adds the `mac` field to a reply, binding it to the request's nonce.
pub fn sign_reply(secret: &[u8], nonce: &str, kv: &mut Kv) {
    let body = kv.encode_without("mac");
    let t = tag(mac(secret, REPLY_LABEL, &[nonce.as_bytes(), b"\n", body.as_bytes()]));
    kv.push("mac", t);
}

/// Checks the `mac` field of a reply to the request that carried `nonce`.
#[must_use]
pub fn verify_reply(secret: &[u8], nonce: &str, kv: &Kv) -> bool {
    let body = kv.encode_without("mac");
    verify(kv, mac(secret, REPLY_LABEL, &[nonce.as_bytes(), b"\n", body.as_bytes()]))
}

fn verify(kv: &Kv, expected: Hmac<Sha256>) -> bool {
    let Some(got) = kv.get("mac").and_then(hex_decode) else {
        return false;
    };
    // Only one mac line may exist, otherwise the signed body is ambiguous.
    // verify_slice compares in constant time.
    kv.get_all("mac").count() == 1 && expected.verify_slice(&got).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> RegToken {
        RegToken { id: [1, 2, 3, 4, 5, 6], secret: [9; TOKEN_SECRET_LEN] }
    }

    #[test]
    fn token_roundtrip() {
        let t = token();
        let s = t.encode();
        assert!(s.starts_with("wrt_") && s.len() == 4 + 32);
        assert_eq!(RegToken::parse(&s), Some(t));
        assert_eq!(RegToken::parse("wrt_AAAA"), None);
        assert_eq!(RegToken::parse("xyz"), None);
    }

    #[test]
    fn request_and_reply_macs() {
        let t = token();
        let mut req = Kv::new();
        req.push("token_id", t.id_hex());
        req.push("pubkey", "k");
        req.push("nonce", "n1");
        sign_request(&t.secret, &mut req);
        let parsed = Kv::parse(&req.encode()).unwrap();
        assert!(verify_request(&t.secret, &parsed));
        assert!(!verify_request(&[0; TOKEN_SECRET_LEN], &parsed));

        // Tampering with any field breaks the MAC.
        let tampered = Kv::parse(&req.encode().replace("pubkey=k", "pubkey=evil")).unwrap();
        assert!(!verify_request(&t.secret, &tampered));

        let mut reply = Kv::new();
        reply.push("address", "10.77.0.2/16");
        sign_reply(&t.secret, "n1", &mut reply);
        let parsed = Kv::parse(&reply.encode()).unwrap();
        assert!(verify_reply(&t.secret, "n1", &parsed));
        assert!(!verify_reply(&t.secret, "n2", &parsed), "reply bound to nonce");

        let mut doubled = parsed.clone();
        doubled.push("mac", "00");
        assert!(!verify_reply(&t.secret, "n1", &doubled));
    }
}
