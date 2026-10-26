//! Passwords, TOTP, permissions and rate limiting.

use crate::util::{base32_decode, base32_encode, random};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use warren_proto::codec::b64_encode;

/// A capability granted by a role. Roles list these names; `*` grants all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Perm {
    /// Create, block, delete users; reset passwords; assign roles; invites.
    ManageUsers,
    /// Change server settings and ACL rules.
    ManageSettings,
    /// See and manage every user's devices.
    AllDevices,
    /// See and manage every user's resources.
    AllResources,
    /// Read everyone's audit log.
    AllAudit,
}

impl Perm {
    /// Name stored in role permission lists.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Perm::ManageUsers => "users.manage",
            Perm::ManageSettings => "settings.manage",
            Perm::AllDevices => "devices.all",
            Perm::AllResources => "resources.all",
            Perm::AllAudit => "audit.all",
        }
    }

    /// Whether a permission list grants this permission.
    #[must_use]
    pub fn granted_by(self, perms: &[String]) -> bool {
        perms.iter().any(|p| p == "*" || p == self.name())
    }
}

/// Argon2id with OWASP's 12 MiB / 3 passes profile: strong, but light enough
/// for a 512 MB VPS.
fn hasher() -> Argon2<'static> {
    // These constants are within Argon2's limits, so `Params::new` succeeds;
    // the default profile is an equally safe fallback.
    let params = Params::new(12 * 1024, 3, 1, None).unwrap_or_default();
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hashes a secret into a PHC string. CPU-heavy: call from a blocking task.
///
/// # Errors
/// Only if the hasher rejects its input, which cannot happen for passwords
/// of sane length.
pub fn hash_secret(secret: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::encode_b64(&random::<16>())?;
    Ok(hasher().hash_password(secret.as_bytes(), &salt)?.to_string())
}

/// Checks a secret against a PHC string. CPU-heavy: call from a blocking task.
#[must_use]
pub fn verify_secret(secret: &str, phc: &str) -> bool {
    PasswordHash::new(phc).is_ok_and(|h| hasher().verify_password(secret.as_bytes(), &h).is_ok())
}

/// A valid PHC hash of a random password, verified against when a user does
/// not exist so that response time does not reveal which names exist.
pub fn dummy_hash() -> &'static str {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DUMMY.get_or_init(|| hash_secret(&b64_encode(&random::<16>())).unwrap_or_default())
}

/// Hashing failed (or its worker thread died).
#[derive(Debug, thiserror::Error)]
pub enum HashError {
    /// The hasher rejected its input.
    #[error("hashing failed: {0}")]
    Hash(argon2::password_hash::Error),
    /// The blocking task panicked or was cancelled.
    #[error("hashing task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
}

/// Bounds concurrent Argon2 runs (12 MiB each) to the number of CPUs, so a
/// burst of logins cannot exhaust memory or the blocking thread pool.
fn argon_slots() -> &'static tokio::sync::Semaphore {
    static SLOTS: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    SLOTS
        .get_or_init(|| tokio::sync::Semaphore::new(std::thread::available_parallelism().map_or(2, |n| n.get().min(4))))
}

/// [`verify_secret`] on a blocking thread, at most a few at a time. With
/// `phc = None` (unknown user) it checks against [`dummy_hash`] so timing
/// does not reveal which accounts exist.
pub async fn verify_async(secret: String, phc: Option<String>) -> bool {
    let Ok(_permit) = argon_slots().acquire().await else { return false };
    tokio::task::spawn_blocking(move || match &phc {
        Some(phc) => verify_secret(&secret, phc),
        None => verify_secret(&secret, dummy_hash()),
    })
    .await
    .unwrap_or(false)
}

/// [`hash_secret`] on a blocking thread, at most a few at a time.
///
/// # Errors
/// When hashing fails or its task dies.
pub async fn hash_async(secret: String) -> Result<String, HashError> {
    let _permit = argon_slots().acquire().await.map_err(|_| HashError::Hash(argon2::password_hash::Error::Crypto))?;
    tokio::task::spawn_blocking(move || hash_secret(&secret)).await?.map_err(HashError::Hash)
}

/// Rate-limit bucket for a client: the address itself for IPv4, the /64
/// for IPv6 (one host usually controls a whole /64).
#[must_use]
pub fn rate_key(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
    }
}

/// Minimum password length enforced everywhere.
pub const MIN_PASSWORD: usize = 10;

/// Rejects passwords that are too short or too long for hashing comfortably.
#[must_use]
pub fn password_ok(p: &str) -> bool {
    (MIN_PASSWORD..=256).contains(&p.chars().count())
}

/// A new random TOTP secret, base32-encoded.
#[must_use]
pub fn new_totp_secret() -> String {
    base32_encode(&random::<20>())
}

/// The `otpauth://` URI authenticator apps scan.
#[must_use]
pub fn totp_uri(issuer: &str, account: &str, secret: &str) -> String {
    let enc = |s: &str| {
        s.bytes()
            .map(|b| if b.is_ascii_alphanumeric() { char::from(b).to_string() } else { format!("%{b:02X}") })
            .collect::<String>()
    };
    format!("otpauth://totp/{}:{}?secret={secret}&issuer={}&digits=6&period=30", enc(issuer), enc(account), enc(issuer))
}

/// RFC 6238 code for a 30-second time step.
#[must_use]
pub fn totp_code(secret: &[u8], step: u64) -> u32 {
    // HMAC accepts keys of any length, so construction cannot fail.
    let Ok(mut mac) = <Hmac<Sha1> as Mac>::new_from_slice(secret) else { return 0 };
    mac.update(&step.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let offset = usize::from(h[19] & 0x0f);
    let bin = u32::from_be_bytes([h[offset] & 0x7f, h[offset + 1], h[offset + 2], h[offset + 3]]);
    bin % 1_000_000
}

/// Verifies a 6-digit code within ±1 step of `unix_time`; returns the
/// matching step so callers can refuse its reuse.
#[must_use]
pub fn totp_verify(secret_b32: &str, code: &str, unix_time: i64) -> Option<u64> {
    let code: u32 = code.trim().replace(' ', "").parse().ok()?;
    let secret = base32_decode(secret_b32)?;
    let now = u64::try_from(unix_time).ok()? / 30;
    [now.saturating_sub(1), now, now + 1].into_iter().find(|&s| totp_code(&secret, s) == code)
}

/// Fixed-window counter keyed by an arbitrary string (IP, user name, …).
pub struct RateLimiter {
    window: Duration,
    limit: u32,
    hits: Mutex<HashMap<String, (Instant, u32)>>,
}

impl RateLimiter {
    /// Allows `limit` hits per `window` per key.
    #[must_use]
    pub fn new(limit: u32, window: Duration) -> Self {
        RateLimiter { window, limit, hits: Mutex::new(HashMap::new()) }
    }

    /// Records a hit; false when the key is over its limit.
    pub fn check(&self, key: &str) -> bool {
        let mut hits = self.hits.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        if hits.len() > 10_000 {
            hits.retain(|_, (start, _)| now.duration_since(*start) < self.window);
        }
        let entry = hits.entry(key.to_string()).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= self.limit
    }

    /// True when the key has used up its limit, without recording a hit.
    pub fn blocked(&self, key: &str) -> bool {
        let hits = self.hits.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        hits.get(key).is_some_and(|(start, n)| start.elapsed() < self.window && *n >= self.limit)
    }

    /// Forgets a key, e.g. after a successful login.
    pub fn reset(&self, key: &str) {
        self.hits.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_sha1_vectors() {
        // RFC 6238 appendix B uses an 8-digit code; the last 6 digits match.
        let secret = b"12345678901234567890";
        for (t, code) in [(59u64, 94_287_082u32), (1_111_111_109, 7_081_804), (1_234_567_890, 89_005_924)] {
            assert_eq!(totp_code(secret, t / 30), code % 1_000_000, "t={t}");
        }
        let b32 = base32_encode(secret);
        assert_eq!(totp_verify(&b32, "287082", 59), Some(1));
        assert_eq!(totp_verify(&b32, "287 082", 59 + 30), Some(1), "previous step accepted");
        assert_eq!(totp_verify(&b32, "287082", 59 + 90), None);
        assert_eq!(totp_verify(&b32, "abc", 59), None);
    }

    #[test]
    fn passwords() {
        let h = hash_secret("correct horse").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_secret("correct horse", &h));
        assert!(!verify_secret("wrong", &h));
        assert!(!verify_secret("x", "not a hash"));
        assert!(!verify_secret("x", dummy_hash()));
        assert!(password_ok("0123456789") && !password_ok("short"));
    }

    #[test]
    fn rate_keys() {
        assert_eq!(rate_key("1.2.3.4".parse().unwrap()), "1.2.3.4");
        assert_eq!(
            rate_key("2001:db8:1:2:aaaa::1".parse().unwrap()),
            rate_key("2001:db8:1:2:bbbb::9".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn async_wrappers() {
        let h = hash_async("pass-word-1".into()).await.unwrap();
        assert!(verify_async("pass-word-1".into(), Some(h)).await);
        assert!(!verify_async("pass-word-1".into(), None).await);
    }

    #[test]
    fn permissions() {
        let admin = vec!["*".to_string()];
        let auditor = vec!["audit.all".to_string()];
        assert!(Perm::ManageUsers.granted_by(&admin));
        assert!(Perm::AllAudit.granted_by(&auditor) && !Perm::ManageUsers.granted_by(&auditor));
        assert!(!Perm::AllDevices.granted_by(&[]));
    }

    #[test]
    fn rate_limiter() {
        let rl = RateLimiter::new(2, Duration::from_secs(60));
        assert!(rl.check("a") && rl.check("a") && !rl.check("a"));
        assert!(rl.check("b"));
        rl.reset("a");
        assert!(rl.check("a"));
    }

    #[test]
    fn otpauth_uri() {
        let u = totp_uri("Warren", "bob smith", "ABC");
        assert_eq!(u, "otpauth://totp/Warren:bob%20smith?secret=ABC&issuer=Warren&digits=6&period=30");
    }
}
