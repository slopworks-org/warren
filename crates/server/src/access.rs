//! Who may open a published resource, and the cookies that remember it.

use crate::auth::Perm;
use crate::db::Resource;
use crate::util::hmac;
use warren_proto::codec::{ct_eq, hex_decode, hex_encode};

/// Name of the visitor cookie on resource hosts. The `__Host-` prefix pins
/// it to the exact host, HTTPS and path `/`, so resources cannot read each
/// other's cookies. It is stripped before requests reach the device.
pub const COOKIE: &str = "__Host-warren_auth";

/// How long a visitor stays signed in to a resource.
pub const COOKIE_TTL: i64 = 12 * 3600;

/// Who, besides the owner and administrators, may open a `users`-mode
/// resource. Written as `all`, `user:<id>` or `role:<id>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Grant {
    /// Every signed-in user.
    All,
    /// One user.
    User(i64),
    /// Everyone with a role.
    Role(String),
}

/// A malformed grant.
#[derive(Debug, thiserror::Error)]
#[error("invalid grant {0:?}: use all, user:<id> or role:<id>")]
pub struct GrantParseError(String);

impl std::str::FromStr for Grant {
    type Err = GrantParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = || GrantParseError(s.to_string());
        match s.split_once(':') {
            None if s == "all" => Ok(Grant::All),
            Some(("user", id)) => id.parse().map(Grant::User).map_err(|_| bad()),
            Some(("role", r)) if !r.is_empty() => Ok(Grant::Role(r.to_string())),
            _ => Err(bad()),
        }
    }
}

impl std::fmt::Display for Grant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Grant::All => f.write_str("all"),
            Grant::User(id) => write!(f, "user:{id}"),
            Grant::Role(r) => write!(f, "role:{r}"),
        }
    }
}

impl serde::Serialize for Grant {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Grant {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?.parse().map_err(serde::de::Error::custom)
    }
}

/// Whether a signed-in Warren user may open a `users`-mode resource: its
/// owner, anyone with `resources.all`, and subjects on its grant list.
#[must_use]
pub fn user_allowed(res: &Resource, user_id: i64, role: &str, perms: &[String]) -> bool {
    res.user_id == user_id
        || Perm::AllResources.granted_by(perms)
        || res.grants.iter().any(|g| match g {
            Grant::All => true,
            Grant::User(id) => *id == user_id,
            Grant::Role(r) => r == role,
        })
}

/// MAC over a cookie's visible part and the resource's current state, so
/// editing the resource (e.g. a new PIN, which gets a fresh salt) signs every
/// visitor out, even within the same second.
fn tag(key: &[u8], res: &Resource, head: &str) -> [u8; 32] {
    hmac(key, &[b"resource-cookie", head.as_bytes(), res.updated_at.to_string().as_bytes(), res.secret_hash.as_bytes()])
}

/// A cookie value `rid.uid.exp.mac`; `uid` is 0 for PIN/Basic visitors.
#[must_use]
pub fn issue(key: &[u8], res: &Resource, uid: i64, exp: i64) -> String {
    let head = format!("{}.{uid}.{exp}", res.id);
    format!("{head}.{}", hex_encode(&tag(key, res, &head)[..16]))
}

/// Validates a cookie for `res`; returns the visitor's user id (0 = anonymous).
#[must_use]
pub fn verify(key: &[u8], res: &Resource, value: &str, now: i64) -> Option<i64> {
    let (head, mac) = value.rsplit_once('.')?;
    let mut parts = head.split('.');
    let (rid, uid, exp) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || rid.parse::<i64>().ok()? != res.id || exp.parse::<i64>().ok()? <= now {
        return None;
    }
    ct_eq(&hex_decode(mac)?, &tag(key, res, head)[..16]).then(|| uid.parse().ok()).flatten()
}

/// Finds a cookie in a `Cookie` header.
#[must_use]
pub fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').filter_map(|c| c.trim().split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| v)
}

/// Removes one cookie from a `Cookie` header; `None` if nothing remains.
#[must_use]
pub fn strip_cookie(header: &str, name: &str) -> Option<String> {
    let kept: Vec<&str> =
        header.split(';').map(str::trim).filter(|c| !c.is_empty() && c.split('=').next() != Some(name)).collect();
    (!kept.is_empty()).then(|| kept.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{AccessMode, Scheme};

    fn res() -> Resource {
        Resource {
            id: 5,
            user_id: 1,
            host: "app.example.com".into(),
            device_id: 1,
            target_port: 80,
            target_scheme: Scheme::Http,
            access: AccessMode::Users,
            basic_user: String::new(),
            secret_hash: String::new(),
            enabled: true,
            created_at: 0,
            updated_at: 100,
            grants: vec![Grant::User(3), Grant::Role("ops".into())],
        }
    }

    #[test]
    fn grants() {
        let r = res();
        assert!(user_allowed(&r, 1, "user", &[]), "owner");
        assert!(user_allowed(&r, 2, "admin", &["*".into()]), "admin");
        assert!(user_allowed(&r, 3, "user", &[]), "granted user");
        assert!(user_allowed(&r, 4, "ops", &[]), "granted role");
        assert!(!user_allowed(&r, 4, "user", &[]), "stranger");
        let mut open = res();
        open.grants = vec![Grant::All];
        assert!(user_allowed(&open, 9, "user", &[]));
    }

    #[test]
    fn grant_syntax() {
        for g in ["all", "user:7", "role:ops"] {
            assert_eq!(g.parse::<Grant>().unwrap().to_string(), g);
        }
        for bad in ["any", "user:x", "role:", "team:1"] {
            assert!(bad.parse::<Grant>().is_err(), "{bad}");
        }
    }

    #[test]
    fn cookies() {
        let key = b"k";
        let r = res();
        let c = issue(key, &r, 3, 1000);
        assert_eq!(verify(key, &r, &c, 999), Some(3));
        assert_eq!(verify(key, &r, &c, 1000), None, "expired");
        assert_eq!(verify(b"other", &r, &c, 1), None, "wrong key");
        let mut other = res();
        other.id = 6;
        assert_eq!(verify(key, &other, &c, 1), None, "other resource");
        let mut edited = res();
        edited.updated_at = 101;
        assert_eq!(verify(key, &edited, &c, 1), None, "edit revokes");
        let mut new_pin = res();
        new_pin.secret_hash = "other".into();
        assert_eq!(verify(key, &new_pin, &c, 1), None, "a new secret revokes within the same second");
        let forged = c.replacen(".3.", ".1.", 1);
        assert_eq!(verify(key, &r, &forged, 1), None, "uid is signed");
        assert_eq!(verify(key, &r, "garbage", 1), None);
    }

    #[test]
    fn cookie_headers() {
        let h = "a=1; __Host-warren_auth=xyz; b=2";
        assert_eq!(cookie_value(h, COOKIE), Some("xyz"));
        assert_eq!(strip_cookie(h, COOKIE).as_deref(), Some("a=1; b=2"));
        assert_eq!(strip_cookie("__Host-warren_auth=x", COOKIE), None);
        assert_eq!(cookie_value("a=1", COOKIE), None);
    }
}
