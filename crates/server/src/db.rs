//! Embedded SQLite storage.
//!
//! One connection behind a mutex: every statement here takes microseconds at
//! the scale Warren targets, so serializing them is simpler than a pool and
//! keeps memory flat. Roles carry a list of permission names, so new roles are
//! new rows, not a schema change.

use crate::access::Grant;
use crate::acl::{PortSpec, Subject};
use crate::util::now;
use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use thiserror::Error;

/// A storage failure.
#[derive(Debug, Error)]
pub enum DbError {
    /// SQLite reported an error.
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// A uniqueness constraint was violated (the name is taken).
    #[error("already exists")]
    Conflict,
    /// A stored value could not be decoded.
    #[error("corrupt value in column {0}")]
    Corrupt(&'static str),
}

/// Result of a storage operation.
pub type DbResult<T> = Result<T, DbError>;

fn conflict(e: rusqlite::Error) -> DbError {
    match &e {
        rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation => DbError::Conflict,
        _ => DbError::Sqlite(e),
    }
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    permissions TEXT NOT NULL
);
INSERT OR IGNORE INTO roles (id, name, permissions) VALUES ('admin', 'Administrator', '["*"]');
INSERT OR IGNORE INTO roles (id, name, permissions) VALUES ('user', 'User', '[]');
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role_id TEXT NOT NULL REFERENCES roles(id),
    disabled INTEGER NOT NULL DEFAULT 0,
    totp_secret TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    mfa_passed INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    ip TEXT NOT NULL,
    user_agent TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
);
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL UNIQUE,
    address TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    hostname TEXT NOT NULL DEFAULT '',
    os TEXT NOT NULL DEFAULT '',
    agent_version TEXT NOT NULL DEFAULT '',
    last_seen_at INTEGER
);
CREATE TABLE IF NOT EXISTS reg_tokens (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret BLOB NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
);
CREATE TABLE IF NOT EXISTS resources (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    host TEXT NOT NULL UNIQUE,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    target_port INTEGER NOT NULL,
    target_scheme TEXT NOT NULL,
    access TEXT NOT NULL,
    basic_user TEXT NOT NULL DEFAULT '',
    secret_hash TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS resource_grants (
    resource_id INTEGER NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    subject TEXT NOT NULL,
    PRIMARY KEY (resource_id, subject)
);
CREATE TABLE IF NOT EXISTS acl_rules (
    id INTEGER PRIMARY KEY,
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    ports TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    actor_id INTEGER,
    actor TEXT NOT NULL,
    ip TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    details TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_actor ON audit(actor_id);
CREATE TABLE IF NOT EXISTS invites (
    id TEXT PRIMARY KEY,
    role_id TEXT NOT NULL REFERENCES roles(id),
    created_by INTEGER,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_by INTEGER,
    used_at INTEGER
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#;

/// Handle to the database.
pub struct Db {
    conn: Mutex<Connection>,
}

/// A role and the permissions it grants (`*` grants all).
#[derive(Clone, Debug, Serialize)]
pub struct Role {
    /// Stable identifier, e.g. `admin`.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Permission names.
    pub permissions: Vec<String>,
}

/// A user account.
#[derive(Clone, Debug, Serialize)]
pub struct User {
    /// Row id.
    pub id: i64,
    /// Login name, unique case-insensitively.
    pub username: String,
    /// Role id.
    pub role: String,
    /// Blocked users cannot sign in and lose their sessions.
    pub disabled: bool,
    /// Whether TOTP is required at sign-in.
    pub totp_enabled: bool,
    /// Creation time.
    pub created_at: i64,
    /// Argon2 PHC string.
    #[serde(skip)]
    pub password_hash: String,
    /// Base32 TOTP secret, also set while enrolment is pending.
    #[serde(skip)]
    pub totp_secret: Option<String>,
}

/// A browser session.
#[derive(Clone, Debug, Serialize)]
pub struct Session {
    /// SHA-256 of the cookie value.
    pub id: String,
    /// Owner.
    pub user_id: i64,
    /// Anti-CSRF token the UI echoes in a header.
    #[serde(skip)]
    pub csrf: String,
    /// False between password and TOTP steps.
    pub mfa_passed: bool,
    /// Creation time.
    pub created_at: i64,
    /// Absolute expiry.
    pub expires_at: i64,
    /// Last request seen.
    pub last_seen_at: i64,
    /// Client address at sign-in.
    pub ip: String,
    /// Client user agent at sign-in.
    pub user_agent: String,
}

/// A personal API token (the secret is shown once and stored hashed).
#[derive(Clone, Debug, Serialize)]
pub struct ApiToken {
    /// Row id.
    pub id: i64,
    /// Owner.
    pub user_id: i64,
    /// Label.
    pub name: String,
    /// Creation time.
    pub created_at: i64,
    /// Last use.
    pub last_used_at: Option<i64>,
}

/// How a device is managed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceKind {
    /// Runs the Warren agent.
    Agent,
    /// Uses a plain WireGuard config.
    Manual,
}

impl DeviceKind {
    fn as_str(self) -> &'static str {
        match self {
            DeviceKind::Agent => "agent",
            DeviceKind::Manual => "manual",
        }
    }
}

/// A device (node) of the network.
#[derive(Clone, Debug, Serialize)]
pub struct Device {
    /// Row id.
    pub id: i64,
    /// Owner.
    pub user_id: i64,
    /// Display name.
    pub name: String,
    /// Base64 WireGuard public key.
    pub public_key: String,
    /// Tunnel address.
    pub address: Ipv4Addr,
    /// Agent or manual config.
    pub kind: DeviceKind,
    /// Disabled devices are removed from the hub but kept.
    pub enabled: bool,
    /// Creation time.
    pub created_at: i64,
    /// Reported by the agent.
    pub hostname: String,
    /// Reported by the agent, e.g. `linux-aarch64`.
    pub os: String,
    /// Reported by the agent.
    pub agent_version: String,
    /// Last WireGuard handshake or control-channel contact.
    pub last_seen_at: Option<i64>,
}

/// A one-time registration token.
#[derive(Clone, Debug)]
pub struct RegTokenRow {
    /// Hex id (public half of the token).
    pub id: String,
    /// User the device will belong to.
    pub user_id: i64,
    /// MAC key.
    pub secret: Vec<u8>,
    /// Suggested device name.
    pub name: String,
    /// Expiry.
    pub expires_at: i64,
    /// Set once used.
    pub used_at: Option<i64>,
}

/// Device-side protocol of a resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    /// Plain HTTP to the device.
    Http,
    /// HTTPS to the device; its certificate is not verified.
    Https,
}

/// How visitors are authorized for a resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessMode {
    /// Anyone.
    Public,
    /// Signed-in Warren users from the grant list (plus owner and admins).
    Users,
    /// HTTP Basic authentication with the resource's own credentials.
    Basic,
    /// A PIN code entered on a Warren page.
    Pin,
}

fn enum_str<T: Serialize>(v: T) -> String {
    serde_json::to_value(v).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

fn enum_from<T: for<'de> Deserialize<'de>>(s: &str, col: &'static str) -> DbResult<T> {
    serde_json::from_value(serde_json::Value::String(s.to_string())).map_err(|_| DbError::Corrupt(col))
}

/// A published service.
#[derive(Clone, Debug, Serialize)]
pub struct Resource {
    /// Row id.
    pub id: i64,
    /// Owner.
    pub user_id: i64,
    /// Public host name.
    pub host: String,
    /// Target device.
    pub device_id: i64,
    /// Target port on the device.
    pub target_port: u16,
    /// Target protocol.
    pub target_scheme: Scheme,
    /// Visitor authorization mode.
    pub access: AccessMode,
    /// Basic-auth user name.
    pub basic_user: String,
    /// Argon2 hash of the Basic password or PIN.
    #[serde(skip)]
    pub secret_hash: String,
    /// Disabled resources answer 404.
    pub enabled: bool,
    /// Creation time.
    pub created_at: i64,
    /// Last change; invalidates visitor cookies.
    pub updated_at: i64,
    /// Who may open it in [`AccessMode::Users`].
    pub grants: Vec<Grant>,
}

/// Fields of a resource that can be written.
#[derive(Clone, Debug)]
pub struct ResourceInput {
    /// Public host name.
    pub host: String,
    /// Target device.
    pub device_id: i64,
    /// Target port.
    pub target_port: u16,
    /// Target protocol.
    pub target_scheme: Scheme,
    /// Authorization mode.
    pub access: AccessMode,
    /// Basic-auth user name.
    pub basic_user: String,
    /// New secret hash; `None` keeps the current one.
    pub secret_hash: Option<String>,
    /// Enabled flag.
    pub enabled: bool,
    /// Who may open it in [`AccessMode::Users`].
    pub grants: Vec<Grant>,
}

/// An administrator ACL rule.
#[derive(Clone, Debug, Serialize)]
pub struct AclRuleRow {
    /// Row id.
    pub id: i64,
    /// Source subject.
    pub src: Subject,
    /// Destination subject.
    pub dst: Subject,
    /// Allowed ports; empty for all traffic. Serialized as `tcp:22,udp:53`.
    #[serde(serialize_with = "ports_text")]
    pub ports: Vec<PortSpec>,
    /// Free-form note.
    pub description: String,
    /// Creation time.
    pub created_at: i64,
}

fn ports_text<S: serde::Serializer>(ports: &[PortSpec], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&PortSpec::format_list(ports))
}

/// An audit log entry.
#[derive(Clone, Debug, Serialize)]
pub struct AuditEntry {
    /// Row id, increasing.
    pub id: i64,
    /// Time.
    pub ts: i64,
    /// Acting user, if any.
    pub actor_id: Option<i64>,
    /// Acting user's name or `system`/`agent`.
    pub actor: String,
    /// Client address.
    pub ip: String,
    /// Action name, e.g. `device.create`.
    pub action: String,
    /// Object acted upon.
    pub target: String,
    /// Extra detail.
    pub details: String,
}

/// An invitation to self-register.
#[derive(Clone, Debug, Serialize)]
pub struct Invite {
    /// SHA-256 of the invite code.
    pub id: String,
    /// Role the new user gets.
    pub role: String,
    /// Creator.
    pub created_by: Option<i64>,
    /// Creation time.
    pub created_at: i64,
    /// Expiry.
    pub expires_at: i64,
    /// Set once used.
    pub used_by: Option<i64>,
}

/// Whether people can create their own accounts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Registration {
    /// Only administrators create accounts.
    #[default]
    Closed,
    /// Anyone with an invite link.
    Invite,
}

/// Settings editable in the admin UI.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Settings {
    /// Self-registration policy.
    pub registration: Registration,
    /// Make TOTP mandatory for every account.
    pub require_2fa: bool,
    /// Session lifetime.
    pub session_ttl_hours: u32,
    /// Default lifetime of device registration tokens.
    pub token_ttl_minutes: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            registration: Registration::Closed,
            require_2fa: false,
            session_ttl_hours: 168,
            token_ttl_minutes: 60,
        }
    }
}

fn user_row(r: &Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: r.get(0)?,
        username: r.get(1)?,
        password_hash: r.get(2)?,
        role: r.get(3)?,
        disabled: r.get(4)?,
        totp_secret: r.get(5)?,
        totp_enabled: r.get(6)?,
        created_at: r.get(7)?,
    })
}

const USER_COLS: &str = "id, username, password_hash, role_id, disabled, totp_secret, totp_enabled, created_at";

fn session_row(r: &Row<'_>) -> rusqlite::Result<Session> {
    Ok(Session {
        id: r.get(0)?,
        user_id: r.get(1)?,
        csrf: r.get(2)?,
        mfa_passed: r.get(3)?,
        created_at: r.get(4)?,
        expires_at: r.get(5)?,
        last_seen_at: r.get(6)?,
        ip: r.get(7)?,
        user_agent: r.get(8)?,
    })
}

const SESSION_COLS: &str = "id, user_id, csrf, mfa_passed, created_at, expires_at, last_seen_at, ip, user_agent";

const DEVICE_COLS: &str =
    "id, user_id, name, public_key, address, kind, enabled, created_at, hostname, os, agent_version, last_seen_at";

fn device_row(r: &Row<'_>) -> DbResult<Device> {
    let address: String = r.get(4)?;
    let kind: String = r.get(5)?;
    Ok(Device {
        id: r.get(0)?,
        user_id: r.get(1)?,
        name: r.get(2)?,
        public_key: r.get(3)?,
        address: address.parse().map_err(|_| DbError::Corrupt("devices.address"))?,
        kind: enum_from(&kind, "devices.kind")?,
        enabled: r.get(6)?,
        created_at: r.get(7)?,
        hostname: r.get(8)?,
        os: r.get(9)?,
        agent_version: r.get(10)?,
        last_seen_at: r.get(11)?,
    })
}

const RESOURCE_COLS: &str = "id, user_id, host, device_id, target_port, target_scheme, access, basic_user, \
     secret_hash, enabled, created_at, updated_at";

fn resource_row(r: &Row<'_>) -> DbResult<Resource> {
    let scheme: String = r.get(5)?;
    let access: String = r.get(6)?;
    Ok(Resource {
        id: r.get(0)?,
        user_id: r.get(1)?,
        host: r.get(2)?,
        device_id: r.get(3)?,
        target_port: r.get(4)?,
        target_scheme: enum_from(&scheme, "resources.target_scheme")?,
        access: enum_from(&access, "resources.access")?,
        basic_user: r.get(7)?,
        secret_hash: r.get(8)?,
        enabled: r.get(9)?,
        created_at: r.get(10)?,
        updated_at: r.get(11)?,
        grants: Vec::new(),
    })
}

/// Collects rows with a mapper that may fail with [`DbError`].
fn collect<T>(
    stmt: &mut rusqlite::Statement<'_>,
    params: impl rusqlite::Params,
    f: impl Fn(&Row<'_>) -> DbResult<T>,
) -> DbResult<Vec<T>> {
    let mut rows = stmt.query(params)?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        out.push(f(r)?);
    }
    Ok(out)
}

impl Db {
    /// Opens (creating if needed) the database and applies the schema.
    ///
    /// # Errors
    /// When the file cannot be opened or the schema cannot be applied.
    pub fn open(path: &Path) -> DbResult<Db> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    /// An in-memory database, for tests.
    ///
    /// # Errors
    /// When the schema cannot be applied.
    pub fn memory() -> DbResult<Db> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> DbResult<Db> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        // Keep the page cache small: this runs on 512 MB VPSes.
        conn.pragma_update(None, "cache_size", -2000)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA)?;
        Ok(Db { conn: Mutex::new(conn) })
    }

    fn c(&self) -> MutexGuard<'_, Connection> {
        // A panic while holding the lock cannot leave SQLite inconsistent
        // (statements are atomic), so a poisoned lock is safe to reuse.
        self.conn.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    // ---- roles and users ----

    /// All roles.
    ///
    /// # Errors
    /// On database failure.
    pub fn roles(&self) -> DbResult<Vec<Role>> {
        let c = self.c();
        let mut s = c.prepare("SELECT id, name, permissions FROM roles ORDER BY id")?;
        collect(&mut s, [], |r| {
            let perms: String = r.get(2)?;
            Ok(Role {
                id: r.get(0)?,
                name: r.get(1)?,
                permissions: serde_json::from_str(&perms).map_err(|_| DbError::Corrupt("roles.permissions"))?,
            })
        })
    }

    /// Number of user accounts.
    ///
    /// # Errors
    /// On database failure.
    pub fn user_count(&self) -> DbResult<i64> {
        Ok(self.c().query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?)
    }

    /// Creates a user.
    ///
    /// # Errors
    /// [`DbError::Conflict`] if the name is taken.
    pub fn create_user(&self, username: &str, password_hash: &str, role: &str) -> DbResult<User> {
        let c = self.c();
        c.execute(
            "INSERT INTO users (username, password_hash, role_id, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![username, password_hash, role, now()],
        )
        .map_err(conflict)?;
        let id = c.last_insert_rowid();
        Ok(c.query_row(&format!("SELECT {USER_COLS} FROM users WHERE id = ?1"), [id], user_row)?)
    }

    /// Looks a user up by id.
    ///
    /// # Errors
    /// On database failure.
    pub fn user(&self, id: i64) -> DbResult<Option<User>> {
        Ok(self.c().query_row(&format!("SELECT {USER_COLS} FROM users WHERE id = ?1"), [id], user_row).optional()?)
    }

    /// Looks a user up by name, case-insensitively.
    ///
    /// # Errors
    /// On database failure.
    pub fn user_by_name(&self, name: &str) -> DbResult<Option<User>> {
        Ok(self
            .c()
            .query_row(&format!("SELECT {USER_COLS} FROM users WHERE username = ?1"), [name], user_row)
            .optional()?)
    }

    /// All users, by name.
    ///
    /// # Errors
    /// On database failure.
    pub fn users(&self) -> DbResult<Vec<User>> {
        let c = self.c();
        let mut s = c.prepare(&format!("SELECT {USER_COLS} FROM users ORDER BY username"))?;
        collect(&mut s, [], |r| Ok(user_row(r)?))
    }

    /// Changes role and/or blocked state.
    ///
    /// # Errors
    /// On database failure, e.g. an unknown role.
    pub fn update_user(&self, id: i64, role: Option<&str>, disabled: Option<bool>) -> DbResult<()> {
        let c = self.c();
        if let Some(role) = role {
            c.execute("UPDATE users SET role_id = ?1 WHERE id = ?2", params![role, id])?;
        }
        if let Some(d) = disabled {
            c.execute("UPDATE users SET disabled = ?1 WHERE id = ?2", params![d, id])?;
            if d {
                c.execute("DELETE FROM sessions WHERE user_id = ?1", [id])?;
                c.execute("DELETE FROM api_tokens WHERE user_id = ?1", [id])?;
            }
        }
        Ok(())
    }

    /// Replaces a password hash and signs the user out everywhere.
    ///
    /// # Errors
    /// On database failure.
    pub fn set_password(&self, id: i64, hash: &str) -> DbResult<()> {
        let c = self.c();
        c.execute("UPDATE users SET password_hash = ?1 WHERE id = ?2", params![hash, id])?;
        c.execute("DELETE FROM sessions WHERE user_id = ?1", [id])?;
        Ok(())
    }

    /// Stores a TOTP secret and whether it is active.
    ///
    /// # Errors
    /// On database failure.
    pub fn set_totp(&self, id: i64, secret: Option<&str>, enabled: bool) -> DbResult<()> {
        self.c().execute(
            "UPDATE users SET totp_secret = ?1, totp_enabled = ?2 WHERE id = ?3",
            params![secret, enabled, id],
        )?;
        Ok(())
    }

    /// Deletes a user with their devices, resources, sessions and tokens.
    ///
    /// # Errors
    /// On database failure.
    pub fn delete_user(&self, id: i64) -> DbResult<bool> {
        Ok(self.c().execute("DELETE FROM users WHERE id = ?1", [id])? > 0)
    }

    // ---- sessions and API tokens ----

    /// Records a new session.
    ///
    /// # Errors
    /// On database failure.
    pub fn create_session(&self, s: &Session) -> DbResult<()> {
        self.c().execute(
            &format!("INSERT INTO sessions ({SESSION_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"),
            params![
                s.id,
                s.user_id,
                s.csrf,
                s.mfa_passed,
                s.created_at,
                s.expires_at,
                s.last_seen_at,
                s.ip,
                s.user_agent
            ],
        )?;
        Ok(())
    }

    /// A live (unexpired) session by id.
    ///
    /// # Errors
    /// On database failure.
    pub fn session(&self, id: &str) -> DbResult<Option<Session>> {
        Ok(self
            .c()
            .query_row(
                &format!("SELECT {SESSION_COLS} FROM sessions WHERE id = ?1 AND expires_at > ?2"),
                params![id, now()],
                session_row,
            )
            .optional()?)
    }

    /// Marks the TOTP step done.
    ///
    /// # Errors
    /// On database failure.
    pub fn pass_mfa(&self, id: &str) -> DbResult<()> {
        self.c().execute("UPDATE sessions SET mfa_passed = 1 WHERE id = ?1", [id])?;
        Ok(())
    }

    /// Updates the last-seen time.
    ///
    /// # Errors
    /// On database failure.
    pub fn touch_session(&self, id: &str) -> DbResult<()> {
        self.c().execute("UPDATE sessions SET last_seen_at = ?1 WHERE id = ?2", params![now(), id])?;
        Ok(())
    }

    /// A user's live sessions, newest first.
    ///
    /// # Errors
    /// On database failure.
    pub fn sessions_of(&self, user: i64) -> DbResult<Vec<Session>> {
        let c = self.c();
        let mut s = c.prepare(&format!(
            "SELECT {SESSION_COLS} FROM sessions WHERE user_id = ?1 AND expires_at > ?2 ORDER BY created_at DESC"
        ))?;
        collect(&mut s, params![user, now()], |r| Ok(session_row(r)?))
    }

    /// Deletes one of a user's sessions.
    ///
    /// # Errors
    /// On database failure.
    pub fn delete_session(&self, user: i64, id: &str) -> DbResult<bool> {
        Ok(self.c().execute("DELETE FROM sessions WHERE id = ?1 AND user_id = ?2", params![id, user])? > 0)
    }

    /// Deletes all of a user's sessions.
    ///
    /// # Errors
    /// On database failure.
    pub fn delete_sessions_of(&self, user: i64) -> DbResult<()> {
        self.c().execute("DELETE FROM sessions WHERE user_id = ?1", [user])?;
        Ok(())
    }

    /// Creates an API token from its hash.
    ///
    /// # Errors
    /// On database failure.
    pub fn create_api_token(&self, user: i64, name: &str, hash: &str) -> DbResult<ApiToken> {
        let c = self.c();
        let created_at = now();
        c.execute(
            "INSERT INTO api_tokens (user_id, name, token_hash, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![user, name, hash, created_at],
        )?;
        Ok(ApiToken { id: c.last_insert_rowid(), user_id: user, name: name.into(), created_at, last_used_at: None })
    }

    /// Finds the owner of an API token by its hash and records the use.
    ///
    /// # Errors
    /// On database failure.
    pub fn use_api_token(&self, hash: &str) -> DbResult<Option<i64>> {
        let c = self.c();
        let user =
            c.query_row("SELECT user_id FROM api_tokens WHERE token_hash = ?1", [hash], |r| r.get(0)).optional()?;
        if user.is_some() {
            c.execute("UPDATE api_tokens SET last_used_at = ?1 WHERE token_hash = ?2", params![now(), hash])?;
        }
        Ok(user)
    }

    /// A user's API tokens.
    ///
    /// # Errors
    /// On database failure.
    pub fn api_tokens_of(&self, user: i64) -> DbResult<Vec<ApiToken>> {
        let c = self.c();
        let mut s = c.prepare(
            "SELECT id, user_id, name, created_at, last_used_at FROM api_tokens WHERE user_id = ?1 ORDER BY id",
        )?;
        collect(&mut s, [user], |r| {
            Ok(ApiToken {
                id: r.get(0)?,
                user_id: r.get(1)?,
                name: r.get(2)?,
                created_at: r.get(3)?,
                last_used_at: r.get(4)?,
            })
        })
    }

    /// Deletes one of a user's API tokens.
    ///
    /// # Errors
    /// On database failure.
    pub fn delete_api_token(&self, user: i64, id: i64) -> DbResult<bool> {
        Ok(self.c().execute("DELETE FROM api_tokens WHERE id = ?1 AND user_id = ?2", params![id, user])? > 0)
    }

    // ---- devices ----

    /// All devices.
    ///
    /// # Errors
    /// On database failure.
    pub fn devices(&self) -> DbResult<Vec<Device>> {
        let c = self.c();
        let mut s = c.prepare(&format!("SELECT {DEVICE_COLS} FROM devices ORDER BY id"))?;
        collect(&mut s, [], device_row)
    }

    /// A device by id.
    ///
    /// # Errors
    /// On database failure.
    pub fn device(&self, id: i64) -> DbResult<Option<Device>> {
        let c = self.c();
        let mut s = c.prepare(&format!("SELECT {DEVICE_COLS} FROM devices WHERE id = ?1"))?;
        Ok(collect(&mut s, [id], device_row)?.pop())
    }

    /// Creates a device.
    ///
    /// # Errors
    /// [`DbError::Conflict`] if the key or address is taken.
    pub fn create_device(
        &self,
        user: i64,
        name: &str,
        public_key: &str,
        address: Ipv4Addr,
        kind: DeviceKind,
    ) -> DbResult<i64> {
        let c = self.c();
        c.execute(
            "INSERT INTO devices (user_id, name, public_key, address, kind, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![user, name, public_key, address.to_string(), kind.as_str(), now()],
        )
        .map_err(conflict)?;
        Ok(c.last_insert_rowid())
    }

    /// Renames and/or enables/disables a device.
    ///
    /// # Errors
    /// On database failure.
    pub fn update_device(&self, id: i64, name: Option<&str>, enabled: Option<bool>) -> DbResult<()> {
        let c = self.c();
        if let Some(n) = name {
            c.execute("UPDATE devices SET name = ?1 WHERE id = ?2", params![n, id])?;
        }
        if let Some(e) = enabled {
            c.execute("UPDATE devices SET enabled = ?1 WHERE id = ?2", params![e, id])?;
        }
        Ok(())
    }

    /// Records what the agent reports about itself.
    ///
    /// # Errors
    /// On database failure.
    pub fn device_report(&self, id: i64, hostname: &str, os: &str, version: &str) -> DbResult<()> {
        self.c().execute(
            "UPDATE devices SET hostname = ?1, os = ?2, agent_version = ?3, last_seen_at = ?4 WHERE id = ?5",
            params![hostname, os, version, now(), id],
        )?;
        Ok(())
    }

    /// Records a sighting (handshake).
    ///
    /// # Errors
    /// On database failure.
    pub fn device_seen(&self, id: i64, at: i64) -> DbResult<()> {
        self.c().execute(
            "UPDATE devices SET last_seen_at = ?1 WHERE id = ?2 AND (last_seen_at IS NULL OR last_seen_at < ?1)",
            params![at, id],
        )?;
        Ok(())
    }

    /// Deletes a device and its resources.
    ///
    /// # Errors
    /// On database failure.
    pub fn delete_device(&self, id: i64) -> DbResult<bool> {
        Ok(self.c().execute("DELETE FROM devices WHERE id = ?1", [id])? > 0)
    }

    // ---- registration tokens ----

    /// Stores a registration token.
    ///
    /// # Errors
    /// On database failure.
    pub fn create_reg_token(&self, t: &RegTokenRow) -> DbResult<()> {
        self.c().execute(
            "INSERT INTO reg_tokens (id, user_id, secret, name, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![t.id, t.user_id, t.secret, t.name, now(), t.expires_at],
        )?;
        Ok(())
    }

    /// A registration token by id, used or not.
    ///
    /// # Errors
    /// On database failure.
    pub fn reg_token(&self, id: &str) -> DbResult<Option<RegTokenRow>> {
        Ok(self
            .c()
            .query_row(
                "SELECT id, user_id, secret, name, expires_at, used_at FROM reg_tokens WHERE id = ?1",
                [id],
                |r| {
                    Ok(RegTokenRow {
                        id: r.get(0)?,
                        user_id: r.get(1)?,
                        secret: r.get(2)?,
                        name: r.get(3)?,
                        expires_at: r.get(4)?,
                        used_at: r.get(5)?,
                    })
                },
            )
            .optional()?)
    }

    /// Consumes a token and creates its device atomically. Returns `None`
    /// if the token was already used or has expired.
    ///
    /// # Errors
    /// [`DbError::Conflict`] if the key or address is taken.
    pub fn register_device(
        &self,
        token_id: &str,
        name: &str,
        public_key: &str,
        address: Ipv4Addr,
    ) -> DbResult<Option<i64>> {
        let mut c = self.c();
        let tx = c.transaction()?;
        let user: Option<i64> = tx
            .query_row(
                "UPDATE reg_tokens SET used_at = ?1 WHERE id = ?2 AND used_at IS NULL AND expires_at > ?1 RETURNING user_id",
                params![now(), token_id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(user) = user else { return Ok(None) };
        tx.execute(
            "INSERT INTO devices (user_id, name, public_key, address, kind, created_at) VALUES (?1, ?2, ?3, ?4, 'agent', ?5)",
            params![user, name, public_key, address.to_string(), now()],
        )
        .map_err(conflict)?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(Some(id))
    }

    /// Deletes expired and used tokens.
    ///
    /// # Errors
    /// On database failure.
    pub fn prune(&self) -> DbResult<()> {
        let c = self.c();
        let t = now();
        c.execute("DELETE FROM reg_tokens WHERE expires_at < ?1 - 86400", [t])?;
        c.execute("DELETE FROM sessions WHERE expires_at < ?1", [t])?;
        c.execute("DELETE FROM invites WHERE expires_at < ?1 - 86400", [t])?;
        Ok(())
    }

    // ---- resources ----

    /// All resources with their grants.
    ///
    /// # Errors
    /// On database failure.
    pub fn resources(&self) -> DbResult<Vec<Resource>> {
        let c = self.c();
        let mut s = c.prepare(&format!("SELECT {RESOURCE_COLS} FROM resources ORDER BY host"))?;
        let mut list = collect(&mut s, [], resource_row)?;
        let mut g = c.prepare("SELECT resource_id, subject FROM resource_grants ORDER BY subject")?;
        let grants = collect(&mut g, [], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
        for (rid, subject) in grants {
            if let Some(res) = list.iter_mut().find(|r| r.id == rid) {
                res.grants.push(subject.parse().map_err(|_| DbError::Corrupt("resource_grants.subject"))?);
            }
        }
        Ok(list)
    }

    /// A resource by id.
    ///
    /// # Errors
    /// On database failure.
    pub fn resource(&self, id: i64) -> DbResult<Option<Resource>> {
        Ok(self.resources()?.into_iter().find(|r| r.id == id))
    }

    fn write_grants(tx: &rusqlite::Transaction<'_>, id: i64, grants: &[Grant]) -> DbResult<()> {
        tx.execute("DELETE FROM resource_grants WHERE resource_id = ?1", [id])?;
        for g in grants {
            tx.execute(
                "INSERT OR IGNORE INTO resource_grants (resource_id, subject) VALUES (?1, ?2)",
                params![id, g.to_string()],
            )?;
        }
        Ok(())
    }

    /// Creates a resource.
    ///
    /// # Errors
    /// [`DbError::Conflict`] if the host is taken.
    pub fn create_resource(&self, user: i64, r: &ResourceInput) -> DbResult<i64> {
        let mut c = self.c();
        let tx = c.transaction()?;
        let t = now();
        tx.execute(
            "INSERT INTO resources (user_id, host, device_id, target_port, target_scheme, access, basic_user, \
             secret_hash, enabled, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)",
            params![
                user,
                r.host,
                r.device_id,
                r.target_port,
                enum_str(r.target_scheme),
                enum_str(r.access),
                r.basic_user,
                r.secret_hash.as_deref().unwrap_or_default(),
                r.enabled,
                t
            ],
        )
        .map_err(conflict)?;
        let id = tx.last_insert_rowid();
        Self::write_grants(&tx, id, &r.grants)?;
        tx.commit()?;
        Ok(id)
    }

    /// Replaces a resource's fields. `owner` is the target device's owner:
    /// moving a resource to another user's device hands it over.
    ///
    /// # Errors
    /// [`DbError::Conflict`] if the new host is taken.
    pub fn update_resource(&self, id: i64, owner: i64, r: &ResourceInput) -> DbResult<()> {
        let mut c = self.c();
        let tx = c.transaction()?;
        tx.execute(
            "UPDATE resources SET host = ?1, device_id = ?2, target_port = ?3, target_scheme = ?4, access = ?5, \
             basic_user = ?6, secret_hash = COALESCE(?7, secret_hash), enabled = ?8, updated_at = ?9, user_id = ?11 \
             WHERE id = ?10",
            params![
                r.host,
                r.device_id,
                r.target_port,
                enum_str(r.target_scheme),
                enum_str(r.access),
                r.basic_user,
                r.secret_hash,
                r.enabled,
                now(),
                id,
                owner
            ],
        )
        .map_err(conflict)?;
        Self::write_grants(&tx, id, &r.grants)?;
        tx.commit()?;
        Ok(())
    }

    /// Deletes a resource.
    ///
    /// # Errors
    /// On database failure.
    pub fn delete_resource(&self, id: i64) -> DbResult<bool> {
        Ok(self.c().execute("DELETE FROM resources WHERE id = ?1", [id])? > 0)
    }

    // ---- ACL rules ----

    /// All ACL rules.
    ///
    /// # Errors
    /// On database failure or a corrupt rule.
    pub fn acl_rules(&self) -> DbResult<Vec<AclRuleRow>> {
        let c = self.c();
        let mut s = c.prepare("SELECT id, src, dst, ports, description, created_at FROM acl_rules ORDER BY id")?;
        collect(&mut s, [], |r| {
            let src: String = r.get(1)?;
            let dst: String = r.get(2)?;
            Ok(AclRuleRow {
                id: r.get(0)?,
                src: src.parse().map_err(|_| DbError::Corrupt("acl_rules.src"))?,
                dst: dst.parse().map_err(|_| DbError::Corrupt("acl_rules.dst"))?,
                ports: PortSpec::parse_list(&r.get::<_, String>(3)?)
                    .map_err(|_| DbError::Corrupt("acl_rules.ports"))?,
                description: r.get(4)?,
                created_at: r.get(5)?,
            })
        })
    }

    /// Adds an ACL rule.
    ///
    /// # Errors
    /// On database failure.
    pub fn create_acl_rule(&self, src: Subject, dst: Subject, ports: &[PortSpec], description: &str) -> DbResult<i64> {
        let c = self.c();
        c.execute(
            "INSERT INTO acl_rules (src, dst, ports, description, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![src.to_string(), dst.to_string(), PortSpec::format_list(ports), description, now()],
        )?;
        Ok(c.last_insert_rowid())
    }

    /// Deletes an ACL rule.
    ///
    /// # Errors
    /// On database failure.
    pub fn delete_acl_rule(&self, id: i64) -> DbResult<bool> {
        Ok(self.c().execute("DELETE FROM acl_rules WHERE id = ?1", [id])? > 0)
    }

    // ---- audit ----

    /// Appends an audit entry.
    ///
    /// # Errors
    /// On database failure.
    pub fn audit(&self, e: &AuditEntry) -> DbResult<()> {
        self.c().execute(
            "INSERT INTO audit (ts, actor_id, actor, ip, action, target, details) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![e.ts, e.actor_id, e.actor, e.ip, e.action, e.target, e.details],
        )?;
        Ok(())
    }

    /// Audit entries older than `before` (newest first), optionally only one actor's.
    ///
    /// # Errors
    /// On database failure.
    pub fn audit_page(&self, actor: Option<i64>, before: Option<i64>, limit: u32) -> DbResult<Vec<AuditEntry>> {
        let c = self.c();
        let mut s = c.prepare(
            "SELECT id, ts, actor_id, actor, ip, action, target, details FROM audit \
             WHERE (?1 IS NULL OR actor_id = ?1) AND (?2 IS NULL OR id < ?2) ORDER BY id DESC LIMIT ?3",
        )?;
        collect(&mut s, params![actor, before, limit], |r| {
            Ok(AuditEntry {
                id: r.get(0)?,
                ts: r.get(1)?,
                actor_id: r.get(2)?,
                actor: r.get(3)?,
                ip: r.get(4)?,
                action: r.get(5)?,
                target: r.get(6)?,
                details: r.get(7)?,
            })
        })
    }

    // ---- invites ----

    /// Stores an invite by the hash of its code.
    ///
    /// # Errors
    /// On database failure.
    pub fn create_invite(&self, hash: &str, role: &str, by: i64, expires_at: i64) -> DbResult<()> {
        self.c().execute(
            "INSERT INTO invites (id, role_id, created_by, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![hash, role, by, now(), expires_at],
        )?;
        Ok(())
    }

    /// All invites, newest first.
    ///
    /// # Errors
    /// On database failure.
    pub fn invites(&self) -> DbResult<Vec<Invite>> {
        let c = self.c();
        let mut s = c.prepare(
            "SELECT id, role_id, created_by, created_at, expires_at, used_by FROM invites ORDER BY created_at DESC",
        )?;
        collect(&mut s, [], |r| {
            Ok(Invite {
                id: r.get(0)?,
                role: r.get(1)?,
                created_by: r.get(2)?,
                created_at: r.get(3)?,
                expires_at: r.get(4)?,
                used_by: r.get(5)?,
            })
        })
    }

    /// Deletes an invite.
    ///
    /// # Errors
    /// On database failure.
    pub fn delete_invite(&self, hash: &str) -> DbResult<bool> {
        Ok(self.c().execute("DELETE FROM invites WHERE id = ?1", [hash])? > 0)
    }

    /// Consumes an invite and creates the user atomically. `None` if the
    /// invite is unknown, used or expired.
    ///
    /// # Errors
    /// [`DbError::Conflict`] if the user name is taken.
    pub fn register_with_invite(&self, hash: &str, username: &str, password_hash: &str) -> DbResult<Option<User>> {
        let mut c = self.c();
        let tx = c.transaction()?;
        let role: Option<String> = tx
            .query_row(
                "SELECT role_id FROM invites WHERE id = ?1 AND used_at IS NULL AND expires_at > ?2",
                params![hash, now()],
                |r| r.get(0),
            )
            .optional()?;
        let Some(role) = role else { return Ok(None) };
        tx.execute(
            "INSERT INTO users (username, password_hash, role_id, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![username, password_hash, role, now()],
        )
        .map_err(conflict)?;
        let id = tx.last_insert_rowid();
        tx.execute("UPDATE invites SET used_by = ?1, used_at = ?2 WHERE id = ?3", params![id, now(), hash])?;
        let user = tx.query_row(&format!("SELECT {USER_COLS} FROM users WHERE id = ?1"), [id], user_row)?;
        tx.commit()?;
        Ok(Some(user))
    }

    // ---- settings ----

    /// Current settings (defaults for anything unset).
    ///
    /// # Errors
    /// On database failure.
    pub fn settings(&self) -> DbResult<Settings> {
        let v: Option<String> =
            self.c().query_row("SELECT value FROM settings WHERE key = 'settings'", [], |r| r.get(0)).optional()?;
        match v {
            Some(v) => serde_json::from_str(&v).map_err(|_| DbError::Corrupt("settings")),
            None => Ok(Settings::default()),
        }
    }

    /// Replaces the settings.
    ///
    /// # Errors
    /// On database failure.
    pub fn set_settings(&self, s: &Settings) -> DbResult<()> {
        let json = serde_json::to_string(s).map_err(|_| DbError::Corrupt("settings"))?;
        self.c().execute(
            "INSERT INTO settings (key, value) VALUES ('settings', ?1) ON CONFLICT(key) DO UPDATE SET value = ?1",
            [json],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db_with_user() -> (Db, User) {
        let db = Db::memory().unwrap();
        let u = db.create_user("alice", "h", "user").unwrap();
        (db, u)
    }

    #[test]
    fn users_are_unique_case_insensitively() {
        let (db, u) = db_with_user();
        assert!(matches!(db.create_user("ALICE", "h", "user"), Err(DbError::Conflict)));
        assert_eq!(db.user_by_name("Alice").unwrap().unwrap().id, u.id);
        assert_eq!(db.roles().unwrap().len(), 2);
    }

    #[test]
    fn registration_tokens_are_single_use() {
        let (db, u) = db_with_user();
        let t = RegTokenRow {
            id: "abc".into(),
            user_id: u.id,
            secret: vec![1; 18],
            name: String::new(),
            expires_at: now() + 60,
            used_at: None,
        };
        db.create_reg_token(&t).unwrap();
        let ip = Ipv4Addr::new(10, 77, 0, 2);
        let id = db.register_device("abc", "box", "key1", ip).unwrap();
        assert!(id.is_some());
        assert_eq!(db.register_device("abc", "box", "key2", Ipv4Addr::new(10, 77, 0, 3)).unwrap(), None);
        let d = db.device(id.unwrap()).unwrap().unwrap();
        assert_eq!((d.address, d.kind, d.user_id), (ip, DeviceKind::Agent, u.id));
    }

    #[test]
    fn expired_tokens_are_rejected() {
        let (db, u) = db_with_user();
        let t = RegTokenRow {
            id: "old".into(),
            user_id: u.id,
            secret: vec![],
            name: String::new(),
            expires_at: now() - 1,
            used_at: None,
        };
        db.create_reg_token(&t).unwrap();
        assert_eq!(db.register_device("old", "x", "k", Ipv4Addr::new(10, 77, 0, 2)).unwrap(), None);
    }

    #[test]
    fn deleting_a_user_cascades() {
        let (db, u) = db_with_user();
        let d = db.create_device(u.id, "box", "k", Ipv4Addr::new(10, 77, 0, 2), DeviceKind::Manual).unwrap();
        let input = ResourceInput {
            host: "app.example.com".into(),
            device_id: d,
            target_port: 80,
            target_scheme: Scheme::Http,
            access: AccessMode::Users,
            basic_user: String::new(),
            secret_hash: None,
            enabled: true,
            grants: vec![Grant::Role("user".into()), Grant::User(7)],
        };
        let r = db.create_resource(u.id, &input).unwrap();
        assert!(matches!(db.create_resource(u.id, &input), Err(DbError::Conflict)));
        assert_eq!(db.resource(r).unwrap().unwrap().grants, [Grant::Role("user".into()), Grant::User(7)]);
        assert!(db.delete_user(u.id).unwrap());
        assert!(db.devices().unwrap().is_empty());
        assert!(db.resources().unwrap().is_empty());
    }

    #[test]
    fn settings_roundtrip() {
        let db = Db::memory().unwrap();
        assert_eq!(db.settings().unwrap(), Settings::default());
        let s = Settings { require_2fa: true, registration: Registration::Invite, ..Settings::default() };
        db.set_settings(&s).unwrap();
        assert_eq!(db.settings().unwrap(), s);
    }

    #[test]
    fn invites_create_users_once() {
        let db = Db::memory().unwrap();
        db.create_invite("h", "user", 0, now() + 60).unwrap();
        let u = db.register_with_invite("h", "bob", "x").unwrap().unwrap();
        assert_eq!(u.role, "user");
        assert!(db.register_with_invite("h", "carol", "x").unwrap().is_none());
    }
}
