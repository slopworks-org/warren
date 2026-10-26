//! JSON API and web UI on the admin host.
//!
//! Everything the UI does goes through this API, so it doubles as the
//! automation interface: personal API tokens (`Authorization: Bearer …`)
//! work wherever a browser session does. Browser sessions must echo their
//! CSRF token in `X-CSRF-Token` on state-changing requests.

mod admin;
mod devices;
mod profile;
mod resources;
mod session;
mod ui;

use crate::auth::Perm;
use crate::db::{DbError, Session, User};
use crate::http::ClientIp;
use crate::state::AppState;
use crate::util::{now, sha256_hex};
use axum::Router;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use http::header::{AUTHORIZATION, COOKIE, HeaderValue};
use http::{Method, StatusCode};
use serde_json::json;
use std::net::IpAddr;
use std::sync::Arc;
use thiserror::Error;
use warren_proto::codec::ct_eq;

/// Session cookie on the admin host.
pub const SESSION_COOKIE: &str = "__Host-warren_session";
const CSRF_HEADER: &str = "x-csrf-token";

/// An API failure, rendered as `{"error": code, "message": text}`.
#[derive(Debug, Error)]
pub enum ApiError {
    /// Malformed or invalid input.
    #[error("{0}")]
    BadRequest(String),
    /// No valid session or token.
    #[error("sign in first")]
    Unauthorized,
    /// Wrong user name, password or code.
    #[error("{0}")]
    BadCredentials(&'static str),
    /// Signed in, but not allowed.
    #[error("not allowed")]
    Forbidden,
    /// The administrator requires two-factor authentication.
    #[error("set up two-factor authentication first")]
    TwoFactorRequired,
    /// No such object (or not visible to the caller).
    #[error("not found")]
    NotFound,
    /// The name is taken or the state conflicts.
    #[error("{0}")]
    Conflict(String),
    /// Rate limit hit.
    #[error("too many attempts; wait a minute")]
    TooManyRequests,
    /// Anything else; details go to the log only.
    #[error("internal error")]
    Internal,
}

impl ApiError {
    fn code(&self) -> (StatusCode, &'static str) {
        match self {
            ApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            ApiError::BadCredentials(_) => (StatusCode::UNAUTHORIZED, "bad_credentials"),
            ApiError::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            ApiError::TwoFactorRequired => (StatusCode::FORBIDDEN, "2fa_required"),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            ApiError::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            ApiError::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            ApiError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        }
    }

    /// Shorthand for [`ApiError::BadRequest`].
    pub fn bad(msg: impl Into<String>) -> ApiError {
        ApiError::BadRequest(msg.into())
    }

    /// Logs an unexpected error and hides it from the client.
    pub fn internal(e: impl std::fmt::Display) -> ApiError {
        tracing::error!(error = %e, "request failed");
        ApiError::Internal
    }
}

impl From<DbError> for ApiError {
    fn from(e: DbError) -> Self {
        match e {
            DbError::Conflict => ApiError::Conflict("that name is already taken".into()),
            other => ApiError::internal(other),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = self.code();
        (status, axum::Json(json!({ "error": code, "message": self.to_string() }))).into_response()
    }
}

/// Result type of API handlers.
pub type ApiResult<T> = Result<T, ApiError>;

/// The client address. Every request through our listeners carries one.
pub struct Ip(pub IpAddr);

impl Ip {
    /// Bucket for per-client rate limits (IPv6 by /64).
    #[must_use]
    pub fn rate_key(&self) -> String {
        crate::auth::rate_key(self.0)
    }
}

impl std::fmt::Display for Ip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Ip {
    type Rejection = ApiError;

    #[expect(clippy::unused_async_trait_impl, reason = "axum declares extractors async; this one needs no I/O")]
    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<ClientIp>().map(|c| Ip(c.0)).ok_or(ApiError::Internal)
    }
}

/// Reads a cookie from the request.
pub fn cookie<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get_all(COOKIE).iter().filter_map(|v| v.to_str().ok()).find_map(|h| crate::access::cookie_value(h, name))
}

/// Builds the `Set-Cookie` value for the session cookie.
#[must_use]
pub fn session_cookie(value: &str, max_age: i64) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}"
    ))
    .unwrap_or_else(|_| HeaderValue::from_static("__Host-warren_session=; Path=/; Secure; HttpOnly; Max-Age=0"))
}

/// An authenticated caller.
pub struct Auth {
    /// The account.
    pub user: User,
    /// Permissions of the account's role.
    pub perms: Vec<String>,
    /// The browser session; `None` for API tokens.
    pub session: Option<Session>,
}

impl Auth {
    /// Whether the caller holds `p`.
    #[must_use]
    pub fn can(&self, p: Perm) -> bool {
        p.granted_by(&self.perms)
    }

    /// Fails with [`ApiError::Forbidden`] unless the caller holds `p`.
    ///
    /// # Errors
    /// When the permission is missing.
    pub fn require(&self, p: Perm) -> ApiResult<()> {
        if self.can(p) { Ok(()) } else { Err(ApiError::Forbidden) }
    }
}

/// An authenticated caller who may still have to enrol in mandatory 2FA.
/// Only the endpoints needed to do so (and to sign out) take this
/// extractor; everything else takes [`Auth`], which refuses such callers.
pub struct PendingAuth(pub Auth);

impl FromRequestParts<Arc<AppState>> for PendingAuth {
    type Rejection = ApiError;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "axum declares extractors async; SQLite calls here are synchronous"
    )]
    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, Self::Rejection> {
        authenticate(parts, state).map(PendingAuth)
    }
}

impl FromRequestParts<Arc<AppState>> for Auth {
    type Rejection = ApiError;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "axum declares extractors async; SQLite calls here are synchronous"
    )]
    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, Self::Rejection> {
        let auth = authenticate(parts, state)?;
        if state.snapshot().settings.require_2fa && !auth.user.totp_enabled {
            return Err(ApiError::TwoFactorRequired);
        }
        Ok(auth)
    }
}

/// Resolves the caller from a bearer token or a session cookie (with CSRF
/// check for state-changing requests).
fn authenticate(parts: &Parts, state: &AppState) -> ApiResult<Auth> {
    let bearer = parts.headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer "));
    let (user_id, session) = if let Some(token) = bearer {
        let uid = state.db.use_api_token(&sha256_hex(token.trim().as_bytes()))?.ok_or(ApiError::Unauthorized)?;
        (uid, None)
    } else {
        let raw = cookie(&parts.headers, SESSION_COOKIE).ok_or(ApiError::Unauthorized)?;
        let s = state.db.session(&sha256_hex(raw.as_bytes()))?.ok_or(ApiError::Unauthorized)?;
        if !s.mfa_passed {
            return Err(ApiError::Unauthorized);
        }
        let safe = matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS);
        let csrf = parts.headers.get(CSRF_HEADER).map(HeaderValue::as_bytes).unwrap_or_default();
        if !safe && !ct_eq(csrf, s.csrf.as_bytes()) {
            return Err(ApiError::Forbidden);
        }
        if now() - s.last_seen_at > 300 {
            state.db.touch_session(&s.id)?;
        }
        (s.user_id, Some(s))
    };
    let snap = state.snapshot();
    let user = snap.users.get(&user_id).filter(|u| !u.disabled).cloned().ok_or(ApiError::Unauthorized)?;
    let perms = snap.perms_of(&user).to_vec();
    Ok(Auth { user, perms, session })
}

impl From<crate::state::AllocError> for ApiError {
    fn from(e: crate::state::AllocError) -> Self {
        match e {
            crate::state::AllocError::Exhausted => ApiError::Conflict(e.to_string()),
            crate::state::AllocError::Db(d) => d.into(),
        }
    }
}

/// A body carrying one TOTP code.
#[derive(serde::Deserialize)]
pub struct CodeReq {
    /// Six digits, spaces allowed.
    pub code: String,
}

/// Validates a user name: 1–32 of `[A-Za-z0-9._-]`.
#[must_use]
pub fn valid_username(name: &str) -> bool {
    (1..=32).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// Applies a snapshot rebuild after a change, mapping failures.
///
/// # Errors
/// [`ApiError::Internal`] when the database cannot be read.
pub fn rebuild(state: &AppState) -> ApiResult<()> {
    state.rebuild().map_err(ApiError::internal)
}

/// The admin-host router: UI, API and the resource sign-in hop.
pub fn router(state: Arc<AppState>) -> Router {
    let api = Router::new()
        .route("/auth/status", get(session::status))
        .route("/auth/login", post(session::login))
        .route("/auth/totp", post(session::totp))
        .route("/auth/logout", post(session::logout))
        .route("/auth/logout-all", post(session::logout_all))
        .route("/auth/setup", post(session::setup))
        .route("/auth/register", post(session::register))
        .route("/me", get(profile::me))
        .route("/me/password", post(profile::change_password))
        .route("/me/totp/setup", post(profile::totp_setup))
        .route("/me/totp/enable", post(profile::totp_enable))
        .route("/me/totp/disable", post(profile::totp_disable))
        .route("/me/sessions", get(profile::sessions))
        .route("/me/sessions/{id}", delete(profile::delete_session))
        .route("/me/tokens", get(profile::tokens).post(profile::create_token))
        .route("/me/tokens/{id}", delete(profile::delete_token))
        .route("/server", get(admin::server_info))
        .route("/server/update", post(admin::update_server))
        .route("/devices", get(devices::list).post(devices::create_manual))
        .route("/devices/tokens", post(devices::create_token))
        .route("/devices/{id}", get(devices::get_one).patch(devices::update).delete(devices::remove))
        .route("/devices/{id}/config", get(devices::config))
        .route("/resources", get(resources::list).post(resources::create))
        .route("/resources/{id}", get(resources::get_one).patch(resources::update).delete(resources::remove))
        .route("/users", get(admin::users).post(admin::create_user))
        .route("/users/{id}", axum::routing::patch(admin::update_user).delete(admin::delete_user))
        .route("/users/{id}/password", post(admin::reset_password))
        .route("/roles", get(admin::roles))
        .route("/invites", get(admin::invites).post(admin::create_invite))
        .route("/invites/{id}", delete(admin::delete_invite))
        .route("/settings", get(admin::settings).put(admin::update_settings))
        .route("/acl", get(admin::acl).post(admin::create_acl))
        .route("/acl/{id}", delete(admin::delete_acl))
        .route("/audit", get(admin::audit))
        .fallback(|| async { ApiError::NotFound });
    Router::new()
        .nest("/api/v1", api)
        .route("/auth/resource", get(session::resource_sign_in))
        .merge(ui::routes())
        .layer(axum::middleware::map_response(ui::security_headers))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    #[test]
    fn usernames() {
        assert!(super::valid_username("alice.b-c_1"));
        assert!(!super::valid_username("") && !super::valid_username("a b") && !super::valid_username(&"a".repeat(33)));
    }
}
