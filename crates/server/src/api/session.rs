//! Sign-in, sign-out, first-run setup, invite registration and the sign-in
//! hop to resource hosts.

use super::{
    ApiError, ApiResult, CodeReq, Ip, PendingAuth, SESSION_COOKIE, cookie, rebuild, session_cookie, valid_username,
};
use crate::access;
use crate::auth::{hash_async, password_ok, totp_verify, verify_async};
use crate::db::{Registration, Session, User};
use crate::http::{pages, redirect};
use crate::state::AppState;
use crate::util::{now, safe_next, sha256_hex, token, url_encode};
use axum::Json;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use http::header::{SET_COOKIE, USER_AGENT};
use http::{HeaderMap, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::{Arc, PoisonError};
use warren_proto::codec::ct_eq;

/// Hashes a password, mapping failures to [`ApiError::Internal`].
pub async fn hash_password(password: String) -> ApiResult<String> {
    hash_async(password).await.map_err(ApiError::internal)
}

/// `GET /api/v1/auth/status`: what the sign-in page needs to know.
pub async fn status(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let snap = state.snapshot();
    Ok(Json(json!({
        "setup_required": snap.users.is_empty(),
        "registration": snap.settings.registration,
    })))
}

#[derive(Deserialize)]
pub struct LoginReq {
    username: String,
    password: String,
}

fn start_session(state: &AppState, user: &User, headers: &HeaderMap, ip: &Ip) -> ApiResult<Response> {
    let raw = token();
    let ttl = i64::from(state.snapshot().settings.session_ttl_hours.max(1)) * 3600;
    let t = now();
    let ua = headers.get(USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or_default();
    state.db.create_session(&Session {
        id: sha256_hex(raw.as_bytes()),
        user_id: user.id,
        csrf: token(),
        mfa_passed: !user.totp_enabled,
        created_at: t,
        expires_at: t + ttl,
        last_seen_at: t,
        ip: ip.to_string(),
        user_agent: ua.chars().take(200).collect(),
    })?;
    let mut resp = Json(json!({ "mfa_required": user.totp_enabled })).into_response();
    resp.headers_mut().insert(SET_COOKIE, session_cookie(&raw, ttl));
    Ok(resp)
}

/// `POST /api/v1/auth/login`: password step. Sets the session cookie; if the
/// account has TOTP, the session stays limited until `/auth/totp`.
pub async fn login(
    State(state): State<Arc<AppState>>,
    ip: Ip,
    headers: HeaderMap,
    Json(req): Json<LoginReq>,
) -> ApiResult<Response> {
    let key = req.username.trim().to_lowercase();
    if !state.limits.login_ip.check(&ip.rate_key()) || state.limits.login_user.blocked(&key) {
        return Err(ApiError::TooManyRequests);
    }
    let user = state.db.user_by_name(req.username.trim())?;
    let ok = verify_async(req.password, user.as_ref().map(|u| u.password_hash.clone())).await;
    match user {
        Some(u) if ok && !u.disabled => {
            state.limits.login_user.reset(&key);
            state.audit(
                Some(&u),
                &ip,
                "auth.login",
                &format!("user:{}", u.id),
                if u.totp_enabled { "password ok, awaiting TOTP" } else { "" },
            );
            start_session(&state, &u, &headers, &ip)
        }
        other => {
            state.limits.login_user.check(&key);
            state.audit(
                other.as_ref(),
                &ip,
                "auth.login_failed",
                &key,
                if ok { "account blocked" } else { "wrong password or user" },
            );
            Err(ApiError::BadCredentials("wrong user name or password"))
        }
    }
}

/// `POST /api/v1/auth/totp`: second step of sign-in.
pub async fn totp(
    State(state): State<Arc<AppState>>,
    ip: Ip,
    headers: HeaderMap,
    Json(req): Json<CodeReq>,
) -> ApiResult<Json<Value>> {
    let raw = cookie(&headers, SESSION_COOKIE).ok_or(ApiError::Unauthorized)?;
    let session = state.db.session(&sha256_hex(raw.as_bytes()))?.ok_or(ApiError::Unauthorized)?;
    let user = state.db.user(session.user_id)?.filter(|u| !u.disabled).ok_or(ApiError::Unauthorized)?;
    let key = user.username.to_lowercase();
    if state.limits.login_user.blocked(&key) {
        return Err(ApiError::TooManyRequests);
    }
    let secret = user.totp_secret.as_deref().filter(|_| user.totp_enabled).ok_or(ApiError::Unauthorized)?;
    let step = totp_verify(secret, &req.code, now());
    let fresh = step.filter(|s| {
        let mut last_steps = state.totp_used.lock().unwrap_or_else(PoisonError::into_inner);
        let ok = last_steps.get(&user.id).is_none_or(|last| s > last);
        if ok {
            last_steps.insert(user.id, *s);
        }
        ok
    });
    if fresh.is_none() {
        state.limits.login_user.check(&key);
        state.audit(Some(&user), &ip, "auth.totp_failed", &format!("user:{}", user.id), "");
        return Err(ApiError::BadCredentials("wrong or already used code"));
    }
    state.db.pass_mfa(&session.id)?;
    state.limits.login_user.reset(&key);
    state.audit(Some(&user), &ip, "auth.totp", &format!("user:{}", user.id), "");
    Ok(Json(json!({ "ok": true })))
}

fn cleared_cookie() -> Response {
    let mut r = Json(json!({ "ok": true })).into_response();
    r.headers_mut().insert(SET_COOKIE, session_cookie("", 0));
    r
}

/// `POST /api/v1/auth/logout`: ends this session.
pub async fn logout(State(state): State<Arc<AppState>>, ip: Ip, PendingAuth(auth): PendingAuth) -> ApiResult<Response> {
    if let Some(s) = &auth.session {
        state.db.delete_session(auth.user.id, &s.id)?;
    }
    state.audit(Some(&auth.user), &ip, "auth.logout", &format!("user:{}", auth.user.id), "");
    Ok(cleared_cookie())
}

/// `POST /api/v1/auth/logout-all`: ends every session of the caller.
pub async fn logout_all(
    State(state): State<Arc<AppState>>,
    ip: Ip,
    PendingAuth(auth): PendingAuth,
) -> ApiResult<Response> {
    state.db.delete_sessions_of(auth.user.id)?;
    state.audit(Some(&auth.user), &ip, "auth.logout_all", &format!("user:{}", auth.user.id), "");
    Ok(cleared_cookie())
}

#[derive(Deserialize)]
pub struct SetupReq {
    token: String,
    username: String,
    password: String,
}

fn check_credentials(username: &str, password: &str) -> ApiResult<()> {
    if !valid_username(username) {
        return Err(ApiError::bad("user names are 1–32 letters, digits, dots, dashes or underscores"));
    }
    if !password_ok(password) {
        return Err(ApiError::bad(format!("passwords need at least {} characters", crate::auth::MIN_PASSWORD)));
    }
    Ok(())
}

/// `POST /api/v1/auth/setup`: creates the first administrator with the
/// one-time token printed in the server log.
pub async fn setup(State(state): State<Arc<AppState>>, ip: Ip, Json(req): Json<SetupReq>) -> ApiResult<Json<Value>> {
    if !state.limits.register_ip.check(&ip.rate_key()) {
        return Err(ApiError::TooManyRequests);
    }
    let expected = state.setup_token.lock().unwrap_or_else(PoisonError::into_inner).clone();
    let valid = expected.is_some_and(|t| ct_eq(t.as_bytes(), req.token.trim().as_bytes()));
    if !valid || state.db.user_count()? > 0 {
        return Err(ApiError::Forbidden);
    }
    check_credentials(&req.username, &req.password)?;
    let hash = hash_password(req.password).await?;
    let user = state.db.create_user(&req.username, &hash, "admin")?;
    *state.setup_token.lock().unwrap_or_else(PoisonError::into_inner) = None;
    rebuild(&state)?;
    state.audit(Some(&user), &ip, "user.create", &format!("user:{}", user.id), "first administrator (setup link)");
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct RegisterReq {
    invite: String,
    username: String,
    password: String,
}

/// `POST /api/v1/auth/register`: self-registration with an invite link.
pub async fn register(
    State(state): State<Arc<AppState>>,
    ip: Ip,
    Json(req): Json<RegisterReq>,
) -> ApiResult<Json<Value>> {
    if !state.limits.register_ip.check(&ip.rate_key()) {
        return Err(ApiError::TooManyRequests);
    }
    if state.snapshot().settings.registration != Registration::Invite {
        return Err(ApiError::Forbidden);
    }
    check_credentials(&req.username, &req.password)?;
    let hash = hash_password(req.password).await?;
    let user = state
        .db
        .register_with_invite(&sha256_hex(req.invite.trim().as_bytes()), &req.username, &hash)?
        .ok_or_else(|| ApiError::bad("this invite is invalid, used or expired"))?;
    rebuild(&state)?;
    state.audit(Some(&user), &ip, "user.register", &format!("user:{}", user.id), &format!("role {}", user.role));
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct ResourceSignIn {
    rid: i64,
    #[serde(default)]
    next: String,
}

/// `GET /auth/resource?rid=…&next=…`: the hop from a `users`-mode resource
/// to the admin host and back. Signed-in, authorized users are sent back
/// with a one-minute code that the resource host exchanges for its cookie.
pub async fn resource_sign_in(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ResourceSignIn>,
    headers: HeaderMap,
) -> Response {
    let next = if safe_next(&q.next) { q.next.clone() } else { "/".to_string() };
    let session = cookie(&headers, SESSION_COOKIE)
        .and_then(|raw| state.db.session(&sha256_hex(raw.as_bytes())).ok().flatten())
        .filter(|s| s.mfa_passed);
    let snap = state.snapshot();
    let user = session.and_then(|s| snap.users.get(&s.user_id).cloned()).filter(|u| !u.disabled);
    let Some(user) = user else {
        let here = format!("/auth/resource?rid={}&next={}", q.rid, url_encode(&next));
        return redirect(&format!("/#/login?next={}", url_encode(&here)), StatusCode::SEE_OTHER);
    };
    if snap.settings.require_2fa && !user.totp_enabled {
        return redirect("/#/profile", StatusCode::SEE_OTHER);
    }
    let Some(res) = snap.resources_by_id.get(&q.rid).cloned() else {
        return pages::not_found();
    };
    if !access::user_allowed(&res, user.id, &user.role, snap.perms_of(&user)) {
        return pages::forbidden();
    }
    let code = state.new_auth_code(res.id, user.id);
    let origin = state.config.https_origin(&res.host);
    redirect(
        &format!("{origin}/.warren/callback?code={}&next={}", url_encode(&code), url_encode(&next)),
        StatusCode::SEE_OTHER,
    )
}
