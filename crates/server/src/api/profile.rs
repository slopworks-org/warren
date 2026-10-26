//! The caller's own account: password, 2FA, sessions, API tokens.

use super::session::hash_password;
use super::{ApiError, ApiResult, Auth, CodeReq, Ip, PendingAuth, rebuild};
use crate::auth::{new_totp_secret, password_ok, totp_uri, totp_verify, verify_async};
use crate::state::AppState;
use crate::util::{now, sha256_hex, token};
use axum::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

/// Renders `data` as an SVG QR code.
pub fn qr_svg(data: &str) -> ApiResult<String> {
    let code = qrcode::QrCode::new(data.as_bytes()).map_err(ApiError::internal)?;
    Ok(code.render::<qrcode::render::svg::Color<'_>>().min_dimensions(240, 240).quiet_zone(true).build())
}

/// `GET /api/v1/me`: the caller, their permissions and their CSRF token.
pub async fn me(State(state): State<Arc<AppState>>, PendingAuth(auth): PendingAuth) -> Json<Value> {
    let snap = state.snapshot();
    Json(json!({
        "user": auth.user,
        "permissions": auth.perms,
        "csrf": auth.session.as_ref().map(|s| s.csrf.clone()),
        "must_setup_2fa": snap.settings.require_2fa && !auth.user.totp_enabled,
        "require_2fa": snap.settings.require_2fa,
    }))
}

#[derive(Deserialize)]
pub struct PasswordReq {
    current: String,
    new: String,
}

/// Checks the caller's password, rate-limited per account.
async fn check_own_password(state: &AppState, auth: &Auth, password: String) -> ApiResult<()> {
    if !state.limits.login_user.check(&format!("reauth:{}", auth.user.id)) {
        return Err(ApiError::TooManyRequests);
    }
    if verify_async(password, Some(auth.user.password_hash.clone())).await {
        Ok(())
    } else {
        Err(ApiError::BadCredentials("wrong password"))
    }
}

/// `POST /api/v1/me/password`: ends every session, this one included.
pub async fn change_password(
    State(state): State<Arc<AppState>>,
    ip: Ip,
    auth: Auth,
    Json(req): Json<PasswordReq>,
) -> ApiResult<Json<Value>> {
    if !password_ok(&req.new) {
        return Err(ApiError::bad(format!("passwords need at least {} characters", crate::auth::MIN_PASSWORD)));
    }
    check_own_password(&state, &auth, req.current).await?;
    let hash = hash_password(req.new).await?;
    state.db.set_password(auth.user.id, &hash)?;
    rebuild(&state)?;
    state.audit(Some(&auth.user), &ip, "user.password", &format!("user:{}", auth.user.id), "changed own password");
    Ok(Json(json!({ "ok": true, "signed_out": true })))
}

/// `POST /api/v1/me/totp/setup`: starts enrolment with a fresh secret.
pub async fn totp_setup(State(state): State<Arc<AppState>>, PendingAuth(auth): PendingAuth) -> ApiResult<Json<Value>> {
    if auth.user.totp_enabled {
        return Err(ApiError::Conflict("two-factor authentication is already on".into()));
    }
    let secret = new_totp_secret();
    state.db.set_totp(auth.user.id, Some(&secret), false)?;
    rebuild(&state)?;
    let uri = totp_uri("Warren", &format!("{}@{}", auth.user.username, state.config.admin_host()), &secret);
    Ok(Json(json!({ "secret": secret, "uri": uri, "qr_svg": qr_svg(&uri)? })))
}

/// `POST /api/v1/me/totp/enable`: confirms enrolment with a code.
pub async fn totp_enable(
    State(state): State<Arc<AppState>>,
    ip: Ip,
    PendingAuth(auth): PendingAuth,
    Json(req): Json<CodeReq>,
) -> ApiResult<Json<Value>> {
    let secret = auth.user.totp_secret.clone().ok_or_else(|| ApiError::bad("start the setup first"))?;
    if auth.user.totp_enabled {
        return Err(ApiError::Conflict("two-factor authentication is already on".into()));
    }
    if !state.limits.login_user.check(&format!("totp-enrol:{}", auth.user.id)) {
        return Err(ApiError::TooManyRequests);
    }
    let step = totp_verify(&secret, &req.code, now()).ok_or(ApiError::BadCredentials("wrong code"))?;
    state.totp_used.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(auth.user.id, step);
    state.db.set_totp(auth.user.id, Some(&secret), true)?;
    rebuild(&state)?;
    state.audit(Some(&auth.user), &ip, "user.2fa_enable", &format!("user:{}", auth.user.id), "");
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct DisableReq {
    password: String,
}

/// `POST /api/v1/me/totp/disable`: needs the password; refused while 2FA is mandatory.
pub async fn totp_disable(
    State(state): State<Arc<AppState>>,
    ip: Ip,
    auth: Auth,
    Json(req): Json<DisableReq>,
) -> ApiResult<Json<Value>> {
    if state.snapshot().settings.require_2fa {
        return Err(ApiError::Conflict("the administrator requires two-factor authentication".into()));
    }
    check_own_password(&state, &auth, req.password).await?;
    state.db.set_totp(auth.user.id, None, false)?;
    rebuild(&state)?;
    state.audit(Some(&auth.user), &ip, "user.2fa_disable", &format!("user:{}", auth.user.id), "");
    Ok(Json(json!({ "ok": true })))
}

/// `GET /api/v1/me/sessions`.
pub async fn sessions(State(state): State<Arc<AppState>>, auth: Auth) -> ApiResult<Json<Value>> {
    let current = auth.session.as_ref().map(|s| s.id.clone());
    let list: Vec<Value> = state
        .db
        .sessions_of(auth.user.id)?
        .into_iter()
        .filter(|s| s.mfa_passed)
        .map(|s| {
            let mut v = json!(s);
            v["current"] = json!(current.as_deref() == Some(s.id.as_str()));
            v
        })
        .collect();
    Ok(Json(json!(list)))
}

/// `DELETE /api/v1/me/sessions/{id}`.
pub async fn delete_session(
    State(state): State<Arc<AppState>>,
    ip: Ip,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    if !state.db.delete_session(auth.user.id, &id)? {
        return Err(ApiError::NotFound);
    }
    state.audit(Some(&auth.user), &ip, "auth.session_revoke", &format!("user:{}", auth.user.id), "");
    Ok(Json(json!({ "ok": true })))
}

/// `GET /api/v1/me/tokens`.
pub async fn tokens(State(state): State<Arc<AppState>>, auth: Auth) -> ApiResult<Json<Value>> {
    Ok(Json(json!(state.db.api_tokens_of(auth.user.id)?)))
}

#[derive(Deserialize)]
pub struct TokenReq {
    name: String,
}

/// `POST /api/v1/me/tokens`: the secret is returned once.
pub async fn create_token(
    State(state): State<Arc<AppState>>,
    ip: Ip,
    auth: Auth,
    Json(req): Json<TokenReq>,
) -> ApiResult<Json<Value>> {
    let name: String = req.name.trim().chars().take(64).collect();
    if name.is_empty() {
        return Err(ApiError::bad("give the token a name"));
    }
    let secret = format!("wat_{}", token());
    let t = state.db.create_api_token(auth.user.id, &name, &sha256_hex(secret.as_bytes()))?;
    state.audit(Some(&auth.user), &ip, "token.create", &format!("token:{}", t.id), &name);
    Ok(Json(json!({ "token": t, "secret": secret })))
}

/// `DELETE /api/v1/me/tokens/{id}`.
pub async fn delete_token(
    State(state): State<Arc<AppState>>,
    ip: Ip,
    auth: Auth,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    if !state.db.delete_api_token(auth.user.id, id)? {
        return Err(ApiError::NotFound);
    }
    state.audit(Some(&auth.user), &ip, "token.delete", &format!("token:{id}"), "");
    Ok(Json(json!({ "ok": true })))
}
