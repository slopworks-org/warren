//! Administration: users, roles, invites, settings, ACL rules, audit log.

use super::session::hash_password;
use super::{ApiError, ApiResult, Auth, Ip, PendingAuth, rebuild, valid_username};
use crate::acl::{PortSpec, Subject};
use crate::auth::{Perm, password_ok};
use crate::db::Settings;
use crate::state::AppState;
use crate::util::{now, sha256_hex, token};
use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::{Arc, PoisonError};
use warren_proto::codec::b64url_encode;

/// `GET /api/v1/server`: facts about this server.
pub async fn server_info(State(state): State<Arc<AppState>>, _auth: PendingAuth) -> Json<Value> {
    let c = &state.config;
    let latest = state.latest_release.read().unwrap_or_else(PoisonError::into_inner).clone();
    let update = latest.filter(|r| crate::update::is_newer(&r.version, warren_proto::VERSION));
    Json(json!({
        "version": warren_proto::VERSION,
        "update": update,
        "self_update": crate::update::self_update_blocker().is_none(),
        "domain": c.domain,
        "admin_host": c.admin_host(),
        "admin_url": c.https_origin(c.admin_host()),
        "wg_endpoint": c.wg_endpoint(),
        "network": state.network.to_string(),
        "server_ip": state.network.server_ip().to_string(),
        "public_key": state.server_public_key,
        "backend": state.backend.name(),
        "tls_mode": format!("{:?}", c.tls.mode).to_lowercase(),
    }))
}

/// `POST /api/v1/server/update`: downloads the latest release and restarts into it.
pub async fn update_server(State(state): State<Arc<AppState>>, ip: Ip, auth: Auth) -> ApiResult<Json<Value>> {
    use crate::update::{Fetcher, UpdateError, install};
    auth.require(Perm::ManageSettings)?;
    let fetcher = Fetcher::new().map_err(ApiError::internal)?;
    let release = install(&state, &fetcher).await.map_err(|e| match e {
        UpdateError::Unsupported(_) | UpdateError::UpToDate | UpdateError::Busy => ApiError::Conflict(e.to_string()),
        other => {
            tracing::warn!(error = %other, "installing the new release");
            ApiError::Conflict(format!("cannot install the update: {other}"))
        }
    })?;
    state.audit(Some(&auth.user), &ip, "server.update", "server", &format!("to {}", release.version));
    Ok(Json(json!({ "version": release.version })))
}

/// `GET /api/v1/users`.
pub async fn users(State(state): State<Arc<AppState>>, auth: Auth) -> ApiResult<Json<Value>> {
    auth.require(Perm::ManageUsers)?;
    Ok(Json(json!(state.db.users()?)))
}

/// `GET /api/v1/roles`: visible to everyone (for grant pickers).
pub async fn roles(State(state): State<Arc<AppState>>, _auth: Auth) -> ApiResult<Json<Value>> {
    Ok(Json(json!(state.db.roles()?)))
}

fn check_role(state: &AppState, role: &str) -> ApiResult<()> {
    if state.snapshot().roles.contains_key(role) { Ok(()) } else { Err(ApiError::bad("no such role")) }
}

/// A readable random password for resets and new accounts.
fn generated_password() -> String {
    b64url_encode(&crate::util::random::<12>())
}

#[derive(Deserialize)]
pub struct CreateUserReq {
    username: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default = "default_role")]
    role: String,
}

fn default_role() -> String {
    "user".into()
}

/// `POST /api/v1/users`: without a password, one is generated and returned once.
pub async fn create_user(
    State(state): State<Arc<AppState>>,
    ip: Ip,
    auth: Auth,
    Json(req): Json<CreateUserReq>,
) -> ApiResult<Json<Value>> {
    auth.require(Perm::ManageUsers)?;
    if !valid_username(&req.username) {
        return Err(ApiError::bad("user names are 1–32 letters, digits, dots, dashes or underscores"));
    }
    check_role(&state, &req.role)?;
    let (password, generated) = match req.password.filter(|p| !p.is_empty()) {
        Some(p) if password_ok(&p) => (p, false),
        Some(_) => {
            return Err(ApiError::bad(format!("passwords need at least {} characters", crate::auth::MIN_PASSWORD)));
        }
        None => (generated_password(), true),
    };
    let user = state.db.create_user(&req.username, &hash_password(password.clone()).await?, &req.role)?;
    rebuild(&state)?;
    state.audit(
        Some(&auth.user),
        &ip,
        "user.create",
        &format!("user:{} {}", user.id, user.username),
        &format!("role {}", user.role),
    );
    Ok(Json(json!({ "user": user, "password": generated.then_some(password) })))
}

#[derive(Deserialize)]
pub struct UpdateUserReq {
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    disabled: Option<bool>,
}

/// `PATCH /api/v1/users/{id}`: role and blocked state. Administrators cannot
/// block or demote themselves, so the server never loses its last admin by accident.
pub async fn update_user(
    State(state): State<Arc<AppState>>,
    ip: Ip,
    auth: Auth,
    Path(id): Path<i64>,
    Json(req): Json<UpdateUserReq>,
) -> ApiResult<Json<Value>> {
    auth.require(Perm::ManageUsers)?;
    let target = state.db.user(id)?.ok_or(ApiError::NotFound)?;
    if id == auth.user.id && (req.disabled == Some(true) || req.role.as_ref().is_some_and(|r| *r != target.role)) {
        return Err(ApiError::Conflict("you cannot block or demote yourself".into()));
    }
    if let Some(r) = &req.role {
        check_role(&state, r)?;
    }
    state.db.update_user(id, req.role.as_deref(), req.disabled)?;
    rebuild(&state)?;
    let mut what = Vec::new();
    if let Some(r) = &req.role {
        what.push(format!("role {} → {r}", target.role));
    }
    if let Some(d) = req.disabled {
        what.push(if d { "blocked".into() } else { "unblocked".into() });
    }
    state.audit(Some(&auth.user), &ip, "user.update", &format!("user:{id} {}", target.username), &what.join(", "));
    Ok(Json(json!(state.db.user(id)?)))
}

/// `DELETE /api/v1/users/{id}`: also deletes the user's devices and resources.
pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    ip: Ip,
    auth: Auth,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    auth.require(Perm::ManageUsers)?;
    if id == auth.user.id {
        return Err(ApiError::Conflict("you cannot delete yourself".into()));
    }
    let target = state.db.user(id)?.ok_or(ApiError::NotFound)?;
    state.db.delete_user(id)?;
    rebuild(&state)?;
    state.audit(Some(&auth.user), &ip, "user.delete", &format!("user:{id} {}", target.username), "");
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct ResetReq {
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    reset_2fa: bool,
}

/// `POST /api/v1/users/{id}/password`: sets or generates a password, signs
/// the user out everywhere and optionally removes their 2FA.
pub async fn reset_password(
    State(state): State<Arc<AppState>>,
    ip: Ip,
    auth: Auth,
    Path(id): Path<i64>,
    Json(req): Json<ResetReq>,
) -> ApiResult<Json<Value>> {
    auth.require(Perm::ManageUsers)?;
    let target = state.db.user(id)?.ok_or(ApiError::NotFound)?;
    let (password, generated) = match req.password.filter(|p| !p.is_empty()) {
        Some(p) if password_ok(&p) => (p, false),
        Some(_) => {
            return Err(ApiError::bad(format!("passwords need at least {} characters", crate::auth::MIN_PASSWORD)));
        }
        None => (generated_password(), true),
    };
    state.db.set_password(id, &hash_password(password.clone()).await?)?;
    if req.reset_2fa {
        state.db.set_totp(id, None, false)?;
    }
    rebuild(&state)?;
    let details = if req.reset_2fa { "password reset, 2FA removed" } else { "password reset" };
    state.audit(Some(&auth.user), &ip, "user.password_reset", &format!("user:{id} {}", target.username), details);
    Ok(Json(json!({ "ok": true, "password": generated.then_some(password) })))
}

/// `GET /api/v1/invites`.
pub async fn invites(State(state): State<Arc<AppState>>, auth: Auth) -> ApiResult<Json<Value>> {
    auth.require(Perm::ManageUsers)?;
    Ok(Json(json!(state.db.invites()?)))
}

#[derive(Deserialize)]
pub struct InviteReq {
    #[serde(default = "default_role")]
    role: String,
    #[serde(default)]
    ttl_hours: Option<u32>,
}

/// `POST /api/v1/invites`: the link is returned once.
pub async fn create_invite(
    State(state): State<Arc<AppState>>,
    ip: Ip,
    auth: Auth,
    Json(req): Json<InviteReq>,
) -> ApiResult<Json<Value>> {
    auth.require(Perm::ManageUsers)?;
    check_role(&state, &req.role)?;
    let code = token();
    let hash = sha256_hex(code.as_bytes());
    let expires_at = now() + i64::from(req.ttl_hours.unwrap_or(72).clamp(1, 24 * 30)) * 3600;
    state.db.create_invite(&hash, &req.role, auth.user.id, expires_at)?;
    state.audit(
        Some(&auth.user),
        &ip,
        "invite.create",
        &format!("invite:{}", &hash[..12]),
        &format!("role {}", req.role),
    );
    let url = format!("{}/#/register?invite={code}", state.config.https_origin(state.config.admin_host()));
    Ok(Json(json!({ "id": hash, "url": url, "expires_at": expires_at })))
}

/// `DELETE /api/v1/invites/{id}`.
pub async fn delete_invite(
    State(state): State<Arc<AppState>>,
    ip: Ip,
    auth: Auth,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    auth.require(Perm::ManageUsers)?;
    if !state.db.delete_invite(&id)? {
        return Err(ApiError::NotFound);
    }
    state.audit(
        Some(&auth.user),
        &ip,
        "invite.delete",
        &format!("invite:{}", id.chars().take(12).collect::<String>()),
        "",
    );
    Ok(Json(json!({ "ok": true })))
}

/// `GET /api/v1/settings`.
pub async fn settings(State(state): State<Arc<AppState>>, auth: Auth) -> ApiResult<Json<Settings>> {
    auth.require(Perm::ManageSettings)?;
    Ok(Json(state.db.settings()?))
}

/// `PUT /api/v1/settings`.
pub async fn update_settings(
    State(state): State<Arc<AppState>>,
    ip: Ip,
    auth: Auth,
    Json(new): Json<Settings>,
) -> ApiResult<Json<Settings>> {
    auth.require(Perm::ManageSettings)?;
    if !(1..=24 * 90).contains(&new.session_ttl_hours) {
        return Err(ApiError::bad("session lifetime must be between 1 hour and 90 days"));
    }
    if !(5..=24 * 60).contains(&new.token_ttl_minutes) {
        return Err(ApiError::bad("token lifetime must be between 5 minutes and 24 hours"));
    }
    if new.require_2fa && !auth.user.totp_enabled {
        return Err(ApiError::Conflict(
            "turn on two-factor authentication for your own account before requiring it".into(),
        ));
    }
    let old = state.db.settings()?;
    state.db.set_settings(&new)?;
    rebuild(&state)?;
    let details = serde_json::to_string(&new).unwrap_or_default();
    state.audit(
        Some(&auth.user),
        &ip,
        "settings.update",
        "settings",
        &format!("{} → {details}", serde_json::to_string(&old).unwrap_or_default()),
    );
    Ok(Json(new))
}

/// `GET /api/v1/acl`.
pub async fn acl(State(state): State<Arc<AppState>>, auth: Auth) -> ApiResult<Json<Value>> {
    auth.require(Perm::ManageSettings)?;
    Ok(Json(json!(state.db.acl_rules()?)))
}

#[derive(Deserialize)]
pub struct AclReq {
    src: Subject,
    dst: Subject,
    #[serde(default)]
    ports: String,
    #[serde(default)]
    description: String,
}

/// `POST /api/v1/acl`: lets `src` devices open connections to `dst` devices.
pub async fn create_acl(
    State(state): State<Arc<AppState>>,
    ip: Ip,
    auth: Auth,
    Json(req): Json<AclReq>,
) -> ApiResult<Json<Value>> {
    auth.require(Perm::ManageSettings)?;
    let ports = PortSpec::parse_list(&req.ports).map_err(|e| ApiError::bad(e.to_string()))?;
    let description: String = req.description.trim().chars().take(200).collect();
    let id = state.db.create_acl_rule(req.src, req.dst, &ports, &description)?;
    rebuild(&state)?;
    let ports_text = if ports.is_empty() { "all traffic".to_string() } else { PortSpec::format_list(&ports) };
    state.audit(
        Some(&auth.user),
        &ip,
        "acl.create",
        &format!("acl:{id}"),
        &format!("{} → {} ({ports_text})", req.src, req.dst),
    );
    Ok(Json(json!({ "id": id })))
}

/// `DELETE /api/v1/acl/{id}`.
pub async fn delete_acl(
    State(state): State<Arc<AppState>>,
    ip: Ip,
    auth: Auth,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    auth.require(Perm::ManageSettings)?;
    if !state.db.delete_acl_rule(id)? {
        return Err(ApiError::NotFound);
    }
    rebuild(&state)?;
    state.audit(Some(&auth.user), &ip, "acl.delete", &format!("acl:{id}"), "");
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct AuditQuery {
    #[serde(default)]
    before: Option<i64>,
    #[serde(default)]
    limit: Option<u32>,
}

/// `GET /api/v1/audit`: everyone's entries with `audit.all`, otherwise the caller's own.
pub async fn audit(
    State(state): State<Arc<AppState>>,
    auth: Auth,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<Value>> {
    let actor = (!auth.can(Perm::AllAudit)).then_some(auth.user.id);
    let entries = state.db.audit_page(actor, q.before, q.limit.unwrap_or(100).clamp(1, 500))?;
    Ok(Json(json!(entries)))
}
