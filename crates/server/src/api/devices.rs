//! Devices: registration tokens, agentless configs, rename, disable, revoke.

use super::profile::qr_svg;
use super::{ApiError, ApiResult, Auth, Ip, rebuild};
use crate::agent_api::clean_name;
use crate::auth::Perm;
use crate::db::{Device, DeviceKind, RegTokenRow};
use crate::state::AppState;
use crate::util::{now, random};
use axum::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use warren_proto::codec;
use warren_proto::register::{RegToken, TOKEN_ID_LEN, TOKEN_SECRET_LEN};

/// A device the caller may see: their own, or any with `devices.all`.
fn visible(state: &AppState, auth: &Auth, id: i64) -> ApiResult<Device> {
    state.db.device(id)?.filter(|d| d.user_id == auth.user.id || auth.can(Perm::AllDevices)).ok_or(ApiError::NotFound)
}

/// Resolves the owner for a new device: the caller, or (with
/// `devices.all`) another active user.
fn owner_for(state: &AppState, auth: &Auth, user_id: Option<i64>) -> ApiResult<i64> {
    match user_id {
        None => Ok(auth.user.id),
        Some(id) if id == auth.user.id => Ok(id),
        Some(id) => {
            auth.require(Perm::AllDevices)?;
            state
                .snapshot()
                .users
                .get(&id)
                .filter(|u| !u.disabled)
                .map(|u| u.id)
                .ok_or_else(|| ApiError::bad("no such user"))
        }
    }
}

/// `GET /api/v1/devices`.
pub async fn list(State(state): State<Arc<AppState>>, auth: Auth) -> ApiResult<Json<Value>> {
    let snap = state.snapshot();
    let mut views: Vec<_> = state
        .db
        .devices()?
        .iter()
        .filter(|d| d.user_id == auth.user.id || auth.can(Perm::AllDevices))
        .map(|d| state.device_view(&snap, d))
        .collect();
    views.sort_by_key(|v| v.device.name.to_lowercase());
    Ok(Json(json!(views)))
}

/// `GET /api/v1/devices/{id}`.
pub async fn get_one(State(state): State<Arc<AppState>>, auth: Auth, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let d = visible(&state, &auth, id)?;
    Ok(Json(json!(state.device_view(&state.snapshot(), &d))))
}

#[derive(Deserialize)]
pub struct TokenReq {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    user_id: Option<i64>,
    #[serde(default)]
    ttl_minutes: Option<u32>,
}

/// `POST /api/v1/devices/tokens`: a one-time token for `warren up`.
pub async fn create_token(
    State(state): State<Arc<AppState>>,
    ip: Ip,
    auth: Auth,
    Json(req): Json<TokenReq>,
) -> ApiResult<Json<Value>> {
    let owner = owner_for(&state, &auth, req.user_id)?;
    let ttl = req.ttl_minutes.unwrap_or(state.snapshot().settings.token_ttl_minutes).clamp(5, 24 * 60);
    let token = RegToken { id: random::<TOKEN_ID_LEN>(), secret: random::<TOKEN_SECRET_LEN>() };
    let name = req.name.as_deref().and_then(clean_name).unwrap_or_default();
    let expires_at = now() + i64::from(ttl) * 60;
    state.db.create_reg_token(&RegTokenRow {
        id: token.id_hex(),
        user_id: owner,
        secret: token.secret.to_vec(),
        name: name.clone(),
        expires_at,
        used_at: None,
    })?;
    state.audit(
        Some(&auth.user),
        &ip,
        "device.token",
        &format!("user:{owner}"),
        &format!("token {} {name}", token.id_hex()),
    );
    let server = state.config.https_origin(state.config.admin_host());
    let encoded = token.encode();
    Ok(Json(json!({
        "token": encoded,
        "expires_at": expires_at,
        "command": format!("warren up --server {server} --token {encoded}"),
    })))
}

#[derive(Deserialize)]
pub struct ManualReq {
    name: String,
    #[serde(default)]
    public_key: Option<String>,
    #[serde(default)]
    user_id: Option<i64>,
}

/// `POST /api/v1/devices`: a device without the agent. Unless the caller
/// brings its own public key, a key pair is generated and the private key
/// appears only in this response's config; it is never stored.
pub async fn create_manual(
    State(state): State<Arc<AppState>>,
    ip: Ip,
    auth: Auth,
    Json(req): Json<ManualReq>,
) -> ApiResult<Json<Value>> {
    let owner = owner_for(&state, &auth, req.user_id)?;
    let name = clean_name(&req.name).ok_or_else(|| ApiError::bad("give the device a name"))?;
    let (public, private) = if let Some(k) = req.public_key.as_deref().map(str::trim).filter(|k| !k.is_empty()) {
        (codec::decode_key(k).ok_or_else(|| ApiError::bad("that is not a WireGuard public key"))?, None)
    } else {
        let mut sk = random::<32>();
        sk[0] &= 0xf8;
        sk[31] = (sk[31] & 0x7f) | 0x40;
        (x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES), Some(codec::encode_key(&sk)))
    };
    let id = state
        .allocate(|addr| state.db.create_device(owner, &name, &codec::encode_key(&public), addr, DeviceKind::Manual))?;
    rebuild(&state)?;
    let device = state.db.device(id)?.ok_or(ApiError::Internal)?;
    state.audit(Some(&auth.user), &ip, "device.create", &format!("device:{id} {name}"), "manual WireGuard config");
    let config = state.wg_quick_config(&device, private.as_deref());
    let qr = if private.is_some() { Some(qr_svg(&config)?) } else { None };
    Ok(Json(json!({
        "device": state.device_view(&state.snapshot(), &device),
        "config": config,
        "qr_svg": qr,
        "private_key_included": private.is_some(),
    })))
}

/// `GET /api/v1/devices/{id}/config`: the config with a placeholder key.
pub async fn config(State(state): State<Arc<AppState>>, auth: Auth, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let d = visible(&state, &auth, id)?;
    Ok(Json(json!({ "config": state.wg_quick_config(&d, None) })))
}

#[derive(Deserialize)]
pub struct UpdateReq {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
}

/// `PATCH /api/v1/devices/{id}`: rename, disable or enable.
pub async fn update(
    State(state): State<Arc<AppState>>,
    ip: Ip,
    auth: Auth,
    Path(id): Path<i64>,
    Json(req): Json<UpdateReq>,
) -> ApiResult<Json<Value>> {
    let d = visible(&state, &auth, id)?;
    let name = match &req.name {
        Some(n) => Some(clean_name(n).ok_or_else(|| ApiError::bad("give the device a name"))?),
        None => None,
    };
    state.db.update_device(id, name.as_deref(), req.enabled)?;
    rebuild(&state)?;
    let mut what = Vec::new();
    if let Some(n) = &name {
        what.push(format!("renamed {:?} to {n:?}", d.name));
    }
    if let Some(e) = req.enabled {
        what.push(if e { "enabled".into() } else { "disabled".into() });
    }
    state.audit(Some(&auth.user), &ip, "device.update", &format!("device:{id} {}", d.name), &what.join(", "));
    let d = state.db.device(id)?.ok_or(ApiError::NotFound)?;
    Ok(Json(json!(state.device_view(&state.snapshot(), &d))))
}

/// `DELETE /api/v1/devices/{id}`: revokes the device; its key leaves the hub
/// immediately and its resources are deleted.
pub async fn remove(
    State(state): State<Arc<AppState>>,
    ip: Ip,
    auth: Auth,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    let d = visible(&state, &auth, id)?;
    state.db.delete_device(id)?;
    rebuild(&state)?;
    state.audit(Some(&auth.user), &ip, "device.revoke", &format!("device:{id} {}", d.name), "");
    Ok(Json(json!({ "ok": true })))
}
