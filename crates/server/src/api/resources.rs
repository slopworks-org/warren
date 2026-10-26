//! Published resources: host → device and port, with an access mode.

use super::session::hash_password;
use super::{ApiError, ApiResult, Auth, Ip, rebuild};
use crate::access::Grant;
use crate::auth::Perm;
use crate::db::{AccessMode, Resource, ResourceInput, Scheme};
use crate::state::AppState;
use axum::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

/// Request body for create and update; on update, absent fields keep their value.
#[derive(Deserialize, Default)]
pub struct ResourceReq {
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    device_id: Option<i64>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    scheme: Option<Scheme>,
    #[serde(default)]
    access: Option<AccessMode>,
    #[serde(default)]
    basic_user: Option<String>,
    /// New Basic password or PIN; required when switching to those modes.
    #[serde(default)]
    secret: Option<String>,
    #[serde(default)]
    grants: Option<Vec<Grant>>,
    #[serde(default)]
    enabled: Option<bool>,
}

fn can_see(auth: &Auth, r: &Resource) -> bool {
    r.user_id == auth.user.id || auth.can(Perm::AllResources)
}

fn view(state: &AppState, r: &Resource) -> Value {
    let snap = state.snapshot();
    let device = snap.devices.get(&r.device_id);
    let mut v = json!(r);
    v["url"] = json!(state.config.https_origin(&r.host));
    v["device_name"] = json!(device.map(|d| d.name.clone()));
    v["device_online"] = json!(device.is_some_and(|d| d.enabled && state.is_online(d.id)));
    v["owner"] = json!(snap.users.get(&r.user_id).map(|u| u.username.clone()));
    v
}

/// Validates a request against the current resource (if any) and builds
/// the stored fields; returns them with the owning user.
async fn validate(
    state: &AppState,
    auth: &Auth,
    current: Option<&Resource>,
    req: ResourceReq,
) -> ApiResult<(ResourceInput, i64)> {
    let host_in =
        req.host.or_else(|| current.map(|c| c.host.clone())).ok_or_else(|| ApiError::bad("host is required"))?;
    let host = state.config.resource_host(&host_in).ok_or_else(|| ApiError::bad("that is not a valid host name"))?;
    if host == state.config.admin_host() {
        return Err(ApiError::bad("that host is reserved for the admin interface"));
    }
    let device_id =
        req.device_id.or_else(|| current.map(|c| c.device_id)).ok_or_else(|| ApiError::bad("device_id is required"))?;
    let device = state.db.device(device_id)?.ok_or_else(|| ApiError::bad("no such device"))?;
    if device.user_id != auth.user.id && !auth.can(Perm::AllDevices) {
        return Err(ApiError::bad("no such device"));
    }
    let target_port =
        req.port.or_else(|| current.map(|c| c.target_port)).ok_or_else(|| ApiError::bad("port is required"))?;
    if target_port == 0 {
        return Err(ApiError::bad("port must be between 1 and 65535"));
    }
    let access = req.access.or_else(|| current.map(|c| c.access)).unwrap_or(AccessMode::Public);
    let basic_user =
        req.basic_user.or_else(|| current.map(|c| c.basic_user.clone())).unwrap_or_default().trim().to_string();
    let secret = req.secret.filter(|s| !s.is_empty());
    let mode_changed = current.is_none_or(|c| c.access != access);
    match access {
        AccessMode::Basic => {
            if basic_user.is_empty() || basic_user.contains(':') {
                return Err(ApiError::bad("Basic auth needs a user name without ':'"));
            }
            if mode_changed && secret.is_none() {
                return Err(ApiError::bad("set a password for Basic auth"));
            }
        }
        AccessMode::Pin => {
            if mode_changed && secret.is_none() {
                return Err(ApiError::bad("set a PIN"));
            }
            if secret.as_ref().is_some_and(|p| !(4..=64).contains(&p.chars().count())) {
                return Err(ApiError::bad("PINs are 4 to 64 characters"));
            }
        }
        AccessMode::Public | AccessMode::Users => {}
    }
    if access == AccessMode::Basic && secret.as_ref().is_some_and(|p| p.chars().count() < 8) {
        return Err(ApiError::bad("Basic passwords need at least 8 characters"));
    }
    let grants = req.grants.unwrap_or_else(|| current.map(|c| c.grants.clone()).unwrap_or_default());
    let snap = state.snapshot();
    for g in &grants {
        let exists = match g {
            Grant::All => true,
            Grant::User(id) => snap.users.contains_key(id),
            Grant::Role(r) => snap.roles.contains_key(r),
        };
        if !exists {
            return Err(ApiError::bad(format!("grant {g} names an unknown user or role")));
        }
    }
    let secret_hash = match secret {
        Some(s) if matches!(access, AccessMode::Basic | AccessMode::Pin) => Some(hash_password(s).await?),
        _ => None,
    };
    let input = ResourceInput {
        host,
        device_id,
        target_port,
        target_scheme: req.scheme.or_else(|| current.map(|c| c.target_scheme)).unwrap_or(Scheme::Http),
        access,
        basic_user: if access == AccessMode::Basic { basic_user } else { String::new() },
        secret_hash,
        enabled: req.enabled.or_else(|| current.map(|c| c.enabled)).unwrap_or(true),
        grants,
    };
    Ok((input, device.user_id))
}

/// `GET /api/v1/resources`.
pub async fn list(State(state): State<Arc<AppState>>, auth: Auth) -> ApiResult<Json<Value>> {
    let list: Vec<Value> =
        state.db.resources()?.iter().filter(|r| can_see(&auth, r)).map(|r| view(&state, r)).collect();
    Ok(Json(json!(list)))
}

/// `GET /api/v1/resources/{id}`.
pub async fn get_one(State(state): State<Arc<AppState>>, auth: Auth, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let r = state.db.resource(id)?.filter(|r| can_see(&auth, r)).ok_or(ApiError::NotFound)?;
    Ok(Json(view(&state, &r)))
}

/// `POST /api/v1/resources`. The resource belongs to the device's owner.
pub async fn create(
    State(state): State<Arc<AppState>>,
    ip: Ip,
    auth: Auth,
    Json(req): Json<ResourceReq>,
) -> ApiResult<Json<Value>> {
    let (input, owner) = validate(&state, &auth, None, req).await?;
    let id = state.db.create_resource(owner, &input)?;
    rebuild(&state)?;
    let details = format!(
        "→ device:{} port {} ({:?}, {:?})",
        input.device_id, input.target_port, input.target_scheme, input.access
    );
    state.audit(Some(&auth.user), &ip, "resource.create", &format!("resource:{id} {}", input.host), &details);
    let r = state.db.resource(id)?.ok_or(ApiError::Internal)?;
    Ok(Json(view(&state, &r)))
}

/// `PATCH /api/v1/resources/{id}`. Any change signs current visitors out.
pub async fn update(
    State(state): State<Arc<AppState>>,
    ip: Ip,
    auth: Auth,
    Path(id): Path<i64>,
    Json(req): Json<ResourceReq>,
) -> ApiResult<Json<Value>> {
    let current = state.db.resource(id)?.filter(|r| can_see(&auth, r)).ok_or(ApiError::NotFound)?;
    let (input, owner) = validate(&state, &auth, Some(&current), req).await?;
    state.db.update_resource(id, owner, &input)?;
    rebuild(&state)?;
    let details = format!(
        "→ device:{} port {} ({:?}, {:?})",
        input.device_id, input.target_port, input.target_scheme, input.access
    );
    state.audit(Some(&auth.user), &ip, "resource.update", &format!("resource:{id} {}", input.host), &details);
    let r = state.db.resource(id)?.ok_or(ApiError::NotFound)?;
    Ok(Json(view(&state, &r)))
}

/// `DELETE /api/v1/resources/{id}`.
pub async fn remove(
    State(state): State<Arc<AppState>>,
    ip: Ip,
    auth: Auth,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    let r = state.db.resource(id)?.filter(|r| can_see(&auth, r)).ok_or(ApiError::NotFound)?;
    state.db.delete_resource(id)?;
    rebuild(&state)?;
    state.audit(Some(&auth.user), &ip, "resource.delete", &format!("resource:{id} {}", r.host), "");
    Ok(Json(json!({ "ok": true })))
}
