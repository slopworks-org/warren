//! Endpoints the agent talks to: registration (plain HTTP, MAC-authenticated)
//! and the config long-poll (inside the tunnel).

use crate::db::DbError;
use crate::state::AppState;
use crate::util::now;
use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Query, State};
use axum::routing::get;
use http::header::CONTENT_TYPE;
use http::{HeaderValue, Request, Response, StatusCode};
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use warren_proto::register::verify_request;
use warren_proto::{Kv, LONG_POLL_SECS, codec, register};

fn text(status: StatusCode, body: String) -> Response<Body> {
    let mut r = Response::new(Body::from(body));
    *r.status_mut() = status;
    r.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    r
}

fn error(status: StatusCode, msg: &str) -> Response<Body> {
    let mut kv = Kv::new();
    kv.push("error", msg);
    text(status, kv.encode())
}

/// Device names: printable, at most 64 characters.
#[must_use]
pub fn clean_name(name: &str) -> Option<String> {
    let n: String = name.trim().chars().filter(|c| !c.is_control()).take(64).collect();
    (!n.is_empty()).then_some(n)
}

/// Handles `POST /agent/v1/register`.
pub async fn register(state: Arc<AppState>, ip: IpAddr, req: Request<Incoming>) -> Response<Body> {
    if !state.limits.register_ip.check(&crate::auth::rate_key(ip)) {
        return error(StatusCode::TOO_MANY_REQUESTS, "too many attempts; wait a minute");
    }
    let Ok(body) = Limited::new(req.into_body(), 8192).collect().await else {
        return error(StatusCode::PAYLOAD_TOO_LARGE, "request too large");
    };
    let Some(kv) = std::str::from_utf8(&body.to_bytes()).ok().and_then(|t| Kv::parse(t).ok()) else {
        return error(StatusCode::BAD_REQUEST, "malformed request");
    };
    let denied = || error(StatusCode::FORBIDDEN, "invalid, used or expired token");
    let Some(token_id) = kv.get("token_id") else { return denied() };
    let token = match state.db.reg_token(token_id) {
        Ok(Some(t)) if t.used_at.is_none() && t.expires_at > now() => t,
        Ok(_) => return denied(),
        Err(e) => {
            tracing::error!(error = %e, "looking up registration token");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };
    if !verify_request(&token.secret, &kv) {
        tracing::warn!(%ip, token = token_id, "registration with a bad MAC");
        return denied();
    }
    let (Some(pubkey), Some(nonce)) = (kv.get("pubkey"), kv.get("nonce")) else {
        return error(StatusCode::BAD_REQUEST, "missing pubkey or nonce");
    };
    if codec::decode_key(pubkey).is_none() {
        return error(StatusCode::BAD_REQUEST, "invalid public key");
    }
    let name =
        clean_name(&token.name).or_else(|| kv.get("name").and_then(clean_name)).unwrap_or_else(|| "device".to_string());

    let created = state.allocate(|addr| state.db.register_device(token_id, &name, pubkey, addr));
    let id = match created {
        Ok(Some(id)) => id,
        Ok(None) => return denied(),
        Err(crate::state::AllocError::Db(DbError::Conflict)) => {
            return error(StatusCode::CONFLICT, "this key is already registered");
        }
        Err(e) => {
            tracing::error!(error = %e, "registering device");
            return error(StatusCode::SERVICE_UNAVAILABLE, &e.to_string());
        }
    };
    let field = |k| kv.get(k).unwrap_or_default().chars().take(64).collect::<String>();
    if let Err(e) = state.db.device_report(id, &field("hostname"), &field("os"), &field("version")) {
        tracing::warn!(error = %e, "recording agent details");
    }
    if let Err(e) = state.rebuild() {
        tracing::error!(error = %e, "reloading state");
    }
    let Ok(Some(device)) = state.db.device(id) else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
    };
    let owner = state.snapshot().users.get(&device.user_id).cloned();
    state.audit(owner.as_ref(), &ip.to_string(), "device.register", &format!("device:{id} {name}"), &field("os"));

    let mut reply = state.agent_config(&device).to_kv();
    register::sign_reply(&token.secret, nonce, &mut reply);
    text(StatusCode::OK, reply.encode())
}

#[derive(Deserialize)]
struct PollQuery {
    #[serde(default)]
    v: u64,
    #[serde(default)]
    wait: u64,
    #[serde(default)]
    agent: String,
    #[serde(default)]
    os: String,
    #[serde(default)]
    hostname: String,
}

/// Handles `GET /agent/v1/config`: answers at once if the agent's version is
/// stale, otherwise waits up to `wait` seconds for a change.
async fn config(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(q): Query<PollQuery>,
) -> Response<Body> {
    // The source address identifies the device: WireGuard only accepts
    // packets from a peer's own tunnel address.
    let IpAddr::V4(ip) = peer.ip() else { return error(StatusCode::FORBIDDEN, "unknown device") };
    let Some(id) = state.snapshot().device_by_ip.get(&ip).copied() else {
        return error(StatusCode::FORBIDDEN, "unknown device");
    };
    if !q.agent.is_empty() {
        let clip = |s: &str| s.chars().take(64).collect::<String>();
        state.record_agent_report(id, &clip(&q.hostname), &clip(&q.os), &clip(&q.agent));
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(q.wait.min(LONG_POLL_SECS + 5));
    let mut rx = state.subscribe();
    loop {
        let snap = state.snapshot();
        let active =
            snap.devices.get(&id).filter(|d| d.enabled && snap.users.get(&d.user_id).is_some_and(|u| !u.disabled));
        let Some(device) = active else { return error(StatusCode::FORBIDDEN, "device disabled or revoked") };
        let cfg = state.agent_config(device);
        if cfg.version != q.v {
            return text(StatusCode::OK, cfg.to_kv().encode());
        }
        tokio::select! {
            changed = rx.changed() => if changed.is_err() { break },
            () = tokio::time::sleep_until(deadline) => break,
        }
    }
    text(StatusCode::NOT_MODIFIED, String::new())
}

/// Router for the control listener.
pub fn control_router(state: Arc<AppState>) -> Router {
    Router::new().route(warren_proto::CONFIG_PATH, get(config)).with_state(state)
}

#[cfg(test)]
mod tests {
    #[test]
    fn names() {
        assert_eq!(super::clean_name("  box\n1 ").as_deref(), Some("box1"));
        assert_eq!(super::clean_name(" \t"), None);
        assert_eq!(super::clean_name(&"x".repeat(100)).unwrap().len(), 64);
    }
}
