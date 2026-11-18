//! Endpoints the agent talks to: registration (plain HTTP, MAC-authenticated)
//! and the config long-poll (inside the tunnel).

use crate::db::{DbError, Device, ReceiptSigner};
use crate::lan::LanReport;
use crate::state::{AppState, Snapshot};
use crate::util::{fnv64, now, sha256_hex};
use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Query, State};
use axum::routing::get;
use http::header::{CACHE_CONTROL, CONTENT_TYPE};
use http::{HeaderValue, Request, Response, StatusCode};
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use warren_proto::{AgentConfig, Kv, LONG_POLL_SECS, codec, register};

// Keep the opt-in response within the Android client's read limit.
const MAX_CONFIG_BYTES: usize = 256 * 1024;
const MAX_ROUTE_PEERS: usize = 256;

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

/// Handles one-time and resumable registration on their respective paths.
pub async fn register(state: Arc<AppState>, ip: IpAddr, req: Request<Incoming>, resumable: bool) -> Response<Body> {
    if !state.limits.register_ip.check(&crate::auth::rate_key(ip)) {
        return error(StatusCode::TOO_MANY_REQUESTS, "too many attempts; wait a minute");
    }
    let Ok(body) = Limited::new(req.into_body(), 8192).collect().await else {
        return error(StatusCode::PAYLOAD_TOO_LARGE, "request too large");
    };
    let Some(kv) = std::str::from_utf8(&body.to_bytes()).ok().and_then(|t| Kv::parse(t).ok()) else {
        return error(StatusCode::BAD_REQUEST, "malformed request");
    };
    if resumable && !kv.get_all("resume").eq(["1"]) {
        return error(StatusCode::BAD_REQUEST, "invalid registration mode");
    }
    register_request(&state, ip, &kv, resumable)
}

fn denied() -> Response<Body> {
    error(StatusCode::FORBIDDEN, "invalid, used or expired token")
}

fn receipt_response(
    state: &AppState,
    token_id: &str,
    request_hash: &str,
    pubkey: &str,
) -> Result<Option<Response<Body>>, DbError> {
    let Some((id, receipt)) = state.db.registration_receipt(token_id, request_hash)? else { return Ok(None) };
    // A previous attempt may have committed before it could update the hub.
    if state.snapshot().devices.get(&id).is_none_or(|d| d.public_key != pubkey) {
        state.rebuild()?;
    }
    let mut response = text(StatusCode::OK, receipt);
    response.headers_mut().insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(Some(response))
}

fn register_request(state: &AppState, ip: IpAddr, kv: &Kv, resumable: bool) -> Response<Body> {
    let Some(token_id) = kv.get("token_id") else { return denied() };
    let request_hash = resumable.then(|| sha256_hex(kv.encode().as_bytes()));
    let recover = || {
        let (Some(hash), Some(pubkey)) = (&request_hash, kv.get("pubkey")) else { return None };
        receipt_response(state, token_id, hash, pubkey).unwrap_or_else(|e| {
            tracing::error!(error = %e, "recovering registration receipt");
            Some(error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"))
        })
    };
    let token = match state.db.reg_token(token_id) {
        Ok(Some(t)) if t.used_at.is_none() && t.expires_at > now() => t,
        Ok(_) => return recover().unwrap_or_else(denied),
        Err(e) => {
            tracing::error!(error = %e, "looking up registration token");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
        }
    };
    let verify = if resumable { register::verify_resumable_request } else { register::verify_request };
    if !verify(&token.secret, kv) {
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

    let sign = |device: &crate::db::Device| {
        let mut receipt = state.enrollment_config(device).to_kv();
        receipt.push("resume", "1");
        register::sign_reply(&token.secret, nonce, &mut receipt);
        receipt.encode()
    };
    let created = state.allocate(|addr| {
        let receipt = request_hash.as_deref().map(|request_hash| ReceiptSigner { request_hash, sign: &sign });
        state.db.register_device_inner(token_id, &name, pubkey, addr, receipt)
    });
    let id = match created {
        Ok(Some(id)) => id,
        Ok(None) => return recover().unwrap_or_else(denied),
        Err(crate::state::AllocError::Db(DbError::Conflict)) => {
            return error(StatusCode::CONFLICT, "this key is already registered");
        }
        Err(e) => {
            if let Some(reply) = recover() {
                return reply;
            }
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
    let snap = state.snapshot();
    let owner = snap.users.get(&device.user_id);
    state.audit(owner, &ip.to_string(), "device.register", &format!("device:{id} {name}"), &field("os"));

    if resumable {
        return recover().unwrap_or_else(denied);
    }
    let mut reply = state.agent_config(&snap, &device).to_kv();
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
    #[serde(default)]
    lan: String,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    mesh: u8,
    #[serde(default)]
    route_peers: u8,
}

// Read outgoing pairs from the compiled hub ACL. Full-access and port-scoped
// pairs are disjoint and each is ordered by overlay address.
fn route_display(snap: &Snapshot, source: Ipv4Addr, budget: usize) -> String {
    const MARKER: &str = "route_peers=1\n";
    if budget < MARKER.len() {
        return String::new();
    }
    let mut display = MARKER.to_string();
    let range = (source, Ipv4Addr::UNSPECIFIED)..=(source, Ipv4Addr::BROADCAST);
    let destinations = snap.acl.all.range(range.clone()).chain(snap.acl.ports.range(range).map(|(pair, _)| pair));
    let peers = destinations.filter_map(|(_, ip)| snap.device_by_ip.get(ip)).filter_map(|id| snap.active_device(*id));
    for device in peers.take(MAX_ROUTE_PEERS) {
        // SQLite can reuse a deleted row id. The key fingerprint survives a
        // rename or address change and does not expose the WireGuard key.
        let id = codec::hex_encode(&Sha256::digest(device.public_key.as_bytes())[..16]);
        let name = clean_name(&device.name).unwrap_or_default();
        let row = format!("route_peer={id} {} {name}", device.address);
        let row = row.trim_end();
        if display.len() + row.len() + 1 > budget {
            break;
        }
        display.push_str(row);
        display.push('\n');
    }
    display
}

fn config_body(snap: &Snapshot, device: &Device, mut cfg: AgentConfig, show_routes: bool) -> (u64, String) {
    let mut body = cfg.to_kv().encode();
    if show_routes {
        // Reserve room for the new version (a positive 63-bit integer).
        let budget = MAX_CONFIG_BYTES.saturating_sub(body.len() + 19 - cfg.version.to_string().len());
        let display = route_display(snap, device.address, budget);
        if !display.is_empty() {
            body.push_str(&display);
            cfg.version = fnv64(body.as_bytes()) >> 1;
            body = cfg.to_kv().encode();
            body.push_str(&display);
        }
    }
    (cfg.version, body)
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
    let snap = state.snapshot();
    let Some(device) = snap.device_by_ip.get(&ip).and_then(|id| snap.active_device(*id)) else {
        return error(StatusCode::FORBIDDEN, "unknown device");
    };
    let (id, key) = (device.id, device.public_key.clone());
    drop(snap);
    if !q.agent.is_empty() {
        let clip = |s: &str| s.chars().take(64).collect::<String>();
        state.record_agent_report(id, &clip(&q.hostname), &clip(&q.os), &clip(&q.agent));
        // Legacy single-interface agents cannot safely accept asymmetric paths.
        state.record_lan(id, if q.mesh == 2 { LanReport::parse(&q.lan, q.port) } else { None });
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(q.wait.min(LONG_POLL_SECS + 5));
    let mut rx = state.subscribe();
    loop {
        let snap = state.snapshot();
        let active = snap.active_device(id).filter(|d| d.address == ip && d.public_key == key);
        let Some(device) = active else { return error(StatusCode::FORBIDDEN, "device disabled or revoked") };
        let (version, body) = config_body(&snap, device, state.agent_config(&snap, device), q.route_peers == 1);
        if version != q.v {
            return text(StatusCode::OK, body);
        }
        tokio::select! {
            changed = rx.changed() => if changed.is_err() { break },
            () = tokio::time::sleep_until(deadline) => break,
        }
    }
    text(StatusCode::NOT_MODIFIED, String::new())
}

#[derive(Deserialize)]
struct BinaryQuery {
    file: String,
}

/// Handles `GET /agent/v1/binary`: the agent build the device should update to.
async fn binary(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(q): Query<BinaryQuery>,
) -> Response<Body> {
    let snap = state.snapshot();
    let known = match peer.ip() {
        IpAddr::V4(ip) => snap.device_by_ip.get(&ip).and_then(|id| snap.devices.get(id)).is_some_and(|d| d.enabled),
        IpAddr::V6(_) => false,
    };
    if !known {
        return error(StatusCode::FORBIDDEN, "unknown device");
    }
    if snap.agent_target.is_empty() {
        return error(StatusCode::NOT_FOUND, "no agent update is scheduled");
    }
    let Some(file) = warren_proto::AGENT_ASSETS.iter().find(|a| **a == q.file) else {
        return error(StatusCode::NOT_FOUND, "no such agent build");
    };
    match crate::update::agent_binary(&state, &snap.agent_target, file).await {
        Ok(data) => {
            let mut r = Response::new(Body::from(data));
            r.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
            r
        }
        Err(e) => {
            tracing::warn!(error = %e, file, "serving an agent build");
            error(StatusCode::BAD_GATEWAY, "cannot download the agent build")
        }
    }
}

/// Router for the control listener.
pub fn control_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(warren_proto::CONFIG_PATH, get(config))
        .route(warren_proto::BINARY_PATH, get(binary))
        .with_state(state)
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
