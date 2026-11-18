//! The opted-in agent control response reflects outbound hub reachability.

#![allow(clippy::unwrap_used, reason = "test fixtures and their replies must satisfy the protocol")]

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use http::{Request, StatusCode};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tower::ServiceExt;
use warren_proto::{AgentConfig, CONFIG_PATH, Kv, codec};
use warren_server::acl::{PortSpec, Subject};
use warren_server::agent_api::control_router;
use warren_server::config::{Config, TlsMode};
use warren_server::db::{Db, DeviceKind};
use warren_server::state::AppState;
use warren_server::tls::CertStore;
use warren_server::wg::Backend;

fn state() -> Arc<AppState> {
    let config =
        Config::from_toml("domain = 'warren.test'\n[tls]\nmode = 'self-signed'\n[wireguard]\nlan_peers = false")
            .unwrap();
    let certs = Arc::new(CertStore::new(TlsMode::SelfSigned, PathBuf::new(), None, None).unwrap());
    Arc::new(AppState::new(config, Db::memory().unwrap(), &[2; 32], [3; 32], certs, Backend::None))
}

fn ip(host: u16) -> Ipv4Addr {
    let [hi, lo] = host.to_be_bytes();
    Ipv4Addr::new(10, 77, hi, lo)
}

fn device(state: &AppState, owner: i64, name: &str, host: u16) -> i64 {
    let mut key = [1; 32];
    key[..2].copy_from_slice(&host.to_be_bytes());
    state.db.create_device(owner, name, &codec::encode_key(&key), ip(host), DeviceKind::Manual).unwrap()
}

async fn poll(router: &Router, host: u16, query: &str, expected: StatusCode) -> Kv {
    let req = Request::get(format!("{CONFIG_PATH}?{query}"))
        .extension(ConnectInfo(SocketAddr::from((ip(host), 50505))))
        .body(Body::empty())
        .unwrap();
    let reply = router.clone().oneshot(req).await.unwrap();
    assert_eq!(reply.status(), expected);
    let bytes = to_bytes(reply.into_body(), 256 * 1024).await.unwrap();
    Kv::parse(std::str::from_utf8(&bytes).unwrap()).unwrap()
}

fn rows(reply: &Kv) -> Vec<(&str, &str, &str)> {
    assert_eq!(reply.get("route_peers"), Some("1"));
    reply
        .get_all("route_peer")
        .map(|row| {
            let mut fields = row.splitn(3, ' ');
            let id = fields.next().unwrap();
            assert_eq!(codec::hex_decode(id).unwrap().len(), 16);
            (id, fields.next().unwrap(), fields.next().unwrap_or_default())
        })
        .collect()
}

#[tokio::test]
async fn route_display_follows_directional_acl_and_live_device_state() {
    let state = state();
    let db = &state.db;
    let owner = db.create_user("owner", "unused", "user").unwrap().id;
    let other = db.create_user("other", "unused", "user").unwrap().id;
    let blocked = db.create_user("blocked", "unused", "user").unwrap().id;
    let phone = device(&state, owner, "Phone", 2);
    let nas = device(&state, owner, "Home NAS", 3);
    let port_only = device(&state, other, "SSH host", 4);
    let reverse = device(&state, other, "Reverse only", 5);
    let disabled = device(&state, owner, "Disabled", 6);
    let blocked_peer = device(&state, blocked, "Blocked owner", 7);
    db.update_device(disabled, None, Some(false)).unwrap();
    db.update_user(blocked, None, Some(true)).unwrap();
    let scope = PortSpec::parse_list("tcp:22").unwrap();
    let rule = db.create_acl_rule(Subject::Device(phone), Subject::Device(port_only), &scope, "SSH").unwrap();
    db.create_acl_rule(Subject::Device(reverse), Subject::Device(phone), &[], "Reverse only").unwrap();
    db.create_acl_rule(Subject::Device(phone), Subject::Device(blocked_peer), &[], "Blocked").unwrap();
    state.rebuild().unwrap();
    let router = control_router(state.clone());

    let legacy = poll(&router, 2, "", StatusCode::OK).await;
    let display = poll(&router, 2, "route_peers=1", StatusCode::OK).await;
    let peers = rows(&display);
    assert_eq!(
        peers.iter().map(|&(_, address, name)| (address, name)).collect::<Vec<_>>(),
        [("10.77.0.3", "Home NAS"), ("10.77.0.4", "SSH host"),]
    );
    assert_eq!(legacy.get("route_peers"), None);
    let mut actual = AgentConfig::from_kv(&display).unwrap();
    let expected = AgentConfig::from_kv(&legacy).unwrap();
    assert_ne!(actual.version, expected.version);
    actual.version = expected.version;
    assert_eq!(actual, expected);
    assert_eq!(actual.lan_peers, []);
    let acl = &state.snapshot().acl;
    assert!(acl.allows(ip(2), ip(4), 6, Some(22)));
    assert!(!acl.allows(ip(2), ip(4), 6, Some(80)));
    assert!(!acl.allows(ip(2), ip(5), 6, Some(22)));
    assert_eq!(poll(&router, 6, "route_peers=1", StatusCode::FORBIDDEN).await.get("route_peers"), None);
    assert_eq!(poll(&router, 7, "route_peers=1", StatusCode::FORBIDDEN).await.get("route_peers"), None);

    let version = display.req("version").unwrap();
    poll(&router, 2, &format!("route_peers=1&v={version}"), StatusCode::NOT_MODIFIED).await;
    let query = format!("route_peers=1&v={version}&wait=30");
    let pending = poll(&router, 2, &query, StatusCode::OK);
    tokio::pin!(pending);
    let returned_before_edit = tokio::select! {
        biased;
        _ = &mut pending => true,
        () = tokio::task::yield_now() => false,
    };
    assert!(!returned_before_edit, "unchanged long poll returned before the ACL edit");
    db.delete_acl_rule(rule).unwrap();
    db.update_device(nas, Some("Renamed NAS"), None).unwrap();
    state.rebuild().unwrap();
    let changed = tokio::time::timeout(std::time::Duration::from_secs(1), pending).await.unwrap();
    assert_eq!(rows(&changed), [(peers[0].0, "10.77.0.3", "Renamed NAS")]);

    db.delete_device(nas).unwrap();
    state.rebuild().unwrap();
    let query = format!("route_peers=1&v={}", changed.req("version").unwrap());
    assert_eq!(rows(&poll(&router, 2, &query, StatusCode::OK).await), []);
    poll(&router, 2, &format!("v={}", legacy.req("version").unwrap()), StatusCode::NOT_MODIFIED).await;
}

#[tokio::test]
async fn route_display_is_bounded_and_ordered() {
    let state = state();
    let owner = state.db.create_user("owner", "unused", "user").unwrap().id;
    device(&state, owner, "Phone", 2);
    for host in (3..270).rev() {
        device(&state, owner, &"🖥".repeat(70), host);
    }
    state.rebuild().unwrap();
    let router = control_router(state);
    let reply = poll(&router, 2, "route_peers=1", StatusCode::OK).await;
    let peers = rows(&reply);
    assert_eq!(peers.len(), 256);
    for (host, (_, address, name)) in (3..).zip(peers) {
        assert_eq!(address, ip(host).to_string());
        assert_eq!(name.chars().count(), 64);
    }
}
