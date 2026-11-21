//! The opted-in agent control response reflects outbound hub reachability.

#![allow(clippy::unwrap_used, reason = "test fixtures and their replies must satisfy the protocol")]

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use http::header::AUTHORIZATION;
use http::{Request, Response, StatusCode};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tower::ServiceExt;
use warren_proto::{AgentConfig, CONFIG_PATH, Kv, codec};
use warren_server::acl::{PortSpec, Subject};
use warren_server::agent_api::control_router;
use warren_server::config::{Config, TlsMode};
use warren_server::db::{Db, DeviceKind};
use warren_server::http::ClientIp;
use warren_server::state::AppState;
use warren_server::tls::CertStore;
use warren_server::update::Release;
use warren_server::util::sha256_hex;
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
    request(router, host, &format!("{CONFIG_PATH}?{query}"), expected, 256 * 1024).await
}

async fn request(router: &Router, host: u16, path: &str, expected: StatusCode, limit: usize) -> Kv {
    let reply = response(router, host, path).await;
    assert_eq!(reply.status(), expected);
    let bytes = to_bytes(reply.into_body(), limit).await.unwrap();
    Kv::parse(std::str::from_utf8(&bytes).unwrap()).unwrap()
}

async fn response(router: &Router, host: u16, path: &str) -> Response<Body> {
    let req =
        Request::get(path).extension(ConnectInfo(SocketAddr::from((ip(host), 50505)))).body(Body::empty()).unwrap();
    router.clone().oneshot(req).await.unwrap()
}

#[tokio::test]
async fn update_requests_are_per_device_and_require_current_local_consent() {
    let state = state();
    let owner = state.db.create_user("owner", "unused", "user").unwrap().id;
    let other = state.db.create_user("other", "unused", "user").unwrap().id;
    for (user, secret) in [(owner, "owner-secret"), (other, "other-secret")] {
        state.db.create_api_token(user, "test", &sha256_hex(secret.as_bytes())).unwrap();
    }
    let add =
        |host: u16| state.db.create_device(owner, "router", &host.to_string(), ip(host), DeviceKind::Agent).unwrap();
    let first = add(2);
    let second = add(3);
    state.rebuild().unwrap();
    *state.latest_release.write().unwrap() =
        Some(Release { version: "9.0.0".into(), tag: "v9.0.0".into(), url: String::new() });
    let admin = warren_server::api::router(state.clone());
    let control = control_router(state.clone());
    let request_update = |device_id, secret| {
        let req = Request::post(format!("/api/v1/devices/{device_id}/update"))
            .header(AUTHORIZATION, format!("Bearer {secret}"))
            .extension(ClientIp(Ipv4Addr::LOCALHOST.into()))
            .body(Body::empty())
            .unwrap();
        admin.clone().oneshot(req)
    };
    let legacy = "agent=0.4.0";
    let off = "agent=0.4.0&remote_updates=0";
    let on = "agent=0.4.0&remote_updates=1";
    for query in [legacy, off] {
        assert!(poll(&control, 2, query, StatusCode::OK).await.get("update").is_none());
        assert_eq!(request_update(first, "owner-secret").await.unwrap().status(), StatusCode::CONFLICT);
    }
    let cfg = poll(&control, 2, on, StatusCode::OK).await;
    poll(&control, 3, on, StatusCode::OK).await;
    assert_eq!(request_update(first, "other-secret").await.unwrap().status(), StatusCode::NOT_FOUND);
    let query = format!("{on}&v={}&wait=30", cfg.req("version").unwrap());
    let waiting = poll(&control, 2, &query, StatusCode::OK);
    tokio::pin!(waiting);
    tokio::select! {
        biased;
        _ = &mut waiting => panic!("unchanged poll returned before the update request"),
        () = tokio::task::yield_now() => {}
    }
    assert_eq!(request_update(first, "owner-secret").await.unwrap().status(), StatusCode::OK);
    let reply = tokio::time::timeout(std::time::Duration::from_secs(1), waiting).await.unwrap();
    assert_eq!(reply.get("update"), Some("9.0.0"));
    assert_eq!(request_update(first, "owner-secret").await.unwrap().status(), StatusCode::OK);
    let audit = state.db.audit_page(Some(owner), None, 50).unwrap();
    assert_eq!(audit.iter().filter(|entry| entry.action == "device.update.request").count(), 1);
    assert!(poll(&control, 3, on, StatusCode::OK).await.get("update").is_none());
    assert!(state.db.device(second).unwrap().unwrap().update_target.is_none());

    // A device that revokes consent drops its queued update on its next poll.
    assert!(poll(&control, 2, off, StatusCode::OK).await.get("update").is_none());
    let device = state.db.device(first).unwrap().unwrap();
    assert_eq!((device.remote_updates, device.update_target), (Some(false), None));
    assert_eq!(request_update(first, "owner-secret").await.unwrap().status(), StatusCode::CONFLICT);
    poll(&control, 2, on, StatusCode::OK).await;
    assert_eq!(request_update(first, "owner-secret").await.unwrap().status(), StatusCode::OK);
    let updated = poll(&control, 2, "agent=9.0.0&remote_updates=1", StatusCode::OK).await;
    assert!(updated.get("update").is_none());
    assert!(state.db.device(first).unwrap().unwrap().update_target.is_none());

    // Re-enabling locally before the next poll must also clear a queued request.
    let epoch = "0123456789abcdef0123456789abcdef";
    let query = |generation| format!("{on}&update_generation={epoch}%3A{generation}");
    poll(&control, 2, &query(1), StatusCode::OK).await;
    assert_eq!(request_update(first, "owner-secret").await.unwrap().status(), StatusCode::OK);
    let first_hint = poll(&control, 2, &query(1), StatusCode::OK).await;
    assert_eq!(first_hint.get("update"), Some("9.0.0"));
    assert_eq!(first_hint.get("update_generation"), Some(format!("{epoch}:1").as_str()));
    let reenabled = poll(&control, 2, &query(3), StatusCode::OK).await;
    assert!(reenabled.get("update").is_none());
    assert!(state.db.device(first).unwrap().unwrap().update_target.is_none());
    assert_eq!(request_update(first, "owner-secret").await.unwrap().status(), StatusCode::OK);
    let fresh = poll(&control, 2, &query(3), StatusCode::OK).await;
    assert_eq!(fresh.get("update"), Some("9.0.0"));
    assert_eq!(fresh.get("update_generation"), Some(format!("{epoch}:3").as_str()));
}

#[tokio::test]
async fn changing_the_channel_clears_queued_targets_and_uses_the_new_catalog() {
    let state = state();
    let owner = state.db.create_user("owner", "unused", "user").unwrap().id;
    state.db.create_api_token(owner, "test", &sha256_hex(b"secret")).unwrap();
    let id = state.db.create_device(owner, "router", "key", ip(2), DeviceKind::Agent).unwrap();
    state.rebuild().unwrap();
    let main = "0.4.0-main.65.g0012345";
    *state.latest_main.write().unwrap() =
        Some(Release { version: main.into(), tag: "main-65-g0012345".into(), url: String::new() });
    *state.latest_release.write().unwrap() =
        Some(Release { version: "0.4.0".into(), tag: "v0.4.0".into(), url: String::new() });
    let admin = warren_server::api::router(state.clone());
    let control = control_router(state.clone());
    let queue = || {
        admin.clone().oneshot(
            Request::post(format!("/api/v1/devices/{id}/update"))
                .header(AUTHORIZATION, "Bearer secret")
                .extension(ClientIp(Ipv4Addr::LOCALHOST.into()))
                .body(Body::empty())
                .unwrap(),
        )
    };
    let report = |version, channel| format!("agent={version}&remote_updates=1&update_channel={channel}");
    let on_main = report("0.4.0", "main");
    poll(&control, 2, &on_main, StatusCode::OK).await;
    let device = state.db.device(id).unwrap().unwrap();
    let view = serde_json::to_value(state.device_view(&state.snapshot(), &device)).unwrap();
    assert_eq!(view["update_channel"], "main");
    assert_eq!(view["agent_outdated"], true);
    assert_eq!(view["agent_latest_version"], main);
    assert_eq!(queue().await.unwrap().status(), StatusCode::OK);
    assert_eq!(poll(&control, 2, &on_main, StatusCode::OK).await.get("update"), Some(main));
    let release = report(main, "release");
    assert!(poll(&control, 2, &release, StatusCode::OK).await.get("update").is_none());
    assert!(state.db.device(id).unwrap().unwrap().update_target.is_none());
    assert_eq!(queue().await.unwrap().status(), StatusCode::OK);
    assert_eq!(poll(&control, 2, &release, StatusCode::OK).await.get("update"), Some("0.4.0"));
    // Both 0.4.0 targets would advance 0.3.0. The channel change alone invalidates the queue.
    assert!(poll(&control, 2, &report("0.3.0", "main"), StatusCode::OK).await.get("update").is_none());
    assert!(state.db.device(id).unwrap().unwrap().update_target.is_none());
}

fn rows(reply: &Kv) -> Vec<(&str, &str, &str)> {
    assert!(matches!(reply.get("route_peers"), Some("1" | "2")));
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
    let small = request(&router, 2, PAGED_CONFIG, StatusCode::OK, PAGE_LIMIT).await;
    assert_eq!(small.get("route_next"), Some("end"));
    assert_eq!(rows(&small), peers);
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
        let name = if host == 3 { "🖥".repeat(70) } else { "x".to_string() };
        device(&state, owner, &name, host);
    }
    state.rebuild().unwrap();
    let router = control_router(state);
    let reply = poll(&router, 2, "route_peers=1", StatusCode::OK).await;
    let peers = rows(&reply);
    assert_eq!(peers.len(), 256);
    for (host, (_, address, name)) in (3..).zip(peers) {
        assert_eq!(address, ip(host).to_string());
        assert_eq!(name.chars().count(), if host == 3 { 64 } else { 1 });
    }
    let first = request(&router, 2, PAGED_CONFIG, StatusCode::OK, PAGE_LIMIT).await;
    assert_eq!(rows(&first).len(), 256);
    let rest = enumerate(&router, &first).await;
    assert_eq!(rest.len(), 1);
    assert_eq!(rows(&rest[0].1).len(), 11);
    assert_eq!(rows(&rest[0].1).last().unwrap().1, ip(269).to_string());
}

const PAGED_CONFIG: &str = "/agent/v1/config?route_peers=1&route_pages=true";
const PAGE_LIMIT: usize = 64 * 1024;

fn continuation(page: &Kv) -> String {
    let revision = page.req("route_revision").unwrap();
    match page.req("route_next").unwrap() {
        "start" => format!("/agent/v1/routes?revision={revision}"),
        cursor => format!("/agent/v1/routes?revision={revision}&after={cursor}"),
    }
}

async fn enumerate(router: &Router, first: &Kv) -> Vec<(String, Kv)> {
    let mut page = first;
    let mut rest = Vec::new();
    while page.get("route_next") != Some("end") {
        assert!(rest.len() < 3);
        let path = continuation(page);
        let next = request(router, 2, &path, StatusCode::OK, PAGE_LIMIT).await;
        assert_eq!(next.get("route_revision"), first.get("route_revision"));
        rest.push((path, next));
        page = &rest.last().unwrap().1;
    }
    rest
}

#[tokio::test]
async fn config_without_room_for_a_row_can_start_on_the_routes_endpoint() {
    const CONFIG_LIMIT: usize = 256 * 1024;
    let state = state();
    let owner = state.db.create_user("owner", "unused", "user").unwrap().id;
    let phone = device(&state, owner, "Phone", 2);
    device(&state, owner, &"🖥".repeat(64), 3);
    state.rebuild().unwrap();
    let router = control_router(state.clone());
    let base = poll(&router, 2, "", StatusCode::OK).await;
    // Simulate a base config whose payload already takes most of the budget.
    let name = "x".repeat(CONFIG_LIMIT - base.encode().len() - 180);
    state.db.update_device(phone, Some(&name), None).unwrap();
    state.rebuild().unwrap();
    let first = request(&router, 2, PAGED_CONFIG, StatusCode::OK, CONFIG_LIMIT).await;
    assert_eq!(first.get("route_next"), Some("start"));
    assert_eq!(rows(&first), []);
    let rest = enumerate(&router, &first).await;
    assert_eq!(rest.len(), 1);
    assert_eq!(rows(&rest[0].1)[0].1, "10.77.0.3");

    let name = "x".repeat(CONFIG_LIMIT - base.encode().len() - 10);
    state.db.update_device(phone, Some(&name), None).unwrap();
    state.rebuild().unwrap();
    let fallback = response(&router, 2, PAGED_CONFIG).await;
    assert_eq!(fallback.status(), StatusCode::OK);
    let header = fallback.headers()["warren-route-page"].to_str().unwrap().to_owned();
    let (version, page) = header.split_once(' ').unwrap();
    assert_eq!(page, format!("{} start", first.req("route_revision").unwrap()));
    let body = to_bytes(fallback.into_body(), CONFIG_LIMIT).await.unwrap();
    let config = Kv::parse(std::str::from_utf8(&body).unwrap()).unwrap();
    assert_eq!(config.req("name").unwrap(), name);
    assert_eq!(config.get("version"), None);
    let poll = format!("{PAGED_CONFIG}&v={version}");
    request(&router, 2, &poll, StatusCode::NOT_MODIFIED, CONFIG_LIMIT).await;
}

#[tokio::test]
async fn paged_route_directory_rechecks_acl_and_covers_the_entire_revision() {
    let state = state();
    let db = &state.db;
    let owner = db.create_user("owner", "unused", "user").unwrap().id;
    let ports = db.create_user("ports", "unused", "user").unwrap().id;
    let denied = db.create_user("denied", "unused", "user").unwrap().id;
    let phone = device(&state, owner, "Phone", 2);
    let stranger = device(&state, denied, "Never visible", 270);
    let scope = PortSpec::parse_list("tcp:22").unwrap();
    let mut port_rules = std::collections::HashMap::new();
    for host in (3..270).rev() {
        let name = format!("peer-{host} {}", "🖥".repeat(64));
        if host % 2 == 0 {
            device(&state, owner, &name, host);
        } else {
            let id = device(&state, ports, &name, host);
            let rule = db.create_acl_rule(Subject::Device(phone), Subject::Device(id), &scope, "").unwrap();
            port_rules.insert(host, (id, rule));
        }
    }
    state.rebuild().unwrap();
    let router = control_router(state.clone());
    let first = request(&router, 2, PAGED_CONFIG, StatusCode::OK, PAGE_LIMIT + 1024).await;
    assert_eq!(first.get("route_peers"), Some("2"));
    assert!(first.encode().len() >= PAGE_LIMIT - 320, "the first page must run out of bytes before rows");
    assert!(rows(&first).len() < 256);
    let first_path = continuation(&first);
    request(&router, 270, &first_path, StatusCode::CONFLICT, PAGE_LIMIT).await;

    db.update_device(stranger, Some("Renamed denied peer"), None).unwrap();
    state.rebuild().unwrap();
    let unchanged = format!("{PAGED_CONFIG}&v={}", first.req("version").unwrap());
    request(&router, 2, &unchanged, StatusCode::NOT_MODIFIED, PAGE_LIMIT).await;
    let rest = enumerate(&router, &first).await;
    let all = std::iter::once(&first).chain(rest.iter().map(|(_, page)| page)).flat_map(rows).collect::<Vec<_>>();
    assert_eq!(all.len(), 267);
    for (host, (_, address, name)) in (3..270).zip(all) {
        assert_eq!(address, ip(host).to_string());
        assert!(name.starts_with(&format!("peer-{host} ")));
        assert_eq!(name.chars().count(), 64);
    }
    assert!(state.snapshot().acl.allows(ip(2), ip(267), 6, Some(22)));
    assert!(!state.snapshot().acl.allows(ip(2), ip(267), 6, Some(80)));

    // Revoke a peer on the tail while the old first page is in flight.
    db.delete_acl_rule(port_rules[&269].1).unwrap();
    state.rebuild().unwrap();
    let conflict = request(&router, 2, &first_path, StatusCode::CONFLICT, PAGE_LIMIT).await;
    assert_eq!(conflict.get_all("route_peer").count(), 0);
    let changed = request(&router, 2, &unchanged, StatusCode::OK, PAGE_LIMIT + 1024).await;
    assert_ne!(changed.get("route_revision"), first.get("route_revision"));
    assert_eq!(rows(&changed), rows(&first));

    // Also remove a peer already read from the first page.
    db.delete_device(port_rules[&3].0).unwrap();
    state.rebuild().unwrap();
    let fresh = request(&router, 2, PAGED_CONFIG, StatusCode::OK, PAGE_LIMIT + 1024).await;
    let fresh_rest = enumerate(&router, &fresh).await;
    let hosts = std::iter::once(&fresh)
        .chain(fresh_rest.iter().map(|(_, page)| page))
        .flat_map(rows)
        .map(|(_, address, _)| address.to_owned())
        .collect::<Vec<_>>();
    assert_eq!(hosts, (4..269).map(|host| ip(host).to_string()).collect::<Vec<_>>());

    let empty = request(&router, 270, PAGED_CONFIG, StatusCode::OK, PAGE_LIMIT).await;
    assert_eq!(empty.get("route_next"), Some("end"));
    assert_eq!(rows(&empty), []);
    db.update_device(phone, None, Some(false)).unwrap();
    state.rebuild().unwrap();
    request(&router, 2, &first_path, StatusCode::FORBIDDEN, PAGE_LIMIT).await;

    // Optional wire transcript for the Android test of the same exchanges.
    if let Some(path) = std::env::var_os("WARREN_ROUTE_TEST_TRANSCRIPT") {
        let mut transcript = String::new();
        let mut record = |path: &str, status: u16, body: &Kv| {
            use std::fmt::Write as _;
            write!(transcript, "{status}\n{path}\n{}\0", body.encode()).unwrap();
        };
        record(PAGED_CONFIG, 200, &first);
        for (path, page) in &rest {
            record(path, 200, page);
        }
        record(&first_path, 409, &conflict);
        record(PAGED_CONFIG, 200, &fresh);
        for (path, page) in &fresh_rest {
            record(path, 200, page);
        }
        record(PAGED_CONFIG, 200, &empty);
        std::fs::write(path, transcript).unwrap();
    }
}
