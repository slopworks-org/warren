//! The Android QR uses the same permission checks, token store and wire protocol as the CLI.

#![allow(clippy::unwrap_used, reason = "test fixtures and wire responses must satisfy the protocol")]

use axum::Router;
use axum::body::{Body, to_bytes};
use http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE};
use http::{Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::{Value, json};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower::ServiceExt;
use warren_proto::register::{RegToken, sign_request, verify_reply};
use warren_proto::{AgentConfig, Kv, REGISTER_PATH, codec};
use warren_server::config::{Config, TlsMode};
use warren_server::db::{Db, DeviceKind, RegTokenRow};
use warren_server::http::ClientIp;
use warren_server::state::AppState;
use warren_server::tls::CertStore;
use warren_server::util::{now, sha256_hex};
use warren_server::wg::Backend;

async fn issue(admin: &Router, auth: bool, body: Value) -> Response<Body> {
    let mut req = Request::post("/api/v1/devices/tokens")
        .header(CONTENT_TYPE, "application/json")
        .extension(ClientIp(Ipv4Addr::LOCALHOST.into()));
    if auth {
        req = req.header(AUTHORIZATION, "Bearer test-api-secret");
    }
    admin.clone().oneshot(req.body(Body::from(body.to_string())).unwrap()).await.unwrap()
}

async fn issued(response: Response<Body>) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    serde_json::from_slice(&to_bytes(response.into_body(), 65_536).await.unwrap()).unwrap()
}

fn registration(uri: &str, token: &RegToken, nonce: &str) -> Request<Body> {
    let mut request = Kv::new();
    request.push("token_id", token.id_hex());
    request.push("pubkey", codec::encode_key(&[42; 32]));
    request.push("nonce", nonce);
    request.push("os", "android");
    sign_request(&token.secret, &mut request);
    Request::post(uri).header(CONTENT_TYPE, "text/plain").body(Body::from(request.encode())).unwrap()
}

#[tokio::test]
async fn android_qr_uses_scoped_one_time_agent_tokens() {
    let config = Config::from_toml(
        "domain = 'warren.test'\nadmin_host = 'admin.warren.test'\npublic_https_port = 8443\n[tls]\nmode = 'self-signed'",
    )
    .unwrap();
    let db = Db::memory().unwrap();
    let user = db.create_user("alice", "unused", "user").unwrap();
    let other = db.create_user("bob", "unused", "user").unwrap();
    db.create_api_token(user.id, "test", &sha256_hex(b"test-api-secret")).unwrap();
    let certs = Arc::new(CertStore::new(TlsMode::SelfSigned, PathBuf::new(), None, None).unwrap());
    let state = Arc::new(AppState::new(config, db, &[2; 32], [3; 32], certs, Backend::None));
    state.rebuild().unwrap();
    let admin = warren_server::api::router(Arc::clone(&state));
    let android = json!({ "android_qr": true, "name": "Lab phone", "ttl_minutes": 15 });
    assert_eq!(issue(&admin, false, android.clone()).await.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        issue(&admin, true, json!({ "android_qr": true, "user_id": other.id })).await.status(),
        StatusCode::FORBIDDEN
    );

    let cli = issued(issue(&admin, true, json!({})).await).await;
    let cli_token = cli["token"].as_str().unwrap();
    assert!(RegToken::parse(cli_token).is_some());
    assert_eq!(cli["command"], format!("warren up --server https://admin.warren.test:8443 --token {cli_token}"));
    assert!(cli.get("qr_svg").is_none());

    let before = now();
    let qr = issued(issue(&admin, true, android).await).await;
    let encoded = qr["token"].as_str().unwrap();
    let expected_uri = format!("warren://enroll?v=1&server=https%3A%2F%2Fadmin.warren.test%3A8443&token={encoded}");
    let expected_svg = qrcode::QrCode::new(&expected_uri)
        .unwrap()
        .render::<qrcode::render::svg::Color<'_>>()
        .min_dimensions(240, 240)
        .quiet_zone(true)
        .build();
    assert!(qr["qr_svg"] == expected_svg, "QR must encode the canonical v1 URI");
    let deadline = qr["expires_at"].as_i64().unwrap();
    assert!((before + 900..=now() + 900).contains(&deadline));
    assert!(state.db.audit_page(None, None, 10).unwrap().iter().all(|entry| !entry.details.contains(encoded)));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let uri = format!("http://{}{REGISTER_PATH}", listener.local_addr().unwrap());
    let server = tokio::spawn(warren_server::http::serve_http(Arc::clone(&state), listener));
    let client = Client::builder(TokioExecutor::new()).build_http();
    let token = RegToken::parse(encoded).unwrap();
    let reply = client.request(registration(&uri, &token, "test-nonce")).await.unwrap();
    assert_eq!(reply.status(), StatusCode::OK);
    let bytes = to_bytes(Body::new(reply.into_body()), 8192).await.unwrap();
    let reply = Kv::parse(std::str::from_utf8(&bytes).unwrap()).unwrap();
    assert!(verify_reply(&token.secret, "test-nonce", &reply));
    let config = AgentConfig::from_kv(&reply).unwrap();
    assert_eq!(config.name, "Lab phone");
    let device = state.db.device(i64::try_from(config.device_id).unwrap()).unwrap().unwrap();
    assert_eq!((device.user_id, device.kind, device.os.as_str()), (user.id, DeviceKind::Agent, "android"));
    let duplicate = client.request(registration(&uri, &token, "another-nonce")).await.unwrap();
    assert_eq!(duplicate.status(), StatusCode::FORBIDDEN);

    let expired = RegToken { id: [1; 6], secret: [2; 18] };
    state
        .db
        .create_reg_token(&RegTokenRow {
            id: expired.id_hex(),
            user_id: user.id,
            secret: expired.secret.to_vec(),
            name: String::new(),
            expires_at: now() - 1,
            used_at: None,
        })
        .unwrap();
    let reply = client.request(registration(&uri, &expired, "test-nonce")).await.unwrap();
    assert_eq!(reply.status(), StatusCode::FORBIDDEN);
    assert_eq!(state.db.devices().unwrap().len(), 1);
    server.abort();
}
