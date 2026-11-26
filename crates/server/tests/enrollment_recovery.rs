//! Exercise registration over the same plain HTTP listener used by Android.

#![allow(clippy::unwrap_used, reason = "test fixtures and wire responses must satisfy the protocol")]

use axum::body::{Body, to_bytes};
use http::{Request, StatusCode, header::CACHE_CONTROL};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use warren_proto::register::{RegToken, sign_request, sign_resumable_request, verify_reply};
use warren_proto::{AgentConfig, Kv, REGISTER_PATH, codec};
use warren_server::{
    config::{Config, TlsMode},
    db::{Db, RegTokenRow},
    state::AppState,
    tls::CertStore,
    util::now,
    wg::Backend,
};

const RESUMABLE: &str = "/agent/v1/register-resumable";
const NONCE: &str = "00112233445566778899aabbccddeeff";

async fn request(addr: SocketAddr, path: &str, body: &str) -> (StatusCode, String) {
    let client = Client::builder(TokioExecutor::new()).build_http();
    let request = Request::post(format!("http://{addr}{path}")).body(Body::from(body.to_owned())).unwrap();
    let response = client.request(request).await.unwrap();
    if path == RESUMABLE && response.status() == StatusCode::OK {
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    }
    let status = response.status();
    let bytes = to_bytes(Body::new(response.into_body()), 8192).await.unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

fn signed(token: &RegToken, key: u8, resumable: bool) -> String {
    let mut kv = Kv::new();
    kv.push("token_id", token.id_hex());
    kv.push("pubkey", codec::encode_key(&[key; 32]));
    kv.push("nonce", NONCE);
    kv.push("os", "android");
    if resumable {
        kv.push("resume", "1");
        sign_resumable_request(&token.secret, &mut kv);
    } else {
        sign_request(&token.secret, &mut kv);
    }
    kv.encode()
}

#[tokio::test]
async fn lost_receipt_can_only_be_recovered_for_the_original_enrollment() {
    let config = Config::from_toml("domain = 'warren.test'\n[tls]\nmode = 'self-signed'").unwrap();
    let db = Db::memory().unwrap();
    let user = db.create_user("alice", "unused", "user").unwrap();
    let token = RegToken { id: [1; 6], secret: [2; 18] };
    let legacy = RegToken { id: [3; 6], secret: [4; 18] };
    for token in [&token, &legacy] {
        db.create_reg_token(&RegTokenRow {
            id: token.id_hex(),
            user_id: user.id,
            secret: token.secret.to_vec(),
            name: "Lab phone".into(),
            expires_at: now() + 600,
            used_at: None,
        })
        .unwrap();
    }
    let certs = Arc::new(CertStore::new(TlsMode::SelfSigned, PathBuf::new(), config.admin_host(), None, None).unwrap());
    let state = Arc::new(AppState::new(config, db, &[2; 32], [3; 32], certs, Backend::None));
    state.rebuild().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(warren_server::http::serve_http(Arc::clone(&state), listener));

    let enrollment = signed(&token, 42, true);
    assert_eq!(request(addr, REGISTER_PATH, &enrollment).await.0, StatusCode::FORBIDDEN);
    let mut abandoned = TcpStream::connect(addr).await.unwrap();
    abandoned
        .write_all(
            format!(
                "POST {RESUMABLE} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\n\r\n{enrollment}",
                enrollment.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while state.db.devices().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    drop(abandoned); // The client never reads the committed response.

    let device = state.db.devices().unwrap().pop().unwrap();
    state.db.update_device(device.id, Some("Renamed"), None).unwrap();
    assert_eq!(request(addr, RESUMABLE, &signed(&token, 43, true)).await.0, StatusCode::FORBIDDEN);
    assert_eq!(request(addr, RESUMABLE, enrollment.split("mac=").next().unwrap()).await.0, StatusCode::FORBIDDEN);
    let (status, receipt) = request(addr, RESUMABLE, &enrollment).await;
    assert_eq!(status, StatusCode::OK);
    let reply = Kv::parse(&receipt).unwrap();
    assert!(verify_reply(&token.secret, NONCE, &reply));
    let config = AgentConfig::from_kv(&reply).unwrap();
    assert_eq!(config.name, "Lab phone");
    assert_eq!(i64::try_from(config.device_id).unwrap(), device.id);
    assert_eq!(state.db.devices().unwrap().len(), 1);
    assert_eq!(state.db.reg_token(&token.id_hex()).unwrap().unwrap().secret, Vec::<u8>::new());

    state.db.update_device(device.id, None, Some(false)).unwrap();
    assert_eq!(request(addr, RESUMABLE, &enrollment).await.0, StatusCode::FORBIDDEN);
    state.db.update_device(device.id, None, Some(true)).unwrap();
    assert_eq!(request(addr, RESUMABLE, &enrollment).await, (StatusCode::OK, receipt));
    state.db.delete_device(device.id).unwrap();
    assert_eq!(request(addr, RESUMABLE, &enrollment).await.0, StatusCode::FORBIDDEN);

    let once = signed(&legacy, 44, false);
    assert_eq!(request(addr, REGISTER_PATH, &once).await.0, StatusCode::OK);
    assert_eq!(request(addr, REGISTER_PATH, &once).await.0, StatusCode::FORBIDDEN);
    server.abort();
}
