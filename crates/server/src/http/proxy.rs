//! Reverse proxy from resource hosts to services on devices.
//!
//! Each upstream stream is opened by the agent and authorized for a single service.

use super::gate::{self, Decision};
use super::{ClientIp, pages};
use crate::access::{COOKIE, strip_cookie};
use crate::db::{AccessMode, Resource, Scheme, User};
use crate::state::AppState;
use axum::body::Body;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Request, Response, StatusCode, Uri};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;

/// Time allowed for the device to start answering.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(300);

/// Headers that describe one hop, never forwarded (RFC 9110 §7.6.1).
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Accepts any certificate but still checks handshake signatures: services
/// on devices typically use self-signed certificates, and the tunnel already
/// authenticates the device.
#[derive(Debug)]
struct AcceptAnyCert(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// TLS settings shared by upstream service connections.
pub struct Upstream {
    tls: TlsConnector,
}

impl Upstream {
    /// Builds the client.
    #[must_use]
    pub fn new() -> Upstream {
        crate::tls::install_crypto_provider();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Upstream { tls: TlsConnector::from(Arc::new(tls)) }
    }
}

impl Default for Upstream {
    fn default() -> Self {
        Self::new()
    }
}

fn is_upgrade(h: &HeaderMap) -> bool {
    h.contains_key(header::UPGRADE)
        && h.get_all(header::CONNECTION)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade")))
}

/// Removes hop-by-hop headers, including any named in `Connection`.
fn strip_hop_by_hop(h: &mut HeaderMap) {
    let named: Vec<HeaderName> = h
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(str::trim).filter_map(|n| n.parse().ok()).collect::<Vec<_>>())
        .collect();
    for n in named {
        h.remove(n);
    }
    for n in HOP_BY_HOP {
        h.remove(n);
    }
}

/// Rewrites client request headers for the device.
fn prepare_headers(h: &mut HeaderMap, upgrade: bool, client: IpAddr, host: &str, res: &Resource, user: Option<&User>) {
    let upgrade_to = h.get(header::UPGRADE).cloned();
    strip_hop_by_hop(h);
    if upgrade && let Some(u) = upgrade_to {
        h.insert(header::UPGRADE, u);
        h.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    }
    let cookies: Vec<String> = h
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|c| strip_cookie(c, COOKIE))
        .collect();
    h.remove(header::COOKIE);
    if !cookies.is_empty()
        && let Ok(v) = HeaderValue::from_str(&cookies.join("; "))
    {
        h.insert(header::COOKIE, v);
    }
    if res.access == AccessMode::Basic {
        h.remove(header::AUTHORIZATION);
    }
    h.remove("x-warren-user");
    if let Some(v) = user.and_then(|u| HeaderValue::from_str(&u.username).ok()) {
        h.insert("x-warren-user", v);
    }
    // Warren is the edge: whatever forwarding headers the client sent are
    // untrusted, so they are replaced rather than appended to.
    h.remove(header::FORWARDED);
    if let Ok(v) = HeaderValue::from_str(&client.to_string()) {
        h.insert("x-forwarded-for", v.clone());
        h.insert("x-real-ip", v);
    }
    h.insert("x-forwarded-proto", HeaderValue::from_static("https"));
    if let Ok(v) = HeaderValue::from_str(host) {
        h.insert("x-forwarded-host", v);
    }
}

fn into_body(resp: Response<Incoming>) -> Response<Body> {
    let (mut parts, body) = resp.into_parts();
    if parts.status != StatusCode::SWITCHING_PROTOCOLS {
        strip_hop_by_hop(&mut parts.headers);
    }
    Response::from_parts(parts, Body::new(body))
}

/// Serves one request for a resource host.
pub async fn handle(
    state: &Arc<AppState>,
    upstream: &Upstream,
    res: Arc<Resource>,
    mut req: Request<Incoming>,
) -> Response<Body> {
    let client = req.extensions().get::<ClientIp>().map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0);
    if req.uri().path().starts_with(gate::PREFIX) {
        return gate::special(state, &res, req, client).await;
    }
    let upgrade = is_upgrade(req.headers());
    let client_upgrade = upgrade.then(|| hyper::upgrade::on(&mut req));
    let (mut parts, body) = req.into_parts();
    let user = match gate::check(state, &res, &parts, client).await {
        Decision::Allow(u) => u,
        Decision::Respond(r) => return r,
    };

    let snap = state.snapshot();
    let Some(device) = snap.devices.get(&res.device_id) else { return pages::not_found() };
    let owner_active = snap.users.get(&device.user_id).is_some_and(|u| !u.disabled);
    if !device.enabled || !owner_active || !state.backend.has_tunnel() || !state.is_online(device.id) {
        return pages::device_offline();
    }

    prepare_headers(&mut parts.headers, upgrade, client, &res.host, &res, user.as_ref());
    let forward = async {
        let (stream, scheme) = state.ingress.open(&device.public_key, &res.service).await?;
        if scheme == Scheme::Https {
            let tls = upstream.tls.connect(ServerName::IpAddress(device.address.into()), stream).await?;
            forward_request(tls, parts, body, client_upgrade).await
        } else {
            forward_request(stream, parts, body, client_upgrade).await
        }
    };
    let result = tokio::time::timeout(RESPONSE_TIMEOUT, forward).await.unwrap_or(Err(ProxyError::Timeout));
    result.unwrap_or_else(|e| {
        tracing::debug!(host = %res.host, device = %device.name, service = %res.service, error = %e, "upstream request failed");
        pages::service_unreachable()
    })
}

/// Why a request could not be forwarded to the device.
#[derive(Debug, thiserror::Error)]
enum ProxyError {
    /// Connecting to the device failed.
    #[error("connecting to the device: {0}")]
    Connect(#[from] io::Error),
    /// HTTP failed on a dedicated (upgrade) connection.
    #[error(transparent)]
    Http(#[from] hyper::Error),
    /// The device did not answer in time.
    #[error("timed out waiting for the device")]
    Timeout,
}

/// Forwards one HTTP request and splices upgraded streams after a 101 response.
async fn forward_request(
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    mut parts: http::request::Parts,
    body: Incoming,
    client_upgrade: Option<hyper::upgrade::OnUpgrade>,
) -> Result<Response<Body>, ProxyError> {
    let path = parts.uri.path_and_query().cloned();
    let (mut sender, conn) =
        hyper::client::conn::http1::Builder::new().max_buf_size(super::MAX_BUF).handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            tracing::debug!(error = %e, "upgrade connection ended");
        }
    });
    // Origin-form request target: just the path and query.
    parts.uri = path.map_or_else(|| Uri::from_static("/"), Uri::from);
    let mut resp = sender.send_request(Request::from_parts(parts, Body::new(body))).await?;
    if resp.status() == StatusCode::SWITCHING_PROTOCOLS
        && let Some(client_upgrade) = client_upgrade
    {
        let device_upgrade = hyper::upgrade::on(&mut resp);
        tokio::spawn(async move {
            match tokio::try_join!(client_upgrade, device_upgrade) {
                Ok((c, d)) => {
                    let _ = tokio::io::copy_bidirectional(&mut TokioIo::new(c), &mut TokioIo::new(d)).await;
                }
                Err(e) => tracing::debug!(error = %e, "upgrade failed"),
            }
        });
    }
    Ok(into_body(resp))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(access: AccessMode) -> Resource {
        Resource {
            id: 1,
            user_id: 1,
            host: "app.example.com".into(),
            device_id: 1,
            service: "web".into(),
            access,
            basic_user: String::new(),
            secret_hash: String::new(),
            enabled: true,
            created_at: 0,
            updated_at: 0,
            grants: vec![],
        }
    }

    #[test]
    fn header_rewriting() {
        let mut h = HeaderMap::new();
        h.insert(header::CONNECTION, HeaderValue::from_static("keep-alive, x-secret"));
        h.insert("x-secret", HeaderValue::from_static("1"));
        h.insert(header::COOKIE, HeaderValue::from_static("a=1; __Host-warren_auth=s"));
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic eDp5"));
        h.insert("x-warren-user", HeaderValue::from_static("spoofed"));
        h.insert("x-forwarded-for", HeaderValue::from_static("1.1.1.1"));
        prepare_headers(&mut h, false, "2.2.2.2".parse().unwrap(), "app.example.com", &res(AccessMode::Basic), None);
        assert!(h.get("x-secret").is_none() && h.get(header::CONNECTION).is_none());
        assert_eq!(h.get(header::COOKIE).unwrap(), "a=1");
        assert!(h.get(header::AUTHORIZATION).is_none(), "basic credentials stay at the gate");
        assert!(h.get("x-warren-user").is_none(), "clients cannot claim an identity");
        assert_eq!(h.get("x-forwarded-for").unwrap(), "2.2.2.2", "client-supplied hops are not trusted");
        assert_eq!(h.get("x-forwarded-proto").unwrap(), "https");
        assert_eq!(h.get("x-forwarded-host").unwrap(), "app.example.com");
    }

    #[test]
    fn websocket_headers_survive() {
        let mut h = HeaderMap::new();
        h.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
        h.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer app-token"));
        assert!(is_upgrade(&h));
        prepare_headers(&mut h, true, "2.2.2.2".parse().unwrap(), "h", &res(AccessMode::Public), None);
        assert_eq!(h.get(header::UPGRADE).unwrap(), "websocket");
        assert_eq!(h.get(header::CONNECTION).unwrap(), "upgrade");
        assert!(h.get(header::AUTHORIZATION).is_some(), "app credentials pass through on public resources");
    }
}
