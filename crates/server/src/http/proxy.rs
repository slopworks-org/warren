//! Reverse proxy from resource hosts to services on devices.
//!
//! Bodies stream in both directions without buffering. Plain requests share
//! a connection pool per device and port; WebSocket (and other `Upgrade`)
//! requests get a dedicated connection that is spliced to the client after
//! the 101 response.

use super::gate::{self, Decision};
use super::{ClientIp, pages};
use crate::access::{COOKIE, strip_cookie};
use crate::db::{AccessMode, Resource, Scheme, User};
use crate::state::AppState;
use axum::body::Body;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Request, Response, StatusCode, Uri};
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
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

/// A connection to a device: plain TCP or TLS over TCP.
pub enum Stream {
    /// `http` target.
    Plain(TcpStream),
    /// `https` target.
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_flush(cx),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

impl Connection for Stream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

/// Opens connections to `http://ip:port` and `https://ip:port` URIs.
#[derive(Clone)]
pub struct Connector {
    tls: TlsConnector,
}

impl Connector {
    async fn connect(self, uri: Uri) -> io::Result<Stream> {
        let bad = || io::Error::new(io::ErrorKind::InvalidInput, "upstream URI needs an IP host and a port");
        let ip: IpAddr = uri.host().ok_or_else(bad)?.trim_matches(['[', ']']).parse().map_err(|_| bad())?;
        let port = uri.port_u16().ok_or_else(bad)?;
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(SocketAddr::new(ip, port)))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))??;
        tcp.set_nodelay(true)?;
        if uri.scheme_str() == Some("https") {
            let tls = self.tls.connect(ServerName::IpAddress(ip.into()), tcp).await?;
            Ok(Stream::Tls(Box::new(tls)))
        } else {
            Ok(Stream::Plain(tcp))
        }
    }
}

impl tower::Service<Uri> for Connector {
    type Response = TokioIo<Stream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<TokioIo<Stream>>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let this = self.clone();
        Box::pin(async move { this.connect(uri).await.map(TokioIo::new) })
    }
}

/// Pooled HTTP client towards devices.
pub struct Upstream {
    client: Client<Connector, Body>,
    connector: Connector,
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
        let connector = Connector { tls: TlsConnector::from(Arc::new(tls)) };
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(60))
            .pool_max_idle_per_host(8)
            .http1_max_buf_size(super::MAX_BUF)
            .set_host(false)
            .build(connector.clone());
        Upstream { client, connector }
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
        return pages::device_offline(&device.name);
    }

    prepare_headers(&mut parts.headers, upgrade, client, &res.host, &res, user.as_ref());
    let scheme = if res.target_scheme == Scheme::Https { "https" } else { "http" };
    let pq = parts.uri.path_and_query().map_or("/", |p| p.as_str()).to_string();
    let Ok(target) = format!("{scheme}://{}:{}{pq}", device.address, res.target_port).parse::<Uri>() else {
        return pages::simple(StatusCode::BAD_REQUEST, "Bad request", "The request path is not valid.");
    };

    let result = if let Some(client_upgrade) = client_upgrade {
        tokio::time::timeout(RESPONSE_TIMEOUT, forward_upgrade(upstream, target, parts, body, client_upgrade))
            .await
            .unwrap_or(Err(ProxyError::Timeout))
    } else {
        parts.uri = target;
        let fut = upstream.client.request(Request::from_parts(parts, Body::new(body)));
        match tokio::time::timeout(RESPONSE_TIMEOUT, fut).await {
            Ok(Ok(resp)) => Ok(into_body(resp)),
            Ok(Err(e)) => Err(ProxyError::Client(e)),
            Err(_) => Err(ProxyError::Timeout),
        }
    };
    result.unwrap_or_else(|e| {
        tracing::debug!(host = %res.host, error = %e, "upstream request failed");
        pages::service_unreachable(&device.name, res.target_port)
    })
}

/// Why a request could not be forwarded to the device.
#[derive(Debug, thiserror::Error)]
enum ProxyError {
    /// Connecting to the device failed.
    #[error("connecting to the device: {0}")]
    Connect(#[from] io::Error),
    /// The pooled client failed.
    #[error(transparent)]
    Client(#[from] hyper_util::client::legacy::Error),
    /// HTTP failed on a dedicated (upgrade) connection.
    #[error(transparent)]
    Http(#[from] hyper::Error),
    /// The device did not answer in time.
    #[error("timed out waiting for the device")]
    Timeout,
}

/// Forwards an `Upgrade` request on its own connection and, on 101, splices
/// the client and device connections together.
async fn forward_upgrade(
    upstream: &Upstream,
    target: Uri,
    mut parts: http::request::Parts,
    body: Incoming,
    client_upgrade: hyper::upgrade::OnUpgrade,
) -> Result<Response<Body>, ProxyError> {
    let path = target.path_and_query().cloned();
    let stream = upstream.connector.clone().connect(target).await?;
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
    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
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
    use crate::db::Scheme;

    fn res(access: AccessMode) -> Resource {
        Resource {
            id: 1,
            user_id: 1,
            host: "app.example.com".into(),
            device_id: 1,
            target_port: 80,
            target_scheme: Scheme::Http,
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
