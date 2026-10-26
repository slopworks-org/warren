//! Listeners and request routing by host.
//!
//! * HTTPS: the admin host goes to the API/UI router, a resource host to the
//!   access gate and the proxy, anything else gets a 404 (and unknown SNI
//!   names never complete the TLS handshake).
//! * HTTP: ACME challenges, agent registration, redirects to HTTPS.
//! * Control: the agent long-poll, bound to the hub's tunnel address only.

mod gate;
pub mod pages;
mod proxy;

use crate::state::AppState;
use axum::Router;
use axum::body::Body;
use http::header::{HOST, LOCATION};
use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, PoisonError};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

pub use proxy::Upstream;

/// Upper bound on simultaneous client connections per listener; protects
/// memory on small machines.
const MAX_CONNECTIONS: usize = 2048;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HEADER_TIMEOUT: Duration = Duration::from_secs(30);
/// Per-connection read/write buffer cap. hyper's default (~400 KiB) lets
/// each streaming connection read far ahead; 64 KiB keeps 100 parallel
/// downloads within the memory budget without hurting throughput.
pub(crate) const MAX_BUF: usize = 64 * 1024;

/// Address of the client, inserted into every request's extensions.
#[derive(Clone, Copy, Debug)]
pub struct ClientIp(pub IpAddr);

/// The request's host name without port, lower-cased.
pub fn request_host<B>(req: &Request<B>) -> Option<String> {
    let raw = req.headers().get(HOST).and_then(|h| h.to_str().ok()).or_else(|| req.uri().host())?;
    let host = match raw.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or_default(),
        None => {
            raw.rsplit_once(':').map_or(raw, |(h, port)| if port.bytes().all(|b| b.is_ascii_digit()) { h } else { raw })
        }
    };
    Some(host.trim_end_matches('.').to_ascii_lowercase())
}

/// An empty response redirecting to `to`.
#[must_use]
pub fn redirect(to: &str, status: StatusCode) -> Response<Body> {
    let mut r = Response::new(Body::empty());
    *r.status_mut() = status;
    if let Ok(v) = to.parse() {
        r.headers_mut().insert(LOCATION, v);
    }
    r
}

fn http1() -> hyper::server::conn::http1::Builder {
    let mut b = hyper::server::conn::http1::Builder::new();
    b.timer(TokioTimer::new()).header_read_timeout(HEADER_TIMEOUT).keep_alive(true).max_buf_size(MAX_BUF);
    b
}

async fn dispatch_https(
    state: Arc<AppState>,
    upstream: Arc<Upstream>,
    admin: Router,
    sni: Option<String>,
    req: Request<Incoming>,
) -> Response<Body> {
    let Some(host) = request_host(&req) else {
        return pages::not_found();
    };
    if sni.as_deref().is_some_and(|s| s != host) {
        return pages::simple(
            StatusCode::MISDIRECTED_REQUEST,
            "Misdirected request",
            "This connection belongs to another host.",
        );
    }
    if host == state.config.admin_host() {
        return admin.oneshot(req.map(Body::new)).await.unwrap_or_else(|e| match e {});
    }
    match state.snapshot().resources.get(&host).cloned() {
        Some(res) => proxy::handle(&state, &upstream, res, req).await,
        None => pages::not_found(),
    }
}

/// Serves HTTPS until the listener fails.
pub async fn serve_https(state: Arc<AppState>, upstream: Arc<Upstream>, admin: Router, listener: TcpListener) {
    let acceptor = TlsAcceptor::from(Arc::new(crate::tls::server_config(Arc::clone(&state.certs))));
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "accepting HTTPS connection");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            tracing::warn!("connection limit reached; dropping HTTPS connection");
            continue;
        };
        let (state, upstream, admin, acceptor) =
            (Arc::clone(&state), Arc::clone(&upstream), admin.clone(), acceptor.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let tls = match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                Ok(Ok(t)) => t,
                Ok(Err(e)) => {
                    tracing::debug!(peer = %peer, error = %e, "TLS handshake failed");
                    return;
                }
                Err(_) => return,
            };
            let sni = tls.get_ref().1.server_name().map(str::to_ascii_lowercase);
            let svc = service_fn(move |mut req: Request<Incoming>| {
                req.extensions_mut().insert(ClientIp(peer.ip()));
                let fut = dispatch_https(Arc::clone(&state), Arc::clone(&upstream), admin.clone(), sni.clone(), req);
                async move { Ok::<_, Infallible>(fut.await) }
            });
            if let Err(e) = http1().serve_connection(TokioIo::new(tls), svc).with_upgrades().await {
                tracing::debug!(peer = %peer, error = %e, "HTTPS connection ended with error");
            }
        });
    }
}

async fn dispatch_http(state: Arc<AppState>, peer: SocketAddr, req: Request<Incoming>) -> Response<Body> {
    let path = req.uri().path().to_string();
    if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
        let key = state.acme_challenges.read().unwrap_or_else(PoisonError::into_inner).get(token).cloned();
        return match key {
            Some(k) => Response::new(Body::from(k)),
            None => pages::not_found(),
        };
    }
    if path == warren_proto::REGISTER_PATH {
        return crate::agent_api::register(state, peer.ip(), req).await;
    }
    match request_host(&req) {
        Some(host) if state.certs.is_known(&host) => {
            let pq = req.uri().path_and_query().map_or("/", |p| p.as_str());
            redirect(&format!("{}{pq}", state.config.https_origin(&host)), StatusCode::PERMANENT_REDIRECT)
        }
        _ => pages::not_found(),
    }
}

/// Serves plain HTTP until the listener fails.
pub async fn serve_http(state: Arc<AppState>, listener: TcpListener) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let Ok((tcp, peer)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else { continue };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _permit = permit;
            let svc = service_fn(move |req| {
                let fut = dispatch_http(Arc::clone(&state), peer, req);
                async move { Ok::<_, Infallible>(fut.await) }
            });
            if let Err(e) = http1().serve_connection(TokioIo::new(tcp), svc).await {
                tracing::debug!(peer = %peer, error = %e, "HTTP connection ended with error");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(host: &str) -> Request<()> {
        Request::builder().header(HOST, host).body(()).unwrap()
    }

    #[test]
    fn host_parsing() {
        assert_eq!(request_host(&req("App.Example.com:8443")).as_deref(), Some("app.example.com"));
        assert_eq!(request_host(&req("example.com.")).as_deref(), Some("example.com"));
        assert_eq!(request_host(&req("[::1]:80")).as_deref(), Some("::1"));
        assert_eq!(request_host(&Request::new(())), None);
    }
}
