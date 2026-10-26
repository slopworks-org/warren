//! The embedded web UI: three static files compiled into the binary.

use crate::state::AppState;
use axum::Router;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use http::HeaderValue;
use http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use std::sync::Arc;

const INDEX: &str = include_str!("../../web/index.html");
const APP_JS: &str = include_str!("../../web/app.js");
const APP_CSS: &str = include_str!("../../web/app.css");
const ICON: &str = include_str!("../../web/icon.svg");

fn asset(body: &'static str, mime: &'static str) -> Response {
    ([(CONTENT_TYPE, mime)], body).into_response()
}

/// `/`, `/app.js`, `/app.css`, `/icon.svg`.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(|| async { asset(INDEX, "text/html; charset=utf-8") }))
        .route("/app.js", get(|| async { asset(APP_JS, "text/javascript; charset=utf-8") }))
        .route("/app.css", get(|| async { asset(APP_CSS, "text/css; charset=utf-8") }))
        .route("/icon.svg", get(|| async { asset(ICON, "image/svg+xml") }))
}

/// Adds hardening headers to every admin-host response.
pub async fn security_headers(mut resp: Response) -> Response {
    let h = resp.headers_mut();
    h.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    h.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    h.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; \
             connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
    );
    resp
}
