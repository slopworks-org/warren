//! Small self-contained HTML pages shown on resource hosts.

use crate::util::html_escape;
use axum::body::Body;
use http::header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE};
use http::{HeaderValue, Response, StatusCode};

const STYLE: &str = "body{font:16px/1.5 system-ui,sans-serif;margin:0;min-height:100vh;display:grid;place-items:center;\
background:#f4f5f7;color:#1d2330}@media(prefers-color-scheme:dark){body{background:#14171c;color:#e6e9ef}\
.card{background:#1e222a!important;border-color:#2c313b!important}input{background:#14171c;color:inherit}}\
.card{background:#fff;border:1px solid #e1e4ea;border-radius:12px;padding:28px 32px;max-width:420px;margin:16px}\
h1{font-size:20px;margin:0 0 8px}p{margin:0 0 12px;opacity:.85}small{opacity:.6}\
input{font:inherit;padding:8px 10px;border:1px solid #9aa3b2;border-radius:8px;width:100%;box-sizing:border-box}\
button{font:inherit;margin-top:12px;padding:8px 16px;border:0;border-radius:8px;background:#2f6fed;color:#fff;cursor:pointer}\
.err{color:#d33}";

/// Renders a page with a heading and HTML body.
fn page(status: StatusCode, title: &str, body_html: &str) -> Response<Body> {
    let html = format!(
        "<!doctype html><html><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <title>{t}</title><style>{STYLE}</style></head><body><div class=card><h1>{t}</h1>{body_html}\
         <small>Warren</small></div></body></html>",
        t = html_escape(title)
    );
    let mut r = Response::new(Body::from(html));
    *r.status_mut() = status;
    let h = r.headers_mut();
    h.insert(CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    h.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
        ),
    );
    r
}

/// A page with a heading and one plain-text paragraph.
#[must_use]
pub fn simple(status: StatusCode, title: &str, text: &str) -> Response<Body> {
    page(status, title, &format!("<p>{}</p>", html_escape(text)))
}

/// 404 for unknown hosts and paths.
#[must_use]
pub fn not_found() -> Response<Body> {
    simple(StatusCode::NOT_FOUND, "Not found", "Nothing is published at this address.")
}

/// 503 when the target device is not connected.
#[must_use]
pub fn device_offline(device: &str) -> Response<Body> {
    simple(
        StatusCode::SERVICE_UNAVAILABLE,
        "Device offline",
        &format!("The device “{device}” that serves this site is not connected right now. Try again later."),
    )
}

/// 502 when the device is connected but the service does not answer.
#[must_use]
pub fn service_unreachable(device: &str, port: u16) -> Response<Body> {
    simple(
        StatusCode::BAD_GATEWAY,
        "Service unreachable",
        &format!("The device “{device}” is connected, but nothing answered on port {port}."),
    )
}

/// 403 for signed-in users without access.
#[must_use]
pub fn forbidden() -> Response<Body> {
    simple(StatusCode::FORBIDDEN, "No access", "Your account is not allowed to open this site.")
}

/// The PIN form for PIN-protected resources.
#[must_use]
pub fn pin_form(host: &str, next: &str, error: bool) -> Response<Body> {
    let err = if error { "<p class=err>Wrong PIN.</p>" } else { "" };
    page(
        StatusCode::UNAUTHORIZED,
        "PIN required",
        &format!(
            "<p>{} is protected by a PIN.</p>{err}<form method=post action=\"/.warren/pin\">\
             <input type=hidden name=next value=\"{}\"><input name=pin type=password inputmode=numeric \
             autocomplete=one-time-code autofocus required aria-label=PIN><button>Continue</button></form>",
            html_escape(host),
            html_escape(next)
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_escape_input() {
        let r = pin_form("<x>", "/\"><script>", true);
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert!(r.headers().get(CONTENT_SECURITY_POLICY).is_some());
    }
}
