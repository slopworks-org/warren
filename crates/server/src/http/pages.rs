//! Small self-contained HTML error pages.

use crate::util::html_escape;
use axum::body::Body;
use http::header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE};
use http::{HeaderValue, Response, StatusCode};

const STYLE: &str = "body{font:16px/1.5 system-ui,sans-serif;margin:0;min-height:100vh;display:grid;place-items:center;\
background:#f4f5f7;color:#1d2330}@media(prefers-color-scheme:dark){body{background:#14171c;color:#e6e9ef}\
.card{background:#1e222a!important;border-color:#2c313b!important}}\
.card{background:#fff;border:1px solid #e1e4ea;border-radius:12px;padding:28px 32px;max-width:420px;margin:16px}\
h1{font-size:20px;margin:0 0 8px}p{margin:0 0 12px;opacity:.85}small{opacity:.6}";

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
    simple(StatusCode::NOT_FOUND, "Not found", "Nothing is served at this address.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_escape_input() {
        let r = simple(StatusCode::NOT_FOUND, "<x>", "<script>");
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        assert!(r.headers().get(CONTENT_SECURITY_POLICY).is_some());
    }
}
