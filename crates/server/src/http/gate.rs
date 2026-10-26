//! The access gate in front of every resource, and its `/.warren/*` pages.

use super::pages;
use super::redirect;
use crate::access::{self, COOKIE, COOKIE_TTL};
use crate::auth::{rate_key, verify_async};
use crate::db::{AccessMode, Resource, User};
use crate::state::AppState;
use crate::util::{now, safe_next, sha256_hex, url_encode};
use axum::body::Body;
use http::header::{AUTHORIZATION, COOKIE as COOKIE_HEADER, SET_COOKIE, WWW_AUTHENTICATE};
use http::request::Parts;
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use std::net::IpAddr;
use std::sync::{Arc, PoisonError};
use warren_proto::codec::b64_decode;

/// Reserved path prefix on resource hosts.
pub const PREFIX: &str = "/.warren/";

/// What the gate decided for a request.
pub enum Decision {
    /// Forward to the device; `Some` for signed-in Warren users.
    Allow(Option<User>),
    /// Answer directly (redirect, login form, 401, 403).
    Respond(Response<Body>),
}

/// A 303 to `to` that also sets the visitor cookie.
fn signed_in(to: &str, value: &str) -> Response<Body> {
    let mut r = redirect(to, StatusCode::SEE_OTHER);
    if let Ok(v) = HeaderValue::from_str(&cookie_header(value, COOKIE_TTL)) {
        r.headers_mut().insert(SET_COOKIE, v);
    }
    r
}

fn cookie_header(value: &str, max_age: i64) -> String {
    format!("{COOKIE}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}")
}

/// Rate-limit bucket for secret guesses: per client network and resource.
fn guess_key(ip: IpAddr, res: &Resource) -> String {
    format!("{}|{}", rate_key(ip), res.id)
}

fn visitor_cookie(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get_all(COOKIE_HEADER)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|h| access::cookie_value(h, COOKIE))
}

/// Checks a Basic `Authorization` header, caching successes for 10 minutes
/// so Argon2 runs once per visitor rather than once per request.
async fn basic_ok(state: &Arc<AppState>, res: &Resource, header: &str, ip: IpAddr) -> bool {
    let cache_key = sha256_hex(format!("{}|{}|{header}", res.id, res.updated_at).as_bytes());
    let t = now();
    if state.basic_cache.lock().unwrap_or_else(PoisonError::into_inner).get(&cache_key).is_some_and(|exp| *exp > t) {
        return true;
    }
    let Some(creds) = header.strip_prefix("Basic ").and_then(|b| b64_decode(b.trim())) else { return false };
    let Ok(creds) = String::from_utf8(creds) else { return false };
    let Some((user, pass)) = creds.split_once(':') else { return false };
    if user != res.basic_user || !state.limits.resource_secret.check(&guess_key(ip, res)) {
        return false;
    }
    let ok = verify_async(pass.to_string(), Some(res.secret_hash.clone())).await;
    if ok {
        state.basic_cache.lock().unwrap_or_else(PoisonError::into_inner).insert(cache_key, t + 600);
    }
    ok
}

/// Decides whether a request may reach the device.
pub async fn check(state: &Arc<AppState>, res: &Resource, parts: &Parts, ip: IpAddr) -> Decision {
    let t = now();
    let cookie_uid = visitor_cookie(parts).and_then(|v| access::verify(&state.cookie_key, res, v, t));
    let next = parts.uri.path_and_query().map_or("/", |p| p.as_str());
    match res.access {
        AccessMode::Public => Decision::Allow(None),
        AccessMode::Pin if cookie_uid == Some(0) => Decision::Allow(None),
        AccessMode::Pin => Decision::Respond(if parts.method == Method::GET {
            pages::pin_form(&res.host, next, false)
        } else {
            pages::simple(StatusCode::UNAUTHORIZED, "PIN required", "Open this site in a browser to enter its PIN.")
        }),
        AccessMode::Basic => {
            let header = parts.headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok()).unwrap_or_default();
            if basic_ok(state, res, header, ip).await {
                Decision::Allow(None)
            } else {
                let mut r = pages::simple(
                    StatusCode::UNAUTHORIZED,
                    "Sign-in required",
                    "This site needs a user name and password.",
                );
                let realm = format!("Basic realm=\"{}\", charset=\"UTF-8\"", res.host);
                if let Ok(v) = HeaderValue::from_str(&realm) {
                    r.headers_mut().insert(WWW_AUTHENTICATE, v);
                }
                Decision::Respond(r)
            }
        }
        AccessMode::Users => {
            let snap = state.snapshot();
            let user = cookie_uid.filter(|&u| u > 0).and_then(|u| snap.users.get(&u)).filter(|u| !u.disabled);
            match user {
                Some(u) if access::user_allowed(res, u.id, &u.role, snap.perms_of(u)) => {
                    Decision::Allow(Some(u.clone()))
                }
                Some(_) => Decision::Respond(pages::forbidden()),
                None if parts.method == Method::GET || parts.method == Method::HEAD => {
                    let admin = state.config.https_origin(state.config.admin_host());
                    let to = format!("{admin}/auth/resource?rid={}&next={}", res.id, url_encode(next));
                    Decision::Respond(redirect(&to, StatusCode::SEE_OTHER))
                }
                None => Decision::Respond(pages::simple(
                    StatusCode::UNAUTHORIZED,
                    "Sign-in required",
                    "Sign in to Warren first.",
                )),
            }
        }
    }
}

fn query_param(parts: &Parts, name: &str) -> Option<String> {
    form_urlencoded::parse(parts.uri.query()?.as_bytes()).find(|(k, _)| k == name).map(|(_, v)| v.into_owned())
}

fn clean_next(next: Option<String>) -> String {
    next.filter(|n| safe_next(n) && !n.starts_with(PREFIX)).unwrap_or_else(|| "/".to_string())
}

/// Serves `/.warren/callback`, `/.warren/pin` and `/.warren/logout`.
pub async fn special(state: &Arc<AppState>, res: &Resource, req: Request<Incoming>, ip: IpAddr) -> Response<Body> {
    let (parts, body) = req.into_parts();
    match (parts.method.clone(), parts.uri.path()) {
        (Method::GET, "/.warren/callback") => {
            let next = clean_next(query_param(&parts, "next"));
            let user = query_param(&parts, "code").and_then(|c| state.take_auth_code(&c, res.id));
            match user {
                Some(uid) => {
                    let value = access::issue(&state.cookie_key, res, uid, now() + COOKIE_TTL);
                    signed_in(&next, &value)
                }
                None => {
                    pages::simple(StatusCode::BAD_REQUEST, "Sign-in link expired", "Go back and open the site again.")
                }
            }
        }
        (Method::POST, "/.warren/pin") if res.access == AccessMode::Pin => {
            let form = match Limited::new(body, 4096).collect().await {
                Ok(b) => b.to_bytes(),
                Err(_) => return pages::simple(StatusCode::PAYLOAD_TOO_LARGE, "Too large", "The form is too large."),
            };
            let fields: Vec<(String, String)> = form_urlencoded::parse(&form).into_owned().collect();
            let field = |n: &str| fields.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
            let next = clean_next(field("next"));
            if !state.limits.resource_secret.check(&guess_key(ip, res)) {
                return pages::simple(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many attempts",
                    "Wait a minute and try again.",
                );
            }
            let ok = verify_async(field("pin").unwrap_or_default(), Some(res.secret_hash.clone())).await;
            if ok {
                let value = access::issue(&state.cookie_key, res, 0, now() + COOKIE_TTL);
                signed_in(&next, &value)
            } else {
                tracing::info!(host = %res.host, %ip, "wrong resource PIN");
                pages::pin_form(&res.host, &next, true)
            }
        }
        (Method::GET, "/.warren/logout") => {
            let mut r = pages::simple(StatusCode::OK, "Signed out", "You are signed out of this site.");
            if let Ok(v) = HeaderValue::from_str(&cookie_header("", 0)) {
                r.headers_mut().insert(SET_COOKIE, v);
            }
            r
        }
        _ => pages::not_found(),
    }
}
