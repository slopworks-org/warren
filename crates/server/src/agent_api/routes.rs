use super::{MAX_ROUTE_PEERS, clean_name, error, text};
use crate::db::Device;
use crate::state::{AppState, Snapshot};
use crate::util::hmac;
use axum::body::Body;
use axum::extract::{ConnectInfo, Query, State};
use http::{HeaderValue, Response, StatusCode};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Bound::{Excluded, Included};
use std::sync::{Arc, PoisonError};
use warren_proto::codec;

const PAGE_BYTES: usize = 64 * 1024;
const PAGE_FIELDS_BYTES: usize = "route_peers=2\nroute_revision=\nroute_next=\n".len() + 64 + 15;

pub(super) fn row(device: &Device) -> String {
    // SQLite can reuse a deleted row id. The key fingerprint survives a rename
    // or address change and keeps the WireGuard key out of the directory.
    let id = codec::hex_encode(&Sha256::digest(device.public_key.as_bytes())[..16]);
    let name = clean_name(&device.name).unwrap_or_default();
    let row = format!("route_peer={id} {} {name}", device.address);
    format!("{}\n", row.trim_end())
}

// Both ACL maps are sorted by (source, destination) and the pairs are disjoint.
fn destinations(snap: &Snapshot, source: Ipv4Addr, after: Option<Ipv4Addr>) -> impl Iterator<Item = &Device> {
    let start = after.map_or(Included((source, Ipv4Addr::UNSPECIFIED)), |ip| Excluded((source, ip)));
    let range = (start, Included((source, Ipv4Addr::BROADCAST)));
    let mut all = snap.acl.all.range(range).peekable();
    let mut ports = snap.acl.ports.range(range).map(|(pair, _)| pair).peekable();
    std::iter::from_fn(move || {
        let next = match (all.peek(), ports.peek()) {
            (Some(a), Some(b)) if b < a => ports.next(),
            (Some(_), _) => all.next(),
            (None, _) => ports.next(),
        };
        next.map(|(_, ip)| ip)
    })
    .filter_map(|ip| snap.device_by_ip.get(ip))
    .filter_map(|id| snap.active_device(*id))
}

pub(super) struct Page {
    revision: String,
    next: String,
    rows: String,
}

impl Page {
    pub(super) fn encode(&self) -> String {
        format!("route_peers=2\nroute_revision={}\nroute_next={}\n{}", self.revision, self.next, self.rows)
    }

    pub(super) fn config_header(&self, version: u64) -> Option<HeaderValue> {
        HeaderValue::from_str(&format!("{version} {} {}", self.revision, self.next)).ok()
    }
}

fn revision(state: &AppState, snap: &Snapshot, source: &Device) -> String {
    let cached = snap.route_revisions.lock().unwrap_or_else(PoisonError::into_inner).get(&source.address).cloned();
    if let Some(cached) = cached {
        return cached;
    }
    // Cover the entire visible directory, including edits beyond the current
    // page. Unrelated rebuilds leave the revision unchanged.
    let mut digest = Sha256::new();
    for peer in destinations(snap, source.address, None) {
        digest.update(row(peer).as_bytes());
    }
    let revision = codec::hex_encode(&hmac(
        &state.cookie_key,
        &[b"route-directory-v2", &source.address.octets(), source.public_key.as_bytes(), &digest.finalize()],
    ));
    snap.route_revisions.lock().unwrap_or_else(PoisonError::into_inner).insert(source.address, revision.clone());
    revision
}

pub(super) fn first_page(state: &AppState, snap: &Snapshot, source: &Device, budget: usize) -> Page {
    page(snap, source.address, None, budget, revision(state, snap, source))
}

fn page(snap: &Snapshot, source: Ipv4Addr, after: Option<Ipv4Addr>, budget: usize, revision: String) -> Page {
    let row_budget = budget.min(PAGE_BYTES).saturating_sub(PAGE_FIELDS_BYTES);
    let mut rows = String::new();
    let mut last = None;
    let mut more = false;
    for (count, device) in destinations(snap, source, after).enumerate() {
        let row = row(device);
        if count == MAX_ROUTE_PEERS || rows.len() + row.len() > row_budget {
            more = true;
            break;
        }
        rows.push_str(&row);
        last = Some(device.address);
    }
    let next = if more { last.map_or_else(|| "start".to_string(), |ip| ip.to_string()) } else { "end".to_string() };
    Page { revision, next, rows }
}

#[derive(Deserialize)]
pub(super) struct Cursor {
    revision: String,
    after: Option<Ipv4Addr>,
}

pub(super) async fn continuation(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(cursor): Query<Cursor>,
) -> Response<Body> {
    // Like config, this listener authenticates the caller by its WireGuard
    // source address. Always authorize against the current snapshot.
    let IpAddr::V4(ip) = peer.ip() else { return error(StatusCode::FORBIDDEN, "unknown device") };
    let snap = state.snapshot();
    let Some(source) = snap.device_by_ip.get(&ip).and_then(|id| snap.active_device(*id)) else {
        return error(StatusCode::FORBIDDEN, "unknown device");
    };
    if cursor.revision.len() != 64 || !cursor.revision.bytes().all(|b| b.is_ascii_hexdigit()) {
        return error(StatusCode::BAD_REQUEST, "invalid route revision");
    }
    let revision = revision(&state, &snap, source);
    if revision != cursor.revision {
        return error(StatusCode::CONFLICT, "route directory changed");
    }
    text(StatusCode::OK, page(&snap, ip, cursor.after, PAGE_BYTES, revision).encode())
}
