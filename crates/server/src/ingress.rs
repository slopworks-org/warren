//! Device-authenticated rendezvous for agent-initiated service streams.
use crate::db::Scheme;
use crate::state::AppState;
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::response::{IntoResponse, Response};
use http::{StatusCode, header};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, oneshot};
use warren_proto::Kv;

pub(crate) type Channel = TokioIo<Upgraded>;
type Catalog = BTreeMap<String, Scheme>;
const REPORT_WAIT: Duration = Duration::from_secs(2);
const LEASE: Duration = Duration::from_secs(15);
const OPEN_TIMEOUT: Duration = Duration::from_secs(6);

struct Pending {
    name: String,
    scheme: Scheme,
    offered: bool,
    reply: oneshot::Sender<Channel>,
}

struct Agent {
    seen: Instant,
    catalog: Catalog,
    wake: Arc<Notify>,
    pending: BTreeMap<u64, Pending>,
}

#[derive(Default)]
pub(crate) struct Directory {
    agents: Mutex<HashMap<String, Agent>>,
    sequence: AtomicU64,
}

impl Directory {
    fn agents(&self) -> std::sync::MutexGuard<'_, HashMap<String, Agent>> {
        self.agents.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn catalog(&self, key: &str) -> Catalog {
        self.agents().get(key).filter(|a| a.seen.elapsed() < LEASE).map(|a| a.catalog.clone()).unwrap_or_default()
    }

    pub(crate) async fn open(&self, key: &str, name: &str) -> io::Result<(Channel, Scheme)> {
        let unavailable = || io::Error::other("service unavailable");
        let (send, recv) = oneshot::channel();
        let ticket = self.sequence.fetch_add(1, Ordering::Relaxed);
        let scheme = {
            let mut agents = self.agents();
            let a = agents.get_mut(key).filter(|a| a.seen.elapsed() < LEASE).ok_or_else(unavailable)?;
            let scheme = *a.catalog.get(name).ok_or_else(unavailable)?;
            a.pending.retain(|_, p| !p.reply.is_closed());
            if a.pending.len() >= 64 {
                return Err(unavailable());
            }
            a.pending.insert(ticket, Pending { name: name.into(), scheme, offered: false, reply: send });
            a.wake.notify_one();
            scheme
        };
        let stream =
            tokio::time::timeout(OPEN_TIMEOUT, recv).await.map_err(|_| unavailable())?.map_err(|_| unavailable())?;
        Ok((stream, scheme))
    }

    fn report(&self, key: &str, catalog: Catalog) -> Arc<Notify> {
        let mut agents = self.agents();
        agents.retain(|_, a| a.seen.elapsed() < LEASE);
        let agent = agents.entry(key.into()).or_insert_with(|| Agent {
            seen: Instant::now(),
            catalog: Catalog::new(),
            wake: Arc::default(),
            pending: BTreeMap::new(),
        });
        agent.seen = Instant::now();
        agent.catalog = catalog;
        agent.pending.retain(|_, p| !p.reply.is_closed() && agent.catalog.get(&p.name) == Some(&p.scheme));
        Arc::clone(&agent.wake)
    }

    fn jobs(&self, key: &str) -> String {
        let mut body = Kv::new();
        if let Some(agent) = self.agents().get_mut(key) {
            for (id, pending) in &mut agent.pending {
                if !pending.offered && !pending.reply.is_closed() {
                    pending.offered = true;
                    body.push("open", format!("{id} {} {}", pending.name, pending.scheme.as_str()));
                }
            }
        }
        body.encode()
    }
}

fn identity(state: &AppState, peer: SocketAddr) -> Result<(i64, String), StatusCode> {
    let IpAddr::V4(ip) = peer.ip() else { return Err(StatusCode::FORBIDDEN) };
    let snap = state.snapshot();
    snap.device_by_ip
        .get(&ip)
        .and_then(|id| snap.active_device(*id))
        .filter(|d| d.kind == crate::db::DeviceKind::Agent)
        .map(|d| (d.id, d.public_key.clone()))
        .ok_or(StatusCode::FORBIDDEN)
}

pub(crate) async fn report(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    body: String,
) -> Result<String, StatusCode> {
    let (_, key) = identity(&state, peer)?;
    let mut catalog = Catalog::new();
    let kv = Kv::parse(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    for row in kv.get_all("service") {
        let (name, scheme) = row.split_once(' ').ok_or(StatusCode::BAD_REQUEST)?;
        let scheme = match scheme {
            "http" => Scheme::Http,
            "https" => Scheme::Https,
            _ => return Err(StatusCode::BAD_REQUEST),
        };
        if !warren_proto::service_name(name)
            || catalog.insert(name.to_owned(), scheme).is_some()
            || catalog.len() > warren_proto::MAX_SERVICES
        {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    let wake = state.ingress.report(&key, catalog);
    let mut jobs = state.ingress.jobs(&key);
    if jobs.is_empty() {
        let _ = tokio::time::timeout(REPORT_WAIT, wake.notified()).await;
        jobs = state.ingress.jobs(&key);
    }
    let (id, same_key) = identity(&state, peer)?;
    if same_key != key {
        return Err(StatusCode::FORBIDDEN);
    }
    jobs.push_str(&publications(&state, id));
    Ok(jobs)
}

fn publications(state: &AppState, id: i64) -> String {
    let mut rows = Kv::new();
    for resource in state.snapshot().resources.values().filter(|r| r.device_id == id && !r.service.is_empty()) {
        rows.push("published", format!("{} {}", resource.service, state.config.https_origin(&resource.host)));
    }
    rows.encode()
}

pub(crate) async fn stream(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(ticket): Path<u64>,
    mut req: Request,
) -> Result<Response, StatusCode> {
    let (_, key) = identity(&state, peer)?;
    if req.headers().get(header::UPGRADE).is_none_or(|v| v != "warren-stream") {
        return Err(StatusCode::BAD_REQUEST);
    }
    let pending = state
        .ingress
        .agents()
        .get_mut(&key)
        .and_then(|a| a.pending.remove(&ticket))
        .filter(|p| p.offered && !p.reply.is_closed())
        .ok_or(StatusCode::NOT_FOUND)?;
    let upgrade = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        if let Ok(io) = upgrade.await {
            let _ = pending.reply.send(TokioIo::new(io));
        }
    });
    Ok((StatusCode::SWITCHING_PROTOCOLS, [(header::CONNECTION, "upgrade"), (header::UPGRADE, "warren-stream")])
        .into_response())
}
