//! Shared server state and the background tasks that keep it in sync.
//!
//! The database is the source of truth. After every change, [`AppState::rebuild`]
//! loads a fresh in-memory [`Snapshot`] that the proxy and the tunnel read
//! without touching SQLite, then wakes the tasks that push it to the
//! WireGuard backend and to long-polling agents.

use crate::acl::{Acl, Node, Rule};
use crate::auth::RateLimiter;
use crate::config::{Config, Net4};
use crate::db::{AuditEntry, Db, DbError, Device, Resource, Settings, User};
use crate::tls::CertStore;
use crate::util::{fnv64, now};
use crate::wg::{Backend, PeerSpec, PeerStats};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{Notify, watch};
use warren_proto::{AgentConfig, DEFAULT_KEEPALIVE, PeerConfig, codec};

/// A device counts as online if it completed a handshake this recently.
/// Agents send a keepalive every 25 s, and WireGuard re-handshakes on the
/// first packet after a session turns 2 minutes old, so a connected device
/// handshakes at least every ~145 s.
pub const ONLINE_WINDOW: i64 = 210;

/// What the proxy and the tunnel need, read without locking the database.
#[derive(Default)]
pub struct Snapshot {
    /// Users by id.
    pub users: HashMap<i64, User>,
    /// Role permissions by role id.
    pub roles: HashMap<String, Vec<String>>,
    /// Devices by id.
    pub devices: HashMap<i64, Device>,
    /// Device id by tunnel address.
    pub device_by_ip: HashMap<Ipv4Addr, i64>,
    /// Enabled resources by host.
    pub resources: HashMap<String, Arc<Resource>>,
    /// The same resources by id.
    pub resources_by_id: HashMap<i64, Arc<Resource>>,
    /// Enabled devices, for the hub.
    pub peers: Vec<PeerSpec>,
    /// Compiled device-to-device ACL.
    pub acl: Acl,
    /// Admin-editable settings.
    pub settings: Settings,
}

impl Snapshot {
    /// Permissions of a user's role.
    #[must_use]
    pub fn perms_of(&self, user: &User) -> &[String] {
        self.roles.get(&user.role).map_or(&[], Vec::as_slice)
    }
}

/// A short-lived code that carries a sign-in from the admin host to a
/// resource host.
pub struct AuthCode {
    /// Resource the code is for.
    pub resource: i64,
    /// Signed-in user.
    pub user: i64,
    /// Expiry.
    pub expires: i64,
}

/// Rate limiters for abuse-prone endpoints.
pub struct Limits {
    /// Login attempts per client IP.
    pub login_ip: RateLimiter,
    /// Failed logins per user name.
    pub login_user: RateLimiter,
    /// Device registrations and setup attempts per client IP.
    pub register_ip: RateLimiter,
    /// PIN and Basic-auth attempts per client IP and resource.
    pub resource_secret: RateLimiter,
}

/// Why a tunnel address could not be assigned.
#[derive(Debug, Error)]
pub enum AllocError {
    /// Every address of the network is taken.
    #[error("the tunnel network has no free addresses left")]
    Exhausted,
    /// Storing the device failed.
    #[error(transparent)]
    Db(#[from] DbError),
}

/// Everything request handlers and tasks share.
pub struct AppState {
    /// Parsed configuration.
    pub config: Config,
    /// Storage.
    pub db: Db,
    /// Tunnel network.
    pub network: Net4,
    /// Hub public key, base64.
    pub server_public_key: String,
    /// Key for visitor cookies on resource hosts.
    pub cookie_key: [u8; 32],
    /// Certificates.
    pub certs: Arc<CertStore>,
    /// The WireGuard hub.
    pub backend: Backend,
    snapshot: RwLock<Arc<Snapshot>>,
    generation: watch::Sender<u64>,
    stats: RwLock<HashMap<i64, PeerStats>>,
    /// HTTP-01 key authorizations by token.
    pub acme_challenges: RwLock<HashMap<String, String>>,
    /// Wakes the ACME task when hosts change.
    pub acme_wake: Notify,
    /// Pending resource sign-ins.
    pub auth_codes: Mutex<HashMap<String, AuthCode>>,
    /// One-time token for creating the first administrator.
    pub setup_token: Mutex<Option<String>>,
    /// Rate limiters.
    pub limits: Limits,
    /// Recently verified Basic-auth headers (hash → expiry), to skip Argon2.
    pub basic_cache: Mutex<HashMap<String, i64>>,
    /// Last TOTP step used per user, to refuse replays.
    pub totp_used: Mutex<HashMap<i64, u64>>,
    /// The latest release on GitHub, once checked.
    pub latest_release: RwLock<Option<crate::update::Release>>,
    alloc: Mutex<()>,
    agent_reports: Mutex<HashMap<i64, (i64, String)>>,
}

/// Device fields plus live tunnel state, as the API shows them.
#[derive(Serialize)]
pub struct DeviceView {
    /// Stored fields.
    #[serde(flatten)]
    pub device: Device,
    /// Owner's user name.
    pub owner: String,
    /// Handshake within [`ONLINE_WINDOW`].
    pub online: bool,
    /// Unix time of the last handshake.
    pub last_handshake: Option<i64>,
    /// Bytes from the device.
    pub rx_bytes: u64,
    /// Bytes to the device.
    pub tx_bytes: u64,
    /// Public address the device connects from.
    pub endpoint: Option<String>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl AppState {
    /// Assembles the state; call [`AppState::rebuild`] before serving.
    #[must_use]
    pub fn new(
        config: Config,
        db: Db,
        server_key: &[u8; 32],
        cookie_key: [u8; 32],
        certs: Arc<CertStore>,
        backend: Backend,
    ) -> AppState {
        let public = x25519_dalek::x25519(*server_key, x25519_dalek::X25519_BASEPOINT_BYTES);
        let minute = Duration::from_secs(60);
        AppState {
            network: config.network(),
            config,
            db,
            server_public_key: codec::encode_key(&public),
            cookie_key,
            certs,
            backend,
            snapshot: RwLock::new(Arc::new(Snapshot::default())),
            generation: watch::Sender::new(0),
            stats: RwLock::new(HashMap::new()),
            acme_challenges: RwLock::new(HashMap::new()),
            acme_wake: Notify::new(),
            auth_codes: Mutex::new(HashMap::new()),
            setup_token: Mutex::new(None),
            limits: Limits {
                login_ip: RateLimiter::new(20, minute),
                login_user: RateLimiter::new(5, minute),
                register_ip: RateLimiter::new(10, minute),
                resource_secret: RateLimiter::new(10, minute),
            },
            basic_cache: Mutex::new(HashMap::new()),
            totp_used: Mutex::new(HashMap::new()),
            latest_release: RwLock::new(None),
            alloc: Mutex::new(()),
            agent_reports: Mutex::new(HashMap::new()),
        }
    }

    /// The current snapshot.
    pub fn snapshot(&self) -> Arc<Snapshot> {
        Arc::clone(&self.snapshot.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Subscribes to snapshot changes.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.generation.subscribe()
    }

    /// Reloads the snapshot from the database and notifies the tunnel,
    /// long-polling agents and the ACME task.
    ///
    /// # Errors
    /// On database failure.
    pub fn rebuild(&self) -> Result<(), DbError> {
        let users: HashMap<i64, User> = self.db.users()?.into_iter().map(|u| (u.id, u)).collect();
        let roles = self.db.roles()?.into_iter().map(|r| (r.id, r.permissions)).collect();
        let devices: HashMap<i64, Device> = self.db.devices()?.into_iter().map(|d| (d.id, d)).collect();
        let resources: HashMap<String, Arc<Resource>> =
            self.db.resources()?.into_iter().filter(|r| r.enabled).map(|r| (r.host.clone(), Arc::new(r))).collect();

        // Devices of blocked users drop off the hub along with disabled ones.
        let active = |d: &&Device| d.enabled && users.get(&d.user_id).is_some_and(|u| !u.disabled);
        let mut peers: Vec<PeerSpec> = devices
            .values()
            .filter(active)
            .filter_map(|d| Some(PeerSpec { key: codec::decode_key(&d.public_key)?, ip: d.address }))
            .collect();
        // A stable order lets the apply task recognize an unchanged peer set.
        peers.sort_by_key(|p| p.ip);
        let nodes: Vec<Node> =
            devices.values().filter(active).map(|d| Node { device: d.id, user: d.user_id, ip: d.address }).collect();
        let acl_rules: Vec<Rule> =
            self.db.acl_rules()?.into_iter().map(|r| Rule { src: r.src, dst: r.dst, ports: r.ports }).collect();

        let mut hosts: HashSet<String> = resources.keys().cloned().collect();
        hosts.insert(self.config.admin_host().to_string());
        self.certs.set_known(hosts);

        let snap = Snapshot {
            device_by_ip: devices.values().map(|d| (d.address, d.id)).collect(),
            resources_by_id: resources.values().map(|r| (r.id, Arc::clone(r))).collect(),
            users,
            roles,
            devices,
            resources,
            peers,
            acl: Acl::compile(&nodes, &acl_rules),
            settings: self.db.settings()?,
        };
        *self.snapshot.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(snap);
        self.generation.send_modify(|g| *g += 1);
        self.acme_wake.notify_one();
        Ok(())
    }

    /// Picks a free tunnel address and stores a device with it, serialized
    /// so concurrent registrations never pick the same address.
    ///
    /// # Errors
    /// When the network is full or `store` fails.
    pub fn allocate<T>(&self, store: impl FnOnce(Ipv4Addr) -> Result<T, DbError>) -> Result<T, AllocError> {
        let _guard = lock(&self.alloc);
        let used: HashSet<Ipv4Addr> = self.db.devices()?.into_iter().map(|d| d.address).collect();
        let addr = crate::ipam::allocate(self.network, &used).ok_or(AllocError::Exhausted)?;
        Ok(store(addr)?)
    }

    /// The desired tunnel state for one device, as served to its agent.
    #[must_use]
    pub fn agent_config(&self, d: &Device) -> AgentConfig {
        let mut cfg = AgentConfig {
            version: 0,
            device_id: u64::try_from(d.id).unwrap_or_default(),
            name: d.name.clone(),
            address: format!("{}/{}", d.address, self.network.prefix),
            control: format!("{}:{}", self.network.server_ip(), self.config.wireguard.control_port),
            peers: vec![PeerConfig {
                public_key: self.server_public_key.clone(),
                endpoint: self.config.wg_endpoint(),
                allowed_ips: vec![self.network.to_string()],
                keepalive: DEFAULT_KEEPALIVE,
            }],
        };
        cfg.version = fnv64(cfg.to_kv().encode().as_bytes()) >> 1;
        cfg
    }

    /// A plain `wg-quick` configuration for a device without the agent.
    #[must_use]
    pub fn wg_quick_config(&self, d: &Device, private_key: Option<&str>) -> String {
        format!(
            "[Interface]\n# Warren device \"{}\"\nPrivateKey = {}\nAddress = {}/{}\n\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = {}\nPersistentKeepalive = {DEFAULT_KEEPALIVE}\n",
            d.name.replace(['\n', '\r'], " "),
            private_key.unwrap_or("<the device's private key>"),
            d.address,
            self.network.prefix,
            self.server_public_key,
            self.config.wg_endpoint(),
            self.network,
        )
    }

    /// Live tunnel state of a device.
    pub fn peer_stats(&self, device: i64) -> PeerStats {
        self.stats.read().unwrap_or_else(PoisonError::into_inner).get(&device).copied().unwrap_or_default()
    }

    /// Whether a device has a recent handshake.
    pub fn is_online(&self, device: i64) -> bool {
        Self::recent(self.peer_stats(device))
    }

    fn recent(s: PeerStats) -> bool {
        s.last_handshake.is_some_and(|t| now() - t <= ONLINE_WINDOW)
    }

    /// Records what an agent reports about itself when it changed, at most
    /// every 10 minutes per device. Only the database is updated: these
    /// fields do not affect routing, so no snapshot rebuild is needed.
    pub fn record_agent_report(&self, device: i64, hostname: &str, os: &str, version: &str) {
        let fingerprint = format!("{hostname}\n{os}\n{version}");
        let t = now();
        {
            let mut reports = lock(&self.agent_reports);
            match reports.get(&device) {
                Some((last, fp)) if *fp == fingerprint || t - last < 600 => return,
                _ => reports.insert(device, (t, fingerprint)),
            };
        }
        if let Err(e) = self.db.device_report(device, hostname, os, version) {
            tracing::warn!(error = %e, "recording agent details");
        }
    }

    /// API view of a device.
    pub fn device_view(&self, snap: &Snapshot, d: &Device) -> DeviceView {
        let s = self.peer_stats(d.id);
        DeviceView {
            owner: snap.users.get(&d.user_id).map(|u| u.username.clone()).unwrap_or_default(),
            online: d.enabled && Self::recent(s),
            last_handshake: s.last_handshake,
            rx_bytes: s.rx_bytes,
            tx_bytes: s.tx_bytes,
            endpoint: s.endpoint.map(|e| e.to_string()),
            device: d.clone(),
        }
    }

    /// Records an audit event and mirrors it to the log.
    pub fn audit(&self, actor: Option<&User>, ip: &dyn std::fmt::Display, action: &str, target: &str, details: &str) {
        let entry = AuditEntry {
            id: 0,
            ts: now(),
            actor_id: actor.map(|u| u.id),
            actor: actor.map_or_else(|| "system".to_string(), |u| u.username.clone()),
            ip: ip.to_string(),
            action: action.to_string(),
            target: target.to_string(),
            details: details.to_string(),
        };
        tracing::info!(target: "audit", actor = %entry.actor, ip = %entry.ip, action, object = target, details);
        if let Err(e) = self.db.audit(&entry) {
            tracing::error!(error = %e, "writing audit log");
        }
    }

    /// Stores a resource sign-in code; returns the code.
    pub fn new_auth_code(&self, resource: i64, user: i64) -> String {
        let code = crate::util::token();
        let mut codes = lock(&self.auth_codes);
        let t = now();
        codes.retain(|_, c| c.expires > t);
        codes.insert(code.clone(), AuthCode { resource, user, expires: t + 60 });
        code
    }

    /// Redeems a sign-in code for `resource`; returns the user id.
    pub fn take_auth_code(&self, code: &str, resource: i64) -> Option<i64> {
        let c = lock(&self.auth_codes).remove(code)?;
        (c.resource == resource && c.expires > now()).then_some(c.user)
    }
}

/// Pushes snapshot changes to the WireGuard backend, in order, skipping
/// snapshots whose peers and ACL equal what was last applied.
pub async fn apply_task(state: Arc<AppState>) {
    let mut rx = state.subscribe();
    let mut applied: Option<Arc<Snapshot>> = None;
    loop {
        let snap = state.snapshot();
        let unchanged = applied.as_ref().is_some_and(|a| a.peers == snap.peers && a.acl == snap.acl);
        if !unchanged {
            match state.backend.apply(&snap.peers, &snap.acl).await {
                Ok(()) => applied = Some(snap),
                Err(e) => tracing::error!(error = %e, "applying tunnel configuration"),
            }
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Polls tunnel statistics every few seconds and records sightings.
pub async fn stats_task(state: Arc<AppState>) {
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    let mut persisted: HashMap<i64, i64> = HashMap::new();
    loop {
        tick.tick().await;
        let raw = match state.backend.stats() {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "reading tunnel statistics");
                continue;
            }
        };
        let snap = state.snapshot();
        let mut by_device = HashMap::new();
        for d in snap.devices.values() {
            let Some(key) = codec::decode_key(&d.public_key) else { continue };
            let Some(s) = raw.get(&key) else { continue };
            by_device.insert(d.id, *s);
            // Persist sightings at most once a minute per device.
            if let Some(hs) = s.last_handshake
                && persisted.get(&d.id).is_none_or(|p| hs - p >= 60)
            {
                persisted.insert(d.id, hs);
                if let Err(e) = state.db.device_seen(d.id, hs) {
                    tracing::warn!(error = %e, "recording device sighting");
                }
            }
        }
        *state.stats.write().unwrap_or_else(PoisonError::into_inner) = by_device;
    }
}

/// Hourly housekeeping: expired tokens, sessions and caches.
pub async fn prune_task(state: Arc<AppState>) {
    let mut tick = tokio::time::interval(Duration::from_secs(3600));
    loop {
        tick.tick().await;
        if let Err(e) = state.db.prune() {
            tracing::warn!(error = %e, "pruning database");
        }
        let t = now();
        lock(&state.basic_cache).retain(|_, exp| *exp > t);
        lock(&state.auth_codes).retain(|_, c| c.expires > t);
    }
}
