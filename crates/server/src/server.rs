//! Startup, shutdown and the offline administration commands.

use crate::auth::{hash_secret, password_ok};
use crate::config::{Config, TlsMode};
use crate::db::{Db, DbError};
use crate::http::Upstream;
use crate::secrets::load_or_create_key;
use crate::state::{self, AppState};
use crate::tls::CertStore;
use crate::wg::{Backend, HubSpec, WgError};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, PoisonError};
use thiserror::Error;
use tokio::net::TcpListener;

/// Why the server could not start or a command failed.
#[derive(Debug, Error)]
pub enum ServerError {
    /// A file or socket operation failed.
    #[error("{what}: {source}")]
    Io {
        /// What was being done.
        what: String,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The database could not be opened or queried.
    #[error(transparent)]
    Db(#[from] DbError),
    /// Certificates could not be loaded.
    #[error(transparent)]
    Tls(#[from] crate::tls::TlsError),
    /// The tunnel could not be set up.
    #[error("setting up WireGuard: {0}")]
    Wg(#[from] WgError),
    /// A command was used wrongly.
    #[error("{0}")]
    Usage(String),
    /// Hashing a password failed.
    #[error("hashing password: {0}")]
    Hash(argon2::password_hash::Error),
}

fn io(what: impl Into<String>) -> impl FnOnce(std::io::Error) -> ServerError {
    let what = what.into();
    move |source| ServerError::Io { what, source }
}

fn open_db(config: &Config) -> Result<Db, ServerError> {
    let dir = &config.data_dir;
    std::fs::create_dir_all(dir).map_err(io(format!("creating {}", dir.display())))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(io(format!("restricting {}", dir.display())))?;
    Ok(Db::open(&dir.join("warren.db"))?)
}

async fn bind(addr: std::net::SocketAddr, what: &str) -> Result<TcpListener, ServerError> {
    TcpListener::bind(addr).await.map_err(io(format!("binding {what} listener on {addr}")))
}

/// Resolves on SIGTERM or Ctrl-C.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut term) => {
            tokio::select! {
                _ = ctrl_c => {},
                _ = term.recv() => {},
            }
        }
        Err(_) => {
            let _ = ctrl_c.await;
        }
    }
}

/// Why [`run`] returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    /// SIGTERM or Ctrl-C.
    Signal,
    /// An update is staged; exit with [`crate::update::RESTART_EXIT`].
    Restart,
}

/// Runs the server until SIGTERM, Ctrl-C or a staged update.
///
/// # Errors
/// When storage, keys, certificates, the tunnel or a listener cannot be set up.
pub async fn run(config: Config) -> Result<Stop, ServerError> {
    let db = open_db(&config)?;
    let dir = config.data_dir.clone();
    let server_key = load_or_create_key(&dir.join("wg.key")).map_err(io("loading wg.key"))?;
    let cookie_key = load_or_create_key(&dir.join("cookie.key")).map_err(io("loading cookie.key"))?;
    let certs = Arc::new(CertStore::new(
        config.tls.mode,
        dir.join("certs"),
        config.tls.cert_file.as_deref(),
        config.tls.key_file.as_deref(),
    )?);

    let hub = HubSpec {
        iface: config.wireguard.interface.clone(),
        port: config.wireguard.port,
        network: config.network(),
        private_key: server_key,
        mtu: config.wireguard.mtu,
    };
    let backend = Backend::start(config.wireguard.backend, hub).await?;
    let plain_listener = bind(config.listen_http, "HTTP").await?;
    let tls_listener = bind(config.listen_https, "HTTPS").await?;
    let control_listener = if backend.has_tunnel() {
        let addr = (config.network().server_ip(), config.wireguard.control_port).into();
        Some(bind(addr, "control").await?)
    } else {
        tracing::warn!("no tunnel backend: devices cannot connect (wireguard.backend = \"none\")");
        None
    };

    let state = Arc::new(AppState::new(config, db, &server_key, cookie_key, certs, backend));
    state.rebuild()?;
    if state.config.update.auto && state.snapshot().agent_target != warren_proto::VERSION {
        state.update_agents()?;
    }
    if state.db.user_count()? == 0 {
        let token = crate::util::token();
        let origin = state.config.https_origin(state.config.admin_host());
        tracing::warn!(
            "no users yet; create the first administrator at {origin}/#/setup?token={token} or with `warren-server create-admin`"
        );
        *state.setup_token.lock().unwrap_or_else(PoisonError::into_inner) = Some(token);
    }

    tracing::info!(
        version = warren_proto::VERSION,
        admin = %state.config.https_origin(state.config.admin_host()),
        backend = state.backend.name(),
        wg_endpoint = %state.config.wg_endpoint(),
        "warren server started"
    );
    let upstream = Arc::new(Upstream::new());
    let admin = crate::api::router(Arc::clone(&state));
    let mut tasks = vec![
        tokio::spawn(state::apply_task(Arc::clone(&state))),
        tokio::spawn(state::stats_task(Arc::clone(&state))),
        tokio::spawn(state::prune_task(Arc::clone(&state))),
        tokio::spawn(crate::http::serve_http(Arc::clone(&state), plain_listener)),
        tokio::spawn(crate::http::serve_https(Arc::clone(&state), upstream, admin, tls_listener)),
    ];
    if state.config.tls.mode == TlsMode::Acme {
        tasks.push(tokio::spawn(crate::acme::task(Arc::clone(&state))));
    }
    if state.config.update.check {
        tasks.push(tokio::spawn(crate::update::task(Arc::clone(&state))));
    }
    if let Some(listener) = control_listener {
        let router = crate::agent_api::control_router(Arc::clone(&state));
        tasks.push(tokio::spawn(async move {
            let svc = router.into_make_service_with_connect_info::<std::net::SocketAddr>();
            if let Err(e) = axum::serve(listener, svc).await {
                tracing::error!(error = %e, "control listener failed");
            }
        }));
    }

    let stop = tokio::select! {
        () = shutdown_signal() => Stop::Signal,
        () = state.restart.notified() => Stop::Restart,
    };
    tracing::info!("shutting down");
    for t in &tasks {
        t.abort();
    }
    state.backend.shutdown().await;
    Ok(stop)
}

/// Reads a password from stdin, or generates one when `from_stdin` is false.
fn password_input(from_stdin: bool) -> Result<(String, bool), ServerError> {
    if !from_stdin {
        return Ok((warren_proto::codec::b64url_encode(&crate::util::random::<12>()), true));
    }
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).map_err(io("reading password from stdin"))?;
    let p = line.trim_end_matches(['\r', '\n']).to_string();
    if !password_ok(&p) {
        return Err(ServerError::Usage(format!("passwords need at least {} characters", crate::auth::MIN_PASSWORD)));
    }
    Ok((p, false))
}

fn hash(p: &str) -> Result<String, ServerError> {
    hash_secret(p).map_err(ServerError::Hash)
}

/// `create-admin`: adds an administrator without the web setup link.
/// Prints a generated password unless one is read from stdin.
///
/// # Errors
/// On invalid input or database failure.
pub fn create_admin(config: &Config, username: &str, from_stdin: bool) -> Result<(), ServerError> {
    if !crate::api::valid_username(username) {
        return Err(ServerError::Usage("user names are 1–32 letters, digits, dots, dashes or underscores".into()));
    }
    let db = open_db(config)?;
    let (password, generated) = password_input(from_stdin)?;
    let user = db.create_user(username, &hash(&password)?, "admin").map_err(|e| match e {
        DbError::Conflict => ServerError::Usage(format!("user {username:?} already exists")),
        other => other.into(),
    })?;
    db.audit(&crate::db::AuditEntry {
        id: 0,
        ts: crate::util::now(),
        actor_id: None,
        actor: "cli".into(),
        ip: String::new(),
        action: "user.create".into(),
        target: format!("user:{} {username}", user.id),
        details: "administrator created from the command line".into(),
    })?;
    println!("Created administrator {username:?}.");
    if generated {
        println!("Password: {password}");
    }
    Ok(())
}

/// `reset-password`: sets a new password (and optionally removes 2FA) for
/// a locked-out user. A running server picks it up on its next restart or change.
///
/// # Errors
/// On unknown users or database failure.
pub fn reset_password(config: &Config, username: &str, from_stdin: bool, reset_2fa: bool) -> Result<(), ServerError> {
    let db = open_db(config)?;
    let user = db.user_by_name(username)?.ok_or_else(|| ServerError::Usage(format!("no user {username:?}")))?;
    let (password, generated) = password_input(from_stdin)?;
    db.set_password(user.id, &hash(&password)?)?;
    if reset_2fa {
        db.set_totp(user.id, None, false)?;
    }
    db.update_user(user.id, None, Some(false))?;
    println!("Password of {username:?} reset{}.", if reset_2fa { ", two-factor authentication removed" } else { "" });
    if generated {
        println!("Password: {password}");
    }
    Ok(())
}

/// Default configuration path.
#[must_use]
pub fn default_config_path() -> PathBuf {
    PathBuf::from("/etc/warren/server.toml")
}
