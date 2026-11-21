//! Supervise the daemon and activate a verified replacement only after its tunnel is ready.

use crate::cli::Args;
use crate::error::{Error, Result};
use crate::state;
use crate::update_files::{
    check_root_dir, check_root_file, lock, open_dir, open_lock, protected_dir, protected_file, runtime_dir, try_lock,
};
use crate::{daemon, log, selfupdate, stopping};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};
use warren_proto::Kv;

const WORKER: &str = "WARREN_DAEMON_BINARY";
const TRIAL: &str = "WARREN_DAEMON_TRIAL";
const COOLDOWN: &str = "WARREN_DAEMON_UPDATE_COOLDOWN";
const STARTUP_LOCK: &str = "WARREN_STARTUP_LOCK";
const REGISTRATION_LOCK: &str = "WARREN_REGISTRATION_LOCK";
const ACTIVATION: &str = "WARREN_ACTIVATING_EXECUTABLE";
const TRIAL_GUARD: &str = "WARREN_TRIAL_GUARD";
const READY: u8 = b'R';
const VERIFIED: u8 = b'V';
const COMMITTED: u8 = b'C';
const ACTIVE: u8 = b'A';
const TICK: Duration = Duration::from_millis(200);
const SERVICE_TICK: Duration = Duration::from_secs(1);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const STOP_TIMEOUT: Duration = Duration::from_secs(5);
const RECOVERY_RETRY: Duration = Duration::from_secs(5);
const UPDATE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(PartialEq, Eq, Clone, Copy)]
struct FileId(u64, u64);

impl FileId {
    fn read(path: &Path) -> io::Result<Self> {
        let path = protected_file(path).map_err(io::Error::other)?;
        let meta = fs::symlink_metadata(path)?;
        if !meta.is_file() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "expected a regular file"));
        }
        Ok(Self(meta.dev(), meta.ino()))
    }
}

#[derive(PartialEq, Eq)]
pub struct Binary {
    id: FileId,
    sha256: Option<String>,
}

impl Binary {
    pub fn record(path: &Path, verified: Option<&[u8]>) -> Result<Self> {
        let id = FileId::read(path).map_err(Error::io("identifying the agent binary"))?;
        let sha256 = match verified {
            Some(data) => warren_proto::asset_sha256(data),
            None => Self::digest(path)?,
        };
        Ok(Self { id, sha256: Some(sha256) })
    }

    fn digest(path: &Path) -> Result<String> {
        let path = protected_file(path)?;
        let data = fs::read(path).map_err(Error::io("reading the agent binary for verification"))?;
        Ok(warren_proto::asset_sha256(&data))
    }

    fn matches(&self, path: &Path) -> Result<bool> {
        // OverlayFS device and inode numbers may change across mounts.
        // Use the original identity only for handoffs written without digests.
        if let Some(sha256) = &self.sha256 {
            Ok(Self::digest(path)? == *sha256)
        } else {
            Ok(FileId::read(path).map_err(Error::io("identifying the agent binary"))? == self.id)
        }
    }

    fn store(&self, kv: &mut Kv, prefix: &str) {
        kv.push(&format!("{prefix}_dev"), self.id.0.to_string());
        kv.push(&format!("{prefix}_ino"), self.id.1.to_string());
        if let Some(sha256) = &self.sha256 {
            kv.push(&format!("{prefix}_sha256"), sha256);
        }
    }

    fn load(kv: &Kv, prefix: &str) -> Option<Self> {
        let number = |suffix| kv.get(&format!("{prefix}_{suffix}"))?.parse().ok();
        Some(Self {
            id: FileId(number("dev")?, number("ino")?),
            sha256: kv.get(&format!("{prefix}_sha256")).map(str::to_string),
        })
    }
}

/// The candidate is next to the binary so activation is one atomic rename.
/// Only one registration may run at a time from a protected executable.
#[derive(Clone)]
pub struct Installation {
    pub exe: PathBuf,
    pub candidate: PathBuf,
    pub request: PathBuf,
    pub update_lock: PathBuf,
    trial_lock: PathBuf,
    service_lock: PathBuf,
    worker_lock: PathBuf,
    registration_lock: PathBuf,
    registration_worker_lock: PathBuf,
    registration: String,
    legacy_registration: String,
    legacy_request: PathBuf,
    service_owner: String,
    activation: PathBuf,
    backup: PathBuf,
}

impl Installation {
    pub fn current(config_dir: &Path) -> Result<Self> {
        let exe = std::env::current_exe().map_err(Error::io("finding the agent binary"))?;
        Self::open(&exe, config_dir)
    }

    pub fn open(exe: &Path, config_dir: &Path) -> Result<Self> {
        Self::at(&protected_file(exe)?, &protected_dir(config_dir, false)?, &runtime_dir()?, true)
    }

    fn at(exe: &Path, config_dir: &Path, runtime: &Path, config_protected: bool) -> Result<Self> {
        // realpath uses the stored spelling on case-insensitive macOS volumes.
        #[cfg(target_os = "macos")]
        let exe = fs::canonicalize(exe).map_err(Error::io("resolving the installed agent"))?;
        #[cfg(target_os = "linux")]
        let exe = exe.to_path_buf();
        #[cfg(target_os = "macos")]
        let canonical = fs::canonicalize(config_dir).map_err(config_error)?;
        #[cfg(target_os = "macos")]
        let config_dir = canonical.as_path();
        let meta = fs::metadata(config_dir).map_err(config_error)?;
        let config_id = format!("{}-{}", meta.dev(), meta.ino());
        let failed = || Error::io("identifying the agent installation");
        let (Some(directory), Some(basename)) = (exe.parent(), exe.file_name()) else {
            return Err(failed()(io::Error::other("missing executable directory or name")));
        };
        let meta = fs::metadata(directory).map_err(failed())?;
        let name = warren_proto::asset_sha256(basename.as_encoded_bytes());
        let exe_id = format!("{}-{}-{name}", meta.dev(), meta.ino());
        let legacy_registration = warren_proto::asset_sha256(config_dir.as_os_str().as_encoded_bytes());
        let registration = if config_protected {
            registered_identity(config_dir)?.unwrap_or_else(|| legacy_registration.clone())
        } else {
            legacy_registration.clone()
        };
        // The key survives reboots. The directory identity also distinguishes
        // separate copies of one registration while a service is running.
        let service_owner = warren_proto::asset_sha256(format!("{registration}:{config_id}").as_bytes());
        Ok(Self {
            candidate: adjacent(&exe, &format!(".{registration}.update-candidate")),
            request: adjacent(&exe, &format!(".{registration}.update-request")),
            legacy_request: adjacent(&exe, &format!(".{legacy_registration}.update-request")),
            activation: adjacent(&exe, ".update-activation"),
            backup: adjacent(&exe, ".update-backup"),
            update_lock: runtime.join(format!("{exe_id}.update")),
            trial_lock: runtime.join(format!("{exe_id}.trial")),
            service_lock: runtime.join(format!("{exe_id}.service")),
            worker_lock: runtime.join(format!("{exe_id}.worker")),
            registration_lock: runtime.join(format!("{config_id}.registration")),
            registration_worker_lock: runtime.join(format!("{config_id}.registration-worker")),
            registration,
            legacy_registration,
            service_owner,
            exe,
        })
    }

    fn handoff_for(&self, registration: &str) -> Self {
        let mut install = self.clone();
        install.candidate = adjacent(&self.exe, &format!(".{registration}.update-candidate"));
        install.request = adjacent(&self.exe, &format!(".{registration}.update-request"));
        registration.clone_into(&mut install.registration);
        install
    }

    pub fn pending_handoff(&self) -> Option<Self> {
        if self.request.exists() {
            return Some(self.clone());
        }
        if self.registration != self.legacy_registration && self.legacy_request.exists() {
            return Some(self.handoff_for(&self.legacy_registration));
        }
        None
    }

    pub fn require_registration(&self, config_dir: &Path) -> Result<()> {
        let identity = registered_identity(&protected_dir(config_dir, false)?)?;
        if identity.as_deref() == Some(&self.registration) { Ok(()) } else { Err(Error::NotRegistered) }
    }

    /// The update lock serializes a service's claim with publishing a request.
    pub fn service_state(&self) -> Result<bool> {
        if try_lock(&self.service_lock)?.is_some() {
            return Ok(false);
        }
        let mut owner = String::new();
        open_lock(&self.service_lock)?
            .take(65)
            .read_to_string(&mut owner)
            .map_err(Error::io("reading the service owner"))?;
        if owner == self.service_owner {
            return Ok(true);
        }
        Err(Error::io("installing the update")(io::Error::other(
            "this executable is in use by another Warren registration",
        )))
    }

    fn claim(&self, supervised: bool) -> Result<File> {
        let mut guard = try_lock(&self.service_lock)?.ok_or_else(|| {
            Error::io("starting the Warren service")(io::Error::other(
                "another Warren service is using this executable",
            ))
        })?;
        guard.set_len(0).map_err(Error::io("clearing the service owner"))?;
        if supervised {
            guard.write_all(self.service_owner.as_bytes()).map_err(Error::io("recording the service owner"))?;
        }
        Ok(guard)
    }

    fn claim_startup(&self, supervised: bool, registration: Option<File>) -> Result<Claims> {
        let service = self.claim(supervised)?;
        let registration = match registration {
            Some(lock) => lock,
            None => try_lock(&self.registration_lock)?
                .ok_or_else(|| Error::io("starting the Warren service")(io::Error::other("agent already running")))?,
        };
        Ok(Claims { _service: service, registration })
    }

    pub fn replacement_pending(&self) -> Result<bool> {
        self.activation.try_exists().map_err(Error::io("checking the replacement in progress"))
    }

    pub fn clear_request(&self) -> Result<()> {
        for path in [&self.candidate, &self.request] {
            match fs::remove_file(path) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => {
                    return Err(Error::io(format!("removing {}", path.display()))(e));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

fn adjacent(exe: &Path, suffix: &str) -> PathBuf {
    let mut path = exe.as_os_str().to_os_string();
    path.push(suffix);
    PathBuf::from(path)
}

fn registered_identity(config_dir: &Path) -> Result<Option<String>> {
    use std::os::unix::fs::OpenOptionsExt;

    let failed = |e| Error::io("identifying the registration key")(e);
    let dir = open_dir(config_dir).map_err(failed)?;
    check_root_dir(&dir).map_err(failed)?;
    let key = config_dir.join("private.key");
    match fs::symlink_metadata(&key) {
        Err(e)
            if e.kind() == io::ErrorKind::NotFound
                && !config_dir.join("agent.conf").try_exists().map_err(failed)? =>
        {
            // An empty registration directory can be prepared before enrollment.
            return Ok(None);
        }
        result => result.map_err(failed)?,
    };
    let key = protected_file(&key)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(key)
        .map_err(failed)?;
    check_root_file(&file).map_err(failed)?;
    let key = state::parse_key(&file).map_err(failed)?;
    Ok(Some(warren_proto::asset_sha256(&key)))
}

fn config_error(error: io::Error) -> Error {
    if error.kind() == io::ErrorKind::NotFound {
        Error::NotRegistered
    } else {
        Error::io("identifying the registration directory")(error)
    }
}

struct Claims {
    _service: File,
    registration: File,
}

pub struct Request {
    pub installed: Binary,
    pub candidate: Binary,
    pub version: String,
    remote: bool,
    consent: Option<String>,
    confirmed: bool,
    registration: Option<String>,
}

impl Request {
    pub fn new(installed: Binary, candidate: Binary, version: &str, consent: Option<String>) -> Self {
        Self {
            installed,
            candidate,
            version: version.into(),
            remote: consent.is_some(),
            consent,
            confirmed: false,
            registration: None,
        }
    }

    pub fn stage(&self, install: &Installation) -> Result<()> {
        self.store(&install.request, &install.registration)
    }

    fn handoff(&self, install: &Installation) -> Installation {
        install.handoff_for(self.registration.as_deref().unwrap_or(&install.legacy_registration))
    }

    fn store(&self, path: &Path, registration: &str) -> Result<()> {
        let mut kv = Kv::new();
        self.installed.store(&mut kv, "installed");
        self.candidate.store(&mut kv, "candidate");
        kv.push("version", &self.version);
        kv.push("remote", if self.remote { "on" } else { "off" });
        if let Some(consent) = &self.consent {
            kv.push("consent", consent);
        }
        kv.push("registration", registration);
        if self.confirmed {
            kv.push("confirmed", "on");
        }
        state::write_private(path, kv.encode().as_bytes())
    }

    fn load(path: &Path) -> Option<Self> {
        let path = protected_file(path).ok()?;
        let kv = Kv::parse(&fs::read_to_string(path).ok()?).ok()?;
        let registration = kv.get("registration");
        if registration.is_some_and(|tag| tag.len() != 64 || !tag.bytes().all(|byte| byte.is_ascii_hexdigit())) {
            return None;
        }
        Some(Self {
            installed: Binary::load(&kv, "installed")?,
            candidate: Binary::load(&kv, "candidate")?,
            version: kv.get("version")?.to_string(),
            remote: match kv.get("remote")? {
                "on" => true,
                "off" => false,
                _ => return None,
            },
            consent: kv.get("consent").map(str::to_owned),
            confirmed: kv.get("confirmed") == Some("on"),
            registration: registration.map(str::to_string),
        })
    }

    fn validate(&self, install: &Installation) -> Result<()> {
        let failed = Error::io("validating the update handoff");
        if !self.installed.matches(&install.exe)? || !self.candidate.matches(&install.candidate)? {
            return Err(failed(io::Error::other("the installed or staged agent changed")));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum ChildRole {
    Worker,
    Supervisor,
    TrialGuard,
}

struct ServiceChild {
    child: Child,
    channel: UnixStream,
    role: ChildRole,
}

impl ServiceChild {
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    fn stop(mut self) -> io::Result<()> {
        // Closing the lifeline also releases any trial waiting for commit.
        let _ = self.channel.shutdown(std::net::Shutdown::Both);
        if self.try_wait()?.is_some() {
            return Ok(());
        }
        // A supervisor needs enough time to shut down and reap its own worker.
        let grace = match self.role {
            ChildRole::Worker => STOP_TIMEOUT,
            ChildRole::Supervisor => STOP_TIMEOUT + SERVICE_TICK,
            ChildRole::TrialGuard => STOP_TIMEOUT + SERVICE_TICK * 2,
        };
        let deadline = Instant::now() + grace;
        let pid = libc::pid_t::try_from(self.child.id()).map_err(io::Error::other)?;
        // SAFETY: this child still has its PID reserved until it is reaped.
        unsafe { libc::kill(pid, libc::SIGTERM) };
        while self.try_wait()?.is_none() {
            if Instant::now() >= deadline {
                if matches!(self.role, ChildRole::TrialGuard) {
                    // SAFETY: the unreaped guard is the leader of its private process group.
                    if unsafe { libc::kill(-pid, libc::SIGKILL) } != 0 {
                        return Err(io::Error::last_os_error());
                    }
                } else {
                    self.child.kill()?;
                }
                self.child.wait()?;
                break;
            }
            std::thread::sleep(TICK);
        }
        Ok(())
    }
}

fn spawn_child(mut command: Command, role: ChildRole, acknowledge: bool) -> Result<ServiceChild> {
    let (channel, child) = UnixStream::pair().map_err(Error::io("opening the daemon supervision channel"))?;
    channel.set_nonblocking(true).map_err(Error::io("configuring the daemon supervision channel"))?;
    let lifeline = child.try_clone().map_err(Error::io("opening the daemon lifeline"))?;
    command.stdin(Stdio::from(OwnedFd::from(lifeline)));
    if acknowledge {
        command.stdout(Stdio::from(OwnedFd::from(child)));
    }
    if matches!(role, ChildRole::TrialGuard) {
        command.process_group(0);
    }
    let child = command.spawn().map_err(Error::io("starting the Warren service process"))?;
    Ok(ServiceChild { child, channel, role })
}

fn watch_supervisor() -> Result<()> {
    std::thread::Builder::new()
        .name("supervisor".into())
        .spawn(|| {
            let _ = io::stdin().read(&mut [0]);
            crate::request_stop();
        })
        .map(drop)
        .map_err(Error::io("watching the Warren supervisor"))
}

fn await_child(worker: &mut ServiceChild, expected: u8, phase: &str) -> Result<()> {
    let failed = Error::io(format!("waiting for the updated daemon to {phase}"));
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    while !stopping() && Instant::now() < deadline {
        if let Some(status) = worker.try_wait().map_err(Error::io("checking the updated daemon"))? {
            return Err(failed(io::Error::other(format!("the candidate exited before it could {phase} ({status})"))));
        }
        let mut byte = [0];
        match worker.channel.read(&mut byte) {
            Ok(1) if byte[0] == expected => return Ok(()),
            Ok(0) => std::thread::sleep(TICK),
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {
                std::thread::sleep(TICK);
            }
            _ => return Err(failed(io::Error::other(format!("the candidate did not {phase}")))),
        }
    }
    Err(failed(io::Error::new(io::ErrorKind::TimedOut, format!("the candidate did not {phase}"))))
}

fn activate(install: &Installation, mut request: Request, worker: &mut Option<ServiceChild>) -> Result<()> {
    request.validate(install)?;
    // The marker must be durable before even the candidate's version command runs.
    if request.registration.as_deref() != Some(&install.registration) {
        request.stage(install)?;
    }
    fs::rename(&install.request, &install.activation).map_err(Error::io("recording the trial in progress"))?;
    sync_executable_dir(install)?;

    let mut command = run_command(&install.exe);
    command.env(TRIAL_GUARD, &install.exe);
    let mut guard = spawn_child(command, ChildRole::TrialGuard, true)?;
    let result = (|| {
        await_child(&mut guard, READY, "start the trial guard")?;
        send_commit(&mut guard)?;
        await_child(&mut guard, VERIFIED, "report the staged version")?;
        if let Some(previous) = worker.take() {
            previous.stop().map_err(Error::io("stopping the previous service process"))?;
        }
        send_commit(&mut guard)?;
        await_child(&mut guard, ACTIVE, "confirm supervisor activation")?;
        request.validate(install)?;
        request.confirmed = true;
        request.store(&install.activation, &install.registration)?;
        fs::rename(&install.candidate, &install.exe).map_err(Error::io("installing the ready agent"))?;
        if let Err(e) = sync_executable_dir(install) {
            log!(Warn, "cannot finish recording the confirmed agent update", error = e);
        }
        Ok(())
    })();
    let stop = guard.stop().map_err(Error::io("stopping the trial service"));
    if result.is_ok() {
        if let Err(e) = stop {
            log!(Warn, "cannot finish stopping the trial service", error = e);
        }
        log!(Info, "agent update activated", version = request.version);
    } else {
        stop?;
    }
    result
}

fn send_commit(worker: &mut ServiceChild) -> Result<()> {
    worker.channel.write_all(&[COMMITTED]).map_err(Error::io("confirming the daemon commit"))
}

fn receive_commit() -> Result<()> {
    let failed = || Error::io("waiting for the supervisor to commit the update");
    let mut byte = [0];
    io::stdin().read_exact(&mut byte).map_err(failed())?;
    if byte[0] == COMMITTED { Ok(()) } else { Err(failed()(io::Error::other("invalid response"))) }
}

fn send_ack(byte: u8) -> Result<()> {
    let mut out = io::stdout().lock();
    out.write_all(&[byte]).and_then(|()| out.flush()).map_err(Error::io("acknowledging the update"))
}

fn run_trial_guard(args: &Args, exe: &Path) -> Result<()> {
    // SAFETY: these calls have no preconditions.
    let (group, pid) = unsafe { (libc::getpgrp(), libc::getpid()) };
    if group != pid {
        return Err(Error::io("starting the trial guard")(io::Error::other("expected a private process group")));
    }
    let install = Installation::open(exe, &args.paths.config_dir)?;
    let _cleanup = lock(&install.trial_lock)?;
    let result = (|| {
        send_ack(READY)?;
        // Recovery can win the lock if the coordinator died before we got it.
        // The coordinator cannot authorize candidate execution until we own it.
        receive_commit()?;
        let request = read_request(&install.activation)?;
        let install = request.handoff(&install);
        request.validate(&install)?;
        selfupdate::check_version(&install.candidate, &request.version)?;
        send_ack(VERIFIED)?;
        receive_commit()?;

        watch_supervisor()?;

        let mut command = run_command(&install.candidate);
        command.env(ACTIVATION, &install.exe);
        let mut candidate = spawn_child(command, ChildRole::Supervisor, true)?;
        let result = (|| {
            await_child(&mut candidate, ACTIVE, "confirm supervisor activation")?;
            send_ack(ACTIVE)?;
            while !stopping() {
                check_running(&mut candidate)?;
                std::thread::sleep(TICK);
            }
            Ok(())
        })();
        candidate.stop().map_err(Error::io("stopping the candidate supervisor"))?;
        result
    })();
    if let Err(e) = &result {
        log!(Warn, "agent trial ended", error = e);
    }
    // Keep the cleanup lock and the process-group ID reserved until all
    // remaining processes have been signaled, including descendants that
    // ignored the lifeline or outlived the candidate executable.
    // SAFETY: this process is still the leader of this private group.
    unsafe { libc::kill(-group, libc::SIGKILL) };
    result
}

fn sync_executable_dir(install: &Installation) -> Result<()> {
    if let Some(dir) = install.exe.parent() {
        File::open(dir)
            .and_then(|dir| dir.sync_all())
            .map_err(Error::io("syncing the agent installation directory"))?;
    }
    Ok(())
}

#[derive(Default)]
struct Recovery {
    restored: bool,
    interrupted: Option<String>,
}

/// Requires the update lock. Backups are only used by the old protocol.
fn recover(install: &Installation) -> Result<Recovery> {
    let failed = || Error::io("recovering the previous agent");
    let mut recovery = Recovery::default();
    let backup = install.backup.try_exists().map_err(failed())?;
    if install.replacement_pending()? {
        let request = read_request(&install.activation)?;
        let handoff = request.handoff(install);
        let installed = request.installed.matches(&install.exe)?;
        // For equal digests, the candidate's old name distinguishes a
        // completed rename from a failure just before the rename.
        let committed = request.confirmed
            && (!installed || !handoff.candidate.try_exists().map_err(failed())?)
            && request.candidate.matches(&install.exe)?;
        if backup && !installed {
            if !request.installed.matches(&install.backup)? || !request.candidate.matches(&install.exe)? {
                return Err(failed()(io::Error::other("the installed agent or backup changed")));
            }
            fs::rename(&install.backup, &install.exe).map_err(failed())?;
            sync_executable_dir(install)?;
            recovery.restored = true;
        } else if !(installed || committed) {
            return Err(failed()(io::Error::other("the previous agent backup is missing")));
        }
        if (installed && !committed) || recovery.restored {
            let cleared = discard_abandoned_candidate(&handoff, &request.candidate)?;
            recovery.interrupted = Some(request.version);
            if !cleared {
                return Ok(recovery);
            }
        }
        clear_activation(install)?;
    }
    if backup {
        match fs::remove_file(&install.backup) {
            Ok(()) => sync_executable_dir(install)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound || cleanup_denied(&e) => {}
            Err(e) => return Err(failed()(e)),
        }
    }
    Ok(recovery)
}

// Keep the activation marker if verified candidate cleanup needs to be retried.
fn discard_abandoned_candidate(install: &Installation, candidate: &Binary) -> Result<bool> {
    let failed = Error::io("removing the abandoned agent candidate");
    let metadata = match fs::symlink_metadata(&install.candidate) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(true),
        Err(e) if cleanup_denied(&e) => return Ok(false),
        Err(e) => return Err(failed(e)),
    };
    if !metadata.is_file() || install.request.exists() {
        return Ok(true);
    }
    match candidate.matches(&install.candidate) {
        Ok(true) => {}
        Ok(false) => return Ok(true),
        Err(e) => {
            log!(Warn, "cannot verify the abandoned agent candidate; will retry cleanup", error = e);
            return Ok(false);
        }
    }
    match fs::remove_file(&install.candidate) {
        Ok(()) => sync_executable_dir(install).map(|()| true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(e) if cleanup_denied(&e) => Ok(false),
        Err(e) => Err(failed(e)),
    }
}

fn cleanup_denied(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::EROFS | libc::EACCES))
}

fn clear_activation(install: &Installation) -> Result<()> {
    match fs::remove_file(&install.activation) {
        Ok(()) => sync_executable_dir(install),
        // The verified installed image can run while cleanup is deferred.
        Err(e) if cleanup_denied(&e) => Ok(()),
        Err(e) => Err(Error::io("clearing the activation marker")(e)),
    }
}

fn wait_for_trial_cleanup(install: &Installation) -> Result<()> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if try_lock(&install.trial_lock)?.is_some() {
            return Ok(());
        }
        if stopping() || Instant::now() >= deadline {
            return Err(Error::io("waiting for the interrupted trial to exit")(io::ErrorKind::TimedOut.into()));
        }
        std::thread::sleep(TICK);
    }
}

fn handle_request(
    args: &Args,
    install: &Installation,
    registration: &File,
    worker: &mut Option<ServiceChild>,
    deferred: &mut Option<FileId>,
) -> Result<Option<String>> {
    let Some(handoff) = install.pending_handoff() else {
        *deferred = None;
        return Ok(None);
    };
    let Some(update) = try_lock(&install.update_lock)? else { return Ok(None) };
    let install = handoff;
    if !install.request.exists() || install.replacement_pending()? {
        return Ok(None);
    }
    let meta = fs::symlink_metadata(&install.request).map_err(Error::io("identifying the update request"))?;
    let id = FileId(meta.dev(), meta.ino());
    if *deferred == Some(id) {
        clear_skipped_request(&install, deferred, id)?;
        return Ok(None);
    }
    let request = read_request(&install.request);
    let cooldown = request.as_ref().map_or_else(|_| String::new(), |request| request.version.clone());
    let result = request.and_then(|request| {
        let policy = request.remote.then(|| selfupdate::Policy::lock(&args.paths, false)).transpose()?;
        if stopping() || policy.as_ref().is_some_and(|policy| !policy.authorizes(request.consent.as_deref())) {
            return Ok(false);
        }
        activate(&install, request, worker)?;
        Ok(true)
    });
    match result {
        Ok(true) if stopping() => Ok(None),
        Ok(true) => Err(exec_installed(&install, &update, registration, Some(&cooldown))),
        Ok(false) => {
            clear_skipped_request(&install, deferred, id)?;
            Ok(None)
        }
        Err(e) => {
            if install.replacement_pending()? {
                wait_for_trial_cleanup(&install)?;
                recover(&install)?;
            } else {
                clear_skipped_request(&install, deferred, id)?;
            }
            log!(Warn, "cannot activate the agent update", error = e);
            Ok(Some(cooldown))
        }
    }
}

fn clear_skipped_request(install: &Installation, deferred: &mut Option<FileId>, id: FileId) -> Result<()> {
    match install.clear_request() {
        Ok(()) => *deferred = None,
        Err(e) if matches!(&e, Error::Io { source, .. } if cleanup_denied(source)) => {
            if *deferred != Some(id) {
                log!(Warn, "keeping the update request suppressed until it can be removed", error = e);
                *deferred = Some(id);
            }
        }
        Err(e) => return Err(e),
    }
    Ok(())
}

fn read_request(path: &Path) -> Result<Request> {
    Request::load(path).ok_or_else(|| Error::io("reading the update handoff")(io::Error::other("invalid request")))
}

fn run_command(path: &Path) -> Command {
    let mut cmd = Command::new(path);
    cmd.args(std::env::args_os().skip(1));
    cmd.env_remove(WORKER)
        .env_remove(TRIAL)
        .env_remove(COOLDOWN)
        .env_remove(STARTUP_LOCK)
        .env_remove(REGISTRATION_LOCK)
        .env_remove(ACTIVATION)
        .env_remove(TRIAL_GUARD);
    cmd
}

fn pass_lock(command: &mut Command, variable: &str, lock: &File) {
    let fd = lock.as_raw_fd();
    command.env(variable, fd.to_string());
    // SAFETY: the caller keeps the descriptor open through exec; fcntl is async-signal-safe.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) == -1 { Err(io::Error::last_os_error()) } else { Ok(()) }
        });
    }
}

fn exec_installed(install: &Installation, update: &File, registration: &File, cooldown: Option<&str>) -> Error {
    let mut command = run_command(&install.exe);
    pass_lock(&mut command, STARTUP_LOCK, update);
    pass_lock(&mut command, REGISTRATION_LOCK, registration);
    if let Some(version) = cooldown {
        command.env(COOLDOWN, version);
    }
    Error::io("starting the installed agent")(command.exec())
}

fn inherited_lock(variable: &str, path: &Path) -> Result<Option<File>> {
    let Some(fd) = std::env::var_os(variable) else { return Ok(None) };
    let failed = |e| Error::io(format!("validating the inherited lock {}", path.display()))(e);
    let fd: libc::c_int = fd
        .to_str()
        .and_then(|fd| fd.parse().ok())
        .filter(|fd| *fd > libc::STDERR_FILENO)
        .ok_or_else(|| failed(io::Error::other("invalid lock descriptor")))?;
    // SAFETY: fcntl validates that this exec-inherited descriptor is open and
    // makes it close on exec before any other children can inherit it.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        return Err(failed(io::Error::last_os_error()));
    }
    if flags & libc::FD_CLOEXEC != 0 {
        return Err(failed(io::Error::other("lock descriptor is already close-on-exec")));
    }
    // SAFETY: the descriptor was checked above and is still open.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
        return Err(failed(io::Error::last_os_error()));
    }
    // SAFETY: the inherited descriptor is open and owned by this process.
    let inherited = unsafe { File::from_raw_fd(fd) };
    let probe = open_lock(path)?;
    let expected = probe.metadata().map_err(failed)?;
    let actual = inherited.metadata().map_err(failed)?;
    if (expected.dev(), expected.ino()) != (actual.dev(), actual.ino()) {
        return Err(failed(io::Error::other("descriptor refers to a different lock")));
    }
    match probe.try_lock() {
        Err(fs::TryLockError::WouldBlock) => {}
        Ok(()) => return Err(failed(io::Error::other("inherited lock was unheld"))),
        Err(fs::TryLockError::Error(e)) => return Err(failed(e)),
    }
    inherited.try_lock().map_err(|e| failed(e.into()))?;
    Ok(Some(inherited))
}

fn startup_executable() -> Result<PathBuf> {
    let exe = std::env::current_exe().map_err(Error::io("finding the agent binary"))?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt;
        // A concurrent startup may have already restored the installed path.
        // Linux appends this suffix to the old image's path after replacement.
        if let Some(path) = exe.as_os_str().as_bytes().strip_suffix(b" (deleted)")
            && !exe.exists()
        {
            return Ok(PathBuf::from(std::ffi::OsStr::from_bytes(path)));
        }
    }
    Ok(exe)
}

// The shared startup path also handles Linux's fallible inode check.
#[cfg_attr(target_os = "macos", allow(clippy::unnecessary_wraps))]
fn needs_startup_exec(install: &Installation, restored: bool, inherited: bool) -> Result<bool> {
    #[cfg(target_os = "linux")]
    {
        let _ = inherited;
        let failed = |e| Error::io("checking the running agent image")(e);
        let image = fs::metadata("/proc/self/exe").map_err(failed)?;
        let installed = FileId::read(&install.exe).map_err(failed)?;
        Ok(restored || FileId(image.dev(), image.ino()) != installed)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = install;
        // current_exe only identifies a pathname on macOS. Load that pathname
        // under the lock before trusting it. An inherited descriptor proves
        // the exec took place with this same lock still held.
        Ok(restored || !inherited)
    }
}

fn run_worker(
    args: &Args,
    install: &Installation,
    supervised: bool,
    trial: bool,
    cooldown: Option<String>,
) -> Result<()> {
    // A worker whose supervisor died can still be cleaning up its tunnel.
    // Both exclusions must remain held until daemon teardown completes.
    let _worker = lock(&install.worker_lock)?;
    let _registration = lock(&install.registration_worker_lock)?;
    if stopping() {
        return Ok(());
    }
    daemon::run(args, supervised.then_some(install), trial, cooldown)
}

pub fn run(args: &Args) -> Result<()> {
    if let Some(exe) = std::env::var_os(TRIAL_GUARD) {
        return run_trial_guard(args, Path::new(&exe));
    }
    if let Some(exe) = std::env::var_os(WORKER) {
        let install = Installation::open(Path::new(&exe), &args.paths.config_dir)?;
        let trial = std::env::var_os(TRIAL).is_some();
        if !trial {
            watch_supervisor()?;
        }
        return run_worker(args, &install, true, trial, std::env::var(COOLDOWN).ok());
    }
    if let Some(exe) = std::env::var_os(ACTIVATION) {
        let install = Installation::open(Path::new(&exe), &args.paths.config_dir)?;
        let request = read_request(&install.activation)?;
        let install = request.handoff(&install);
        if startup_executable()? != install.candidate {
            return Err(Error::io("starting the updated supervisor")(io::Error::other("invalid activation state")));
        }
        request.validate(&install)?;
        watch_supervisor()?;
        return supervise_candidate(&install);
    }

    let runtime = runtime_dir()?;
    let exe = startup_executable()?;
    let Ok(exe) = protected_file(&exe) else {
        let exe = fs::canonicalize(exe).map_err(Error::io("resolving the agent executable"))?;
        let install = Installation::at(&exe, &args.paths.config_dir, &runtime, false)?;
        // A protected alias of this executable may still be re-executing
        // its coordinator with the update lock held.
        let update = lock(&install.update_lock)?;
        let _claims = install.claim_startup(false, None)?;
        drop(update);
        return run_worker(args, &install, false, false, None);
    };
    let config = protected_dir(&args.paths.config_dir, false).ok();
    let install =
        Installation::at(&exe, config.as_deref().unwrap_or(&args.paths.config_dir), &runtime, config.is_some())?;
    let inherited = inherited_lock(STARTUP_LOCK, &install.update_lock)?;
    let entered_under_lock = inherited.is_some();
    let update = inherited.map_or_else(|| lock(&install.update_lock), Ok)?;
    let registration = inherited_lock(REGISTRATION_LOCK, &install.registration_lock)?;
    let claims = install.claim_startup(config.is_some(), registration)?;
    if install.replacement_pending()? {
        wait_for_trial_cleanup(&install)?;
    }
    let recovery = recover(&install)?;
    if let Some(version) = &recovery.interrupted {
        log!(Warn, "kept the previous agent after an interrupted activation", version = version);
    }
    let cooldown =
        recovery.interrupted.or_else(|| if entered_under_lock { std::env::var(COOLDOWN).ok() } else { None });
    if needs_startup_exec(&install, recovery.restored, entered_under_lock)? {
        return Err(exec_installed(&install, &update, &claims.registration, cooldown.as_deref()));
    }
    drop(update);
    if config.is_none() {
        return run_worker(args, &install, false, false, None);
    }
    supervise(args, &install, &claims.registration, cooldown)
}

fn check_running(worker: &mut ServiceChild) -> Result<()> {
    if let Some(status) = worker.try_wait().map_err(Error::io("checking the Warren service process"))? {
        return Err(Error::io("running the Warren service process")(io::Error::other(status.to_string())));
    }
    Ok(())
}

fn start_worker(install: &Installation, activating: bool, cooldown: Option<&str>) -> Result<ServiceChild> {
    let mut command = run_command(if activating { &install.candidate } else { &install.exe });
    command.env(WORKER, &install.exe);
    if activating {
        command.env(TRIAL, "1");
    }
    if let Some(version) = cooldown {
        command.env(COOLDOWN, version);
    }
    spawn_child(command, ChildRole::Worker, activating)
}

fn supervise_candidate(install: &Installation) -> Result<()> {
    let mut worker = start_worker(install, true, Some(warren_proto::VERSION))?;
    let result = (|| {
        await_child(&mut worker, READY, "confirm tunnel readiness")?;
        send_commit(&mut worker)?;
        await_child(&mut worker, ACTIVE, "confirm activation")?;
        send_ack(ACTIVE)?;
        while !stopping() {
            check_running(&mut worker)?;
            std::thread::sleep(TICK);
        }
        Ok(())
    })();
    worker.stop().map_err(Error::io("stopping the Warren service process"))?;
    result
}

fn supervise(args: &Args, install: &Installation, registration: &File, mut cooldown: Option<String>) -> Result<()> {
    let mut worker = None;
    let mut deferred = None;
    let mut last_recovery = Instant::now();
    let result = (|| -> Result<()> {
        while !stopping() {
            if last_recovery.elapsed() >= RECOVERY_RETRY {
                last_recovery = Instant::now();
                if install.replacement_pending()?
                    && let Some(_guard) = try_lock(&install.update_lock)?
                {
                    recover(install)?;
                }
            }
            if let Some(version) = handle_request(args, install, registration, &mut worker, &mut deferred)? {
                cooldown = Some(version);
            }
            if stopping() {
                break;
            }
            if let Some(worker) = &mut worker {
                check_running(worker)?;
            } else {
                worker = Some(start_worker(install, false, cooldown.take().as_deref())?);
            }
            std::thread::sleep(SERVICE_TICK);
        }
        Ok(())
    })();
    if let Some(worker) = worker {
        worker.stop().map_err(Error::io("stopping the Warren service process"))?;
    }
    result
}

pub fn acknowledge_ready() -> Result<()> {
    send_ack(READY)?;
    receive_commit()?;
    watch_supervisor()?;
    send_ack(ACTIVE)
}

pub fn wait_for_install(install: &Installation, candidate: &Binary) -> Result<()> {
    let deadline = Instant::now() + UPDATE_TIMEOUT;
    while Instant::now() < deadline {
        if !install.request.try_exists().map_err(Error::io("checking the update handoff"))? {
            return finish_wait(install, candidate);
        }
        std::thread::sleep(TICK);
    }
    finish_wait(install, candidate)
}

fn finish_wait(install: &Installation, candidate: &Binary) -> Result<()> {
    let _guard = lock(&install.update_lock)?;
    let pending = install.request.try_exists().map_err(Error::io("checking the update handoff"))?;
    if install.replacement_pending()? {
        return Err(activation_failed());
    }
    let request = Request::load(&install.request);
    let ours = request.as_ref().is_some_and(|request| request.candidate == *candidate);
    if candidate.matches(&install.exe)? {
        return if pending && (ours || request.is_none()) {
            Err(Error::io("activating the update")(io::Error::other(
                "the updated supervisor has yet to confirm activation",
            )))
        } else {
            Ok(())
        };
    }
    if ours && candidate.matches(&install.candidate).unwrap_or(false) {
        install.clear_request()?;
    }
    Err(activation_failed())
}

fn activation_failed() -> Error {
    Error::io("activating the update")(io::Error::other(
        "the Warren daemon did not confirm a working tunnel; the previous binary was kept (see the service log)",
    ))
}

#[cfg(all(test, target_os = "macos"))]
#[test]
fn case_variants_of_one_directory_share_the_registration() {
    let suffix = warren_proto::codec::hex_encode(&state::random_bytes::<8>().unwrap());
    let dir = std::env::temp_dir().join(format!("warren-config-{suffix}"));
    let variant = dir.with_file_name(format!("WARREN-CONFIG-{suffix}"));
    fs::create_dir(&dir).unwrap();
    let exe = std::env::current_exe().unwrap();
    let case_insensitive = variant.is_dir();
    if !case_insensitive {
        fs::create_dir(&variant).unwrap();
    }
    let first = Installation::at(&exe, &dir, &dir, false).unwrap();
    let second = Installation::at(&exe, &variant, &dir, false).unwrap();
    if !case_insensitive {
        fs::remove_dir(&variant).unwrap();
    }
    fs::remove_dir(&dir).unwrap();

    assert_eq!(first.registration == second.registration, case_insensitive);
    assert_eq!(first.request == second.request, case_insensitive);
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) mod tests {
    // Fixture setup failures should fail the test at the operation that failed.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::state::Paths;
    use std::os::unix::fs::PermissionsExt;

    pub(crate) struct Fixture {
        pub dir: PathBuf,
        pub install: Installation,
    }

    impl Fixture {
        pub(crate) fn new() -> Self {
            // SAFETY: geteuid has no preconditions.
            assert_eq!(unsafe { libc::geteuid() }, 0, "update fixtures need root; run just check-linux");
            let suffix = warren_proto::codec::hex_encode(&state::random_bytes::<8>().unwrap());
            let dir = PathBuf::from(format!("/var/lib/warren-update-{suffix}"));
            state::store_key(&dir.join("private.key"), &[1; 32]).unwrap();
            let install = Installation::at(&dir.join("warren"), &dir, &runtime_dir().unwrap(), true).unwrap();
            fs::write(&install.exe, "#!/bin/sh\necho warren 1.0.0\n").unwrap();
            fs::set_permissions(&install.exe, fs::Permissions::from_mode(0o755)).unwrap();
            Self { dir, install }
        }

        pub(crate) fn claim(&self) -> File {
            self.install.claim(true).unwrap()
        }

        pub(crate) fn paths(&self) -> Paths {
            Paths { config_dir: self.dir.clone(), run_dir: self.dir.clone() }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.dir).unwrap();
        }
    }

    fn stage(fixture: &Fixture) -> Request {
        let install = &fixture.install;
        let data = b"#!/bin/sh\nexit 77\n";
        fs::write(&install.candidate, data).unwrap();
        let request = Request::new(
            Binary::record(&install.exe, None).unwrap(),
            Binary::record(&install.candidate, Some(data)).unwrap(),
            "9.0.0",
            None,
        );
        request.stage(install).unwrap();
        request
    }

    #[test]
    #[ignore = "requires root-owned update fixtures"]
    fn invalid_keys_prevent_staging_and_daemon_startup() {
        let fixture = Fixture::new();
        let path = fixture.paths().key();
        let key = warren_proto::codec::encode_key(&[1; 32]);
        let zero = warren_proto::codec::encode_key(&[0; 32]);
        for invalid in [format!("{key:<128}trailing garbage"), format!("{key:<129}"), format!("{key}garbage"), zero] {
            fs::write(&path, invalid).unwrap();
            assert!(Installation::open(&fixture.install.exe, &fixture.dir).is_err());
            assert!(state::load_key(&path).is_err());
        }
        fs::write(&path, format!("{key:<128}")).unwrap();
        assert!(Installation::open(&fixture.install.exe, &fixture.dir).is_ok());
        assert_eq!(state::load_key(&path).unwrap(), [1; 32]);
    }

    #[test]
    #[ignore = "requires root-owned update fixtures"]
    fn changed_filesystem_identity_keeps_the_verified_handoff() {
        let fixture = Fixture::new();
        let install = &fixture.install;
        let mut request = stage(&fixture);
        request.installed.id = FileId(0, 0);
        request.candidate.id = FileId(0, 0);
        request.stage(install).unwrap();

        let request = read_request(&install.request).unwrap();
        request.validate(install).unwrap();
        fs::write(&install.candidate, "different contents").unwrap();
        assert!(request.validate(install).is_err());
    }

    #[test]
    #[ignore = "requires root-owned update fixtures"]
    fn a_second_registration_recovers_an_interrupted_replacement() {
        let fixture = Fixture::new();
        let install = &fixture.install;
        let request = stage(&fixture);
        fs::rename(&install.request, &install.activation).unwrap();
        fs::hard_link(&install.exe, &install.backup).unwrap();
        fs::rename(&install.candidate, &install.exe).unwrap();
        assert!(finish_wait(install, &request.candidate).is_err());

        let config = fixture.dir.join("second");
        fs::create_dir(&config).unwrap();
        let second = Installation::open(&install.exe, &config).unwrap();
        assert_ne!(second.request, install.request);
        let _updated = lock(&second.update_lock).unwrap();
        let _service = second.claim(true).unwrap();
        recover(&second).unwrap();
        assert!(FileId::read(&install.exe).unwrap() == request.installed.id);
        assert!(!install.backup.exists() && !install.activation.exists());
    }

    #[test]
    #[ignore = "requires a privileged bind mount"]
    fn staged_update_and_service_owner_match_with_a_symlinked_key_between_bind_aliases() {
        struct Mount(PathBuf);
        impl Drop for Mount {
            fn drop(&mut self) {
                assert!(Command::new("umount").arg(&self.0).status().unwrap().success());
            }
        }

        let fixture = Fixture::new();
        let config = fixture.dir.join("config");
        state::store_key(&config.join("protected/key"), &[7; 32]).unwrap();
        std::os::unix::fs::symlink("protected/key", config.join("private.key")).unwrap();
        let bind = |name| {
            let path = fixture.dir.join(name);
            fs::create_dir(&path).unwrap();
            assert!(Command::new("mount").arg("--bind").arg(&config).arg(&path).status().unwrap().success());
            Mount(path)
        };
        let first = bind("first");
        let second = bind("second");
        let executable = &fixture.install.exe;
        let staging = Installation::open(executable, &first.0).unwrap();
        let running = Installation::open(executable, &second.0).unwrap();
        let _claims = running.claim_startup(true, None).unwrap();
        assert!(staging.service_state().unwrap());
        assert_eq!(staging.request, running.request);
        assert_eq!(staging.candidate, running.candidate);
        fs::write(&staging.candidate, b"candidate").unwrap();
        let request = Request::new(
            Binary::record(executable, None).unwrap(),
            Binary::record(&staging.candidate, None).unwrap(),
            "9.0.0",
            None,
        );
        request.stage(&staging).unwrap();
        let handoff = running.pending_handoff().unwrap();
        read_request(&handoff.request).unwrap().validate(&handoff).unwrap();

        // Reopening the same saved key in a different directory models the
        // durable part of the identity independently of directory inodes.
        let restored = fixture.dir.join("restored");
        state::store_key(&restored.join("private.key"), &[7; 32]).unwrap();
        let restored = Installation::open(executable, &restored).unwrap();
        assert_ne!(restored.registration_lock, running.registration_lock);
        assert_eq!(restored.request, staging.request);
        assert!(restored.service_state().is_err());
    }

    #[test]
    #[ignore = "requires root-owned update fixtures"]
    fn coordinator_exec_keeps_the_registration_claim() {
        const CONFIG: &str = "WARREN_TEST_EXEC_CONFIG";
        if let Some(config) = std::env::var_os(CONFIG) {
            let config = Path::new(&config);
            let install = Installation::open(&config.join("warren"), config).unwrap();
            let competing = Installation::open(&config.join("second-warren"), config).unwrap();
            // The parent drops its descriptors before closing the pipe.
            assert_eq!(io::stdin().read(&mut [0]).unwrap(), 0);
            assert!(competing.claim_startup(true, None).is_err());

            let update = inherited_lock(STARTUP_LOCK, &install.update_lock).unwrap().unwrap();
            let registration = inherited_lock(REGISTRATION_LOCK, &install.registration_lock).unwrap().unwrap();
            let claims = install.claim_startup(true, Some(registration)).unwrap();
            drop(update);
            assert!(try_lock(&install.update_lock).unwrap().is_some());
            assert!(competing.claim_startup(true, None).is_err());
            drop(claims);
            assert!(competing.claim_startup(true, None).is_ok());
            return;
        }

        let fixture = Fixture::new();
        let install = &fixture.install;
        fs::copy(&install.exe, fixture.dir.join("second-warren")).unwrap();
        let update = lock(&install.update_lock).unwrap();
        let claims = install.claim_startup(true, None).unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--ignored", "--exact", "update_service::tests::coordinator_exec_keeps_the_registration_claim"])
            .env(CONFIG, &fixture.dir)
            .stdin(Stdio::piped());
        pass_lock(&mut command, STARTUP_LOCK, &update);
        pass_lock(&mut command, REGISTRATION_LOCK, &claims.registration);
        let mut child = command.spawn().unwrap();
        drop(update);
        drop(claims);
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
    }

    #[test]
    #[ignore = "requires root-owned update fixtures"]
    fn recovery_cleans_only_the_verified_abandoned_candidate() {
        let fixture = Fixture::new();
        let install = &fixture.install;
        let other = fixture.dir.join("other");
        fs::create_dir(&other).unwrap();
        let other = Installation::open(&install.exe, &other).unwrap();
        for changed in [false, true] {
            stage(&fixture);
            fs::rename(&install.request, &install.activation).unwrap();
            if changed {
                fs::write(&install.candidate, b"unrelated").unwrap();
            }
            assert_eq!(recover(&other).unwrap().interrupted.as_deref(), Some("9.0.0"));
            assert_eq!(install.candidate.exists(), changed);
            assert!(!install.activation.exists());
        }
    }

    #[test]
    #[ignore = "requires root-owned update fixtures"]
    fn recovery_retries_candidate_verification_errors() {
        let fixture = Fixture::new();
        let install = &fixture.install;
        stage(&fixture);
        fs::rename(&install.request, &install.activation).unwrap();

        fs::set_permissions(&install.candidate, fs::Permissions::from_mode(0o666)).unwrap();
        recover(install).unwrap();
        assert!(install.activation.exists() && install.candidate.exists());

        fs::set_permissions(&install.candidate, fs::Permissions::from_mode(0o600)).unwrap();
        recover(install).unwrap();
        assert!(!install.activation.exists() && !install.candidate.exists());
    }
}
