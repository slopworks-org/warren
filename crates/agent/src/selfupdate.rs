//! Installs official releases independently of the device's control server.

use crate::error::{Error, Result};
use crate::state::{self, Paths, Saved};
use crate::update_files::{
    check_root_dir, check_root_file, lock, open_dir, protected_dir, protected_file, runtime_dir, try_lock,
};
use crate::update_service::{self, Binary, Installation, Request};
use std::ffi::CStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use warren_proto::{RELEASE_REPO, VERSION, is_newer};

pub const CHECK_TIMEOUT: Duration = Duration::from_secs(10);
const HTTPS_HELP: &str = "install curl and the system CA certificates (OpenWrt packages: curl and ca-bundle), then check HTTPS access to github.com";

fn curl(timeout: Duration) -> Result<Command> {
    let bin = ["/usr/bin/curl", "/bin/curl"]
        .into_iter()
        .find_map(|path| protected_file(Path::new(path)).ok())
        .ok_or_else(|| {
            Error::io("finding a trusted HTTPS downloader")(io::Error::other(
                "system curl was not found in /usr/bin or /bin",
            ))
        })?;
    let mut cmd = Command::new(bin);
    cmd.env_clear()
        .args(["-q", "--proto", "=https", "--proto-redir", "=https", "--fail", "--silent", "--show-error"])
        .args(["--max-time", &timeout.as_secs().to_string()]);
    Ok(cmd)
}

fn lookup_curl(timeout: Duration) -> Result<Command> {
    let mut cmd = curl(timeout)?;
    // Informational lookups do not need privileged filesystem access.
    let sudo_id = |key| std::env::var(key).ok()?.parse::<u32>().ok();
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0
        && let (Some(uid), Some(gid)) = (sudo_id("SUDO_UID"), sudo_id("SUDO_GID"))
        && uid != 0
    {
        cmd.uid(uid).gid(gid);
    }
    Ok(cmd)
}

fn fetch(cmd: &mut Command, what: &str) -> Result<Vec<u8>> {
    let out = cmd.output().map_err(Error::io("starting the trusted HTTPS downloader"))?;
    if !out.status.success() {
        return Err(Error::io(what)(io::Error::other(String::from_utf8_lossy(&out.stderr).trim())));
    }
    Ok(out.stdout)
}

fn release_tag(url: &str) -> Option<String> {
    let version = url.trim().strip_prefix(&format!("https://github.com/{RELEASE_REPO}/releases/tag/v"))?;
    let (major, minor, patch) = warren_proto::parse_version(version)?;
    (version == format!("{major}.{minor}.{patch}")).then(|| version.to_string())
}

pub fn latest(timeout: Duration) -> Result<String> {
    release_version(lookup_curl(timeout)?)
}

fn trusted_latest() -> Result<String> {
    release_version(curl(CHECK_TIMEOUT)?)
}

fn release_version(mut cmd: Command) -> Result<String> {
    let url = format!("https://github.com/{RELEASE_REPO}/releases/latest");
    let output = fetch(
        cmd.args(["--head", "--output", "/dev/null", "--write-out", "%{redirect_url}", &url]),
        "checking for an official release",
    )?;
    release_tag(&String::from_utf8_lossy(&output)).ok_or_else(|| {
        Error::io("checking for an official release")(io::Error::other("GitHub did not return a stable release tag"))
    })
}

fn asset(version: &str, file: &str, max_bytes: &str) -> Result<Vec<u8>> {
    let url = format!("https://github.com/{RELEASE_REPO}/releases/download/v{version}/{file}");
    fetch(
        curl(Duration::from_secs(60))?.args(["--location", "--max-redirs", "5", "--max-filesize", max_bytes, &url]),
        &format!("downloading {file}"),
    )
}

fn verified_binary(version: &str) -> Result<Vec<u8>> {
    let file = warren_proto::agent_asset()
        .ok_or_else(|| Error::io("finding an agent build")(io::Error::other("unsupported platform")))?;
    // Both verification inputs come from trusted system curl running as the
    // updater. A sudo caller's account cannot trace these downloads.
    let sums = asset(version, "SHA256SUMS", "65536")?;
    let binary = asset(version, file, "16777216")?;
    let sums = String::from_utf8_lossy(&sums);
    if !warren_proto::asset_checksum(&sums, file)
        .is_some_and(|want| warren_proto::asset_sha256(&binary).eq_ignore_ascii_case(want))
    {
        return Err(Error::io("verifying the download")(io::Error::other("agent checksum mismatch")));
    }
    Ok(binary)
}

pub struct Policy {
    dir: File,
    _guard: File,
}

const POLICY_NAME: &CStr = c"remote-updates";

fn open_policy_dir(paths: &Paths, create: bool) -> Result<File> {
    let path = protected_dir(&paths.config_dir, create)?;
    let dir = open_dir(&path).map_err(Error::io("opening the registration directory"))?;
    check_root_dir(&dir).map_err(Error::io("checking the registration directory"))?;
    Ok(dir)
}

struct Consent {
    enabled: bool,
    generation: Option<Generation>,
}

struct Generation {
    epoch: String,
    counter: u64,
}

impl Generation {
    fn parse(value: &str) -> Option<Self> {
        let (epoch, counter) = value.split_once(':')?;
        if epoch.len() != 32 || !epoch.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        Some(Self { epoch: epoch.into(), counter: counter.parse().ok()? })
    }

    fn encode(&self) -> String {
        format!("{}:{}", self.epoch, self.counter)
    }
}

fn read_consent(dir: &File) -> io::Result<Option<Consent>> {
    check_root_dir(dir)?;
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    let file = match state::open_at(dir, POLICY_NAME, flags, 0) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound || e.raw_os_error() == Some(libc::ELOOP) => return Ok(None),
        Err(e) => return Err(e),
    };
    check_root_file(&file)?;
    let mut value = String::new();
    file.take(129).read_to_string(&mut value)?;
    if value.len() > 128 {
        return Ok(None);
    }
    let value = value.trim();
    let (mode, generation) = if let Some((mode, generation)) = value.split_once(' ') {
        let Some(generation) = Generation::parse(generation) else { return Ok(None) };
        (mode, Some(generation))
    } else {
        (value, None)
    };
    let enabled = match mode {
        "on" => true,
        "off" => false,
        _ => return Ok(None),
    };
    Ok(Some(Consent { enabled, generation }))
}

fn write_consent(dir: &File, enabled: bool) -> Result<String> {
    let failed = |e| Error::io("reading the remote update consent generation")(e);
    let previous = read_consent(dir).map_err(failed)?.and_then(|state| state.generation);
    let generation = if let Some(mut previous) = previous {
        previous.counter = previous
            .counter
            .checked_add(1)
            .ok_or_else(|| failed(io::Error::other("remote update consent generation exhausted")))?;
        previous
    } else {
        // A new policy must not authorize requests from a removed policy,
        // even if the same registration key is restored after forgetting it.
        Generation { epoch: warren_proto::codec::hex_encode(&state::random_bytes::<16>()?), counter: 1 }
    }
    .encode();
    let mode = if enabled { "on" } else { "off" };
    state::write_private_at(dir, POLICY_NAME, format!("{mode} {generation}\n").as_bytes())?;
    Ok(generation)
}

pub fn remote_enabled(paths: &Paths) -> bool {
    open_policy_dir(paths, false)
        .is_ok_and(|dir| read_consent(&dir).is_ok_and(|state| state.is_some_and(|s| s.enabled)))
}

pub fn remote_generation(paths: &Paths) -> Option<String> {
    let dir = open_policy_dir(paths, false).ok()?;
    let consent = read_consent(&dir).ok().flatten().filter(|consent| consent.enabled)?;
    if let Some(generation) = consent.generation {
        return Some(generation.encode());
    }
    // Upgrade an existing opt-in under the policy lock before reporting it.
    Policy::lock(paths, false).ok()?.generation_for_poll().ok().flatten()
}

impl Policy {
    pub fn lock(paths: &Paths, create: bool) -> Result<Self> {
        let dir = open_policy_dir(paths, create)?;
        let guard = lock(&policy_lock_path(&dir)?)?;
        Ok(Self { dir, _guard: guard })
    }

    pub fn authorizes(&self, generation: Option<&str>) -> bool {
        generation.is_some_and(|generation| {
            self.active_consent()
                .and_then(|state| state.generation)
                .is_some_and(|current| current.encode() == generation)
        })
    }

    fn active_consent(&self) -> Option<Consent> {
        read_consent(&self.dir).ok().flatten().filter(|state| state.enabled)
    }

    fn generation_for_poll(&self) -> Result<Option<String>> {
        match self.active_consent() {
            Some(Consent { generation: Some(generation), .. }) => Ok(Some(generation.encode())),
            Some(_) => write_consent(&self.dir, true).map(Some),
            None => Ok(None),
        }
    }

    fn set_enabled(&self, enabled: bool) -> Result<()> {
        write_consent(&self.dir, enabled).map(drop)
    }
}

pub fn policy_lock_path(dir: &File) -> Result<PathBuf> {
    let meta = dir.metadata().map_err(Error::io("identifying the registration directory"))?;
    Ok(runtime_dir()?.join(format!("{}-{}.policy", meta.dev(), meta.ino())))
}

pub fn set_remote(paths: &Paths, enabled: bool) -> Result<()> {
    if enabled {
        let config_dir = protected_dir(&paths.config_dir, true)?;
        let installation = Installation::current(&config_dir)?;
        drop(try_lock(&installation.update_lock)?);
        trusted_latest()
            .map_err(|e| Error::io("enabling remote updates")(io::Error::other(format!("{e}; {HTTPS_HELP}"))))?;
    }
    Policy::lock(paths, true)?.set_enabled(enabled)
}

pub struct Forget<'a> {
    paths: &'a Paths,
    dir: File,
    _policy: File,
}

impl<'a> Forget<'a> {
    pub fn open(paths: &'a Paths) -> Result<Option<Self>> {
        let failed = |e| Self::error(paths, e);
        // Follow aliases while opening the directory. All other operations
        // then use its descriptor, even if the alias is redirected.
        let dir = match OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY).open(&paths.config_dir) {
            Ok(dir) => dir,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(failed(e)),
        };
        let policy = lock(&policy_lock_path(&dir)?)?;
        Ok(Some(Self { paths, dir, _policy: policy }))
    }

    pub fn load_config(&self) -> Result<Saved> {
        Saved::load_at(&self.dir, &self.paths.config())
    }

    pub fn revoke(self) -> Result<()> {
        let failed = |e| Self::error(self.paths, e);
        if read_consent(&self.dir).is_ok_and(|state| state.is_some_and(|s| s.generation.is_some())) {
            write_consent(&self.dir, false)?;
        } else if unlink_entry(&self.dir, POLICY_NAME).map_err(failed)? {
            self.dir.sync_all().map_err(failed)?;
        }
        for (name, path) in [(c"agent.conf", self.paths.config()), (c"private.key", self.paths.key())] {
            if unlink_entry(&self.dir, name).map_err(Error::io(format!("deleting {}", path.display())))? {
                println!("Deleted {}.", path.display());
            }
        }
        self.dir.sync_all().map_err(failed)
    }

    fn error(paths: &Paths, error: io::Error) -> Error {
        Error::io(format!("forgetting the registration in {}", paths.config_dir.display()))(error)
    }
}

fn unlink_entry(dir: &File, name: &CStr) -> io::Result<bool> {
    // SAFETY: dir and name remain live for the call. With flags zero,
    // unlinkat removes the entry itself, including a symlink.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound { Ok(false) } else { Err(error) }
}

enum Install {
    Unchanged,
    Staged(String),
    Live(String, Binary),
}

/// Publish a handoff for a tunnel trial by the supervisor, on its next start
/// if the service is stopped.
fn install(
    install: &Installation,
    paths: &Paths,
    version: &str,
    consent: Option<&str>,
    download: impl FnOnce() -> Result<Vec<u8>>,
) -> Result<Install> {
    install.require_registration(&paths.config_dir)?;
    let Some(_guard) = try_lock(&install.update_lock)? else {
        return Err(Error::io("installing the update")(io::Error::other("another update is in progress")));
    };
    if install.pending_handoff().is_some() || install.replacement_pending()? {
        return Err(Error::io("installing the update")(io::Error::other("another update is pending")));
    }
    let current = reported_version(&install.exe)?;
    if !is_newer(version, &current) {
        return Ok(Install::Unchanged);
    }
    if !install.service_state()? && consent.is_some() {
        return Ok(Install::Unchanged);
    }
    if consent.is_some() && !Policy::lock(paths, false)?.authorizes(consent) {
        return Ok(Install::Unchanged);
    }
    let installed = Binary::record(&install.exe, None)?;
    let data = download()?;
    let policy = consent.map(|_| Policy::lock(paths, false)).transpose()?;
    if crate::stopping() || policy.as_ref().is_some_and(|policy| !policy.authorizes(consent)) {
        return Ok(Install::Unchanged);
    }
    install.require_registration(&paths.config_dir)?;
    let service = install.service_state()?;
    if !service && consent.is_some() {
        return Ok(Install::Unchanged);
    }
    install.clear_request()?;
    let stage = || -> Result<Install> {
        let mut staged = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&install.candidate)
            .map_err(Error::io("creating the staged agent"))?;
        staged
            .write_all(&data)
            .and_then(|()| staged.set_permissions(fs::Permissions::from_mode(0o755)))
            .and_then(|()| staged.sync_all())
            .map_err(Error::io("writing the staged agent"))?;
        drop(staged);
        let candidate = Binary::record(&install.candidate, Some(&data))?;
        let request = Request::new(installed, candidate, version, consent.map(str::to_string));
        request.stage(install)?;
        Ok(if service { Install::Live(current, request.candidate) } else { Install::Staged(current) })
    };
    let result = stage();
    if result.is_err() {
        install.clear_request()?;
    }
    result
}

fn reported_version(bin: &Path) -> Result<String> {
    let failed = || Error::io(format!("checking {}", bin.display()));
    let (mut output, writer) = UnixStream::pair().map_err(failed())?;
    output.set_nonblocking(true).map_err(failed())?;
    let mut child = Command::new(bin)
        .arg("version")
        .stdin(Stdio::null())
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .spawn()
        .map_err(failed())?;
    let deadline = Instant::now() + CHECK_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(failed())? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(failed()(io::Error::new(io::ErrorKind::TimedOut, "agent version command timed out")));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut bytes = [0; 128];
    let read = output.read(&mut bytes).map_err(failed())?;
    String::from_utf8_lossy(&bytes[..read])
        .trim()
        .strip_prefix("warren ")
        .filter(|_| status.success())
        .map(str::to_string)
        .ok_or_else(|| failed()(io::Error::other("agent did not report its version")))
}

pub fn check_version(bin: &Path, expected: &str) -> Result<()> {
    if reported_version(bin)? != expected {
        return Err(Error::io("checking the staged agent")(io::Error::other("unexpected binary version")));
    }
    Ok(())
}

pub fn run(paths: &Paths, check: bool, remote: Option<bool>) -> Result<()> {
    if let Some(enabled) = remote {
        set_remote(paths, enabled)?;
        println!("Automatic and dashboard updates: {}", if enabled { "on" } else { "off" });
        return Ok(());
    }
    println!("Checking for Warren updates...");
    let version = if check { latest(CHECK_TIMEOUT)? } else { trusted_latest()? };
    if !is_newer(&version, VERSION) {
        println!("v{VERSION}, already up to date");
    } else if check {
        println!("v{VERSION} (v{version} available)");
    } else {
        let config_dir = protected_dir(&paths.config_dir, true)?;
        let installation = Installation::current(&config_dir)?;
        println!("Downloading and verifying Warren v{version}...");
        match install(&installation, paths, &version, None, || verified_binary(&version))? {
            Install::Unchanged => {
                println!("v{}, already up to date", reported_version(&installation.exe)?);
                return Ok(());
            }
            Install::Staged(current) => {
                println!("{current} -> {version}, staged (will activate on next service start)");
            }
            Install::Live(current, candidate) => {
                println!("Restarting the Warren service and checking the tunnel...");
                update_service::wait_for_install(&installation, &candidate)?;
                println!("{current} -> {version}, updated");
            }
        }
    }
    Ok(())
}

pub fn auto_update(installation: &Installation, paths: &Paths, generation: &str) -> Result<()> {
    if remote_generation(paths).as_deref() != Some(generation) {
        return Ok(());
    }
    let version = trusted_latest()?;
    if is_newer(&version, VERSION) {
        crate::log!(Info, "downloading the official agent release", version = version);
        install(installation, paths, &version, Some(generation), || verified_binary(&version))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_the_official_release_tag() {
        let base = format!("https://github.com/{RELEASE_REPO}/releases/tag/");
        assert_eq!(release_tag(&format!("{base}v9.8.7")).as_deref(), Some("9.8.7"));
        assert_eq!(release_tag(&format!("{base}v9.8.7-rc.1")), None);
        assert_eq!(release_tag(&format!("{base}v9.8.7?other")), None);
        assert_eq!(release_tag("https://example.com/releases/tag/v9.8.7"), None);
    }
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root-owned update fixtures"]
    fn revoking_consent_during_download_never_invokes_the_candidate() {
        use update_service::tests::Fixture;

        let fixture = Fixture::new();
        let paths = fixture.paths();
        let installation = &fixture.install;
        state::write_private(&paths.update_policy(), b"on\n").unwrap();
        let _service = fixture.claim();
        assert!(remote_enabled(&paths));

        let generation = remote_generation(&paths).unwrap();
        let result = install(installation, &paths, "9.0.0", Some(&generation), || {
            set_remote(&paths, false)?;
            Policy::lock(&paths, false)?.set_enabled(true)?;
            Ok(br#"#!/bin/sh
: > "$0.invoked"
echo warren 9.0.0
"#
            .to_vec())
        });

        assert!(matches!(result, Ok(Install::Unchanged)));
        assert!(!installation.candidate.with_extension("update-candidate.invoked").exists());
        assert!(!installation.request.exists() && !installation.candidate.exists());
        let result = install(installation, &paths, "9.0.0", Some(&generation), || {
            panic!("a request from a revoked generation cannot download")
        });
        assert!(matches!(result, Ok(Install::Unchanged)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root-owned update fixtures"]
    fn forgetting_a_registration_revokes_numbered_consent() {
        use update_service::tests::Fixture;

        let fixture = Fixture::new();
        let paths = fixture.paths();
        let generation = write_consent(&open_policy_dir(&paths, false).unwrap(), true).unwrap();
        Forget::open(&paths).unwrap().unwrap().revoke().unwrap();
        let policy = Policy::lock(&paths, false).unwrap();
        assert!(!policy.authorizes(Some(&generation)));
        policy.set_enabled(true).unwrap();
        assert!(!policy.authorizes(Some(&generation)));
        let current = policy.generation_for_poll().unwrap().unwrap();
        assert_eq!(current, generation.replace(":1", ":3"));
        assert!(policy.authorizes(Some(&current)));
        assert!(!policy.authorizes(None));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root-owned update fixtures"]
    fn stopped_service_keeps_the_installed_agent_until_the_startup_trial() {
        use update_service::tests::Fixture;

        let fixture = Fixture::new();
        let installation = &fixture.install;
        let previous = Binary::record(&installation.exe, None).unwrap();
        let result = install(installation, &fixture.paths(), "9.0.0", None, || {
            Ok(br#"#!/bin/sh
case "$1" in
    version) : > "$0.checked"; echo warren 9.0.0 ;;
    run) exit 1 ;;
esac
"#
            .to_vec())
        });

        assert!(matches!(result, Ok(Install::Staged(current)) if current == "1.0.0"));
        assert!(Binary::record(&installation.exe, None).unwrap() == previous);
        assert!(installation.request.exists());
        assert!(!installation.candidate.with_extension("update-candidate.checked").exists());
        assert_eq!(fs::metadata(&installation.candidate).unwrap().permissions().mode() & 0o777, 0o755);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root-owned update fixtures"]
    fn staging_revalidates_the_key_if_it_changes_during_download() {
        let fixture = update_service::tests::Fixture::new();
        let paths = fixture.paths();
        let installation = &fixture.install;
        let result = install(installation, &paths, "9.0.0", None, || {
            state::store_key(&paths.key(), &[0; 32])?;
            Ok(b"candidate".to_vec())
        });
        assert!(result.is_err());
        assert!(!installation.request.exists() && !installation.candidate.exists());
        assert!(install(installation, &paths, "9.0.0", None, || panic!("an invalid key cannot stage")).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root-owned update fixtures"]
    fn a_second_registration_cannot_stage_an_update_for_a_running_executable() {
        use update_service::tests::Fixture;

        let fixture = Fixture::new();
        let first = &fixture.install;
        let config_dir = fixture.dir.join("second");
        state::store_key(&config_dir.join("private.key"), &[2; 32]).unwrap();
        let paths = Paths { config_dir, run_dir: fixture.dir.clone() };
        let second = Installation::open(&first.exe, &paths.config_dir).unwrap();
        let _service = fixture.claim();

        let result = install(&second, &paths, "9.0.0", None, || panic!("a second registration cannot download"));
        assert!(result.err().unwrap().to_string().contains("in use by another Warren registration"));
        assert!(!second.request.exists() && !second.candidate.exists());
        assert_eq!(reported_version(&first.exe).unwrap(), "1.0.0");
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root-owned update fixtures"]
    fn forget_revokes_consent_even_if_the_directory_has_become_untrusted() {
        use update_service::tests::Fixture;

        let fixture = Fixture::new();
        let paths = fixture.paths();
        let marker = paths.update_policy();
        state::write_private(&marker, b"on\n").unwrap();
        assert!(remote_enabled(&paths));
        fs::set_permissions(&fixture.dir, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(protected_dir(&fixture.dir, false).is_err());

        Forget::open(&paths).unwrap().unwrap().revoke().unwrap();
        assert!(!marker.exists());

        let target = fixture.dir.join("untouched");
        fs::write(&target, b"on\n").unwrap();
        std::os::unix::fs::symlink(&target, &marker).unwrap();
        Forget::open(&paths).unwrap().unwrap().revoke().unwrap();
        assert!(fs::symlink_metadata(&marker).is_err());
        assert_eq!(fs::read(target).unwrap(), b"on\n");

        fs::set_permissions(&fixture.dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(protected_dir(&fixture.dir, false).is_ok());
        assert!(!remote_enabled(&paths));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root-owned update fixtures"]
    fn forget_pins_interface_lookup_and_revocation_to_one_registration() {
        use std::os::unix::fs::symlink;
        use update_service::tests::Fixture;

        let fixture = Fixture::new();
        let first = fixture.dir.join("first");
        let second = fixture.dir.join("second");
        for (dir, iface) in [(&first, "warrenA"), (&second, "warrenB")] {
            fs::create_dir(dir).unwrap();
            fs::write(dir.join("remote-updates"), b"on\n").unwrap();
            fs::write(dir.join("private.key"), b"key").unwrap();
            fs::write(
                dir.join("agent.conf"),
                format!(
                    "interface={iface}\nserver=https://warren.test\nversion=1\ndevice_id=1\nname=agent\naddress=10.0.0.2/24\ncontrol=10.0.0.1:80\n"
                ),
            )
            .unwrap();
        }
        let alias = fixture.dir.join("alias");
        symlink(&first, &alias).unwrap();
        let paths = Paths { config_dir: alias.clone(), run_dir: fixture.dir.clone() };
        let registration = Forget::open(&paths).unwrap().unwrap();

        fs::remove_file(&alias).unwrap();
        symlink(&second, &alias).unwrap();
        let policy_path = |path| policy_lock_path(&open_dir(path).unwrap()).unwrap();
        assert!(try_lock(&policy_path(&first)).unwrap().is_none());
        assert!(try_lock(&policy_path(&second)).unwrap().is_some());
        assert_eq!(registration.load_config().unwrap().interface, "warrenA");
        registration.revoke().unwrap();

        for name in ["agent.conf", "private.key", "remote-updates"] {
            assert!(!first.join(name).exists());
            assert!(second.join(name).exists());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root-owned update fixtures"]
    fn policy_reads_and_writes_the_locked_directory_after_substitution() {
        use update_service::tests::Fixture;

        let fixture = Fixture::new();
        let dir = fixture.dir.join("registration");
        let original = fixture.dir.join("original");
        let paths = Paths { config_dir: dir.clone(), run_dir: fixture.dir.clone() };
        let policy = Policy::lock(&paths, true).unwrap();
        policy.set_enabled(true).unwrap();
        fs::rename(&dir, &original).unwrap();
        state::write_private(&paths.update_policy(), b"off\n").unwrap();

        assert!(policy.active_consent().is_some());
        policy.set_enabled(false).unwrap();
        let original = open_dir(&original).unwrap();
        let off = read_consent(&original).unwrap().unwrap();
        assert!(!off.enabled);
        assert_eq!(off.generation.unwrap().counter, 2);
        policy.set_enabled(true).unwrap();
        assert_eq!(fs::read(paths.update_policy()).unwrap(), b"off\n");
        assert!(policy.active_consent().is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires a privileged bind mount"]
    fn forget_through_a_bind_alias_waits_for_the_active_policy_lock() {
        use std::process::Command;
        use std::sync::mpsc::{RecvTimeoutError, channel};
        use update_service::tests::Fixture;

        struct BindMount(PathBuf);
        impl Drop for BindMount {
            fn drop(&mut self) {
                assert!(Command::new("umount").arg(&self.0).status().unwrap().success());
            }
        }

        let fixture = Fixture::new();
        let source = fixture.dir.join("registration");
        let untrusted = fixture.dir.join("untrusted");
        let alias = untrusted.join("alias");
        fs::create_dir(&source).unwrap();
        fs::create_dir_all(&alias).unwrap();
        fs::set_permissions(&untrusted, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(Command::new("mount").arg("--bind").arg(&source).arg(&alias).status().unwrap().success());
        let _bind = BindMount(alias.clone());
        let original = Paths { config_dir: source, run_dir: fixture.dir.clone() };
        let aliased = Paths { config_dir: alias, run_dir: fixture.dir.clone() };
        state::write_private(&original.update_policy(), b"on\n").unwrap();
        let policy = Policy::lock(&original, false).unwrap();
        assert!(policy.active_consent().is_some());
        assert!(protected_dir(&aliased.config_dir, false).is_err());
        fs::set_permissions(&original.config_dir, fs::Permissions::from_mode(0o777)).unwrap();
        let local_lock = original.config_dir.join("remote-updates.lock");
        drop(File::create(&local_lock).unwrap());
        fs::remove_file(&local_lock).unwrap();
        drop(File::create(&local_lock).unwrap());

        let (ready, started) = channel();
        let (done, finished) = channel();
        let forget = std::thread::spawn(move || {
            ready.send(()).unwrap();
            let result = Forget::open(&aliased).and_then(|entry| entry.unwrap().revoke());
            done.send(result).unwrap();
        });
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        let while_locked = finished.recv_timeout(Duration::from_millis(300));
        let present_while_locked = original.update_policy().exists();
        drop(policy);
        assert!(matches!(while_locked, Err(RecvTimeoutError::Timeout)));
        assert!(present_while_locked);
        finished.recv_timeout(Duration::from_secs(5)).unwrap().unwrap();
        forget.join().unwrap();
        assert!(!original.update_policy().exists());
    }
}
