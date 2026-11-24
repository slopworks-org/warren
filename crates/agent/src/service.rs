//! Install and control the native background service.

use crate::cli::{Args, Service};
use crate::error::{Error, Result};
use crate::state;
use std::{env, fs, io, path::Path, process::Command};

const JOB: &str = "system/org.slopworks.warren";

#[derive(Clone, Copy)]
enum Manager {
    Systemd,
    Openwrt,
    Launchd,
}

fn run(program: &str, args: &[&str]) -> Result<()> {
    let cmd = format!("{program} {}", args.join(" "));
    let status = Command::new(program).args(args).status().map_err(Error::io(&cmd))?;
    if status.success() { Ok(()) } else { Err(Error::io(cmd)(io::Error::other(status.to_string()))) }
}

impl Manager {
    fn detect() -> Result<Self> {
        if cfg!(target_os = "macos") {
            Ok(Self::Launchd)
        } else if Path::new("/etc/openwrt_release").is_file() {
            Ok(Self::Openwrt)
        } else if Path::new("/run/systemd/system").is_dir() {
            Ok(Self::Systemd)
        } else {
            Err(Error::Usage("no supported service manager is running; use `warren run`".into()))
        }
    }

    fn path(self) -> &'static str {
        match self {
            Self::Systemd => "/etc/systemd/system/warren.service",
            Self::Openwrt => "/etc/init.d/warren",
            Self::Launchd => "/Library/LaunchDaemons/org.slopworks.warren.plist",
        }
    }

    fn render(self, arguments: &[String], config: &str) -> String {
        match self {
            Self::Systemd => {
                let quote =
                    |s: &String| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace('%', "%%"));
                include_str!("../../../dist/systemd/warren.service")
                    .lines()
                    .map(|line| {
                        if line.starts_with("ExecStart=") {
                            format!(
                                "ExecStart={}",
                                std::iter::once(quote(&format!(":{}", arguments[0])))
                                    .chain(arguments[1..].iter().map(quote))
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            )
                        } else if line.starts_with("ConditionPathExists=") {
                            format!("ConditionPathExists={}/agent.conf", config.replace('%', "%%"))
                        } else {
                            line.to_owned()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n"
            }
            Self::Openwrt => {
                let quote = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
                include_str!("../../../dist/openwrt/warren.init")
                    .lines()
                    .map(|line| match line.trim_start() {
                        "PROG=/usr/bin/warren" => format!("PROG={}", quote(&arguments[0])),
                        "if [ ! -f /etc/warren/agent.conf ]; then" => {
                            format!("\tif [ ! -f {}/agent.conf ]; then", quote(config))
                        }
                        "procd_set_param command \"$PROG\" run" => format!(
                            "\tprocd_set_param command \"$PROG\" {}",
                            arguments[1..].iter().map(|s| quote(s)).collect::<Vec<_>>().join(" ")
                        ),
                        _ => line.to_owned(),
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n"
            }
            Self::Launchd => {
                let strings = arguments
                    .iter()
                    .map(|s| {
                        format!(
                            "    <string>{}</string>",
                            s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                include_str!("../../../dist/macos/org.slopworks.warren.plist")
                    .replace("    <string>/usr/local/bin/warren</string>\n    <string>run</string>", &strings)
            }
        }
    }

    fn unload() -> Result<()> {
        let probe = Command::new("launchctl").args(["print", JOB]).output().map_err(Error::io("querying launchd"))?;
        if probe.status.success() {
            run("launchctl", &["bootout", JOB])
        } else if probe.status.code() == Some(113) {
            Ok(())
        } else {
            Err(Error::io("querying launchd")(io::Error::other(String::from_utf8_lossy(&probe.stderr).into_owned())))
        }
    }

    fn start(self, install: bool) -> Result<()> {
        match self {
            Self::Systemd => {
                if install {
                    run("systemctl", &["daemon-reload"])?;
                    run("systemctl", &["enable", "warren.service"])?;
                }
                run("systemctl", &["restart", "warren.service"])
            }
            Self::Openwrt => {
                if install {
                    run(self.path(), &["enable"])?;
                }
                run(self.path(), &["restart"])
            }
            Self::Launchd if install => {
                Self::unload()?;
                run("launchctl", &["enable", JOB])?;
                run("launchctl", &["bootstrap", "system", self.path()])
            }
            Self::Launchd => run("launchctl", &["kickstart", "-k", JOB]),
        }
    }
}

fn path_arg(path: &Path) -> Result<String> {
    let path = std::path::absolute(path).map_err(Error::io("resolving service path"))?;
    path.to_str()
        .filter(|s| !s.chars().any(char::is_control))
        .map(str::to_owned)
        .ok_or_else(|| Error::Usage("service paths must be UTF-8 without control characters".into()))
}

pub fn manage(action: Service, args: &Args) -> Result<()> {
    let manager = Manager::detect()?;
    let path = Path::new(manager.path());
    let context = || Error::io(manager.path());
    match action {
        Service::Install => {
            if !args.paths.config().is_file() {
                return Err(Error::NotRegistered);
            }
            let config = path_arg(&args.paths.config_dir)?;
            let exe = env::current_exe().map_err(Error::io("locating warren"))?;
            let mut arguments = vec![
                path_arg(&exe)?,
                "run".into(),
                "--config-dir".into(),
                config.clone(),
                "--run-dir".into(),
                path_arg(&args.paths.run_dir)?,
            ];
            if let Some(level) = args.log_level.clone().or_else(|| env::var("WARREN_LOG").ok()) {
                arguments.extend(["--log-level".into(), level]);
            }
            let dir = fs::File::open(path.parent().ok_or(Error::InvalidConfig("invalid service directory"))?)
                .map_err(context())?;
            let name = std::ffi::CString::new(path.file_name().unwrap_or_default().as_encoded_bytes())
                .map_err(|e| context()(e.into()))?;
            state::write_at(
                &dir,
                &name,
                manager.render(&arguments, &config).as_bytes(),
                if matches!(manager, Manager::Openwrt) { 0o755 } else { 0o644 },
            )?;
            manager.start(true)?;
            println!("Installed and started the Warren service ({path}).", path = path.display());
        }
        Service::Restart => {
            if !path.try_exists().map_err(context())? {
                return Err(Error::Usage("Warren service is not installed; run `warren service install`".into()));
            }
            manager.start(false)?;
            println!("Restarted the Warren service.");
        }
        Service::Uninstall => {
            if !path.try_exists().map_err(context())? {
                println!("Warren service is already uninstalled.");
                return Ok(());
            }
            match manager {
                Manager::Systemd => run("systemctl", &["disable", "--now", "warren.service"])?,
                Manager::Openwrt => {
                    run(manager.path(), &["stop"])?;
                    run(manager.path(), &["disable"])?;
                }
                Manager::Launchd => Manager::unload()?,
            }
            fs::remove_file(path).map_err(context())?;
            if matches!(manager, Manager::Systemd) {
                run("systemctl", &["daemon-reload"])?;
            }
            println!("Uninstalled the Warren service. Registration is preserved.");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_arguments_for_each_service_manager() {
        let args = ["/opt/warren's & tools/agent".to_owned(), "run".into(), "/tmp/%n $a".into()];
        let unit = Manager::Systemd.render(&args, "/tmp/%n");
        assert!(unit.contains("ConditionPathExists=/tmp/%%n/agent.conf"));
        assert!(unit.contains("ExecStart=\":/opt/warren's & tools/agent\" \"run\" \"/tmp/%%n $a\""));
        let script = Manager::Openwrt.render(&args, "/tmp/it's private");
        assert!(script.contains("PROG='/opt/warren'\\''s & tools/agent'"));
        assert!(script.contains("[ ! -f '/tmp/it'\\''s private'/agent.conf ]"));
        assert!(script.contains("command \"$PROG\" 'run' '/tmp/%n $a'"));
        let plist = Manager::Launchd.render(&args, "/tmp");
        assert!(plist.contains("<string>/opt/warren's &amp; tools/agent</string>"));
        assert!(plist.contains("<string>/tmp/%n $a</string>"));
    }
}
