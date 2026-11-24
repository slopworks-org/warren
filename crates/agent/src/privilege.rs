//! Restart privileged commands through sudo before they access system state.

use crate::cli::{Args, Command};
use std::os::unix::process::CommandExt;

fn needs_root(args: &Args) -> bool {
    !matches!(
        args.command,
        Command::ServiceHelp
            | Command::Help
            | Command::Version
            | Command::Status
            | Command::Update { check: true, remote: None, .. }
    ) && !crate::expose::is_list(args)
}

pub fn elevate(args: &Args) -> std::io::Result<()> {
    // SAFETY: geteuid takes no arguments and has no preconditions.
    if !needs_root(args) || unsafe { libc::geteuid() } == 0 {
        return Ok(());
    }
    let executable = std::env::current_exe()?;
    let mut sudo = std::process::Command::new("/usr/bin/sudo");
    sudo.args(["-u", "root", "--"]).arg(executable).args(std::env::args_os().skip(1));
    // Preserve the supported logging setting without forwarding the user's environment.
    if args.log_level.is_none()
        && let Ok(level) = std::env::var("WARREN_LOG")
    {
        sudo.args(["--log-level", &level]);
    }
    eprintln!("warren: administrator privileges are required; requesting them through sudo");
    let error = sudo.exec();
    Err(std::io::Error::new(error.kind(), format!("could not start sudo: {error}; install sudo or run warren as root")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_operational_commands_require_root() {
        for argv in [
            &["up", "--server", "https://vpn.example.com", "--token", "tok"][..],
            &["run"][..],
            &["down"][..],
            &["update", "--channel", "main"][..],
            &["expose", "web", "8080"][..],
            &["unexpose", "web"][..],
        ] {
            let args = Args::parse(argv.iter().copied().map(str::to_owned)).unwrap();
            assert!(needs_root(&args), "expected root for {argv:?}");
        }
        for argv in [
            &["--help"][..],
            &["--version"][..],
            &["status"][..],
            &["update", "--check", "--channel", "main"][..],
            &["expose"][..],
            &["expose", "--list"][..],
        ] {
            let args = Args::parse(argv.iter().copied().map(str::to_owned)).unwrap();
            assert!(!needs_root(&args), "did not expect root for {argv:?}");
        }
    }
}
