//! Command-line parsing, by hand to keep the binary small.

use crate::error::{Error, Result};
use crate::state::{DEFAULT_CONFIG_DIR, DEFAULT_INTERFACE, DEFAULT_RUN_DIR, Paths};
use std::path::PathBuf;
use warren_proto::UpdateChannel;

pub const HELP: &str = "\
warren — Warren agent

USAGE:
    warren up --server <URL> --token <TOKEN> [--name <NAME>] [--interface <IFACE>] [--force]
    warren run                 keep the tunnel up (run this as a service)
    warren service <install|uninstall|restart>   manage the background service
    warren status              show the agent version and connection state
    warren update              install the latest build on the configured channel
    warren update --check [--channel <release|main>]
                               check a channel without changing settings
    warren update --channel <release|main> [--remote <on|off>]
                               select the update channel (default release)
    warren update --remote <on|off>
                               allow automatic and dashboard-requested updates (default off)
    warren down [--forget]     remove the interface; --forget also deletes the registration
    warren version

COMMON OPTIONS:
    --config-dir <DIR>    config and key directory (default /etc/warren)
    --run-dir <DIR>       runtime status directory (/var/run/warren on Linux,
                          /var/db/warren/run on macOS)
    --log-level <LEVEL>   error, warn, info or debug (default info; env WARREN_LOG)

`--server` is the server's address, e.g. https://vpn.example.com. Registration
talks plain HTTP on port 80 (or the port of an http:// URL) and is authenticated
with the token, so the agent needs no TLS stack.

Operational commands request administrator privileges through sudo when needed.
On systems without sudo, run them as root. Update checks use system curl and CA certificates.
";

pub const SERVICE_HELP: &str = "\
warren service install    enable and start the agent using this executable
warren service restart    restart the installed agent
warren service uninstall  stop and remove the service, keeping registration

Register with warren up before installing. Install accepts --config-dir <DIR>,
--run-dir <DIR> and --log-level <LEVEL> for the background agent.
";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service {
    Install,
    Uninstall,
    Restart,
}

/// Which subcommand to run.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Service(Service),
    ServiceHelp,
    Up,
    Run,
    Status,
    Update { check: bool, remote: Option<bool>, channel: Option<UpdateChannel> },
    Down,
    Version,
    Help,
}

/// Parsed command line.
#[derive(Debug)]
pub struct Args {
    pub command: Command,
    pub server: Option<String>,
    pub token: Option<String>,
    pub name: Option<String>,
    pub interface: String,
    pub force: bool,
    pub forget: bool,
    pub log_level: Option<String>,
    pub paths: Paths,
}

impl Args {
    pub fn parse(words: impl IntoIterator<Item = String>) -> Result<Args> {
        let mut it = words.into_iter();
        let command = match it.next().as_deref() {
            Some("service") => match it.next().as_deref() {
                Some("install") => Command::Service(Service::Install),
                Some("uninstall") => Command::Service(Service::Uninstall),
                Some("restart") => Command::Service(Service::Restart),
                Some("--help" | "-h" | "help") | None => Command::ServiceHelp,
                Some(other) => return Err(Error::Usage(format!("unknown service command {other:?}"))),
            },
            Some("up") => Command::Up,
            Some("run") => Command::Run,
            Some("status") => Command::Status,
            Some("update") => Command::Update { check: false, remote: None, channel: None },
            Some("down") => Command::Down,
            Some("version" | "--version" | "-V") => Command::Version,
            Some("help" | "--help" | "-h") | None => Command::Help,
            Some(other) => return Err(Error::Usage(format!("unknown command {other:?}"))),
        };
        let mut args = Args {
            command,
            server: None,
            token: None,
            name: None,
            interface: DEFAULT_INTERFACE.to_string(),
            force: false,
            forget: false,
            log_level: None,
            paths: Paths { config_dir: DEFAULT_CONFIG_DIR.into(), run_dir: DEFAULT_RUN_DIR.into() },
        };
        while let Some(arg) = it.next() {
            let (flag, inline) = match arg.split_once('=') {
                Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
                _ => (arg, None),
            };
            let mut value =
                || inline.clone().or_else(|| it.next()).ok_or_else(|| Error::Usage(format!("{flag} needs a value")));
            match flag.as_str() {
                "--server" | "-s" => args.server = Some(value()?),
                "--token" | "-t" => args.token = Some(value()?),
                "--name" | "-n" => args.name = Some(value()?),
                "--interface" | "-i" => args.interface = value()?,
                "--config-dir" => args.paths.config_dir = PathBuf::from(value()?),
                "--run-dir" => args.paths.run_dir = PathBuf::from(value()?),
                "--log-level" => args.log_level = Some(value()?),
                "--force" | "--forget" if inline.is_some() => {
                    return Err(Error::Usage(format!("{flag} takes no value")));
                }
                "--check" if inline.is_none() => match &mut args.command {
                    Command::Update { check, remote: None, .. } => *check = true,
                    _ => return Err(Error::Usage("--check is only for `warren update` without --remote".into())),
                },
                "--channel" => match &mut args.command {
                    Command::Update { channel, .. } => {
                        *channel = Some(
                            UpdateChannel::parse(&value()?)
                                .ok_or_else(|| Error::Usage("--channel needs release or main".into()))?,
                        );
                    }
                    _ => return Err(Error::Usage("--channel is only for `warren update`".into())),
                },
                "--remote" => match &mut args.command {
                    Command::Update { check: false, remote, .. } => {
                        *remote = Some(match value()?.as_str() {
                            "on" => true,
                            "off" => false,
                            _ => return Err(Error::Usage("--remote needs on or off".into())),
                        });
                    }
                    _ => return Err(Error::Usage("--remote is only for `warren update` without --check".into())),
                },
                "--force" => args.force = true,
                "--forget" => args.forget = true,
                "--help" | "-h" => args.command = Command::Help,
                _ => return Err(Error::Usage(format!("unknown option {flag:?}"))),
            }
        }
        if args.command == Command::Up && (args.server.is_none() || args.token.is_none()) {
            return Err(Error::Usage("`warren up` needs --server and --token".into()));
        }
        if args.interface.is_empty() || args.interface.len() > 15 {
            return Err(Error::Usage("interface names are 1 to 15 characters".into()));
        }
        Ok(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Args> {
        Args::parse(s.split_whitespace().map(String::from))
    }

    #[test]
    fn parses_up() {
        let a = parse("up --server=https://x --token wrt_a -n box --config-dir /tmp/w").unwrap();
        assert_eq!(a.command, Command::Up);
        assert_eq!(a.server.as_deref(), Some("https://x"));
        assert_eq!(a.token.as_deref(), Some("wrt_a"));
        assert_eq!(a.name.as_deref(), Some("box"));
        assert_eq!(a.paths.config_dir, PathBuf::from("/tmp/w"));
        assert_eq!(a.interface, "warren0");
    }

    #[test]
    fn parses_update_channels() {
        assert_eq!(
            parse("update --check --channel main").unwrap().command,
            Command::Update { check: true, remote: None, channel: Some(UpdateChannel::Main) }
        );
        assert_eq!(
            parse("update --remote off --channel=release").unwrap().command,
            Command::Update { check: false, remote: Some(false), channel: Some(UpdateChannel::Release) }
        );
        for invalid in [
            "update --channel",
            "update --channel nightly",
            "status --channel main",
            "update --check --remote on",
            "update --remote off --check",
        ] {
            assert!(parse(invalid).is_err());
        }
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse("up --server x").is_err());
        assert!(parse("run --bogus").is_err());
        assert!(parse("run --log-level").is_err());
        assert!(parse("frobnicate").is_err());
        assert!(parse("down --forget=no").is_err());
        assert!(parse("run -i averyveryverylongname").is_err());
        assert_eq!(parse("").unwrap().command, Command::Help);
    }
}
