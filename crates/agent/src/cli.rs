//! Command-line parsing, by hand to keep the binary small.

use crate::error::{Error, Result};
use crate::state::{DEFAULT_CONFIG_DIR, DEFAULT_INTERFACE, DEFAULT_RUN_DIR, Paths};
use std::path::PathBuf;

pub const HELP: &str = "\
warren — Warren agent

USAGE:
    warren up --server <URL> --token <TOKEN> [--name <NAME>] [--interface <IFACE>] [--force]
    warren run                 keep the tunnel up (run this as a service)
    warren status              show tunnel and server connection state
    warren down [--forget]     remove the interface; --forget also deletes the registration
    warren version

COMMON OPTIONS:
    --config-dir <DIR>    config and key directory (default /etc/warren)
    --run-dir <DIR>       runtime status directory (default /var/run/warren)
    --log-level <LEVEL>   error, warn, info or debug (default info; env WARREN_LOG)

`--server` is the server's address, e.g. https://vpn.example.com. Registration
talks plain HTTP on port 80 (or the port of an http:// URL) and is authenticated
with the token, so the agent needs no TLS stack.
";

/// Which subcommand to run.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Up,
    Run,
    Status,
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
            Some("up") => Command::Up,
            Some("run") => Command::Run,
            Some("status") => Command::Status,
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
