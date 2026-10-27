//! `warren-server` command line.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;
use warren_server::config::{Config, LogFormat};
use warren_server::server::{self, Stop};

#[derive(Parser)]
#[command(name = "warren-server", version, about = "Warren server: WireGuard hub, reverse proxy and web admin")]
struct Cli {
    /// Configuration file.
    #[arg(short, long, env = "WARREN_CONFIG", default_value_os_t = server::default_config_path())]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server (the default).
    Run,
    /// Create an administrator; prints a generated password unless --password-stdin.
    CreateAdmin {
        /// User name.
        username: String,
        /// Read the password from the first line of stdin.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Reset a user's password (and unblock them); prints a generated one unless --password-stdin.
    ResetPassword {
        /// User name.
        username: String,
        /// Read the password from the first line of stdin.
        #[arg(long)]
        password_stdin: bool,
        /// Also remove two-factor authentication.
        #[arg(long)]
        reset_2fa: bool,
    },
    /// Validate the configuration file and exit.
    CheckConfig,
    /// Install a downloaded update; the systemd unit runs this before each start.
    ApplyUpdate,
}

fn init_logging(config: &Config) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log.level));
    let builder = tracing_subscriber::fmt().with_env_filter(filter).with_target(false);
    match config.log.format {
        LogFormat::Json => builder.json().init(),
        LogFormat::Text => builder.init(),
    }
}

fn print_error(e: &dyn std::error::Error) {
    eprint!("warren-server: {e}");
    let mut source = e.source();
    while let Some(s) = source {
        eprint!(": {s}");
        source = s.source();
    }
    eprintln!();
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let config = match Config::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            print_error(&e);
            return ExitCode::from(2);
        }
    };
    let result = match cli.command.unwrap_or(Command::Run) {
        Command::CheckConfig => {
            println!("{}: ok (admin at {})", cli.config.display(), config.https_origin(config.admin_host()));
            Ok(Stop::Signal)
        }
        Command::ApplyUpdate => match warren_server::update::apply_staged(&config.data_dir) {
            Ok(Some(version)) => {
                println!("installed warren-server {version}");
                Ok(Stop::Signal)
            }
            Ok(None) => Ok(Stop::Signal),
            Err(source) => Err(server::ServerError::Io { what: "installing the update".into(), source }),
        },
        Command::CreateAdmin { username, password_stdin } => {
            server::create_admin(&config, &username, password_stdin).map(|()| Stop::Signal)
        }
        Command::ResetPassword { username, password_stdin, reset_2fa } => {
            server::reset_password(&config, &username, password_stdin, reset_2fa).map(|()| Stop::Signal)
        }
        Command::Run => {
            init_logging(&config);
            // Few threads keep memory low; the work is I/O-bound.
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(std::thread::available_parallelism().map_or(2, |n| n.get().clamp(1, 4)))
                .max_blocking_threads(16)
                .enable_all()
                .build();
            match runtime {
                Ok(rt) => rt.block_on(server::run(config)),
                Err(source) => Err(server::ServerError::Io { what: "starting the async runtime".into(), source }),
            }
        }
    };
    match result {
        Ok(Stop::Signal) => ExitCode::SUCCESS,
        Ok(Stop::Restart) => ExitCode::from(warren_server::update::RESTART_EXIT),
        Err(e) => {
            print_error(&e);
            ExitCode::FAILURE
        }
    }
}
