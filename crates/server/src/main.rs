//! `warren-server` command line.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;
use warren_server::config::{Config, LogFormat};
use warren_server::server;

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
            Ok(())
        }
        Command::CreateAdmin { username, password_stdin } => server::create_admin(&config, &username, password_stdin),
        Command::ResetPassword { username, password_stdin, reset_2fa } => {
            server::reset_password(&config, &username, password_stdin, reset_2fa)
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
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            print_error(&e);
            ExitCode::FAILURE
        }
    }
}
