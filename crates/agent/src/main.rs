//! Warren agent: registers a device with a Warren server and keeps its
//! WireGuard tunnel up.
//!
//! Size matters here (the agent runs on routers), so it uses only `std`,
//! blocking I/O on one thread, and hand-written parsing.

mod cli;
mod daemon;
mod error;
mod http;
mod log;
mod state;
mod status;
mod tunnel;
mod up;

use cli::{Args, Command};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);

/// True once SIGTERM or SIGINT arrived.
pub fn stopping() -> bool {
    STOP.load(Ordering::Relaxed)
}

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

/// Installs SIGTERM/SIGINT handlers without `SA_RESTART`. Blocking reads
/// also wake up every second (see `http`), so a stop is noticed promptly.
fn install_signal_handlers() -> std::io::Result<()> {
    for sig in [libc::SIGTERM, libc::SIGINT] {
        // SAFETY: sigaction is plain old data, so all-zero (no flags) is a
        // valid value; sigemptyset then initializes the mask properly. The
        // handler only stores to an atomic, which is async-signal-safe.
        let r = unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            libc::sigemptyset(&raw mut sa.sa_mask);
            sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
            libc::sigaction(sig, &raw const sa, std::ptr::null_mut())
        };
        if r != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let args = match Args::parse(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("warren: {e}");
            return ExitCode::from(2);
        }
    };
    let level = args.log_level.clone().or_else(|| std::env::var("WARREN_LOG").ok());
    if let Some(level) = level
        && !log::set_level(&level)
    {
        eprintln!("warren: unknown log level {level:?}");
        return ExitCode::from(2);
    }
    let result = match args.command {
        Command::Up => up::run(&args),
        Command::Run => install_signal_handlers()
            .map_err(error::Error::io("installing signal handlers"))
            .and_then(|()| daemon::run(&args)),
        Command::Status => status::status(&args),
        Command::Down => status::down(&args),
        Command::Version => {
            println!("warren {}", warren_proto::VERSION);
            Ok(())
        }
        Command::Help => {
            print!("{}", cli::HELP);
            Ok(())
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("warren: {e}");
            ExitCode::FAILURE
        }
    }
}
