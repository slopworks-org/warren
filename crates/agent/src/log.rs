//! Structured logfmt logging to stderr: `ts=… level=… msg="…" key=value`.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Log severity, most severe first.
#[derive(Clone, Copy, PartialEq, PartialOrd)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

impl Level {
    fn name(self) -> &'static str {
        match self {
            Level::Error => "error",
            Level::Warn => "warn",
            Level::Info => "info",
            Level::Debug => "debug",
        }
    }
}

static LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);

/// Sets the most verbose level that is printed. Returns false for an unknown name.
pub fn set_level(name: &str) -> bool {
    let level = [Level::Error, Level::Warn, Level::Info, Level::Debug].into_iter().find(|l| l.name() == name);
    if let Some(l) = level {
        LEVEL.store(l as u8, Ordering::Relaxed);
    }
    level.is_some()
}

fn enabled(l: Level) -> bool {
    l as u8 <= LEVEL.load(Ordering::Relaxed)
}

/// Formats a Unix timestamp as RFC 3339 UTC.
pub fn rfc3339(secs: u64) -> String {
    let rem = secs % 86_400;
    // Civil-from-days (Howard Hinnant), shifted so all terms stay unsigned.
    let z = secs / 86_400 + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem / 60 % 60, rem % 60)
}

/// Seconds since the Unix epoch.
pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn quote(v: &str) -> String {
    if !v.is_empty() && v.bytes().all(|b| b.is_ascii_graphic() && b != b'"' && b != b'=') {
        v.to_string()
    } else {
        format!("{v:?}")
    }
}

/// Prints one log line; use the [`log!`](crate::log!) macro instead.
pub fn emit(level: Level, msg: &str, fields: &[(&str, &dyn std::fmt::Display)]) {
    if !enabled(level) {
        return;
    }
    let mut line = format!("ts={} level={} msg={}", rfc3339(now()), level.name(), quote(msg));
    for (k, v) in fields {
        let _ = write!(line, " {k}={}", quote(&v.to_string()));
    }
    eprintln!("{line}");
}

/// `log!(Info, "message", key = value, ...)`.
#[macro_export]
macro_rules! log {
    ($lvl:ident, $msg:expr $(, $k:ident = $v:expr)* $(,)?) => {
        $crate::log::emit($crate::log::Level::$lvl, &$msg, &[$((stringify!($k), &$v as &dyn std::fmt::Display)),*])
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn rfc3339_known_dates() {
        assert_eq!(super::rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(super::rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(super::rfc3339(1_792_972_800 + 3661), "2026-10-26T01:01:01Z");
    }

    #[test]
    fn quoting() {
        assert_eq!(super::quote("abc"), "abc");
        assert_eq!(super::quote("a b"), "\"a b\"");
        assert_eq!(super::quote(""), "\"\"");
    }
}
