//! The agent's error type.

use std::fmt;
use std::io;

/// Everything that can make an agent command fail.
#[derive(Debug)]
pub enum Error {
    /// Bad command line.
    Usage(String),
    /// A file or network operation failed.
    Io {
        /// What was being done, e.g. "reading /etc/warren/agent.conf".
        what: String,
        /// The underlying error.
        source: io::Error,
    },
    /// Configuring the WireGuard interface failed.
    Wg(warren_wgctl::Error),
    /// A stored file or a server message is malformed.
    Format {
        /// Which document was being parsed.
        what: &'static str,
        /// The parse error.
        source: warren_proto::Error,
    },
    /// The server answered with an error.
    Server {
        /// HTTP status code.
        status: u16,
        /// The server's explanation, if any.
        message: String,
    },
    /// The server's reply failed authentication or validation.
    BadReply(&'static str),
    /// A tunnel configuration (pushed or stored) cannot be applied.
    InvalidConfig(&'static str),
    /// No `agent.conf`: the device has not been registered yet.
    NotRegistered,
}

impl Error {
    /// Wraps an I/O error with a description of the operation.
    pub fn io(what: impl Into<String>) -> impl FnOnce(io::Error) -> Error {
        let what = what.into();
        move |source| Error::Io { what, source }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Usage(m) => write!(f, "{m} (see `warren help`)"),
            Error::Io { what, source } => write!(f, "{what}: {source}"),
            Error::Wg(e) => e.fmt(f),
            Error::Format { what, source } => write!(f, "malformed {what}: {source}"),
            Error::Server { status, message } if message.is_empty() => {
                write!(f, "server answered HTTP {status}")
            }
            Error::Server { status, message } => write!(f, "server answered HTTP {status}: {message}"),
            Error::BadReply(why) => write!(f, "rejected server reply: {why}"),
            Error::InvalidConfig(why) => write!(f, "invalid tunnel configuration: {why}"),
            Error::NotRegistered => f.write_str("this device is not registered; run `warren up` first"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            Error::Wg(e) => Some(e),
            Error::Format { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<warren_wgctl::Error> for Error {
    fn from(e: warren_wgctl::Error) -> Self {
        Error::Wg(e)
    }
}

/// Result of an agent operation.
pub type Result<T> = std::result::Result<T, Error>;
