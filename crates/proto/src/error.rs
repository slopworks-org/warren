//! Error type for parsing the wire formats.

use std::fmt;

/// Why a message in one of the wire formats could not be parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Line `line` (1-based) has no `=` separator.
    MissingSeparator {
        /// 1-based line number.
        line: usize,
    },
    /// Line `line` has an empty key or one with characters other than `[A-Za-z0-9_]`.
    BadKey {
        /// 1-based line number.
        line: usize,
    },
    /// A required field is absent.
    MissingField(&'static str),
    /// A field is present but its value is malformed.
    BadField(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MissingSeparator { line } => write!(f, "line {line}: missing '='"),
            Error::BadKey { line } => write!(f, "line {line}: invalid key"),
            Error::MissingField(k) => write!(f, "missing field {k:?}"),
            Error::BadField(k) => write!(f, "invalid value for field {k:?}"),
        }
    }
}

impl std::error::Error for Error {}
