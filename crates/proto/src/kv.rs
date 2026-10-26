//! Line-based `key=value` text format used between agent and server.

use crate::Error;

/// An ordered list of `key=value` pairs; keys may repeat.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Kv(Vec<(String, String)>);

impl Kv {
    /// Creates an empty list.
    #[must_use]
    pub fn new() -> Self {
        Kv(Vec::new())
    }

    /// Appends a pair. Keys may only contain `[A-Za-z0-9_]` (other characters
    /// become `_`), and line breaks in values become spaces, so neither can
    /// smuggle in another pair. Values are trimmed, as `parse` does, so a
    /// sender and a receiver encode the same pairs to the same bytes.
    pub fn push(&mut self, key: &str, value: impl AsRef<str>) {
        let key: String = key.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect();
        let value = value.as_ref().replace(['\n', '\r'], " ");
        self.0.push((key, value.trim().to_string()));
    }

    /// Returns the first value of `key`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    /// Returns the first value of `key`, or [`Error::MissingField`].
    ///
    /// # Errors
    /// When `key` is absent.
    pub fn req(&self, key: &'static str) -> Result<&str, Error> {
        self.get(key).ok_or(Error::MissingField(key))
    }

    /// Parses the first value of `key` with [`str::parse`].
    ///
    /// # Errors
    /// When `key` is absent or its value does not parse.
    pub fn parse_field<T: std::str::FromStr>(&self, key: &'static str) -> Result<T, Error> {
        self.req(key)?.parse().map_err(|_| Error::BadField(key))
    }

    /// Iterates over every value of `key`, in order.
    pub fn get_all<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.0.iter().filter(move |(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    /// Serializes to the text format, one `key=value` line per pair.
    #[must_use]
    pub fn encode(&self) -> String {
        let mut s = String::new();
        for (k, v) in &self.0 {
            s.push_str(k);
            s.push('=');
            s.push_str(v);
            s.push('\n');
        }
        s
    }

    /// Parses the text format. Blank lines and `#` comments are skipped;
    /// keys and values are trimmed.
    ///
    /// # Errors
    /// When a line lacks `=` or has an invalid key.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut kv = Kv::new();
        for (i, line) in text.lines().enumerate() {
            let line = line.trim_end_matches('\r');
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (k, v) = line.split_once('=').ok_or(Error::MissingSeparator { line: i + 1 })?;
            let k = k.trim();
            if k.is_empty() || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                return Err(Error::BadKey { line: i + 1 });
            }
            kv.0.push((k.to_string(), v.trim().to_string()));
        }
        Ok(kv)
    }

    /// Encoding of every pair except `skip`, used as the MAC input.
    #[must_use]
    pub fn encode_without(&self, skip: &str) -> String {
        let mut s = String::new();
        for (k, v) in self.0.iter().filter(|(k, _)| k != skip) {
            s.push_str(k);
            s.push('=');
            s.push_str(v);
            s.push('\n');
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_injection() {
        let mut kv = Kv::new();
        kv.push("a", "1");
        kv.push("peer", "x");
        kv.push("peer", "y");
        kv.push("evil", "v\nmac=forged");
        kv.push("bad key=", "x");
        let parsed = Kv::parse(&kv.encode()).unwrap();
        assert_eq!(parsed.get("a"), Some("1"));
        assert_eq!(parsed.get_all("peer").collect::<Vec<_>>(), ["x", "y"]);
        assert_eq!(parsed.get("mac"), None);
        assert_eq!(parsed.get("evil"), Some("v mac=forged"));
        assert_eq!(parsed.get("bad_key_"), Some("x"));
        assert!(Kv::parse("no equals").is_err());
        assert!(Kv::parse("bad key=1").is_err());
        assert_eq!(Kv::parse("# c\n\nx = y \n").unwrap().get("x"), Some("y"));
    }
}
