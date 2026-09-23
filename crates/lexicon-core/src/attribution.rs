//! User attribution bound into every event's canonical bytes (signed, hashed).
//!
//! These fields are an OS-session *claim*, not an attestation. `user` / `host`
//! / `hwid` come from whoami, hostname, and machine-id. They are not
//! cryptographically bound to a person. A CLI flag cannot override them in a
//! production build.
//!
//! PIV/CAC binding is the HSM profile (future). AU-10 non-repudiation waits
//! on that — this crate records who the OS said was at the keyboard.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Attribution {
    /// OS session user (whoami). A claim, not a PIV/CAC attestation.
    pub user: String,
    /// OS hostname. A claim.
    pub host: String,
    /// Kept for wire compat with older events. New collection leaves this None.
    #[serde(default)]
    pub ip: Option<String>,
    /// machine-id / platform UUID. A claim.
    #[serde(default)]
    pub hwid: Option<String>,
}

impl Attribution {
    /// Fresh session claim. `ip` is always None — a UDP-probe address is not identity.
    pub fn session(user: impl Into<String>, host: impl Into<String>, hwid: Option<String>) -> Self {
        Self {
            user: user.into(),
            host: host.into(),
            ip: None,
            hwid,
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put(&mut out, &self.user);
        put(&mut out, &self.host);
        put_opt(&mut out, self.ip.as_deref());
        put_opt(&mut out, self.hwid.as_deref());
        out
    }

    /// Human-readable form for the ledger TEXT column.
    /// Canonical bytes are length-prefixed binary — not UTF-8 once any
    /// field is >= 128 bytes (ioreg hwid). Store this, sign that.
    pub fn display(&self) -> String {
        if self.user.is_empty() && self.host.is_empty() && self.ip.is_none() && self.hwid.is_none()
        {
            return String::new();
        }
        let mut s = format!("{}@{}", self.user, self.host);
        if let Some(ip) = &self.ip {
            s.push_str(" ip=");
            s.push_str(ip);
        }
        if let Some(hwid) = &self.hwid {
            s.push_str(" hwid=");
            s.push_str(hwid);
        }
        s
    }
}

fn put(out: &mut Vec<u8>, s: &str) {
    let len = u32::try_from(s.len()).expect("field too long");
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn put_opt(out: &mut Vec<u8>, s: Option<&str>) {
    match s {
        Some(v) => {
            out.push(1);
            put(out, v);
        }
        None => out.push(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_stable() {
        let a = Attribution {
            user: "jdoe".into(),
            host: "ws001".into(),
            ip: Some("10.0.0.1".into()),
            hwid: None,
        };
        assert_eq!(a.canonical_bytes(), a.canonical_bytes());
    }

    #[test]
    fn roundtrip_some_and_none() {
        let a = Attribution {
            user: "u".into(),
            host: "h".into(),
            ip: None,
            hwid: None,
        };
        let b = Attribution {
            user: "u".into(),
            host: "h".into(),
            ip: Some("1.2.3.4".into()),
            hwid: Some("uuid-7".into()),
        };
        // both stable; presence flag distinguishes Some from None.
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
    }

    #[test]
    fn display_roundtrip_long_hwid() {
        let hwid = "H".repeat(200);
        let a = Attribution {
            user: "jdoe".into(),
            host: "ws001".into(),
            ip: Some("10.0.0.1".into()),
            hwid: Some(hwid.clone()),
        };
        let s = a.display();
        assert_eq!(s, format!("jdoe@ws001 ip=10.0.0.1 hwid={hwid}"));
        // length prefix 200 = 0xC8 makes the blob invalid UTF-8
        assert!(String::from_utf8(a.canonical_bytes()).is_err());
    }

    #[test]
    fn session_claim_has_no_ip() {
        let a = Attribution::session("jdoe", "ws001", Some("mid".into()));
        assert!(a.ip.is_none());
        assert_eq!(a.user, "jdoe");
        assert_eq!(a.host, "ws001");
        assert_eq!(a.hwid.as_deref(), Some("mid"));
    }

    #[test]
    fn default_display_is_empty() {
        assert!(Attribution::default().display().is_empty());
    }
}
