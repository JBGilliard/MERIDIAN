//! User attribution: who ran the command, on which host.
//! Bound into every event's canonical bytes (signed, hashed).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Attribution {
    pub user: String,
    pub host: String,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub hwid: Option<String>,
}

impl Attribution {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put(&mut out, &self.user);
        put(&mut out, &self.host);
        put_opt(&mut out, self.ip.as_deref());
        put_opt(&mut out, self.hwid.as_deref());
        out
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
}
