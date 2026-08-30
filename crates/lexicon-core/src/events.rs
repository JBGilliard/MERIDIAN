use crate::error::{Error, Result};
use crate::types::{normalize, NameType};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameStatus {
    Issued,
    Retired,
    Revoked,
}

impl NameStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "issued" => Ok(Self::Issued),
            "retired" => Ok(Self::Retired),
            "revoked" => Ok(Self::Revoked),
            other => Err(Error::Parse(format!("unknown status: {other}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptReason {
    Collision,
    Lint,
    AgencyBlock,
}

impl AttemptReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collision => "collision",
            Self::Lint => "lint",
            Self::AgencyBlock => "agency_block",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "collision" => Ok(Self::Collision),
            "lint" => Ok(Self::Lint),
            "agency_block" => Ok(Self::AgencyBlock),
            other => Err(Error::Parse(format!("unknown attempt reason: {other}"))),
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::Collision => 1,
            Self::Lint => 2,
            Self::AgencyBlock => 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    Issued {
        name: String,
        name_type: NameType,
        authority_id: String,
        authority_pk: String,
        pool_id: String,
        sequence: u64,
        nonce: u32,
        vrf_proof: String,
        vrf_output: String,
        indices: Vec<u32>,
        #[serde(default)]
        marking: crate::marking::Marking,
    },
    Retired {
        name: String,
        reason: String,
        authority_id: String,
    },
    Revoked {
        name: String,
        reason: String,
        authority_id: String,
    },
    KeyRotated {
        authority_id: String,
        old_pk: String,
        new_pk: String,
        #[serde(default)]
        new_alg: crate::sig::SigAlg,
    },
    Attempt {
        candidate: String,
        name_type: NameType,
        authority_id: String,
        nonce: u32,
        reason: AttemptReason,
        detail: String,
    },
}

impl EventKind {
    fn tag(&self) -> u8 {
        match self {
            Self::Issued { .. } => 1,
            Self::Retired { .. } => 2,
            Self::Revoked { .. } => 3,
            Self::KeyRotated { .. } => 4,
            Self::Attempt { .. } => 5,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Issued { .. } => "issued",
            Self::Retired { .. } => "retired",
            Self::Revoked { .. } => "revoked",
            Self::KeyRotated { .. } => "key_rotated",
            Self::Attempt { .. } => "attempt",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub kind: EventKind,
    pub created_at: String,
}

impl Event {
    pub fn new(kind: EventKind) -> Self {
        Self {
            kind,
            created_at: now_rfc3339(),
        }
    }

    /// Fixed-order length-prefixed encoding. Not JSON — JSON key order is a footgun.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"MERIDIAN-EVENT-v2\0");
        buf.push(self.kind.tag());
        put_str(&mut buf, &self.created_at);
        match &self.kind {
            EventKind::Issued {
                name,
                name_type,
                authority_id,
                authority_pk,
                pool_id,
                sequence,
                nonce,
                vrf_proof,
                vrf_output,
                indices,
                marking,
            } => {
                put_str(&mut buf, &normalize(name));
                buf.push(name_type.tag());
                put_str(&mut buf, authority_id);
                put_str(&mut buf, authority_pk);
                put_str(&mut buf, pool_id);
                buf.extend_from_slice(&sequence.to_le_bytes());
                buf.extend_from_slice(&nonce.to_le_bytes());
                put_str(&mut buf, vrf_proof);
                put_str(&mut buf, vrf_output);
                buf.extend_from_slice(&(indices.len() as u32).to_le_bytes());
                for i in indices {
                    buf.extend_from_slice(&i.to_le_bytes());
                }
                buf.extend(&marking.canonical_bytes());
            }
            EventKind::Retired {
                name,
                reason,
                authority_id,
            }
            | EventKind::Revoked {
                name,
                reason,
                authority_id,
            } => {
                put_str(&mut buf, &normalize(name));
                put_str(&mut buf, reason);
                put_str(&mut buf, authority_id);
            }
            EventKind::KeyRotated {
                authority_id,
                old_pk,
                new_pk,
                new_alg,
            } => {
                put_str(&mut buf, authority_id);
                put_str(&mut buf, old_pk);
                put_str(&mut buf, new_pk);
                buf.push(new_alg.as_u8());
            }
            EventKind::Attempt {
                candidate,
                name_type,
                authority_id,
                nonce,
                reason,
                detail,
            } => {
                put_str(&mut buf, &normalize(candidate));
                buf.push(name_type.tag());
                put_str(&mut buf, authority_id);
                buf.extend_from_slice(&nonce.to_le_bytes());
                buf.push(reason.tag());
                put_str(&mut buf, detail);
            }
        }
        buf
    }

    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }

    pub fn issued_name(&self) -> Option<String> {
        match &self.kind {
            EventKind::Issued { name, .. }
            | EventKind::Retired { name, .. }
            | EventKind::Revoked { name, .. } => Some(normalize(name)),
            _ => None,
        }
    }
}

fn put_str(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = u32::try_from(bytes.len()).expect("field too long");
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
}

pub fn now_rfc3339() -> String {
    let now = time::OffsetDateTime::now_utc();
    now.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_stable() {
        let e = Event {
            kind: EventKind::Retired {
                name: "granite spire".into(),
                reason: "done".into(),
                authority_id: "DIA".into(),
            },
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        assert_eq!(e.hash(), e.hash());
        assert_eq!(e.issued_name().as_deref(), Some("GRANITE SPIRE"));
    }

    #[test]
    fn key_rotation_carries_algorithm() {
        use crate::sig::SigAlg;
        let e = Event {
            kind: EventKind::KeyRotated {
                authority_id: "DIA".into(),
                old_pk: "aa".into(),
                new_pk: "bb".into(),
                new_alg: SigAlg::Ed25519,
            },
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        // The algorithm tag is bound into canonical bytes, so a rotation to
        // a different algorithm produces a different, authenticated event.
        let bytes = e.canonical_bytes();
        assert_eq!(e.hash(), e.hash());
        assert!(bytes.ends_with(&[SigAlg::Ed25519.as_u8()]));

        let json = serde_json::to_string(&e.kind).unwrap();
        let back: EventKind = serde_json::from_str(&json).unwrap();
        match back {
            EventKind::KeyRotated { new_alg, .. } => assert_eq!(new_alg, SigAlg::Ed25519),
            _ => panic!("wrong kind"),
        }
    }
}
