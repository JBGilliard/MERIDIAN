use crate::error::{Error, Result};
use crate::program::{Compartment, Control, Program, ProgramEvent};
use crate::types::{normalize, NameType};
use serde::{Deserialize, Serialize};

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
        /// Names-index only. Not in `canonical_bytes` — Issued hashes stay stable.
        #[serde(default)]
        program_pid: Option<String>,
        #[serde(default)]
        compartment_id: Option<String>,
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
    ProgramCreated(Program),
    CompartmentAdded(Compartment),
    ProgramControlsChanged {
        program_pid: String,
        #[serde(default)]
        compartment_id: Option<String>,
        #[serde(default)]
        add: Vec<Control>,
        #[serde(default)]
        remove: Vec<Control>,
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
            Self::ProgramCreated(_) => 6,
            Self::CompartmentAdded(_) => 7,
            Self::ProgramControlsChanged { .. } => 8,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Issued { .. } => "issued",
            Self::Retired { .. } => "retired",
            Self::Revoked { .. } => "revoked",
            Self::KeyRotated { .. } => "key_rotated",
            Self::Attempt { .. } => "attempt",
            Self::ProgramCreated(_) => "program_created",
            Self::CompartmentAdded(_) => "compartment_added",
            Self::ProgramControlsChanged { .. } => "program_controls_changed",
        }
    }

    pub fn is_program(&self) -> bool {
        matches!(
            self,
            Self::ProgramCreated(_)
                | Self::CompartmentAdded(_)
                | Self::ProgramControlsChanged { .. }
        )
    }

    pub fn to_program_event(&self) -> Option<ProgramEvent> {
        match self {
            Self::ProgramCreated(p) => Some(ProgramEvent::Created(p.clone())),
            Self::CompartmentAdded(c) => Some(ProgramEvent::CompartmentAdded(c.clone())),
            Self::ProgramControlsChanged {
                program_pid,
                compartment_id,
                add,
                remove,
            } => Some(ProgramEvent::ControlsChanged {
                program_pid: program_pid.clone(),
                compartment_id: compartment_id.clone(),
                add: add.clone(),
                remove: remove.clone(),
            }),
            _ => None,
        }
    }
}

impl From<ProgramEvent> for EventKind {
    fn from(e: ProgramEvent) -> Self {
        match e {
            ProgramEvent::Created(p) => Self::ProgramCreated(p),
            ProgramEvent::CompartmentAdded(c) => Self::CompartmentAdded(c),
            ProgramEvent::ControlsChanged {
                program_pid,
                compartment_id,
                add,
                remove,
            } => Self::ProgramControlsChanged {
                program_pid,
                compartment_id,
                add,
                remove,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub kind: EventKind,
    pub created_at: String,
    #[serde(default)]
    pub attribution: crate::attribition::Attribution,
}

impl Event {
    /// v2 binds attribution. v3 is the PQ valve (RFC §12).
    pub const PREFIX: &'static [u8] = b"MERIDIAN-EVENT-v2\0";
    pub const BINDING_PREFIX: &'static [u8] = b"MERIDIAN-BINDING-v1\0";

    pub fn version() -> u8 {
        2
    }

    pub fn new(kind: EventKind) -> Self {
        Self {
            kind,
            created_at: now_rfc3339(),
            attribution: crate::attribition::Attribution::default(),
        }
    }

    /// Full encoding (marking + attribution). Kept for tests / old combined hashes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Self::header(Self::PREFIX, self.kind.tag(), &self.created_at);
        buf.extend(&self.attribution.canonical_bytes());
        self.put_kind(&mut buf, true);
        buf
    }

    /// Names-chain encoding: no attribution, no marking.
    pub fn canonical_u_bytes(&self) -> Vec<u8> {
        let mut buf = Self::header(Self::PREFIX, self.kind.tag(), &self.created_at);
        self.put_kind(&mut buf, false);
        buf
    }

    /// Bindings-chain encoding: attribution + marking + program_pid + compartment_id.
    pub fn canonical_binding_bytes(&self) -> Vec<u8> {
        let mut buf = Self::header(Self::BINDING_PREFIX, self.kind.tag(), &self.created_at);
        buf.extend(&self.attribution.canonical_bytes());
        match &self.kind {
            EventKind::Issued {
                marking,
                program_pid,
                compartment_id,
                ..
            } => {
                buf.extend(&marking.canonical_bytes());
                put_opt_norm(&mut buf, program_pid.as_deref());
                put_opt_norm(&mut buf, compartment_id.as_deref());
            }
            EventKind::ProgramCreated(_)
            | EventKind::CompartmentAdded(_)
            | EventKind::ProgramControlsChanged { .. } => {
                self.put_kind(&mut buf, true);
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
            EventKind::KeyRotated { .. } | EventKind::Attempt { .. } => {}
        }
        buf
    }

    fn header(prefix: &[u8], tag: u8, created_at: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(prefix);
        buf.push(tag);
        put_str(&mut buf, created_at);
        buf
    }

    fn put_kind(&self, buf: &mut Vec<u8>, include_marking: bool) {
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
                program_pid: _,
                compartment_id: _,
            } => {
                put_str(buf, &normalize(name));
                buf.push(name_type.tag());
                put_str(buf, authority_id);
                put_str(buf, authority_pk);
                put_str(buf, pool_id);
                buf.extend_from_slice(&sequence.to_le_bytes());
                buf.extend_from_slice(&nonce.to_le_bytes());
                put_str(buf, vrf_proof);
                put_str(buf, vrf_output);
                buf.extend_from_slice(&(indices.len() as u32).to_le_bytes());
                for i in indices {
                    buf.extend_from_slice(&i.to_le_bytes());
                }
                if include_marking {
                    buf.extend(&marking.canonical_bytes());
                }
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
                put_str(buf, &normalize(name));
                put_str(buf, reason);
                put_str(buf, authority_id);
            }
            EventKind::KeyRotated {
                authority_id,
                old_pk,
                new_pk,
                new_alg,
            } => {
                put_str(buf, authority_id);
                put_str(buf, old_pk);
                put_str(buf, new_pk);
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
                put_str(buf, &normalize(candidate));
                buf.push(name_type.tag());
                put_str(buf, authority_id);
                buf.extend_from_slice(&nonce.to_le_bytes());
                buf.push(reason.tag());
                put_str(buf, detail);
            }
            EventKind::ProgramCreated(p) => {
                put_str(buf, &normalize(&p.pid));
                put_str(buf, &normalize(&p.nickname));
                put_opt_norm(buf, p.codeword.as_deref());
                buf.push(p.sap_type.tag());
                buf.push(p.level.as_u8());
                put_str(buf, &p.authority_id);
                put_controls(buf, &p.controls);
            }
            EventKind::CompartmentAdded(c) => {
                put_str(buf, &normalize(&c.program_pid));
                put_str(buf, &normalize(&c.id));
                put_str(buf, &normalize(&c.nickname));
                put_opt_norm(buf, c.codeword.as_deref());
                put_opt_norm(buf, c.parent_id.as_deref());
                put_opt_level(buf, c.level);
                put_controls(buf, &c.controls);
            }
            EventKind::ProgramControlsChanged {
                program_pid,
                compartment_id,
                add,
                remove,
            } => {
                put_str(buf, &normalize(program_pid));
                put_opt_norm(buf, compartment_id.as_deref());
                put_controls(buf, add);
                put_controls(buf, remove);
            }
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        crate::crypto::sha256(&[&self.canonical_bytes()])
    }

    pub fn hash_u(&self) -> [u8; 32] {
        crate::crypto::sha256(&[&self.canonical_u_bytes()])
    }

    pub fn hash_binding(&self) -> [u8; 32] {
        crate::crypto::sha256(&[&self.canonical_binding_bytes()])
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

fn put_opt_norm(buf: &mut Vec<u8>, s: Option<&str>) {
    match s.map(normalize).filter(|t| !t.is_empty()) {
        Some(v) => {
            buf.push(1);
            put_str(buf, &v);
        }
        None => buf.push(0),
    }
}

// Option<Level>: None=0, Some(l)=1+l.as_u8() (so Some(Unclassified)=1 != None=0).
fn put_opt_level(buf: &mut Vec<u8>, level: Option<crate::marking::Level>) {
    match level {
        None => buf.push(0),
        Some(l) => buf.push(1 + l.as_u8()),
    }
}

fn put_controls(buf: &mut Vec<u8>, controls: &[Control]) {
    buf.extend_from_slice(&(controls.len() as u32).to_le_bytes());
    for c in controls {
        buf.push(c.kind.tag());
        put_str(buf, &c.value.trim().to_ascii_uppercase());
    }
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
            attribution: crate::attribition::Attribution::default(),
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
            attribution: crate::attribition::Attribution::default(),
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

    #[test]
    fn attribution_is_bound_into_hash() {
        use crate::attribition::Attribution;
        let base = EventKind::Retired {
            name: "granite spire".into(),
            reason: "done".into(),
            authority_id: "DIA".into(),
        };
        let a = Event {
            kind: base.clone(),
            created_at: "2026-01-01T00:00:00Z".into(),
            attribution: Attribution {
                user: "jdoe".into(),
                host: "ws001".into(),
                ip: None,
                hwid: None,
            },
        };
        let b = Event {
            kind: base,
            created_at: "2026-01-01T00:00:00Z".into(),
            attribution: Attribution {
                user: "asmith".into(),
                host: "ws002".into(),
                ip: None,
                hwid: None,
            },
        };
        // Same event, different user/host -> different canonical -> different hash.
        assert_ne!(a.hash(), b.hash());
        // The user string is literally in canonical (bound), not just the hash.
        let ca = a.canonical_bytes();
        let cb = b.canonical_bytes();
        assert!(ca.windows(b"jdoe".len()).any(|w| w == b"jdoe"));
        assert!(cb.windows(b"asmith".len()).any(|w| w == b"asmith"));
    }

    #[test]
    fn prefix_version_is_discoverable() {
        let expected = format!("MERIDIAN-EVENT-v{}\0", Event::version());
        assert_eq!(Event::PREFIX, expected.as_bytes());
        let e = Event {
            kind: EventKind::Retired {
                name: "x".into(),
                reason: "y".into(),
                authority_id: "DIA".into(),
            },
            created_at: "2026-01-01T00:00:00Z".into(),
            attribution: crate::attribition::Attribution::default(),
        };
        assert!(e.canonical_bytes().starts_with(Event::PREFIX));
    }

    fn qsv() -> Program {
        use crate::marking::Level;
        use crate::program::{Control, ControlKind, SapType};
        Program {
            pid: "QSV".into(),
            nickname: "DILIGENTLY IMPRESSED".into(),
            codeword: None,
            sap_type: SapType::Unacknowledged,
            level: Level::TopSecret,
            authority_id: "DIA".into(),
            controls: vec![
                Control::new(ControlKind::Sci, "TK"),
                Control::new(ControlKind::Dissem, "NOFORN"),
            ],
        }
    }

    fn hol() -> Compartment {
        use crate::program::{Control, ControlKind};
        Compartment {
            program_pid: "QSV".into(),
            id: "HOL".into(),
            nickname: "HOLLERED".into(),
            codeword: None,
            parent_id: None,
            controls: vec![Control::new(ControlKind::Sci, "TK")],
            level: None,
        }
    }

    fn wrap(kind: EventKind) -> Event {
        Event {
            kind,
            created_at: "2026-01-01T00:00:00Z".into(),
            attribution: crate::attribition::Attribution::default(),
        }
    }

    #[test]
    fn program_kind_tags_are_6_7_8() {
        let created = wrap(EventKind::ProgramCreated(qsv()));
        let added = wrap(EventKind::CompartmentAdded(hol()));
        let changed = wrap(EventKind::ProgramControlsChanged {
            program_pid: "QSV".into(),
            compartment_id: None,
            add: vec![],
            remove: vec![],
        });
        assert_eq!(created.canonical_bytes()[Event::PREFIX.len()], 6);
        assert_eq!(added.canonical_bytes()[Event::PREFIX.len()], 7);
        assert_eq!(changed.canonical_bytes()[Event::PREFIX.len()], 8);
        // Existing kinds keep their tags so old hashes stay valid.
        let retired = wrap(EventKind::Retired {
            name: "x".into(),
            reason: "y".into(),
            authority_id: "DIA".into(),
        });
        assert_eq!(retired.canonical_bytes()[Event::PREFIX.len()], 2);
    }

    #[test]
    fn program_events_bind_delta_into_hash() {
        let a = wrap(EventKind::ProgramCreated(qsv()));
        assert_eq!(a.hash(), a.hash());
        assert!(a
            .canonical_bytes()
            .windows(b"QSV".len())
            .any(|w| w == b"QSV"));
        assert!(a.issued_name().is_none());

        let mut other = qsv();
        other.controls.pop();
        let b = wrap(EventKind::ProgramCreated(other));
        assert_ne!(a.hash(), b.hash());

        let c = wrap(EventKind::CompartmentAdded(hol()));
        assert!(c
            .canonical_bytes()
            .windows(b"HOL".len())
            .any(|w| w == b"HOL"));

        let d = wrap(EventKind::ProgramControlsChanged {
            program_pid: "QSV".into(),
            compartment_id: Some("HOL".into()),
            add: vec![crate::program::Control::new(
                crate::program::ControlKind::Sci,
                "SI",
            )],
            remove: vec![],
        });
        let e = wrap(EventKind::ProgramControlsChanged {
            program_pid: "QSV".into(),
            compartment_id: None,
            add: vec![crate::program::Control::new(
                crate::program::ControlKind::Sci,
                "SI",
            )],
            remove: vec![],
        });
        assert_ne!(d.hash(), e.hash());
        assert!(d.canonical_bytes().windows(b"SI".len()).any(|w| w == b"SI"));
    }

    #[test]
    fn program_events_serde_and_fold_roundtrip() {
        let kinds = [
            EventKind::from(ProgramEvent::Created(qsv())),
            EventKind::from(ProgramEvent::CompartmentAdded(hol())),
            EventKind::from(ProgramEvent::ControlsChanged {
                program_pid: "QSV".into(),
                compartment_id: Some("HOL".into()),
                add: vec![],
                remove: vec![crate::program::Control::new(
                    crate::program::ControlKind::Dissem,
                    "NOFORN",
                )],
            }),
        ];
        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            let back: EventKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind.type_name(), back.type_name());
            let pe = back.to_program_event().expect("program kind");
            let via: EventKind = pe.into();
            assert_eq!(wrap(kind.clone()).hash(), wrap(via).hash(),);
        }
    }

    #[test]
    fn issued_program_bind_is_not_in_canonical() {
        let kind = |pid: Option<String>| EventKind::Issued {
            name: "GRANITE SPIRE".into(),
            name_type: NameType::Nickname,
            authority_id: "DIA".into(),
            authority_pk: "aa".into(),
            pool_id: "p".into(),
            sequence: 1,
            nonce: 0,
            vrf_proof: "00".into(),
            vrf_output: "00".into(),
            indices: vec![1, 2],
            marking: crate::marking::Marking::default(),
            program_pid: pid,
            compartment_id: None,
        };
        assert_eq!(
            wrap(kind(None)).hash(),
            wrap(kind(Some("QSV".into()))).hash()
        );
        assert_eq!(
            wrap(kind(None)).hash_u(),
            wrap(kind(Some("QSV".into()))).hash_u()
        );
        assert_ne!(
            wrap(kind(None)).hash_binding(),
            wrap(kind(Some("QSV".into()))).hash_binding()
        );
    }

    #[test]
    fn canonical_u_omits_marking_and_attribution() {
        use crate::attribition::Attribution;
        let kind = EventKind::Issued {
            name: "GRANITE SPIRE".into(),
            name_type: NameType::Nickname,
            authority_id: "DIA".into(),
            authority_pk: "aa".into(),
            pool_id: "p".into(),
            sequence: 1,
            nonce: 0,
            vrf_proof: "00".into(),
            vrf_output: "00".into(),
            indices: vec![1, 2],
            marking: crate::marking::Marking::default(),
            program_pid: None,
            compartment_id: None,
        };
        let mut a = wrap(kind.clone());
        a.attribution = Attribution {
            user: "jdoe".into(),
            host: "ws001".into(),
            ip: None,
            hwid: None,
        };
        let mut b = wrap(kind);
        b.kind = match b.kind {
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
                program_pid,
                compartment_id,
                ..
            } => EventKind::Issued {
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
                marking: crate::marking::Marking {
                    level: crate::marking::Level::TopSecret,
                    ..Default::default()
                },
                program_pid,
                compartment_id,
            },
            other => other,
        };
        assert_eq!(a.hash_u(), b.hash_u());
        assert_ne!(a.hash(), b.hash());
        let u = a.canonical_u_bytes();
        assert!(!u.windows(b"jdoe".len()).any(|w| w == b"jdoe"));
        assert!(a
            .canonical_bytes()
            .windows(b"jdoe".len())
            .any(|w| w == b"jdoe"));
        assert!(a
            .canonical_binding_bytes()
            .windows(b"jdoe".len())
            .any(|w| w == b"jdoe"));
        assert!(a.canonical_u_bytes().starts_with(Event::PREFIX));
        assert!(a
            .canonical_binding_bytes()
            .starts_with(Event::BINDING_PREFIX));
    }
}
