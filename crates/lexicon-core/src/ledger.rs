use crate::authority::Authority;
use crate::error::{Error, Result};
use crate::events::{now_rfc3339, Event, EventKind, NameStatus};
use crate::merkle::{self, InclusionProof};
use crate::sig::{Signature, Signer};
use crate::types::normalize;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRoot {
    pub root: String,
    pub leaf_count: u64,
    pub signed_at: String,
    pub authority_id: String,
    pub authority_pk: String,
    pub signature: String,
}

pub struct Ledger {
    conn: Connection,
}

impl Ledger {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        let ledger = Self { conn };
        ledger.init()?;
        Ok(ledger)
    }

    pub fn open_memory() -> Result<Self> {
        let ledger = Self {
            conn: Connection::open_in_memory()?,
        };
        ledger.init()?;
        Ok(ledger)
    }

    fn init(&self) -> Result<()> {
        self.conn.execute_batch(
            "
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY,
                event_type TEXT NOT NULL,
                canonical BLOB NOT NULL,
                event_hash BLOB NOT NULL,
                signature BLOB NOT NULL,
                created_at TEXT NOT NULL,
                attribution TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS names (
                normalized TEXT PRIMARY KEY,
                display TEXT NOT NULL,
                status TEXT NOT NULL,
                event_seq INTEGER NOT NULL,
                name_type TEXT NOT NULL,
                authority_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS snapshots (
                seq INTEGER PRIMARY KEY,
                root BLOB NOT NULL,
                signature BLOB NOT NULL,
                signed_at TEXT NOT NULL,
                authority_id TEXT NOT NULL,
                authority_pk BLOB NOT NULL,
                leaf_count INTEGER NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS events_no_update
                BEFORE UPDATE ON events
                BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS events_no_delete
                BEFORE DELETE ON events
                BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
            ",
        )?;
        self.migrate()?;
        Ok(())
    }

    /// Forward-only schema migration. `PRAGMA user_version` tracks the
    /// schema version; each step ALTERs an old DB up. The one place
    /// the schema is allowed to change.
    fn migrate(&self) -> Result<()> {
        // v0: add the `marking` column. CREATE TABLE IF NOT EXISTS
        // does not add columns to an existing table, so ALTER explicitly.
        let current: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if current > MAX_SCHEMA_VERSION {
            return Err(Error::SchemaTooNew {
                found: current,
                max: MAX_SCHEMA_VERSION,
            });
        }
        if current < 1 {
            let has_marking: bool = self
                .conn
                .prepare("SELECT * FROM names LIMIT 0")?
                .column_names()
                .contains(&"marking");
            if !has_marking {
                self.conn.execute(
                    "ALTER TABLE names ADD COLUMN marking TEXT NOT NULL DEFAULT 'U'",
                    [],
                )?;
            }
            self.conn.execute_batch("PRAGMA user_version = 1")?;
        }
        if current < 2 {
            let has_attr: bool = self
                .conn
                .prepare("SELECT * FROM events LIMIT 0")?
                .column_names()
                .contains(&"attribution");
            if !has_attr {
                self.conn.execute(
                    "ALTER TABLE events ADD COLUMN attribution TEXT NOT NULL DEFAULT ''",
                    [],
                )?;
            }
            self.conn.execute_batch("PRAGMA user_version = 2")?;
        }
        Ok(())
    }

    pub fn next_seq(&self) -> Result<u64> {
        let n: i64 = self
            .conn
            .query_row("SELECT COALESCE(MAX(seq), 0) FROM events", [], |r| r.get(0))?;
        Ok((n as u64) + 1)
    }

    pub fn len(&self) -> Result<u64> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    pub fn name_status(&self, name: &str) -> Result<Option<NameStatus>> {
        let key = normalize(name);
        let status: Option<String> = self
            .conn
            .query_row(
                "SELECT status FROM names WHERE normalized = ?1",
                [&key],
                |r| r.get(0),
            )
            .optional()?;
        status.map(|s| NameStatus::parse(&s)).transpose()
    }

    pub fn is_taken(&self, name: &str) -> Result<bool> {
        Ok(self.name_status(name)?.is_some())
    }

    /// Append an event signed by a single authority.
    pub fn append(&mut self, event: Event, authority: &Authority) -> Result<u64> {
        let canonical = event.canonical_bytes();
        let sig = authority.sign(&canonical);
        self.append_with(event, sig)
    }

    /// Append with a pre-built (possibly multi-part) signature.
    /// Two-person control: the caller builds a multi-part sig and
    /// passes it here. The blob is stored as-is; it is not
    /// `canonical`, not Merkle-hashed.
    pub fn append_with(&mut self, event: Event, sig: Signature) -> Result<u64> {
        let canonical = event.canonical_bytes();
        let hash = event.hash();
        let sig_bytes = sig.to_bytes();
        let attribution = event.attribution.display();
        let seq = self.next_seq()?;

        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO events (seq, event_type, canonical, event_hash, signature, created_at, attribution)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                seq as i64,
                event.kind.type_name(),
                canonical,
                hash.as_slice(),
                sig_bytes.as_slice(),
                event.created_at,
                attribution,
            ],
        )?;

        match &event.kind {
            EventKind::Issued {
                name,
                name_type,
                authority_id,
                marking,
                ..
            } => {
                let key = normalize(name);
                tx.execute(
                    "INSERT INTO names (normalized, display, status, event_seq, name_type, authority_id, marking)
                     VALUES (?1, ?2, 'issued', ?3, ?4, ?5, ?6)",
                    params![key, name, seq as i64, name_type.as_str(), authority_id, marking.to_string()],
                )?;
            }
            EventKind::Retired {
                name,
                authority_id,
                ..
            } => {
                update_status(&tx, name, NameStatus::Retired, seq, authority_id)?;
            }
            EventKind::Revoked {
                name,
                authority_id,
                ..
            } => {
                update_status(&tx, name, NameStatus::Revoked, seq, authority_id)?;
            }
            EventKind::KeyRotated { .. } | EventKind::Attempt { .. } => {}
        }
        tx.commit()?;
        Ok(seq)
    }

    fn leaf_hashes(&self) -> Result<Vec<[u8; 32]>> {
        let mut stmt = self
            .conn
            .prepare("SELECT event_hash FROM events ORDER BY seq ASC")?;
        let rows = stmt.query_map([], |r| {
            let b: Vec<u8> = r.get(0)?;
            Ok(b)
        })?;
        let mut out = Vec::new();
        for row in rows {
            let b = row?;
            let arr: [u8; 32] = b
                .try_into()
                .map_err(|_| Error::LedgerCorrupt("event_hash not 32 bytes".into()))?;
            out.push(merkle::leaf_hash(&arr));
        }
        Ok(out)
    }

    pub fn root(&self) -> Result<[u8; 32]> {
        Ok(merkle::root(&self.leaf_hashes()?))
    }

    pub fn inclusion_proof(&self, seq: u64) -> Result<InclusionProof> {
        if seq == 0 {
            return Err(Error::MissingEvent(seq));
        }
        let leaves = self.leaf_hashes()?;
        let idx = (seq - 1) as usize;
        merkle::prove(&leaves, idx).ok_or(Error::MissingEvent(seq))
    }

    pub fn sign_root(&self, authority: &Authority) -> Result<SignedRoot> {
        let root = self.root()?;
        let leaf_count = self.len()?;
        let signed_at = now_rfc3339();
        let mut msg = Vec::new();
        msg.extend_from_slice(b"MERIDIAN-ROOT-v1\0");
        msg.extend_from_slice(&root);
        msg.extend_from_slice(&leaf_count.to_le_bytes());
        msg.extend_from_slice(signed_at.as_bytes());
        let signature = authority.sign(&msg);
        let sig_bytes = signature.to_bytes();
        let snap = SignedRoot {
            root: hex::encode(root),
            leaf_count,
            signed_at: signed_at.clone(),
            authority_id: authority.id.clone(),
            authority_pk: hex::encode(authority.public_key()),
            signature: hex::encode(&sig_bytes),
        };
        self.conn.execute(
            "INSERT INTO snapshots (seq, root, signature, signed_at, authority_id, authority_pk, leaf_count)
             VALUES ((SELECT COALESCE(MAX(seq), 0) + 1 FROM snapshots), ?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                root.as_slice(),
                sig_bytes.as_slice(),
                signed_at,
                authority.id,
                authority.public_key().as_slice(),
                leaf_count as i64,
            ],
        )?;
        Ok(snap)
    }

    pub fn verify_chain(&self) -> Result<()> {
        let mut stmt = self
            .conn
            .prepare("SELECT seq, canonical, event_hash, signature FROM events ORDER BY seq ASC")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        for (expect, row) in (1i64..).zip(rows) {
            let (seq, canonical, hash, _sig) = row?;
            if seq != expect {
                return Err(Error::LedgerCorrupt(format!(
                    "seq gap: expected {expect}, got {seq}"
                )));
            }
            let computed: [u8; 32] = Sha256::digest(&canonical).into();
            if hash.as_slice() != computed.as_slice() {
                return Err(Error::LedgerCorrupt(format!("hash mismatch at seq {seq}")));
            }
        }
        self.verify_name_index()?;
        Ok(())
    }

    fn verify_name_index(&self) -> Result<()> {
        let mut stmt = self
            .conn
            .prepare("SELECT normalized, status, event_seq FROM names")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        for row in rows {
            let (name, _status, seq) = row?;
            let exists: bool = self.conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM events WHERE seq = ?1)",
                [seq],
                |r| r.get(0),
            )?;
            if !exists {
                return Err(Error::LedgerCorrupt(format!(
                    "name {name} points at missing seq {seq}"
                )));
            }
        }
        Ok(())
    }

    /// Verify event signature(s) against `pks`. A two-part event
    /// (two-person control) requires two distinct pks.
    pub fn verify_event_signature(&self, seq: u64, pks: &[&[u8]]) -> Result<()> {
        let (canonical, sig): (Vec<u8>, Vec<u8>) = self.conn.query_row(
            "SELECT canonical, signature FROM events WHERE seq = ?1",
            [seq as i64],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let sig = Signature::from_bytes(&sig)?;
        crate::sig::verify(pks, &canonical, &sig)
    }

    pub fn issued_names(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT display FROM names WHERE status = 'issued' ORDER BY event_seq")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// One name's full record, or None if unknown.
    pub fn lookup(&self, name: &str) -> Result<Option<NameRecord>> {
        let key = normalize(name);
        let row = self
            .conn
            .query_row(
                "SELECT n.display, n.normalized, n.status, n.name_type, n.authority_id, n.event_seq, e.created_at, n.marking, e.attribution FROM names n JOIN events e ON n.event_seq = e.seq WHERE n.normalized = ?1",
                [&key],
                |r| {
                    Ok(NameRecord {
                        display: r.get(0)?,
                        normalized: r.get(1)?,
                        status: r.get(2)?,
                        name_type: r.get(3)?,
                        authority_id: r.get(4)?,
                        event_seq: r.get::<_, i64>(5)? as u64,
                        created_at: r.get(6)?,
                        marking: r.get(7)?,
                        attribution: r.get(8)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// Every name record, ordered by issue seq. The CLI filters
    /// in Rust — keeps SQL out of the trust path.
    pub fn name_records(&self) -> Result<Vec<NameRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT n.display, n.normalized, n.status, n.name_type, n.authority_id, n.event_seq, e.created_at, n.marking, e.attribution FROM names n JOIN events e ON n.event_seq = e.seq ORDER BY n.event_seq",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(NameRecord {
                display: r.get(0)?,
                normalized: r.get(1)?,
                status: r.get(2)?,
                name_type: r.get(3)?,
                authority_id: r.get(4)?,
                event_seq: r.get::<_, i64>(5)? as u64,
                created_at: r.get(6)?,
                marking: r.get(7)?,
                attribution: r.get(8)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Raw event rows for offline audit. Includes canonical,
    /// hash, signature — an auditor re-verifies without this binary.
    pub fn event_rows(&self) -> Result<Vec<EventRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT e.seq, e.event_type, e.created_at, n.display, n.marking, e.attribution, e.canonical, e.event_hash, e.signature FROM events e LEFT JOIN names n ON n.event_seq = e.seq ORDER BY e.seq",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(EventRow {
                seq: r.get::<_, i64>(0)? as u64,
                event_type: r.get(1)?,
                created_at: r.get(2)?,
                name: r.get(3)?,
                marking: r.get(4)?,
                attribution: r.get(5)?,
                canonical: hex::encode(r.get::<_, Vec<u8>>(6)?),
                event_hash: hex::encode(r.get::<_, Vec<u8>>(7)?),
                signature: hex::encode(r.get::<_, Vec<u8>>(8)?),
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Container marking of the ledger: max of every name's
    /// marking. Derived, not stored.
    pub fn aggregate_marking(&self) -> Result<crate::marking::Marking> {
        let mut stmt = self.conn.prepare("SELECT marking FROM names")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut agg = crate::marking::Marking::default();
        for r in rows {
            let m: crate::marking::Marking = r?
                .parse()
                .map_err(|e| crate::error::Error::LedgerCorrupt(format!("bad marking: {e}")))?;
            agg = agg.max(&m);
        }
        Ok(agg)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameRecord {
    pub display: String,
    pub normalized: String,
    pub status: String,
    pub name_type: String,
    pub authority_id: String,
    pub event_seq: u64,
    pub created_at: String,
    pub marking: String,
    pub attribution: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRow {
    pub seq: u64,
    pub event_type: String,
    pub created_at: String,
    pub name: Option<String>,
    pub marking: Option<String>,
    pub attribution: String,
    pub canonical: String,
    pub event_hash: String,
    pub signature: String,
}

const MAX_SCHEMA_VERSION: i64 = 2;

fn update_status(
    tx: &rusqlite::Transaction<'_>,
    name: &str,
    status: NameStatus,
    seq: u64,
    requester: &str,
) -> Result<()> {
    let key = normalize(name);
    let n = tx.execute(
        "UPDATE names SET status = ?1, event_seq = ?2 WHERE normalized = ?3 AND authority_id = ?4",
        params![status.as_str(), seq as i64, key, requester],
    )?;
    if n == 0 {
        let owner: Option<String> = tx
            .query_row(
                "SELECT authority_id FROM names WHERE normalized = ?1",
                [&key],
                |r| r.get(0),
            )
            .optional()?;
        return match owner {
            Some(owner) => Err(Error::NotOwner {
                name: name.to_string(),
                requester: requester.to_string(),
                owner,
            }),
            None => Err(Error::Parse(format!(
                "cannot {status:?} unknown name {name}"
            ))),
        };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EventKind;
    use crate::types::NameType;

    #[test]
    fn append_and_prove() {
        let mut led = Ledger::open_memory().unwrap();
        let auth = Authority::from_seed("DIA", [3u8; 32]);
        let ev = Event::new(EventKind::Issued {
            name: "GRANITE SPIRE".into(),
            name_type: NameType::Nickname,
            authority_id: "DIA".into(),
            authority_pk: hex::encode(auth.public_key()),
            pool_id: "p".into(),
            sequence: 1,
            nonce: 0,
            vrf_proof: "00".into(),
            vrf_output: "00".into(),
            indices: vec![1, 2],
            marking: crate::marking::Marking::default(),
        });
        let seq = led.append(ev, &auth).unwrap();
        assert_eq!(seq, 1);
        assert!(led.is_taken("granite  spire").unwrap());
        led.verify_chain().unwrap();
        led.verify_event_signature(seq, &[auth.public_key().as_slice()])
            .unwrap();
        let proof = led.inclusion_proof(seq).unwrap();
        assert!(merkle::verify_inclusion(&proof));
    }

    #[test]
    fn retire_quarantines() {
        let mut led = Ledger::open_memory().unwrap();
        let auth = Authority::from_seed("DIA", [3u8; 32]);
        led.append(
            Event::new(EventKind::Issued {
                name: "COPPER LEDGER".into(),
                name_type: NameType::Nickname,
                authority_id: "DIA".into(),
                authority_pk: hex::encode(auth.public_key()),
                pool_id: "p".into(),
                sequence: 1,
                nonce: 0,
                vrf_proof: "00".into(),
                vrf_output: "00".into(),
                indices: vec![0, 0],
                marking: crate::marking::Marking::default(),
            }),
            &auth,
        )
        .unwrap();
        led.append(
            Event::new(EventKind::Retired {
                name: "COPPER LEDGER".into(),
                reason: "complete".into(),
                authority_id: "DIA".into(),
            }),
            &auth,
        )
        .unwrap();
        assert_eq!(
            led.name_status("COPPER LEDGER").unwrap(),
            Some(NameStatus::Retired)
        );
        assert!(led.is_taken("COPPER LEDGER").unwrap());
    }

    #[test]
    fn attribution_column_stores_display_not_canonical() {
        let mut led = Ledger::open_memory().unwrap();
        let auth = Authority::from_seed("DIA", [3u8; 32]);
        let attr = crate::attribition::Attribution {
            user: "jdoe".into(),
            host: "ws001".into(),
            ip: None,
            hwid: Some("H".repeat(200)),
        };
        let mut ev = Event::new(EventKind::Issued {
            name: "GRANITE SPIRE".into(),
            name_type: NameType::Nickname,
            authority_id: "DIA".into(),
            authority_pk: hex::encode(auth.public_key()),
            pool_id: "p".into(),
            sequence: 1,
            nonce: 0,
            vrf_proof: "00".into(),
            vrf_output: "00".into(),
            indices: vec![1, 2],
            marking: crate::marking::Marking::default(),
        });
        ev.attribution = attr.clone();
        led.append(ev, &auth).unwrap();
        let rec = led.lookup("GRANITE SPIRE").unwrap().unwrap();
        assert_eq!(rec.attribution, attr.display());
        assert!(rec.attribution.contains("jdoe@ws001"));
        assert!(rec.attribution.contains(&"H".repeat(200)));
    }

    #[test]
    fn foreign_authority_cannot_retire() {
        let mut led = Ledger::open_memory().unwrap();
        let cia = Authority::from_seed("CIA", [1u8; 32]);
        let dia = Authority::from_seed("DIA", [3u8; 32]);
        led.append(
            Event::new(EventKind::Issued {
                name: "GRANITE SPIRE".into(),
                name_type: NameType::Nickname,
                authority_id: "CIA".into(),
                authority_pk: hex::encode(cia.public_key()),
                pool_id: "p".into(),
                sequence: 1,
                nonce: 0,
                vrf_proof: "00".into(),
                vrf_output: "00".into(),
                indices: vec![1, 2],
                marking: crate::marking::Marking::default(),
            }),
            &cia,
        )
        .unwrap();
        let err = led
            .append(
                Event::new(EventKind::Retired {
                    name: "GRANITE SPIRE".into(),
                    reason: "complete".into(),
                    authority_id: "DIA".into(),
                }),
                &dia,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            Error::NotOwner {
                ref name,
                ref requester,
                ref owner
            } if name == "GRANITE SPIRE" && requester == "DIA" && owner == "CIA"
        ));
        assert_eq!(
            led.name_status("GRANITE SPIRE").unwrap(),
            Some(NameStatus::Issued)
        );
    }

    #[test]
    fn refuse_schema_too_new() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.sqlite");
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch("PRAGMA user_version = 99").unwrap();
        }
        match Ledger::open(&path) {
            Err(Error::SchemaTooNew {
                found: 99,
                max: MAX_SCHEMA_VERSION,
            }) => {}
            Err(e) => panic!("wrong error: {e}"),
            Ok(_) => panic!("stale binary must refuse a newer schema"),
        }
    }
}
