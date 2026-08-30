use crate::authority::{self, Authority};
use crate::error::{Error, Result};
use crate::events::{now_rfc3339, Event, EventKind, NameStatus};
use crate::merkle::{self, InclusionProof};
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
                created_at TEXT NOT NULL
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

    pub fn append(&mut self, event: Event, authority: &Authority) -> Result<u64> {
        let canonical = event.canonical_bytes();
        let hash = event.hash();
        let sig = authority.sign(&canonical);
        let seq = self.next_seq()?;

        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO events (seq, event_type, canonical, event_hash, signature, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                seq as i64,
                event.kind.type_name(),
                canonical,
                hash.as_slice(),
                sig.as_slice(),
                event.created_at,
            ],
        )?;

        match &event.kind {
            EventKind::Issued {
                name,
                name_type,
                authority_id,
                ..
            } => {
                let key = normalize(name);
                tx.execute(
                    "INSERT INTO names (normalized, display, status, event_seq, name_type, authority_id)
                     VALUES (?1, ?2, 'issued', ?3, ?4, ?5)",
                    params![key, name, seq as i64, name_type.as_str(), authority_id],
                )?;
            }
            EventKind::Retired { name, .. } => {
                update_status(&tx, name, NameStatus::Retired, seq)?;
            }
            EventKind::Revoked { name, .. } => {
                update_status(&tx, name, NameStatus::Revoked, seq)?;
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
        let snap = SignedRoot {
            root: hex::encode(root),
            leaf_count,
            signed_at: signed_at.clone(),
            authority_id: authority.id.clone(),
            authority_pk: hex::encode(authority.public_key()),
            signature: hex::encode(signature),
        };
        self.conn.execute(
            "INSERT INTO snapshots (seq, root, signature, signed_at, authority_id, authority_pk, leaf_count)
             VALUES ((SELECT COALESCE(MAX(seq), 0) + 1 FROM snapshots), ?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                root.as_slice(),
                signature.as_slice(),
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

    pub fn verify_event_signature(&self, seq: u64, pk: &[u8; 32]) -> Result<()> {
        let (canonical, sig): (Vec<u8>, Vec<u8>) = self.conn.query_row(
            "SELECT canonical, signature FROM events WHERE seq = ?1",
            [seq as i64],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let sig: [u8; 64] = sig
            .try_into()
            .map_err(|_| Error::LedgerCorrupt("signature not 64 bytes".into()))?;
        authority::verify_signature(pk, &canonical, &sig)
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
}

fn update_status(
    tx: &rusqlite::Transaction<'_>,
    name: &str,
    status: NameStatus,
    seq: u64,
) -> Result<()> {
    let key = normalize(name);
    let n = tx.execute(
        "UPDATE names SET status = ?1, event_seq = ?2 WHERE normalized = ?3",
        params![status.as_str(), seq as i64, key],
    )?;
    if n == 0 {
        return Err(Error::Parse(format!(
            "cannot {status:?} unknown name {name}"
        )));
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
        });
        let seq = led.append(ev, &auth).unwrap();
        assert_eq!(seq, 1);
        assert!(led.is_taken("granite  spire").unwrap());
        led.verify_chain().unwrap();
        led.verify_event_signature(seq, &auth.public_key()).unwrap();
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
}
