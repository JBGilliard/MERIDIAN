use crate::authority::Authority;
use crate::error::{Error, Result};
use crate::events::{now_rfc3339, Event, EventKind, NameStatus};
use crate::marking::{Level, Marking};
use crate::merkle::{self, InclusionProof};
use crate::policy::Policy;
use crate::program::{
    Compartment, Control, ControlKind, Program, ProgramEvent, ProgramSet, SapType,
};
use crate::sig::{Signature, Signer};
use crate::types::{normalize, NameType};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

pub const NAMES_FILE: &str = "names.sqlite";
pub const BINDINGS_FILE: &str = "bindings.sqlite";
pub const LEGACY_FILE: &str = "ledger.sqlite";

pub struct Ledger {
    names: Connection,
    bindings: Option<Connection>,
}

impl Ledger {
    pub fn open(data_dir: &Path, policy: &Policy) -> Result<Self> {
        if data_dir.join(LEGACY_FILE).exists() {
            return Err(Error::LegacyLedger);
        }
        std::fs::create_dir_all(data_dir)?;
        let names = Connection::open(data_dir.join(NAMES_FILE))?;
        init_names(&names)?;
        let bindings = if policy.allow_persist_markings {
            let conn = Connection::open(data_dir.join(BINDINGS_FILE))?;
            init_bindings(&conn)?;
            Some(conn)
        } else {
            None
        };
        Ok(Self { names, bindings })
    }

    pub fn open_memory() -> Result<Self> {
        let names = Connection::open_in_memory()?;
        init_names(&names)?;
        Ok(Self {
            names,
            bindings: None,
        })
    }

    pub fn open_memory_with_bindings() -> Result<Self> {
        let names = Connection::open_in_memory()?;
        init_names(&names)?;
        let bindings = Connection::open_in_memory()?;
        init_bindings(&bindings)?;
        Ok(Self {
            names,
            bindings: Some(bindings),
        })
    }

    /// Combined `ledger.sqlite` is not converted. Quarantine it so a later
    /// `open` can start a clean names.sqlite. Local ledgers are disposable.
    pub fn migrate(data_dir: &Path) -> Result<()> {
        let old = data_dir.join(LEGACY_FILE);
        if !old.exists() {
            return Ok(());
        }
        let dest = data_dir.join("ledger.sqlite.refused");
        if dest.exists() {
            std::fs::remove_file(&dest)?;
        }
        std::fs::rename(&old, dest)?;
        Ok(())
    }

    pub fn has_bindings(&self) -> bool {
        self.bindings.is_some()
    }

    /// Open an existing bindings.sqlite for read. Does not create the file.
    /// Export `--bindings` uses this when persist is off for the session.
    pub fn attach_bindings_read(&mut self, data_dir: &Path) -> Result<()> {
        if self.bindings.is_some() {
            return Ok(());
        }
        let path = data_dir.join(BINDINGS_FILE);
        if !path.exists() {
            return Err(Error::BindingsClosed);
        }
        let conn = Connection::open(&path)?;
        init_bindings(&conn)?;
        self.bindings = Some(conn);
        Ok(())
    }

    pub fn next_seq(&self) -> Result<u64> {
        next_seq(&self.names, "events")
    }

    pub fn len(&self) -> Result<u64> {
        table_len(&self.names, "events")
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    pub fn bindings_len(&self) -> Result<u64> {
        let bind = self.bindings_conn()?;
        table_len(bind, "binding_events")
    }

    pub fn name_status(&self, name: &str) -> Result<Option<NameStatus>> {
        let key = normalize(name);
        let status: Option<String> = self
            .names
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

    fn bindings_conn(&self) -> Result<&Connection> {
        self.bindings.as_ref().ok_or(Error::BindingsClosed)
    }

    /// Append an event signed by a single signer.
    pub fn append(&mut self, event: Event, signer: &dyn Signer) -> Result<u64> {
        if event.kind.is_program() {
            let sig = signer.sign(&event.canonical_binding_bytes());
            return self.append_program(event, sig);
        }
        let name_sig = signer.sign(&event.canonical_u_bytes());
        let bind_sig = if self.bindings.is_some() && matches!(event.kind, EventKind::Issued { .. })
        {
            Some(signer.sign(&event.canonical_binding_bytes()))
        } else {
            None
        };
        let seq = self.append_name(&event, name_sig)?;
        if let Some(sig) = bind_sig {
            self.append_issued_binding(seq, &event, sig)?;
        }
        Ok(seq)
    }

    /// Append with a pre-built (possibly multi-part) signature.
    /// Two-person control: the caller builds a multi-part sig and
    /// passes it here. The blob is stored as-is; it is not
    /// `canonical`, not Merkle-hashed. Program events treat `sig` as
    /// the bindings-chain signature.
    pub fn append_with(&mut self, event: Event, sig: Signature) -> Result<u64> {
        if event.kind.is_program() {
            return self.append_program(event, sig);
        }
        self.append_name(&event, sig)
    }

    fn precheck_issued(&self, event: &Event) -> Result<(Option<String>, Option<String>)> {
        let EventKind::Issued {
            program_pid,
            compartment_id,
            ..
        } = &event.kind
        else {
            return Ok((None, None));
        };
        let (pid, cid) = bind_keys(program_pid.as_deref(), compartment_id.as_deref())?;
        if pid.is_some() && self.bindings.is_none() {
            return Err(Error::BindingsClosed);
        }
        if let Some(ref pid) = pid {
            let bind = self.bindings_conn()?;
            require_program(bind, pid)?;
            if let Some(ref cid) = cid {
                require_compartment(bind, pid, cid)?;
            }
        }
        Ok((pid, cid))
    }

    fn append_name(&mut self, event: &Event, sig: Signature) -> Result<u64> {
        self.precheck_issued(event)?;
        let canonical = event.canonical_u_bytes();
        let hash = event.hash_u();
        let sig_bytes = sig.to_bytes();
        let seq = next_seq(&self.names, "events")?;
        let tx = self.names.transaction()?;
        tx.execute(
            "INSERT INTO events (seq, event_type, canonical, event_hash, signature, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                seq as i64,
                event.kind.type_name(),
                canonical,
                hash.as_slice(),
                sig_bytes.as_slice(),
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
                    "INSERT INTO names (normalized, display, status, event_seq, issued_seq, name_type, authority_id)
                     VALUES (?1, ?2, 'issued', ?3, ?3, ?4, ?5)",
                    params![key, name, seq as i64, name_type.as_str(), authority_id],
                )?;
            }
            EventKind::Retired {
                name, authority_id, ..
            } => {
                update_status(&tx, name, NameStatus::Retired, seq, authority_id)?;
            }
            EventKind::Revoked {
                name, authority_id, ..
            } => {
                update_status(&tx, name, NameStatus::Revoked, seq, authority_id)?;
            }
            EventKind::ProgramCreated(_)
            | EventKind::CompartmentAdded(_)
            | EventKind::ProgramControlsChanged { .. } => {
                return Err(Error::Parse(
                    "program events belong on the bindings chain".into(),
                ));
            }
            EventKind::KeyRotated { .. } | EventKind::Attempt { .. } => {}
        }
        tx.commit()?;
        Ok(seq)
    }

    fn append_program(&mut self, event: Event, sig: Signature) -> Result<u64> {
        let bind = self.bindings.as_mut().ok_or(Error::BindingsClosed)?;
        let canonical = event.canonical_binding_bytes();
        let hash = event.hash_binding();
        let sig_bytes = sig.to_bytes();
        let seq = next_seq(bind, "binding_events")?;
        let tx = bind.transaction()?;
        tx.execute(
            "INSERT INTO binding_events (seq, event_type, names_seq, canonical, event_hash, signature, created_at)
             VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6)",
            params![
                seq as i64,
                event.kind.type_name(),
                canonical,
                hash.as_slice(),
                sig_bytes.as_slice(),
                event.created_at,
            ],
        )?;
        match &event.kind {
            EventKind::ProgramCreated(p) => persist_program_created(&tx, p)?,
            EventKind::CompartmentAdded(c) => persist_compartment_added(&tx, c)?,
            EventKind::ProgramControlsChanged {
                program_pid,
                compartment_id,
                add,
                remove,
            } => {
                persist_controls_changed(&tx, program_pid, compartment_id.as_deref(), add, remove)?
            }
            _ => {
                return Err(Error::Parse("append_program: not a program event".into()));
            }
        }
        tx.commit()?;
        Ok(seq)
    }

    fn append_issued_binding(
        &mut self,
        names_seq: u64,
        event: &Event,
        sig: Signature,
    ) -> Result<()> {
        let EventKind::Issued {
            marking,
            program_pid,
            compartment_id,
            ..
        } = &event.kind
        else {
            return Ok(());
        };
        let (pid, cid) = bind_keys(program_pid.as_deref(), compartment_id.as_deref())?;
        let bind = self.bindings.as_mut().ok_or(Error::BindingsClosed)?;
        let canonical = event.canonical_binding_bytes();
        let hash = event.hash_binding();
        let sig_bytes = sig.to_bytes();
        let seq = next_seq(bind, "binding_events")?;
        let tx = bind.transaction()?;
        tx.execute(
            "INSERT INTO binding_events (seq, event_type, names_seq, canonical, event_hash, signature, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                seq as i64,
                event.kind.type_name(),
                names_seq as i64,
                canonical,
                hash.as_slice(),
                sig_bytes.as_slice(),
                event.created_at,
            ],
        )?;
        tx.execute(
            "INSERT INTO bindings (names_seq, marking, program_pid, compartment_id, attribution)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                names_seq as i64,
                marking.to_string(),
                pid,
                cid,
                event.attribution.display(),
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn leaf_hashes(&self) -> Result<Vec<[u8; 32]>> {
        leaf_hashes(&self.names, "events")
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
        let snap = sign_conn_root(&self.names, authority, b"MERIDIAN-ROOT-v1\0", "events")?;
        if let Some(ref bind) = self.bindings {
            let _ = sign_conn_root(
                bind,
                authority,
                b"MERIDIAN-BIND-ROOT-v1\0",
                "binding_events",
            )?;
        }
        Ok(snap)
    }

    pub fn verify_chain(&self) -> Result<()> {
        verify_event_table(&self.names, "events")?;
        self.verify_name_index()?;
        if let Some(ref bind) = self.bindings {
            verify_event_table(bind, "binding_events")?;
            self.verify_binding_index()?;
        }
        Ok(())
    }

    fn verify_name_index(&self) -> Result<()> {
        let mut raw = Vec::new();
        {
            let mut stmt = self
                .names
                .prepare("SELECT normalized, event_seq, issued_seq FROM names")?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?;
            for row in rows {
                raw.push(row?);
            }
        }
        for (name, seq, issued_seq) in raw {
            for (label, s) in [("event_seq", seq), ("issued_seq", issued_seq)] {
                let exists: bool = self.names.query_row(
                    "SELECT EXISTS(SELECT 1 FROM events WHERE seq = ?1)",
                    [s],
                    |r| r.get(0),
                )?;
                if !exists {
                    return Err(Error::LedgerCorrupt(format!(
                        "name {name} {label} points at missing seq {s}"
                    )));
                }
            }
        }
        Ok(())
    }

    fn verify_binding_index(&self) -> Result<()> {
        let Some(bind) = &self.bindings else {
            return Ok(());
        };
        let mut raw = Vec::new();
        {
            let mut stmt =
                bind.prepare("SELECT names_seq, program_pid, compartment_id FROM bindings")?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            })?;
            for row in rows {
                raw.push(row?);
            }
        }
        for (names_seq, pid, cid) in raw {
            let exists: bool = self.names.query_row(
                "SELECT EXISTS(SELECT 1 FROM events WHERE seq = ?1)",
                [names_seq],
                |r| r.get(0),
            )?;
            if !exists {
                return Err(Error::LedgerCorrupt(format!(
                    "binding names_seq {names_seq} missing from names events"
                )));
            }
            if let Some(pid) = opt_key(pid.as_deref()) {
                require_program(bind, &pid).map_err(|_| {
                    Error::LedgerCorrupt(format!(
                        "binding seq {names_seq} bound to missing program {pid}"
                    ))
                })?;
                if let Some(cid) = opt_key(cid.as_deref()) {
                    require_compartment(bind, &pid, &cid).map_err(|_| {
                        Error::LedgerCorrupt(format!(
                            "binding seq {names_seq} bound to missing compartment {cid} on {pid}"
                        ))
                    })?;
                }
            }
        }
        Ok(())
    }

    /// Verify event signature(s) against `pks`. A two-part event
    /// (two-person control) requires two distinct pks.
    pub fn verify_event_signature(&self, seq: u64, pks: &[&[u8]]) -> Result<()> {
        let (canonical, sig): (Vec<u8>, Vec<u8>) = self.names.query_row(
            "SELECT canonical, signature FROM events WHERE seq = ?1",
            [seq as i64],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let sig = Signature::from_bytes(&sig)?;
        crate::sig::verify(pks, &canonical, &sig)
    }

    pub fn issued_names(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .names
            .prepare("SELECT display FROM names WHERE status = 'issued' ORDER BY event_seq")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn program(&self, pid: &str) -> Result<Option<Program>> {
        let bind = self.bindings_conn()?;
        let pid = pid_key(pid);
        let row = bind
            .query_row(
                "SELECT pid, nickname, codeword, sap_type, level, authority_id FROM programs WHERE pid = ?1",
                [&pid],
                program_row,
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some(t) => Ok(Some(assemble_program(bind, t)?)),
        }
    }

    /// The display-name namespace is global across all types and programs.
    /// Compartment nicknames/codewords are steward-assigned (not VRF-minted),
    /// so they must be checked against the `names` table AND every other
    /// compartment's nickname/codeword to preserve the deconfliction invariant.
    pub fn is_display_name_taken(&self, name: &str) -> Result<bool> {
        let key = normalize(name);
        if key.is_empty() {
            return Ok(false);
        }
        if self.name_status(&key)?.is_some() {
            return Ok(true);
        }
        let Some(bind) = &self.bindings else {
            return Ok(false);
        };
        let exists: bool = bind.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM compartments
                WHERE UPPER(nickname) = ?1
                   OR UPPER(codeword) = ?1
            )",
            [&key],
            |r| r.get(0),
        )?;
        Ok(exists)
    }

    pub fn programs(&self) -> Result<Vec<Program>> {
        let bind = self.bindings_conn()?;
        let mut raw = Vec::new();
        {
            let mut stmt = bind.prepare(
                "SELECT pid, nickname, codeword, sap_type, level, authority_id FROM programs ORDER BY pid",
            )?;
            let rows = stmt.query_map([], program_row)?;
            for row in rows {
                raw.push(row?);
            }
        }
        let mut out = Vec::new();
        for t in raw {
            out.push(assemble_program(bind, t)?);
        }
        Ok(out)
    }

    pub fn compartment(&self, pid: &str, id: &str) -> Result<Option<Compartment>> {
        let bind = self.bindings_conn()?;
        let pid = pid_key(pid);
        let id = pid_key(id);
        let row = bind
            .query_row(
                "SELECT program_pid, id, nickname, codeword, parent_id, level FROM compartments WHERE program_pid = ?1 AND id = ?2",
                params![pid, id],
                compartment_row,
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some(t) => Ok(Some(assemble_compartment(bind, t)?)),
        }
    }

    pub fn compartments(&self, pid: &str) -> Result<Vec<Compartment>> {
        self.load_compartments(Some(&pid_key(pid)))
    }

    /// Fold of program/compartment tables. Same shape as event materialization.
    /// Empty when bindings are closed (U-only read).
    pub fn program_set(&self) -> Result<ProgramSet> {
        if self.bindings.is_none() {
            return Ok(ProgramSet::new());
        }
        let mut set = ProgramSet::new();
        for p in self.programs()? {
            set.apply(ProgramEvent::Created(p))
                .map_err(|e| Error::LedgerCorrupt(format!("programs index: {e}")))?;
        }
        for c in self.load_compartments(None)? {
            set.apply(ProgramEvent::CompartmentAdded(c))
                .map_err(|e| Error::LedgerCorrupt(format!("compartments index: {e}")))?;
        }
        Ok(set)
    }

    fn load_compartments(&self, pid: Option<&str>) -> Result<Vec<Compartment>> {
        let bind = self.bindings_conn()?;
        let mut raw = Vec::new();
        {
            let sql = match pid {
                Some(_) => {
                    "SELECT program_pid, id, nickname, codeword, parent_id, level FROM compartments WHERE program_pid = ?1 ORDER BY id"
                }
                None => {
                    "SELECT program_pid, id, nickname, codeword, parent_id, level FROM compartments ORDER BY program_pid, id"
                }
            };
            let mut stmt = bind.prepare(sql)?;
            match pid {
                Some(pid) => {
                    let rows = stmt.query_map([pid], compartment_row)?;
                    for row in rows {
                        raw.push(row?);
                    }
                }
                None => {
                    let rows = stmt.query_map([], compartment_row)?;
                    for row in rows {
                        raw.push(row?);
                    }
                }
            }
        }
        let mut out = Vec::new();
        for t in raw {
            out.push(assemble_compartment(bind, t)?);
        }
        Ok(out)
    }

    /// One name's full record, or None if unknown.
    pub fn lookup(&self, name: &str) -> Result<Option<NameRecord>> {
        let key = normalize(name);
        let row = self
            .names
            .query_row(
                "SELECT n.display, n.normalized, n.status, n.name_type, n.authority_id, n.event_seq, e.created_at, n.issued_seq FROM names n JOIN events e ON n.event_seq = e.seq WHERE n.normalized = ?1",
                [&key],
                names_record_row,
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some((mut rec, issued_seq)) => {
                self.overlay_binding(&mut rec, issued_seq)?;
                self.resolve_name_marking(&mut rec)?;
                Ok(Some(rec))
            }
        }
    }

    /// Every name record, ordered by issue seq. The CLI filters
    /// in Rust — keeps SQL out of the trust path.
    pub fn name_records(&self) -> Result<Vec<NameRecord>> {
        let mut stmt = self.names.prepare(
            "SELECT n.display, n.normalized, n.status, n.name_type, n.authority_id, n.event_seq, e.created_at, n.issued_seq FROM names n JOIN events e ON n.event_seq = e.seq ORDER BY n.issued_seq",
        )?;
        let rows = stmt.query_map([], names_record_row)?;
        let mut out = Vec::new();
        let mut issued = Vec::new();
        for r in rows {
            let (rec, issued_seq) = r?;
            issued.push(issued_seq);
            out.push(rec);
        }
        drop(stmt);
        if let Some(bind) = &self.bindings {
            let map = load_bindings_map(bind)?;
            for (rec, issued_seq) in out.iter_mut().zip(issued.iter()) {
                if let Some(b) = map.get(issued_seq) {
                    apply_binding(rec, b);
                }
            }
        }
        let set = self.program_set()?;
        for rec in &mut out {
            resolve_name_marking_with(&set, rec)?;
        }
        Ok(out)
    }

    fn overlay_binding(&self, rec: &mut NameRecord, issued_seq: u64) -> Result<()> {
        let Some(bind) = &self.bindings else {
            return Ok(());
        };
        if let Some(b) = binding_for(bind, issued_seq)? {
            apply_binding(rec, &b);
        }
        Ok(())
    }

    fn resolve_name_marking(&self, rec: &mut NameRecord) -> Result<()> {
        if rec.program_pid.is_some() && name_derives(&rec.name_type) {
            resolve_name_marking_with(&self.program_set()?, rec)?;
        }
        Ok(())
    }

    /// Unclassified names-chain rows. No marking, attribution, or program fields.
    pub fn name_rows(&self) -> Result<Vec<NameRow>> {
        let mut stmt = self.names.prepare(
            "SELECT e.seq, e.event_type, e.created_at, n.display, e.canonical, e.event_hash, e.signature FROM events e LEFT JOIN names n ON n.event_seq = e.seq ORDER BY e.seq",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(NameRow {
                seq: r.get::<_, i64>(0)? as u64,
                event_type: r.get(1)?,
                created_at: r.get(2)?,
                name: r.get(3)?,
                canonical: hex::encode(r.get::<_, Vec<u8>>(4)?),
                event_hash: hex::encode(r.get::<_, Vec<u8>>(5)?),
                signature: hex::encode(r.get::<_, Vec<u8>>(6)?),
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Classified bindings-chain rows. BindingsClosed when the store is not open.
    pub fn binding_rows(&self) -> Result<Vec<BindingRow>> {
        let bind = self.bindings_conn()?;
        let mut stmt = bind.prepare(
            "SELECT e.seq, e.event_type, e.created_at, e.names_seq, b.marking, b.program_pid, b.compartment_id, b.attribution, e.canonical, e.event_hash, e.signature
             FROM binding_events e
             LEFT JOIN bindings b ON b.names_seq = e.names_seq
             ORDER BY e.seq",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(BindingRow {
                seq: r.get::<_, i64>(0)? as u64,
                event_type: r.get(1)?,
                created_at: r.get(2)?,
                names_seq: r.get::<_, Option<i64>>(3)?.map(|n| n as u64),
                marking: r.get(4)?,
                program_pid: r.get(5)?,
                compartment_id: r.get(6)?,
                attribution: r.get::<_, Option<String>>(7)?.unwrap_or_default(),
                canonical: hex::encode(r.get::<_, Vec<u8>>(8)?),
                event_hash: hex::encode(r.get::<_, Vec<u8>>(9)?),
                signature: hex::encode(r.get::<_, Vec<u8>>(10)?),
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Container marking of the ledger: max of every name's
    /// marking. Program-bound names derive from current controls;
    /// free-standing names use the stored string. U-only when bindings closed.
    pub fn aggregate_marking(&self) -> Result<Marking> {
        let Some(bind) = &self.bindings else {
            return Ok(Marking::default());
        };
        let set = self.program_set()?;
        let mut stmt = bind.prepare("SELECT marking, program_pid, compartment_id FROM bindings")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })?;
        let mut agg = Marking::default();
        for row in rows {
            let (stored, pid, cid) = row?;
            let pid = opt_key(pid.as_deref());
            let cid = opt_key(cid.as_deref());
            let m = if let Some(pid) = pid {
                set.derive_marking(&pid, cid.as_deref())
                    .map_err(|e| Error::LedgerCorrupt(format!("derive marking: {e}")))?
            } else {
                let s = stored
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "U".into());
                Marking::from_stored(&s)
                    .map_err(|e| Error::LedgerCorrupt(format!("bad marking: {e}")))?
            };
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
    #[serde(default)]
    pub program_pid: Option<String>,
    #[serde(default)]
    pub compartment_id: Option<String>,
}

/// Names-chain export row. Schema cannot carry classified fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameRow {
    pub seq: u64,
    pub event_type: String,
    pub created_at: String,
    pub name: Option<String>,
    pub canonical: String,
    pub event_hash: String,
    pub signature: String,
}

/// Bindings-chain export row. Born classified; caller redacts attribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindingRow {
    pub seq: u64,
    pub event_type: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub names_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marking: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_pid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compartment_id: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub attribution: String,
    pub canonical: String,
    pub event_hash: String,
    pub signature: String,
}

const MAX_SCHEMA_VERSION: i64 = 5;

const NAMES_DDL: &str = "
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
    issued_seq INTEGER NOT NULL,
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
";

const BINDINGS_DDL: &str = "
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS binding_events (
    seq INTEGER PRIMARY KEY,
    event_type TEXT NOT NULL,
    names_seq INTEGER,
    canonical BLOB NOT NULL,
    event_hash BLOB NOT NULL,
    signature BLOB NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bindings (
    names_seq INTEGER PRIMARY KEY,
    marking TEXT NOT NULL DEFAULT 'U',
    program_pid TEXT,
    compartment_id TEXT,
    attribution TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS programs (
    pid TEXT PRIMARY KEY,
    nickname TEXT NOT NULL,
    codeword TEXT,
    sap_type TEXT NOT NULL,
    level TEXT NOT NULL,
    authority_id TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS program_controls (
    program_pid TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (program_pid, kind, value),
    FOREIGN KEY (program_pid) REFERENCES programs(pid)
);
CREATE TABLE IF NOT EXISTS compartments (
    program_pid TEXT NOT NULL,
    id TEXT NOT NULL,
    nickname TEXT NOT NULL,
    codeword TEXT,
    parent_id TEXT,
    level TEXT,
    PRIMARY KEY (program_pid, id),
    FOREIGN KEY (program_pid) REFERENCES programs(pid)
);
CREATE TABLE IF NOT EXISTS compartment_controls (
    program_pid TEXT NOT NULL,
    compartment_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (program_pid, compartment_id, kind, value),
    FOREIGN KEY (program_pid, compartment_id)
        REFERENCES compartments(program_pid, id)
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
CREATE TRIGGER IF NOT EXISTS binding_events_no_update
    BEFORE UPDATE ON binding_events
    BEGIN SELECT RAISE(ABORT, 'binding_events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS binding_events_no_delete
    BEFORE DELETE ON binding_events
    BEGIN SELECT RAISE(ABORT, 'binding_events are append-only'); END;
";

fn init_names(conn: &Connection) -> Result<()> {
    conn.execute_batch(NAMES_DDL)?;
    set_schema(conn)
}

fn init_bindings(conn: &Connection) -> Result<()> {
    conn.execute_batch(BINDINGS_DDL)?;
    set_schema(conn)
}

fn set_schema(conn: &Connection) -> Result<()> {
    let current: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if current > MAX_SCHEMA_VERSION {
        return Err(Error::SchemaTooNew {
            found: current,
            max: MAX_SCHEMA_VERSION,
        });
    }
    if current > 0 && current < MAX_SCHEMA_VERSION {
        return Err(Error::LegacyLedger);
    }
    if current == 0 {
        conn.execute_batch(&format!("PRAGMA user_version = {MAX_SCHEMA_VERSION}"))?;
    }
    Ok(())
}

fn next_seq(conn: &Connection, table: &str) -> Result<u64> {
    let sql = format!("SELECT COALESCE(MAX(seq), 0) FROM {table}");
    let n: i64 = conn.query_row(&sql, [], |r| r.get(0))?;
    Ok((n as u64) + 1)
}

fn table_len(conn: &Connection, table: &str) -> Result<u64> {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    let n: i64 = conn.query_row(&sql, [], |r| r.get(0))?;
    Ok(n as u64)
}

fn leaf_hashes(conn: &Connection, table: &str) -> Result<Vec<[u8; 32]>> {
    let sql = format!("SELECT event_hash FROM {table} ORDER BY seq ASC");
    let mut stmt = conn.prepare(&sql)?;
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

fn verify_event_table(conn: &Connection, table: &str) -> Result<()> {
    let sql = format!("SELECT seq, canonical, event_hash FROM {table} ORDER BY seq ASC");
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, Vec<u8>>(1)?,
            r.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    for (expect, row) in (1i64..).zip(rows) {
        let (seq, canonical, hash) = row?;
        if seq != expect {
            return Err(Error::LedgerCorrupt(format!(
                "{table} seq gap: expected {expect}, got {seq}"
            )));
        }
        let computed = crate::crypto::sha256(&[&canonical]);
        if hash.as_slice() != computed.as_slice() {
            return Err(Error::LedgerCorrupt(format!(
                "{table} hash mismatch at seq {seq}"
            )));
        }
    }
    Ok(())
}

fn sign_conn_root(
    conn: &Connection,
    authority: &Authority,
    ctx: &[u8],
    events_table: &str,
) -> Result<SignedRoot> {
    let root = merkle::root(&leaf_hashes(conn, events_table)?);
    let leaf_count = table_len(conn, events_table)?;
    let signed_at = now_rfc3339();
    let mut msg = Vec::new();
    msg.extend_from_slice(ctx);
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
    conn.execute(
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

struct BindingOverlay {
    marking: String,
    attribution: String,
    program_pid: Option<String>,
    compartment_id: Option<String>,
}

fn binding_for(conn: &Connection, names_seq: u64) -> Result<Option<BindingOverlay>> {
    conn.query_row(
        "SELECT marking, attribution, program_pid, compartment_id FROM bindings WHERE names_seq = ?1",
        [names_seq as i64],
        |r| {
            Ok(BindingOverlay {
                marking: r.get(0)?,
                attribution: r.get(1)?,
                program_pid: r.get(2)?,
                compartment_id: r.get(3)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

fn load_bindings_map(conn: &Connection) -> Result<HashMap<u64, BindingOverlay>> {
    let mut stmt = conn.prepare(
        "SELECT names_seq, marking, attribution, program_pid, compartment_id FROM bindings",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)? as u64,
            BindingOverlay {
                marking: r.get(1)?,
                attribution: r.get(2)?,
                program_pid: r.get(3)?,
                compartment_id: r.get(4)?,
            },
        ))
    })?;
    let mut out = HashMap::new();
    for row in rows {
        let (seq, b) = row?;
        out.insert(seq, b);
    }
    Ok(out)
}

fn apply_binding(rec: &mut NameRecord, b: &BindingOverlay) {
    rec.marking = if b.marking.is_empty() {
        "U".into()
    } else {
        b.marking.clone()
    };
    rec.attribution = b.attribution.clone();
    rec.program_pid = opt_key(b.program_pid.as_deref());
    rec.compartment_id = opt_key(b.compartment_id.as_deref());
}

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

fn pid_key(s: &str) -> String {
    s.trim().to_ascii_uppercase()
}

fn opt_key(s: Option<&str>) -> Option<String> {
    s.map(pid_key).filter(|s| !s.is_empty())
}

fn bind_keys(
    program_pid: Option<&str>,
    compartment_id: Option<&str>,
) -> Result<(Option<String>, Option<String>)> {
    let pid = opt_key(program_pid);
    let cid = opt_key(compartment_id);
    if cid.is_some() && pid.is_none() {
        return Err(Error::Parse("compartment_id requires program_pid".into()));
    }
    Ok((pid, cid))
}

fn name_derives(name_type: &str) -> bool {
    matches!(
        name_type.parse::<NameType>(),
        Ok(NameType::CodeWord | NameType::Cryptonym)
    )
}

fn require_program(conn: &Connection, pid: &str) -> Result<()> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM programs WHERE pid = ?1)",
        [pid],
        |r| r.get(0),
    )?;
    if exists {
        Ok(())
    } else {
        Err(Error::Parse(format!("unknown program: {pid}")))
    }
}

fn require_compartment(conn: &Connection, pid: &str, cid: &str) -> Result<()> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM compartments WHERE program_pid = ?1 AND id = ?2)",
        params![pid, cid],
        |r| r.get(0),
    )?;
    if exists {
        Ok(())
    } else {
        Err(Error::Parse(format!(
            "unknown compartment {cid} on program {pid}"
        )))
    }
}

fn persist_program_created(tx: &rusqlite::Transaction<'_>, program: &Program) -> Result<()> {
    let pid = pid_key(&program.pid);
    if pid.is_empty() {
        return Err(Error::Parse("program pid is empty".into()));
    }
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM programs WHERE pid = ?1)",
        [&pid],
        |r| r.get(0),
    )?;
    if exists {
        return Err(Error::Parse(format!("program already exists: {pid}")));
    }
    let nickname = normalize(&program.nickname);
    let codeword = program
        .codeword
        .as_deref()
        .map(normalize)
        .filter(|s| !s.is_empty());
    tx.execute(
        "INSERT INTO programs (pid, nickname, codeword, sap_type, level, authority_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            pid,
            nickname,
            codeword,
            program.sap_type.as_str(),
            program.level.as_str(),
            program.authority_id.trim(),
        ],
    )?;
    apply_control_delta(tx, &pid, None, &program.controls, &[])?;
    Ok(())
}

fn persist_compartment_added(tx: &rusqlite::Transaction<'_>, c: &Compartment) -> Result<()> {
    let pid = pid_key(&c.program_pid);
    let id = pid_key(&c.id);
    if id.is_empty() {
        return Err(Error::Parse("compartment id is empty".into()));
    }
    require_program(tx, &pid)?;
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM compartments WHERE program_pid = ?1 AND id = ?2)",
        params![pid, id],
        |r| r.get(0),
    )?;
    if exists {
        return Err(Error::Parse(format!(
            "compartment {id} already exists on {pid}"
        )));
    }
    let nickname = normalize(&c.nickname);
    let codeword = c
        .codeword
        .as_deref()
        .map(normalize)
        .filter(|s| !s.is_empty());
    let parent_id = opt_key(c.parent_id.as_deref());
    let level = c.level.map(|l| l.as_str().to_string());
    tx.execute(
        "INSERT INTO compartments (program_pid, id, nickname, codeword, parent_id, level)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![pid, id, nickname, codeword, parent_id, level],
    )?;
    apply_control_delta(tx, &pid, Some(&id), &c.controls, &[])?;
    Ok(())
}

fn persist_controls_changed(
    tx: &rusqlite::Transaction<'_>,
    program_pid: &str,
    compartment_id: Option<&str>,
    add: &[Control],
    remove: &[Control],
) -> Result<()> {
    let pid = pid_key(program_pid);
    require_program(tx, &pid)?;
    let cid = opt_key(compartment_id);
    if let Some(ref cid) = cid {
        require_compartment(tx, &pid, cid)?;
    }
    apply_control_delta(tx, &pid, cid.as_deref(), add, remove)
}

fn apply_control_delta(
    tx: &rusqlite::Transaction<'_>,
    pid: &str,
    cid: Option<&str>,
    add: &[Control],
    remove: &[Control],
) -> Result<()> {
    for r in remove {
        let value = pid_key(&r.value);
        if value.is_empty() {
            continue;
        }
        match cid {
            None => {
                tx.execute(
                    "DELETE FROM program_controls WHERE program_pid = ?1 AND kind = ?2 AND value = ?3",
                    params![pid, r.kind.as_str(), value],
                )?;
            }
            Some(cid) => {
                tx.execute(
                    "DELETE FROM compartment_controls WHERE program_pid = ?1 AND compartment_id = ?2 AND kind = ?3 AND value = ?4",
                    params![pid, cid, r.kind.as_str(), value],
                )?;
            }
        }
    }
    for a in add {
        let value = pid_key(&a.value);
        if value.is_empty() {
            continue;
        }
        match cid {
            None => {
                tx.execute(
                    "INSERT OR IGNORE INTO program_controls (program_pid, kind, value) VALUES (?1, ?2, ?3)",
                    params![pid, a.kind.as_str(), value],
                )?;
            }
            Some(cid) => {
                tx.execute(
                    "INSERT OR IGNORE INTO compartment_controls (program_pid, compartment_id, kind, value) VALUES (?1, ?2, ?3, ?4)",
                    params![pid, cid, a.kind.as_str(), value],
                )?;
            }
        }
    }
    Ok(())
}

type ProgramRow = (String, String, Option<String>, String, String, String);

fn program_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ProgramRow> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
    ))
}

fn assemble_program(conn: &Connection, row: ProgramRow) -> Result<Program> {
    let (pid, nickname, codeword, sap_type, level, authority_id) = row;
    Ok(Program {
        controls: load_program_controls(conn, &pid)?,
        pid,
        nickname,
        codeword: codeword.filter(|s| !s.is_empty()),
        sap_type: SapType::parse(&sap_type)
            .map_err(|_| Error::LedgerCorrupt(format!("bad sap_type: {sap_type}")))?,
        level: Level::parse(&level)
            .ok_or_else(|| Error::LedgerCorrupt(format!("bad program level: {level}")))?,
        authority_id,
    })
}

type CompartmentRow = (
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn compartment_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<CompartmentRow> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
    ))
}

fn assemble_compartment(conn: &Connection, row: CompartmentRow) -> Result<Compartment> {
    let (program_pid, id, nickname, codeword, parent_id, level) = row;
    Ok(Compartment {
        controls: load_compartment_controls(conn, &program_pid, &id)?,
        program_pid,
        id,
        nickname,
        codeword: codeword.filter(|s| !s.is_empty()),
        parent_id: opt_key(parent_id.as_deref()),
        level: level.and_then(|s| Level::parse(&s)),
    })
}

fn load_program_controls(conn: &Connection, pid: &str) -> Result<Vec<Control>> {
    let mut stmt = conn.prepare(
        "SELECT kind, value FROM program_controls WHERE program_pid = ?1 ORDER BY rowid",
    )?;
    let rows = stmt.query_map([pid], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (kind, value) = row?;
        let kind = ControlKind::parse(&kind)
            .map_err(|_| Error::LedgerCorrupt(format!("bad control kind: {kind}")))?;
        out.push(Control { kind, value });
    }
    Ok(out)
}

fn load_compartment_controls(conn: &Connection, pid: &str, cid: &str) -> Result<Vec<Control>> {
    let mut stmt = conn.prepare(
        "SELECT kind, value FROM compartment_controls WHERE program_pid = ?1 AND compartment_id = ?2 ORDER BY rowid",
    )?;
    let rows = stmt.query_map(params![pid, cid], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (kind, value) = row?;
        let kind = ControlKind::parse(&kind)
            .map_err(|_| Error::LedgerCorrupt(format!("bad control kind: {kind}")))?;
        out.push(Control { kind, value });
    }
    Ok(out)
}

fn names_record_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<(NameRecord, u64)> {
    Ok((
        NameRecord {
            display: r.get(0)?,
            normalized: r.get(1)?,
            status: r.get(2)?,
            name_type: r.get(3)?,
            authority_id: r.get(4)?,
            event_seq: r.get::<_, i64>(5)? as u64,
            created_at: r.get(6)?,
            marking: "U".into(),
            attribution: String::new(),
            program_pid: None,
            compartment_id: None,
        },
        r.get::<_, i64>(7)? as u64,
    ))
}

fn resolve_name_marking_with(set: &ProgramSet, rec: &mut NameRecord) -> Result<()> {
    let Some(pid) = rec.program_pid.as_deref() else {
        return Ok(());
    };
    if !name_derives(&rec.name_type) {
        return Ok(());
    }
    rec.marking = set
        .derive_marking(pid, rec.compartment_id.as_deref())
        .map_err(|e| Error::LedgerCorrupt(format!("derive marking for {}: {e}", rec.display)))?
        .to_string();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EventKind;
    use crate::types::NameType;

    #[test]
    fn append_and_prove() {
        let mut led = Ledger::open_memory_with_bindings().unwrap();
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
            program_pid: None,
            compartment_id: None,
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
        let mut led = Ledger::open_memory_with_bindings().unwrap();
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
                program_pid: None,
                compartment_id: None,
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
        let mut led = Ledger::open_memory_with_bindings().unwrap();
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
            program_pid: None,
            compartment_id: None,
        });
        ev.attribution = attr.clone();
        led.append(ev, &auth).unwrap();
        let rec = led.lookup("GRANITE SPIRE").unwrap().unwrap();
        assert_eq!(rec.attribution, attr.display());
        assert!(rec.attribution.contains("jdoe@ws001"));
        assert!(rec.attribution.contains(&"H".repeat(200)));
    }

    #[test]
    fn default_attribution_persists_empty() {
        let mut led = Ledger::open_memory_with_bindings().unwrap();
        let auth = Authority::from_seed("DIA", [3u8; 32]);
        led.append(
            Event::new(EventKind::Issued {
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
                program_pid: None,
                compartment_id: None,
            }),
            &auth,
        )
        .unwrap();
        let rec = led.lookup("GRANITE SPIRE").unwrap().unwrap();
        assert!(rec.attribution.is_empty());
        let names = led.name_rows().unwrap();
        let json = serde_json::to_string(&names[0]).unwrap();
        assert!(!json.contains("attribution"));
        assert!(!json.contains("marking"));
        let binds = led.binding_rows().unwrap();
        assert!(binds.iter().all(|r| r.attribution.is_empty()));
    }

    #[test]
    fn foreign_authority_cannot_retire() {
        let mut led = Ledger::open_memory_with_bindings().unwrap();
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
                program_pid: None,
                compartment_id: None,
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
        let path = dir.path().join(NAMES_FILE);
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch("PRAGMA user_version = 99").unwrap();
        }
        match Ledger::open(dir.path(), &Policy::default_oss()) {
            Err(Error::SchemaTooNew {
                found: 99,
                max: MAX_SCHEMA_VERSION,
            }) => {}
            Err(e) => panic!("wrong error: {e}"),
            Ok(_) => panic!("stale binary must refuse a newer schema"),
        }
    }

    #[test]
    fn aggregate_keeps_pre_register_sci() {
        let mut led = Ledger::open_memory_with_bindings().unwrap();
        let auth = Authority::from_seed("DIA", [3u8; 32]);
        let marking = crate::marking::Marking::from_stored("TS//SCI/ZZZZ").unwrap();
        led.append(
            Event::new(EventKind::Issued {
                name: "FAKE SCI".into(),
                name_type: NameType::Nickname,
                authority_id: "DIA".into(),
                authority_pk: hex::encode(auth.public_key()),
                pool_id: "p".into(),
                sequence: 1,
                nonce: 0,
                vrf_proof: "00".into(),
                vrf_output: "00".into(),
                indices: vec![1, 2],
                marking,
                program_pid: None,
                compartment_id: None,
            }),
            &auth,
        )
        .unwrap();
        let agg = led.aggregate_marking().unwrap();
        assert_eq!(agg.to_string(), "TS//ZZZZ");
    }

    fn qsv() -> Program {
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

    fn issued(
        name: &str,
        name_type: NameType,
        auth: &Authority,
        marking: Marking,
        program_pid: Option<&str>,
        compartment_id: Option<&str>,
    ) -> Event {
        Event::new(EventKind::Issued {
            name: name.into(),
            name_type,
            authority_id: auth.id.clone(),
            authority_pk: hex::encode(auth.public_key()),
            pool_id: "p".into(),
            sequence: 1,
            nonce: 0,
            vrf_proof: "00".into(),
            vrf_output: "00".into(),
            indices: vec![1, 2],
            marking,
            program_pid: program_pid.map(str::to_string),
            compartment_id: compartment_id.map(str::to_string),
        })
    }

    #[test]
    fn schema_v5_fresh_names_has_no_classified_columns() {
        let led = Ledger::open_memory().unwrap();
        let v: i64 = led
            .names
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, MAX_SCHEMA_VERSION);
        let cols: Vec<String> = led
            .names
            .prepare("SELECT * FROM names LIMIT 0")
            .unwrap()
            .column_names()
            .into_iter()
            .map(str::to_string)
            .collect();
        assert!(!cols.iter().any(|c| c == "marking"));
        assert!(!cols.iter().any(|c| c == "program_pid"));
        assert!(cols.iter().any(|c| c == "issued_seq"));
        assert!(!led.has_bindings());
    }

    #[test]
    fn name_rows_omit_classified_fields() {
        let mut led = Ledger::open_memory_with_bindings().unwrap();
        let auth = Authority::from_seed("DIA", [3u8; 32]);
        let mut ev = issued(
            "OXIDE",
            NameType::CodeWord,
            &auth,
            Marking::from_stored("TS//SCI/TK").unwrap(),
            None,
            None,
        );
        ev.attribution = crate::Attribution::session("jdoe", "ws001", None);
        led.append(ev, &auth).unwrap();

        let rows = led.name_rows().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name.as_deref(), Some("OXIDE"));
        let v = serde_json::to_value(&rows[0]).unwrap();
        let obj = v.as_object().unwrap();
        assert!(!obj.contains_key("marking"));
        assert!(!obj.contains_key("attribution"));
        assert!(!obj.contains_key("program_pid"));
        assert!(!obj.contains_key("compartment_id"));

        let binds = led.binding_rows().unwrap();
        assert_eq!(binds.len(), 1);
        assert_eq!(binds[0].names_seq, Some(1));
        assert_eq!(binds[0].marking.as_deref(), Some("TS//TK"));
        assert!(binds[0].attribution.contains("jdoe@ws001"));
        let bj = serde_json::to_value(&binds[0]).unwrap();
        assert!(bj.get("marking").is_some());
        assert!(bj.get("attribution").is_some());
    }

    #[test]
    fn binding_rows_closed_without_store() {
        let led = Ledger::open_memory().unwrap();
        assert!(matches!(led.binding_rows(), Err(Error::BindingsClosed)));
        assert!(led.name_rows().unwrap().is_empty());
    }

    #[test]
    fn attach_bindings_read_opens_existing() {
        let dir = tempfile::tempdir().unwrap();
        let mut persist = Policy::default_oss();
        persist.allow_persist_markings = true;
        {
            let mut led = Ledger::open(dir.path(), &persist).unwrap();
            let auth = Authority::from_seed("DIA", [3u8; 32]);
            led.append(
                issued(
                    "OXIDE",
                    NameType::CodeWord,
                    &auth,
                    Marking::from_stored("S").unwrap(),
                    None,
                    None,
                ),
                &auth,
            )
            .unwrap();
        }
        let mut oss = Ledger::open(dir.path(), &Policy::default_oss()).unwrap();
        assert!(!oss.has_bindings());
        assert!(matches!(oss.binding_rows(), Err(Error::BindingsClosed)));
        oss.attach_bindings_read(dir.path()).unwrap();
        let binds = oss.binding_rows().unwrap();
        assert_eq!(binds.len(), 1);
        assert_eq!(binds[0].marking.as_deref(), Some("S"));
        let names = oss.name_rows().unwrap();
        let json = serde_json::to_string(&names[0]).unwrap();
        assert!(!json.contains("\"marking\""));
    }

    #[test]
    fn binding_rows_include_program_events() {
        let mut led = Ledger::open_memory_with_bindings().unwrap();
        let auth = Authority::from_seed("DIA", [3u8; 32]);
        led.append(Event::new(EventKind::ProgramCreated(qsv())), &auth)
            .unwrap();
        led.append(
            issued(
                "HOLLERED",
                NameType::CodeWord,
                &auth,
                Marking::default(),
                Some("QSV"),
                None,
            ),
            &auth,
        )
        .unwrap();
        let binds = led.binding_rows().unwrap();
        assert_eq!(binds.len(), 2);
        assert_eq!(binds[0].event_type, "program_created");
        assert!(binds[0].names_seq.is_none());
        assert!(binds[0].marking.is_none());
        assert_eq!(binds[1].event_type, "issued");
        assert_eq!(binds[1].program_pid.as_deref(), Some("QSV"));
    }

    #[test]
    fn persist_policy_creates_bindings_file() {
        let dir = tempfile::tempdir().unwrap();
        let oss = Ledger::open(dir.path(), &Policy::default_oss()).unwrap();
        assert!(!oss.has_bindings());
        assert!(dir.path().join(NAMES_FILE).exists());
        assert!(!dir.path().join(BINDINGS_FILE).exists());

        let mut p = Policy::default_oss();
        p.allow_persist_markings = true;
        let led = Ledger::open(dir.path(), &p).unwrap();
        assert!(led.has_bindings());
        assert!(dir.path().join(BINDINGS_FILE).exists());
    }

    #[test]
    fn refuse_legacy_combined_without_migrate() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(LEGACY_FILE), b"old").unwrap();
        match Ledger::open(dir.path(), &Policy::default_oss()) {
            Err(Error::LegacyLedger) => {}
            Err(e) => panic!("wrong error: {e}"),
            Ok(_) => panic!("must refuse combined ledger.sqlite"),
        }
    }

    #[test]
    fn migrate_quarantines_legacy_and_open_starts_clean() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(LEGACY_FILE), b"old").unwrap();
        Ledger::migrate(dir.path()).unwrap();
        assert!(!dir.path().join(LEGACY_FILE).exists());
        assert!(dir.path().join("ledger.sqlite.refused").exists());
        let led = Ledger::open(dir.path(), &Policy::default_oss()).unwrap();
        assert!(led.is_empty().unwrap());
        assert!(dir.path().join(NAMES_FILE).exists());
    }

    #[test]
    fn bindings_closed_rejects_program_and_stays_u() {
        let mut led = Ledger::open_memory().unwrap();
        let auth = Authority::from_seed("DIA", [3u8; 32]);
        let err = led
            .append(Event::new(EventKind::ProgramCreated(qsv())), &auth)
            .unwrap_err();
        assert!(matches!(err, Error::BindingsClosed));
        assert!(led.is_empty().unwrap());

        led.append(
            issued(
                "GRANITE SPIRE",
                NameType::Nickname,
                &auth,
                Marking::from_stored("TS").unwrap(),
                None,
                None,
            ),
            &auth,
        )
        .unwrap();
        let rec = led.lookup("GRANITE SPIRE").unwrap().unwrap();
        assert_eq!(rec.marking, "U");
        assert!(rec.attribution.is_empty());
        assert_eq!(led.aggregate_marking().unwrap(), Marking::default());
    }

    #[test]
    fn program_crud_and_controls_delta() {
        let mut led = Ledger::open_memory_with_bindings().unwrap();
        let auth = Authority::from_seed("DIA", [3u8; 32]);
        led.append(Event::new(EventKind::ProgramCreated(qsv())), &auth)
            .unwrap();
        led.append(Event::new(EventKind::CompartmentAdded(hol())), &auth)
            .unwrap();

        let p = led.program("qsv").unwrap().unwrap();
        assert_eq!(p.pid, "QSV");
        assert_eq!(p.nickname, "DILIGENTLY IMPRESSED");
        assert_eq!(p.sap_type, SapType::Unacknowledged);
        assert_eq!(p.level, Level::TopSecret);
        assert_eq!(p.controls.len(), 2);

        let c = led.compartment("QSV", "hol").unwrap().unwrap();
        assert_eq!(c.id, "HOL");
        assert_eq!(c.controls.len(), 1);
        assert_eq!(led.compartments("QSV").unwrap().len(), 1);

        led.append(
            Event::new(EventKind::ProgramControlsChanged {
                program_pid: "QSV".into(),
                compartment_id: None,
                add: vec![Control::new(ControlKind::Sci, "SI")],
                remove: vec![Control::new(ControlKind::Dissem, "NOFORN")],
            }),
            &auth,
        )
        .unwrap();
        let p = led.program("QSV").unwrap().unwrap();
        assert!(p
            .controls
            .iter()
            .any(|c| c.kind == ControlKind::Sci && c.value == "SI"));
        assert!(!p
            .controls
            .iter()
            .any(|c| c.kind == ControlKind::Dissem && c.value == "NOFORN"));

        led.append(
            Event::new(EventKind::ProgramControlsChanged {
                program_pid: "QSV".into(),
                compartment_id: Some("HOL".into()),
                add: vec![Control::new(ControlKind::Sci, "HCS")],
                remove: vec![],
            }),
            &auth,
        )
        .unwrap();
        let c = led.compartment("QSV", "HOL").unwrap().unwrap();
        assert!(c.controls.iter().any(|x| x.value == "HCS"));
        led.verify_chain().unwrap();
    }

    #[test]
    fn program_materialize_rejects_dup_and_orphan() {
        let mut led = Ledger::open_memory_with_bindings().unwrap();
        let auth = Authority::from_seed("DIA", [3u8; 32]);
        led.append(Event::new(EventKind::ProgramCreated(qsv())), &auth)
            .unwrap();
        let err = led
            .append(Event::new(EventKind::ProgramCreated(qsv())), &auth)
            .unwrap_err();
        assert!(matches!(err, Error::Parse(_)));
        assert_eq!(led.bindings_len().unwrap(), 1);
        assert!(led.is_empty().unwrap());

        let err = led
            .append(
                Event::new(EventKind::CompartmentAdded(Compartment {
                    program_pid: "ZZZ".into(),
                    ..hol()
                })),
                &auth,
            )
            .unwrap_err();
        assert!(matches!(err, Error::Parse(_)));
        assert_eq!(led.bindings_len().unwrap(), 1);
    }

    #[test]
    fn name_join_derives_and_nickname_stays_u() {
        let mut led = Ledger::open_memory_with_bindings().unwrap();
        let auth = Authority::from_seed("DIA", [3u8; 32]);
        led.append(Event::new(EventKind::ProgramCreated(qsv())), &auth)
            .unwrap();
        led.append(Event::new(EventKind::CompartmentAdded(hol())), &auth)
            .unwrap();

        led.append(
            issued(
                "DILIGENTLY IMPRESSED",
                NameType::Nickname,
                &auth,
                Marking::default(),
                Some("QSV"),
                None,
            ),
            &auth,
        )
        .unwrap();
        led.append(
            issued(
                "HOLLERED",
                NameType::CodeWord,
                &auth,
                Marking::default(),
                Some("QSV"),
                Some("HOL"),
            ),
            &auth,
        )
        .unwrap();

        let nick = led.lookup("DILIGENTLY IMPRESSED").unwrap().unwrap();
        assert_eq!(nick.marking, "U");
        assert_eq!(nick.program_pid.as_deref(), Some("QSV"));
        assert!(nick.compartment_id.is_none());

        let cw = led.lookup("HOLLERED").unwrap().unwrap();
        assert_eq!(cw.marking, "TS//TK//SAR-QSV-HOL//NF");
        assert_eq!(cw.program_pid.as_deref(), Some("QSV"));
        assert_eq!(cw.compartment_id.as_deref(), Some("HOL"));

        let agg = led.aggregate_marking().unwrap();
        // Nickname derives SAR-QSV; codeword derives SAR-QSV-HOL; max unions.
        assert_eq!(agg.to_string(), "TS//TK//SAR-QSV//SAR-QSV-HOL//NF");

        led.append(
            Event::new(EventKind::ProgramControlsChanged {
                program_pid: "QSV".into(),
                compartment_id: None,
                add: vec![Control::new(ControlKind::Sci, "SI")],
                remove: vec![Control::new(ControlKind::Dissem, "NOFORN")],
            }),
            &auth,
        )
        .unwrap();
        let cw = led.lookup("HOLLERED").unwrap().unwrap();
        assert_eq!(cw.marking, "TS//TK,SI//SAR-QSV-HOL");
        led.verify_chain().unwrap();
    }

    #[test]
    fn aggregate_derives_program_bound_nickname() {
        let mut led = Ledger::open_memory_with_bindings().unwrap();
        let auth = Authority::from_seed("DIA", [3u8; 32]);
        led.append(Event::new(EventKind::ProgramCreated(qsv())), &auth)
            .unwrap();
        led.append(
            issued(
                "DILIGENTLY IMPRESSED",
                NameType::Nickname,
                &auth,
                Marking::default(),
                Some("QSV"),
                None,
            ),
            &auth,
        )
        .unwrap();
        let nick = led.lookup("DILIGENTLY IMPRESSED").unwrap().unwrap();
        assert_eq!(nick.marking, "U");
        // Container marking still derives: the program is on the ledger.
        let agg = led.aggregate_marking().unwrap();
        assert_eq!(agg.to_string(), "TS//TK//SAR-QSV//NF");
    }

    #[test]
    fn bind_requires_existing_program() {
        let mut led = Ledger::open_memory_with_bindings().unwrap();
        let auth = Authority::from_seed("DIA", [3u8; 32]);
        let err = led
            .append(
                issued(
                    "HOLLERED",
                    NameType::CodeWord,
                    &auth,
                    Marking::default(),
                    Some("QSV"),
                    None,
                ),
                &auth,
            )
            .unwrap_err();
        assert!(matches!(err, Error::Parse(_)));
        assert!(led.is_empty().unwrap());
    }

    #[test]
    fn is_display_name_taken_checks_global_namespace() {
        let mut led = Ledger::open_memory_with_bindings().unwrap();
        let auth = Authority::from_seed("DIA", [3u8; 32]);
        led.append(Event::new(EventKind::ProgramCreated(qsv())), &auth)
            .unwrap();
        // Free before any issue.
        assert!(!led.is_display_name_taken("GRANITE SPIRE").unwrap());
        // Issued name occupies the namespace.
        led.append(
            issued(
                "GRANITE SPIRE",
                NameType::Nickname,
                &auth,
                Marking::default(),
                None,
                None,
            ),
            &auth,
        )
        .unwrap();
        assert!(led.is_display_name_taken("granite spire").unwrap());
        // Compartment nickname shares the namespace.
        led.append(Event::new(EventKind::CompartmentAdded(hol())), &auth)
            .unwrap();
        assert!(led.is_display_name_taken("HOLLERED").unwrap());
        // A codeword on a compartment also counts.
        let mut c = hol();
        c.id = "SEN".into();
        c.codeword = Some("BIKINIED".into());
        led.append(Event::new(EventKind::CompartmentAdded(c)), &auth)
            .unwrap();
        assert!(led.is_display_name_taken("BIKINIED").unwrap());
        // Unrelated name is still free.
        assert!(!led.is_display_name_taken("OXIDE").unwrap());
    }
}
