use crate::authority::Authority;
use crate::error::{Error, Result};
use crate::events::{AttemptReason, Event, EventKind};
use crate::ledger::Ledger;
use crate::linter::{LintEngine, NameCandidate};
use crate::marking::{Level, Marking};
use crate::merkle;
use crate::pool::{PoolSet, PoolWord};
use crate::sig::Signer;
use crate::types::{indices_from_beta, mint_alpha, normalize, NameType, POOL_ID_V1};
use crate::vrf::{self, VrfOutput, VrfProof, VrfSigner};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Alpha sequence for dry-run. Matches `Ledger::next_seq` on an empty names chain.
const DRY_RUN_SEQ: u64 = 1;

#[derive(Debug, Clone)]
pub struct MintRequest {
    pub name_type: NameType,
    pub pool_id: String,
    pub max_attempts: u32,
    /// Pin a cryptonym digraph instead of VRF-picking from the agency allocation.
    pub digraph: Option<String>,
    /// Classification marking bound to the issued name (signed + hashed).
    /// Ignored for program-bound codeword/cryptonym — those derive from the program.
    pub marking: Marking,
    pub attribution: crate::attribition::Attribution,
    pub program_pid: Option<String>,
    pub compartment_id: Option<String>,
}

impl MintRequest {
    pub fn new(name_type: NameType) -> Self {
        Self {
            name_type,
            pool_id: POOL_ID_V1.into(),
            max_attempts: 64,
            digraph: None,
            marking: Marking::default(),
            attribution: crate::attribition::Attribution::default(),
            program_pid: None,
            compartment_id: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintedName {
    pub name: String,
    pub name_type: NameType,
    pub authority_id: String,
    pub authority_pk: String,
    pub pool_id: String,
    pub sequence: u64,
    pub nonce: u32,
    pub vrf_proof: String,
    pub vrf_output: String,
    pub indices: Vec<u32>,
    pub ledger_seq: u64,
    pub event_hash: String,
    pub inclusion: merkle::InclusionProof,
    pub marking: Marking,
}

pub struct Minter<'a> {
    pub authority_id: &'a str,
    pub vrf: &'a dyn VrfSigner,
    pub signer: &'a dyn Signer,
    pub pools: &'a PoolSet,
    pub linter: &'a LintEngine,
    pub ledger: &'a mut Ledger,
}

impl<'a> Minter<'a> {
    pub fn new(
        authority: &'a Authority,
        pools: &'a PoolSet,
        linter: &'a LintEngine,
        ledger: &'a mut Ledger,
    ) -> Self {
        Self {
            authority_id: &authority.id,
            vrf: authority,
            signer: authority,
            pools,
            linter,
            ledger,
        }
    }

    pub fn mint(&mut self, req: MintRequest) -> Result<MintedName> {
        let agency = self.authority_id;
        let _ = self.pools.agency(agency)?;
        let sizes = self.pools.pool_sizes(req.name_type, agency)?;
        if sizes.contains(&0) {
            return Err(Error::EmptyPool(req.pool_id.clone()));
        }

        let (program_pid, compartment_id) = bind_program(&req)?;
        let marking = resolve_mint_marking(
            self.ledger,
            req.name_type,
            &req.marking,
            program_pid.as_deref(),
            compartment_id.as_deref(),
        )?;

        let sequence = self.ledger.next_seq()?;
        let mut nonce = 0u32;
        let mut last_lint: Option<String> = None;

        while nonce < req.max_attempts {
            let p = propose(self.vrf, self.pools, agency, &req, &sizes, sequence, nonce)?;
            let candidate = NameCandidate {
                name: p.name.clone(),
                name_type: req.name_type,
                words: p.words,
            };

            if let Some(hit) = self.linter.first_reject(&candidate) {
                self.log_attempt(
                    &p.name,
                    req.name_type,
                    nonce,
                    AttemptReason::Lint,
                    &hit.detail,
                )?;
                last_lint = Some(format!("{}: {}", hit.rule, hit.detail));
                nonce += 1;
                continue;
            }

            if let Some(status) = self.ledger.name_status(&p.name)? {
                // Surface the winner's marking so a CUI operator colliding
                // with a TS//SCI name stops instead of re-rolling blind.
                let held_marking = self
                    .ledger
                    .lookup(&p.name)?
                    .map(|r| r.marking)
                    .unwrap_or_default();
                self.log_attempt(
                    &p.name,
                    req.name_type,
                    nonce,
                    AttemptReason::Collision,
                    &format!("{}; held as {}", status.as_str(), held_marking),
                )?;
                nonce += 1;
                continue;
            }

            let vrf_proof = hex::encode(p.proof.as_bytes());
            let vrf_output = hex::encode(p.beta.as_bytes());
            let mut event = Event::new(EventKind::Issued {
                name: p.name.clone(),
                name_type: req.name_type,
                authority_id: agency.to_string(),
                authority_pk: hex::encode(self.vrf.public_key()),
                pool_id: req.pool_id.clone(),
                sequence,
                nonce,
                vrf_proof: vrf_proof.clone(),
                vrf_output: vrf_output.clone(),
                indices: p.indices.clone(),
                marking: marking.clone(),
                program_pid: program_pid.clone(),
                compartment_id: compartment_id.clone(),
            });
            event.attribution = req.attribution.clone();
            let event_hash = event.hash_u();
            let ledger_seq = self.ledger.append(event, self.signer)?;
            let inclusion = self.ledger.inclusion_proof(ledger_seq)?;

            return Ok(MintedName {
                name: p.name,
                name_type: req.name_type,
                authority_id: agency.to_string(),
                authority_pk: hex::encode(self.vrf.public_key()),
                pool_id: req.pool_id,
                sequence,
                nonce,
                vrf_proof,
                vrf_output,
                indices: p.indices,
                ledger_seq,
                event_hash: hex::encode(event_hash),
                inclusion,
                marking,
            });
        }

        Err(Error::MintExhausted(req.max_attempts)).map_err(|e| {
            if let Some(detail) = last_lint {
                Error::LintRejected {
                    rule: "mint".into(),
                    detail: format!("{e}; last lint {detail}"),
                }
            } else {
                e
            }
        })
    }

    /// VRF candidates from a 32-byte seed. No ledger I/O.
    /// Same seed + authority + request always yields the same list.
    pub fn mint_dry_run(
        seed: &[u8; 32],
        authority_id: &str,
        pools: &PoolSet,
        linter: &LintEngine,
        req: MintRequest,
    ) -> Result<Vec<MintedName>> {
        let _ = pools.agency(authority_id)?;
        let sizes = pools.pool_sizes(req.name_type, authority_id)?;
        if sizes.contains(&0) {
            return Err(Error::EmptyPool(req.pool_id.clone()));
        }
        let marking = resolve_dry_marking(&req)?;
        let auth = Authority::from_seed(authority_id, *seed);
        let pk = hex::encode(VrfSigner::public_key(&auth));

        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut last_lint: Option<String> = None;

        for nonce in 0..req.max_attempts {
            let p = propose(&auth, pools, authority_id, &req, &sizes, DRY_RUN_SEQ, nonce)?;
            let candidate = NameCandidate {
                name: p.name.clone(),
                name_type: req.name_type,
                words: p.words,
            };
            if let Some(hit) = linter.first_reject(&candidate) {
                last_lint = Some(format!("{}: {}", hit.rule, hit.detail));
                continue;
            }
            if !seen.insert(normalize(&p.name)) {
                continue;
            }
            out.push(MintedName {
                name: p.name,
                name_type: req.name_type,
                authority_id: authority_id.to_string(),
                authority_pk: pk.clone(),
                pool_id: req.pool_id.clone(),
                sequence: DRY_RUN_SEQ,
                nonce,
                vrf_proof: hex::encode(p.proof.as_bytes()),
                vrf_output: hex::encode(p.beta.as_bytes()),
                indices: p.indices,
                ledger_seq: 0,
                event_hash: String::new(),
                inclusion: unsigned_receipt(),
                marking: marking.clone(),
            });
        }

        if out.is_empty() {
            return Err(Error::MintExhausted(req.max_attempts)).map_err(|e| {
                if let Some(detail) = last_lint {
                    Error::LintRejected {
                        rule: "mint".into(),
                        detail: format!("{e}; last lint {detail}"),
                    }
                } else {
                    e
                }
            });
        }
        Ok(out)
    }

    fn log_attempt(
        &mut self,
        candidate: &str,
        name_type: NameType,
        nonce: u32,
        reason: AttemptReason,
        detail: &str,
    ) -> Result<()> {
        let ev = Event::new(EventKind::Attempt {
            candidate: candidate.into(),
            name_type,
            authority_id: self.authority_id.to_string(),
            nonce,
            reason,
            detail: detail.into(),
        });
        self.ledger.append(ev, self.signer)?;
        Ok(())
    }
}

fn opt_key(s: Option<&str>) -> Option<String> {
    s.map(|s| s.trim().to_ascii_uppercase())
        .filter(|s| !s.is_empty())
}

struct Proposal {
    name: String,
    words: Vec<PoolWord>,
    indices: Vec<u32>,
    proof: VrfProof,
    beta: VrfOutput,
}

fn propose(
    vrf: &dyn VrfSigner,
    pools: &PoolSet,
    agency: &str,
    req: &MintRequest,
    sizes: &[usize],
    sequence: u64,
    nonce: u32,
) -> Result<Proposal> {
    let alpha = mint_alpha(agency, req.name_type, &req.pool_id, sequence, nonce);
    let (proof, beta) = vrf.prove(&alpha)?;
    let mut indices = indices_from_beta(beta.as_bytes(), sizes);

    if let Some(ref dg) = req.digraph {
        if req.name_type == NameType::Cryptonym {
            let first = pools.first_pool(req.name_type, agency)?;
            let want = dg.to_ascii_uppercase();
            let pos = first
                .words
                .iter()
                .position(|w| w.word == want)
                .ok_or_else(|| Error::Parse(format!("digraph {want} not allocated to {agency}")))?;
            if indices.is_empty() {
                return Err(Error::IndexMismatch);
            }
            indices[0] = pos as u32;
        }
    }

    let name = pools.compose(req.name_type, agency, &indices)?;
    let words = pools.lookup_words(req.name_type, agency, &indices)?;
    Ok(Proposal {
        name,
        words,
        indices,
        proof,
        beta,
    })
}

fn unsigned_receipt() -> merkle::InclusionProof {
    merkle::InclusionProof {
        leaf_index: 0,
        leaf_hash: String::new(),
        siblings: Vec::new(),
        root: String::new(),
        leaf_count: 0,
    }
}

fn resolve_dry_marking(req: &MintRequest) -> Result<Marking> {
    let (program_pid, compartment_id) = bind_program(req)?;
    if program_pid.is_some() || compartment_id.is_some() {
        return Err(Error::Parse(
            "dry-run cannot bind programs (no ledger)".into(),
        ));
    }
    if name_stays_unclassified(req.name_type) && req.marking.level > Level::Unclassified {
        return Err(Error::Parse(format!(
            "{} names stay unclassified (got {})",
            req.name_type,
            req.marking.level.as_str()
        )));
    }
    Ok(req.marking.clone())
}

fn bind_program(req: &MintRequest) -> Result<(Option<String>, Option<String>)> {
    let pid = opt_key(req.program_pid.as_deref());
    let cid = opt_key(req.compartment_id.as_deref());
    if cid.is_some() && pid.is_none() {
        return Err(Error::Parse("compartment_id requires program_pid".into()));
    }
    Ok((pid, cid))
}

fn name_stays_unclassified(t: NameType) -> bool {
    matches!(
        t,
        NameType::Nickname | NameType::ExerciseTerm | NameType::SapDesignator
    )
}

fn resolve_mint_marking(
    ledger: &Ledger,
    name_type: NameType,
    requested: &Marking,
    program_pid: Option<&str>,
    compartment_id: Option<&str>,
) -> Result<Marking> {
    let marking = match (program_pid, name_type) {
        (Some(pid), NameType::CodeWord | NameType::Cryptonym) => {
            ledger.program_set()?.derive_marking(pid, compartment_id)?
        }
        (Some(pid), _) => {
            require_binding(ledger, pid, compartment_id)?;
            requested.clone()
        }
        (None, _) => requested.clone(),
    };

    if name_stays_unclassified(name_type) && marking.level > Level::Unclassified {
        return Err(Error::Parse(format!(
            "{name_type} names stay unclassified (got {})",
            marking.level.as_str()
        )));
    }
    Ok(marking)
}

fn require_binding(ledger: &Ledger, pid: &str, cid: Option<&str>) -> Result<()> {
    if ledger.program(pid)?.is_none() {
        return Err(Error::Parse(format!("unknown program: {pid}")));
    }
    if let Some(cid) = cid {
        if ledger.compartment(pid, cid)?.is_none() {
            return Err(Error::Parse(format!(
                "unknown compartment {cid} on program {pid}"
            )));
        }
    }
    Ok(())
}

/// Verify name was fairly minted: VRF proof, indices, pool words.
/// Does not check ledger inclusion — use `verify_issued` for that.
pub fn verify_mint(minted: &MintedName, pools: &PoolSet) -> Result<()> {
    let pk_raw =
        hex::decode(&minted.authority_pk).map_err(|e| Error::Parse(format!("pk hex: {e}")))?;
    let pk: [u8; 32] = pk_raw
        .try_into()
        .map_err(|_| Error::Parse("pk must be 32 bytes".into()))?;
    let proof_raw =
        hex::decode(&minted.vrf_proof).map_err(|e| Error::Parse(format!("proof hex: {e}")))?;
    let proof = VrfProof::from_slice(&proof_raw)?;
    let alpha = mint_alpha(
        &minted.authority_id,
        minted.name_type,
        &minted.pool_id,
        minted.sequence,
        minted.nonce,
    );
    let beta = vrf::verify(&pk, &alpha, &proof)?;
    if hex::encode(beta.as_bytes()) != minted.vrf_output {
        return Err(Error::VrfInvalid);
    }

    let sizes = pools.pool_sizes(minted.name_type, &minted.authority_id)?;
    let expected = indices_from_beta(beta.as_bytes(), &sizes);
    // Digraph override is allowed for cryptonyms; still check the word index.
    match minted.name_type {
        NameType::Cryptonym if minted.indices.len() == 2 && expected.len() == 2 => {
            if minted.indices[1] != expected[1] {
                return Err(Error::IndexMismatch);
            }
        }
        _ => {
            if minted.indices != expected {
                return Err(Error::IndexMismatch);
            }
        }
    }

    let composed = pools.compose(minted.name_type, &minted.authority_id, &minted.indices)?;
    if normalize(&composed) != normalize(&minted.name) {
        return Err(Error::IndexMismatch);
    }
    Ok(())
}

pub fn verify_issued(minted: &MintedName, pools: &PoolSet, ledger: &Ledger) -> Result<()> {
    verify_mint(minted, pools)?;
    // Receipt is against the root at mint time. Later appends change the live
    // root; we re-prove the same leaf and check the hash still matches.
    if !merkle::verify_inclusion(&minted.inclusion) {
        return Err(Error::InclusionFailed);
    }
    let live = ledger.inclusion_proof(minted.ledger_seq)?;
    if !merkle::verify_inclusion(&live) || live.leaf_hash != minted.inclusion.leaf_hash {
        return Err(Error::InclusionFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::{AgencyAlloc, Pool, PoolSet};

    fn tiny_pools() -> PoolSet {
        PoolSet {
            id: "tiny".into(),
            nickname_first: Pool::from_lines("nf", "AMBER\nCOPPER\nGRANITE\nTIMBER\n"),
            nickname_second: Pool::from_lines("ns", "LEDGER\nSPIRE\nRIDGE\nORBIT\n"),
            codeword: Pool::from_lines("cw", "OXIDE\nPEBBLE\nQUARRY\nWALNUT\n"),
            cryptonym_word: Pool::from_lines("cr", "FLOOR\nLANTERN\nORCHID\nTINDER\n"),
            exercise_first: Pool::from_lines("ef", "AMBER\nCOPPER\nGRANITE\nTIMBER\n"),
            exercise_second: Pool::from_lines("es", "DRILL\nRELAY\nSIGNAL\nVECTOR\n"),
            agencies: vec![
                AgencyAlloc {
                    id: "DIA".into(),
                    first_letters: "ACGT".into(),
                    digraphs: vec!["DI".into(), "DH".into()],
                    sap_designators: vec!["TK".into(), "SI".into()],
                },
                AgencyAlloc {
                    id: "CIA".into(),
                    first_letters: "ACGT".into(),
                    digraphs: vec!["AE".into(), "GP".into()],
                    sap_designators: vec!["HCS".into()],
                },
            ],
        }
    }

    #[test]
    fn mint_verify_unique() {
        let pools = tiny_pools();
        let linter = LintEngine::core();
        let mut ledger = Ledger::open_memory().unwrap();
        let auth = Authority::from_seed("DIA", [11u8; 32]);
        let mut names = Vec::new();
        for _ in 0..12 {
            let mut minter = Minter::new(&auth, &pools, &linter, &mut ledger);
            let minted = minter.mint(MintRequest::new(NameType::Nickname)).unwrap();
            verify_mint(&minted, &pools).unwrap();
            names.push(minted.name);
        }
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "collision in 12 mints");
        ledger.verify_chain().unwrap();
    }

    #[test]
    fn remints_on_collision() {
        let pools = tiny_pools();
        let linter = LintEngine::core();
        let mut ledger = Ledger::open_memory().unwrap();
        let auth = Authority::from_seed("DIA", [11u8; 32]);
        let first = {
            let mut minter = Minter::new(&auth, &pools, &linter, &mut ledger);
            minter.mint(MintRequest::new(NameType::CodeWord)).unwrap()
        };
        // Force the same name onto the ledger under a different path, then mint
        // from a second authority? Single-authority remint: pre-insert via retire
        // already occupies the name. Second mint from same key/seq differs by
        // ledger seq in alpha, so just check taken-name is skipped by minting many.
        let mut minter = Minter::new(&auth, &pools, &linter, &mut ledger);
        let second = minter.mint(MintRequest::new(NameType::CodeWord)).unwrap();
        assert_ne!(first.name, second.name);
        verify_mint(&second, &pools).unwrap();
        verify_issued(&first, &pools, minter.ledger).unwrap();
        verify_issued(&second, &pools, minter.ledger).unwrap();
    }

    #[test]
    fn cryptonym_and_sap() {
        let pools = tiny_pools();
        let linter = LintEngine::core();
        let mut ledger = Ledger::open_memory().unwrap();
        let auth = Authority::from_seed("CIA", [19u8; 32]);
        let mut minter = Minter::new(&auth, &pools, &linter, &mut ledger);
        let c = minter
            .mint(MintRequest {
                digraph: Some("AE".into()),
                max_attempts: 32,
                ..MintRequest::new(NameType::Cryptonym)
            })
            .unwrap();
        assert!(c.name.starts_with("AE"), "{}", c.name);
        assert!(!c.name.contains(' '));
        verify_mint(&c, &pools).unwrap();

        let s = minter
            .mint(MintRequest::new(NameType::SapDesignator))
            .unwrap();
        assert!(s.name == "HCS");
        verify_mint(&s, &pools).unwrap();
    }

    #[test]
    fn exercise_namespace() {
        let pools = tiny_pools();
        let linter = LintEngine::core();
        let mut ledger = Ledger::open_memory().unwrap();
        let auth = Authority::from_seed("DIA", [5u8; 32]);
        let mut minter = Minter::new(&auth, &pools, &linter, &mut ledger);
        let e = minter
            .mint(MintRequest::new(NameType::ExerciseTerm))
            .unwrap();
        assert!(e.name.contains(' '));
        verify_mint(&e, &pools).unwrap();
    }

    #[test]
    fn minter_accepts_split_vrf_and_signer() {
        let pools = tiny_pools();
        let linter = LintEngine::core();
        let mut ledger = Ledger::open_memory().unwrap();
        let auth = Authority::from_seed("DIA", [11u8; 32]);
        let mut minter = Minter {
            authority_id: &auth.id,
            vrf: &auth,
            signer: &auth,
            pools: &pools,
            linter: &linter,
            ledger: &mut ledger,
        };
        let minted = minter.mint(MintRequest::new(NameType::Nickname)).unwrap();
        verify_mint(&minted, &pools).unwrap();
    }

    fn ts() -> Marking {
        Marking {
            level: Level::TopSecret,
            ..Default::default()
        }
    }

    fn seed_qsv(ledger: &mut Ledger, auth: &Authority) {
        use crate::program::{Compartment, Control, ControlKind, Program, SapType};
        ledger
            .append(
                Event::new(EventKind::ProgramCreated(Program {
                    pid: "QSV".into(),
                    nickname: "DILIGENTLY IMPRESSED".into(),
                    codeword: None,
                    sap_type: SapType::Unacknowledged,
                    level: Level::TopSecret,
                    authority_id: auth.id.clone(),
                    controls: vec![
                        Control::new(ControlKind::Sci, "TK"),
                        Control::new(ControlKind::Dissem, "NOFORN"),
                    ],
                })),
                auth,
            )
            .unwrap();
        ledger
            .append(
                Event::new(EventKind::CompartmentAdded(Compartment {
                    program_pid: "QSV".into(),
                    id: "HOL".into(),
                    nickname: "HOLLERED".into(),
                    codeword: None,
                    parent_id: None,
                    controls: vec![Control::new(ControlKind::Sci, "TK")],
                    level: None,
                })),
                auth,
            )
            .unwrap();
    }

    #[test]
    fn nickname_stays_u_rejects_classified() {
        let pools = tiny_pools();
        let linter = LintEngine::core();
        let mut ledger = Ledger::open_memory().unwrap();
        let auth = Authority::from_seed("DIA", [11u8; 32]);
        let mut minter = Minter::new(&auth, &pools, &linter, &mut ledger);
        for ty in [
            NameType::Nickname,
            NameType::ExerciseTerm,
            NameType::SapDesignator,
        ] {
            let err = minter
                .mint(MintRequest {
                    marking: ts(),
                    ..MintRequest::new(ty)
                })
                .unwrap_err();
            assert!(
                matches!(err, Error::Parse(ref s) if s.contains("stay unclassified")),
                "{ty}: {err}"
            );
        }
        assert!(minter.ledger.is_empty().unwrap());
    }

    #[test]
    fn nickname_cui_is_rejected() {
        let pools = tiny_pools();
        let linter = LintEngine::core();
        let mut ledger = Ledger::open_memory().unwrap();
        let auth = Authority::from_seed("DIA", [11u8; 32]);
        let mut minter = Minter::new(&auth, &pools, &linter, &mut ledger);
        let err = minter
            .mint(MintRequest {
                marking: Marking {
                    level: Level::Cui,
                    ..Default::default()
                },
                ..MintRequest::new(NameType::Nickname)
            })
            .unwrap_err();
        assert!(
            matches!(err, Error::Parse(ref s) if s.contains("stay unclassified")),
            "{err}"
        );
    }

    #[test]
    fn program_bound_codeword_derives_and_ignores_request() {
        let pools = tiny_pools();
        let linter = LintEngine::core();
        let mut ledger = Ledger::open_memory_with_bindings().unwrap();
        let auth = Authority::from_seed("DIA", [11u8; 32]);
        seed_qsv(&mut ledger, &auth);
        let mut minter = Minter::new(&auth, &pools, &linter, &mut ledger);
        let minted = minter
            .mint(MintRequest {
                marking: Marking::default(),
                program_pid: Some("qsv".into()),
                compartment_id: Some("hol".into()),
                ..MintRequest::new(NameType::CodeWord)
            })
            .unwrap();
        assert_eq!(minted.marking.to_string(), "TS//TK//SAR-QSV-HOL//NF");
        verify_mint(&minted, &pools).unwrap();
        let rec = minter.ledger.lookup(&minted.name).unwrap().unwrap();
        assert_eq!(rec.marking, "TS//TK//SAR-QSV-HOL//NF");
        assert_eq!(rec.program_pid.as_deref(), Some("QSV"));
        assert_eq!(rec.compartment_id.as_deref(), Some("HOL"));
    }

    #[test]
    fn program_bound_nickname_records_pid_stays_u() {
        let pools = tiny_pools();
        let linter = LintEngine::core();
        let mut ledger = Ledger::open_memory_with_bindings().unwrap();
        let auth = Authority::from_seed("DIA", [11u8; 32]);
        seed_qsv(&mut ledger, &auth);
        for ty in [
            NameType::Nickname,
            NameType::ExerciseTerm,
            NameType::SapDesignator,
        ] {
            let mut minter = Minter::new(&auth, &pools, &linter, &mut ledger);
            let minted = minter
                .mint(MintRequest {
                    program_pid: Some("QSV".into()),
                    ..MintRequest::new(ty)
                })
                .unwrap();
            assert_eq!(minted.marking, Marking::default(), "{ty}");
            verify_mint(&minted, &pools).unwrap();
            let rec = minter.ledger.lookup(&minted.name).unwrap().unwrap();
            assert_eq!(rec.marking, "U", "{ty}");
            assert_eq!(rec.program_pid.as_deref(), Some("QSV"), "{ty}");
            assert!(rec.compartment_id.is_none(), "{ty}");
        }
    }

    #[test]
    fn program_bound_nickname_rejects_classified_even_with_program() {
        let pools = tiny_pools();
        let linter = LintEngine::core();
        let mut ledger = Ledger::open_memory_with_bindings().unwrap();
        let auth = Authority::from_seed("DIA", [11u8; 32]);
        seed_qsv(&mut ledger, &auth);
        let mut minter = Minter::new(&auth, &pools, &linter, &mut ledger);
        let err = minter
            .mint(MintRequest {
                marking: ts(),
                program_pid: Some("QSV".into()),
                ..MintRequest::new(NameType::Nickname)
            })
            .unwrap_err();
        assert!(matches!(err, Error::Parse(ref s) if s.contains("stay unclassified")));
    }

    #[test]
    fn free_standing_codeword_keeps_requested_marking() {
        let pools = tiny_pools();
        let linter = LintEngine::core();
        let mut ledger = Ledger::open_memory().unwrap();
        let auth = Authority::from_seed("DIA", [11u8; 32]);
        let mut minter = Minter::new(&auth, &pools, &linter, &mut ledger);
        let minted = minter
            .mint(MintRequest {
                marking: ts(),
                ..MintRequest::new(NameType::CodeWord)
            })
            .unwrap();
        assert_eq!(minted.marking.level, Level::TopSecret);
        verify_mint(&minted, &pools).unwrap();
    }

    #[test]
    fn compartment_requires_program() {
        let pools = tiny_pools();
        let linter = LintEngine::core();
        let mut ledger = Ledger::open_memory().unwrap();
        let auth = Authority::from_seed("DIA", [11u8; 32]);
        let mut minter = Minter::new(&auth, &pools, &linter, &mut ledger);
        let err = minter
            .mint(MintRequest {
                compartment_id: Some("HOL".into()),
                ..MintRequest::new(NameType::CodeWord)
            })
            .unwrap_err();
        assert!(matches!(err, Error::Parse(ref s) if s.contains("compartment_id requires")));
    }

    #[test]
    fn unknown_program_fails_before_issue() {
        let pools = tiny_pools();
        let linter = LintEngine::core();
        let mut ledger = Ledger::open_memory_with_bindings().unwrap();
        let auth = Authority::from_seed("DIA", [11u8; 32]);
        let mut minter = Minter::new(&auth, &pools, &linter, &mut ledger);
        let err = minter
            .mint(MintRequest {
                program_pid: Some("QSV".into()),
                ..MintRequest::new(NameType::CodeWord)
            })
            .unwrap_err();
        assert!(matches!(err, Error::Parse(ref s) if s.contains("unknown program")));
        assert!(minter.ledger.is_empty().unwrap());
    }

    #[test]
    fn program_bound_cryptonym_derives() {
        let pools = tiny_pools();
        let linter = LintEngine::core();
        let mut ledger = Ledger::open_memory_with_bindings().unwrap();
        let auth = Authority::from_seed("CIA", [19u8; 32]);
        seed_qsv(&mut ledger, &auth);
        let mut minter = Minter::new(&auth, &pools, &linter, &mut ledger);
        let minted = minter
            .mint(MintRequest {
                program_pid: Some("QSV".into()),
                ..MintRequest::new(NameType::Cryptonym)
            })
            .unwrap();
        assert_eq!(minted.marking.to_string(), "TS//TK//SAR-QSV//NF");
        verify_mint(&minted, &pools).unwrap();
    }

    #[test]
    fn dry_run_is_deterministic_and_ledger_free() {
        let pools = tiny_pools();
        let linter = LintEngine::core();
        let seed = [11u8; 32];
        let req = MintRequest {
            max_attempts: 8,
            ..MintRequest::new(NameType::Nickname)
        };
        let a = Minter::mint_dry_run(&seed, "DIA", &pools, &linter, req.clone()).unwrap();
        let b = Minter::mint_dry_run(&seed, "DIA", &pools, &linter, req).unwrap();
        assert!(!a.is_empty());
        assert_eq!(
            a.iter().map(|m| &m.name).collect::<Vec<_>>(),
            b.iter().map(|m| &m.name).collect::<Vec<_>>()
        );
        for m in &a {
            assert_eq!(m.ledger_seq, 0);
            assert!(m.event_hash.is_empty());
            assert_eq!(m.sequence, DRY_RUN_SEQ);
            verify_mint(m, &pools).unwrap();
        }
    }

    #[test]
    fn dry_run_first_matches_empty_ledger_mint() {
        let pools = tiny_pools();
        let linter = LintEngine::core();
        let seed = [11u8; 32];
        let req = MintRequest::new(NameType::Nickname);
        let candidates = Minter::mint_dry_run(&seed, "DIA", &pools, &linter, req.clone()).unwrap();
        let auth = Authority::from_seed("DIA", seed);
        let mut ledger = Ledger::open_memory().unwrap();
        let mut minter = Minter::new(&auth, &pools, &linter, &mut ledger);
        let issued = minter.mint(req).unwrap();
        assert_eq!(candidates[0].name, issued.name);
        assert_eq!(candidates[0].nonce, issued.nonce);
        assert_eq!(candidates[0].vrf_output, issued.vrf_output);
    }

    #[test]
    fn dry_run_refuses_program_bind() {
        let pools = tiny_pools();
        let linter = LintEngine::core();
        let err = Minter::mint_dry_run(
            &[3u8; 32],
            "DIA",
            &pools,
            &linter,
            MintRequest {
                program_pid: Some("QSV".into()),
                ..MintRequest::new(NameType::CodeWord)
            },
        )
        .unwrap_err();
        assert!(matches!(err, Error::Parse(ref s) if s.contains("dry-run")));
    }

    #[test]
    fn dry_run_nickname_stays_u() {
        let pools = tiny_pools();
        let linter = LintEngine::core();
        let err = Minter::mint_dry_run(
            &[11u8; 32],
            "DIA",
            &pools,
            &linter,
            MintRequest {
                marking: ts(),
                ..MintRequest::new(NameType::Nickname)
            },
        )
        .unwrap_err();
        assert!(matches!(err, Error::Parse(ref s) if s.contains("stay unclassified")));
    }
}
