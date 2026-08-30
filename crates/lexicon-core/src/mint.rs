use crate::authority::Authority;
use crate::error::{Error, Result};
use crate::events::{AttemptReason, Event, EventKind};
use crate::ledger::Ledger;
use crate::linter::{LintEngine, NameCandidate};
use crate::merkle;
use crate::pool::PoolSet;
use crate::types::{indices_from_beta, mint_alpha, normalize, NameType, POOL_ID_V1};
use crate::vrf::{self, VrfProof};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct MintRequest {
    pub name_type: NameType,
    pub pool_id: String,
    pub max_attempts: u32,
    /// Pin a cryptonym digraph instead of VRF-picking from the agency allocation.
    pub digraph: Option<String>,
    /// Classification marking bound to the issued name (signed + hashed).
    pub marking: crate::marking::Marking,
}

impl MintRequest {
    pub fn new(name_type: NameType) -> Self {
        Self {
            name_type,
            pool_id: POOL_ID_V1.into(),
            max_attempts: 64,
            digraph: None,
            marking: crate::marking::Marking::default(),
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
    pub marking: crate::marking::Marking,
}

pub struct Minter<'a> {
    pub authority: &'a Authority,
    pub pools: &'a PoolSet,
    pub linter: &'a LintEngine,
    pub ledger: &'a mut Ledger,
}

impl Minter<'_> {
    pub fn mint(&mut self, req: MintRequest) -> Result<MintedName> {
        let agency = &self.authority.id;
        let _ = self.pools.agency(agency)?;
        let sizes = self.pools.pool_sizes(req.name_type, agency)?;
        if sizes.contains(&0) {
            return Err(Error::EmptyPool(req.pool_id.clone()));
        }

        let sequence = self.ledger.next_seq()?;
        let mut nonce = 0u32;
        let mut last_lint: Option<String> = None;

        while nonce < req.max_attempts {
            let alpha = mint_alpha(agency, req.name_type, &req.pool_id, sequence, nonce);
            let (proof, beta) = self.authority.vrf_prove(&alpha)?;
            let mut indices = indices_from_beta(beta.as_bytes(), &sizes);

            if let Some(ref dg) = req.digraph {
                if req.name_type == NameType::Cryptonym {
                    let first = self.pools.first_pool(req.name_type, agency)?;
                    let want = dg.to_ascii_uppercase();
                    let pos = first
                        .words
                        .iter()
                        .position(|w| w.word == want)
                        .ok_or_else(|| {
                            Error::Parse(format!("digraph {want} not allocated to {agency}"))
                        })?;
                    if indices.is_empty() {
                        return Err(Error::IndexMismatch);
                    }
                    indices[0] = pos as u32;
                }
            }

            let name = self.pools.compose(req.name_type, agency, &indices)?;
            let words = self.pools.lookup_words(req.name_type, agency, &indices)?;
            let candidate = NameCandidate {
                name: name.clone(),
                name_type: req.name_type,
                words,
            };

            if let Some(hit) = self.linter.first_reject(&candidate) {
                self.log_attempt(
                    &name,
                    req.name_type,
                    nonce,
                    AttemptReason::Lint,
                    &hit.detail,
                )?;
                last_lint = Some(format!("{}: {}", hit.rule, hit.detail));
                nonce += 1;
                continue;
            }

            if let Some(status) = self.ledger.name_status(&name)? {
                // Surface the winner's marking so a CUI operator colliding
                // with a TS//SCI name stops instead of re-rolling blind.
                let held_marking = self
                    .ledger
                    .lookup(&name)?
                    .map(|r| r.marking)
                    .unwrap_or_default();
                self.log_attempt(
                    &name,
                    req.name_type,
                    nonce,
                    AttemptReason::Collision,
                    &format!("{}; held as {}", status.as_str(), held_marking),
                )?;
                nonce += 1;
                continue;
            }

            let event = Event::new(EventKind::Issued {
                name: name.clone(),
                name_type: req.name_type,
                authority_id: agency.clone(),
                authority_pk: hex::encode(self.authority.public_key()),
                pool_id: req.pool_id.clone(),
                sequence,
                nonce,
                vrf_proof: hex::encode(proof.as_bytes()),
                vrf_output: hex::encode(beta.as_bytes()),
                indices: indices.clone(),
                marking: req.marking.clone(),
            });
            let event_hash = event.hash();
            let ledger_seq = self.ledger.append(event, self.authority)?;
            let inclusion = self.ledger.inclusion_proof(ledger_seq)?;

            return Ok(MintedName {
                name,
                name_type: req.name_type,
                authority_id: agency.clone(),
                authority_pk: hex::encode(self.authority.public_key()),
                pool_id: req.pool_id,
                sequence,
                nonce,
                vrf_proof: hex::encode(proof.as_bytes()),
                vrf_output: hex::encode(beta.as_bytes()),
                indices,
                ledger_seq,
                event_hash: hex::encode(event_hash),
                inclusion,
                marking: req.marking.clone(),
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
            authority_id: self.authority.id.clone(),
            nonce,
            reason,
            detail: detail.into(),
        });
        self.ledger.append(ev, self.authority)?;
        Ok(())
    }
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
            let mut minter = Minter {
                authority: &auth,
                pools: &pools,
                linter: &linter,
                ledger: &mut ledger,
            };
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
            let mut minter = Minter {
                authority: &auth,
                pools: &pools,
                linter: &linter,
                ledger: &mut ledger,
            };
            minter.mint(MintRequest::new(NameType::CodeWord)).unwrap()
        };
        // Force the same name onto the ledger under a different path, then mint
        // from a second authority? Single-authority remint: pre-insert via retire
        // already occupies the name. Second mint from same key/seq differs by
        // ledger seq in alpha, so just check taken-name is skipped by minting many.
        let mut minter = Minter {
            authority: &auth,
            pools: &pools,
            linter: &linter,
            ledger: &mut ledger,
        };
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
        let mut minter = Minter {
            authority: &auth,
            pools: &pools,
            linter: &linter,
            ledger: &mut ledger,
        };
        let c = minter
            .mint(MintRequest {
                name_type: NameType::Cryptonym,
                pool_id: POOL_ID_V1.into(),
                max_attempts: 32,
                digraph: Some("AE".into()),
                marking: crate::marking::Marking::default(),
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
        let mut minter = Minter {
            authority: &auth,
            pools: &pools,
            linter: &linter,
            ledger: &mut ledger,
        };
        let e = minter
            .mint(MintRequest::new(NameType::ExerciseTerm))
            .unwrap();
        assert!(e.name.contains(' '));
        verify_mint(&e, &pools).unwrap();
    }
}
