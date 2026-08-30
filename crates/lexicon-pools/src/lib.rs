//! Bundled pools and agency allocations. Data, not mechanism.

use lexicon_core::linter::LintEngine;
use lexicon_core::pool::{AgencyAlloc, Pool, PoolSet, PoolWord};
use lexicon_core::types::POOL_ID;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::OnceLock;

const CROSSWD: &str = include_str!("../data/crosswd.txt");
const EX_FIRST: &str = include_str!("../data/exercise_first.txt");
const EX_SECOND: &str = include_str!("../data/exercise_second.txt");
const AGENCIES: &str = include_str!("../data/agencies.json");

/// JANAP-119 sample list shipped for the linter hook. Not authoritative.
pub const JANAP119_SAMPLE: &str = include_str!("../data/janap119_sample.txt");

const MIN_LEN: usize = 4;
const MAX_LEN: usize = 10;

#[derive(Deserialize)]
struct AgencyFile {
    agencies: Vec<AgencyJson>,
}

#[derive(Deserialize)]
struct AgencyJson {
    id: String,
    first_letters: String,
    digraphs: Vec<String>,
    sap_designators: Vec<String>,
}

pub fn bundled() -> &'static PoolSet {
    static POOLS: OnceLock<PoolSet> = OnceLock::new();
    POOLS.get_or_init(build)
}

fn build() -> PoolSet {
    let words = filter_crosswd(CROSSWD);
    let file: AgencyFile = serde_json::from_str(AGENCIES).expect("agencies.json");
    PoolSet {
        id: POOL_ID.into(),
        nickname_first: Pool {
            id: "nickname_first".into(),
            words: words.clone(),
        },
        nickname_second: Pool {
            id: "nickname_second".into(),
            words: words.clone(),
        },
        codeword: Pool {
            id: "codeword".into(),
            words: words.clone(),
        },
        cryptonym_word: Pool {
            id: "cryptonym_word".into(),
            words,
        },
        exercise_first: Pool::from_lines("exercise_first", EX_FIRST),
        exercise_second: Pool::from_lines("exercise_second", EX_SECOND),
        agencies: file
            .agencies
            .into_iter()
            .map(|a| AgencyAlloc {
                id: a.id.to_ascii_uppercase(),
                first_letters: a.first_letters.to_ascii_uppercase(),
                digraphs: a
                    .digraphs
                    .into_iter()
                    .map(|d| d.to_ascii_uppercase())
                    .collect(),
                sap_designators: a
                    .sap_designators
                    .into_iter()
                    .map(|d| d.to_ascii_uppercase())
                    .collect(),
            })
            .collect(),
    }
}

pub fn agency_ids() -> Vec<String> {
    bundled().agencies.iter().map(|a| a.id.clone()).collect()
}

fn filter_crosswd(text: &str) -> Vec<PoolWord> {
    let mut raw: Vec<String> = text.lines().filter_map(candidate).collect();
    raw.sort();
    raw.dedup();

    let stems: HashSet<String> = raw.iter().cloned().collect();
    let linter = LintEngine::core();
    raw.into_iter()
        .filter(|w| !regular_plural(w, &stems) && linter.rejects_word(w).is_none())
        .map(PoolWord::new)
        .collect()
}

fn candidate(line: &str) -> Option<String> {
    let w = line.trim();
    if w.is_empty() || w.starts_with('#') {
        return None;
    }
    if w.len() < MIN_LEN || w.len() > MAX_LEN {
        return None;
    }
    if !w.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    Some(w.to_ascii_uppercase())
}

fn regular_plural(word: &str, stems: &HashSet<String>) -> bool {
    word.strip_suffix('S')
        .is_some_and(|stem| stem.len() >= MIN_LEN && stems.contains(stem))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lexicon_core::types::NameType;

    #[test]
    fn every_agency_has_pools() {
        let pools = bundled();
        for a in &pools.agencies {
            for ty in [
                NameType::Nickname,
                NameType::CodeWord,
                NameType::Cryptonym,
                NameType::SapDesignator,
                NameType::ExerciseTerm,
            ] {
                let sizes = pools.pool_sizes(ty, &a.id).unwrap();
                assert!(sizes.iter().all(|&n| n > 0), "{} {:?}", a.id, ty);
            }
        }
    }

    #[test]
    fn crosswd_is_large_and_clean() {
        let pools = bundled();
        assert!(
            pools.nickname_first.len() >= 1500,
            "filtered pool too small: {}",
            pools.nickname_first.len()
        );
        let linter = lexicon_core::linter::LintEngine::core();
        assert!(linter.rejects_word("SECRET").is_some());
        let set: HashSet<&str> = pools
            .nickname_first
            .words
            .iter()
            .map(|w| w.word.as_str())
            .collect();
        for w in &pools.nickname_first.words {
            assert!(linter.rejects_word(&w.word).is_none(), "{}", w.word);
            if let Some(stem) = w.word.strip_suffix('S') {
                assert!(
                    !set.contains(stem),
                    "plural {} kept with stem {stem}",
                    w.word
                );
            }
        }
    }

    #[test]
    fn bundled_mint_unique_and_verifiable() {
        use lexicon_core::ledger::Ledger;
        use lexicon_core::linter::LintEngine;
        use lexicon_core::mint::{verify_mint, MintRequest, Minter};
        use lexicon_core::Authority;

        let pools = bundled();
        let linter = LintEngine::core();
        let mut ledger = Ledger::open_memory().unwrap();
        let auth = Authority::from_seed("DIA", [42u8; 32]);
        let mut seen = std::collections::HashSet::new();
        for ty in [
            NameType::Nickname,
            NameType::CodeWord,
            NameType::ExerciseTerm,
            NameType::Cryptonym,
        ] {
            for _ in 0..15 {
                let mut minter = Minter {
                    authority: &auth,
                    pools,
                    linter: &linter,
                    ledger: &mut ledger,
                };
                let minted = minter.mint(MintRequest::new(ty)).unwrap();
                verify_mint(&minted, pools).unwrap();
                assert!(seen.insert(minted.name), "duplicate {}", seen.len());
            }
        }
        ledger.verify_chain().unwrap();
        assert_eq!(seen.len(), 60);
    }
}
