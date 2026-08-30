//! Bundled pools and agency allocations. Data, not mechanism.

use lexicon_core::janap::JanapTable;
use lexicon_core::linter::LintEngine;
use lexicon_core::pool::{AgencyAlloc, Pool, PoolSet, PoolWord};
use lexicon_core::types::POOL_ID;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::OnceLock;

const CROSSWD: &str = include_str!("../data/crosswd.txt");
const AGENCIES: &str = include_str!("../data/agencies.json");
const JANAP119A: &str = include_str!("../data/JANAP_119A_Table_II.tsv");
const HISTORICAL: &str = include_str!("../data/historical_cryptonyms.txt");
const MILITARY: &str = include_str!("../data/military_acronyms.txt");

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

pub fn janap() -> &'static JanapTable {
    static TABLE: OnceLock<JanapTable> = OnceLock::new();
    TABLE.get_or_init(|| JanapTable::parse(JANAP119A).expect("JANAP_119A_Table_II.tsv"))
}

pub fn bundled_linter() -> LintEngine {
    let mut engine = LintEngine::with_janap(janap());
    engine.push_rule(Box::new(lexicon_core::RejectListRule::new(
        "historical_cryptonym",
        reject_words(HISTORICAL),
    )));
    engine.push_rule(Box::new(lexicon_core::RejectListRule::new(
        "military_acronym",
        reject_words(MILITARY),
    )));
    engine
}

fn reject_words(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|w| w.to_ascii_uppercase())
        .collect()
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
            words: words.clone(),
        },
        exercise_first: Pool {
            id: "exercise_first".into(),
            words: words.clone(),
        },
        exercise_second: Pool {
            id: "exercise_second".into(),
            words,
        },
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
    let engine = bundled_linter();
    raw.into_iter()
        .filter(|w| !regular_plural(w, &stems) && engine.rejects_word(w).is_none())
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
    fn janap_table_ii_loads() {
        let t = janap();
        assert!(t.contains("HAWK") && t.is_first("HAWK"));
        assert!(t.contains("PANTHER") && t.is_second("PANTHER"));
        assert!(!t.contains("COB"));
        assert!(!t.contains("EAGLE"));
        assert!(t.contains("MORE"));
        assert!(t.len() >= 2700, "janap words: {}", t.len());
        assert!(
            t.entries.iter().filter(|e| e.word == "MORE").count() == 2,
            "MORE should keep both codes"
        );
    }

    #[test]
    fn every_agency_has_pools() {
        let pools = bundled();
        for a in &pools.agencies {
            for ty in [
                NameType::Nickname,
                NameType::CodeWord,
                NameType::SapDesignator,
                NameType::ExerciseTerm,
            ] {
                let sizes = pools.pool_sizes(ty, &a.id).unwrap();
                assert!(sizes.iter().all(|&n| n > 0), "{} {:?}", a.id, ty);
            }
            // Cryptonym is a CIA convention; only agencies with digraphs can mint it.
            if a.digraphs.is_empty() {
                assert!(
                    pools.pool_sizes(NameType::Cryptonym, &a.id).is_err(),
                    "{} should not mint cryptonyms",
                    a.id
                );
            } else {
                let sizes = pools.pool_sizes(NameType::Cryptonym, &a.id).unwrap();
                assert!(sizes.iter().all(|&n| n > 0), "{} Cryptonym", a.id);
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
        let engine = bundled_linter();
        assert!(engine.rejects_word("SECRET").is_some());
        assert!(engine.rejects_word("HAWK").is_some());
        assert!(!pools.nickname_first.words.iter().any(|w| w.word == "HAWK"));
        let set: HashSet<&str> = pools
            .nickname_first
            .words
            .iter()
            .map(|w| w.word.as_str())
            .collect();
        for w in &pools.nickname_first.words {
            assert!(engine.rejects_word(&w.word).is_none(), "{}", w.word);
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
    fn historical_cryptonyms_rejected_and_purged() {
        let pools = bundled();
        let engine = bundled_linter();
        // Notable historical names must not be mintable as codewords...
        for w in [
            "CORONA", "PHOENIX", "MKULTRA", "RAWHIDE", "LANCER", "STARGATE",
        ] {
            assert!(engine.rejects_word(w).is_some(), "{w} not rejected");
        }
        // ...and must not survive pool curation.
        for w in [
            "CORONA", "PHOENIX", "RAWHIDE", "LANCER", "MONGOOSE", "EAGLE",
        ] {
            assert!(
                !pools.codeword.words.iter().any(|p| p.word == w),
                "{w} leaked into codeword pool"
            );
            assert!(
                !pools.nickname_first.words.iter().any(|p| p.word == w),
                "{w} leaked into nickname_first pool"
            );
        }
        // Sanity: a plain dictionary word is still allowed.
        assert!(engine.rejects_word("GRANITE").is_none());
    }

    #[test]
    fn military_acronyms_rejected_and_purged() {
        let pools = bundled();
        let engine = bundled_linter();
        // Weapon systems are real words that DO enter the crossword pool.
        for w in [
            "PATRIOT", "JAVELIN", "STINGER", "TOMAHAWK", "PREDATOR", "REAPER",
        ] {
            assert!(engine.rejects_word(w).is_some(), "{w} not rejected");
            assert!(
                !pools.codeword.words.iter().any(|p| p.word == w),
                "{w} leaked into codeword pool"
            );
        }
        // INT disciplines / combatant commands aren't dictionary words but
        // must be rejected on compose (defense-in-depth for future pools).
        for w in [
            "HUMINT", "SIGINT", "COMINT", "OSINT", "MASINT", "IMINT", "CENTCOM", "CONUS",
        ] {
            assert!(engine.rejects_word(w).is_some(), "{w} not rejected");
        }
        // The reject set is the full wikipedia sweep, not a sample.
        let count = MILITARY
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .count();
        assert!(count >= 1000, "military_acronyms.txt too thin: {count}");
    }

    #[test]
    fn bundled_mint_unique_and_verifiable() {
        use lexicon_core::ledger::Ledger;
        use lexicon_core::mint::{verify_mint, MintRequest, Minter};
        use lexicon_core::Authority;

        let pools = bundled();
        let linter = bundled_linter();
        let mut ledger = Ledger::open_memory().unwrap();
        let dia = Authority::from_seed("DIA", [42u8; 32]);
        let cia = Authority::from_seed("CIA", [7u8; 32]);
        let mut seen = std::collections::HashSet::new();
        // Non-cryptonym types under DIA (exercises the GHI letter block).
        for ty in [
            NameType::Nickname,
            NameType::CodeWord,
            NameType::ExerciseTerm,
        ] {
            for _ in 0..15 {
                let mut minter = Minter {
                    authority: &dia,
                    pools,
                    linter: &linter,
                    ledger: &mut ledger,
                };
                let minted = minter.mint(MintRequest::new(ty)).unwrap();
                verify_mint(&minted, pools).unwrap();
                assert!(seen.insert(minted.name), "duplicate {}", seen.len());
            }
        }
        // Cryptonym is a CIA convention; only CIA carries digraphs.
        for _ in 0..15 {
            let mut minter = Minter {
                authority: &cia,
                pools,
                linter: &linter,
                ledger: &mut ledger,
            };
            let minted = minter.mint(MintRequest::new(NameType::Cryptonym)).unwrap();
            verify_mint(&minted, pools).unwrap();
            assert!(seen.insert(minted.name), "duplicate {}", seen.len());
        }
        ledger.verify_chain().unwrap();
        assert_eq!(seen.len(), 60);
    }
}
