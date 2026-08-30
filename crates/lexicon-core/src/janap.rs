//! JANAP-119A Table II: word → slot → digraph.
//!
//! Slot is exclusive. `COB` (no digraph) is skipped. Duplicate words with
//! different codes (MORE, PLAID) are kept as separate entries; the lint
//! set is the word.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JanapSlot {
    First,
    Second,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JanapEntry {
    pub word: String,
    pub slot: JanapSlot,
    pub digraph: String,
}

#[derive(Debug, Clone)]
pub struct JanapTable {
    pub entries: Vec<JanapEntry>,
    words: HashSet<String>,
    first: HashSet<String>,
    second: HashSet<String>,
}

impl JanapTable {
    pub fn parse(tsv: &str) -> Result<Self> {
        let mut entries = Vec::new();
        for (i, line) in tsv.lines().enumerate() {
            let line = line.trim_end();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let cols: Vec<&str> = line.split('\t').collect();
            if i == 0 && cols.first().is_some_and(|c| c.eq_ignore_ascii_case("word")) {
                continue;
            }
            let word = cols.first().copied().unwrap_or("").trim();
            if word.is_empty() {
                continue;
            }
            if !word.bytes().all(|b| b.is_ascii_alphabetic()) {
                return Err(Error::Parse(format!(
                    "janap line {}: bad word {word}",
                    i + 1
                )));
            }
            let d1 = cols.get(1).copied().unwrap_or("").trim();
            let d2 = cols.get(2).copied().unwrap_or("").trim();
            let (slot, digraph) = match (d1.is_empty(), d2.is_empty()) {
                (false, true) => (JanapSlot::First, d1),
                (true, false) => (JanapSlot::Second, d2),
                (true, true) => continue, // COB
                (false, false) => {
                    return Err(Error::Parse(format!(
                        "janap line {}: {word} has both slots",
                        i + 1
                    )));
                }
            };
            entries.push(JanapEntry {
                word: word.to_ascii_uppercase(),
                slot,
                digraph: digraph.to_ascii_uppercase(),
            });
        }
        Ok(Self::from_entries(entries))
    }

    fn from_entries(entries: Vec<JanapEntry>) -> Self {
        let mut words = HashSet::new();
        let mut first = HashSet::new();
        let mut second = HashSet::new();
        for e in &entries {
            words.insert(e.word.clone());
            match e.slot {
                JanapSlot::First => {
                    first.insert(e.word.clone());
                }
                JanapSlot::Second => {
                    second.insert(e.word.clone());
                }
            }
        }
        Self {
            entries,
            words,
            first,
            second,
        }
    }

    pub fn contains(&self, word: &str) -> bool {
        self.words.contains(&word.to_ascii_uppercase())
    }

    pub fn is_first(&self, word: &str) -> bool {
        self.first.contains(&word.to_ascii_uppercase())
    }

    pub fn is_second(&self, word: &str) -> bool {
        self.second.contains(&word.to_ascii_uppercase())
    }

    pub fn word_set(&self) -> &HashSet<String> {
        &self.words
    }

    pub fn len(&self) -> usize {
        self.words.len()
    }

    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = "\
word\tfirst_digraph\tsecond_digraph
HAWK\tE3\t
RAVEN\t\tGK
COB\t\t
MORE\tK9\t
MORE\t97\t
";

    #[test]
    fn parse_skips_cob_keeps_more() {
        let t = JanapTable::parse(FIXTURE).unwrap();
        assert!(t.contains("HAWK"));
        assert!(t.is_first("HAWK"));
        assert!(t.is_second("RAVEN"));
        assert!(!t.contains("COB"));
        assert_eq!(
            t.entries
                .iter()
                .filter(|e| e.word == "MORE")
                .map(|e| e.digraph.as_str())
                .collect::<Vec<_>>(),
            ["K9", "97"]
        );
        assert_eq!(t.len(), 3);
    }
}
