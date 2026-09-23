use crate::error::{Error, Result};
use crate::types::NameType;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolWord {
    pub word: String,
    /// ISO-like language tags this word transliterates badly into (e.g. "ru").
    #[serde(default)]
    pub unsafe_langs: Vec<String>,
}

impl PoolWord {
    pub fn new(word: impl Into<String>) -> Self {
        Self {
            word: word.into().to_ascii_uppercase(),
            unsafe_langs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pool {
    pub id: String,
    pub words: Vec<PoolWord>,
}

impl Pool {
    pub fn from_lines(id: impl Into<String>, text: &str) -> Self {
        let words = text.lines().filter_map(parse_word_line).collect();
        Self {
            id: id.into(),
            words,
        }
    }

    pub fn get(&self, index: u32) -> Result<&PoolWord> {
        self.words
            .get(index as usize)
            .ok_or_else(|| Error::Parse(format!("index {index} out of pool {}", self.id)))
    }

    pub fn len(&self) -> usize {
        self.words.len()
    }

    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }

    pub fn starting_with(&self, letters: &str) -> Pool {
        let set: Vec<char> = letters.to_ascii_uppercase().chars().collect();
        let words = self
            .words
            .iter()
            .filter(|w| w.word.chars().next().is_some_and(|c| set.contains(&c)))
            .cloned()
            .collect();
        Pool {
            id: format!("{}[{}]", self.id, letters),
            words,
        }
    }
}

fn parse_word_line(line: &str) -> Option<PoolWord> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut parts = line.split('\t');
    let word = parts.next()?.trim().to_ascii_uppercase();
    if word.is_empty() {
        return None;
    }
    let mut unsafe_langs = Vec::new();
    for part in parts {
        if let Some(rest) = part.strip_prefix("unsafe=") {
            unsafe_langs.extend(
                rest.split(',')
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty()),
            );
        }
    }
    Some(PoolWord { word, unsafe_langs })
}

#[derive(Debug, Clone)]
pub struct AgencyAlloc {
    pub id: String,
    /// First-word initial-letter block (NICKA-style allocation).
    pub first_letters: String,
    pub digraphs: Vec<String>,
    pub sap_designators: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PoolSet {
    pub id: String,
    pub nickname_first: Pool,
    pub nickname_second: Pool,
    pub codeword: Pool,
    pub cryptonym_word: Pool,
    pub exercise_first: Pool,
    pub exercise_second: Pool,
    pub agencies: Vec<AgencyAlloc>,
}

impl PoolSet {
    pub fn agency(&self, id: &str) -> Result<&AgencyAlloc> {
        let needle = id.to_ascii_uppercase();
        self.agencies
            .iter()
            .find(|a| a.id == needle)
            .ok_or_else(|| Error::UnknownAgency(id.to_string()))
    }

    pub fn first_pool(&self, name_type: NameType, agency: &str) -> Result<Pool> {
        let alloc = self.agency(agency)?;
        match name_type {
            NameType::Nickname => {
                let p = self.nickname_first.starting_with(&alloc.first_letters);
                if p.is_empty() {
                    return Err(Error::EmptyPool(p.id));
                }
                Ok(p)
            }
            NameType::ExerciseTerm => {
                let p = self.exercise_first.starting_with(&alloc.first_letters);
                if p.is_empty() {
                    return Err(Error::EmptyPool(p.id));
                }
                Ok(p)
            }
            NameType::CodeWord => Ok(self.codeword.clone()),
            NameType::Cryptonym => {
                if alloc.digraphs.is_empty() {
                    return Err(Error::EmptyPool(format!("{agency} digraphs")));
                }
                Ok(Pool {
                    id: format!("digraph:{agency}"),
                    words: alloc.digraphs.iter().map(PoolWord::new).collect(),
                })
            }
            NameType::SapDesignator => {
                if alloc.sap_designators.is_empty() {
                    return Err(Error::EmptyPool(format!("{agency} sap")));
                }
                Ok(Pool {
                    id: format!("sap:{agency}"),
                    words: alloc.sap_designators.iter().map(PoolWord::new).collect(),
                })
            }
        }
    }

    pub fn second_pool(&self, name_type: NameType) -> Option<&Pool> {
        match name_type {
            NameType::Nickname => Some(&self.nickname_second),
            NameType::ExerciseTerm => Some(&self.exercise_second),
            NameType::Cryptonym => Some(&self.cryptonym_word),
            NameType::CodeWord | NameType::SapDesignator => None,
        }
    }

    pub fn compose(&self, name_type: NameType, agency: &str, indices: &[u32]) -> Result<String> {
        let first = self.first_pool(name_type, agency)?;
        match name_type {
            NameType::CodeWord | NameType::SapDesignator => {
                let w = first.get(*indices.first().ok_or(Error::IndexMismatch)?)?;
                Ok(w.word.clone())
            }
            NameType::Cryptonym => {
                let dg = first.get(*indices.first().ok_or(Error::IndexMismatch)?)?;
                let word_pool = self
                    .cryptonym_word
                    .get(*indices.get(1).ok_or(Error::IndexMismatch)?)?;
                Ok(format!("{}{}", dg.word, word_pool.word))
            }
            NameType::Nickname | NameType::ExerciseTerm => {
                let a = first.get(*indices.first().ok_or(Error::IndexMismatch)?)?;
                let second = self
                    .second_pool(name_type)
                    .ok_or_else(|| Error::UnknownPool("second".into()))?;
                let b = second.get(*indices.get(1).ok_or(Error::IndexMismatch)?)?;
                Ok(format!("{} {}", a.word, b.word))
            }
        }
    }

    pub fn pool_sizes(&self, name_type: NameType, agency: &str) -> Result<Vec<usize>> {
        let first = self.first_pool(name_type, agency)?;
        Ok(match name_type {
            NameType::CodeWord | NameType::SapDesignator => vec![first.len()],
            NameType::Cryptonym | NameType::Nickname | NameType::ExerciseTerm => {
                let second = self
                    .second_pool(name_type)
                    .ok_or_else(|| Error::UnknownPool("second".into()))?;
                vec![first.len(), second.len()]
            }
        })
    }

    pub fn lookup_words(
        &self,
        name_type: NameType,
        agency: &str,
        indices: &[u32],
    ) -> Result<Vec<PoolWord>> {
        let first = self.first_pool(name_type, agency)?;
        let mut out = vec![first
            .get(*indices.first().ok_or(Error::IndexMismatch)?)?
            .clone()];
        if let Some(second) = self.second_pool(name_type) {
            out.push(
                second
                    .get(*indices.get(1).ok_or(Error::IndexMismatch)?)?
                    .clone(),
            );
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_unsafe_flag() {
        let p = Pool::from_lines("t", "ALPHA\nBETA\tunsafe=ru,ar\n# skip\n");
        assert_eq!(p.len(), 2);
        assert_eq!(p.words[1].unsafe_langs, vec!["ru", "ar"]);
    }
}
