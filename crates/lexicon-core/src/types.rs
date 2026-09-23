use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Bundled pool set identifier. Bump when word lists change incompatibly.
pub const POOL_ID: &str = "lexicon-pools-v4";
#[doc(hidden)]
pub const POOL_ID_V1: &str = POOL_ID;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameType {
    /// Two unclassified words. NICKA nickname successor.
    Nickname,
    /// Single word. NICKA code-word successor.
    CodeWord,
    /// Digraph prefix + word (AEFOXTROT). CIA cryptonym convention.
    Cryptonym,
    /// Digraph or trigraph (TK, HCS). SAP/SCI designator form.
    SapDesignator,
    /// Two words from the exercise namespace. Distinct from real-world names.
    ExerciseTerm,
}

impl NameType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nickname => "nickname",
            Self::CodeWord => "codeword",
            Self::Cryptonym => "cryptonym",
            Self::SapDesignator => "sap",
            Self::ExerciseTerm => "exercise",
        }
    }

    pub fn tag(self) -> u8 {
        match self {
            Self::Nickname => 1,
            Self::CodeWord => 2,
            Self::Cryptonym => 3,
            Self::SapDesignator => 4,
            Self::ExerciseTerm => 5,
        }
    }

    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Nickname),
            2 => Some(Self::CodeWord),
            3 => Some(Self::Cryptonym),
            4 => Some(Self::SapDesignator),
            5 => Some(Self::ExerciseTerm),
            _ => None,
        }
    }
}

impl fmt::Display for NameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for NameType {
    type Err = crate::Error;

    fn from_str(s: &str) -> crate::Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "nickname" | "nick" => Ok(Self::Nickname),
            "codeword" | "code-word" | "code" => Ok(Self::CodeWord),
            "cryptonym" | "crypt" => Ok(Self::Cryptonym),
            "sap" | "sap-designator" | "trigraph" | "digraph" => Ok(Self::SapDesignator),
            "exercise" | "exercise-term" => Ok(Self::ExerciseTerm),
            other => Err(crate::Error::Parse(format!("unknown name type: {other}"))),
        }
    }
}

/// Collapse whitespace and uppercase. Ledger uniqueness key.
pub fn normalize(name: &str) -> String {
    name.split_whitespace()
        .filter(|w| !w.is_empty())
        .map(|w| w.to_ascii_uppercase())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Canonical VRF alpha: authority, type, pool, sequence, nonce.
///
/// Length-prefixed so field boundaries can't slide.
pub fn mint_alpha(
    authority_id: &str,
    name_type: NameType,
    pool_id: &str,
    sequence: u64,
    nonce: u32,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64 + authority_id.len() + pool_id.len());
    buf.extend_from_slice(b"MERIDIAN-MINT-v1\0");
    write_len_str(&mut buf, authority_id);
    buf.push(name_type.tag());
    write_len_str(&mut buf, pool_id);
    buf.extend_from_slice(&sequence.to_le_bytes());
    buf.extend_from_slice(&nonce.to_le_bytes());
    buf
}

fn write_len_str(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = u16::try_from(bytes.len()).expect("field exceeds u16");
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// Two u64 LE windows of `beta`, reduced into pool sizes.
pub fn indices_from_beta(beta: &[u8; 64], sizes: &[usize]) -> Vec<u32> {
    sizes
        .iter()
        .enumerate()
        .map(|(i, &n)| {
            assert!(n > 0, "empty pool");
            let off = i * 8;
            let slice = beta
                .get(off..off + 8)
                .expect("beta too short for requested indices");
            let raw = u64::from_le_bytes(slice.try_into().expect("8 bytes"));
            (raw % n as u64) as u32
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_collapses() {
        assert_eq!(normalize("  granite   spire "), "GRANITE SPIRE");
        assert_eq!(normalize("aefoxtrot"), "AEFOXTROT");
    }

    #[test]
    fn alpha_is_stable() {
        let a = mint_alpha("DIA", NameType::Nickname, POOL_ID_V1, 7, 2);
        let b = mint_alpha("DIA", NameType::Nickname, POOL_ID_V1, 7, 2);
        assert_eq!(a, b);
        let c = mint_alpha("DIA", NameType::Nickname, POOL_ID_V1, 7, 3);
        assert_ne!(a, c);
    }
}
