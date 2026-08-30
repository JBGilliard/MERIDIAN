//! RFC 6962-style Merkle tree (Certificate Transparency lineage).
//!
//! leaf = SHA256(0x00 || data)
//! node = SHA256(0x01 || left || right)
//! Odd leftover at a level is promoted, not duplicated.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    h.finalize().into()
}

pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Empty tree root: SHA256 of nothing. Distinct from a one-leaf tree.
pub fn empty_root() -> [u8; 32] {
    Sha256::digest([]).into()
}

pub fn root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return empty_root();
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(node_hash(&level[i], &level[i + 1]));
                i += 2;
            } else {
                next.push(level[i]);
                i += 1;
            }
        }
        level = next;
    }
    level[0]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    pub leaf_index: u64,
    pub leaf_hash: String,
    pub siblings: Vec<Sibling>,
    pub root: String,
    pub leaf_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sibling {
    pub hash: String,
    pub is_left: bool,
}

pub fn prove(leaves: &[[u8; 32]], index: usize) -> Option<InclusionProof> {
    if index >= leaves.len() {
        return None;
    }
    let mut idx = index;
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut siblings = Vec::new();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        let mut next_idx = 0;
        let mut found = None;
        while i < level.len() {
            if i + 1 < level.len() {
                if i == idx {
                    siblings.push(Sibling {
                        hash: hex::encode(level[i + 1]),
                        is_left: false,
                    });
                    found = Some(next.len());
                } else if i + 1 == idx {
                    siblings.push(Sibling {
                        hash: hex::encode(level[i]),
                        is_left: true,
                    });
                    found = Some(next.len());
                }
                next.push(node_hash(&level[i], &level[i + 1]));
                i += 2;
            } else {
                if i == idx {
                    found = Some(next.len());
                }
                next.push(level[i]);
                i += 1;
            }
            if found.is_some() && next_idx == 0 {
                next_idx = next.len() - 1;
            }
        }
        idx = found?;
        level = next;
    }
    Some(InclusionProof {
        leaf_index: index as u64,
        leaf_hash: hex::encode(leaves[index]),
        siblings,
        root: hex::encode(level[0]),
        leaf_count: leaves.len() as u64,
    })
}

pub fn verify_inclusion(proof: &InclusionProof) -> bool {
    let mut acc = match hex::decode(&proof.leaf_hash) {
        Ok(v) => {
            let arr: [u8; 32] = match v.try_into() {
                Ok(a) => a,
                Err(_) => return false,
            };
            arr
        }
        Err(_) => return false,
    };
    for sib in &proof.siblings {
        let Ok(raw) = hex::decode(&sib.hash) else {
            return false;
        };
        let Ok(h) = <[u8; 32]>::try_from(raw) else {
            return false;
        };
        acc = if sib.is_left {
            node_hash(&h, &acc)
        } else {
            node_hash(&acc, &h)
        };
    }
    hex::encode(acc) == proof.root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|i| leaf_hash(&[i as u8])).collect()
    }

    #[test]
    fn empty_and_one() {
        assert_ne!(root(&[]), root(&leaves(1)));
        let l = leaves(1);
        let p = prove(&l, 0).unwrap();
        assert!(verify_inclusion(&p));
        assert_eq!(p.siblings.len(), 0);
    }

    #[test]
    fn odd_and_even() {
        for n in 2..=17 {
            let l = leaves(n);
            let r = root(&l);
            for i in 0..n {
                let p = prove(&l, i).unwrap();
                assert_eq!(p.root, hex::encode(r));
                assert!(verify_inclusion(&p), "n={n} i={i}");
            }
        }
    }

    #[test]
    fn tamper_fails() {
        let l = leaves(8);
        let mut p = prove(&l, 3).unwrap();
        p.siblings[0].hash = hex::encode([0u8; 32]);
        assert!(!verify_inclusion(&p));
    }
}
