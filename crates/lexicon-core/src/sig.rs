//! Pluggable event-signature algorithm.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// One byte on the wire. New algorithms append; never renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SigAlg {
    #[default]
    Ed25519 = 1,
    /// FIPS 204 ML-DSA-65. Reserved: not in the OSS build; a ledger
    /// carrying it reads (canonical + Merkle) but verify returns
    /// `UnsupportedAlg` until a PQ build is linked.
    MlDsa65 = 2,
}

impl SigAlg {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(b: u8) -> Result<Self> {
        match b {
            1 => Ok(Self::Ed25519),
            2 => Ok(Self::MlDsa65),
            other => Err(Error::Parse(format!("unknown signature algorithm {other}"))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::MlDsa65 => "ml-dsa-65",
        }
    }
}

/// One signature under one algorithm. A `Signature` is a list of these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigPart {
    pub alg: SigAlg,
    pub bytes: Vec<u8>,
}

/// Algorithm-tagged signature. Wire: `[count: u8][alg_u8, len_u16_le, bytes]...`
/// One part today; a list enables hybrid and two-person control without
/// a ledger-format break - the blob is not `canonical`, not Merkle-hashed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub parts: Vec<SigPart>,
}

impl Signature {
    pub fn new(alg: SigAlg, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            parts: vec![SigPart {
                alg,
                bytes: bytes.into(),
            }],
        }
    }

    pub fn from_parts(parts: Vec<SigPart>) -> Self {
        Self { parts }
    }

    /// Flatten N single-part signatures into one multi-part signature
    /// (two-person control: each authority signs, then join).
    pub fn join(signatures: Vec<Signature>) -> Self {
        let mut parts = Vec::new();
        for s in signatures {
            parts.extend(s.parts);
        }
        Self { parts }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.parts.len() * 4);
        out.push(self.parts.len() as u8);
        for p in &self.parts {
            out.push(p.alg.as_u8());
            let len = u16::try_from(p.bytes.len()).expect("sig part exceeds u16");
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&p.bytes);
        }
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.is_empty() {
            return Err(Error::Parse("empty signature".into()));
        }
        let count = b[0] as usize;
        let mut parts = Vec::with_capacity(count);
        let mut i = 1;
        for _ in 0..count {
            if i + 3 > b.len() {
                return Err(Error::Parse("truncated signature part header".into()));
            }
            let alg = SigAlg::from_u8(b[i])?;
            let len = u16::from_le_bytes([b[i + 1], b[i + 2]]) as usize;
            i += 3;
            if i + len > b.len() {
                return Err(Error::Parse("truncated signature part body".into()));
            }
            parts.push(SigPart {
                alg,
                bytes: b[i..i + len].to_vec(),
            });
            i += len;
        }
        Ok(Self { parts })
    }
}

/// Produces signatures under a single declared algorithm.
pub trait Signer {
    fn alg(&self) -> SigAlg;
    fn sign(&self, msg: &[u8]) -> Signature;
}

#[cfg(feature = "pq")]
pub struct MlDsaSigner {
    seed: [u8; 32],
}

#[cfg(feature = "pq")]
impl MlDsaSigner {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        crate::crypto::fill_random(&mut seed);
        Self { seed }
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        crate::crypto::mldsa_public_key(&self.seed)
    }
}

#[cfg(feature = "pq")]
impl Signer for MlDsaSigner {
    fn alg(&self) -> SigAlg {
        SigAlg::MlDsa65
    }

    fn sign(&self, msg: &[u8]) -> Signature {
        let bytes = crate::crypto::mldsa_sign(&self.seed, msg).expect("ml-dsa-65 sign");
        Signature::new(SigAlg::MlDsa65, bytes)
    }
}

/// Verify every part of `sig` against `pks`. Each part must verify
/// under exactly one pk, and each pk is used at most once — a two-part
/// signature requires two distinct pks (two-person control).
pub fn verify(pks: &[&[u8]], msg: &[u8], sig: &Signature) -> Result<()> {
    if sig.parts.is_empty() {
        return Err(Error::BadSignature);
    }
    if pks.len() < sig.parts.len() {
        return Err(Error::BadSignature);
    }
    let mut used = vec![false; pks.len()];
    for part in &sig.parts {
        // Without the `pq` feature, ML-DSA is a build/config error
        // (the OSS binary can't verify it), not a bad signature.
        #[cfg(not(feature = "pq"))]
        if part.alg == SigAlg::MlDsa65 {
            return Err(Error::UnsupportedAlg(part.alg.as_str().into()));
        }
        let mut matched = false;
        for (i, pk) in pks.iter().enumerate() {
            if used[i] {
                continue;
            }
            if verify_part(part.alg, pk, msg, &part.bytes).is_ok() {
                used[i] = true;
                matched = true;
                break;
            }
        }
        if !matched {
            return Err(Error::BadSignature);
        }
    }
    Ok(())
}

fn verify_part(alg: SigAlg, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    match alg {
        SigAlg::Ed25519 => {
            let pk32: [u8; 32] = pk
                .try_into()
                .map_err(|_| Error::Key("ed25519 public key must be 32 bytes".into()))?;
            let s64: [u8; 64] = sig.try_into().map_err(|_| Error::BadSignature)?;
            crate::crypto::ed25519_verify(&pk32, msg, &s64)
        }
        SigAlg::MlDsa65 => verify_mldsa(pk, msg, sig),
    }
}

#[cfg(feature = "pq")]
fn verify_mldsa(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    crate::crypto::mldsa_verify(pk, msg, sig)
}

#[cfg(not(feature = "pq"))]
fn verify_mldsa(_pk: &[u8], _msg: &[u8], _sig: &[u8]) -> Result<()> {
    Err(Error::UnsupportedAlg("ml-dsa-65".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alg_roundtrip() {
        for a in [SigAlg::Ed25519, SigAlg::MlDsa65] {
            assert_eq!(SigAlg::from_u8(a.as_u8()).unwrap(), a);
        }
        assert!(SigAlg::from_u8(9).is_err());
    }

    #[test]
    fn signature_wire_roundtrip() {
        let s = Signature::new(SigAlg::Ed25519, [1u8; 64]);
        let wire = s.to_bytes();
        // [count=1][alg=1][len_lo=64][len_hi=0][64 bytes...]
        assert_eq!(wire[0], 1);
        assert_eq!(wire[1], 1);
        assert_eq!(u16::from_le_bytes([wire[2], wire[3]]), 64);
        let back = Signature::from_bytes(&wire).unwrap();
        assert_eq!(back, s);
        assert!(Signature::from_bytes(&[]).is_err());
    }

    #[test]
    fn two_part_wire_roundtrip() {
        let s = Signature::from_parts(vec![
            SigPart {
                alg: SigAlg::Ed25519,
                bytes: vec![1u8; 64],
            },
            SigPart {
                alg: SigAlg::Ed25519,
                bytes: vec![2u8; 64],
            },
        ]);
        let wire = s.to_bytes();
        assert_eq!(wire[0], 2);
        let back = Signature::from_bytes(&wire).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn ed25519_sign_verify() {
        let a = crate::authority::Authority::generate("T");
        let pk = a.public_key();
        let sig = a.sign(b"msg");
        assert_eq!(sig.parts.len(), 1);
        assert_eq!(sig.parts[0].alg, SigAlg::Ed25519);
        assert!(verify(&[&pk], b"msg", &sig).is_ok());
        assert!(verify(&[&pk], b"tampered", &sig).is_err());
    }

    #[test]
    fn two_person_control_requires_two_keys() {
        let a = crate::authority::Authority::generate("A");
        let b = crate::authority::Authority::generate("B");
        let pk_a = a.public_key();
        let pk_b = b.public_key();
        let sig = Signature::join(vec![a.sign(b"msg"), b.sign(b"msg")]);
        // Both keys present: verifies.
        assert!(verify(&[&pk_a, &pk_b], b"msg", &sig).is_ok());
        // One key only: a single key cannot cover two parts.
        assert!(verify(&[&pk_a], b"msg", &sig).is_err());
        // Same key twice in the set: still only one distinct key.
        assert!(verify(&[&pk_a, &pk_a], b"msg", &sig).is_err());
    }

    #[cfg(not(feature = "pq"))]
    #[test]
    fn ml_dsa_unsupported_is_clear() {
        let sig = Signature::new(SigAlg::MlDsa65, vec![0u8; 3300]);
        let err = verify(&[&[0u8; 32]], b"msg", &sig).unwrap_err();
        assert!(matches!(err, Error::UnsupportedAlg(_)));
    }

    #[cfg(feature = "pq")]
    #[test]
    fn ml_dsa_signs_and_verifies() {
        let signer = MlDsaSigner::generate();
        let pk = signer.public_key_bytes();
        let sig = signer.sign(b"msg");
        assert_eq!(sig.parts[0].alg, SigAlg::MlDsa65);
        let r = verify(&[&pk], b"msg", &sig);
        assert!(r.is_ok());
        assert!(verify(&[&pk], b"tampered", &sig).is_err());
    }
}
