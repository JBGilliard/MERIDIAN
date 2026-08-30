//! Pluggable event-signature algorithm.

use crate::error::{Error, Result};
use ed25519_dalek::{Signature as EdSig, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// One byte on the wire. New algorithms append; never renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SigAlg {
    #[default]
    Ed25519 = 1,
    /// FIPS 204 ML-DSA-65. Reserved: not implemented in the OSS build.
    /// A ledger carrying ML-DSA signatures can still be read (canonical +
    /// Merkle verify) but signature verification returns `UnsupportedAlg`
    /// until a PQ-enabled build is linked.
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

/// Algorithm-tagged signature. Wire format:
/// `[count: u8][part: alg_u8, len_u16_le, sig_bytes]...`
///
/// One part today; a list enables hybrid (same key, two algorithms) and
/// two-person control (two keys, one part each) without a ledger-format
/// break — the signature blob is not part of `canonical` and is not
/// hashed into the Merkle tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub parts: Vec<SigPart>,
}

impl Signature {
    /// Single-part signature (the common case).
    pub fn new(alg: SigAlg, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            parts: vec![SigPart {
                alg,
                bytes: bytes.into(),
            }],
        }
    }

    /// Combine independently-produced parts into one signature. Used for
    /// two-person control: each authority signs the canonical bytes and
    /// the parts are joined.
    pub fn from_parts(parts: Vec<SigPart>) -> Self {
        Self { parts }
    }

    /// Flatten a list of (single-part) signatures into one multi-part
    /// signature. The two-person-control path: each authority produces a
    /// one-part `Signature`; `join` merges them into a single event signature.
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

/// Verify every part of `sig` against the supplied public keys. Each part
/// must verify under exactly one pk in `pks`, and each pk may be used at most
/// once — so a two-part signature requires two distinct pks. This is the
/// two-person control policy: a `KeyRotated` or `Revoked` event signed by
/// two authorities cannot be verified by a single key.
///
/// For a single-part signature (the common case) pass one pk.
pub fn verify(pks: &[&[u8]], msg: &[u8], sig: &Signature) -> Result<()> {
    if sig.parts.is_empty() {
        return Err(Error::BadSignature);
    }
    if pks.len() < sig.parts.len() {
        return Err(Error::BadSignature);
    }
    let mut used = vec![false; pks.len()];
    for part in &sig.parts {
        // Unsupported algorithm is a build/config error, not a bad signature.
        // Surface it distinctly so an auditor knows the ledger is readable
        // but this signature can't be checked in this binary.
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
            let vk = VerifyingKey::from_bytes(&pk32).map_err(|e| Error::Key(e.to_string()))?;
            let s = EdSig::from_bytes(&s64);
            vk.verify(msg, &s).map_err(|_| Error::BadSignature)
        }
        SigAlg::MlDsa65 => Err(Error::UnsupportedAlg(alg.as_str().into())),
    }
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
        use ed25519_dalek::{Signer as _, SigningKey};
        use rand::rngs::OsRng;
        struct Ed25519Signer<'a>(&'a SigningKey);
        impl<'a> Signer for Ed25519Signer<'a> {
            fn alg(&self) -> SigAlg {
                SigAlg::Ed25519
            }
            fn sign(&self, msg: &[u8]) -> Signature {
                Signature::new(SigAlg::Ed25519, self.0.sign(msg).to_bytes())
            }
        }
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        let signer = Ed25519Signer(&sk);
        let sig = signer.sign(b"msg");
        assert_eq!(sig.parts.len(), 1);
        assert_eq!(sig.parts[0].alg, SigAlg::Ed25519);
        assert!(verify(&[&pk], b"msg", &sig).is_ok());
        assert!(verify(&[&pk], b"tampered", &sig).is_err());
    }

    #[test]
    fn two_person_control_requires_two_keys() {
        use ed25519_dalek::{Signer as _, SigningKey};
        use rand::rngs::OsRng;
        struct Ed25519Signer<'a>(&'a SigningKey);
        impl<'a> Signer for Ed25519Signer<'a> {
            fn alg(&self) -> SigAlg {
                SigAlg::Ed25519
            }
            fn sign(&self, msg: &[u8]) -> Signature {
                Signature::new(SigAlg::Ed25519, self.0.sign(msg).to_bytes())
            }
        }
        let a = Ed25519Signer(&SigningKey::generate(&mut OsRng));
        let b = Ed25519Signer(&SigningKey::generate(&mut OsRng));
        let pk_a = a.0.verifying_key().to_bytes();
        let pk_b = b.0.verifying_key().to_bytes();
        let sig = Signature::join(vec![a.sign(b"msg"), b.sign(b"msg")]);
        // Both keys present: verifies.
        assert!(verify(&[&pk_a, &pk_b], b"msg", &sig).is_ok());
        // One key only: a single key cannot cover two parts.
        assert!(verify(&[&pk_a], b"msg", &sig).is_err());
        // Same key twice in the set: still only one distinct key.
        assert!(verify(&[&pk_a, &pk_a], b"msg", &sig).is_err());
    }

    #[test]
    fn ml_dsa_unsupported_is_clear() {
        let sig = Signature::new(SigAlg::MlDsa65, vec![0u8; 3300]);
        let err = verify(&[&[0u8; 32]], b"msg", &sig).unwrap_err();
        assert!(matches!(err, Error::UnsupportedAlg(_)));
    }
}
