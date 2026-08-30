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

/// Algorithm-tagged signature. Wire format: `[alg_byte][raw_sig_bytes...]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub alg: SigAlg,
    pub bytes: Vec<u8>,
}

impl Signature {
    pub fn new(alg: SigAlg, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            alg,
            bytes: bytes.into(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.bytes.len());
        out.push(self.alg.as_u8());
        out.extend_from_slice(&self.bytes);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.is_empty() {
            return Err(Error::Parse("empty signature".into()));
        }
        let alg = SigAlg::from_u8(b[0])?;
        Ok(Self {
            alg,
            bytes: b[1..].to_vec(),
        })
    }
}

/// Produces signatures under a single declared algorithm.
pub trait Signer {
    fn alg(&self) -> SigAlg;
    fn sign(&self, msg: &[u8]) -> Signature;
}

/// Verify a signature under the algorithm named in the blob. The caller is
/// responsible for confirming `sig.alg` matches the key's declared algorithm
/// (the ledger does this by binding alg to the authority in `key_rotated`).
pub fn verify(pk: &[u8], msg: &[u8], sig: &Signature) -> Result<()> {
    match sig.alg {
        SigAlg::Ed25519 => {
            let pk32: [u8; 32] = pk
                .try_into()
                .map_err(|_| Error::Key("ed25519 public key must be 32 bytes".into()))?;
            let s64: [u8; 64] = sig
                .bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::BadSignature)?;
            let vk = VerifyingKey::from_bytes(&pk32).map_err(|e| Error::Key(e.to_string()))?;
            let s = EdSig::from_bytes(&s64);
            vk.verify(msg, &s).map_err(|_| Error::BadSignature)
        }
        SigAlg::MlDsa65 => Err(Error::UnsupportedAlg(sig.alg.as_str().into())),
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
        assert_eq!(wire[0], 1);
        let back = Signature::from_bytes(&wire).unwrap();
        assert_eq!(back, s);
        assert!(Signature::from_bytes(&[]).is_err());
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
        assert_eq!(sig.alg, SigAlg::Ed25519);
        assert!(verify(&pk, b"msg", &sig).is_ok());
        assert!(verify(&pk, b"tampered", &sig).is_err());
    }

    #[test]
    fn ml_dsa_unsupported_is_clear() {
        let sig = Signature::new(SigAlg::MlDsa65, vec![0u8; 3300]);
        let err = verify(&[0u8; 32], b"msg", &sig).unwrap_err();
        assert!(matches!(err, Error::UnsupportedAlg(_)));
    }
}
