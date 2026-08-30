use crate::error::{Error, Result};
use serde::Serialize;
#[cfg(feature = "fips")]
use std::sync::OnceLock;

pub trait CryptoProvider {
    fn sha256(parts: &[&[u8]]) -> [u8; 32];
    fn ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64];
    fn ed25519_verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<()>;
    fn ed25519_public_key(seed: &[u8; 32]) -> [u8; 32];

    #[cfg(feature = "pq")]
    fn mldsa_sign(seed: &[u8; 32], msg: &[u8]) -> Result<Vec<u8>>;
    #[cfg(feature = "pq")]
    fn mldsa_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<()>;
    #[cfg(feature = "pq")]
    fn mldsa_public_key(seed: &[u8; 32]) -> Vec<u8>;
}

#[cfg(not(feature = "fips"))]
pub struct RustCrypto;

#[cfg(feature = "fips")]
pub struct AwsLc;

#[cfg(not(feature = "fips"))]
pub type Active = RustCrypto;
#[cfg(feature = "fips")]
pub type Active = AwsLc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CryptoBoundary {
    pub profile: &'static str,
    pub module: &'static str,
    pub sha256: &'static str,
    pub ed25519: &'static str,
    pub mldsa: &'static str,
    pub vrf: &'static str,
    pub approved: bool,
}

pub const VRF_SUITE_STATUS: &str = "ecvrf-ed25519-tai/sc-13(2)";

pub fn boundary() -> CryptoBoundary {
    #[cfg(feature = "fips")]
    {
        CryptoBoundary {
            profile: "ic",
            module: "aws-lc-fips-140-3",
            sha256: "aws-lc",
            ed25519: "aws-lc",
            mldsa: if cfg!(feature = "pq") {
                "aws-lc"
            } else {
                "off"
            },
            vrf: VRF_SUITE_STATUS,
            approved: true,
        }
    }
    #[cfg(not(feature = "fips"))]
    {
        CryptoBoundary {
            profile: "oss",
            module: "rustcrypto",
            sha256: "sha2",
            ed25519: "ed25519-dalek",
            mldsa: if cfg!(feature = "pq") {
                "ml-dsa"
            } else {
                "off"
            },
            vrf: VRF_SUITE_STATUS,
            approved: false,
        }
    }
}

/// Greppable AO line. `ledger verify` prints this verbatim.
pub fn status_line() -> String {
    let b = boundary();
    format!(
        "STATUS crypto-boundary={} sha256={} ed25519={} mldsa={} vrf={} approved={}",
        b.module, b.sha256, b.ed25519, b.mldsa, b.vrf, b.approved
    )
}

/// FIPS builds: FIPS_mode + SHA-256/Ed25519 KATs. OSS: no-op.
pub fn init() -> Result<()> {
    #[cfg(not(feature = "fips"))]
    {
        Ok(())
    }

    #[cfg(feature = "fips")]
    {
        static INIT: OnceLock<std::result::Result<(), String>> = OnceLock::new();
        match INIT.get_or_init(fips_boot) {
            Ok(()) => Ok(()),
            Err(e) => Err(Error::CryptoBoundary(e.clone())),
        }
    }
}

/// `--approved-mode`: refuse unless this binary is the FIPS profile and init passed.
pub fn require_approved() -> Result<()> {
    #[cfg(not(feature = "fips"))]
    {
        Err(Error::CryptoBoundary(
            "--approved-mode requires a binary built with --features fips".into(),
        ))
    }
    #[cfg(feature = "fips")]
    init()
}

fn ready() {
    init().unwrap_or_else(|e| panic!("{e}"));
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    ready();
    Active::sha256(parts)
}

pub fn ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    ready();
    Active::ed25519_sign(seed, msg)
}

pub fn ed25519_verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<()> {
    ready();
    Active::ed25519_verify(pk, msg, sig)
}

pub fn ed25519_public_key(seed: &[u8; 32]) -> [u8; 32] {
    ready();
    Active::ed25519_public_key(seed)
}

#[cfg(feature = "pq")]
pub fn mldsa_sign(seed: &[u8; 32], msg: &[u8]) -> Result<Vec<u8>> {
    ready();
    Active::mldsa_sign(seed, msg)
}

#[cfg(feature = "pq")]
pub fn mldsa_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    ready();
    Active::mldsa_verify(pk, msg, sig)
}

#[cfg(feature = "pq")]
pub fn mldsa_public_key(seed: &[u8; 32]) -> Vec<u8> {
    ready();
    Active::mldsa_public_key(seed)
}

pub fn fill_random(buf: &mut [u8]) {
    #[cfg(feature = "fips")]
    {
        aws_lc_rs::rand::fill(buf).expect("FIPS RNG");
    }
    #[cfg(not(feature = "fips"))]
    {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(buf);
    }
}

#[cfg(feature = "fips")]
fn fips_boot() -> std::result::Result<(), String> {
    aws_lc_rs::try_fips_mode().map_err(|e| format!("FIPS_mode not active: {e}"))?;
    known_answer().map_err(|e| match e {
        Error::CryptoBoundary(s) => s,
        other => other.to_string(),
    })
}

#[cfg(any(test, feature = "fips"))]
fn known_answer() -> Result<()> {
    kat_sha256()?;
    kat_ed25519()?;
    Ok(())
}

#[cfg(any(test, feature = "fips"))]
fn kat_sha256() -> Result<()> {
    // FIPS 180-4 / CAVP empty and "abc".
    let empty = Active::sha256(&[]);
    let abc = Active::sha256(&[b"abc"]);
    let want_empty =
        hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
    let want_abc =
        hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").unwrap();
    if empty.as_slice() != want_empty {
        return Err(Error::CryptoBoundary("SHA-256 KAT (empty) failed".into()));
    }
    if abc.as_slice() != want_abc {
        return Err(Error::CryptoBoundary("SHA-256 KAT (abc) failed".into()));
    }
    Ok(())
}

#[cfg(any(test, feature = "fips"))]
fn kat_ed25519() -> Result<()> {
    // RFC 8032 test vector 1 (empty message). Public key is bit-exact on
    // both providers. Signature bytes match only under AWS-LC — dalek
    // inherits curve25519-dalek `legacy_compatibility` (ECVRF needs it)
    // which changes scalar reduction.
    let sk = hex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let pk = hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    if Active::ed25519_public_key(&sk) != pk {
        return Err(Error::CryptoBoundary(
            "Ed25519 KAT (public key) failed".into(),
        ));
    }
    let sig = Active::ed25519_sign(&sk, b"");
    Active::ed25519_verify(&pk, b"", &sig)
        .map_err(|_| Error::CryptoBoundary("Ed25519 KAT (verify) failed".into()))?;
    if Active::ed25519_verify(&pk, b"x", &sig).is_ok() {
        return Err(Error::CryptoBoundary(
            "Ed25519 KAT (verify must reject) failed".into(),
        ));
    }
    #[cfg(feature = "fips")]
    {
        let want = hex::decode(
            "e5564300c360ac729086e2cc806eaeae9b80759aa382e05591b584eeeba2f5ca\
             989519ce437d080c7b0bd10345e28549aae7291727005cf122861e01341c080b",
        )
        .unwrap();
        if sig.as_slice() != want {
            return Err(Error::CryptoBoundary("Ed25519 KAT (sign) failed".into()));
        }
    }
    Ok(())
}

#[cfg(any(test, feature = "fips"))]
fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

#[cfg(not(feature = "fips"))]
impl CryptoProvider for RustCrypto {
    fn sha256(parts: &[&[u8]]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        for p in parts {
            h.update(p);
        }
        h.finalize().into()
    }

    fn ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
        use ed25519_dalek::{Signer as _, SigningKey};
        SigningKey::from_bytes(seed).sign(msg).to_bytes()
    }

    fn ed25519_verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<()> {
        use ed25519_dalek::{Signature as EdSig, Verifier, VerifyingKey};
        let vk = VerifyingKey::from_bytes(pk).map_err(|e| Error::Key(e.to_string()))?;
        vk.verify(msg, &EdSig::from_bytes(sig))
            .map_err(|_| Error::BadSignature)
    }

    fn ed25519_public_key(seed: &[u8; 32]) -> [u8; 32] {
        use ed25519_dalek::SigningKey;
        SigningKey::from_bytes(seed).verifying_key().to_bytes()
    }

    #[cfg(feature = "pq")]
    fn mldsa_sign(seed: &[u8; 32], msg: &[u8]) -> Result<Vec<u8>> {
        use ml_dsa::{MlDsa65, SignatureEncoding, Signer as _, SigningKey};
        let sk = SigningKey::<MlDsa65>::from_seed(&(*seed).into());
        Ok(sk.sign(msg).to_bytes().to_vec())
    }

    #[cfg(feature = "pq")]
    fn mldsa_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
        use ml_dsa::{MlDsa65, Verifier};
        const PK_LEN: usize = 1952;
        const SIG_LEN: usize = 3309;
        let pk_arr: [u8; PK_LEN] = pk
            .try_into()
            .map_err(|_| Error::Key(format!("ml-dsa-65 pk must be {PK_LEN} bytes")))?;
        let enc_pk: ml_dsa::EncodedVerifyingKey<MlDsa65> = pk_arr.into();
        let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&enc_pk);
        let sig_arr: [u8; SIG_LEN] = sig.try_into().map_err(|_| Error::BadSignature)?;
        let enc_sig: ml_dsa::EncodedSignature<MlDsa65> = sig_arr.into();
        let s = ml_dsa::Signature::<MlDsa65>::decode(&enc_sig).ok_or(Error::BadSignature)?;
        vk.verify(msg, &s).map_err(|_| Error::BadSignature)
    }

    #[cfg(feature = "pq")]
    fn mldsa_public_key(seed: &[u8; 32]) -> Vec<u8> {
        use ml_dsa::{KeyExport, Keypair, MlDsa65, SigningKey};
        SigningKey::<MlDsa65>::from_seed(&(*seed).into())
            .verifying_key()
            .to_bytes()
            .to_vec()
    }
}

#[cfg(feature = "fips")]
impl CryptoProvider for AwsLc {
    fn sha256(parts: &[&[u8]]) -> [u8; 32] {
        let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
        for p in parts {
            ctx.update(p);
        }
        ctx.finish().as_ref().try_into().expect("sha256 is 32")
    }

    fn ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
        use aws_lc_rs::signature::Ed25519KeyPair;
        let kp = Ed25519KeyPair::from_seed_unchecked(seed).expect("ed25519 seed");
        kp.sign(msg).as_ref().try_into().expect("ed25519 sig is 64")
    }

    fn ed25519_verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<()> {
        use aws_lc_rs::signature::{UnparsedPublicKey, ED25519};
        UnparsedPublicKey::new(&ED25519, pk.as_slice())
            .verify(msg, sig)
            .map_err(|_| Error::BadSignature)
    }

    fn ed25519_public_key(seed: &[u8; 32]) -> [u8; 32] {
        use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
        let kp = Ed25519KeyPair::from_seed_unchecked(seed).expect("ed25519 seed");
        kp.public_key()
            .as_ref()
            .try_into()
            .expect("ed25519 pk is 32")
    }

    #[cfg(feature = "pq")]
    fn mldsa_sign(seed: &[u8; 32], msg: &[u8]) -> Result<Vec<u8>> {
        use aws_lc_rs::signature::{PqdsaKeyPair, ML_DSA_65_SIGNING};
        let kp = PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, seed)
            .map_err(|e| Error::Key(format!("ml-dsa-65 seed: {e}")))?;
        let mut sig = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
        let n = kp
            .sign(msg, &mut sig)
            .map_err(|_| Error::Key("ml-dsa-65 sign failed".into()))?;
        sig.truncate(n);
        Ok(sig)
    }

    #[cfg(feature = "pq")]
    fn mldsa_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
        use aws_lc_rs::signature::{UnparsedPublicKey, ML_DSA_65};
        UnparsedPublicKey::new(&ML_DSA_65, pk)
            .verify(msg, sig)
            .map_err(|_| Error::BadSignature)
    }

    #[cfg(feature = "pq")]
    fn mldsa_public_key(seed: &[u8; 32]) -> Vec<u8> {
        use aws_lc_rs::signature::{KeyPair, PqdsaKeyPair, ML_DSA_65_SIGNING};
        let kp = PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, seed).expect("ml-dsa-65 seed");
        kp.public_key().as_ref().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answers() {
        known_answer().unwrap();
    }

    #[test]
    fn status_line_is_machine_parseable() {
        let line = status_line();
        assert!(line.starts_with("STATUS "));
        assert!(line.contains("crypto-boundary="));
        assert!(line.contains("vrf=ecvrf-ed25519-tai/sc-13(2)"));
        assert!(line.contains("approved="));
    }

    #[test]
    fn boundary_matches_feature() {
        let b = boundary();
        assert_eq!(b.vrf, VRF_SUITE_STATUS);
        #[cfg(feature = "fips")]
        {
            assert_eq!(b.module, "aws-lc-fips-140-3");
            assert!(b.approved);
        }
        #[cfg(not(feature = "fips"))]
        {
            assert_eq!(b.module, "rustcrypto");
            assert!(!b.approved);
        }
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn approved_mode_refuses_oss() {
        let err = require_approved().unwrap_err();
        assert!(matches!(err, Error::CryptoBoundary(_)));
        assert!(err.to_string().contains("--features fips"));
    }

    #[cfg(feature = "fips")]
    #[test]
    fn fips_init_and_approved() {
        init().unwrap();
        require_approved().unwrap();
    }
}
