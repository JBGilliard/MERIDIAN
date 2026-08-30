//! ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381 §5.5, suite 0x03).
//!
//! TAI encode-to-curve timing depends on `alpha`. Our alpha is
//! (authority, type, pool, seq, nonce) — not a secret identity.

use crate::error::{Error, Result};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use sha2::{Digest, Sha512};

pub const SUITE_STRING: u8 = 0x03;
pub const PROOF_LEN: usize = 80; // ptLen(32) + cLen(16) + qLen(32)
pub const C_LEN: usize = 16;
pub const PT_LEN: usize = 32;
pub const Q_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfProof(pub [u8; PROOF_LEN]);

impl VrfProof {
    pub fn as_bytes(&self) -> &[u8; PROOF_LEN] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; PROOF_LEN] = bytes.try_into().map_err(|_| Error::VrfInvalid)?;
        Ok(Self(arr))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfOutput(pub [u8; 64]);

impl VrfOutput {
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

struct SecretScalar {
    x: Scalar,
    prefix: [u8; 32],
    pk: [u8; 32],
}

fn expand_sk(sk: &[u8; 32]) -> SecretScalar {
    let hash = Sha512::digest(sk);
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash[..32]);
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 63;
    scalar_bytes[31] |= 64;
    let x = Scalar::from_bytes_mod_order(scalar_bytes);
    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&hash[32..]);
    let y = EdwardsPoint::mul_base(&x);
    SecretScalar {
        x,
        prefix,
        pk: y.compress().to_bytes(),
    }
}

pub fn public_key(sk: &[u8; 32]) -> [u8; 32] {
    expand_sk(sk).pk
}

fn point_to_string(p: &EdwardsPoint) -> [u8; 32] {
    p.compress().to_bytes()
}

fn string_to_point(bytes: &[u8]) -> Result<EdwardsPoint> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::VrfInvalid)?;
    CompressedEdwardsY(arr)
        .decompress()
        .ok_or(Error::VrfInvalid)
}

fn encode_to_curve(salt: &[u8], alpha: &[u8]) -> Result<EdwardsPoint> {
    for ctr in 0u8..=255 {
        let mut h = Sha512::new();
        h.update([SUITE_STRING, 0x01]);
        h.update(salt);
        h.update(alpha);
        h.update([ctr, 0x00]);
        let hash = h.finalize();
        if let Ok(p) = string_to_point(&hash[..32]) {
            let h_point = p.mul_by_cofactor();
            if h_point != EdwardsPoint::identity() {
                return Ok(h_point);
            }
        }
    }
    Err(Error::VrfEncodeToCurve)
}

fn nonce_generation(prefix: &[u8; 32], h_string: &[u8; 32]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(prefix);
    hasher.update(h_string);
    let k_string: [u8; 64] = hasher.finalize().into();
    Scalar::from_bytes_mod_order_wide(&k_string)
}

fn challenge(points: [&EdwardsPoint; 5]) -> ([u8; C_LEN], Scalar) {
    let mut hasher = Sha512::new();
    hasher.update([SUITE_STRING, 0x02]);
    for p in points {
        hasher.update(point_to_string(p));
    }
    hasher.update([0x00]);
    let c_hash = hasher.finalize();
    let mut c_bytes = [0u8; C_LEN];
    c_bytes.copy_from_slice(&c_hash[..C_LEN]);
    let mut wide = [0u8; 32];
    wide[..C_LEN].copy_from_slice(&c_bytes);
    (c_bytes, Scalar::from_bytes_mod_order(wide))
}

fn decode_proof(pi: &[u8; PROOF_LEN]) -> Result<(EdwardsPoint, [u8; C_LEN], Scalar)> {
    let gamma = string_to_point(&pi[..PT_LEN])?;
    let mut c_bytes = [0u8; C_LEN];
    c_bytes.copy_from_slice(&pi[PT_LEN..PT_LEN + C_LEN]);
    let s_bytes: [u8; 32] = pi[PT_LEN + C_LEN..].try_into().unwrap();
    let s =
        Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)).ok_or(Error::VrfInvalid)?;
    Ok((gamma, c_bytes, s))
}

fn proof_to_hash(gamma: &EdwardsPoint) -> VrfOutput {
    let eight_gamma = gamma.mul_by_cofactor();
    let mut hasher = Sha512::new();
    hasher.update([SUITE_STRING, 0x03]);
    hasher.update(point_to_string(&eight_gamma));
    hasher.update([0x00]);
    VrfOutput(hasher.finalize().into())
}

fn validate_key(y: &EdwardsPoint) -> Result<()> {
    if y.mul_by_cofactor() == EdwardsPoint::identity() {
        return Err(Error::VrfInvalid);
    }
    Ok(())
}

/// Prove. `sk` is the 32-byte RFC 8032 seed. Salt is the public key.
pub fn prove(sk: &[u8; 32], alpha: &[u8]) -> Result<(VrfProof, VrfOutput)> {
    let sec = expand_sk(sk);
    let y = string_to_point(&sec.pk)?;
    let h = encode_to_curve(&sec.pk, alpha)?;
    let h_string = point_to_string(&h);
    let gamma = sec.x * h;
    let k = nonce_generation(&sec.prefix, &h_string);
    let u = EdwardsPoint::mul_base(&k);
    let v = k * h;
    let (c_bytes, c) = challenge([&y, &h, &gamma, &u, &v]);
    let s = k + c * sec.x;
    let mut pi = [0u8; PROOF_LEN];
    pi[..PT_LEN].copy_from_slice(&point_to_string(&gamma));
    pi[PT_LEN..PT_LEN + C_LEN].copy_from_slice(&c_bytes);
    pi[PT_LEN + C_LEN..].copy_from_slice(&s.to_bytes());
    Ok((VrfProof(pi), proof_to_hash(&gamma)))
}

pub fn verify(pk: &[u8; 32], alpha: &[u8], proof: &VrfProof) -> Result<VrfOutput> {
    let y = string_to_point(pk)?;
    validate_key(&y)?;
    let (gamma, c_bytes, s) = decode_proof(&proof.0)?;
    let mut c_wide = [0u8; 32];
    c_wide[..C_LEN].copy_from_slice(&c_bytes);
    let c = Scalar::from_bytes_mod_order(c_wide);
    let h = encode_to_curve(pk, alpha)?;
    let u = EdwardsPoint::mul_base(&s) - c * y;
    let v = s * h - c * gamma;
    let (c_prime, _) = challenge([&y, &h, &gamma, &u, &v]);
    if c_prime != c_bytes {
        return Err(Error::VrfInvalid);
    }
    Ok(proof_to_hash(&gamma))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn hex32(s: &str) -> [u8; 32] {
        let v = hex::decode(s).unwrap();
        v.try_into().unwrap()
    }

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s.replace([' ', '\n'], "")).unwrap()
    }

    // RFC 9381 Appendix B.3, Examples 16–18.
    struct VecB3 {
        sk: [u8; 32],
        pk: [u8; 32],
        alpha: Vec<u8>,
        pi: Vec<u8>,
        beta: Vec<u8>,
    }

    fn vectors() -> [VecB3; 3] {
        [
            VecB3 {
                sk: hex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
                pk: hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
                alpha: vec![],
                pi: unhex(
                    "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f\
                     26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1\
                     268a1b0db10836d9826a528ca76567805",
                ),
                beta: unhex(
                    "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff\
                     66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae",
                ),
            },
            VecB3 {
                sk: hex32("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
                pk: hex32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
                alpha: vec![0x72],
                pi: unhex(
                    "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed593\
                     3bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926\
                     da3ef39226bbc355bdc9850112c8f4b02",
                ),
                beta: unhex(
                    "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb\
                     5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031",
                ),
            },
            VecB3 {
                sk: hex32("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"),
                pk: hex32("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
                alpha: vec![0xaf, 0x82],
                pi: unhex(
                    "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf80\
                     96bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7\
                     a2d41b00b05081ed0f58ee5e31b3a970e",
                ),
                beta: unhex(
                    "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c45\
                     2118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f",
                ),
            },
        ]
    }

    #[test]
    fn rfc9381_b3_prove_and_verify() {
        for (i, v) in vectors().iter().enumerate() {
            assert_eq!(public_key(&v.sk), v.pk, "pk mismatch example {}", i + 16);
            let (pi, beta) = prove(&v.sk, &v.alpha).unwrap();
            assert_eq!(
                pi.as_bytes().as_slice(),
                v.pi.as_slice(),
                "pi mismatch example {}",
                i + 16
            );
            assert_eq!(
                beta.as_bytes().as_slice(),
                v.beta.as_slice(),
                "beta mismatch example {}",
                i + 16
            );
            let out = verify(&v.pk, &v.alpha, &pi).unwrap();
            assert_eq!(out.as_bytes().as_slice(), v.beta.as_slice());
        }
    }

    #[test]
    fn verify_rejects_tampered_proof() {
        let v = &vectors()[0];
        let (mut pi, _) = prove(&v.sk, &v.alpha).unwrap();
        pi.0[10] ^= 0x01;
        assert!(verify(&v.pk, &v.alpha, &pi).is_err());
    }

    #[test]
    fn verify_rejects_wrong_alpha() {
        let v = &vectors()[1];
        let (pi, _) = prove(&v.sk, &v.alpha).unwrap();
        assert!(verify(&v.pk, b"nope", &pi).is_err());
    }

    proptest! {
        #[test]
        fn random_alpha_roundtrip(
            seed in proptest::array::uniform32(0u8..=255),
            alpha in proptest::collection::vec(0u8..=255, 0..64),
        ) {
            let pk = public_key(&seed);
            let (pi, beta) = prove(&seed, &alpha).unwrap();
            let out = verify(&pk, &alpha, &pi).unwrap();
            prop_assert_eq!(out.as_bytes(), beta.as_bytes());
        }
    }
}
