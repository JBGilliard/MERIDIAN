use crate::crypto;
use crate::error::{Error, Result};
use crate::sig::{SigAlg, Signature, Signer};
use crate::vrf::{self, VrfOutput, VrfProof, VrfSigner};
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

pub struct Authority {
    pub id: String,
    seed: [u8; 32],
}

impl Authority {
    pub fn generate(id: impl Into<String>) -> Self {
        let mut seed = [0u8; 32];
        crypto::fill_random(&mut seed);
        Self {
            id: id.into(),
            seed,
        }
    }

    pub fn from_seed(id: impl Into<String>, seed: [u8; 32]) -> Self {
        Self {
            id: id.into(),
            seed,
        }
    }

    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }

    pub fn public_key(&self) -> [u8; 32] {
        crypto::ed25519_public_key(&self.seed)
    }

    pub fn vrf_prove(&self, alpha: &[u8]) -> Result<(VrfProof, VrfOutput)> {
        VrfSigner::prove(self, alpha)
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        fs::create_dir_all(dir)?;
        let mut seed = self.seed();
        fs::write(dir.join(format!("{}.sk", self.id)), hex::encode(seed))?;
        seed.zeroize();
        fs::write(
            dir.join(format!("{}.pk", self.id)),
            hex::encode(self.public_key()),
        )?;
        Ok(())
    }

    pub fn load(dir: &Path, id: &str) -> Result<Self> {
        let path = dir.join(format!("{id}.sk"));
        if !path.exists() {
            return Err(Error::MissingKey {
                agency: id.to_string(),
            });
        }
        let hex_seed = fs::read_to_string(path)?;
        let raw =
            hex::decode(hex_seed.trim()).map_err(|e| Error::Key(format!("decode seed: {e}")))?;
        let seed: [u8; 32] = raw
            .try_into()
            .map_err(|_| Error::Key("seed must be 32 bytes".into()))?;
        Ok(Self::from_seed(id, seed))
    }
}

impl Drop for Authority {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl Signer for Authority {
    fn alg(&self) -> SigAlg {
        SigAlg::Ed25519
    }

    fn sign(&self, msg: &[u8]) -> Signature {
        Signature::new(SigAlg::Ed25519, crypto::ed25519_sign(&self.seed, msg))
    }
}

impl VrfSigner for Authority {
    fn public_key(&self) -> [u8; 32] {
        vrf::public_key(&self.seed)
    }

    fn prove(&self, alpha: &[u8]) -> Result<(VrfProof, VrfOutput)> {
        vrf::prove(&self.seed, alpha)
    }
}

pub fn verify_signature(pk: &[u8], msg: &[u8], sig: &Signature) -> Result<()> {
    crate::sig::verify(&[pk], msg, sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_roundtrip() {
        let a = Authority::from_seed("DIA", [7u8; 32]);
        let sig = a.sign(b"hello");
        assert_eq!(sig.parts.len(), 1);
        assert_eq!(sig.parts[0].alg, SigAlg::Ed25519);
        verify_signature(a.public_key().as_slice(), b"hello", &sig).unwrap();
        assert!(verify_signature(a.public_key().as_slice(), b"nope", &sig).is_err());
    }

    #[test]
    fn load_missing_names_agency() {
        let err = match Authority::load(std::path::Path::new("/no/such/keys"), "CIA") {
            Err(e) => e,
            Ok(_) => panic!("expected missing key"),
        };
        assert!(matches!(err, Error::MissingKey { ref agency } if agency == "CIA"));
    }

    #[test]
    fn vrf_signer_matches_free_prove() {
        let a = Authority::from_seed("DIA", [7u8; 32]);
        let alpha = b"alpha";
        let (pi, beta) = VrfSigner::prove(&a, alpha).unwrap();
        let (pi2, beta2) = vrf::prove(&a.seed(), alpha).unwrap();
        assert_eq!(pi, pi2);
        assert_eq!(beta, beta2);
        assert_eq!(VrfSigner::public_key(&a), vrf::public_key(&a.seed()));
        assert_eq!(VrfSigner::public_key(&a), a.public_key());
    }
}
