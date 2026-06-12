//! ed25519 signing over RFC-8785 canonical JSON. Proves a verdict is exactly
//! what this operator's key emitted (integrity + provenance) — not remote
//! attestation.

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier, VerifyingKey};

pub struct Signer {
    key: SigningKey,
}

impl Signer {
    pub fn generate() -> Self {
        use rand_core::OsRng;
        Self {
            key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }

    pub fn to_seed_hex(&self) -> String {
        hex::encode(self.key.to_bytes())
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }

    pub fn sign_hex(&self, message: &[u8]) -> String {
        hex::encode(self.key.sign(message).to_bytes())
    }
}

/// Verify a hex signature over `message` against a hex public key.
pub fn verify_hex(pubkey_hex: &str, message: &[u8], sig_hex: &str) -> Result<(), String> {
    let pk_bytes: [u8; 32] = hex::decode(pubkey_hex)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "bad pubkey length".to_string())?;
    let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|e| e.to_string())?;
    let sig_bytes: [u8; 64] = hex::decode(sig_hex)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "bad signature length".to_string())?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(message, &sig).map_err(|e| e.to_string())
}

/// Resolve the signing key: an explicit hex seed (e.g. from `--signing-key` file
/// contents or `run --signing-seed`) → the `PROCTOR_SIGNING_SEED` env → a fresh
/// key saved to `out_dir/signing-seed.hex`. A malformed explicit/env seed is an
/// error (fail loud) rather than a silent fresh key.
pub fn resolve_signer(
    explicit_seed_hex: Option<&str>,
    out_dir: &std::path::Path,
) -> Result<Signer, String> {
    fn from_hex(h: &str) -> Result<Signer, String> {
        let seed: [u8; 32] = hex::decode(h.trim())
            .map_err(|e| format!("signing seed not hex: {e}"))?
            .try_into()
            .map_err(|_| "signing seed must be 32 bytes".to_string())?;
        Ok(Signer::from_bytes(&seed))
    }
    if let Some(h) = explicit_seed_hex {
        return from_hex(h);
    }
    if let Ok(h) = std::env::var("PROCTOR_SIGNING_SEED") {
        return from_hex(&h);
    }
    let s = Signer::generate();
    std::fs::write(out_dir.join("signing-seed.hex"), s.to_seed_hex())
        .map_err(|e| format!("write signing-seed.hex: {e}"))?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_seed_is_used_and_stable() {
        let dir = tempfile::tempdir().unwrap();
        let seed = Signer::generate().to_seed_hex();
        let a = resolve_signer(Some(&seed), dir.path()).unwrap();
        let b = resolve_signer(Some(&seed), dir.path()).unwrap();
        assert_eq!(a.public_key_hex(), b.public_key_hex());
    }

    #[test]
    fn fresh_when_unset_and_seed_is_saved() {
        let dir = tempfile::tempdir().unwrap();
        std::env::remove_var("PROCTOR_SIGNING_SEED");
        let s = resolve_signer(None, dir.path()).unwrap();
        let saved = std::fs::read_to_string(dir.path().join("signing-seed.hex")).unwrap();
        assert_eq!(saved.trim(), s.to_seed_hex());
    }

    #[test]
    fn malformed_seed_errors() {
        let dir = tempfile::tempdir().unwrap();
        assert!(resolve_signer(Some("nothex"), dir.path()).is_err());
    }
}
