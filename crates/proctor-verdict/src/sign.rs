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
