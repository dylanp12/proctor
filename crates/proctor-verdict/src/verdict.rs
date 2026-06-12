//! The signed verdict: the trustworthy result of a Proctor run.

use crate::sign::{verify_hex, Signer};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// the agent attempted no in-sandbox cheat
    Clean,
    /// at least one attempted violation was logged
    Compromised,
}

/// The signed portion (everything except the signature itself).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerdictBody {
    pub task_id: String,
    pub pass: bool,
    pub status: Status,
    pub violations_head: String,
    pub violations_count: u64,
    pub env_digest: String,
    /// digest binding the run's artifact (agent log) hashes into the signature
    pub artifacts_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reward: Option<f64>,
    pub proctor_version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    #[serde(flatten)]
    pub body: VerdictBody,
    pub public_key: String,
    pub signature: String,
}

pub struct VerdictBuilder {
    pub task_id: String,
    pub pass: bool,
    pub status: Status,
    pub violations_head: String,
    pub violations_count: u64,
    pub env_digest: String,
    pub artifacts_digest: String,
    pub reward: Option<f64>,
}

impl VerdictBuilder {
    pub fn sign(self, signer: &Signer) -> Verdict {
        let body = VerdictBody {
            task_id: self.task_id,
            pass: self.pass,
            status: self.status,
            violations_head: self.violations_head,
            violations_count: self.violations_count,
            env_digest: self.env_digest,
            artifacts_digest: self.artifacts_digest,
            reward: self.reward,
            proctor_version: env!("CARGO_PKG_VERSION").to_string(),
        };
        let msg = canonical(&body);
        let signature = signer.sign_hex(msg.as_bytes());
        Verdict {
            public_key: signer.public_key_hex(),
            signature,
            body,
        }
    }
}

impl Verdict {
    pub fn verify(&self, expected_pubkey_hex: &str) -> Result<(), String> {
        if self.public_key != expected_pubkey_hex {
            return Err("verdict public key does not match expected".into());
        }
        let msg = canonical(&self.body);
        verify_hex(&self.public_key, msg.as_bytes(), &self.signature)
    }

    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        std::fs::write(path, serde_json::to_vec_pretty(self)?)
    }
}

/// RFC-8785 canonical JSON of the signed body.
fn canonical(body: &VerdictBody) -> String {
    let val = serde_json::to_value(body).expect("body serializes");
    serde_json_canonicalizer::to_string(&val).expect("canonicalize")
}
