//! A portable, self-contained, independently verifiable run bundle: the signed
//! verdict + the violation records + a manifest of agent-log hashes, all bound
//! under the verdict's single ed25519 signature.

use crate::digest::{artifacts_digest, chain_head, env_digest_of};
use crate::verdict::Verdict;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("verdict signature invalid: {0}")]
    Signature(String),
    #[error("verdict public key does not match expected")]
    PubkeyMismatch,
    #[error("violation chain head does not match the signed verdict")]
    Chain,
    #[error("violation count does not match the signed verdict")]
    Count,
    #[error("artifact hashes do not match the signed verdict")]
    Artifacts,
    #[error("recorded environment does not match the signed env_digest")]
    EnvMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub name: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub artifacts: Vec<Artifact>,
}

/// The recorded run environment (bundle v2+): cleartext, so a verifier can read
/// *what* ran and recompute `env_digest` over it (see `digest::env_digest_of`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Environment {
    pub agent_command: String,
    /// "host" | "image"
    pub rootfs_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_digest: Option<String>,
    pub proctor_version: String,
    pub proctor_commit: String,
    pub policy_sha256: String,
    pub spec_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    pub bundle_version: u32,
    pub verdict: Verdict,
    pub violations: Vec<serde_json::Value>,
    pub manifest: Manifest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<Environment>,
}

/// Hash a set of (name, host-path) artifacts; missing files are skipped.
pub fn hash_artifacts(items: &[(String, PathBuf)]) -> Result<Vec<Artifact>, BundleError> {
    let mut out = Vec::new();
    for (name, path) in items {
        if !path.exists() {
            continue;
        }
        let data = std::fs::read(path)?;
        let mut h = Sha256::new();
        h.update(&data);
        out.push(Artifact {
            name: name.clone(),
            sha256: hex::encode(h.finalize()),
            bytes: data.len() as u64,
        });
    }
    Ok(out)
}

/// Parse a hash-chained violations.jsonl into its records.
pub fn read_records(path: &Path) -> Result<Vec<serde_json::Value>, BundleError> {
    let mut out = Vec::new();
    if !path.exists() {
        return Ok(out);
    }
    for line in std::fs::read_to_string(path)?.lines() {
        if line.trim().is_empty() {
            continue;
        }
        out.push(serde_json::from_str(line)?);
    }
    Ok(out)
}

impl Bundle {
    pub fn build(
        verdict: Verdict,
        violations_path: &Path,
        artifacts: &[Artifact],
    ) -> Result<Bundle, BundleError> {
        Ok(Bundle {
            bundle_version: 1,
            verdict,
            violations: read_records(violations_path)?,
            manifest: Manifest {
                artifacts: artifacts.to_vec(),
            },
            environment: None,
        })
    }

    pub fn save(&self, path: &Path) -> Result<(), BundleError> {
        std::fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Bundle, BundleError> {
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    }

    /// Re-check everything a third party needs to trust this run.
    pub fn verify(&self, expected_pubkey: Option<&str>) -> Result<(), BundleError> {
        // 1. signature valid for the embedded public key
        self.verdict
            .verify(&self.verdict.public_key)
            .map_err(BundleError::Signature)?;
        if let Some(pk) = expected_pubkey {
            if self.verdict.public_key != pk {
                return Err(BundleError::PubkeyMismatch);
            }
        }
        // 2. the violation timeline is the one that was signed
        if chain_head(&self.violations) != self.verdict.body.violations_head {
            return Err(BundleError::Chain);
        }
        if self.violations.len() as u64 != self.verdict.body.violations_count {
            return Err(BundleError::Count);
        }
        // 3. the agent-log hashes are the ones that were signed
        if artifacts_digest(&self.manifest.artifacts) != self.verdict.body.artifacts_digest {
            return Err(BundleError::Artifacts);
        }
        // 4. (v2+) the recorded environment recomputes to the signed env_digest
        if let Some(env) = &self.environment {
            if env_digest_of(env) != self.verdict.body.env_digest {
                return Err(BundleError::EnvMismatch);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::Signer;
    use crate::verdict::{Status, VerdictBuilder};

    fn good_bundle(dir: &std::path::Path, signer: &Signer) -> Bundle {
        use proctor_monitor::chain::ChainWriter;
        use proctor_monitor::event::{Violation, ViolationKind};
        let vpath = dir.join("violations.jsonl");
        let head = {
            let mut w = ChainWriter::create(&vpath).unwrap();
            w.append(&Violation {
                step: 1,
                kind: ViolationKind::MaskedRead,
                path: Some("/oracle/a".into()),
                host: None,
                pid: 9,
                syscall: "openat".into(),
            })
            .unwrap();
            w.append(&Violation {
                step: 2,
                kind: ViolationKind::BlockedConnect,
                path: None,
                host: Some("1.2.3.4:443".into()),
                pid: 9,
                syscall: "connect".into(),
            })
            .unwrap();
            w.head().to_string()
        };
        std::fs::write(dir.join("agent-stdout.log"), b"hello stdout").unwrap();
        std::fs::write(dir.join("agent-stderr.log"), b"").unwrap();
        let arts = hash_artifacts(&[
            ("agent-stdout.log".into(), dir.join("agent-stdout.log")),
            ("agent-stderr.log".into(), dir.join("agent-stderr.log")),
        ])
        .unwrap();
        let verdict = VerdictBuilder {
            task_id: "t".into(),
            pass: false,
            status: Status::Compromised,
            violations_head: head,
            violations_count: 2,
            env_digest: "e".into(),
            artifacts_digest: artifacts_digest(&arts),
            reward: None,
        }
        .sign(signer);
        Bundle::build(verdict, &vpath, &arts).unwrap()
    }

    #[test]
    fn good_bundle_verifies_and_round_trips() {
        let d = tempfile::tempdir().unwrap();
        let signer = Signer::generate();
        let b = good_bundle(d.path(), &signer);
        assert!(b.verify(None).is_ok());
        assert!(b.verify(Some(&signer.public_key_hex())).is_ok());
        let p = d.path().join("bundle.json");
        b.save(&p).unwrap();
        let back = Bundle::load(&p).unwrap();
        assert!(back.verify(Some(&signer.public_key_hex())).is_ok());
    }

    #[test]
    fn wrong_pubkey_fails() {
        let d = tempfile::tempdir().unwrap();
        let b = good_bundle(d.path(), &Signer::generate());
        let other = Signer::generate();
        assert!(matches!(
            b.verify(Some(&other.public_key_hex())),
            Err(BundleError::PubkeyMismatch)
        ));
    }

    #[test]
    fn mutated_violation_fails_chain() {
        let d = tempfile::tempdir().unwrap();
        let mut b = good_bundle(d.path(), &Signer::generate());
        b.violations[0]["path"] = serde_json::json!("/oracle/CHANGED");
        assert!(matches!(b.verify(None), Err(BundleError::Chain)));
    }

    #[test]
    fn dropped_violation_fails() {
        let d = tempfile::tempdir().unwrap();
        let mut b = good_bundle(d.path(), &Signer::generate());
        b.violations.pop();
        assert!(b.verify(None).is_err()); // Chain (head changed) or Count
    }

    #[test]
    fn tampered_artifact_hash_fails() {
        let d = tempfile::tempdir().unwrap();
        let mut b = good_bundle(d.path(), &Signer::generate());
        b.manifest.artifacts[0].sha256 = "00".repeat(32);
        assert!(matches!(b.verify(None), Err(BundleError::Artifacts)));
    }

    #[test]
    fn bundle_v2_round_trips_environment() {
        let env = Environment {
            agent_command: "agent --solve".into(),
            rootfs_kind: "image".into(),
            image_ref: Some("ghcr.io/x/y@sha256:abc".into()),
            image_digest: Some("abc".into()),
            proctor_version: "0.1.0".into(),
            proctor_commit: "deadbee".into(),
            policy_sha256: "p".into(),
            spec_sha256: "s".into(),
        };
        let json = serde_json::to_string(&env).unwrap();
        let back: Environment = serde_json::from_str(&json).unwrap();
        assert_eq!(back.agent_command, "agent --solve");
        assert_eq!(back.image_digest.as_deref(), Some("abc"));
    }

    #[test]
    fn bundle_v1_without_environment_still_loads() {
        // Verdict uses #[serde(flatten)] for body, so the verdict object is flat
        // and must carry the required proctor_version. No `environment` key = v1.
        let j = r#"{"bundle_version":1,
          "verdict":{"task_id":"t","pass":true,"status":"clean",
            "violations_head":"0000000000000000000000000000000000000000000000000000000000000000",
            "violations_count":0,"env_digest":"e","artifacts_digest":"a",
            "proctor_version":"0.1.0","public_key":"00","signature":"00"},
          "violations":[],"manifest":{"artifacts":[]}}"#;
        let b: Bundle = serde_json::from_str(j).unwrap();
        assert_eq!(b.bundle_version, 1);
        assert!(b.environment.is_none());
    }

    #[test]
    fn verify_fails_on_tampered_environment() {
        let env = Environment {
            agent_command: "agent --solve".into(),
            rootfs_kind: "host".into(),
            image_ref: None,
            image_digest: None,
            proctor_version: "0.1.0".into(),
            proctor_commit: "c".into(),
            policy_sha256: "p".into(),
            spec_sha256: "s".into(),
        };
        let signer = Signer::generate();
        let arts: Vec<Artifact> = vec![];
        let verdict = VerdictBuilder {
            task_id: "t".into(),
            pass: true,
            status: Status::Clean,
            violations_head: crate::digest::GENESIS.into(),
            violations_count: 0,
            env_digest: env_digest_of(&env),
            artifacts_digest: artifacts_digest(&arts),
            reward: None,
        }
        .sign(&signer);
        let mut b = Bundle {
            bundle_version: 2,
            verdict,
            violations: vec![],
            manifest: Manifest { artifacts: vec![] },
            environment: Some(env),
        };
        assert!(b.verify(None).is_ok(), "good v2 bundle verifies");
        b.environment.as_mut().unwrap().image_digest = Some("tampered".into());
        assert!(matches!(b.verify(None), Err(BundleError::EnvMismatch)));
    }
}
