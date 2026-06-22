//! Environment digest: a deterministic hash binding the run's inputs (policy,
//! spec, tool versions, and optionally a workspace tree) so the verdict is
//! reproducible and any input change is visible.

use sha2::{Digest, Sha256};
use std::path::Path;

/// Deterministic hash over a directory tree (sorted relative paths + content).
pub fn tree_digest(root: &Path) -> std::io::Result<String> {
    let mut entries: Vec<std::path::PathBuf> = walkdir::WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .collect();
    entries.sort();
    let mut h = Sha256::new();
    for p in entries {
        let rel = p.strip_prefix(root).unwrap();
        h.update(rel.to_string_lossy().as_bytes());
        h.update([0u8]);
        h.update(std::fs::read(&p)?);
        h.update([0u8]);
    }
    Ok(hex::encode(h.finalize()))
}

/// Genesis hash of an empty violation chain (matches proctor-monitor::chain).
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Recompute the violation chain head from parsed records (each a JSON object
/// containing the violation fields + a `chain` field). Mirrors the monitor's
/// writer: head = SHA256(prev || canonical(record-without-chain)), folded from
/// GENESIS. This is the verify side of the chain; agreement with the writer is
/// cross-tested.
pub fn chain_head(records: &[serde_json::Value]) -> String {
    let mut prev = GENESIS.to_string();
    for rec in records {
        let mut v = rec.clone();
        if let Some(map) = v.as_object_mut() {
            map.remove("chain");
        }
        let canon = canonical_value(&v);
        let mut h = Sha256::new();
        h.update(prev.as_bytes());
        h.update(canon.as_bytes());
        prev = hex::encode(h.finalize());
    }
    prev
}

/// Sorted-key canonical JSON (ported from proctor-monitor::chain so the verdict
/// crate stays free of a runtime dependency on the monitor).
fn canonical_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let inner: Vec<String> = keys
                .iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap(),
                        canonical_value(&map[*k])
                    )
                })
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        serde_json::Value::Array(a) => {
            format!(
                "[{}]",
                a.iter().map(canonical_value).collect::<Vec<_>>().join(",")
            )
        }
        other => serde_json::to_string(other).unwrap(),
    }
}

/// Digest binding a manifest's artifact (name, sha256) entries — folded into the
/// signed verdict body, and recomputed at verify time from the manifest.
pub fn artifacts_digest(artifacts: &[crate::bundle::Artifact]) -> String {
    let parts: Vec<(&str, &[u8])> = artifacts
        .iter()
        .map(|a| (a.name.as_str(), a.sha256.as_bytes()))
        .collect();
    env_digest(&parts)
}

/// Fold a recorded `Environment` into a single digest. This is what a run stores
/// in the signed `env_digest` field, and what `verify-bundle` recomputes from the
/// bundle's recorded environment to confirm the binding (v2+).
pub fn env_digest_of(e: &crate::bundle::Environment) -> String {
    env_digest(&[
        ("agent_command", e.agent_command.as_bytes()),
        ("rootfs_kind", e.rootfs_kind.as_bytes()),
        ("image_ref", e.image_ref.as_deref().unwrap_or("").as_bytes()),
        ("image_digest", e.image_digest.as_deref().unwrap_or("").as_bytes()),
        ("proctor_version", e.proctor_version.as_bytes()),
        ("proctor_commit", e.proctor_commit.as_bytes()),
        ("policy_sha256", e.policy_sha256.as_bytes()),
        ("spec_sha256", e.spec_sha256.as_bytes()),
    ])
}

/// Raw SHA-256 hex of bytes — used to record the policy/spec hashes in the
/// bundle's `Environment` so a verifier can confirm what the run was given.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Digest of arbitrary labeled byte blobs (policy yaml, spec json, versions).
pub fn env_digest(parts: &[(&str, &[u8])]) -> String {
    let mut sorted: Vec<&(&str, &[u8])> = parts.iter().collect();
    sorted.sort_by_key(|(k, _)| *k);
    let mut h = Sha256::new();
    for (k, v) in sorted {
        h.update(k.as_bytes());
        h.update([0u8]);
        h.update(v);
        h.update([0u8]);
    }
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_hash_is_order_independent_for_dirs_but_content_sensitive() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("a")).unwrap();
        std::fs::write(d.path().join("a/x"), "1").unwrap();
        std::fs::write(d.path().join("y"), "2").unwrap();
        let h1 = tree_digest(d.path()).unwrap();
        let d2 = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d2.path().join("a")).unwrap();
        std::fs::write(d2.path().join("y"), "2").unwrap();
        std::fs::write(d2.path().join("a/x"), "1").unwrap();
        assert_eq!(h1, tree_digest(d2.path()).unwrap());
        std::fs::write(d2.path().join("y"), "3").unwrap();
        assert_ne!(h1, tree_digest(d2.path()).unwrap());
    }

    #[test]
    fn env_digest_is_stable_and_sensitive() {
        let a = env_digest(&[("policy", b"x"), ("spec", b"y")]);
        let b = env_digest(&[("spec", b"y"), ("policy", b"x")]); // order-independent
        assert_eq!(a, b);
        let c = env_digest(&[("policy", b"x"), ("spec", b"z")]);
        assert_ne!(a, c);
    }

    #[test]
    fn env_digest_of_is_stable_and_field_sensitive() {
        use crate::bundle::Environment;
        let base = Environment {
            agent_command: "a".into(),
            rootfs_kind: "host".into(),
            image_ref: None,
            image_digest: None,
            proctor_version: "0.1.0".into(),
            proctor_commit: "c".into(),
            policy_sha256: "p".into(),
            spec_sha256: "s".into(),
        };
        let d1 = env_digest_of(&base);
        assert_eq!(d1, env_digest_of(&base.clone()), "stable");
        let mut changed = base.clone();
        changed.agent_command = "b".into();
        assert_ne!(d1, env_digest_of(&changed), "sensitive to agent_command");
    }

    #[test]
    fn chain_head_agrees_with_monitor_writer() {
        use proctor_monitor::chain::{verify_chain, ChainWriter};
        use proctor_monitor::event::{Violation, ViolationKind};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.jsonl");
        {
            let mut w = ChainWriter::create(&path).unwrap();
            for (i, p) in ["/oracle/a", "/oracle/b", "/logs/verifier"]
                .iter()
                .enumerate()
            {
                w.append(&Violation {
                    step: i as u64 + 1,
                    kind: if i == 2 {
                        ViolationKind::MaskedWrite
                    } else {
                        ViolationKind::MaskedRead
                    },
                    path: Some((*p).into()),
                    host: None,
                    pid: 7,
                    syscall: "openat".into(),
                })
                .unwrap();
            }
        }
        let writer_head = verify_chain(&path).unwrap();
        let records: Vec<serde_json::Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(
            chain_head(&records),
            writer_head,
            "verify-side head must equal writer head"
        );
    }

    #[test]
    fn chain_head_empty_is_genesis() {
        assert_eq!(chain_head(&[]), GENESIS);
    }
}
