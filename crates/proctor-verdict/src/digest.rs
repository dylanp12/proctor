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
}
