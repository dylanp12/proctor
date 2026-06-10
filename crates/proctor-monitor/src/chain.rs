//! Hash-chained JSONL writer + verifier. record_hash = SHA256(prev_hash ||
//! canonical_json(violation)). The head hash is bound into the signed verdict,
//! so any edit/drop/reorder is detectable.

use crate::event::Violation;
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed record on line {line}: {detail}")]
    Malformed { line: usize, detail: String },
    #[error("hash chain broken at line {line}")]
    Broken { line: usize },
}

/// One JSONL line: the violation plus the running chain hash.
#[derive(serde::Serialize, serde::Deserialize)]
struct Record {
    #[serde(flatten)]
    violation: Violation,
    /// SHA256(prev || canonical(violation)), hex
    chain: String,
}

fn next_hash(prev: &str, v: &Violation) -> String {
    let canon = canonical_violation(v);
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(canon.as_bytes());
    hex::encode(h.finalize())
}

/// Canonical JSON of a violation (sorted keys) for stable hashing.
fn canonical_violation(v: &Violation) -> String {
    let val = serde_json::to_value(v).expect("violation serializes");
    canonical_value(&val)
}

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

pub struct ChainWriter {
    file: std::fs::File,
    head: String,
}

impl ChainWriter {
    pub fn create(path: &Path) -> Result<Self, ChainError> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        Ok(Self {
            file,
            head: GENESIS.to_string(),
        })
    }

    pub fn append(&mut self, v: &Violation) -> Result<(), ChainError> {
        let chain = next_hash(&self.head, v);
        let rec = Record {
            violation: v.clone(),
            chain: chain.clone(),
        };
        let mut line = serde_json::to_vec(&rec).map_err(|e| ChainError::Malformed {
            line: 0,
            detail: e.to_string(),
        })?;
        line.push(b'\n');
        self.file.write_all(&line)?;
        self.file.flush()?;
        self.head = chain;
        Ok(())
    }

    pub fn head(&self) -> &str {
        &self.head
    }
}

/// Recompute the chain from scratch; returns the head hash if intact.
pub fn verify_chain(path: &Path) -> Result<String, ChainError> {
    let f = std::fs::File::open(path)?;
    let mut prev = GENESIS.to_string();
    for (i, line) in BufReader::new(f).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let rec: Record = serde_json::from_str(&line).map_err(|e| ChainError::Malformed {
            line: i + 1,
            detail: e.to_string(),
        })?;
        let expect = next_hash(&prev, &rec.violation);
        if expect != rec.chain {
            return Err(ChainError::Broken { line: i + 1 });
        }
        prev = rec.chain;
    }
    Ok(prev)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Violation, ViolationKind};

    fn v(step: u64, path: &str) -> Violation {
        Violation {
            step,
            kind: ViolationKind::MaskedRead,
            path: Some(path.into()),
            host: None,
            pid: 42,
            syscall: "openat".into(),
        }
    }

    #[test]
    fn empty_chain_head_is_genesis() {
        let dir = tempfile::tempdir().unwrap();
        let w = ChainWriter::create(&dir.path().join("violations.jsonl")).unwrap();
        assert_eq!(w.head(), GENESIS);
    }

    #[test]
    fn head_advances_and_is_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.jsonl");
        let h = {
            let mut w = ChainWriter::create(&path).unwrap();
            w.append(&v(1, "/oracle/a")).unwrap();
            w.append(&v(2, "/oracle/b")).unwrap();
            w.head().to_string()
        };
        let path2 = dir.path().join("v2.jsonl");
        let h2 = {
            let mut w = ChainWriter::create(&path2).unwrap();
            w.append(&v(1, "/oracle/a")).unwrap();
            w.append(&v(2, "/oracle/b")).unwrap();
            w.head().to_string()
        };
        assert_eq!(h, h2);
        assert_ne!(h, GENESIS);
    }

    #[test]
    fn verify_accepts_an_untampered_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.jsonl");
        let head = {
            let mut w = ChainWriter::create(&path).unwrap();
            w.append(&v(1, "/oracle/a")).unwrap();
            w.append(&v(2, "/oracle/b")).unwrap();
            w.head().to_string()
        };
        assert_eq!(verify_chain(&path).unwrap(), head);
    }

    #[test]
    fn verify_detects_a_mutated_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.jsonl");
        {
            let mut w = ChainWriter::create(&path).unwrap();
            w.append(&v(1, "/oracle/a")).unwrap();
            w.append(&v(2, "/oracle/b")).unwrap();
        }
        let body = std::fs::read_to_string(&path)
            .unwrap()
            .replace("/oracle/b", "/oracle/X");
        std::fs::write(&path, body).unwrap();
        assert!(matches!(
            verify_chain(&path),
            Err(ChainError::Broken { line: 2 })
        ));
    }

    #[test]
    fn verify_detects_a_dropped_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.jsonl");
        {
            let mut w = ChainWriter::create(&path).unwrap();
            w.append(&v(1, "/oracle/a")).unwrap();
            w.append(&v(2, "/oracle/b")).unwrap();
            w.append(&v(3, "/oracle/c")).unwrap();
        }
        let kept: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, l)| l.to_string())
            .collect();
        std::fs::write(&path, kept.join("\n") + "\n").unwrap();
        assert!(verify_chain(&path).is_err());
    }
}
