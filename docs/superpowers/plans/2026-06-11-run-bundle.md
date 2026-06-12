# Signed Run-Bundle + verify-bundle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Package a run into a single self-contained `bundle.json` and add `proctor verify-bundle` that re-checks the signature, the violation chain (bound to the signed verdict), and the agent-log hashes; plus a stable operator signing key.

**Architecture:** Add `proctor-verdict::bundle` (a `Bundle` embedding the signed verdict + violation records + a log-hash manifest). Bind the log hashes into the existing verdict signature via a new signed `VerdictBody.artifacts_digest`. The verify-side chain recompute is a ported copy of the monitor's canonicalizer, cross-tested for agreement. A `sign::resolve_signer` resolves a stable key from `--signing-key`/`PROCTOR_SIGNING_SEED` (fresh fallback). Run commands additionally emit `bundle.json`.

**Tech Stack:** Rust 2021 workspace. `proctor-verdict` (sha2/hex/ed25519/serde_json), `proctor-cli`. Spec: [`docs/superpowers/specs/2026-06-11-run-bundle-design.md`](../specs/2026-06-11-run-bundle-design.md).

---

## Context primer (read before Task 1)

- This is **sub-project #3**. The loose `verdict.json` / `violations.jsonl` keep being written; `bundle.json` is **additive** — existing corpus/e2e/tb/swebench tests must stay green.
- The violation hash chain (in `proctor-monitor::chain`) is `record_hash = SHA256(prev_hash || canonical(violation))`, where `canonical` is a **custom sorted-key** JSON encoder (NOT RFC-8785), and `violation` is the record WITHOUT the `chain` field. `GENESIS = "0"*64`. The verify side must replicate this exactly; we port the canonicalizer into `proctor-verdict::digest` and add a cross-test that builds a chain with the real writer and re-derives the same head.
- `VerdictBody` is signed via `serde_json_canonicalizer` over the body. Adding a field is automatically covered by the signature. `Verdict` derives `Clone`.
- `digest::env_digest(&[(&str, &[u8])])` already hashes a sorted labeled-blob set — reuse it for `artifacts_digest`.

### File structure

```
crates/proctor-verdict/src/digest.rs   # + chain_head(records) + GENESIS + canonical_value (ported)
crates/proctor-verdict/src/verdict.rs  # + VerdictBody.artifacts_digest, VerdictBuilder.artifacts_digest
crates/proctor-verdict/src/bundle.rs   # NEW: Bundle, Manifest, Artifact, hash_artifacts, artifacts_digest, read_records, verify
crates/proctor-verdict/src/sign.rs     # + resolve_signer
crates/proctor-verdict/src/lib.rs      # + pub mod bundle;
crates/proctor-verdict/Cargo.toml      # dev-deps: proctor-monitor, tempfile (cross-test only)
crates/proctor-cli/src/run.rs          # all 3 run fns: artifacts_digest + bundle.json + resolve_signer
crates/proctor-cli/src/main.rs         # verify-bundle + keygen subcommands; --signing-key on run cmds
crates/proctor-cli/tests/bundle_e2e_test.rs  # run -> verify-bundle ok; tamper -> fail; stable seed -> shared pubkey
```

---

## Task 1: `digest::chain_head` (verify-side chain recompute)

**Files:** Modify `crates/proctor-verdict/src/digest.rs`, `crates/proctor-verdict/Cargo.toml`

- [ ] **Step 1: Add the cross-test** (append to the `#[cfg(test)] mod tests` in `digest.rs`)

```rust
    #[test]
    fn chain_head_agrees_with_monitor_writer() {
        use proctor_monitor::chain::{verify_chain, ChainWriter};
        use proctor_monitor::event::{Violation, ViolationKind};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.jsonl");
        {
            let mut w = ChainWriter::create(&path).unwrap();
            for (i, p) in ["/oracle/a", "/oracle/b", "/logs/verifier"].iter().enumerate() {
                w.append(&Violation {
                    step: i as u64 + 1,
                    kind: if i == 2 { ViolationKind::MaskedWrite } else { ViolationKind::MaskedRead },
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
        assert_eq!(chain_head(&records), writer_head, "verify-side head must equal writer head");
    }

    #[test]
    fn chain_head_empty_is_genesis() {
        assert_eq!(chain_head(&[]), GENESIS);
    }
```

- [ ] **Step 2: Add the dev-deps** in `crates/proctor-verdict/Cargo.toml`

Under `[dev-dependencies]`:

```toml
proctor-monitor.workspace = true
tempfile.workspace = true
```

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test -p proctor-verdict --lib`
Expected: COMPILE ERROR (`chain_head`, `GENESIS` undefined).

- [ ] **Step 4: Implement `chain_head` + the ported canonicalizer** in `digest.rs`

Add (the `canonical_value` is a verbatim port of `proctor-monitor::chain`'s, kept
in sync by the cross-test above):

```rust
use sha2::{Digest, Sha256};

/// Genesis hash of an empty violation chain (matches proctor-monitor::chain).
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Recompute the violation chain head from parsed records (each a JSON object
/// containing the violation fields + a `chain` field). Mirrors the monitor's
/// writer: head = SHA256(prev || canonical(record-without-chain)), folded from
/// GENESIS. Verify side of the chain; agreement with the writer is cross-tested.
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
                    format!("{}:{}", serde_json::to_string(k).unwrap(), canonical_value(&map[*k]))
                })
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        serde_json::Value::Array(a) => {
            format!("[{}]", a.iter().map(canonical_value).collect::<Vec<_>>().join(","))
        }
        other => serde_json::to_string(other).unwrap(),
    }
}
```

(`digest.rs` already imports `sha2`/`hex` for `tree_digest`/`env_digest`; if the
`use sha2::{Digest, Sha256};` line already exists at the top, don't duplicate it.)

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p proctor-verdict --lib`
Expected: both new tests PASS (head agrees with the monitor writer; empty = genesis).

- [ ] **Step 6: Commit**

```bash
cargo fmt --all
git add -A && git commit -m "feat(verdict): chain_head — verify-side violation-chain recompute (cross-tested vs monitor)"
```

---

## Task 2: `artifacts_digest` in the signed verdict body

**Files:** Modify `crates/proctor-verdict/src/verdict.rs`, `crates/proctor-verdict/tests/verdict_test.rs`

- [ ] **Step 1: Update the failing test** — in `crates/proctor-verdict/tests/verdict_test.rs`, add `artifacts_digest` to the `VerdictBuilder` in `sample()`:

```rust
        env_digest: "deadbeef".into(),
        reward: Some(0.0),
        artifacts_digest: "cafef00d".into(),
    }
    .sign(signer)
```

and add a test that a tampered artifacts digest fails verification:

```rust
#[test]
fn tampered_artifacts_digest_fails_verification() {
    let signer = Signer::generate();
    let mut v = sample(&signer);
    v.body.artifacts_digest = "00".into();
    assert!(v.verify(&signer.public_key_hex()).is_err());
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p proctor-verdict --test verdict_test`
Expected: COMPILE ERROR (`VerdictBuilder` has no `artifacts_digest`).

- [ ] **Step 3: Add the field** in `crates/proctor-verdict/src/verdict.rs`

In `VerdictBody` (after `env_digest`):

```rust
    pub env_digest: String,
    /// digest binding the run's artifact (agent log) hashes into the signature
    pub artifacts_digest: String,
```

In `VerdictBuilder` (after `env_digest`):

```rust
    pub env_digest: String,
    pub artifacts_digest: String,
```

In `VerdictBuilder::sign`, set it on the body (it serializes into the canonical
signed JSON automatically):

```rust
            env_digest: self.env_digest,
            artifacts_digest: self.artifacts_digest,
            reward: self.reward,
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p proctor-verdict --test verdict_test`
Expected: all PASS (including the new tampered-artifacts test). The existing
`round_trips_through_json` / tamper tests still pass.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add -A && git commit -m "feat(verdict): sign artifacts_digest (binds run log hashes into the verdict signature)"
```

---

## Task 3: the `bundle` module

**Files:** Create `crates/proctor-verdict/src/bundle.rs`; Modify `crates/proctor-verdict/src/lib.rs`

- [ ] **Step 1: Write the failing tests** (inline in `bundle.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::Signer;
    use crate::verdict::{Status, VerdictBuilder};

    // build a 2-record violations.jsonl with the real monitor writer, plus a
    // verdict whose head/count/artifacts_digest match, then a bundle.
    fn good_bundle(dir: &std::path::Path, signer: &Signer) -> Bundle {
        use proctor_monitor::chain::ChainWriter;
        use proctor_monitor::event::{Violation, ViolationKind};
        let vpath = dir.join("violations.jsonl");
        let head = {
            let mut w = ChainWriter::create(&vpath).unwrap();
            w.append(&Violation { step: 1, kind: ViolationKind::MaskedRead, path: Some("/oracle/a".into()), host: None, pid: 9, syscall: "openat".into() }).unwrap();
            w.append(&Violation { step: 2, kind: ViolationKind::BlockedConnect, path: None, host: Some("1.2.3.4:443".into()), pid: 9, syscall: "connect".into() }).unwrap();
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
        assert!(matches!(b.verify(Some(&other.public_key_hex())), Err(BundleError::PubkeyMismatch)));
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
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p proctor-verdict --lib bundle` (after adding `pub mod bundle;`)
Expected: COMPILE ERROR (`Bundle` etc. undefined).

- [ ] **Step 3: Implement `bundle.rs`**

```rust
//! A portable, self-contained, independently verifiable run bundle: the signed
//! verdict + the violation records + a manifest of agent-log hashes, all bound
//! under the verdict's single ed25519 signature.

use crate::digest::{artifacts_digest, chain_head};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    pub bundle_version: u32,
    pub verdict: Verdict,
    pub violations: Vec<serde_json::Value>,
    pub manifest: Manifest,
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
            manifest: Manifest { artifacts: artifacts.to_vec() },
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
        Ok(())
    }
}
```

- [ ] **Step 4: Add `artifacts_digest` helper** in `crates/proctor-verdict/src/digest.rs`

```rust
use crate::bundle::Artifact;

/// Digest binding a manifest's artifact (name, sha256) entries — folded into the
/// signed verdict body, and recomputed at verify time from the manifest.
pub fn artifacts_digest(artifacts: &[Artifact]) -> String {
    let parts: Vec<(&str, &[u8])> =
        artifacts.iter().map(|a| (a.name.as_str(), a.sha256.as_bytes())).collect();
    env_digest(&parts)
}
```

- [ ] **Step 5: Register the module** in `crates/proctor-verdict/src/lib.rs`

```rust
//! Verdict assembly: environment digest, ed25519 signing, verification, bundles.
pub mod bundle;
pub mod digest;
pub mod sign;
pub mod verdict;
```

- [ ] **Step 6: Run to verify it passes**

Run: `cargo test -p proctor-verdict`
Expected: all bundle tests PASS (good verifies + round-trips; wrong pubkey, mutated/dropped violation, tampered artifact all fail with the right error). `digest`/`verdict`/`sign` tests still pass.

- [ ] **Step 7: Commit**

```bash
cargo fmt --all && cargo clippy -p proctor-verdict --all-targets -- -D warnings
git add -A && git commit -m "feat(verdict): bundle module — portable signed run-bundle + verify()"
```

---

## Task 4: stable operator key — `resolve_signer`

**Files:** Modify `crates/proctor-verdict/src/sign.rs`

- [ ] **Step 1: Write the failing test** (append to a `#[cfg(test)] mod tests` in `sign.rs`; create the module if absent)

```rust
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
        // ensure the env is not set for this check
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
```

Add `tempfile` to `proctor-verdict`'s `[dev-dependencies]` if not already added in
Task 1 (it is).

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p proctor-verdict --lib sign`
Expected: COMPILE ERROR (`resolve_signer` undefined).

- [ ] **Step 3: Implement `resolve_signer`** in `sign.rs`

```rust
/// Resolve the signing key: an explicit hex seed (e.g. from `--signing-key` file
/// contents) → the `PROCTOR_SIGNING_SEED` env → a fresh key saved to
/// `out_dir/signing-seed.hex`. A malformed explicit/env seed is an error (fail
/// loud) rather than a silent fresh key.
pub fn resolve_signer(explicit_seed_hex: Option<&str>, out_dir: &std::path::Path) -> Result<Signer, String> {
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
```

(`sign.rs` already imports `hex` via the existing `verify_hex`/`to_seed_hex`; no
new top-level imports needed.)

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p proctor-verdict --lib sign`
Expected: 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add -A && git commit -m "feat(verdict): resolve_signer — stable operator key (explicit/env/fresh)"
```

---

## Task 5: CLI — emit bundle.json, verify-bundle, keygen, stable key

**Files:** Modify `crates/proctor-cli/src/run.rs`, `crates/proctor-cli/src/main.rs`; Test `crates/proctor-cli/tests/bundle_e2e_test.rs`

- [ ] **Step 1: Write the failing e2e test** (`crates/proctor-cli/tests/bundle_e2e_test.rs`)

```rust
use proctor_sandbox::require_sandbox;
use std::path::Path;
use std::process::Command;

fn proctor() -> Command {
    Command::new(env!("CARGO_BIN_EXE_proctor"))
}
fn write(p: &Path, s: &str) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, s).unwrap();
}

fn make_task(root: &Path) {
    write(&root.join("task/workspace/solve.sh"), "#!/bin/sh\ncat /oracle/x 2>/dev/null; echo 42 > /workspace/a\n");
    write(&root.join("task/oracle/x"), "SECRET\n");
    write(&root.join("task/oracle/expected.txt"), "42\n");
    write(&root.join("task/grade.sh"), "diff -q /workspace/a /oracle/expected.txt");
    write(&root.join("policy.yaml"), "version: 1\nforbidden:\n  reads: [/oracle]\nnetwork: {mode: deny}\n");
}

fn run(root: &Path, out: &str, seed_env: Option<&str>) {
    let mut c = proctor();
    c.args(["run", "--task"]).arg(root.join("task"))
        .args(["--agent", "sh /workspace/solve.sh"])
        .args(["--policy"]).arg(root.join("policy.yaml"))
        .args(["--out"]).arg(root.join(out));
    if let Some(s) = seed_env {
        c.env("PROCTOR_SIGNING_SEED", s);
    }
    let st = c.output().unwrap();
    assert!(st.status.success(), "run failed: {}", String::from_utf8_lossy(&st.stderr));
}

#[test]
fn bundle_emitted_and_verifies_then_tamper_fails() {
    require_sandbox!();
    let d = tempfile::tempdir().unwrap();
    make_task(d.path());
    run(d.path(), "out", None);
    let bundle = d.path().join("out/bundle.json");
    assert!(bundle.exists(), "run must emit bundle.json");

    // verify-bundle OK
    let v = proctor().args(["verify-bundle", "--bundle"]).arg(&bundle).output().unwrap();
    assert!(v.status.success(), "verify-bundle should pass: {}", String::from_utf8_lossy(&v.stderr));

    // tamper a violation record in the bundle -> verify fails
    let txt = std::fs::read_to_string(&bundle).unwrap().replace("/oracle/x", "/oracle/Y");
    std::fs::write(&bundle, txt).unwrap();
    let v2 = proctor().args(["verify-bundle", "--bundle"]).arg(&bundle).output().unwrap();
    assert!(!v2.status.success(), "tampered bundle must fail verification");
}

#[test]
fn stable_seed_gives_shared_pubkey() {
    require_sandbox!();
    let d = tempfile::tempdir().unwrap();
    make_task(d.path());
    // keygen a seed, then two runs with it share a pubkey and both verify against it
    let kg = proctor().arg("keygen").output().unwrap();
    let kg_out = String::from_utf8_lossy(&kg.stdout);
    let seed = kg_out.lines().find_map(|l| l.strip_prefix("seed=")).unwrap().trim().to_string();
    let pubkey = kg_out.lines().find_map(|l| l.strip_prefix("pubkey=")).unwrap().trim().to_string();

    run(d.path(), "out1", Some(&seed));
    run(d.path(), "out2", Some(&seed));
    for out in ["out1", "out2"] {
        let b = d.path().join(out).join("bundle.json");
        let v = proctor().args(["verify-bundle", "--bundle"]).arg(&b).args(["--pubkey", &pubkey]).output().unwrap();
        assert!(v.status.success(), "{out}: should verify against the operator pubkey: {}", String::from_utf8_lossy(&v.stderr));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p proctor-cli --test bundle_e2e_test`
Expected: FAIL — no `bundle.json` emitted, `verify-bundle`/`keygen` subcommands missing.

- [ ] **Step 3: Emit `bundle.json` + use `resolve_signer` in `run.rs`**

In `run.rs`, add a shared helper near `self_invoker`:

```rust
/// hash the agent logs, fold their digest into the verdict, and write bundle.json
fn write_bundle(
    verdict: &proctor_verdict::verdict::Verdict,
    session: &Path,
    out: &Path,
) -> Result<(), anyhow::Error> {
    let arts = proctor_verdict::bundle::hash_artifacts(&[
        ("agent-stdout.log".into(), session.join("agent-stdout.log")),
        ("agent-stderr.log".into(), session.join("agent-stderr.log")),
    ])?;
    let bundle =
        proctor_verdict::bundle::Bundle::build(verdict.clone(), &out.join("violations.jsonl"), &arts)?;
    bundle.save(&out.join("bundle.json"))?;
    Ok(())
}

/// compute the artifacts_digest for the verdict body from the agent logs
fn artifacts_digest_for(session: &Path) -> Result<String, anyhow::Error> {
    let arts = proctor_verdict::bundle::hash_artifacts(&[
        ("agent-stdout.log".into(), session.join("agent-stdout.log")),
        ("agent-stderr.log".into(), session.join("agent-stderr.log")),
    ])?;
    Ok(proctor_verdict::digest::artifacts_digest(&arts))
}
```

Then in **each** of `run`, `run_tb`, `run_swebench`:
1. Replace the signer construction with the resolver. In `run` (which has
   `signing_seed: Option<&str>`):
   ```rust
   let signer = proctor_verdict::sign::resolve_signer(signing_seed, out)
       .map_err(|e| anyhow::anyhow!(e))?;
   ```
   In `run_tb` and `run_swebench` (which currently call `Signer::generate()` then
   write the seed):
   ```rust
   let signer = proctor_verdict::sign::resolve_signer(None, out)
       .map_err(|e| anyhow::anyhow!(e))?;
   ```
   (Delete the old `Signer::generate()` + `std::fs::write(... signing-seed.hex ...)`
   lines they replace; `resolve_signer` writes the seed in the fresh case.)
2. Add `artifacts_digest` to each `VerdictBuilder { ... }` — computed from the
   agent session before signing:
   ```rust
   let art_digest = artifacts_digest_for(&session)?;
   ```
   and in the builder, after `env_digest: digest,`:
   ```rust
       artifacts_digest: art_digest,
   ```
3. After `verdict.save(&out.join("verdict.json"))?;` in each, add:
   ```rust
   write_bundle(&verdict, &session, out)?;
   ```
   (`session` is the agent session dir already bound in each function; `out` is the
   output dir. In `run_swebench` the session var is `session`; in `run`/`run_tb`
   it is `session`.)

Note: the existing `run` `signing_seed` parameter stays; this plan does not add a
separate `--signing-key` file flag (env + `--signing-seed` cover the stable-key
need). If a file flag is desired later it reads to a hex string and feeds the same
`resolve_signer` arg.

- [ ] **Step 4: Add `verify-bundle` and `keygen` subcommands** in `main.rs`

Add to `enum Cmd`:

```rust
    /// Verify a run bundle: signature, violation chain, and artifact hashes.
    VerifyBundle {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        pubkey: Option<String>,
    },
    /// Print a fresh signing seed + its public key (for PROCTOR_SIGNING_SEED).
    Keygen,
```

Add match arms:

```rust
        Cmd::VerifyBundle { bundle, pubkey } => {
            match proctor_verdict::bundle::Bundle::load(&bundle) {
                Ok(b) => match b.verify(pubkey.as_deref()) {
                    Ok(()) => {
                        println!(
                            "bundle OK: signature valid, chain bound, {} violation(s), status={:?}",
                            b.verdict.body.violations_count, b.verdict.body.status
                        );
                        0
                    }
                    Err(e) => {
                        eprintln!("bundle INVALID: {e}");
                        2
                    }
                },
                Err(e) => {
                    eprintln!("bundle INVALID: {e}");
                    2
                }
            }
        }
        Cmd::Keygen => {
            let s = proctor_verdict::sign::Signer::generate();
            println!("seed={}", s.to_seed_hex());
            println!("pubkey={}", s.public_key_hex());
            0
        }
```

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p proctor-cli --test bundle_e2e_test`
Expected: both tests PASS — `bundle.json` emitted, `verify-bundle` passes, tamper fails, stable seed yields a shared pubkey both bundles verify against.

- [ ] **Step 6: Full gate + commit**

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: green (existing verdict/e2e/tb/swebench/corpus tests pass; verdict builders all carry the new field).

```bash
git add -A && git commit -m "feat(cli): emit bundle.json, verify-bundle + keygen, stable operator key"
```

---

## Self-review

**Spec coverage:**
- single self-contained `bundle.json` (verdict + violations + manifest) → Task 3 ✓
- log hashes bound via signed `artifacts_digest` → Task 2 (field) + Task 3 (helper + verify) + Task 5 (computed in pipeline) ✓
- `verify-bundle` checks signature + chain head/count + artifacts digest → Task 3 `Bundle::verify` + Task 5 CLI ✓
- stable operator key (`PROCTOR_SIGNING_SEED`, fresh fallback) + keygen → Task 4 + Task 5 ✓
- loose verdict.json/violations.jsonl still written (no regression) → Task 5 keeps the existing saves; adds bundle ✓
- chain recompute in `proctor-verdict` cross-tested vs `proctor-monitor` → Task 1 ✓
- tests: round-trip, verify good, tamper (violation/count/artifact), wrong pubkey, stable key, e2e → Tasks 1–5 ✓

**Placeholder scan:** every code step is complete; commands have expected output. The `--signing-key` file flag from the spec is intentionally folded into `PROCTOR_SIGNING_SEED` + the existing `run --signing-seed` (noted in Task 5 step 3) — env + explicit cover the stable-key requirement; a redundant file flag is YAGNI. No TODOs.

**Type consistency:** `chain_head(&[Value]) -> String` and `GENESIS` (Task 1) used by `Bundle::verify` (Task 3). `artifacts_digest(&[Artifact]) -> String` (Task 3 step 4, in `digest`) imports `bundle::Artifact` — `digest` and `bundle` are sibling modules in the same crate (no cycle: `bundle` uses `digest::{chain_head, artifacts_digest}`, `digest::artifacts_digest` uses `bundle::Artifact` — a type-only reference within one crate, which compiles). `VerdictBody`/`VerdictBuilder.artifacts_digest: String` (Task 2) set in all builders (Task 5) and in the verdict tests. `Bundle::build(Verdict, &Path, &[Artifact])`, `hash_artifacts(&[(String,PathBuf)])`, `resolve_signer(Option<&str>, &Path)` signatures match every call site. `Verdict` derives `Clone` (used by `write_bundle`).

> Note on the `digest`↔`bundle` reference: if the in-crate type reference trips a borrow/cycle lint at build time, move `Artifact` + `artifacts_digest` entirely into `bundle.rs` and have `Bundle::verify` call a local `artifacts_digest`; `chain_head` stays in `digest`. Functionally identical; decide by what compiles.

---

## Execution handoff

Recommended: **inline** — all tasks are in `proctor-verdict`/`proctor-cli` internals already in context, and the tasks build on each other (chain_head → artifacts_digest → bundle → CLI). Tasks 1–4 are pure-logic (no sandbox); Task 5's e2e needs a sandbox-capable host.
