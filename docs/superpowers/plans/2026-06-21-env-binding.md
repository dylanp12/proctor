# Bind the run environment into the signed bundle — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `bundle.json` bind and record the run environment (agent command, rootfs/image ref+digest, Proctor version+commit, policy/spec hashes) so `verify-bundle` can independently recompute and confirm it.

**Architecture:** Add a cleartext `environment` section to `Bundle` (bundle_version → 2). `env_digest` (already in the signed `VerdictBody`) is computed by folding the `Environment` fields, so the existing ed25519 signature binds them. `verify-bundle` gains a 4th check: recompute `env_digest` from the recorded `environment` and require it equals `verdict.body.env_digest`. v1 bundles (no environment) keep verifying on the original 3 checks.

**Tech Stack:** Rust, `serde`/`serde_json`, `sha2`, ed25519 (existing `proctor-verdict`); a `build.rs` for the git commit. Spec: `docs/superpowers/specs/2026-06-21-env-binding-design.md`.

---

### Task 1: `Environment` struct + `Bundle` v2 (recorded, optional, round-trips)

**Files:**
- Modify: `crates/proctor-verdict/src/bundle.rs`
- Test: `crates/proctor-verdict/src/bundle.rs` (`#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing test** (append to the existing tests module)

```rust
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
    // a pre-env bundle: no `environment` key, version 1
    let j = r#"{"bundle_version":1,"verdict":{"body":{"task_id":"t","pass":true,
      "status":"clean","reward":0.0,"violations_head":"0000000000000000000000000000000000000000000000000000000000000000",
      "violations_count":0,"env_digest":"e","artifacts_digest":"a"},
      "public_key":"00","signature":"00"},"violations":[],"manifest":{"artifacts":[]}}"#;
    let b: Bundle = serde_json::from_str(j).unwrap();
    assert_eq!(b.bundle_version, 1);
    assert!(b.environment.is_none());
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p proctor-verdict bundle_v`
Expected: FAIL — `Environment` undefined / `environment` field missing.

- [ ] **Step 3: Implement** (in `bundle.rs`, near the existing `Bundle`/`Manifest`/`Artifact` structs)

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct Environment {
    pub agent_command: String,
    pub rootfs_kind: String,            // "host" | "image"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_digest: Option<String>,
    pub proctor_version: String,
    pub proctor_commit: String,
    pub policy_sha256: String,
    pub spec_sha256: String,
}
```

Add to `Bundle` (keep existing fields; add the optional environment, default None so v1 loads):

```rust
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<Environment>,
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p proctor-verdict bundle_v`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add crates/proctor-verdict/src/bundle.rs
git commit -m "feat(verdict): add recorded Environment to Bundle (v2, optional)"
```

---

### Task 2: `env_digest_of(&Environment)` digest helper

**Files:**
- Modify: `crates/proctor-verdict/src/digest.rs`
- Test: `crates/proctor-verdict/src/digest.rs` tests module

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn env_digest_of_is_stable_and_field_sensitive() {
    use crate::bundle::Environment;
    let base = Environment {
        agent_command: "a".into(), rootfs_kind: "host".into(),
        image_ref: None, image_digest: None, proctor_version: "0.1.0".into(),
        proctor_commit: "c".into(), policy_sha256: "p".into(), spec_sha256: "s".into(),
    };
    let d1 = env_digest_of(&base);
    let d2 = env_digest_of(&base.clone());
    assert_eq!(d1, d2, "stable");
    let mut changed = base.clone();
    changed.agent_command = "b".into();
    assert_ne!(d1, env_digest_of(&changed), "sensitive to agent_command");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p proctor-verdict env_digest_of`
Expected: FAIL — `env_digest_of` undefined.

- [ ] **Step 3: Implement** (in `digest.rs`, reusing the existing `env_digest`)

```rust
/// Fold an Environment into a single digest (folded into the signed verdict body,
/// recomputed at verify time from the bundle's recorded environment).
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
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p proctor-verdict env_digest_of`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/proctor-verdict/src/digest.rs
git commit -m "feat(verdict): env_digest_of folds the Environment fields"
```

---

### Task 3: `verify-bundle` 4th check — recompute env_digest from the recorded environment

**Files:**
- Modify: `crates/proctor-verdict/src/bundle.rs` (the `verify` method + `BundleError`)
- Test: `crates/proctor-verdict/src/bundle.rs` tests

- [ ] **Step 1: Write the failing test** (extend the existing bundle-build test helper to set an environment; assert good passes + tampered fails)

```rust
#[test]
fn verify_fails_on_tampered_environment() {
    let mut b = sample_bundle_with_env(); // helper builds a signed v2 bundle (see Step 3)
    assert!(b.verify(None).is_ok(), "good v2 bundle verifies");
    if let Some(env) = b.environment.as_mut() { env.image_digest = Some("tampered".into()); }
    match b.verify(None) {
        Err(BundleError::EnvMismatch) => {}
        other => panic!("expected EnvMismatch, got {other:?}"),
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p proctor-verdict verify_fails_on_tampered_environment`
Expected: FAIL — `BundleError::EnvMismatch` undefined / no env check yet.

- [ ] **Step 3: Implement**

Add the error variant to `BundleError`:

```rust
    #[error("environment digest mismatch (recorded environment does not match the signed env_digest)")]
    EnvMismatch,
```

Add a 4th check at the end of `Bundle::verify`, before `Ok(())`:

```rust
        // 4. if an environment is recorded (v2+), it must recompute to the signed env_digest
        if let Some(env) = &self.environment {
            if crate::digest::env_digest_of(env) != self.verdict.body.env_digest {
                return Err(BundleError::EnvMismatch);
            }
        }
```

Add the test helper (in the tests module), reusing the existing `VerdictBuilder` test path and setting `env_digest = env_digest_of(&env)`:

```rust
fn sample_bundle_with_env() -> Bundle {
    use crate::verdict::{Status, VerdictBuilder};
    let env = Environment {
        agent_command: "agent --solve".into(), rootfs_kind: "host".into(),
        image_ref: None, image_digest: None, proctor_version: "0.1.0".into(),
        proctor_commit: "c".into(), policy_sha256: "p".into(), spec_sha256: "s".into(),
    };
    let signer = crate::sign::Signer::generate();
    let verdict = VerdictBuilder {
        task_id: "t".into(), pass: true, status: Status::Clean,
        violations_head: crate::digest::GENESIS.into(), violations_count: 0,
        env_digest: crate::digest::env_digest_of(&env),
        artifacts_digest: crate::digest::artifacts_digest(&[]),
        reward: 0.0,
    }.sign(&signer);
    Bundle {
        bundle_version: 2, verdict, violations: vec![],
        manifest: Manifest { artifacts: vec![] }, environment: Some(env),
    }
}
```

(Adjust field names to match the actual `VerdictBuilder` / `Signer` API confirmed in `verdict.rs` and `sign.rs`; if `Signer::generate` differs, use the crate's existing fresh-signer constructor.)

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p proctor-verdict`
Expected: PASS (all verdict-crate tests, including the existing v1 round-trip).

- [ ] **Step 5: Commit**

```bash
git add crates/proctor-verdict/src/bundle.rs
git commit -m "feat(verdict): verify-bundle recomputes env_digest from recorded environment"
```

---

### Task 4: Capture the Proctor build commit (`build.rs`)

**Files:**
- Create: `crates/proctor-cli/build.rs`
- Modify: `crates/proctor-cli/src/run.rs` (read it where the Environment is built — Task 5)

- [ ] **Step 1: Implement the build script**

```rust
// crates/proctor-cli/build.rs
use std::process::Command;
fn main() {
    let commit = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=PROCTOR_GIT_COMMIT={commit}");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
}
```

- [ ] **Step 2: Verify it compiles + the env var is available**

Run: `cargo build -p proctor-cli` then `cargo test -p proctor-cli commit_env`
After adding this test to `run.rs` tests:

```rust
#[test]
fn build_commit_is_present() {
    let c = env!("PROCTOR_GIT_COMMIT");
    assert!(!c.is_empty());
}
```

Expected: PASS (value is a short SHA or `"unknown"`).

- [ ] **Step 3: Commit**

```bash
git add crates/proctor-cli/build.rs crates/proctor-cli/src/run.rs
git commit -m "build(cli): capture git commit into PROCTOR_GIT_COMMIT"
```

---

### Task 5: Build the `Environment` in all three run paths and bind it

**Files:**
- Modify: `crates/proctor-cli/src/run.rs` (the 3 `env_digest(&[…])` sites: ~169, ~338, ~532, and the `write_bundle`/`Bundle::build` call)
- Test: `crates/proctor-cli/tests/` (extend the existing e2e/corpus path or add `env_binding_test.rs`)

- [ ] **Step 1: Write the failing e2e test** (a `proctor run` on a tiny task emits a v2 bundle whose environment verifies)

```rust
// crates/proctor-cli/tests/env_binding_test.rs
// Runs `proctor run` on a minimal task (mirror an existing e2e test's setup),
// then loads out/bundle.json and asserts:
#[test]
fn run_emits_v2_bundle_with_verifying_environment() {
    // … set up a minimal task + out dir like the existing e2e test …
    let bundle: proctor_verdict::bundle::Bundle =
        serde_json::from_str(&std::fs::read_to_string(out.join("bundle.json")).unwrap()).unwrap();
    assert_eq!(bundle.bundle_version, 2);
    let env = bundle.environment.as_ref().expect("environment recorded");
    assert!(!env.agent_command.is_empty());
    assert_eq!(env.rootfs_kind, "host"); // host-system path
    assert!(bundle.verify(None).is_ok(), "env digest check passes");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p proctor-cli run_emits_v2_bundle`
Expected: FAIL — bundle_version is 1 / `environment` is None.

- [ ] **Step 3: Implement** — at each of the three verdict-build sites, replace the inline `env_digest(&[("policy",…),("spec",…),("versions",…)])` with an `Environment` + `env_digest_of`:

```rust
let policy_sha = proctor_verdict::digest::env_digest(&[("policy", policy_yaml.as_bytes())]);
let spec_sha = proctor_verdict::digest::env_digest(&[("spec", &spec_json)]);
let environment = proctor_verdict::bundle::Environment {
    agent_command: agent.to_string(),          // the argv/command string for this run path
    rootfs_kind: rootfs_kind_str.into(),        // "host" or "image" per the RootfsSpec used
    image_ref,                                  // Some(ref) on the ociroot/--image path, else None
    image_digest,                               // Some(resolved sha256) on the image path, else None
    proctor_version: env!("CARGO_PKG_VERSION").into(),
    proctor_commit: env!("PROCTOR_GIT_COMMIT").into(),
    policy_sha256: policy_sha,
    spec_sha256: spec_sha,
};
let digest = proctor_verdict::digest::env_digest_of(&environment);
```

Thread `environment` into the bundle: update `write_bundle(...)` / `Bundle::build(...)` to take and store `Some(environment)` and set `bundle_version = 2`. (For `run-tb`/`run-swebench` image paths, populate `image_ref`/`image_digest` from the resolved `ociroot` image; on host-system paths leave them `None` and set `rootfs_kind = "host"`.)

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p proctor-cli` (and `-p proctor-verdict`)
Expected: PASS, including the corpus/tb/swebench/e2e regressions.

- [ ] **Step 5: Commit**

```bash
git add crates/proctor-cli/src/run.rs crates/proctor-cli/tests/env_binding_test.rs
git commit -m "feat(cli): record + bind the run environment into bundle.json (v2)"
```

---

### Task 6: Update `docs/bundle-spec.md` to v2

**Files:**
- Modify: `docs/bundle-spec.md`

- [ ] **Step 1:** Move agent-command, rootfs/image ref+digest, and Proctor version+commit from "What is bound (and what is not)" → bound; document the recorded `environment` section + the **4th verify check** (env recompute); change `bundle_version` to `2` in the JSON example and the Versioning note; trim the Roadmap to just **agent-binary attestation** + **v0.2 submission-provenance**. No code; prose must match the implemented field names from Task 1.

- [ ] **Step 2: Commit**

```bash
git add docs/bundle-spec.md
git commit -m "docs: bundle-spec v2 — environment is bound + recorded + verifier-checkable"
```

---

### Task 7: Full green + format/lint

- [ ] **Step 1:** `./scripts/dev-setup.sh` (if not already linked)
- [ ] **Step 2:** `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings`
- [ ] **Step 3:** `PROCTOR_REQUIRE_SANDBOX=1 cargo test --workspace` (on a sandbox-capable host) — expect all green; otherwise `cargo test --workspace` with the sandbox tests skipping.
- [ ] **Step 4: Commit** any fmt/clippy fixups.

---

## Self-review notes

- **Spec coverage:** Environment struct (Task 1), env_digest fold (Task 2), 4th verify check (Task 3), build commit (Task 4), 3 run-path wiring + image vs host (Task 5), version bump (Tasks 1+5+6), docs (Task 6), tests for each. v1 back-compat covered (Task 1 + the `if let Some` guard in Task 3).
- **Open implementation detail to confirm at Task 5:** the exact variable holding the agent command and the resolved image ref/digest differ per run path (`run`, `run-tb`, `run-swebench --image`); read each site's locals (the `RootfsSpec`/`ociroot` resolution) before wiring. Host-system paths set `rootfs_kind="host"`, image fields `None`.
- **Signature/verify:** `VerdictBody` is unchanged in shape (still carries `env_digest: String`); only its *value source* changes (now `env_digest_of(&environment)`), so existing signing/verify logic and the v1 round-trip test stay valid.
