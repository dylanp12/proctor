# Docker-image-rootfs backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `proctor run-swebench --image` runs the agent + grader inside the instance's pinned SWE-bench image (daemonless podman/docker fetch → overlay lower), with Proctor's gitsan'd repo overlaid at `/testbed`, for faithful resolved-grading.

**Architecture:** A new `proctor_sandbox::ociroot` fetches+unpacks an image to a directory (`<tool> create` + `export | tar`, tool auto-detected). `GradeRequest` gains a `rootfs` field so the grader can run in that image. `run-swebench --image` wires it for both agent and grader; a `grade_script_image` activates the image's conda env and gates on the full FAIL_TO_PASS. The host path is unchanged.

**Tech Stack:** Rust (proctor-sandbox/grader/adapter-swebench/cli), podman/docker (fetch only), GitHub Actions.

---

## Spec

`docs/superpowers/specs/2026-06-12-docker-rootfs-design.md`.

## File Structure

- **Create `crates/proctor-sandbox/src/ociroot.rs`** — `container_tool()` + `export_image_rootfs()` + `OciError`.
- **Modify `crates/proctor-sandbox/src/lib.rs`** — declare `pub mod ociroot;`.
- **Create `crates/proctor-sandbox/tests/ociroot_test.rs`** — gated alpine smoke.
- **Modify `crates/proctor-grader/src/lib.rs`** — `GradeRequest.rootfs`; use it in `grade()`.
- **Modify `crates/proctor-grader/tests/*.rs`** + **`crates/proctor-cli/src/run.rs`** — set `rootfs` at every `GradeRequest`.
- **Modify `crates/proctor-adapter-swebench/src/lib.rs`** — `Instance/SwePlan.image`; `grade_script_image()`.
- **Modify `crates/proctor-cli/src/main.rs`** — `--image` flag.
- **Modify `crates/proctor-cli/src/run.rs`** — `run_swebench(use_image)` + image branch.
- **Modify `corpus/real-tasks/swebench/psf__requests-2317.json`** — `image` ref.
- **Modify `.github/workflows/swebench.yml`** — `--image` path (dispatch-only).
- **Create `docs/reports/2026-06-12-swebench-grading-pinned.md`** — faithful matrix.

## Pre-flight

- [ ] **Step 0: Clean tree on `main`, spec committed**

Run: `git -C . status -sb && git log --oneline -1`
Expected: clean; top commit is the docker-rootfs spec.

---

### Task 1: `proctor_sandbox::ociroot` — daemonless image → rootfs

**Files:**
- Create: `crates/proctor-sandbox/src/ociroot.rs`
- Modify: `crates/proctor-sandbox/src/lib.rs`
- Create: `crates/proctor-sandbox/tests/ociroot_test.rs`

- [ ] **Step 1: Declare the module**

In `crates/proctor-sandbox/src/lib.rs`, add after `pub mod net;`:
```rust
pub mod ociroot;
```

- [ ] **Step 2: Write `ociroot.rs`**

```rust
//! Daemonless container-image -> rootfs directory (an overlay lower for
//! RootfsSpec::Dir). Prefers podman (rootless/daemonless), falls back to docker.
//! Used to materialize a benchmark's pinned image BEFORE sandboxing — Proctor
//! never runs a container runtime; this only fetches + unpacks the image.

use std::path::Path;
use std::process::{Command, Stdio};

#[derive(Debug, thiserror::Error)]
pub enum OciError {
    #[error("no container tool found (need podman or docker on PATH)")]
    NoTool,
    #[error("{tool} {step} failed: {stderr}")]
    Tool {
        tool: String,
        step: String,
        stderr: String,
    },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// First working container CLI, preferring the daemonless one.
pub fn container_tool() -> Option<String> {
    for t in ["podman", "docker"] {
        let ok = Command::new(t)
            .arg("version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return Some(t.to_string());
        }
    }
    None
}

/// Fetch `image_ref` (auto-pulls) and export its filesystem into `dest` (created).
/// `<tool> create <ref>` -> cid -> `<tool> export <cid> | tar -x -C dest`.
pub fn export_image_rootfs(image_ref: &str, dest: &Path) -> Result<(), OciError> {
    let tool = container_tool().ok_or(OciError::NoTool)?;
    let create = Command::new(&tool).args(["create", image_ref]).output()?;
    if !create.status.success() {
        return Err(OciError::Tool {
            tool,
            step: "create".into(),
            stderr: String::from_utf8_lossy(&create.stderr).into(),
        });
    }
    let cid = String::from_utf8_lossy(&create.stdout).trim().to_string();
    std::fs::create_dir_all(dest)?;
    let export = Command::new(&tool)
        .args(["export", &cid])
        .stdout(Stdio::piped())
        .spawn()?;
    let tar = Command::new("tar")
        .arg("-x")
        .arg("-C")
        .arg(dest)
        .stdin(export.stdout.unwrap())
        .output()?;
    let _ = Command::new(&tool).args(["rm", "-f", &cid]).output();
    if !tar.status.success() {
        return Err(OciError::Tool {
            tool,
            step: "export|tar".into(),
            stderr: String::from_utf8_lossy(&tar.stderr).into(),
        });
    }
    Ok(())
}
```

- [ ] **Step 3: Write the gated smoke test**

Create `crates/proctor-sandbox/tests/ociroot_test.rs`:
```rust
//! Exercises the real fetch+unpack on a tiny image. Gated: only runs with
//! PROCTOR_OCI_SMOKE=1 (needs a container tool + network), so the default
//! `cargo test` / CI stays hermetic.
use std::path::Path;

#[test]
fn export_alpine_rootfs_has_sh() {
    if std::env::var("PROCTOR_OCI_SMOKE").is_err() {
        eprintln!("SKIP: set PROCTOR_OCI_SMOKE=1 to run the image smoke test");
        return;
    }
    let Some(tool) = proctor_sandbox::ociroot::container_tool() else {
        eprintln!("SKIP: no container tool");
        return;
    };
    eprintln!("using container tool: {tool}");
    let d = tempfile::tempdir().unwrap();
    proctor_sandbox::ociroot::export_image_rootfs("docker.io/library/alpine:3.19", d.path())
        .expect("export alpine rootfs");
    assert!(
        Path::new(&d.path().join("bin/sh")).exists(),
        "rootfs should contain /bin/sh"
    );
}
```

- [ ] **Step 4: Build + run the smoke locally**

Run: `cargo build -p proctor-sandbox 2>&1 | tail -3 && PROCTOR_OCI_SMOKE=1 cargo test -p proctor-sandbox --test ociroot_test 2>&1 | tail -8`
Expected: compiles; the test prints `using container tool: docker` (or podman) and passes (`/bin/sh` found). If no tool/network, it SKIPs — then at minimum confirm it compiles and the default (no-env) run skips.

- [ ] **Step 5: Commit**

```bash
git add crates/proctor-sandbox/src/ociroot.rs crates/proctor-sandbox/src/lib.rs crates/proctor-sandbox/tests/ociroot_test.rs
git commit -m "feat(sandbox): ociroot — daemonless image->rootfs (podman/docker)"
```

---

### Task 2: `GradeRequest.rootfs` — let the grader run in an image

**Files:**
- Modify: `crates/proctor-grader/src/lib.rs`
- Modify: `crates/proctor-grader/tests/grade_test.rs`, `crates/proctor-grader/tests/grade_net_test.rs`
- Modify: `crates/proctor-cli/src/run.rs` (3 call sites)

- [ ] **Step 1: Add the field to `GradeRequest`**

In `crates/proctor-grader/src/lib.rs`, add to `GradeRequest` (after `network`):
```rust
    /// rootfs for the grader sandbox (HostSystem, or an image overlay-lower Dir)
    pub rootfs: RootfsSpec,
```
(`RootfsSpec` is already imported in this file.)

- [ ] **Step 2: Use it in `grade()`**

In `grade()`, change `rootfs: RootfsSpec::HostSystem,` (the line in the `SandboxSpec { … }`) to:
```rust
        rootfs: req.rootfs.clone(),
```

- [ ] **Step 3: Build to find every broken call site**

Run: `cargo build --workspace 2>&1 | grep -E "missing field .rootfs|error\[" | head`
Expected: errors at the `GradeRequest { … }` constructions (grader tests + run.rs lines 150/316/470).

- [ ] **Step 4: Fix grader test call sites**

Run: `grep -rn "GradeRequest {" crates/proctor-grader/tests`
In each `GradeRequest { … }` there, add `rootfs: proctor_sandbox::spec::RootfsSpec::HostSystem,`. (Import already available via `proctor_sandbox`; if the test lacks it, fully-qualify as shown.)

- [ ] **Step 5: Fix run.rs call sites for `run` and `run_tb`**

In `crates/proctor-cli/src/run.rs`, in the `GradeRequest { … }` at the `run` site (~150) and the `run_tb` site (~316), add:
```rust
            rootfs: RootfsSpec::HostSystem,
```
(The `run_swebench` site ~470 is handled in Task 4 — for now add `rootfs: RootfsSpec::HostSystem,` there too so the workspace compiles.)

- [ ] **Step 6: Build + test the grader**

Run: `cargo build --workspace 2>&1 | tail -3 && cargo test -p proctor-grader 2>&1 | grep -E "test result|error" | head`
Expected: builds; grader tests pass (rootfs defaults to HostSystem — no behavior change).

- [ ] **Step 7: Commit**

```bash
git add crates/proctor-grader/src/lib.rs crates/proctor-grader/tests crates/proctor-cli/src/run.rs
git commit -m "feat(grader): GradeRequest.rootfs (default HostSystem) so the grader can run in an image"
```

---

### Task 3: Adapter — `image` field + `grade_script_image`

**Files:**
- Modify: `crates/proctor-adapter-swebench/src/lib.rs`

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module:
```rust
    #[test]
    fn instance_carries_image_ref() {
        let j = INSTANCE.replace(
            r#""version": "2.9""#,
            r#""version": "2.9", "image": "docker.io/swebench/sweb.eval.x86_64.psf_1776_requests-2317:latest""#,
        );
        let plan = from_json(&j).unwrap();
        assert_eq!(
            plan.image.as_deref(),
            Some("docker.io/swebench/sweb.eval.x86_64.psf_1776_requests-2317:latest")
        );
    }

    #[test]
    fn image_grade_script_activates_env_and_parses_fail_to_pass() {
        let s = grade_script_image("python -m pytest -p no:cacheprovider");
        assert!(s.contains("conda activate testbed"), "{s}");
        assert!(s.contains("git apply /oracle/test_patch.diff"), "{s}");
        assert!(s.contains("python -m pytest -p no:cacheprovider -v"), "{s}");
        assert!(s.contains("/oracle/fail_to_pass"), "{s}");
        assert!(s.contains("PASSED"), "{s}");
        assert!(s.contains(r#"{"reward":1}"#), "{s}");
        assert!(s.contains(r#"{"reward":0}"#), "{s}");
        assert!(!s.contains("httpbin_stub"), "image mode uses the image's env, not the stub");
    }
```

- [ ] **Step 2: Run — verify failure**

Run: `cargo test -p proctor-adapter-swebench instance_carries_image 2>&1 | tail -5`
Expected: compile error — `SwePlan` has no field `image` / `grade_script_image` not found.

- [ ] **Step 3: Add `image` to `Instance` and `SwePlan`**

In `Instance`, after the `grade_tests` field, add:
```rust
    #[serde(default)]
    pub image: Option<String>,
```
In `SwePlan`, after `grade_tests`, add:
```rust
    /// published per-instance image ref (for run-swebench --image); None = host mode
    pub image: Option<String>,
```
In `load_instance`'s `Ok(SwePlan { … })`, add:
```rust
        image: inst.image.clone(),
```

- [ ] **Step 4: Add `grade_script_image`**

After `grade_script`, add:
```rust
/// Image-mode grade script: the pinned SWE-bench image already has the test env,
/// so we activate its conda env (SWE-bench standard: /opt/miniconda3 env `testbed`)
/// and run the FULL FAIL_TO_PASS faithfully — no host venv, no pip, no httpbin stub.
/// Run under bash (conda activate needs it). Resolved iff every FAIL_TO_PASS PASSED.
pub fn grade_script_image(test_cmd: &str) -> String {
    format!(
        "set -e\n\
. /opt/miniconda3/etc/profile.d/conda.sh\n\
conda activate testbed\n\
cd /testbed\n\
git apply /oracle/test_patch.diff\n\
mkdir -p /logs/verifier\n\
ids=\"$(tr '\\n' ' ' < /oracle/fail_to_pass)\"\n\
{test_cmd} -v $ids >/tmp/test.out 2>&1 || true\n\
ok=1\n\
while IFS= read -r id; do [ -z \"$id\" ] && continue; grep -qF \"$id PASSED\" /tmp/test.out || ok=0; done < /oracle/fail_to_pass\n\
if [ \"$ok\" = 1 ]; then printf '{{\"reward\":1}}\\n' >/logs/verifier/reward.json; \
else printf '{{\"reward\":0}}\\n' >/logs/verifier/reward.json; tail -25 /tmp/test.out; fi\n"
    )
}
```

- [ ] **Step 5: Run the adapter tests**

Run: `cargo test -p proctor-adapter-swebench 2>&1 | grep -E "test result|FAILED" | head`
Expected: all pass (existing + 2 new).

- [ ] **Step 6: Commit**

```bash
git add crates/proctor-adapter-swebench/src/lib.rs
git commit -m "feat(swebench): instance image ref + grade_script_image (conda env, full FAIL_TO_PASS)"
```

---

### Task 4: CLI — `run-swebench --image`

**Files:**
- Modify: `crates/proctor-cli/src/main.rs`
- Modify: `crates/proctor-cli/src/run.rs`

- [ ] **Step 1: Add `--image` to the subcommand**

In `main.rs`, in `RunSwebench { … }`, add after `grade: bool,`:
```rust
        /// run the agent + grader inside the instance's pinned image (RootfsSpec::Dir)
        #[arg(long)]
        image: bool,
```

- [ ] **Step 2: Thread it through the match arm**

In `main.rs`, change the `RunSwebench { instance, repo, agent, out, grade } => match run::run_swebench(&instance, &repo, &agent, &out, grade)` to destructure `image` and pass it:
```rust
        Cmd::RunSwebench {
            instance,
            repo,
            agent,
            out,
            grade,
            image,
        } => match run::run_swebench(&instance, &repo, &agent, &out, grade, image) {
```
(Leave the `Ok`/`Err` body unchanged.)

- [ ] **Step 3: Add `use_image` to `run_swebench` + build the rootfs**

In `run.rs`, change the signature to add `use_image: bool,` as the last param. Then, immediately after `let plan = …from_json…?;` and `std::fs::create_dir_all(out)?;`, compute the rootfs:
```rust
    // image mode: fetch the instance's pinned image into an overlay-lower rootfs
    let rootfs = if use_image {
        let image = plan
            .image
            .as_deref()
            .context("run-swebench --image requires an `image` ref in the instance")?;
        let rootfs_dir = out.join("rootfs");
        let _ = std::fs::remove_dir_all(&rootfs_dir);
        proctor_sandbox::ociroot::export_image_rootfs(image, &rootfs_dir)
            .map_err(|e| anyhow::anyhow!(e))
            .context("fetch instance image rootfs")?;
        RootfsSpec::Dir(rootfs_dir)
    } else {
        RootfsSpec::HostSystem
    };
```

- [ ] **Step 4: Use that rootfs for the agent spec**

In the agent `SandboxSpec { … }` in `run_swebench`, change `rootfs: RootfsSpec::HostSystem,` to:
```rust
        rootfs: rootfs.clone(),
```

- [ ] **Step 5: Make the grade step image-aware**

In the grade block (`if do_grade && !plan.grade_tests.is_empty() {`), change the gate + body to handle both modes. Replace the gate line with:
```rust
    let grade_ids = if use_image { &plan.fail_to_pass } else { &plan.grade_tests };
    let (pass, reward) = if do_grade && !grade_ids.is_empty() {
```
Then, where the oracle files are written, branch:
```rust
        std::fs::write(oracle.join("test_patch.diff"), &plan.test_patch)?;
        std::fs::write(oracle.join("fail_to_pass"), grade_ids.join("\n"))?;
        let grade_cmd = if use_image {
            std::fs::write(
                oracle.join("grade.sh"),
                proctor_adapter_swebench::grade_script_image("python -m pytest -p no:cacheprovider"),
            )?;
            "bash /oracle/grade.sh".to_string()
        } else {
            std::fs::write(oracle.join("httpbin_stub.py"), SWEBENCH_HTTPBIN_STUB)?;
            std::fs::write(
                oracle.join("grade.sh"),
                proctor_adapter_swebench::grade_script(&plan.install_cmd, &plan.test_cmd),
            )?;
            "sh /oracle/grade.sh".to_string()
        };
```
(Delete the old unconditional `httpbin_stub.py` + `grade.sh` writes and the old `grade_cmd: "sh /oracle/grade.sh".into()`.) Then set the `GradeRequest` fields:
```rust
                grade_cmd,
                ...
                rootfs: rootfs.clone(),
```
(Replace the `rootfs: RootfsSpec::HostSystem,` added as a stopgap in Task 2 Step 5 with `rootfs: rootfs.clone(),`.)

- [ ] **Step 6: Build + confirm host path unchanged**

Run: `cargo build -p proctor-cli 2>&1 | tail -3 && cargo clippy -p proctor-cli --all-targets -- -D warnings 2>&1 | tail -2 && cargo test -p proctor-cli --test swebench_test 2>&1 | grep -E "test result|error" | head`
Expected: builds, clippy clean, `swebench_test` passes (host path, `--image` absent → unchanged).

- [ ] **Step 7: Full suite + fmt**

Run: `cargo fmt --all && cargo test --workspace 2>&1 | grep -E "test result: FAILED|error\[" | head; echo done`
Expected: only `done` (no failures; the gated ociroot smoke skips without the env var).

- [ ] **Step 8: Commit**

```bash
git add crates/proctor-cli/src/main.rs crates/proctor-cli/src/run.rs
git commit -m "feat(cli): run-swebench --image (agent+grader in the pinned image, gitsan /testbed overlay)"
```

---

### Task 5: Instance image ref

**Files:**
- Modify: `corpus/real-tasks/swebench/psf__requests-2317.json`

- [ ] **Step 1: Verify the ref resolves, then add it**

Run:
```bash
REF=docker.io/swebench/sweb.eval.x86_64.psf_1776_requests-2317:latest
skopeo inspect --raw "docker://$REF" >/dev/null 2>&1 && echo "RESOLVES: $REF" || echo "CHECK REF"
python3 - <<PY
import json
F="corpus/real-tasks/swebench/psf__requests-2317.json"
d=json.load(open(F)); d["image"]="$REF"
json.dump(d, open(F,"w"), indent=2); open(F,"a").write("\n"); print("image ->", d["image"])
PY
```
Expected: `RESOLVES: …` then `image -> docker.io/swebench/…`. (If `skopeo` is absent, the ref was already verified during design; proceed.)

- [ ] **Step 2: Commit**

```bash
git add corpus/real-tasks/swebench/psf__requests-2317.json
git commit -m "data(swebench): pin psf__requests-2317 eval image ref for --image grading"
```

---

### Task 6: CI — image-mode grading path

**Files:**
- Modify: `.github/workflows/swebench.yml`

- [ ] **Step 1: Add an image-mode job**

Append this job to `.github/workflows/swebench.yml` (under `jobs:`, sibling to `grade`):
```yaml
  grade-image:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v5
      - name: host deps
        run: |
          sudo apt-get update
          sudo apt-get install -y libseccomp-dev git podman
          sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
      - uses: dtolnay/rust-toolchain@stable
      - run: ./scripts/dev-setup.sh
      - run: cargo build --release -p proctor-cli
      - name: fetch requests at base_commit + assemble agents
        id: prep
        shell: bash
        run: |
          set -euo pipefail
          INST=corpus/real-tasks/swebench/psf__requests-2317.json
          REPOURL="https://github.com/$(jq -r .repo "$INST").git"
          BASE="$(jq -r .base_commit "$INST")"
          CLONE="$RUNNER_TEMP/requests"
          mkdir -p "$CLONE"; git -C "$CLONE" init -q
          git -C "$CLONE" fetch --depth 1 -q "$REPOURL" "$BASE"
          DESC="$(git ls-remote "$REPOURL" HEAD | cut -f1)"
          echo "clone=$CLONE" >> "$GITHUB_OUTPUT"
          ./scripts/assemble-swebench-demo.sh "$INST" "$DESC" >> "$GITHUB_OUTPUT"
      - name: grade in the pinned image (honest / unsolved / cheat)
        shell: bash
        env:
          BIN: ${{ github.workspace }}/target/release/proctor
          INST: corpus/real-tasks/swebench/psf__requests-2317.json
          CLONE: ${{ steps.prep.outputs.clone }}
          HONEST: ${{ steps.prep.outputs.honest }}
          UNSOLVED: ${{ steps.prep.outputs.unsolved }}
          CHEAT: ${{ steps.prep.outputs.cheat }}
        run: |
          set -euo pipefail
          for kind in honest unsolved cheat; do
            case $kind in honest) A="$HONEST";; unsolved) A="$UNSOLVED";; cheat) A="$CHEAT";; esac
            echo "== $kind =="
            "$BIN" run-swebench --image --grade --instance "$INST" --repo "$CLONE" \
              --agent "$A" --out "out-img-$kind" || true
            echo "--- $kind verdict ---"; cat "out-img-$kind/verdict.json"; echo
          done
      - name: verify bundles
        shell: bash
        run: |
          set -euo pipefail
          for kind in honest unsolved cheat; do
            target/release/proctor verify-bundle --bundle "out-img-$kind/bundle.json"
          done
      - uses: actions/upload-artifact@v4
        with:
          name: swebench-image-bundles
          path: |
            out-img-honest/bundle.json
            out-img-unsolved/bundle.json
            out-img-cheat/bundle.json
          if-no-files-found: error
```

- [ ] **Step 2: Validate YAML**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/swebench.yml')); print('swebench.yml OK')"`
Expected: `swebench.yml OK`.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/swebench.yml
git commit -m "ci(swebench): grade-image job — run-swebench --image trio in the pinned image"
```

---

### Task 7: Run in CI and converge the image-env invocation

**Files:** possibly `crates/proctor-adapter-swebench/src/lib.rs` (the conda activation in `grade_script_image`) and/or the instance.

- [ ] **Step 1: Push and dispatch the image path**

Run:
```bash
git push origin main
gh workflow run swebench.yml -R dylanp12/proctor
sleep 8
gh run list --workflow=swebench.yml -R dylanp12/proctor --limit 1 --json databaseId -q '.[0].databaseId'
```
Expected: a run id. (Both `grade` and `grade-image` jobs run on dispatch.)

- [ ] **Step 2: Watch + inspect the image matrix**

Run: `id=<from Step 1>; gh run watch "$id" -R dylanp12/proctor --interval 30 >/dev/null 2>&1; gh run view "$id" -R dylanp12/proctor --json conclusion -q '.conclusion'; gh run view "$id" -R dylanp12/proctor --log | grep -E '== (honest|unsolved|cheat) ==|"pass"|"reward"|"status"|conda activate|No such file|passed|failed,' | sed 's/.*2026[^ ]* //' | head -40`
Expected target: honest `pass=true reward=1`, unsolved `pass=false reward=0`, cheat `pass=false status=compromised`.

- [ ] **Step 3: Converge if the env activation is off**

If honest isn't `reward=1` (e.g. `conda: command not found`, wrong env name, or `No such file`): the image's conda path/env name differs. Inspect it once:
```bash
podman create docker.io/swebench/sweb.eval.x86_64.psf_1776_requests-2317:latest >/tmp/cid 2>/dev/null || docker create ... 
# or, lighter: read the image config env/entrypoint
skopeo inspect docker://docker.io/swebench/sweb.eval.x86_64.psf_1776_requests-2317:latest | jq '.Env, .Config' 2>/dev/null || true
```
Adjust the activation line in `grade_script_image` (e.g. a different env name than `testbed`, or `source /opt/miniconda3/bin/activate testbed`), commit, push, re-dispatch, re-watch. This is the one expected in-CI unknown (per the spec).

- [ ] **Step 4: Download + verify the image bundles**

Run:
```bash
id=$(gh run list --workflow=swebench.yml -R dylanp12/proctor --limit 1 --json databaseId -q '.[0].databaseId')
rm -rf /tmp/img && gh run download "$id" -n swebench-image-bundles -D /tmp/img
for k in honest unsolved cheat; do printf '%s: ' "$k"; target/release/proctor verify-bundle --bundle "/tmp/img/out-img-$k/bundle.json"; done
```
Expected: all three `bundle OK`; the verdicts show the faithful matrix.

---

### Task 8: Report + docs

**Files:**
- Create: `docs/reports/2026-06-12-swebench-grading-pinned.md`
- Modify: `README.md`, `CLAUDE.md`, `docs/usage.md`

- [ ] **Step 1: Write the report**

Create `docs/reports/2026-06-12-swebench-grading-pinned.md`: the goal (faithful grading via the pinned image), the matrix (honest resolved / unsolved fail / cheat compromised+fail) with actual verdict snippets, how the integrity guarantee is kept (gitsan'd `/testbed` overlaid over the image), the daemonless fetch (podman/docker), and "reproduce via `gh workflow run swebench.yml`". Contrast with the host-path #6 report (which the pinned image now supersedes for fidelity).

- [ ] **Step 2: Update usage + README + CLAUDE**

In `docs/usage.md` `proctor run-swebench` section, document `--image` (runs agent+grader in the instance's pinned image for faithful grading; needs podman/docker; the gitsan'd `/testbed` overlay keeps the git-mining block). In `README.md` and `CLAUDE.md`, note that `--image` closes #6's environment-fidelity gap (faithful resolved-grading), linking the new report.

- [ ] **Step 3: Commit + push**

```bash
git add docs/reports/2026-06-12-swebench-grading-pinned.md README.md CLAUDE.md docs/usage.md
git commit -m "docs(swebench): pinned-image faithful grading report + --image docs"
git push origin main
```

---

## Self-Review

**1. Spec coverage:**
- `ociroot` daemonless image→rootfs (podman/docker auto-detect) → Task 1. ✅
- `GradeRequest.rootfs` + `grade()` uses it → Task 2. ✅
- `run-swebench --image` (agent + grader in image, gitsan `/testbed` overlay) → Task 4. ✅
- `grade_script_image` (conda env, full FAIL_TO_PASS, no stub/pip) → Task 3. ✅
- instance `image` ref → Tasks 3 (field) + 5 (data). ✅
- host path unchanged (mode branch; `--image` default false) → Task 4 Steps 5–6. ✅
- CI dispatch-only image job → Task 6; converge + verify → Task 7. ✅
- Report + docs → Task 8. ✅
- Fail-closed (`--image` with no ref / no tool / failed pull errors) → Task 4 Step 3. ✅

**2. Placeholder scan:** No TBD/TODO. Task 7 Step 3 is an explicit converge-from-real-output step (the spec's one acknowledged unknown), with concrete inspect commands — not an unfilled placeholder. The host-path stopgap `rootfs: RootfsSpec::HostSystem` in Task 2 Step 5 is explicitly replaced in Task 4 Step 5.

**3. Type/contract consistency:**
- `RootfsSpec` (HostSystem | Dir(PathBuf)) is the type added to `GradeRequest` and used in `run_swebench`'s `rootfs` binding; both `grade()` and the agent spec consume it. ✅
- `export_image_rootfs(&str, &Path) -> Result<(), OciError>` matches the call in Task 4 Step 3 (mapped to anyhow). ✅
- `grade_script_image(&str) -> String` matches the call `grade_script_image("python -m pytest -p no:cacheprovider")`. ✅
- image mode writes `plan.fail_to_pass`; host mode writes `plan.grade_tests` (the `grade_ids` binding) — matches the spec's mode split. ✅
- `Instance.image: Option<String>` ↔ `SwePlan.image: Option<String>` ↔ `plan.image.as_deref()` in run.rs. ✅
```
