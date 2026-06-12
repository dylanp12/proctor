# GitHub Action / CI wrapper — Design Spec

**Date:** 2026-06-11
**Status:** Draft for review
**Sub-project:** #4 of the productionization program.

## Summary

Ship a reusable **composite GitHub Action** (`action.yml`) that runs a Proctor
task under isolation on a CI runner, verifies the resulting bundle, and uploads
it as a build artifact — plus a **dogfood workflow** (`demo.yml`) that exercises
the action on *both* a tiny synthetic task and the real Terminal-Bench task
(`log-summary-date-ranges`), publishing verifiable `bundle.json` artifacts. This
turns "the sandbox runs off-machine" into a continuously-proven, downloadable
fact, and establishes the controlled GitHub-runner environment that sub-project
#6 (full SWE-bench harness) will run in — off the maintainer's personal machine.

## Context

Sub-project #4 of the program (done: #1 SWE-bench adapter, #2 grader network, #3
signed run-bundle; remaining after this: #5 release & packaging, #6 full
SWE-bench harness).

**Prerequisite, just landed:** CI had **never** been green (13/13 red) because the
agent sandbox died mounting `/proc` on the `ubuntu-24.04` runner
(`handshake: proc: EPERM`). Root-caused to a kernel-strictness difference in the
`mount_too_revealing` check and fixed in `e9547e8` (defer the old-root detach
until after pid1 mounts `/proc`). CI is now green and the full sandbox suite runs
on a stock GitHub runner. That fix is what makes this sub-project — and #6 —
possible; without an off-machine runner that can actually sandbox, a CI wrapper
has nothing to wrap.

A prebuilt binary / `cargo install` path is explicitly **sub-project #5**, so for
now the Action **builds Proctor from source**.

## Goals

- **`action.yml`** at the repo root: a composite action that, given the args for
  a `proctor` run, performs the full pipeline on a Linux runner — host-deps →
  toolchain → (optional clone) → build → run → `verify-bundle` → upload the
  bundle — and exposes `pass` / `verdict-status` / `violations` / `bundle-path`
  as step outputs so a caller can gate on integrity.
- **`.github/workflows/demo.yml`**: a dogfood workflow that uses `./` (the
  composite action) to run, on the runner:
  - a **synthetic** task (agent writes the answer *and* attempts to read a masked
    `/oracle` → `pass=true, status=compromised, 1 violation`), and
  - the **real Terminal-Bench** task, both an **honest** run (reference solution
    → clean pass) and a **cheat** run (reads the masked `/tests` oracle → blocked
    + logged).
  Each run uploads its own verified `bundle.json` artifact.
- **`scripts/assemble-tb-task.sh`**: the task-assembly half of the existing
  `run-report.sh`, extracted so both the local report and the CI workflow build
  the identical runnable task (no drift). `run-report.sh` is refactored to source
  it.
- **`scripts/action-smoke.sh`**: a local mirror of the action's core (synthetic
  task → `proctor run` → assert `bundle.json` exists and `verify-bundle` exits 0)
  so the logic is validated on the dev host before any push.
- **CI hygiene:** bump `actions/checkout@v4 → v5` (the green run flagged the
  Node-20 deprecation) in `ci.yml`; use `checkout@v5` + `upload-artifact@v4` in
  the new workflow/action.

## Non-goals

- **Prebuilt binary / `cargo install` / release tarball** — that is sub-project
  #5. #4 builds from source (with a `proctor-ref` clone option for external use).
- **Docker-image action** — rejected: needs an image build/publish pipeline
  (overlaps #5) and a privileged-enough runner for the nested sandbox; premature.
- **Running #6's full SWE-bench harness now** — #4 only *creates the environment*
  it will run in. The SWE-bench dogfood stays at the current `run-swebench`
  (no grading) demo; wiring real test bootstraps is #6.
- **Non-Linux runners** — Proctor is Linux-only by charter.
- **Cross-run build caching beyond cargo's own incremental build** — noted as a
  future optimization (`Swatinem/rust-cache`); not required for #4.

## Architecture

### `action.yml` — composite action (repo root)

```yaml
name: "Proctor run"
description: "Run a benchmark task under Proctor isolation and publish the signed bundle."
inputs:
  run-args:      { description: "args passed to `proctor` (e.g. 'run --task ./t --agent \"...\" --policy ./p.yaml'); do NOT include --out", required: true }
  out:           { description: "output directory", default: "proctor-out" }
  signing-seed:  { description: "ed25519 seed hex; set from a secret. Empty => ephemeral key", default: "" }
  pubkey:        { description: "if set, verify-bundle --pubkey <hex>", default: "" }
  artifact-name: { description: "uploaded artifact name", default: "proctor-bundle" }
  upload:        { description: "upload the bundle artifact", default: "true" }
  proctor-ref:   { description: "if set, clone dylanp12/proctor@<ref> and build it; else build from working-directory", default: "" }
  working-directory: { description: "path to the proctor source checkout (when proctor-ref is empty)", default: "." }
outputs:
  pass:           { value: ... }
  verdict-status: { value: ... }
  violations:     { value: ... }
  bundle-path:    { value: ... }
runs:
  using: "composite"
  steps: [ ... ]
```

Steps (all `shell: bash`, `set -euo pipefail`):

1. **host deps** — `sudo apt-get update && sudo apt-get install -y libseccomp-dev`;
   `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`.
2. **toolchain** — `uses: dtolnay/rust-toolchain@stable` (composite actions may
   nest `uses:` steps).
3. **resolve source** — if `proctor-ref` is non-empty:
   `actions/checkout@v5` with `repository: dylanp12/proctor`, `ref: ${proctor-ref}`,
   `path: .proctor-src`, and `PROCTOR_SRC=.proctor-src`; else
   `PROCTOR_SRC=${working-directory}`. Export `PROCTOR_SRC` to `$GITHUB_ENV`.
4. **build** — in `$PROCTOR_SRC`: `./scripts/dev-setup.sh && cargo build --release -p proctor-cli`.
   (A repeated invocation in the same job is a near-instant cargo no-op.) Binary =
   `$PROCTOR_SRC/target/release/proctor`; export `PROCTOR_BIN` to `$GITHUB_ENV`.
5. **run** — `PROCTOR_SIGNING_SEED` is set from the `signing-seed` input *only if
   non-empty* (passed via env, never argv, so it can't land in logs). The command
   is invoked with `eval` —
   `eval "\"$PROCTOR_BIN\" ${run-args} --out \"${out}\""` — **not** a bare
   `$run-args`: an agent value like `--agent "sh /workspace/solve.sh"` is
   multi-word and quoted, and a plain unquoted expansion would word-split it into
   broken args. `eval` honours the quoting in `run-args`. (Safe here: `run-args`
   is a trusted CI input authored by the workflow, not third-party data.) The
   action owns `--out` so it knows where the bundle lands; it runs from the
   workflow's working dir so relative task paths in `run-args` resolve.
6. **verify** — `"$PROCTOR_BIN" verify-bundle --bundle "${out}/bundle.json"`
   plus `--pubkey ${pubkey}` when set. A failure fails the job.
7. **outputs** — `jq` (preinstalled) reads `${out}/verdict.json`:
   `pass`, `status` (→ `verdict-status`), `violations_count` (→ `violations`),
   and `bundle-path=${out}/bundle.json` into `$GITHUB_OUTPUT`.
8. **upload** — when `upload == 'true'`: `actions/upload-artifact@v4` with
   `name: ${artifact-name}` and an **explicit file list** —
   `${out}/bundle.json`, `${out}/verdict.json`, `${out}/violations.jsonl`.
   **Never** the whole `out/` dir: an ephemeral run writes `out/signing-seed.hex`
   (the private key), which must not be published.

**Security invariants (load-bearing):**
- `signing-seed` is the **private** signing key. It is provided only via a GitHub
  Actions secret, consumed as an env var, and never echoed or placed in argv.
- The upload step lists files explicitly to guarantee `signing-seed.hex` (present
  for ephemeral-key runs) is never uploaded.
- The action fails closed: any non-zero step (build, sandbox setup, run,
  `verify-bundle`) fails the job. A runner that cannot isolate makes CI **red**,
  never a silent pass.

### `.github/workflows/demo.yml` — dogfood

```yaml
name: demo
on:
  push: { branches: [main] }
  workflow_dispatch:
permissions: { contents: read }
```

- **job `synthetic`** (`runs-on: ubuntu-24.04`): `checkout@v5` → a `run:` step
  writes the synthetic task inline (the `bundle_e2e_test` fixture: `solve.sh`
  does `cat /oracle/x 2>/dev/null; echo 42 > /workspace/a`; `oracle/expected.txt`
  = `42`; `grade.sh` diffs; `policy.yaml` masks `/oracle`) → `uses: ./` with
  `run-args: run --task ./task --agent "sh /workspace/solve.sh" --policy ./policy.yaml`,
  `out: out-synth`, `artifact-name: proctor-bundle-synthetic`,
  `signing-seed: ${{ secrets.PROCTOR_SIGNING_SEED }}`.
- **job `terminal-bench`** (`runs-on: ubuntu-24.04`): `checkout@v5` →
  `run: ./scripts/assemble-tb-task.sh "$RUNNER_TEMP/tb"` (assembles the runnable
  task + generates logs via the deterministic python generator + writes the
  offline grader) → `uses: ./` **twice**:
  - honest: `run-args: run-tb --task "$RUNNER_TEMP/tb/task" --agent "<honest b64 cmd>"`,
    `out: out-tb-honest`, `artifact-name: proctor-bundle-tb-honest`.
  - cheat: same task, `--agent "<cheat b64 cmd>"`, `out: out-tb-cheat`,
    `artifact-name: proctor-bundle-tb-cheat`.
  The assemble step (`id: assemble`) prints `honest=<cmd>` / `cheat=<cmd>` to
  stdout, which the workflow appends to `$GITHUB_OUTPUT`; each action invocation
  then sets `run-args: run-tb --task … --agent "${{ steps.assemble.outputs.honest }}"`.
  Because those agent commands are **base64-encoded one-liners**
  (`echo <b64> | base64 -d | bash`, already how `run-report.sh` defines them),
  the values are quote-free and embed inside the double-quoted `--agent` argument
  without escaping — and `run-report.sh` consumes the same two lines, so CI and
  the local report run byte-identical agents.

Both jobs inherit `PROCTOR_SIGNING_SEED` from the optional repo secret; absent →
ephemeral key (bundle self-consistent, just not operator-attributable). The
workflow header comments how to set the secret + publish the pubkey.

### `scripts/assemble-tb-task.sh` (extracted from `run-report.sh`)

Pure assembly, no runs. Args: `$1` = output base dir. It performs the current
`run-report.sh` steps: copy vendored `task.toml` / `instruction.md` /
`environment/*` / `solution/solve.sh` / `tests/test_outputs.py` into
`$OUT/task`; generate `$OUT/task/workspace/logs` via the deterministic generator;
write the offline `tests/test.sh` grader; and emit the honest + cheat agent
command strings (the existing base64 one-liners) to stdout as
`honest=<cmd>` / `cheat=<cmd>` lines (machine-readable for both callers).
`run-report.sh` is refactored to `source`/call it, then do its two runs + report
exactly as today (its output and the published report are unchanged).

### `scripts/action-smoke.sh`

Builds (or reuses) the release binary, creates the synthetic task in a
`mktemp -d`, runs `proctor run … --out`, asserts `bundle.json` exists and
`proctor verify-bundle` exits 0; non-zero + message on any failure. Run locally
before pushing; safe to also invoke from CI later.

## Data flow

`demo.yml` job → (assemble task, for TB) → composite action: host-deps →
toolchain → [clone @ proctor-ref] → `cargo build --release` → `proctor <run-args>
--out OUT` (sandboxed; emits `OUT/bundle.json`) → `proctor verify-bundle` → parse
`verdict.json` to outputs → `upload-artifact` (bundle.json + verdict.json +
violations.jsonl). Result: a green run and downloadable, independently
`verify-bundle`-checkable bundles for the synthetic + honest + cheat runs.

## Error handling — fail closed

- Every `run:` step uses `set -euo pipefail`; any non-zero exit fails the job.
- `proctor` run failure (incl. sandbox-setup failure) → non-zero → job red.
- `verify-bundle` failure → job red, naming the failed check.
- A mis-set `PROCTOR_SIGNING_SEED` (malformed) makes `resolve_signer` error
  loudly (existing #3 behavior) rather than silently minting a fresh key.

## Testing / verification

Composite actions and workflows can't be meaningfully unit-tested in Rust; the
verification is integration-on-the-real-platform plus a local logic mirror:

1. **Local:** `scripts/action-smoke.sh` green; `scripts/assemble-tb-task.sh`
   produces a task that `run-report.sh` still runs to the same honest-clean /
   cheat-blocked result (the refactor is behavior-preserving — the published
   report is unchanged).
2. **CI:** push `demo.yml`; **watch the real GitHub Actions run** (`gh run watch`)
   until both jobs are green. Then **download all three artifacts and
   `proctor verify-bundle` each locally** — confirming the synthetic bundle is
   `pass=true, status=compromised, violations=1`, the honest bundle is a clean
   pass, and the cheat bundle is `status=compromised` with a `masked_read` of
   `/tests/...` in its timeline. This is the deliverable proof.
3. **Regression:** `ci.yml` stays green after the `checkout@v5` bump; the
   `run-report.sh` refactor leaves `corpus/real-tasks/run-report.sh` output
   intact.

## Open questions / risks

- **External reuse builds from source (~1 min first build)** until #5 ships a
  prebuilt binary; `proctor-ref` makes external use possible *today*. Accepted.
- **Actions minutes:** `demo.yml` runs on `push: main` + `workflow_dispatch`
  only (not on every PR — `ci.yml` already covers PRs), bounding cost.
- **Optional operator key:** without the `PROCTOR_SIGNING_SEED` secret the
  bundles use ephemeral keys (still self-verifying). Documented, not required.
- **TB task runtime deps:** the offline grader needs `python3` (preinstalled on
  `ubuntu-24.04`); no extra install expected. If a future task needs more, add an
  install step in that job, not the action.
- **`mount_too_revealing` on other runner images:** the `e9547e8` fix matches
  what `unshare --mount-proc` relies on and is expected to hold across runner
  kernels; if a future image regresses, the failure is loud (job red at `proc`),
  not silent.
