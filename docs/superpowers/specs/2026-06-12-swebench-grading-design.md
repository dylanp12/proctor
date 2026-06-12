# SWE-bench grading under Proctor — Design Spec

**Date:** 2026-06-12
**Status:** Draft for review
**Sub-project:** #6 (stretch) of the productionization program — the last item.

## Summary

Make `proctor run-swebench` actually **grade** an instance (real pass/reward in
the signed verdict), by running the SWE-bench tests through Proctor's existing
isolated grader over the **Host grader network** (#2). Prove it in CI — off the
maintainer's machine, per the standing constraint — on the real
`psf__requests-2317` with a **solved / unsolved / cheat** trio. This closes the
gap left in sub-project #1, where `run-swebench` materialized + masked the
instance but stopped at `pass: false` ("grading deferred — needs the instance's
dependency env"). The Host grader network is exactly that env.

## Context

Sub-projects #1–#5 are complete. #1 built `proctor-adapter-swebench` +
`run-swebench`: it materializes the repo at `base_commit` with fix history
stripped (`gitsan`), masks the test/patch paths, runs the agent isolated, and
emits the integrity verdict + violation timeline — but **does not grade**
(`run.rs` `run_swebench` hardcodes `pass: false`, `reward: None`). #2 added
`GraderNet::Host` (grader-only full network; the agent never gets it). #3 added
the signed bundle. #4/#5 gave a CI runner that can sandbox + a release.

The grading machinery already exists: `proctor-grader::grade()` runs a
`grade_cmd` in a second isolated sandbox with the agent's merged workspace bound
at `workspace_mount`, the oracle bound read-only at `oracle_mount`, a writable
`/logs`, a configurable `GraderNet`, and a `RewardFile` protocol. `run`/`run_tb`
already `merge_overlay(lower, ws_upper)` to get the agent's result and call
`grade()`. #6 wires the SWE-bench equivalent.

## Goals

- `run-swebench` grades: after the agent runs, merge its `/testbed`, apply the
  instance's `test_patch` as the oracle, install deps over `GraderNet::Host`, run
  the **FAIL_TO_PASS** test IDs (the SWE-bench "resolved" signal), and set
  `verdict.pass` / `reward`.
- Pass criterion: **the test run exits 0** (all FAIL_TO_PASS pass) ⇒ reward 1;
  otherwise reward 0. (CONVERGENCE NOTE: the gate is FAIL_TO_PASS — the
  fix-relevant tests. Full PASS_TO_PASS regression-guarding needs SWE-bench's
  exact pinned test env; in a generic CI runner env 2/133 requests auth tests are
  environment-sensitive — local `pytest-httpbin` makes "off-host" redirects
  same-host — and would fail for *every* agent, giving no signal. The grading
  report records the observed PASS_TO_PASS result transparently.)
- `proctor-adapter-swebench::Instance` carries `FAIL_TO_PASS`, `PASS_TO_PASS`,
  and optional `install_cmd` / `test_cmd` (pytest defaults).
- Enrich the vendored `psf__requests-2317.json` with the **authoritative**
  FAIL_TO_PASS / PASS_TO_PASS / version from the SWE-bench Lite dataset.
- `.github/workflows/swebench.yml` runs the trio in CI and uploads three bundles.
- A report (`docs/reports/…-swebench-grading.md`) with the pass/fail/blocked matrix.

## Non-goals

- **The full SWE-bench dataset harness.** This grades *one real instance* under
  Proctor; generalizing per-repo install/test specs to all instances (the
  "embedded specs" option) is future work, called out honestly.
- **Per-test log parsing / partial credit.** A binary pass via the combined test
  run's exit code is the verdict; SWE-bench has no partial credit.
- **Running grading locally.** The heavy `pip install` + `pytest` runs in CI
  only (standing constraint). Local tests are unit-level.
- **The official `swebench` Python/Docker harness** (rejected in brainstorming —
  it grades in its own container, bypassing Proctor's grader + signed verdict).
- **An agent that actually solves the issue.** The honest agent applies the known
  gold patch to *exercise the grader*; it demonstrates the grader, not problem-
  solving (the same convention as the Terminal-Bench reference-solution demo).

## Architecture

### `proctor-adapter-swebench` (extend)

```rust
#[derive(Debug, Deserialize)]
pub struct Instance {
    pub instance_id: String,
    pub repo: String,
    pub base_commit: String,
    pub problem_statement: String,
    pub test_patch: String,
    #[serde(default)] pub patch: String,            // gold (masked from agent)
    #[serde(default, rename = "FAIL_TO_PASS")] pub fail_to_pass: Vec<String>,
    #[serde(default, rename = "PASS_TO_PASS")] pub pass_to_pass: Vec<String>,
    #[serde(default)] pub install_cmd: Option<String>,
    #[serde(default)] pub test_cmd: Option<String>,
}
```

`SwePlan` gains `test_patch`, `fail_to_pass`, `pass_to_pass`, `install_cmd`,
`test_cmd` (carried through `load_instance`). Defaults when absent:
`install_cmd = "python -m pip install -e ."`,
`test_cmd = "python -m pytest -p no:cacheprovider -q"`.
The existing masking of `test_paths(test_patch)` + staged-answer drops is unchanged.

### `proctor-cli::run_swebench` (add grading)

Grading is gated behind a new **`--grade`** flag (default off). This is what keeps
the local integrity report (`run-swebench-report.sh`) from ever `pip install`-ing
on the maintainer's machine: it runs `run-swebench` *without* `--grade`, so the
heavy grade step only happens in CI where the workflow passes `--grade`.

After the agent run + violation finalize, when `--grade` is passed and
`fail_to_pass` is non-empty:

1. `merge_overlay(&lower, &session.join("ws_upper"), &merged)` → agent's `/testbed`.
2. Build the **oracle dir** `out/swebench-oracle/`:
   - `test_patch.diff` ← `plan.test_patch`
   - `test_ids` ← `fail_to_pass`, one per line (the resolved signal; see the
     convergence note on PASS_TO_PASS env-fidelity)
   - `grade.sh` ← generated (below)
3. `grade(&GradeRequest {`
   `workspace: merged, workspace_mount: "/testbed",`
   `oracle: out/swebench-oracle, oracle_mount: "/oracle",`
   `grade_cmd: "sh /oracle/grade.sh",`
   `protocol: RewardFile { path: "/logs/verifier/reward.json" },`
   `network: GraderNet::Host, … }, &self_invoker())`
4. `verdict.pass = gr.pass; reward = gr.reward`.

Without `--grade`, or when `fail_to_pass` is empty (e.g. the adapter unit
fixtures), skip grading and keep `pass: false` (today's behavior) — no regression,
and no network/pip locally.

### The generated grade script (`grade.sh`)

```sh
set -e
cd /testbed
git apply /oracle/test_patch.diff
{install_cmd} >/tmp/install.log 2>&1 || { echo "install failed"; cat /tmp/install.log; }
mkdir -p /logs/verifier
ids="$(tr '\n' ' ' < /oracle/test_ids)"
if {test_cmd} $ids; then
  printf '{"reward":1}\n' > /logs/verifier/reward.json
else
  printf '{"reward":0}\n' > /logs/verifier/reward.json
fi
```

`{install_cmd}` / `{test_cmd}` are interpolated from the plan. The agent's patch
is already in `/testbed` (it edited the files); the script adds only the test
patch (the oracle) on top, then installs + runs. `GraderNet::Host` gives `pip`
egress to PyPI on the runner.

### Data — enrich the vendored instance

`corpus/real-tasks/swebench/psf__requests-2317.json` gains the authoritative
`FAIL_TO_PASS`, `PASS_TO_PASS`, and `version` from the **SWE-bench Lite** dataset
(fetched during the build, not guessed — Task verifies the IDs resolve to real
tests). `install_cmd`/`test_cmd` are added only if the pytest defaults don't go
green in CI for requests.

### CI — `.github/workflows/swebench.yml`

`workflow_dispatch` + `push: { branches: [main] }`, `runs-on: ubuntu-24.04`:
checkout → build proctor (or reuse `./action.yml` with `proctor-version`) →
shallow-fetch requests at `base_commit` into a clone dir → run the trio via
`proctor run-swebench` (the grader uses the runner's network) → upload the three
bundles. The honest agent's gold-patch command and the cheat agent's git-mining
command are produced by a small `scripts/assemble-swebench-demo.sh` (mirrors the
TB assembler: prints `honest=…` / `unsolved=…` / `cheat=…`), shared with
`corpus/real-tasks/run-swebench-report.sh`.

## Data flow

agent (isolated, net denied, history stripped) → merged `/testbed` → grader
(Host net): apply test_patch → `pip install` → run FAIL_TO_PASS+PASS_TO_PASS →
exit 0? → reward 1/0 → signed verdict `{pass, reward, status, violations}` →
bundle.

## Error handling — fail closed

- `grade()` surfacing a sandbox error → `run_swebench` errors (no verdict).
- A missing/garbled reward file → `GradeError::Reward` → run errors (existing
  behavior); a run that can't be graded is not silently a pass.
- `install` failure is logged inside the grader and the test run then fails →
  reward 0 (an uninstallable env grades as fail, never as pass).
- The agent never gets `GraderNet::Host`; only the grader does (unchanged #2
  invariant; the CLI sets the agent's network from the policy = Deny).

## Testing / verification

1. **Local unit (no pip/pytest):**
   - adapter parses `FAIL_TO_PASS`/`PASS_TO_PASS` (rename), defaults
     `install_cmd`/`test_cmd`, and `SwePlan` carries them.
   - grade-script generation interpolates the commands + emits the
     `git apply` / reward-branch shape (string assertions).
   - existing swebench/adapter tests stay green (empty `fail_to_pass` ⇒ no grading).
2. **CI end-to-end (the proof):** dispatch `swebench.yml`; watch green; download
   the three bundles; `verify-bundle` each and confirm the matrix —
   honest `pass=true reward=1 status=clean`, unsolved `pass=false reward=0
   status=clean`, cheat `pass=false status=compromised` with a `masked_read` /
   unreachable-history violation. Confirm the grader actually installed + ran
   (log shows pytest collecting the FAIL_TO_PASS id).
3. **Report:** `docs/reports/2026-06-12-swebench-grading.md` with the matrix +
   the honest substitutions, reproducible via the CI workflow.

## Open questions / risks

- **Exact requests install/test invocation.** The pytest defaults may need a
  tweak (e.g. a test extra) to go green for requests at `base_commit`; nailed in
  CI during the build, captured via the instance's `install_cmd`/`test_cmd`.
- **FAIL_TO_PASS authority.** The IDs must match the dataset exactly or grading
  is meaningless; the build sources them from SWE-bench Lite and verifies they
  resolve to collected tests (pytest `--collect-only`) before trusting a pass.
- **Old Python / requests at base_commit.** requests `psf__requests-2317`
  predates modern packaging; `pip install -e .` on a current runner Python may
  need `setuptools`/a compatible interpreter — handled via `install_cmd` in CI.
- **Runner network for grading.** `GraderNet::Host` uses the runner's egress to
  PyPI — available on GitHub runners; this is the intended off-machine env.
