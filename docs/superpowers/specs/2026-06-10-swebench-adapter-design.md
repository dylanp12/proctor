# SWE-bench adapter + git-history demo — Design Spec

**Date:** 2026-06-10
**Status:** Draft for review
**Sub-project:** #1 of a productionization program (see "Context" below).

## Summary

A second Proctor adapter, `proctor-adapter-swebench`, that maps a SWE-bench
task instance into a Proctor policy + run plan, plus a report that runs **one
real SWE-bench instance** and proves the SWE-bench-specific cheat —
**git-history mining for the fix commit** (the IQuest-Coder pattern in the UPenn
study) — dies by construction, and that staged answer artifacts (the gold patch,
the test files) are masked. This is the first adapter to exercise Proctor's git
sanitization (`sandbox::gitsan`) on real data, which until now is proven only
synthetically.

## Context — where this sits

This is sub-project #1 of a larger program agreed during brainstorming. The
others get their own specs later, in this order: (2) grader network support,
(3) signed run-bundle + `proctor verify-bundle`, (4) GitHub Action / CI wrapper,
(5) release & packaging, and as a stretch (6) full SWE-bench harness integration
that runs in the CI environment from (4), never on a developer's machine. This
spec covers only #1.

## Goals

- `proctor-adapter-swebench`: a pure transformation from a SWE-bench instance to
  a `proctor_policy::Policy` + a run plan, mirroring `proctor-adapter-tb`.
- Materialize the repo at `base_commit` with later (fix) history stripped, via
  `sandbox::gitsan::sanitize_repo_at` — so `git log`/`git fetch` cannot reach the
  fix commit.
- Mask the answer artifacts: the files the `test_patch` touches (the test
  oracle) and the gold `patch` (never materialized for the agent).
- `proctor run-swebench` CLI wiring.
- A report on **one real SWE-bench_Lite instance** proving: (a) git-history
  mining cannot reach the fix commit (the fix sha and fix content are
  unreachable), and (b) reading a masked test path is blocked and logged.

## Non-goals (this sub-project)

- **Graded honest pass on a real instance** — that needs the instance's
  dependency environment (often large), which belongs in the controlled CI
  environment (sub-project #4) and the full-harness integration (#6). The demo
  states this boundary honestly, exactly as the Terminal-Bench report did.
- The official SWE-bench harness, per-instance Docker images, conda envs (→ #6).
- Grader network support (→ #2).

## Background — the SWE-bench instance format

A SWE-bench instance (e.g. from `princeton-nlp/SWE-bench_Lite`) is a JSON record
with the fields this adapter uses:

| Field | Meaning | Adapter use |
| --- | --- | --- |
| `instance_id` | unique id (e.g. `astropy__astropy-12345`) | verdict task_id |
| `repo` | `owner/name` on GitHub | source repo to clone |
| `base_commit` | sha the agent starts from | gitsan target (fix history stripped) |
| `problem_statement` | the issue text | instruction |
| `test_patch` | diff adding/modifying the tests that verify the fix | its target paths → forbidden reads (the oracle) |
| `patch` | the gold solution diff | grader-only; never materialized for the agent |
| `FAIL_TO_PASS`, `PASS_TO_PASS` | test node ids | recorded in the plan for grading (#6) |

In SWE-bench the agent gets the repo at `base_commit` + the problem statement;
the `test_patch` and gold `patch` are applied only at evaluation. So the
dominant on-disk cheat is **git-history mining**: `git log`/`git show` to find
the fix commit and copy its patch. Masking the test/patch paths is defense in
depth for harnesses that stage those artifacts (the Terminal-Bench Pilot
misconfiguration, generalized).

## Architecture

A new workspace crate, `proctor-adapter-swebench` (depends on `proctor-policy`;
the demo/CLI also use `proctor-sandbox`’s gitsan + the existing run pipeline).

### `proctor-adapter-swebench` (pure transformation)

- `Instance` — serde struct for the SWE-bench JSON fields above.
- `load_instance(instance: &Instance) -> SwePlan` and a convenience
  `from_json(&str)`. `SwePlan { policy, instruction, workdir, base_commit,
  test_paths, grade: SweGrade }`.
- **Policy mapping:**
  - `workspace.mount_at = /testbed` (SWE-bench convention).
  - `git.base_commit = instance.base_commit` (drives gitsan).
  - `forbidden.reads` = the file paths the `test_patch` modifies (parsed from the
    unified-diff `+++ b/<path>` headers), each resolved under `/testbed`, plus a
    conventional staging path for the gold patch (`/patch.diff`,
    `/tmp/patch.diff`) in case a scaffold drops it.
  - `network.mode = deny` (SWE-bench solve is offline; deps live in the env).
  - `env.allow = []`.
- **Diff parsing** is a small, self-contained helper (`test_paths(diff: &str) ->
  Vec<PathBuf>`): collect `+++ b/...` targets, ignore `/dev/null`. Unit-tested
  directly.

### Workspace materialization (in the CLI/demo, reusing existing pieces)

- Clone (or be given) the real `repo`, then
  `gitsan::sanitize_repo_at(repo_clone, base_commit, dest)` → the agent's
  workspace at `base_commit` with fix history unreachable.
- The materialized repo IS the workspace lower; the masks (test paths) apply on
  top, as in the generic `proctor run` path.

### CLI: `proctor run-swebench`

`proctor run-swebench --instance <json> --repo <clone-dir> --agent <cmd> --out <dir>`
- loads the instance, gitsan-materializes the repo at `base_commit`, builds the
  spec (masks from `test_paths`, deny network, workdir `/testbed`), runs the
  agent under the sandbox + monitor, and emits the signed verdict + violations
  (same pipeline as `run`/`run-tb`). v1 grading for this command = exit-code of a
  caller-supplied check; the full FAIL_TO_PASS/PASS_TO_PASS grade is #6.

## The demo (one real SWE-bench_Lite instance)

A script `corpus/real-tasks/run-swebench-report.sh` + a written report
(`docs/reports/2026-06-10-real-task-swebench.md`):

1. Fetch one small real instance from `princeton-nlp/SWE-bench_Lite` (instance
   JSON) and a **partial clone** (`--filter=blob:none`) of its `repo` containing
   `base_commit` and the fix commit.
2. Adapter-materialize: gitsan to `base_commit`; derive masks from `test_patch`.
3. **git-history-mining cheat (the headline SWE-bench cheat):** the agent runs
   `git log --all -p`, `git show <fix-sha>`, `git fetch` — assert the **fix commit
   sha is not present** and the fix patch content (a sentinel string from the gold
   `patch`) never appears in the agent's output. Provable with git ops only — no
   test env needed.
4. **staged-answer-read cheat:** simulate the generalized Pilot misconfiguration
   — a scaffold drops the gold patch on disk at `/patch.diff` (a masked path) —
   and the agent tries to read it; assert blocked + logged (`masked_read`),
   verdict `compromised`. (Masking the `test_patch` target paths is additional
   defense-in-depth; the meaningful on-disk answer here is the staged gold patch,
   since SWE-bench applies the real test/patch only at eval time.)
5. The report documents that the **graded honest pass is deferred** to the
   controlled-environment harness (#6), with the same honesty boundary as the TB
   report.

## Testing

- **Unit (no network):** `test_paths` diff parsing (multiple files, renames,
  `/dev/null`); `load_instance` → policy (base_commit set, test paths masked
  under `/testbed`, deny network, workdir `/testbed`); malformed instance JSON
  rejected.
- **Integration (gitsan, synthetic repo):** build a repo with a base commit + a
  "fix" commit carrying a sentinel; map an instance pointing at the base; assert
  the materialized workspace cannot reach the fix sha or the sentinel (mirrors
  the existing `gitsan_test`, driven through the adapter).
- **Demo (real instance):** the script above, gated on network availability;
  asserts the two cheats die. Skips with a message when offline.

## Error handling — fail closed

Consistent with the rest of Proctor: a malformed instance, a `base_commit` not
present in the provided clone (gitsan fetch fails), or any sandbox-setup failure
aborts the run with an error rather than proceeding under-protected.

## Open questions / risks

- **Instance + repo size.** SWE-bench repos are large; a `--filter=blob:none`
  partial clone keeps the demo light. Pick a small-repo instance. Resolve when
  selecting the instance during implementation.
- **Whether to vendor the chosen instance** (like the TB task) for offline
  reproducibility vs. fetch at run time. Lean: vendor the small instance JSON;
  fetch the repo clone at run time (too large to vendor). Decide in the plan.
- **`run-swebench` grading shape.** v1 = exit-code check; the real
  FAIL_TO_PASS/PASS_TO_PASS grade depends on #2 (grader network) and #6 (harness)
  — keep the plan's grade interface forward-compatible with those.
