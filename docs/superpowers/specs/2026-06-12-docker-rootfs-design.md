# Docker-image-rootfs backend — Design Spec

**Date:** 2026-06-12
**Status:** Draft for review
**Follow-on to:** sub-project #6 (SWE-bench grading) — closes its documented
environment-fidelity gap.

## Summary

Add an opt-in **container-image rootfs backend** so `proctor run-swebench --image`
runs the agent **and** grader inside the instance's **pinned SWE-bench image**.
That makes resolved-grading *faithful* — the gold fix resolves the instance and a
no-op does not — which the host-rootfs path provably cannot deliver (in a generic
Python the requests-2.4 bug doesn't reproduce; see the #6 report). Proctor's
integrity guarantee is preserved: the image supplies the *environment*, while
Proctor still overlays its **base-commit, fix-history-stripped repo at `/testbed`**,
so the `git log`-mining cheat still dies by construction.

The image is fetched + unpacked into a plain directory once, on the host, **before**
the sandbox — using `podman` or `docker` (auto-detected, daemonless when podman is
present) — and consumed via the existing `RootfsSpec::Dir` overlay-lower path. The
container tool is only a build-time fetch step; Proctor still executes the task in
its own namespaces, never in a container runtime.

## Context

#6 shipped the SWE-bench grading *pipeline* (isolated grader applies the hidden
`test_patch`, installs deps over the Host network, runs the tests, signs the
reward) and the integrity verdict (the git-mining cheat → `compromised`). Its
honest, empirically-confirmed limit: a *faithful resolved/unresolved grade* needs
the instance's pinned interpreter/dependency environment — exactly what SWE-bench
publishes as a per-instance Docker image. The sandbox already supports a directory
rootfs (`RootfsSpec::Dir`, used as the overlay lower in `mounts.rs::overlay_rootfs`);
`run-tb --image` already turns a Docker image into such a directory via
`proctor-adapter-tb::rootfs` (`docker build`/`create`/`export | tar`). This
sub-project generalizes that to **pulling a published image, daemonlessly**, and
wires it through `run-swebench`.

Verified during design: `docker.io/swebench/sweb.eval.x86_64.psf_1776_requests-2317:latest`
resolves (the SWE-bench `__`→`_1776_` tag convention); `skopeo`/`docker` present on
the dev host, `podman` is the daemonless target on CI.

## Goals

- `proctor_sandbox::ociroot` — a daemonless image→rootfs helper: detect a container
  tool (prefer `podman`, else `docker`), `<tool> create <ref>` (auto-pulls) +
  `<tool> export <cid> | tar -x -C <dest>` → a rootfs directory.
- `run-swebench --image`: fetch the instance's `image`, use `RootfsSpec::Dir` for
  **both** the agent run and the grader, with Proctor's gitsan'd repo overlaid at
  `/testbed`.
- `GradeRequest` gains a `rootfs: RootfsSpec` field so the grader can run in the
  image (existing callers pass `HostSystem` — no behavior change).
- Faithful image-mode grade: apply the hidden `test_patch`, run the **full
  FAIL_TO_PASS** with the image's environment (its conda Python), per-test parse →
  resolved. No host venv, no pip install, no httpbin stub (the image provides it).
- The vendored `psf__requests-2317.json` gains an `image` ref (verified pullable).
- CI: the `swebench` workflow gains an `--image` path (dispatch-only) demonstrating
  the **faithful** matrix: honest resolved, unsolved fail, cheat blocked+fail.
- Report: `docs/reports/…-swebench-grading-pinned.md` (or extend the #6 report).

## Non-goals

- **Replacing the host-rootfs path.** `run-swebench` without `--image` is unchanged
  (the #6 demo + the local integrity report keep working with no container tool).
- **skopeo + umoci / manual OCI layer unpacking.** Rejected during brainstorming:
  `podman`/`docker` `export` yields a flat, whiteout-resolved rootfs tar with the
  primitive we already have — no extra tooling or layer logic.
- **A container *runtime*.** Proctor never runs the task inside docker/podman; the
  tool only fetches+unpacks the image to a directory. Execution stays in Proctor's
  namespaces.
- **Building images.** We pull SWE-bench's published images; we don't build them.
- **Non-x86_64 / instances without a published image** (the field is required for
  `--image`; absent → a clear error, fall back to the host path).
- **Generalizing every SWE-bench instance now.** Proven on the one vendored
  instance; the mechanism is generic.

## Architecture

### `proctor_sandbox::ociroot` (new module)

`proctor-sandbox` already shells to external tools (`gitsan` → `git`); this mirrors
that for containers.

```rust
/// Prefer podman (daemonless); fall back to docker. None if neither is usable.
pub fn container_tool() -> Option<String>;

/// Fetch `image_ref` (auto-pulls) and export its filesystem into `dest` (created).
/// `<tool> create <ref>` -> cid -> `<tool> export <cid> | tar -x -C dest` -> `rm -f`.
pub fn export_image_rootfs(image_ref: &str, dest: &Path) -> Result<(), OciError>;
```

`OciError` (thiserror) distinguishes "no container tool", a failed tool step (with
stderr), and IO. Fail-closed: any failure aborts the run (no silent host-rootfs
fallback when `--image` was explicitly requested).

### `proctor-grader` — grader rootfs

`GradeRequest` gains `pub rootfs: RootfsSpec` (re-exported type). `grade()` uses
`req.rootfs` instead of the hardcoded `RootfsSpec::HostSystem`. All current callers
(`run`, `run_tb`, host-mode `run_swebench`) pass `RootfsSpec::HostSystem` — no
change in behavior. Image-mode `run_swebench` passes `RootfsSpec::Dir(image_rootfs)`.

### `proctor-adapter-swebench` — instance + image grade script

- `Instance`/`SwePlan` gain `image: Option<String>` (the published eval image ref).
- `grade_script_image(test_cmd) -> String` — the image-mode grader script. It
  activates the image's environment (SWE-bench standard: `source
  /opt/miniconda3/etc/profile.d/conda.sh && conda activate testbed`), `cd /testbed`,
  `git apply /oracle/test_patch.diff`, runs `{test_cmd} -v $(cat /oracle/fail_to_pass)`,
  per-test-parses each id `PASSED`, and writes the reward. No pip, no httpbin stub.
  (The exact activation/test invocation is the one in-CI unknown — see Risks — and
  is captured in the instance's `image` test command if it deviates from the
  standard convention.)
- Image-mode `grade_tests` = the **full FAIL_TO_PASS** (faithful in the pinned env),
  not the host-mode pinned single test.

### `proctor-cli::run_swebench(--image)`

```
run_swebench(instance, repo, agent, out, do_grade, use_image)
```

When `use_image`:
1. Require `plan.image` (else error). `ociroot::export_image_rootfs(&plan.image,
   out/rootfs)` → rootfs dir.
2. Agent spec: `rootfs = RootfsSpec::Dir(rootfs_dir)`; `workspace_lower` = the
   gitsan'd repo (overlaid at `/testbed`), network denied, masks as today.
3. Grade (if `--grade`): `GradeRequest { rootfs: RootfsSpec::Dir(rootfs_dir),
   workspace_mount: /testbed, grade_cmd: sh /oracle/grade.sh
   (grade_script_image), network: Host, … }`. The oracle dir holds
   `test_patch.diff` + `fail_to_pass`. **Which ids gate the verdict depends on the
   mode:** image mode writes the **full `plan.fail_to_pass`** (faithful in the
   pinned env); host mode keeps writing `plan.grade_tests` (the pinned single test
   from #6). No `httpbin_stub.py` in image mode.

Without `use_image`: the current host path, unchanged.

CLI: add `--image` to the `RunSwebench` subcommand (mirrors `run-tb --image`).

## Data flow

`--image`: detect tool → `<tool> create+export` the pinned image into `out/rootfs`
→ agent runs in that rootfs with the gitsan'd `/testbed` overlay (net denied) →
grader runs in the same rootfs (Host net), applies `test_patch`, runs FAIL_TO_PASS
in the image's env → per-test parse → signed verdict + bundle. The image's editable
`requests` install resolves to the overlaid `/testbed` (same base content), so it
sees the agent's fix (or its absence).

## Error handling — fail closed

- `--image` with no `image` field, or no container tool, or a failed pull/export →
  the run errors. No silent downgrade to host rootfs when the image was requested.
- Grade failures behave as in #6 (a run that can't be graded is not a pass).
- The agent still gets **no** network and the gitsan'd repo; the image cannot
  reintroduce git history because `/testbed` is overlaid by Proctor's sanitized repo.

## Testing

1. **Local unit:** `container_tool()` prefers podman when both exist; `OciError`
   when neither; `grade_script_image` contains the conda activation, `git apply`,
   `/oracle/fail_to_pass`, per-test `PASSED` parse, and both reward branches;
   `Instance` parses `image`; host-mode `run_swebench` unaffected (existing tests
   green).
2. **Local gated smoke (optional):** if a container tool is present,
   `export_image_rootfs("docker.io/library/alpine:3.19", tmp)` produces a rootfs
   with `/bin/sh` — validates the fetch+unpack mechanism on a tiny image without
   touching SWE-bench's multi-GB one. Skips with a message when no tool.
3. **CI (the proof), dispatch-only:** the `swebench` workflow `--image` path
   installs/uses podman, runs the trio, and shows the **faithful** matrix —
   honest `pass=true reward=1`, unsolved `pass=false reward=0`, cheat
   `status=compromised pass=false`. Download + `verify-bundle` each. Heavy image
   work stays off the maintainer's machine (the standing constraint).

## Open questions / risks

- **Exact image-env test invocation.** The conda env name/path and any
  `HTTPBIN_URL`/eval setup the image expects is the one real unknown — nailed in CI
  (as in #6), captured in `grade_script_image` / an instance override. The image is
  built to make these tests run, so faithful discrimination is expected.
- **Image size / CI disk + time.** SWE-bench eval images are ~1–2 GB; pull+unpack
  is minutes and needs runner disk (~14 GB available). Dispatch-only bounds cost.
- **Container tool on the runner.** GitHub `ubuntu-24.04` ships podman/docker; the
  workflow asserts/install one. Documented prerequisite for `--image`.
- **Tag convention.** `__`→`_1776_` is captured in the instance's explicit `image`
  field (verified resolvable), not derived blindly.
