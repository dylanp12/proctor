# Faithful SWE-bench grading under Proctor (docker-rootfs backend)

**Date:** 2026-06-12
**Instances:** `sympy__sympy-13647`, `psf__requests-2317` (SWE-bench Lite)
**Where:** GitHub Actions (`swebench` workflow), off the maintainer's machine.
**Reproduce:** `gh workflow run swebench.yml` (dispatch-only).

> **Supersedes the earlier "does not discriminate" findings.** Those were caused
> by a grade bug, now fixed (see "The bug that hid everything"). With it fixed,
> Proctor grades SWE-bench instances **faithfully** — a real fix resolves the
> instance, a no-op does not, and a cheat is blocked, flagged, and fails.

## The result — faithful, on two instances, three ways

All three `swebench` jobs are green, and each produces the full matrix:

| job | env | honest (gold fix) | unsolved (no-op) | cheat (git-mining) |
| --- | --- | --- | --- | --- |
| `grade` | host rootfs + local httpbin stub (requests) | `pass=true reward=1` | `pass=false reward=0` | `compromised, pass=false reward=0` |
| `grade-image` | **pinned image** (requests, full FAIL_TO_PASS) | `pass=true reward=1` | `pass=false reward=0` | `compromised, pass=false reward=0` |
| `grade-image-sympy` | **pinned image** (sympy `col_insert`) | `pass=true reward=1` | `pass=false reward=0` | `compromised, pass=false reward=0` |

The bundles `verify-bundle` (e.g. sympy: honest clean/0 violations, unsolved
clean/0, cheat compromised/1). A real fix is graded resolved; no fix isn't; and
the cheat is caught **and** unresolved — the whole thesis, end to end.

## The docker-rootfs backend (what makes the pinned-image runs possible)

`proctor run-swebench --image` runs the agent **and** grader inside the
instance's pinned SWE-bench image, without giving up isolation or integrity:

- **Daemonless image → rootfs** (`proctor_sandbox::ociroot`): `podman`/`docker`
  auto-detected; `create` + `export | tar` into an overlay-lower dir. No container
  runtime executes the task — Proctor still runs it in its own namespaces.
- **Image as rootfs, gitsan'd repo overlaid at `/testbed`**: the pinned env
  (correct Python/deps, e.g. sympy editable-installed at `/testbed`) *and* the
  base-commit, fix-history-stripped repo — so the `git log`-mining cheat still
  dies by construction (the cheat run is `compromised` and unresolved).
- **Grader in the image**: activates the image's conda env (`testbed`), installs
  `pytest` if absent (the SWE-bench images don't ship it), applies the hidden
  `test_patch`, runs the FAIL_TO_PASS suite, and signs the reward into the verdict.
- **Working DNS in the image rootfs** (a Host-net `/etc/resolv.conf` fix) so the
  test bootstrap and any network the suite needs work.

## The bug that hid everything

Earlier runs showed *all three* agents "passing" — which looked like the bug not
manifesting / the env not reproducing. It was neither. The grade script never
actually checked the tests, for two compounding reasons:

1. **`while read` skipped the only test id.** `/oracle/fail_to_pass` is written
   without a trailing newline; `while IFS= read -r id; …` returns non-zero on the
   final newline-less line, so with a single id the loop body **never ran** and the
   `ok` flag stayed `1` → **reward was always 1**, regardless of test results.
   Fixed with `… read -r id || [ -n "$id" ]`.
2. **No `pytest` in the image env.** SWE-bench's `testbed` conda env ships no
   `pytest`, so `python -m pytest` failed; `grade_script_image` now installs it
   (the grader has network).

With both fixed, the grade is faithful — confirmed locally and on the runner. (The
same `while read` fix corrects the host-path grade reported in
[the #6 report](2026-06-12-swebench-grading.md), which now also discriminates.)

## What this establishes

- **Proctor grades SWE-bench faithfully** — both on the host (with a local httpbin
  stub for a network test) and, generally, inside the instance's **pinned image**,
  demonstrated on a network bug (requests) and a pure-logic bug (sympy).
- **Integrity is preserved throughout**: the cheat is `compromised` (git history
  unreachable, masked-answer read logged) *and* unresolved — a naive grader might
  pass it; Proctor does not.
- The docker-rootfs backend generalizes the grade to any instance with a published
  image, while keeping Proctor's isolation + signed, tamper-evident verdict.

## Honest boundary

A faithful grade still depends on the instance's tests being deterministic in the
provided env (the host path uses a local stub for requests' network test; the
pinned image supplies the real env). Proctor contributes the isolation, the
pinned-env execution, and the signed verdict; we verify where the grade is
faithful rather than assume it.
