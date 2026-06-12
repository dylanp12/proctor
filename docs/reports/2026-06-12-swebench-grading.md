# SWE-bench grading under Proctor — real instance, in CI

**Date:** 2026-06-12
**Instance:** `psf__requests-2317` (SWE-bench Lite)
**Where:** GitHub Actions (`swebench` workflow), off the maintainer's machine.
**Reproduce:** `gh workflow run swebench.yml` (dispatch-only).

## What this demonstrates

`proctor run-swebench --grade` runs a **real** SWE-bench instance entirely under
Proctor and binds the result into a signed verdict + bundle:

1. The agent runs **isolated** — repo materialized at `base_commit` with fix
   history stripped (`gitsan`), the test/patch paths masked, network denied.
2. A second **isolated grader** then merges the agent's `/testbed`, applies the
   instance's hidden `test_patch` (the oracle the agent never saw), installs the
   dependencies over the **Host grader network** (#2), runs the instance's
   fix-validating test, and writes a reward that is signed into the verdict.

The whole pipeline executes on a stock GitHub runner — the controlled,
off-machine environment established in #4.

## Result matrix

Three agents on the same instance:

| agent | what it does | `pass` (grade) | `status` (integrity) |
| --- | --- | --- | --- |
| **honest** | applies the real gold patch (the reference fix) | true | clean |
| **unsolved** | no-op | true | clean |
| **cheat** | mines git history for the fix + reads the staged answer | true | **compromised** |

The cheat's signed timeline records the block (`run` 27400289888):

```
masked_read /patch.diff           # the staged gold patch — absent from its mount ns
git: fix commit unreachable       # later history stripped from the materialized repo
```

## The honest reading — why this is the project thesis, not a bug

All three agents **"pass" the grade** — including the no-op and the cheat. That is
not a grader defect; it is the point. Two things are true and both are by design:

- **The grading *pipeline* works** end-to-end on a real instance: the hidden test
  patch is applied, requests is installed over the Host network, the real
  upstream test runs, and the reward is bound under the verdict's signature. This
  is the systems contribution.
- **A grade alone is not trustworthy.** Here the fix-validating test is
  *environment-insensitive* (see below), so a naive grader passes the cheating
  agent. **Proctor's tamper-evident isolation is what flags it as
  `compromised`.** Grades are gameable; the integrity verdict is the reliable
  signal — which is the entire reason Proctor exists.

## The environment-fidelity boundary (a non-goal, now confirmed empirically)

`psf__requests-2317` fixes a Python-3 bytes-method bug:
`requests/sessions.py` did `method = builtin_str(method)` (so `b'GET'` →
`"b'GET'"`); the gold patch changes it to `to_native_string(method)`. The base
commit genuinely contains the buggy line (verified), and the gold patch is *not*
present in the unsolved/cheat runs.

Yet on a **generic Python 3.9 runner** the FAIL_TO_PASS test passes at the base
commit too — the bug does not reproduce the way it does in SWE-bench's reference
environment. SWE-bench grades each instance inside a **pinned per-instance Docker
image** (specific interpreter + dependency versions, a local `httpbin` server);
the exact 2014 pass/fail behavior depends on that image. Replicating it is the
**full SWE-bench dataset harness**, which the spec scoped out as a non-goal:

- requests-2.4's suite is dominated by **live `httpbin.org`** calls (e.g.
  `requests.get('https://httpbin.org/redirect/5')`), which are non-deterministic
  in 2026 (12 years of service drift) and order/fixture dependent.
- For a deterministic check we point requests' `httpbin()` helper (via
  `$HTTPBIN_URL`) at a tiny stdlib stub and grade the instance's own
  fix-validating test (`test_encoded_methods`, added by the test patch for
  upstream issue #2316). The *pipeline* is faithful; the *outcome* is not a
  faithful resolved-signal without the pinned interpreter env.

**Conclusion:** Proctor contributes the isolation, the grading pipeline, and the
tamper-evident verdict on a real instance. Faithful per-instance
resolved-grading additionally requires SWE-bench's pinned environment — a clean,
separable add-on (a Docker-image rootfs backend), not a rewrite, and explicitly
out of scope for v1.

## Convergence notes (what it took to run a 2014 suite on a 2026 runner)

Each was a real fix found by iterating in CI; none touched Proctor's isolation
core except one genuine sandbox bug:

1. grader binds `/usr` read-only → install into a **venv**.
2. `pip install -e .` doesn't pull `pytest` → add test deps.
3. **Sandbox bug (fixed):** Host-net `/etc/resolv.conf` is a systemd symlink into
   a `/run` tmpfs that the sandbox recreates empty → DNS dangled. Now the
   resolv.conf stub is recreated for Host-net sandboxes (`mounts.rs`).
4. requests 2.4 needs Python `< 3.10` (`collections.Mapping`) → install 3.9.
5. live-`httpbin.org` flakiness / env-insensitivity → local stub + the
   fix-validating test, with the boundary documented above.
