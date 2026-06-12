# SWE-bench grading in the pinned image (docker-rootfs backend)

**Date:** 2026-06-12
**Instance:** `psf__requests-2317` (SWE-bench Lite)
**Where:** GitHub Actions (`swebench` workflow, `grade-image` job), off the maintainer's machine.
**Reproduce:** `gh workflow run swebench.yml` (dispatch-only).

## What this delivers (the backend — complete + green in CI)

`proctor run-swebench --image` runs the agent **and** grader inside the instance's
**pinned SWE-bench image**, while preserving Proctor's isolation and integrity:

- **Daemonless image → rootfs** (`proctor_sandbox::ociroot`): `podman`/`docker`
  auto-detected; `create` + `export | tar` into an overlay-lower directory. No
  container runtime executes the task — Proctor still runs it in its own
  namespaces.
- **Image as rootfs, gitsan'd repo overlaid at `/testbed`**: the pinned env
  (correct Python/deps) *and* the base-commit, fix-history-stripped repo — so the
  `git log`-mining cheat still dies by construction.
- **Grader in the image**: activates the image's conda env, applies the hidden
  `test_patch`, runs the FAIL_TO_PASS suite, signs the reward into the verdict +
  bundle. DNS works inside the image rootfs (a Host-net resolv.conf fix).

The `grade-image` job is **green**; all three bundles `verify-bundle`. The systems
goal — run a benchmark task inside its pinned container image without giving up
Proctor's isolation, integrity, or signed verdict — is met.

## The result on this instance, and an honest finding

| agent | `pass` | `status` |
| --- | --- | --- |
| honest (gold patch) | true | clean |
| unsolved (no-op) | true | clean |
| cheat (git-mining) | true | **compromised** |

All three "pass" — the same non-discrimination seen on the host path (#6). The
reproducible signal remains the **integrity verdict**: only the cheat is flagged
`compromised`.

**Why `psf__requests-2317` does not discriminate — in any environment we can
construct:** its eight FAIL_TO_PASS tests **pass at the base commit** everywhere we
ran them — host Python 3.9 (#6) and now the pinned image, both online and against a
local stub. Two compounding reasons:

1. **The bug doesn't manifest on the available interpreter.** The fix changes
   `method = builtin_str(method)` → `to_native_string(method)` (so a bytes method
   `b'GET'` isn't stringified to `"b'GET'"`). On the Python in reach,
   `requests.request(b'GET', …)` already succeeds at base — the FAIL_TO_PASS test
   `test_encoded_methods` never failed for a *method* reason in our runs, only ever
   on `ConnectionError`.
2. **The tests are dominated by live `httpbin`.** Seven of the eight hit
   `httpbin(...)` (redirects, posts, basic-auth); their pass/fail tracks
   connectivity and 12 years of `httpbin.org` drift, not the fix.

So even the pinned **image is necessary but not sufficient** for a faithful
resolved/unresolved grade of this instance: SWE-bench's dataset labels these
"fail at base" under its exact 2024 eval conditions, which the image alone (as a
rootfs) doesn't reconstitute.

## What this means

- The **docker-rootfs backend is done and correct** — a real systems capability
  (pinned-env execution + integrity + signed verdict), independent of any one
  instance.
- Demonstrating **faithful discrimination** needs a *deterministic, network-free
  logic-bug instance* whose FAIL_TO_PASS genuinely fails at base and passes after
  the fix in its pinned image. That is an **instance/data choice**, separable from
  the backend — `psf__requests-2317` happens to be a poor discriminator (a method
  bug that doesn't surface on modern Python + a network-heavy test suite).
- Proctor's core claim is unchanged and reproducible: **in-sandbox access cheats
  die by construction and leave a signed, tamper-evident trail** — the cheat run
  is `compromised` here regardless of the grade.

## Honest boundary (restated)

A trustworthy *grade* of an arbitrary SWE-bench instance ultimately requires that
instance's full eval harness conditions; Proctor contributes the isolation, the
pinned-env execution, and the tamper-evident verdict. We document where the grade
is and isn't faithful rather than overclaim it.
