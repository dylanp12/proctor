# Proctor

> Context for anyone (human or agent) working in this repo. Read this first. It documents not just
> *what* Proctor is, but *why it exists*, *what gap it fills*, and *where its honest limits are*.
> Keep the project honest to all three.

**Status:** v1 implemented (2026-06-09) — M0–M9 complete, all tests green, the exploit
corpus blocks + logs every documented in-sandbox cheat class. Spec:
[`docs/superpowers/specs/2026-06-09-proctor-design.md`](docs/superpowers/specs/2026-06-09-proctor-design.md);
viability review (verdict: build with changes):
[`docs/superpowers/specs/2026-06-09-proctor-viability-review.md`](docs/superpowers/specs/2026-06-09-proctor-viability-review.md);
plan: [`docs/superpowers/plans/2026-06-09-proctor-v1.md`](docs/superpowers/plans/2026-06-09-proctor-v1.md);
usage: [`docs/usage.md`](docs/usage.md). A real Terminal-Bench 2 task now runs end-to-end
(reference solution → clean pass; oracle read → blocked + logged): see
[`docs/reports/2026-06-10-real-task-log-summary.md`](docs/reports/2026-06-10-real-task-log-summary.md)
(reproduce with `corpus/real-tasks/run-report.sh`). A real SWE-bench instance also runs
(`proctor run-swebench`): git-history mining for the fix commit is unreachable, staged
answers masked — see
[`docs/reports/2026-06-10-real-task-swebench.md`](docs/reports/2026-06-10-real-task-swebench.md)
(reproduce with `corpus/real-tasks/run-swebench-report.sh`).
**Productionization (2026-06-11/12) — all 6 sub-projects done:** (1) SWE-bench adapter,
(2) grader network (`GraderNet::Host`), (3) signed run-bundle + `verify-bundle`, (4)
composite `action.yml` + dogfood `demo.yml` (CI now green on `ubuntu-24.04` — it never
was before; proc-mount fix), (5) release & packaging (**v0.1.0** prebuilt binary +
`proctor-version` action fast-path), (6) `proctor run-swebench --grade` runs a real
instance's tests through the isolated grader over the Host network in CI — the grading
pipeline + integrity verdict (grading is now **faithful**; see the docker-rootfs
follow-on below — an early "doesn't discriminate" note in
[`docs/reports/2026-06-12-swebench-grading.md`](docs/reports/2026-06-12-swebench-grading.md)
was a since-fixed grade bug).
**Follow-on — docker-rootfs backend (done) + faithful grading:** `run-swebench
--image` runs the agent+grader inside the instance's pinned SWE-bench image
(daemonless podman/docker fetch via `proctor_sandbox::ociroot` → `RootfsSpec::Dir`),
gitsan'd repo overlaid at `/testbed` (git-mining still dies). **Grading is now
faithful** across three CI jobs — host-stub (requests), pinned-image (requests),
pinned-image (sympy `col_insert`): honest (gold fix) `reward=1`, unsolved `reward=0`,
cheat `compromised`+`reward=0`. (The earlier "doesn't discriminate" finding was a
grade bug — `while read` skipped the newline-less single test id, so reward was
always 1; plus images ship no pytest. Both fixed.) See
[`docs/reports/2026-06-12-swebench-grading-pinned.md`](docs/reports/2026-06-12-swebench-grading-pinned.md).
**Working name:** Proctor (changeable). **Language:** Rust. **Platform:** Linux-only (v1).

> **Verified-record note (do not regress):** the headline numbers are "1,000+
> *harness-level* cheating traces" concentrated in Terminal-Bench 2 + HAL USACO, plus
> ~30 task-level cases; the 415/429 figure is one submission (Pilot). Proctor's honest
> claim is **in-sandbox access cheats die by construction + leave a tamper-evident trail**
> — scaffold-injected answers, in-binary answers, and grader-fooling are documented
> non-goals (see the viability review and `corpus/RESULTS.md`). v1 uses `libseccomp`
> (not `seccompiler`, which lacks USER_NOTIF) and resolved `nix` 0.30.

---

## 1. What Proctor is

Proctor is a harness that runs a coding-agent benchmark task under enforced OS-level isolation, so
the agent **physically cannot reach the task's answer** — the oracle/test files, the fix-commit git
history, or the network — and emits a **signed verdict** plus a **tamper-evident log of every cheat
the agent attempted**.

In one line: **a tamper-proof execution sandbox for trustworthy agent benchmarks.** You hand it a
task, an agent command, and a policy; it gives back a result you can trust and a record of everything
the agent tried to cheat with.

```
proctor run --task ./task --agent "my-agent --solve" --policy ./policy.yaml
# -> verdict.json      { pass: false, status: "compromised", ... }
# -> violations.jsonl  [ {step: 14, kind: "masked_read", path: "/tests/oracle.py"}, ... ]
```

---

## 2. The problem we're solving

**AI coding-agent benchmarks are being gamed, and the numbers that drive billions in model decisions
are quietly wrong.**

The April 2026 University of Pennsylvania study ("cheating-agents", arXiv 2604.11806) found **1,000+
validated cheating instances across 9 major coding-agent benchmarks** (Terminal-Bench 2, SWE-bench,
SWE-rebench, SWE-smith, HAL USACO, CyBench, BountyBench, and more). The exploits are mundane and
devastating:

- reading the test oracle directly — `cat /tests/test_outputs.py` (415 of 429 Terminal-Bench 2
  traces were plain filesystem reads of the answer)
- hardcoding return values for the exact test inputs
- printing `PASS` against a grader that only greps output for the string "PASS"
- running `git log` to find the fix commit and copying the historical patch
- `curl`-ing the solution from the internet (confirmed by Terminal-Bench's own operators)
- replacing an entire library with a mock

The impact is not marginal: removing cheating dropped one top agent from 81.8% → 71.7% pass rate and
**1st → 14th place**. Leaderboards that teams, buyers, and labs treat as ground truth are
contaminated.

**The key insight — and why this is buildable by a systems engineer, not an ML researcher: every one
of these exploits is a sandboxing / access-control / harness failure, not a modeling failure.** The
agent isn't "smart"; the evaluation is leaky. The study's own prescribed fix is pure systems work:
*"isolate the agent from the evaluator — this is non-negotiable."* And it is durable: the authors
conclude cheating "will become more, not less, common as agents become more capable."

That is the problem Proctor exists to make go away — by construction.

---

## 3. The gap, and how Proctor fills it

The demand side is real and growing (frontier labs are investing heavily in RL environments and
eval integrity, with dedicated teams staffing reward-hacking QA). But the supply side has a
specific hole:

| What exists today | What it does | The gap |
| --- | --- | --- |
| `verifiers` / Prime Intellect Environments Hub | OSS framework + marketplace for RL *environments* and graders | Owns the *content/framework* layer; does **not** provide a hardened, by-construction agent↔evaluator isolation runtime |
| `claude-replay` and similar | Static, self-contained HTML *replays* of agent sessions | Read-only artifacts; no enforcement, no isolation, no live grading |
| Per-benchmark harness patches (e.g. Terminal-Bench post-incident) | Each operator ad-hoc-fixes its own harness after an exploit is found | Reactive, one-benchmark, detection-after-the-fact; no shared, general, *preventive* standard |
| The UPenn study itself | Documents the problem rigorously | A paper, not a tool — names the fix but doesn't ship the runtime |

**Proctor fills the un-owned middle: a general, adoptable, benchmark-agnostic execution harness that
prevents the documented cheat classes *by construction* (the agent cannot read what isn't in its
mount namespace, cannot reach a network namespace with no route, cannot `git log` to a commit that
isn't in its repo) and *audits every attempt* (tamper-evident).** Detection is easy and leaky;
prevention-by-construction is the hard, defensible part — and it is squarely systems engineering.

**Two design commitments that define the gap we're filling:**
1. **Prevention, not detection.** We don't watch for cheating and flag it; we build the environment
   so the cheat is impossible, and *log the attempt* as a side effect. ("Detect" is a heuristic arms
   race; "prevent by construction" is a guarantee.)
2. **Benchmark-agnostic standard, not a one-benchmark patch.** The core is a generic "run agent task
   + grade, isolated" contract. Terminal-Bench is the first adapter; SWE-bench and the RL
   (`verifiers`) side are later adapters, not rewrites. This is what makes it a *standard* an operator
   or lab would adopt, rather than a patch they'd in-house and forget.

---

## 4. Architecture (summary — full detail in the spec)

A small workspace of focused, independently-testable units:

- **`policy`** — declarative per-task spec: forbidden read-paths (oracle/test/solution set), network
  egress rules, required repo/git state. YAML, or derived from a benchmark's task definition by an
  adapter.
- **`sandbox`** — builds the isolated run: user / mount / PID / net / IPC / UTS namespaces; an overlay
  rootfs where forbidden paths are **masked** (absent from the agent's mount namespace); a network
  namespace with egress denied or allowlisted; the task repo materialized at the base commit with
  fix-history stripped; a seccomp filter in deny-and-audit mode; cgroup limits. Runs the agent inside.
- **`monitor`** — captures *attempted* violations (seccomp user-notification / audit events) into an
  ordered timeline. The tamper-evidence and the demo.
- **`grader`** — runs the benchmark's existing grader in a separate isolated step against the true
  oracle the agent never saw. v1 = thin wrapper.
- **`verdict`** — assembles `{pass/fail, clean|compromised, violations, env digest, signature}`.
  Reproducible env hash + signature ⇒ tamper-evident.
- **`adapters/terminal_bench`** — maps a Terminal-Bench task → policy + workspace (first adapter).
- **`corpus`** — the published cheating trajectories replayed as a regression suite; each known
  exploit asserted blocked + logged. Doubles as the credibility artifact.
- **`cli`** — `proctor run …` → `verdict.json` + `violations.jsonl`.

### How each documented cheat dies, by construction

| Cheat | Why it fails under Proctor |
| --- | --- |
| read oracle/test/solution files | not in the agent's mount namespace; `open()` → ENOENT, logged |
| `git log` → fix commit → copy patch | repo at base commit, later history removed; fix unreachable |
| `curl` the solution | network namespace denies egress (allowlist only) |
| read leaked answers from env/process | minimal env; PID namespace isolation |
| print `PASS` / hardcode / mock the lib | **phase b** (grader hardening); v1 grades vs. the true isolated oracle |

---

## 5. Threat model (the load-bearing framing — do not drift from it)

- **Adversary:** a capable coding agent taking the *easy path to the answer* during a task. **NOT** a
  malicious actor attempting kernel escape or host compromise.
- This is why v1 builds the sandbox **directly** on namespaces/seccomp/overlayfs rather than reaching
  for a hypervisor: you do not need a microVM to stop `cat /tests/` — you need correct mounts, a cut
  network, and a sanitized repo. VM-grade isolation would be cost without matching threat.
- **In scope (v1):** filesystem access to the answer; git-history leakage; network lookup/exfil;
  env/process leakage.
- **Out of scope (v1):** grader-fooling (phase b); kernel 0-days / sandbox escapes (wrong threat
  model — we prevent *access by construction*; we are not defending against an attacker holding a
  privilege-escalation exploit).

If a change starts defending against escape rather than preventing access, stop — that's a different
(and unjustified) project.

---

## 6. Roadmap (capability milestones, not dates)

Constrained by capability/dependency, not calendar. Each milestone ends at a *provable* claim.

**Phase A — agent-side isolation (v1, the whole near-term focus):**
- **M0** — Cargo workspace scaffold; the crates above as empty modules with their public interfaces;
  CI (fmt + clippy + test) green on an empty tree.
- **M1** — `policy` model + parser. *Prove:* a policy round-trips and rejects malformed specs.
- **M2** — `sandbox` mount masking (user+mount namespaces, overlay). *Prove:* a path in the oracle set
  is unreadable from inside; a normal workspace path is readable.
- **M3** — network isolation (net namespace, egress deny/allowlist). *Prove:* `curl` to a blocked host
  fails inside; an allowlisted host succeeds.
- **M4** — git sanitization (repo at base commit, fix history stripped). *Prove:* `git log` inside
  cannot reach the fix commit.
- **M5** — `monitor` attempt audit (seccomp user-notification). *Prove:* a blocked `open()`/`connect()`
  appears in the violation timeline with the right path/host and step.
- **M6** — `grader` thin wrapper + signed `verdict` (env digest + signature). *Prove:* a verdict
  verifies and a tampered verdict fails verification.
- **M7** — `cli` end-to-end wiring. *Prove:* `proctor run` produces `verdict.json` + `violations.jsonl`.
- **M8** — `adapters/terminal_bench`. *Prove:* a real Terminal-Bench task runs unmodified under Proctor
  and grades correctly.
- **M9 — THE PROOF / launch artifact:** `corpus` replays the published cheating trajectories; assert
  **every documented exploit class is blocked and logged.** This is the regression suite and the
  credibility artifact. Ship: corpus + neutralization results + the harness, with a writeup.

**Phase B — grader hardening (deferred):** robust graders that resist `PASS`-greps, hardcoded
outputs, and mocks; tamper-evident grading the agent cannot pre-bake against. The (c) boundary in the
spec keeps this a clean add-on, not a rewrite.

**Later (only if pulled by real demand):** SWE-bench / `verifiers` (RL training-time) adapters;
optional microVM backend *only if* a concrete threat ever justifies it (it does not today).

---

## 7. Build plan & how we work here

- **TDD, always.** The exploit corpus and the per-module "prove" claims above are the tests. Write
  the failing test (the cheat that should be blocked), then the isolation that blocks it. Use the
  `superpowers:test-driven-development` discipline.
- **Small, focused units.** Each crate/module does one thing with a clear interface (see Architecture).
  If a file grows unwieldy, it's doing too much — split it.
- **Fail closed.** If isolation cannot be established (namespace/mount/netns/seccomp setup fails), the
  run *errors*; never proceed under-protected. An under-isolated run is worse than no run.
- **Reuse primitives, don't reinvent syscalls.** Build the sandbox *assembly* ourselves (that's the
  point), but on battle-tested crates: `nix` (namespaces, mounts, unshare), `libseccomp` (seccomp
  unotify; **not** `seccompiler` — it lacks `SECCOMP_RET_USER_NOTIF`, see the viability review),
  `libc`, `walkdir`. No hand-rolled syscall ABI.
- **Linux-only, and say so loudly.** Benchmarks run on Linux; the harness must too. Dev on Linux/WSL2.
  CI runs on Linux. Don't add cross-platform shims for an audience that doesn't exist.
- **Determinism & reproducibility are features.** The verdict carries an environment digest; the same
  task + agent + policy must produce the same isolation and the same verdict modulo the agent's own
  nondeterminism.
- **Build in the open.** Clean, legible commits; a strong README; the M9 writeup. Adoption is the goal,
  and a benchmark operator evaluates the *code* and the *clarity* as much as the result.

### Conventions

- Rust 2021, a Cargo workspace (one crate per unit, or modules in a core crate + a `cli` + adapters —
  decide at M0 during `writing-plans`).
- `cargo fmt` + `cargo clippy -D warnings` clean; CI enforces both plus `cargo test`.
- Integration tests that need real namespaces run on Linux CI; gate anything requiring privileges
  explicitly and skip-with-a-message when unavailable (mirror Tideline's Redis-test pattern).
- Errors: `thiserror` for typed errors; fail-closed paths return errors, never silent fallbacks.

---

## 8. Success criteria & honest risks

**v1 is "done" when** the corpus replay (M9) shows the covered in-sandbox access-cheat classes
blocked and logged, a real Terminal-Bench task runs unmodified under Proctor, and the result +
harness are published.

**The load-bearing risk is adoption, not technology.** Proctor's value depends on benchmark
operators or lab eval teams actually running evals under it, or building on the bundle format.
Operators have historically patched their own harnesses ad hoc after an exploit goes public
(Terminal-Bench self-patched within days of the UPenn paper), so being the *general, adoptable,
multi-benchmark* standard — with a runnable corpus and a verifiable bundle format — rather than a
one-benchmark patch, is what earns adoption.

**Stay on the systems/isolation core.** If the work drifts toward reward/grader *design*, that's a
different (ML-research) project; Proctor's edge is the isolation + attestation systems work. The
honest scope boundary (see README) is part of the credibility: an integrity tool that overclaims is
worse than none.

---

## 9. Pointers

- **Spec:** [`docs/superpowers/specs/2026-06-09-proctor-design.md`](docs/superpowers/specs/2026-06-09-proctor-design.md)
- **The problem evidence:** UPenn "cheating-agents" study (April 2026, arXiv 2604.11806);
  Terminal-Bench leaderboard-integrity incident (April 2026).
- **The adjacent ecosystem (know it, don't rebuild it):** Prime Intellect `verifiers` + Environments
  Hub (the *content/framework* layer Proctor deliberately does **not** compete with).
- **First integration target:** Terminal-Bench (container-shaped tasks; public integrity incident;
  operators who demonstrably care).
