# Proctor — Design Spec

**Date:** 2026-06-09
**Status:** Draft for review
**Working name:** Proctor (changeable — "it proctors the agent's exam")

## Summary

Proctor is a Rust harness that runs a coding-agent benchmark task under enforced OS-level
isolation so the agent **physically cannot reach the task's answer** (oracle/test files, the
fix-commit git history, the network), and emits a **signed verdict** plus a **tamper-evident log of
every cheat the agent attempted**.

It targets a documented, growing failure in agent evaluation: the April 2026 UPenn study found
1,000+ validated cheating instances across 9 coding-agent benchmarks (e.g., 415/429 Terminal-Bench
traces were plain filesystem reads of the test oracle; de-cheating dropped the top agent 81.8%→71.7%,
1st→14th). Every documented exploit is a sandboxing / access-control / harness failure — a systems
problem, not an ML problem.

## Goals (v1)

- Run a benchmark task + agent command in an isolated sandbox that blocks the documented
  "reach the answer" cheat classes **by construction** (not by detection).
- Record every **attempted** violation as a tamper-evident timeline.
- Emit a **signed, reproducible verdict**: `{pass/fail, clean/compromised, violations, env digest}`.
- Integrate with **Terminal-Bench** (first adapter) with ~no task rewrite.
- **Prove** correctness by replaying the published cheating corpus: every documented exploit class
  blocked *and* logged.

## Non-goals (deferred — kept clean by the (c) boundary)

- **Grader hardening** against "fool the grader" cheats (print `PASS`, hardcode outputs, mock the
  lib) — phase b.
- **microVM / hypervisor** isolation — overkill for a cheating (non-escape) threat model.
- **SWE-bench / `verifiers` (RL)** adapters — later integrations; the core interface stays
  benchmark-agnostic so these are integrations, not rewrites.
- Horizontal scale / distributed execution; advanced attestation cryptography.
- Non-Linux hosts (benchmarks run on Linux).

## Threat model

- **Adversary:** a capable coding agent taking the *easy path to the answer* during a benchmark
  task. **NOT** a malicious actor attempting kernel escape or host compromise.
- **In scope (v1):** agent reads oracle/test/solution files; reads git history to find the fix
  commit; exfiltrates or looks up the solution over the network; inspects env/processes for leaked
  answers.
- **Out of scope (v1):** grader-fooling (phase b); kernel 0-days / sandbox escapes (wrong threat
  model — Proctor prevents *access by construction*, it does not defend against an attacker holding
  a privilege-escalation exploit).

## Architecture — units (each independently testable)

- **`policy`** — declarative per-task spec: forbidden read-paths (the oracle/test/solution set),
  network egress rules, required repo/git state. Authored as YAML or derived from a benchmark's task
  definition by an adapter. *What it does:* turns "what the agent must not reach" into an enforceable
  policy object. *Depends on:* nothing.
- **`sandbox`** — constructs the isolated run: user / mount / PID / network / IPC / UTS namespaces;
  an overlay rootfs where forbidden paths are **masked** (absent from the agent's mount namespace); a
  network namespace with egress denied or allowlisted; the task repo materialized at the base commit
  with later (fix) history stripped; a seccomp filter in deny-and-audit mode; cgroup resource limits.
  Launches the agent command inside. *Depends on:* `policy`, `monitor`.
- **`monitor`** — captures *attempted* violations during the run (seccomp user-notification / audit
  events: `open()`/`openat()` on a masked path, `connect()` to a blocked host) into a structured,
  ordered violation timeline. *Depends on:* nothing (consumes events from the kernel).
- **`grader`** — runs the benchmark's existing grader in a **separate isolated step** against the
  true oracle the agent never saw. v1 = thin wrapper; robust/anti-fool grading is phase b.
- **`verdict`** — assembles the result: `{pass/fail, clean|compromised, violation timeline, env
  digest, signature}`. Reproducible env hash + signature ⇒ tamper-evident.
- **`adapters/terminal_bench`** — maps a Terminal-Bench task → `policy` + workspace, so operators run
  TB tasks under Proctor with ~no rewrite. *Depends on:* `policy`.
- **`corpus`** — the published cheating trajectories as a replay regression suite; each known exploit
  asserted blocked + logged. Doubles as the credibility artifact.
- **`cli`** — `proctor run --task <dir> --agent <cmd> [--policy <file>]` → `verdict.json` +
  `violations.jsonl`. *Depends on:* all of the above.

## Enforcement mechanics — how each documented cheat dies, by construction

| Documented cheat | How Proctor kills it |
| --- | --- |
| `cat /tests/test_outputs.py`, read oracle/solution files | those paths are not in the agent's mount namespace (masked by the overlay); `open()` → ENOENT, logged |
| `git log` → fix commit → copy the historical patch | repo materialized at the base commit with later history removed; the fix is unreachable |
| `curl`/look up the solution online | network namespace denies egress (allowlist only) |
| read leaked answers from env/process table | minimal env; PID namespace isolation |
| print `PASS` / hardcode outputs / mock the lib | **deferred to phase b** (grader hardening); v1 grades against the true isolated oracle, weakening pre-baked checks, but no robust-grader work in v1 |

## Data flow

`cli` → `sandbox` builds the masked / git-sanitized / netns'd workspace → agent command runs under
seccomp + `monitor` → `grader` runs isolated vs. the true oracle → `verdict` assembled + signed →
`verdict.json` + `violations.jsonl`.

## Error handling — fail closed

If isolation cannot be established (namespace / mount / netns / seccomp setup fails), the run
**errors** rather than proceeding under-protected — an under-isolated run is worse than no run. cgroup
resource limits + bounded timeouts. A run in which the agent attempted a violation is still graded
but flagged `compromised`, with the attempt timeline attached.

## Testing

- **Unit** per module: policy parsing; mount masking (a masked path is unreadable); netns egress
  blocking; git base-commit sanitization (fix unreachable); seccomp filter behavior.
- **Integration (the headline):** the `corpus` replay — each documented exploit class run under
  Proctor, asserted blocked *and* logged.
- **Property:** any read of any path in a task's oracle set is always blocked + logged.

## v1 scope (MVP)

`sandbox` (agent-side isolation) + `monitor` (attempt audit) + signed `verdict` + `policy` +
Terminal-Bench adapter + the `corpus` proof + `cli`. Nothing else.

## Success criterion

Replay the published cheating corpus under Proctor; every documented exploit class is blocked *and*
logged. Then publish: the corpus, the neutralization results, and the harness. That is the
regression suite and the credibility artifact in one — and the wedge to earn a benchmark-operator
pilot.

## Tech decisions

- **Rust core, Linux-only v1.**
- **Build the sandbox directly** (namespaces + seccomp + overlayfs via `nix` / `seccompiler`) rather
  than wrapping a full OCI runtime — it is the systems-credibility centerpiece and gives full control
  over masking/audit semantics; reuse battle-tested *primitive* crates, do not reinvent syscalls.
- **v1 grader = thin isolated wrapper** around the operator's existing grader, run against the true
  oracle the agent never saw.

## Open questions / risks (resolve during planning)

- **Attempt-audit mechanism:** seccomp user-notification vs. ptrace vs. eBPF/LSM. Lean: seccomp
  user-notification (in-process, no eBPF privilege/complexity, fits "prevent + log").
- **In-housing risk:** Terminal-Bench patched its own harness within days of the UPenn study.
  Mitigation: be the *general, adoptable, multi-benchmark* standard + the corpus authority, not a
  one-benchmark patch.
- **Adoption dependency:** the value needs a benchmark operator (or lab eval team) to pilot; the
  corpus result is the wedge to earn that conversation. This is the load-bearing go-to-market risk.
