# Proctor — comparison & FAQ

## How Proctor compares

| Approach | What it does | Where it falls short for benchmark integrity |
| --- | --- | --- |
| **Cheat *detection*** (scan traces/output for suspicious behavior) | Flags likely cheating after the fact | A heuristic arms race: capable agents route around detectors. No guarantee, only suspicion. |
| **Per-benchmark harness patches** | Each operator fixes its own harness after an exploit goes public | Reactive, one-benchmark, after-the-fact. No shared, preventive standard; the next exploit class repeats it. |
| **RL-env frameworks / marketplaces** (e.g. `verifiers`) | Author and host eval environments + graders (the content layer) | Not a hardened, by-construction agent↔evaluator isolation runtime. Complementary, not a substitute. |
| **Session replays** | Read-only HTML of a finished run | No enforcement, no isolation, no live grading. A record, not a guard. |
| **Containers (Docker) alone** | Package/runtime for the task environment | A container still ships the test files, git history, and network to the agent unless something hides them. Proctor *uses* a rootfs (incl. a container image) but adds the masking, repo sanitization, cut network, and signed verdict. |
| **microVM / hypervisor isolation** (Firecracker, gVisor, etc.) | Strong host-from-guest security boundary | Solves the *wrong* threat (kernel escape), at boot/emulation cost. It doesn't, by itself, hide the *answer* from the agent or produce a signed integrity verdict. |
| **The published checklists** (UPenn / Berkeley RDI integrity recommendations) | Name the fix ("isolate the agent from the evaluator") + list good practices (canary tokens, privilege separation) | A paper, not a runtime: it doesn't run unprivileged in CI, mask the oracle, or sign a verdict. Proctor is a runnable implementation of that minimum bar, and already asserts the canary-token rec in CI. |
| **Grader-hardening** (Hacker-Fixer loops, Terminal-Bench 2.1 task fixes) | Harden the verifier so `PASS`-greps / mocks / hardcoded outputs fail | The *complementary half*: it fixes the grader; Proctor isolates the agent. Two halves of one trustworthy run (grader-hardening is Proctor's explicit later phase). |
| **Proctor** | Runs the task so the answer is **not reachable** (by construction) + a **signed, tamper-evident** verdict | In-sandbox access cheats only (by design — see "What can't it stop?"). |

**The short version:** everyone else either detects cheating after it happens,
patches one benchmark at a time, or secures the *host* from the guest. Proctor
secures the *answer* from the agent, generically, and signs the result.

## FAQ

**Why prevent instead of detect?**
Detection is a moving target — every detector is a hint to the next agent about
what to avoid, and the study's own authors expect cheating to grow as agents get
more capable. Prevention is a fixed guarantee: the agent cannot read a file that
isn't in its mount namespace, cannot reach a network with no route, cannot
`git log` to a commit that was never transferred. There's nothing to evade.

**Why not just use a VM / microVM?**
Because that's the wrong threat model. The adversary here is a capable agent taking
the *easy path to the answer* during a benchmark — not an attacker trying to escape
the kernel and compromise your host. You don't need a hypervisor to stop
`cat /tests/`; you need correct mounts, a cut network, and a sanitized repo. A
microVM would add boot time and operational cost without addressing the actual
problem (the answer being reachable). If a concrete escape threat ever justifies
it, a microVM rootfs backend is a clean later addition — but it isn't what makes
benchmarks trustworthy.

**How is this different from AISI's Inspect Sandboxing Toolkit?**
Different problem. Inspect and host-isolation sandboxes isolate the *host* from a
potentially-dangerous agent — stopping escape and exfiltration when you run untrusted
evals. Proctor isolates the *answer* from the agent — masking the oracle, git history, and
network so the solution isn't reachable — and signs a tamper-evident integrity verdict.
They compose: run Proctor's answer-isolation inside whatever host-isolation you already use.

**Isn't this just the academic checklist, implemented?**
Partly — and that's the point. The UPenn and Berkeley RDI writeups *name* the fix
("isolate the agent from the evaluator — non-negotiable") and list good practices. Naming a
fix isn't running it. Proctor is the unprivileged, signed, multi-benchmark runtime that
enforces it — and it already implements their canary-token recommendation: every corpus
test plants a random nonce as the "answer" and proves the agent never sees it, asserted in
CI. Building the runtime that makes the checklist real, across benchmarks, is the un-done
hard part.

**Can the agent just bypass the seccomp monitor?**
It can try, and it still gains nothing. **Isolation is enforced by the mounts and
the empty network namespace, not by the monitor.** The seccomp user-notification
monitor is *audit-only* — it records attempts into the signed timeline and always
replies CONTINUE. Even an agent that avoided every audited syscall still can't read
an oracle that isn't in its filesystem. The monitor is the trail, not the wall.

**Can the agent forge or tamper with the verdict?**
No. The agent runs inside the sandbox; the verdict is assembled and **signed
outside it**, with a key the agent never holds, over an environment digest and the
hash-chained violation log. `proctor verify-bundle` recomputes the signature, the
violation chain (bound to the verdict), and the log hashes — any edit, hidden
violation, or wrong key fails verification. With a stable operator key, the
signature also proves *which operator* produced the result.

**What's the performance overhead?**
Small. Proctor uses Linux namespaces, overlayfs, and seccomp user-notification —
no VM boot, no per-syscall emulation. Non-audited syscalls run at native speed; the
monitor only sees the handful on its notify list. Setup is process-fork-fast, not
VM-boot-slow.

**Does it need root?**
No. Proctor runs fully unprivileged via user namespaces. (On some distros you
enable unprivileged user namespaces once, e.g.
`sysctl kernel.apparmor_restrict_unprivileged_userns=0` on Ubuntu 24.04.)

**How do I integrate it with my benchmark?**
Three ways: (1) the generic `proctor run` with a small YAML policy
(forbidden read-paths, network rule, required repo state); (2) a benchmark
**adapter** — `proctor run-tb` (Terminal-Bench / Harbor) and `proctor run-swebench`
run existing tasks unmodified; (3) the **GitHub Action** (`action.yml`), so your
CI runs tasks under Proctor in a few lines and publishes a signed bundle artifact.

**Does it modify my tasks?**
No. Adapters map an existing task definition to a Proctor policy + workspace. A real
Terminal-Bench 2 task and a real SWE-bench instance both run unmodified.

**What can't it stop?** (We're deliberate about this.)
- **Out-of-sandbox answer injection** — a scaffold that puts the answer key in the
  agent's prompt, or a solution compiled into the agent binary. That's a
  submission-provenance problem, not an isolation one.
- **Grader-fooling** — `PASS`-greps, hardcoded outputs for the exact test inputs,
  mocked libraries. Hardening the grader against these is a later phase.
- **Behavioral sandbagging** — an agent that detects it's in a controlled
  environment and acts differently. Proctor guarantees it can't reach the answer;
  it doesn't model the agent's intent.

An integrity tool that overclaims is worse than none, so these are documented
non-goals, not hidden gaps.

**Is SWE-bench fully graded?**
Proctor runs a real SWE-bench instance with fix history stripped and, with
`--grade`, runs the instance's tests through the isolated grader over a host
network in CI — proving the pipeline and the integrity verdict (the git-mining
cheat is blocked + `compromised`). A *faithful* per-instance resolved-grade needs
that instance's pinned environment (specific interpreter/dependency versions), which the
`--image` backend now runs against. See the
[grading report](../reports/2026-06-12-swebench-grading-pinned.md).

**Why Linux-only?**
Coding-agent benchmarks run on Linux, so the harness does too. We don't ship
cross-platform shims for an audience that doesn't exist; the isolation primitives
(namespaces, overlayfs, seccomp) are Linux's.

**Is it production-ready / released?**
v1 is implemented and released (prebuilt v0.1.1 binary + `cargo install`), the full
suite is green in CI on a stock GitHub runner, and the exploit corpus asserts every
documented in-sandbox cheat class is blocked and logged. It's MIT-licensed.

**How can I trust *your* numbers?**
Don't — verify them. The corpus is runnable, the reports are reproducible, and
every run emits a `verify-bundle`-checkable signed artifact. That's the whole point.
