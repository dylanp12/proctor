# Why Proctor

**An answer-isolating execution harness for AI coding-agent benchmarks — it turns a run
into a signed, independently verifiable integrity bundle.**

If you run a coding-agent benchmark, your leaderboard is probably wrong — not
because the models are mis-measured, but because the agents are reaching the
answer instead of solving the task. Proctor isolates that answer from the agent
by construction, and signs a tamper-evident record of covered forbidden-access attempts.

---

## The problem: benchmarks are being gamed

AI coding-agent benchmarks drive billions of dollars in model decisions, hiring,
and procurement. They are also leaky.

In April 2026, UPenn researchers (Stein, Brown, Hassani, Naik & Wong) documented
[widespread cheating on popular agent benchmarks](https://debugml.github.io/cheating-agents/) —
**1,000+ validated harness-level cheating traces** across nine major coding-agent
benchmarks, concentrated in Terminal-Bench 2 and HAL USACO, plus dozens of task-level
cases (method paper: *Detecting Safety Violations Across Many Agent Traces*,
[arXiv 2604.11806](https://arxiv.org/abs/2604.11806)). The exploits are mundane and
devastating:

- **Read the test oracle directly** — `cat /tests/test_outputs.py`. In one
  Terminal-Bench submission, **415 of 429** successful traces were plain
  filesystem reads of the answer.
- **Mine git history** — `git log` / `git show` to the fix commit, then copy the
  historical patch.
- **`curl` the solution** from the internet (confirmed by Terminal-Bench's own
  operators).
- **Pre-write the grader's reward file**, hardcode return values for the exact
  test inputs, or replace a library with a mock.

The impact is not marginal — and it's worth being precise about which cheat caused it.
The study's most dramatic single result, one top agent falling from **81.8% → 71.7%** and
**1st → 14th**, came from *scaffold-injected answer keys* (`AGENTS.md`) — a cheat that
arrives from **outside** the sandbox. That class is a documented non-goal here and the
target of [Proctor's v0.2 provenance work](#roadmap); the access cheats listed above —
oracle reads, git-mining, `curl`, reward-file pre-writes — are the ones Proctor kills by
construction today. Either way, leaderboards that teams, buyers, and labs treat as ground
truth are contaminated, and the authors conclude this "will become more, not less, common
as agents become more capable."

## Why it happens: it's a sandboxing failure, not a modeling one

Here's the key insight. **Every one of those exploits is an
access-control / harness failure.** The agent isn't doing something clever; the
evaluation simply left the answer reachable. The study's own prescribed fix is
pure systems work: *"isolate the agent from the evaluator — this is
non-negotiable."*

That means the fix doesn't require a smarter grader or an ML breakthrough. It
requires an execution environment where the answer is **not present** for the
agent to reach.

## The gap: nobody ships the isolation runtime

| What exists today | What it does | The gap |
| --- | --- | --- |
| RL-environment frameworks & marketplaces (e.g. `verifiers`) | The *content/grader* layer for eval environments | Not a hardened, by-construction agent↔evaluator isolation runtime |
| Agent-session replays | Read-only HTML artifacts of a run | No enforcement, no isolation, no live grading |
| Per-benchmark harness patches | Each operator ad-hoc-fixes its own harness *after* an exploit is found | Reactive, one-benchmark, detection-after-the-fact — no shared standard |
| The UPenn study | Documents the problem rigorously | A paper, not a tool |

Proctor fills the un-owned middle: **a general, adoptable, benchmark-agnostic
execution harness that prevents the documented cheat classes by construction and
audits every attempt.**

## How Proctor fixes it — by construction

You hand Proctor a task, an agent command, and a policy. It runs the agent inside
fresh, fully-unprivileged Linux namespaces (user / mount / PID / network / IPC /
UTS) where the answer was never placed:

| Cheat | Why it dies under Proctor |
| --- | --- |
| read the oracle/test/solution files | not in the agent's mount namespace — `open()` returns ENOENT |
| `git log` → fix commit → copy patch | repo is materialized at the base commit; later history was never transferred |
| `curl` the solution | the network namespace is empty — egress fails (allowlist mode bridges only approved hosts) |
| read leaked answers from env / other processes | minimal scrubbed environment; PID-namespace isolation |

This is the load-bearing distinction: **prevention, not detection.** We don't
watch for cheating and flag it (a heuristic arms race the agents win as they get
smarter). We build the environment so the cheat is *impossible*, and record the
attempt as a side effect.

```
proctor run --task ./task --agent "my-agent --solve" --policy ./policy.yaml
# -> verdict.json      { "pass": true, "status": "compromised", "violations_count": 1, ... }
# -> violations.jsonl  { "step": 8, "kind": "masked_read", "path": "/oracle/answer.txt", ... }
```

That `status: compromised` is the point: the agent may have produced a passing
answer *and* tried to cheat — and now you can see it, signed and ordered.

## Trust the result: signed and tamper-evident

The grader runs in a **second** isolated sandbox against the true oracle the agent
never saw. The verdict is an **ed25519 signature over RFC-8785 canonical JSON**
plus an environment digest, and every run emits a portable **`bundle.json`** — the
signed verdict, the full violation timeline (hash-chained), and agent-log hashes,
all bound under one signature. Anyone can `proctor verify-bundle` it; with a
stable operator key, the signature proves *which operator* produced the result.

A leaderboard backed by verifiable Proctor bundles is one you can audit — not one
you have to take on faith.

## A standard, not a one-off patch

Proctor's core is a generic "run agent task + grade, isolated" contract.
Benchmarks plug in as **adapters**:

- **Terminal-Bench** (Harbor format) — `proctor run-tb`. A real Terminal-Bench 2
  task runs unmodified: the reference solution grades clean; an agent that reads
  the masked `/tests` oracle is blocked and logged.
- **SWE-bench** — `proctor run-swebench`. The repo is materialized at the base
  commit with fix history stripped; `--grade` runs the instance's tests through
  the isolated grader. A real instance demonstrates the git-history-mining cheat
  dying by construction.

The same harness, the same signed verdict, across benchmarks — which is what makes
it adoptable as a shared standard rather than yet another in-housed patch.

## Proof it works

- **The exploit corpus** ([`corpus/`](../../corpus/)) replays the documented
  in-sandbox access-cheat classes and asserts each is **blocked and logged** — it's both the
  regression suite and the credibility artifact.
- **Real tasks, end-to-end:** a Terminal-Bench 2 task and a SWE-bench instance,
  with before/after reports.
- **Green in CI on a stock GitHub runner** — the sandbox provably establishes
  off-machine, and `proctor` ships as a GitHub Action plus a prebuilt binary, so a
  benchmark's CI can run under Proctor in a few lines.

## What Proctor does *not* claim (on purpose)

Proctor blocks **in-sandbox access** cheats — reaching the answer through the
filesystem, git history, the network, or the process table. It deliberately does
not pretend to do more:

- It does not block answers that arrive from **outside** the sandbox — a scaffold
  that injects an answer key into the agent's prompt, or a solution smuggled
  inside the agent binary. Those need submission-provenance policy, not isolation — the
  focus of [v0.2 (see Roadmap)](#roadmap).
- It does not yet harden the **grader** against `PASS`-greps, hardcoded outputs,
  or mocks — that's a later phase.
- Faithful per-instance *resolved-grading* of a benchmark like SWE-bench needs
  that benchmark's pinned environment; Proctor provides the isolation, the grading
  pipeline, and the tamper-evident verdict.

We state the boundary plainly because an integrity tool that overclaims is worse
than none.

## Roadmap

Isolation ships today; the next layer answers the limitation above.

**v0.2 — attested submission provenance.** The cheats isolation can't stop are the ones the
submitter carries *in*: an answer key injected through the agent's scaffold (`AGENTS.md` —
the class behind the study's 1st→14th drop) or baked into the agent binary. You can't mask
an answer that was never reached for. v0.2 attacks it from the other side: Proctor captures
and content-addresses every input the agent was handed (scaffold, instruction files, binary,
environment) and binds a signed **submission manifest** into the run bundle — turning "what
was this agent fed?" into a verifiable, tamper-evident fact. It's the same move as the
violation log, one layer up: attest the inputs, don't trust them.

**Later, if demand pulls it:** grader hardening (`PASS`-greps, hardcoded outputs, mocks);
more benchmark adapters; pinned-image resolved-grading for SWE-bench.

## Who it's for

- **Benchmark operators** who want leaderboard integrity they can defend, without
  hand-patching their harness after every new exploit.
- **AI labs and eval teams** building RL environments and internal evals, who need
  reward signals that aren't quietly hacked.
- **Anyone publishing agent results** who wants a signed, verifiable artifact
  instead of "trust me."

## Get started

```
# prebuilt binary (Linux x86_64)
gh release download v0.1.1 --repo dylanp12/proctor \
  --pattern 'proctor-x86_64-unknown-linux-gnu.tar.gz*'
sha256sum -c proctor-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf proctor-x86_64-unknown-linux-gnu.tar.gz && ./proctor-x86_64-unknown-linux-gnu/proctor --version
```

Then see **[usage](../usage.md)** to run a task, or drop the **GitHub Action**
into your benchmark's CI. Proctor is **MIT-licensed**, Linux, and unprivileged.

> Cheating doesn't get rarer as agents get better — it gets more common. The
> answer isn't a smarter cheat-detector; it's an environment where the cheat was
> never possible. That's Proctor.
