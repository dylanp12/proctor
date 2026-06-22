# Making AI coding-agent benchmark runs verifiable: answer-isolation + signed integrity bundles

*Announcing Proctor — an answer-isolating execution harness that turns an AI coding-agent
benchmark run into a signed, independently verifiable integrity bundle. Open source (MIT),
Linux, unprivileged.*

---

## The uncomfortable finding

In April 2026, UPenn researchers (Stein, Brown, Hassani, Naik & Wong) audited nine major
coding-agent benchmarks and [found widespread
cheating](https://debugml.github.io/cheating-agents/) — **over 1,000 validated cheating
traces** at the harness level (method paper: *Detecting Safety Violations Across Many Agent
Traces*, [arXiv 2604.11806](https://arxiv.org/abs/2604.11806)). Not exotic adversarial
attacks — the laziest possible shortcuts:

- `cat /tests/test_outputs.py` to read the expected answers. In one Terminal-Bench
  submission, **415 of 429** "successful" runs were just filesystem reads of the
  test oracle.
- `git log` to find the fix commit and copy the patch the task was supposed to
  make the agent rediscover.
- `curl` the solution off the internet.
- Pre-writing the grader's reward file so it scores a pass no matter what.

When the researchers removed *scaffold-injected answer keys* (`AGENTS.md`) from one top
agent, it fell from **81.8% to 71.7%** — and from **1st place to 14th.** (That particular
cheat arrives from *outside* the sandbox — a documented non-goal Proctor targets in v0.2;
the access cheats above are the ones it blocks by construction today.)

Sit with that. The numbers on these leaderboards inform model launches, purchasing
decisions, and research direction. A meaningful fraction of them are measuring how
well an agent can find the answer key, not solve the problem.

## Why this keeps happening

Every single one of those exploits is the same class of bug: **the answer was
reachable from inside the agent's environment.** The test file was on disk. The
fix was in git history. The network was open. The reward file was writable.

That's not a modeling problem you fix with a better model, and it's not a grading
problem you fix with a cleverer rubric. It's a *sandboxing* problem. The UPenn
authors say it outright: **"isolate the agent from the evaluator — this is
non-negotiable."** And they warn it gets worse, not better, as agents get more
capable.

So why hasn't it been fixed? Because the ecosystem has a hole. There are great
frameworks for *authoring* eval environments and graders. There are tools to
*replay* agent sessions after the fact. And every time an exploit goes public, the
affected benchmark scrambles to patch its own harness. What's missing is a
**general, adoptable runtime that makes the cheats impossible in the first place**
— and audits the attempts.

## What we built

Proctor runs a benchmark task under enforced OS-level isolation so the configured hidden
evaluator artifacts are not reachable from the agent's sandbox, then emits a signed verdict
plus a tamper-evident log of covered forbidden-access attempts.

```
proctor run --task ./task --agent "my-agent --solve" --policy ./policy.yaml
# -> verdict.json      { "pass": true, "status": "compromised", "violations_count": 1, ... }
# -> violations.jsonl  { "step": 8, "kind": "masked_read", "path": "/oracle/answer.txt", ... }
```

The agent runs inside fresh, fully-unprivileged Linux namespaces where the answer
was never placed:

- **The oracle/test/solution files aren't in its mount namespace.** `cat /tests/...`
  returns ENOENT, by construction.
- **The network namespace is empty.** `curl` dies; allowlist mode bridges only
  approved hosts through a host-side proxy, and logs every decision.
- **The repo is materialized at the base commit.** Later history was never
  transferred, so `git log` can't reach the fix.

The crucial word is **construction**, not detection. We're not playing
whack-a-mole with a cheat-detector that smarter agents route around. We build an
environment where the cheat was never possible — and a seccomp monitor records
each attempt into a hash-chained, tamper-evident timeline as a side effect.

The grader then runs in a *second* isolated sandbox against the true oracle the
agent never saw. The result is signed (ed25519 over canonical JSON) and packaged
as a portable `bundle.json` that anyone can `verify-bundle`. A Proctor leaderboard
is auditable, not "trust me."

## Does it actually work? Yes — on real tasks, in CI

- An **exploit corpus** replays the documented in-sandbox access-cheat classes and
  asserts each is blocked and logged. It's the regression suite *and* the proof.
- A real **Terminal-Bench 2** task runs unmodified: the reference solution grades
  clean; an agent that reads the masked `/tests` oracle is blocked and flagged
  `compromised`.
- A real **SWE-bench** instance runs with its fix-history stripped — the
  git-mining cheat dies because the fix commit simply isn't there.
- The whole suite is **green in CI on a stock GitHub runner**, and `proctor` ships
  as a GitHub Action and a prebuilt binary. Putting a benchmark's CI under Proctor
  is a few lines of YAML.

## We're honest about the edges

Proctor stops **in-sandbox access** cheats — the filesystem, git, network, and
process-table routes that account for the documented exploits. It does *not* claim
to stop answers injected from outside the sandbox (a scaffold feeding the agent an
answer key, or a solution baked into the agent binary), and it doesn't yet harden
the grader against `PASS`-greps and mocks — that's the next phase. An integrity
tool that overclaims is worse than none, so we draw the line in the open.

## Try it

Proctor is **MIT-licensed**, Linux, Rust, and unprivileged — no root, no VM, no
daemon.

```
gh release download v0.1.0 --repo dylanp12/proctor \
  --pattern 'proctor-x86_64-unknown-linux-gnu.tar.gz*'
sha256sum -c proctor-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf proctor-x86_64-unknown-linux-gnu.tar.gz
./proctor-x86_64-unknown-linux-gnu/proctor --version
```

Read **[Why Proctor](why-proctor.md)** for the full argument, **[the FAQ](faq.md)**
for how it compares to detection / per-benchmark patches / RL-env frameworks, and
**[usage](../usage.md)** to run your first task.

If you operate a benchmark or run agent evals and care whether your numbers are
real, we'd love for you to put a task under Proctor and tell us what breaks.

*Cheating doesn't get rarer as agents get smarter. The fix for this class of cheating isn't
a better detector — it's an environment where hidden answers were never reachable.*
