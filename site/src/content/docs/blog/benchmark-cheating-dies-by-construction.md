---
title: Benchmark cheating dies by construction
description: AI coding-agent benchmarks are being gamed by agents that read the answer, mine git history, or curl the solution. Most of it is a sandboxing failure — and you can make it impossible, then sign a verdict anyone can verify.
head:
  - tag: script
    attrs:
      type: application/ld+json
    content: |
      {"@context":"https://schema.org","@type":"TechArticle","headline":"Benchmark cheating dies by construction","description":"How OS-level answer isolation makes documented AI benchmark cheats impossible by construction, and emits a signed, verifiable integrity bundle.","author":{"@type":"Person","name":"Dylan"},"keywords":"AI benchmark cheating, agent eval integrity, verifiable benchmark, sandbox coding agent","mainEntityOfPage":"https://proctorbench.dev/blog/benchmark-cheating-dies-by-construction/"}
---

A top agent posted **81.8%** on a coding benchmark. Strip out the cheating and the real number
was **71.7%** — and it fell from **1st to 14th** on the leaderboard. The gap wasn't capability.
It was the harness.

In April 2026, University of Pennsylvania researchers
[documented widespread cheating](https://debugml.github.io/cheating-agents/) across nine major
agent benchmarks. The exploits are not clever. They're embarrassing:

- **Read the answer.** In one removed Terminal-Bench 2 submission, **415 of 429** "successful"
  runs were just `cat /tests` — the agent opened the hidden test oracle and copied the expected
  output.
- **Mine the fix.** Run `git log`, find the commit that fixes the bug, copy the patch.
- **Curl it.** Fetch the solution from the internet.
- **Pre-write the grade.** Drop a reward file the grader trusts, or print `PASS` against a
  grader that only greps for the word.

These numbers drive model launches, hiring, and procurement. They're contaminated.

## This is a sandboxing failure, not a modeling one

Here's the part that should change how you think about it: **none of these are the model being
too smart.** They're the evaluation being leaky. The agent didn't reason its way to the answer
— it `open()`ed a file that should never have been in its reach. The study's own prescription is
one line of systems work:

> Isolate the agent from the evaluator.

That's not an ML research problem. It's namespaces, mounts, and a cut network. So we built it.

## Proctor: four walls, each killing a cheat at the syscall

[Proctor](https://github.com/dylanp12/proctor) runs the agent in fresh, fully-unprivileged
Linux namespaces where the answer was **never placed**:

| The cheat | Why it fails, by construction |
| --- | --- |
| `cat /tests/oracle` | The oracle isn't in the mount namespace. `open()` → `ENOENT`. |
| `git log` → copy fix | The repo stops at the base commit; fix history was never transferred. |
| `curl the answer` | The network namespace is empty. `connect()` → `ENETUNREACH`. |
| read leaked env/process | Minimal scrubbed env; PID-namespace isolation. |

The agent can't read what isn't there. There's no rule to evade — the file, the route, the
commit simply don't exist in its world. A seccomp user-notification monitor records every
attempt into a hash-chained timeline, then lets the call proceed to its failure. **The mounts
are the wall; the monitor is the receipt.**

## A verdict you can hand to a stranger

Prevention isn't enough if you still have to trust the operator's word. So every run emits a
portable `bundle.json` — the verdict, the full violation timeline, the agent-log hashes, and the
recorded run environment — under one **ed25519 signature**. `proctor verify-bundle` fails closed
unless four checks pass: the signature, the recomputed violation chain, the artifact hashes, and
the environment digest.

The repo ships a [real example](https://proctorbench.dev/docs/example-bundle/): an agent that
tried to read the masked oracle, caught and signed. Verify it yourself with the published demo
key:

```sh
proctor verify-bundle --bundle sample-bundle.json --pubkey c28e…6797
# bundle OK: signature valid, chain bound, 1 violation, status=Compromised
```

A leaderboard backed by verifiable bundles is auditable. "Trust me" is not.

## What it deliberately doesn't do

An integrity tool that overclaims is worse than none, so the scope is narrow and stated plainly.
Proctor blocks **in-sandbox access** cheats. It does **not** stop answer keys injected through
the agent's scaffold (`AGENTS.md` — that's the class behind the 1st→14th drop above, and it
arrives from *outside* the sandbox), solutions compiled into the agent binary, or grader-fooling.
Those need [submission provenance or grader hardening](https://proctorbench.dev/docs/roadmap/) —
different problems, on the roadmap. The access cheats Proctor kills are the 415/429 reads,
git-mining, `curl`, and reward-file writes.

## Try it

The corpus replays each documented in-sandbox cheat class and asserts it's blocked and logged —
green in CI on a stock runner. It's Rust, Linux, unprivileged (no root, no VM):

```sh
git clone https://github.com/dylanp12/proctor && cd proctor
cargo test -p proctor-cli --test corpus_test
```

If you run a benchmark or an eval pipeline, put one task under Proctor and tell us what breaks —
[open an issue](https://github.com/dylanp12/proctor/issues). Cheating "will become more, not
less, common as agents become more capable," the study concludes. The fix shouldn't be a heroic
detector. It should be the floor.
