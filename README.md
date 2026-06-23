# Proctor

[![demo](https://github.com/dylanp12/proctor/actions/workflows/demo.yml/badge.svg)](https://github.com/dylanp12/proctor/actions/workflows/demo.yml)

**Proctor turns AI coding-agent benchmark runs into signed, independently verifiable
integrity bundles.**

It runs agents in an answer-isolated Linux sandbox where the configured hidden tests, fix
history, and network egress are not reachable, then signs the verdict and the covered
forbidden-access timeline.

AI coding-agent benchmarks are being gamed. In April 2026, UPenn researchers (Stein,
Brown, Hassani, Naik & Wong) documented [widespread cheating on popular agent
benchmarks](https://debugml.github.io/cheating-agents/): **1,000+ harness-level cheating
traces** across major benchmarks — concentrated in Terminal-Bench 2 and HAL USACO — plus
~30 task-level cases (method paper: *Detecting Safety Violations Across Many Agent
Traces*, [arXiv 2604.11806](https://arxiv.org/abs/2604.11806)). The cheats are mundane:
agents read the test oracle (**in one removed Terminal-Bench 2 submission, 415 of 429
successful traces were plain filesystem reads of `/tests`**), mine `git log` for the fix
commit, `curl` the solution, or pre-write the grader's reward file. Every one of these is a
sandboxing / access-control failure, not a modeling one.

> The study's most dramatic single number — a top submission falling from **1st to 14th**
> once de-cheated — came from a *different* cheat class: answer keys injected through the
> agent's scaffold (`AGENTS.md`). That arrives from **outside** the sandbox, so OS isolation
> alone can't stop it — it's the target of Proctor's [v0.2 provenance work](#roadmap), and
> we name that boundary plainly (see [Honest claim scope](#honest-claim-scope)) rather than
> quietly claiming it.

Proctor runs a benchmark task under enforced OS-level isolation so the configured hidden
evaluator artifacts (oracle/tests, fix history, network) are not reachable from the agent's
sandbox, and emits a signed verdict plus a tamper-evident log of covered forbidden-access
attempts (masked-file reads, blocked egress).

```
proctor run --task ./task --agent "my-agent --solve" --policy ./policy.yaml
# -> verdict.json      { "pass": true, "status": "compromised", "violations_count": 1, ... }
# -> violations.jsonl  { "step": 8, "kind": "masked_read", "path": "/oracle/answer.txt", ... }
```

## How it works (v1)

The agent runs in a re-exec'd sandbox-init process inside fresh user / mount / PID /
network / IPC / UTS namespaces, fully unprivileged:

- **oracle/test/solution files aren't in its mount namespace** — masked by an empty
  read-only tmpfs over an overlay workspace; `open()` → ENOENT, by construction
- **the network namespace is empty** — direct egress dies with `ENETUNREACH`; allowlist
  mode bridges approved hosts through a host-side CONNECT/forward proxy over a unix socket,
  and every proxy allow/deny decision is recorded in the signed timeline
- **the repo is materialized at the base commit** — later (fix) history is never
  transferred, so `git log` can't reach it
- **a seccomp user-notification monitor** records attempted opens (`open`/`openat`/`openat2`)
  of forbidden paths and direct egress `connect`s into a hash-chained, tamper-evident
  timeline, then always replies CONTINUE — so isolation is enforced by the mounts and netns,
  never by the monitor. Enforcement is complete by construction; the *audit* covers the
  syscalls on the notify list, not every conceivable variant
- the grader runs in a **second** isolated sandbox, against the true oracle the agent
  never saw; the verdict is an **ed25519 signature over RFC-8785 canonical JSON** + an
  environment digest
- every run also emits a portable **`bundle.json`** — the signed verdict + the violation
  records + agent-log hashes, all bound under one signature. `proctor verify-bundle`
  re-checks the signature, the violation chain (bound to the verdict), and the log hashes;
  with a stable operator key (`proctor keygen` / `PROCTOR_SIGNING_SEED`) it proves
  *which operator* produced the result

The design goal is a *general, benchmark-agnostic standard*. Terminal-Bench (Harbor
format) is the first adapter (`proctor run-tb`); a SWE-bench adapter
(`proctor run-swebench`) materializes the repo at the base commit with fix history
stripped, and `--grade` runs the instance's tests through the isolated grader over the
Host network on CI — see the
[grading report](docs/reports/2026-06-12-swebench-grading-pinned.md), which also documents
the boundary: faithful per-instance resolved-grading needs SWE-bench's pinned
environment, while Proctor's reproducible signal is the tamper-evident integrity
verdict (the git-mining cheat is blocked + flagged `compromised`). `--image` runs
the agent + grader inside the instance's pinned SWE-bench image (daemonless
podman/docker fetch) with the gitsan'd repo still overlaid at `/testbed`.

## Honest scope

Proctor blocks **in-sandbox access** cheats — reaching the answer through the filesystem,
git history, the network, or the process table. It does **not** block answers that arrive
from *outside* the sandbox (a scaffold that injects answer keys into the agent's prompt,
or solutions smuggled inside the agent binary) — those need submission-provenance policy,
the focus of [v0.2](#roadmap) — nor grader-fooling (`PASS`-greps, hardcoded outputs, mocks),
which is a later phase. See [`corpus/RESULTS.md`](corpus/RESULTS.md) for the full per-class
table.

## Status

**v1 implemented and released** (Linux, Rust, unprivileged). The exploit corpus
([`corpus/`](corpus/)) replays the documented in-sandbox access-cheat classes it covers and
asserts each is blocked and logged, and the full suite is **green in CI on a stock GitHub
runner** —
so the sandbox provably establishes off-machine, not just on a dev box. Shipped on top of
the core:

- **Signed, portable run bundles** — `bundle.json` (verdict + violations + log hashes
  under one signature); `proctor verify-bundle` re-checks everything; stable operator keys.
- **Real benchmark tasks, end-to-end:** a Terminal-Bench 2 task (reference solution →
  clean pass; oracle read → blocked + logged) and a SWE-bench instance
  (`proctor run-swebench`; `--grade` runs the tests through the isolated grader in CI).
- **`proctor` as a GitHub Action** (`action.yml`) + a prebuilt **v0.1.1** binary, so a
  benchmark's CI can run under Proctor in a few lines.

**New here?** Read **[Why Proctor](docs/marketing/why-proctor.md)** first, then
**[usage](docs/usage.md)** to run your first task. For the full design and threat model see
the **[design spec](docs/superpowers/specs/2026-06-09-proctor-design.md)** and the
**[FAQ](docs/marketing/faq.md)**. The **[bundle spec](docs/bundle-spec.md)** defines exactly
what a verifier can — and cannot — conclude from a signed run, with a verifiable
**[example bundle](docs/examples/)**.

## Roadmap

**v0.2 — attested submission provenance.** The biggest documented cheat Proctor can't yet
stop is *out-of-sandbox* answer smuggling: answer keys injected through the agent's scaffold
(`AGENTS.md`) or a solution compiled into the agent binary — the class behind the study's
1st→14th drop. OS isolation can't see an answer the submitter carries in. v0.2 closes it
from the other side: Proctor captures and content-addresses every input the agent was given
(scaffold, instruction files, agent binary, environment) and binds a signed, tamper-evident
**submission manifest** into the run bundle — so a reviewer can verify exactly what went in,
not just what the agent reached for. Same philosophy as the violation log: *attest the
inputs, don't trust them.*

**Later (pulled by real demand):** grader hardening against `PASS`-greps / hardcoded
outputs / mocked libraries; additional benchmark adapters; a pinned-image SWE-bench
resolved-grading path.

## Install

**Prebuilt binary** (Linux x86_64, glibc ≥ 2.35):

```
gh release download v0.1.1 --repo dylanp12/proctor \
  --pattern 'proctor-x86_64-unknown-linux-gnu.tar.gz*'
sha256sum -c proctor-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf proctor-x86_64-unknown-linux-gnu.tar.gz
sudo install proctor-x86_64-unknown-linux-gnu/proctor /usr/local/bin/
proctor --version
```

Needs `libseccomp2` (the runtime library) present — installed by default on most
distributions (`sudo apt-get install -y libseccomp2` otherwise). On Ubuntu 24.04 (and any
distro that restricts unprivileged user namespaces) enable them once or every run fails:
`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`. Run `proctor probe` to
confirm your host can sandbox.

**From source** with `cargo`:

```
sudo apt-get install -y libseccomp-dev          # link-time libseccomp
cargo install --git https://github.com/dylanp12/proctor proctor-cli
```

## Verify it yourself (60 seconds)

The corpus is the proof: five documented in-sandbox cheat classes, each replayed as a test
that plants a random nonce as the "answer" and asserts the agent never sees it.

```
git clone https://github.com/dylanp12/proctor && cd proctor
./scripts/dev-setup.sh        # links libseccomp for the build
# Ubuntu 24.04 (incl. the GitHub CI runner) disables unprivileged user namespaces by
# default — enable once, or every sandbox run fails:
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
cargo test -p proctor-cli --test corpus_test -- --nocapture
```

Each test builds a task, runs an agent that *tries* the cheat, and asserts it's blocked
(and, where a syscall is issued against a masked resource, logged). See
[`corpus/RESULTS.md`](corpus/RESULTS.md) for the per-class table.

## Building

```
./scripts/dev-setup.sh        # links libseccomp for the build (one-time)
cargo test --workspace        # unit + isolation integration tests
cargo run -p proctor-cli -- probe   # check the host can sandbox
```

Requires Linux ≥ 5.11 with unprivileged user namespaces, a C `libseccomp` ≥ 2.5
runtime, and `git`. On Ubuntu 24.04 / CI, enable unprivileged userns first:
`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`.

## License

[MIT](LICENSE).
