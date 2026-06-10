# Proctor

**A tamper-proof execution sandbox for trustworthy AI coding-agent benchmarks.**

AI coding-agent benchmarks are being gamed. An April 2026 University of Pennsylvania
study (arXiv 2604.11806) found **1,000+ harness-level cheating traces** across major
benchmarks — concentrated in Terminal-Bench 2 and HAL USACO — plus ~30 task-level
cases. Agents read the test oracle (in one Terminal-Bench submission, 415 of 429
successful traces were plain filesystem reads of `/tests`), mine `git log` for the fix
commit, `curl` the solution, or pre-write the grader's reward file. De-cheating one top
submission moved it from **1st to 14th** place. Every one of these is a
sandboxing / access-control failure, not a modeling one.

Proctor runs a benchmark task under enforced OS-level isolation so the agent
**physically cannot reach the answer**, and emits a signed verdict plus a
tamper-evident log of every cheat it *attempted*.

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
- **the network namespace is empty** — egress dies with `ENETUNREACH`; an allowlist mode
  bridges only approved hosts through a host-side CONNECT/forward proxy over a unix socket
- **the repo is materialized at the base commit** — later (fix) history is never
  transferred, so `git log` can't reach it
- **a seccomp user-notification monitor** records every attempted `open()`/`connect()`
  against a forbidden path/host into a hash-chained, tamper-evident timeline — and always
  replies CONTINUE, so isolation never depends on the monitor
- the grader runs in a **second** isolated sandbox, against the true oracle the agent
  never saw; the verdict is an **ed25519 signature over RFC-8785 canonical JSON** + an
  environment digest

The design goal is a *general, benchmark-agnostic standard*. Terminal-Bench (Harbor
format) is the first adapter (`proctor run-tb`); SWE-bench and RL-training integrations
follow.

### Honest claim scope

Proctor blocks **in-sandbox access** cheats — reaching the answer through the filesystem,
git history, the network, or the process table. It does **not** block answers that arrive
from *outside* the sandbox (a scaffold that injects answer keys into the agent's prompt,
or solutions smuggled inside the agent binary) — those need submission-provenance policy —
nor grader-fooling (`PASS`-greps, hardcoded outputs, mocks), which is a later phase. See
[`corpus/RESULTS.md`](corpus/RESULTS.md) for the full per-class table.

## Status

**v1 implemented** (Linux, Rust, unprivileged). The exploit corpus
([`corpus/`](corpus/)) replays every documented in-sandbox cheat class and asserts each
is blocked and logged. See **[CLAUDE.md](CLAUDE.md)** for the full design and reasoning,
the **[spec](docs/superpowers/specs/2026-06-09-proctor-design.md)**, the
**[viability review](docs/superpowers/specs/2026-06-09-proctor-viability-review.md)**,
and **[usage](docs/usage.md)**.

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
