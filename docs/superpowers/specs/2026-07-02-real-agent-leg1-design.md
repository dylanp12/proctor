# Leg 1 — a real LLM agent under Proctor — Design Spec

**Date:** 2026-07-02
**Status:** Draft for review
**Context:** post-launch direction (leg 1 of the "prove it with a real agent + publish
findings" plan). No real LLM-driven agent has ever run inside Proctor — every
demonstration so far used scripted agents (reference solution, `cat /tests`
one-liner). This closes that gap.

> **Best-judgment defaults (flagged — override at review):** the clarifying question
> on agent harness went unanswered (user away). This spec assumes **minimal agent
> first, then mini-swe-agent**, model **Haiku to validate → a frontier model for the
> headline run**, instance **`sympy__sympy-13647`** (deterministic + faithfully
> graded already), and the real run in **CI with an `ANTHROPIC_API_KEY` secret**
> (local with your key for dev iteration). The live run is gated on that key.

## Summary

Run a **real LLM agent** inside Proctor on `sympy__sympy-13647`: the agent's only
network egress is to the LLM API through the allowlist proxy, its API key arrives
via the env passlist, and the answer stays unreachable (test oracle masked, fix
history stripped). Then grade it faithfully in the pinned image. Ship: a signed
bundle from an LLM-driven run, the egress timeline proving the agent reached
*only* the LLM, and a **friction list** — the exact things a real adopter hits.

This is deliberately a *mechanism + one run* milestone, not the findings run (that
is leg 2: many instances × agents).

## Goals

- **Expose the existing allowlist + env-passlist to `run-swebench`.** Today it
  hardcodes `network: Deny` and `env: [PATH]`, ignoring both. Add repeatable
  `--allow-host <host:port>` and `--pass-env <VAR>` flags that reuse the generic
  `run` path's `HostProxy` + env-passthrough (no new isolation code).
- **A minimal in-repo LLM agent** (`scripts/minimal-llm-agent.sh`): reads the
  problem statement + repo, calls the Anthropic API **through the injected
  `HTTPS_PROXY`** for a unified diff, and `git apply`s it — using only `curl`/`jq`
  (or python stdlib) already in the rootfs, so it needs no runtime install.
- **Wire it end-to-end**: `run-swebench --image --grade --allow-host
  api.anthropic.com:443 --pass-env ANTHROPIC_API_KEY --agent "<minimal agent>"` on
  `sympy-13647` → the agent solves via the LLM (egress allowlisted, answer masked) →
  the faithful pinned-image grader scores it → signed bundle + verdict.
- **Friction list + report** documenting what a real agent hits (TLS through the
  CONNECT proxy, key/env, proxy env var casing, `git apply` from model output, etc.).
- **Follow-on (same sub-project, second commit series): mini-swe-agent** as the
  sandboxed agent, once the plumbing is green.

## Non-goals

- **The findings run** (leg 2) — many instances / multiple agents / violation stats.
- **New isolation primitives** — reuse the allowlist proxy (#2) + env passlist as-is.
- **Solving hard tasks / agent quality** — the LLM's problem-solving is the LLM's;
  Proctor's claim is isolation + faithful grade + egress audit, not agent skill.
- **Provenance / scaffold-injection defense** (v0.2) — leg 1 informs it, doesn't build it.
- **Vendoring a whole agent framework into the repo** — mini-swe-agent is a
  dependency invoked in CI, not vendored source.

## Architecture

### `run-swebench` egress + env passthrough (the only new Rust)

`main.rs`: add to the `RunSwebench` subcommand
```
--allow-host <HOST:PORT>   (repeatable) egress hosts for the agent (allowlist proxy)
--pass-env <VAR>           (repeatable) host env vars to pass into the agent
```
`run.rs::run_swebench(...)` gains `allow_hosts: Vec<String>, pass_env: Vec<String>`:
- If `allow_hosts` is non-empty → agent `network = NetSpec::Allowlist { proxy_sock:
  "/run/proctor/egress.sock" }`, start `HostProxy::start(&sock, allow_hosts)` (kept
  alive for the run), set `spec.host_proxy_sock`. Empty → `Deny` (unchanged).
- Agent `env` = `[PATH]` + each `--pass-env VAR` present in the host environment
  (mirrors the generic `run` passlist). `spawn.rs` already injects
  `HTTP(S)_PROXY=http://127.0.0.1:3128` for allowlist mode.
- Isolation invariants **unchanged**: `/tests` + patch paths masked, git history
  stripped, PID/mount/UTS/IPC namespaces. The agent gains egress **only** to the
  allowlisted host(s); the answer is still not reachable. Every proxy allow/deny
  is folded into the signed violation timeline (existing behavior).

Refactor: extract the generic `run`'s allowlist-proxy setup into a small shared
helper so `run` and `run_swebench` don't duplicate it.

### The minimal agent (`scripts/minimal-llm-agent.sh`)

Runs as the sandboxed `--agent`. Steps:
1. Read the problem statement from `$PROCTOR_PROBLEM` — `run_swebench` sets this in
   the agent env from `plan.instruction` (directly, not via `--pass-env`; env values
   carry the multi-line statement fine and it avoids polluting `/testbed`).
2. Gather a little repo context (the target file(s) named in the problem).
3. `curl https://api.anthropic.com/v1/messages` (honoring `HTTPS_PROXY`) with
   `x-api-key: $ANTHROPIC_API_KEY`, asking for a unified diff that fixes the issue.
4. Extract the diff (`jq`) and `git apply` it in `/testbed`.
5. Exit. (Deliberately single-shot for the plumbing proof; multi-turn is
   mini-swe-agent's job.)

Only `curl`, `jq`/python-stdlib, `git` — all present in the rootfs. No PyPI egress.

### Grading

Reuse the faithful pinned-image grader (`--image --grade`): after the agent run,
merge `/testbed`, apply the hidden `test_patch`, install pytest, run
`test_col_insert`. A genuine fix → `reward=1, status=clean`; a failed attempt →
`reward=0`; any masked-oracle read → `status=compromised` (it can't — masked).

### CI

A `real-agent` job in `swebench.yml` (or a new `real-agent.yml`),
`workflow_dispatch`, gated on the `ANTHROPIC_API_KEY` secret: build proctor, fetch
sympy at base, run the minimal agent under `--image --grade --allow-host
api.anthropic.com:443 --pass-env ANTHROPIC_API_KEY`, upload the bundle + the egress
timeline. Skips cleanly if the secret is unset.

## Data flow

`run-swebench --image --grade --allow-host api.anthropic.com:443 --pass-env
ANTHROPIC_API_KEY --agent minimal-llm-agent.sh`:
agent (image rootfs, `/tests` masked, history stripped, egress→proxy→anthropic only)
→ calls Claude for a patch → `git apply` → merged `/testbed`
→ grader (pinned image, Host net) applies test_patch + runs the test → signed
verdict/bundle + egress timeline (shows: connected only to api.anthropic.com).

## Error handling — fail closed

- No `ANTHROPIC_API_KEY` (or empty) → the run still executes but the agent's LLM
  call fails; the CI job guards on the secret and skips with a message rather than
  running a keyless no-op.
- Proxy denies any non-allowlisted egress the agent attempts → logged, connection
  fails (existing).
- `git apply` of a malformed model diff fails → the agent exits non-zero; the run
  still grades (unsolved) — no crash.
- All existing isolation fail-closed behavior is unchanged.

## Testing

- **Local, no key (mechanism):** a unit/integration test that `run_swebench` with
  `--allow-host`/`--pass-env` builds an `Allowlist` spec + passes the named env var
  (assert the `SandboxSpec`), plus the existing `net_allow_test` already proves the
  allowlist forward-proxy reaches an approved host and blocks others. This validates
  the plumbing without spending a cent.
- **Local, with your key (dev):** one real run on `sympy-13647` with Haiku; inspect
  the bundle (`verify-bundle`) + the egress timeline.
- **CI (artifact):** the `real-agent` job with the secret, a frontier model, uploads
  the bundle. The deliverable proof: "a real LLM agent solved a real SWE-bench
  instance under Proctor — here's the signed bundle and the proof it reached only
  the LLM."

## Open questions / risks

- **API key** is required for any live run and only you can supply it (CI secret or
  local). All non-LLM plumbing is buildable + testable now without it.
- **Anthropic API shape** (model ids, headers, `anthropic-version`) — pin against
  the current API when wiring the minimal agent; the frontier model id is chosen at
  run time.
- **Model may "know" the fix from training** — orthogonal to Proctor (that's
  benchmark contamination, not an in-sandbox access cheat). Proctor's guarantee is
  that the agent can't reach *this instance's* answer; a clean pass is still a
  legitimate, isolation-verified result.
- **mini-swe-agent deps** (follow-on): it can't pip-install under LLM-only egress, so
  it'll need pre-baking into the rootfs or a `pypi.org` allowlist entry for a pre-step
  — decided when that phase starts.
