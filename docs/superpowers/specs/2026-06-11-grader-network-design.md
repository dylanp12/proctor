# Grader network support — Design Spec

**Date:** 2026-06-11
**Status:** Draft for review
**Sub-project:** #2 of the productionization program.

## Summary

Give Proctor's grader phase a configurable network mode so a real benchmark test
harness (`test.sh` that bootstraps `uv`/`pip`/`apt`) can run during grading,
instead of the offline substitution the Terminal-Bench report had to document.
The agent's network policy is unchanged; only the **grade request** gains the
option, and only the trusted grader may use the new full-network ("host") mode.

## Context

Sub-project #2 of the program (the others, in order: #1 SWE-bench adapter —
done; #3 signed run-bundle + verify; #4 GitHub Action / CI wrapper; #5 release &
packaging; #6 full SWE-bench harness). This is foundational: real grading for
both TB and SWE-bench depends on it. Today `proctor-grader` hardcodes
`NetSpec::Deny`, so the grader has no egress.

## Goals

- A grader that can run with **deny | allowlist | host** network, default deny
  (no behavior change for existing callers).
- A new sandbox network mode `NetSpec::Host` (no network namespace = share the
  host's network) for the trusted grader.
- Reuse the hardened allowlist proxy (`HostProxy` + in-ns forwarder) for the
  grader's `allowlist` mode.
- Tests proving a `host` grader has egress and a `deny` grader does not.

## Non-goals

- Changing the **agent's** network options. The agent stays deny/allowlist; it is
  never given `host` (that would defeat egress isolation). `Host` is reachable
  only through a grade request.
- Wiring TB/SWE-bench grading to actually use network (removing the offline
  substitution in those reports). That is sub-project #6, where the prebuilt
  image + networked `test.sh` come together. This sub-project ships the mechanism
  and leaves call sites on `Deny`.
- veth/NAT real networking (root-only) — rejected; Proctor is unprivileged.

## Architecture

### Sandbox layer — `proctor-sandbox`

- **`spec.rs`:** add a third `NetSpec` variant, `Host`. Semantics: the sandbox is
  NOT placed in a new network namespace; it shares the host's. All other
  namespaces (user/mount/pid/ipc/uts), mount masking, and seccomp are unchanged.
- **`spawn.rs`:** the `unshare` flag set becomes conditional — include
  `CLONE_NEWNET` for `Deny`/`Allowlist` (today's behavior), omit it for `Host`.
  The `HTTP_PROXY`/`HTTPS_PROXY` env injection stays `Allowlist`-only; `Host` gets
  no proxy env (direct egress). The flags are computed before `pre_exec` and
  captured by the closure (no allocation in `pre_exec`).
- **`net.rs`:** `setup()` returns immediately for `Host` — it must not touch the
  host's `lo` or any host interface (it lacks permission, and they are already
  up). `Deny` (lo up) and `Allowlist` (lo up + forwarder) are unchanged.
- **`mounts.rs`:** unchanged — the proxy-socket bind is already `Allowlist`-only.

Why `Host` is safe here: not unsharing `CLONE_NEWNET` leaves the process in the
host network namespace; `connect()` to remote hosts needs no capability, so the
userns-root grader can reach the network through the host's routes. We do not
bind privileged ports or modify interfaces.

### Grader layer — `proctor-grader`

- New public enum:
  ```rust
  pub enum GraderNet {
      Deny,                  // empty netns (default; today's behavior)
      Host,                  // share the host network (full egress)
      Allowlist(Vec<String>),// "host:port" entries, enforced by the grader's proxy
  }
  ```
- `GradeRequest` gains `pub network: GraderNet`.
- `grade()` translates `network` into the grade sandbox's `SandboxSpec.network`:
  - `Deny` → `NetSpec::Deny`.
  - `Host` → `NetSpec::Host`.
  - `Allowlist(hosts)` → start a `HostProxy` on `<session>/egress.sock` with
    `hosts`, set `network: NetSpec::Allowlist { proxy_sock: /run/proctor/egress.sock }`
    and `host_proxy_sock: <session>/egress.sock`; keep the proxy alive for the
    grade run and drop it after (it owns a background listener thread). This
    mirrors `run.rs`'s allowlist wiring.

### Call sites

`run.rs` (`run`, `run_tb`) and any other `GradeRequest` construction add
`network: GraderNet::Deny` — preserving current behavior. (SWE-bench's
`run_swebench` does not grade, so it is unaffected.)

## Data flow

`GradeRequest{network}` → `grade()` builds the grade `SandboxSpec.network`
(+ optional `HostProxy`) → `run_sandboxed` (conditional netns) → the grade
command runs with the chosen egress → reward/exit-code interpreted as today.

## Error handling — fail closed

Unchanged posture: a `HostProxy` bind failure in `Allowlist` mode is an error
(the grade cannot run as specified) rather than a silent downgrade. `Host` adds
no new failure mode (it removes an unshare). `Deny` is unchanged.

## Testing

- **Sandbox unit/integration (`proctor-sandbox`):** a `Host` sandbox connecting to
  a host-local TCP origin **succeeds**; a `Deny` sandbox connecting to the same
  origin **fails** (empty netns, `ENETUNREACH`). (Reuses the host-origin pattern
  from `net_allow_test`.)
- **Grader integration (`proctor-grader`):** with a host-local origin server and
  a grade command that connects to it (exit-code protocol):
  - `GraderNet::Host` → grade **passes** (egress works).
  - `GraderNet::Deny` → grade **fails** (no egress).
  - `GraderNet::Allowlist([origin])` → grade **passes** through the grader's proxy;
    a non-allowlisted target is refused.
- **Regression:** existing grader tests (exit-code, reward.json/txt) and the
  agent-side network tests stay green with the default `Deny`.

## Open questions / risks

- **Test without the internet.** Tests use a host-local origin server (127.0.0.1)
  rather than real internet hosts, so `Host` vs `Deny` is provable deterministically
  offline. Resolved: host-local origin.
- **`curl` availability** in the grade command for tests — gate the HTTP asserts
  on `curl` presence (as `net_allow_test` does) or connect with a small inline
  Python/`/dev/tcp` probe. Decide in the plan; prefer a dependency-free probe.
