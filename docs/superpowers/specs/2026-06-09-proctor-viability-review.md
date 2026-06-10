# Proctor — Viability Review

**Date:** 2026-06-09
**Verdict: VIABLE — build, with design changes.**
**Inputs:** local kernel/toolchain probes on the dev machine + a 4-agent research sweep with
adversarial completeness critique (raw findings: [`docs/research/2026-06-09-viability-research.md`](../../research/2026-06-09-viability-research.md)).

## 1. What checked out

**The local platform supports every mechanism in the spec, unprivileged.** Probed on this machine
(WSL2, kernel 6.6.114, Rust 1.95):

- user + mount + PID + net + IPC + UTS namespaces unshare cleanly without root
- overlayfs mounts inside a user namespace; a tmpfs mask over a path makes it return ENOENT —
  the core "blocked by construction" semantic, demonstrated end-to-end
- seccomp user-notification works end-to-end: a C probe intercepted `openat`, read the attempted
  path from the supervised process via `/proc/<pid>/mem`, replied `SECCOMP_USER_NOTIF_FLAG_CONTINUE`,
  and the syscall proceeded normally — exactly the `monitor` design
- inside the full namespace stack: host processes invisible (private `/proc`), netns contains only a
  dead loopback (egress impossible by default)
- cgroup v2 mounted; docker 29.3.1 + podman available (Terminal-Bench environment materialization)

**The problem is real and the numbers substantially verify.** arXiv 2604.11806 ("Detecting Safety
Violations Across Many Agent Traces", Stein/Brown/Hassani/Naik/Wong, UPenn, April 2026) and its
companion post (debugml.github.io/cheating-agents) confirm: 1,000+ harness-level cheating traces;
the 415/429 oracle-read figure (the Pilot submission); the 81.8%→71.7%, 1st→14th de-cheating drop
(ForgeCode). Nuances that our docs must adopt — see §3.

**The gap is still open.** As of June 2026, nobody ships a general, preventive, benchmark-agnostic
answer-isolation runtime. The field does detection/auditing (Meerkat, BenchJack, HAL log review),
generic security sandboxing (AISI Inspect, e2b, gVisor, Anthropic sandbox-runtime), and reactive
per-benchmark patches (SWE-bench PR #471). Closest threats: Harbor (Terminal-Bench's framework)
shipped opt-in separate verifier environments (2026-05-15) and per-phase network policy
(2026-05-30) — partial in-housing, which **narrows the window and argues for building now**, as the
cross-benchmark standard Harbor is not trying to be.

**The Rust path exists** — but not the one the spec named (§2, change 1).

## 2. Required design changes (from the adversarial critique)

1. **seccomp crate: `libseccomp` (libseccomp-rs 0.4), not `seccompiler`.** seccompiler 0.5 has no
   `SECCOMP_RET_USER_NOTIF` action and no notify-fd API; M5 cannot be built on it. libseccomp-rs
   wraps the full unotify flow (`ScmpAction::Notify`, `get_notify_fd()`, `ScmpNotifReq::receive`,
   `ScmpNotifResp::new_continue`, `notify_id_valid`). Host dep: C libseccomp ≥ 2.5 (runtime `.so.2`
   present on this machine; link via `LIBSECCOMP_LIB_PATH` or `libseccomp-dev`). Reference
   implementations: youki v0.6 (unotify + fd passing), hakoniwa 1.7 (namespace assembly).

2. **M9 re-scope — the corpus must be authored, not downloaded.** The UPenn authors published only
   the Meerkat auditing *tool*; no cheating-trajectory corpus exists. The raw trajectories live in
   the 40 GB Terminal-Bench-2 leaderboard HuggingFace dataset (ATIF format), and the key cheating
   submissions were removed/rescored (recoverable, if at all, from dataset git history). **v1
   corpus = our own faithful replays of each documented exploit class** (oracle read, reward-file
   pre-write, git-history mining, network lookup, env/process inspection), built from the study's
   published descriptions. Pulling real ATIF traces becomes a later enrichment, not a launch
   dependency.

3. **Success criterion re-scoped to in-sandbox access cheats — stated honestly.** Two headline
   exploit classes from the study are *categorically unreachable by OS isolation*: ForgeCode's
   scaffold-injected AGENTS.md answer keys (the answers arrive inside the agent's prompt) and
   OB-1's solutions encrypted inside the agent binary. No mount/netns/git mechanism can block an
   answer the submitter carries in. Proctor's claim becomes: **every documented in-sandbox access
   exploit class is blocked by construction and logged**; submitter-side smuggling requires
   provenance/submission policy (a documented non-goal, alongside grader-fooling). Anything else
   would be falsified on contact.

4. **Policy gains write-deny rules and phase semantics.** A documented exploit class is a *write*:
   pre-writing the reward file (`/logs/verifier/reward.txt`, world-writable in Harbor's shared
   mode) that the harness later parses. The policy model needs `forbidden_writes` and a
   distinction between agent-phase and verify-phase mounts (the agent never sees the verifier's
   writable surfaces).

5. **Network allowlist mechanism: empty netns + host-side proxy.** Default is an empty network
   namespace — egress fails by construction (`ENETUNREACH`), no firewall needed, fully
   unprivileged. Allowlist mode (agents need their LLM API): a Proctor-owned forward proxy
   listening on a unix socket bridged into the sandbox (unix sockets cross netns via the
   filesystem); the host side enforces the domain allowlist and logs every CONNECT — allowed and
   denied — into the violation timeline. Direct (non-proxy) egress remains impossible by
   construction.

6. **Mount masking reframed: Proctor owns workspace materialization.** In stock Harbor, `/tests`
   is uploaded only *after* the agent phase — the Pilot exploit happened because the submitter's
   own setup leaked it. Proctor's guarantee is therefore not "we mask the task's oracle paths"
   but "**we materialize the agent's world, so the oracle is never in it** — and the canonical
   oracle paths are masked anyway (defense in depth), with every attempted access logged."

7. **Git sanitization stays, but the TB adapter doesn't exercise it.** TB2 tasks are not git repos
   with fix commits; git-history mining is a SWE-bench-class exploit (IQuest-Coder). M4 is proven
   with synthetic repos in the corpus; it becomes load-bearing when the SWE-bench adapter lands.

8. **Terminal-Bench adapter targets the Harbor task format** (not legacy `task.yaml`): `task.toml`,
   `instruction.md`, `environment/Dockerfile`, `solution/solve.sh`, `tests/{test.sh,test_outputs.py}`;
   verifier writes `/logs/verifier/reward.txt|json`. Environment materialization: `docker build` +
   `docker export` → rootfs dir → overlay (docker is present); plus a host-rootfs mode for tasks
   without exotic environments.

9. **Verdict signing scoped honestly.** ed25519 (`ed25519-dalek` 2.x) over RFC 8785 canonical JSON
   (`serde_json_canonicalizer`) + env digest gives *integrity + operator provenance* — "this
   verdict is exactly what this operator's Proctor emitted, unmodified." It is not remote
   attestation; don't claim more.

10. **Docs corrections.** README/CLAUDE.md stats updated to the verified record: "1,000+
    harness-level cheating traces" (concentrated in TB2 top-3 + HAL USACO) + ~30 task-level cases;
    415/429 is one submission (Pilot); TB's response was a leaderboard-integrity update (removals,
    ATIF requirement, LLM-judge review) plus Harbor's later opt-in isolation features — not "no
    response," and not full prevention either.

## 3. Known risks accepted into the build

- **unotify overhead:** every `openat` in the sandbox round-trips to the supervisor. Acceptable for
  benchmark-scale runs (μs per open vs. minutes per task); the notify filter is scoped to
  open/openat/openat2/connect only. If a build-heavy task hurts, the monitor is audit-only by
  design (enforcement is the mounts) and can be degraded without weakening isolation. Measure at M5.
- **TOCTOU on path reads in the monitor:** inherent to unotify + `/proc/<pid>/mem`. Fine here:
  enforcement never depends on the monitor; it is an audit trail (bracket with `notify_id_valid`).
- **WSL2 ≠ CI:** Ubuntu 24.04 runners restrict unprivileged userns via AppArmor; CI needs
  `sysctl kernel.apparmor_restrict_unprivileged_userns=0` or equivalent. Gate integration tests,
  skip-with-message when the host can't sandbox (and fail closed at runtime).
- **Adoption risk** (unchanged from spec): load-bearing, non-technical, explicitly accepted;
  Harbor's recent isolation features make the corpus-proof wedge *more* urgent, not less.

## 4. Bottom line

Every kernel mechanism is proven on this machine; the crate path exists (with one substitution);
the problem and the gap verify; the launch artifact is re-scoped to something provable. The honest
version of the claim — *all documented in-sandbox access cheats die by construction and leave a
tamper-evident trail* — is buildable now, and still owned by nobody.
