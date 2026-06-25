---
title: How it works
description: By-construction answer isolation — masked mounts, an empty network namespace, base-commit git sanitization, and a seccomp audit — plus a signed verdict.
sidebar:
  order: 3
---

The agent runs in a re-exec'd sandbox-init process inside fresh, fully-unprivileged user /
mount / PID / network / IPC / UTS namespaces. The answer was never placed where it can reach
it:

- **Oracle/test/solution files aren't in its mount namespace** — masked by an empty read-only
  tmpfs over an overlay workspace; `open()` → `ENOENT`, by construction.
- **The network namespace is empty** — direct egress dies with `ENETUNREACH`. Allowlist mode
  bridges approved hosts through a host-side CONNECT proxy over a unix socket, and every
  allow/deny decision is recorded in the signed timeline.
- **The repo is materialized at the base commit** — later (fix) history is never transferred,
  so `git log` can't reach it.
- **A seccomp user-notification monitor** records attempted forbidden `open`/`openat`/`connect`
  calls into a hash-chained, tamper-evident timeline, then replies CONTINUE. **Isolation is
  enforced by the mounts and the empty netns, not by the monitor** — the monitor is the trail,
  not the wall.

The grader then runs in a **second** isolated sandbox, against the true oracle the agent never
saw. The verdict is an **ed25519 signature over RFC-8785 canonical JSON** plus an environment
digest, packaged into a portable [`bundle.json`](/docs/bundle-spec/).

## How each documented cheat dies

| Cheat | Why it fails under Proctor |
| --- | --- |
| read the oracle/test/solution files | not in the mount namespace — `open()` → ENOENT, logged |
| `git log` → fix commit → copy the patch | repo at the base commit; fix history unreachable |
| `curl` the solution | empty netns; egress fails (allowlist bridges only approved hosts) |
| read leaked answers from env / processes | minimal scrubbed env; PID-namespace isolation |

## Threat model (the load-bearing framing)

The adversary is a **capable agent taking the easy path to the answer during a benchmark** —
**not** an attacker trying to escape the kernel or compromise the host. That's why v1 builds
the sandbox directly on namespaces + seccomp + overlayfs rather than a hypervisor: you don't
need a microVM to stop `cat /tests`. See [Honest scope](/docs/honest-scope/) for what this
deliberately does **not** cover.
