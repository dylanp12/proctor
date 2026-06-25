---
title: FAQ
description: How Proctor compares to detection, per-benchmark patches, RL-env frameworks, containers, microVMs, and host-isolation sandboxes — and answers to the common objections.
sidebar:
  order: 6
---

## How it compares

| Approach | What it does | Where it falls short for benchmark integrity |
| --- | --- | --- |
| Cheat **detection** | Flags likely cheating after the fact | A heuristic arms race; capable agents route around detectors. |
| Per-benchmark **patches** | Each operator fixes its harness after an exploit | Reactive, one-benchmark, after-the-fact. No shared standard. |
| **RL-env frameworks** (e.g. `verifiers`) | Author/host eval environments + graders | Not a by-construction agent↔evaluator isolation runtime. Complementary. |
| Published **checklists** (UPenn / Berkeley RDI) | Name the fix + list good practices | A paper, not a runtime — doesn't run unprivileged in CI or sign a verdict. |
| **Grader-hardening** (Hacker-Fixer, TB 2.1 fixes) | Harden the verifier so PASS-greps/mocks fail | The complementary half: it fixes the grader; Proctor isolates the agent. |
| **Containers alone** | Package the task environment | Still ship the tests/git/network unless something hides them. |
| **microVM / hypervisor** | Strong host-from-guest boundary | Solves the wrong threat (escape), at cost; doesn't hide the *answer* or sign a verdict. |
| **Proctor** | Removes the answer from the agent's reach (by construction) + a signed, tamper-evident verdict | In-sandbox access cheats only (by design — see [Honest scope](/docs/honest-scope/)). |

## Isn't this just the academic checklist, implemented?
Partly — and that's the point. Naming a fix isn't running it. The un-done part is the
unprivileged, signed, multi-benchmark runtime + a CI-green corpus of the documented cheat
classes (which already implements the study's canary-token recommendation, asserted in CI).

## How is this different from AISI's Inspect Sandboxing Toolkit?
Different layer. Inspect isolates the *host* from a potentially-dangerous agent (escape/exfil);
Proctor isolates the *answer* from the agent and signs the run. They compose.

## Can the agent bypass the seccomp monitor?
It can try and gains nothing — isolation is enforced by the mounts and the empty network
namespace, not the monitor (which is audit-only and replies CONTINUE). An agent that avoids
every audited syscall still can't read an oracle that isn't in its filesystem.

## Can the agent forge the verdict?
No. It's signed *outside* the sandbox with a key the agent never holds; `verify-bundle`
recomputes the signature, chain, artifact hashes, and environment.

## Does it need root? / overhead?
No root — fully unprivileged user namespaces. Overhead is small: namespaces + overlayfs +
seccomp user-notification, no VM boot, no per-syscall emulation.

## Why Linux-only?
Coding-agent benchmarks run on Linux, and the isolation primitives (namespaces, overlayfs,
seccomp) are Linux's.
