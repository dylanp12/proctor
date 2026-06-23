# Security Policy

## Threat model (read this first)

Proctor's adversary is a **capable coding agent taking the easy path to the answer during a
benchmark** — reading a hidden test oracle, mining git history for the fix, reaching the
network, or reading leaked answers from the environment. It is **not** designed to defend a
host against a malicious operator or an attacker holding a kernel/namespace escape. "Security"
here means **integrity of the evaluation** (the agent cannot reach the masked answer, and the
result is tamper-evident), not host-from-guest hardening. If you need to run genuinely
untrusted, hostile code, run Proctor inside a microVM or equivalent — that is a different
(complementary) layer.

## In scope

Reports that Proctor fails to deliver its actual guarantees:

- An agent, within the in-sandbox access threat model, **reaches a configured masked answer**
  (reads a masked oracle/test/solution path, recovers the stripped fix-commit history, reaches
  a denied network, or reads leaked answers from env/process state) **without being blocked
  and, where a syscall is issued against a masked resource, logged**.
- A way to **forge or tamper** with a `bundle.json` so that `proctor verify-bundle` still
  passes (signature, violation chain/count, artifact hashes, or the recorded environment not
  matching what was signed).
- A way the recorded **environment** can disagree with what actually ran while still verifying.

## Out of scope

- Kernel 0-days, namespace/seccomp escapes, or host compromise (wrong threat model — see
  above; Proctor is not a boundary against a malicious host/operator).
- The **documented non-goals** (these are stated limitations, not vulnerabilities): out-of-
  sandbox / scaffold-injected answer keys, solutions baked into the agent binary, and
  grader-fooling (`PASS`-greps, mocks, hardcoded outputs). See [`docs/bundle-spec.md`](docs/bundle-spec.md)
  and the README "Honest scope".
- The currently-unbound items noted in the bundle spec roadmap (image *content* digest,
  agent-binary hash) — known and tracked, not a disclosure.

## Reporting

Please report suspected vulnerabilities **privately** via GitHub Security Advisories
("Report a vulnerability" on the repository's Security tab) rather than a public issue. Include
a minimal reproduction (a task + agent command + policy that demonstrates the bypass, or a
bundle that wrongly verifies). We aim to acknowledge within a few days.
