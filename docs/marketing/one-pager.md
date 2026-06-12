# Proctor — one-page brief

**A tamper-proof execution sandbox for trustworthy AI coding-agent benchmarks.**
Open source (MIT) · Linux · unprivileged.

---

**The problem.** AI coding-agent leaderboards drive model launches and purchasing
decisions — and they're contaminated. A 2026 UPenn study found **1,000+
harness-level cheating traces** across nine major benchmarks. Agents `cat` the
test oracle (415/429 "passes" in one Terminal-Bench submission were just that),
`git log` the fix commit, `curl` the answer, or pre-write the reward file.
De-cheating one top agent moved it from **1st to 14th place**. Every one of these
is a sandboxing failure, not a modeling one.

**The solution.** Proctor runs a benchmark task under enforced OS-level isolation
so the agent **physically cannot reach the answer**, and emits a **signed verdict**
plus a **tamper-evident log of every cheat it attempted**.

**How it works (by construction, not detection):**
- Oracle/test/solution files **aren't in the agent's mount namespace** → `open()` → ENOENT.
- The **network namespace is empty** → `curl` fails (allowlist bridges only approved hosts).
- The repo is **materialized at the base commit** → `git log` can't reach the fix.
- The grader runs in a **second isolated sandbox** against the true oracle; the
  result is an **ed25519-signed bundle** anyone can `verify-bundle`.

**Proof.**
- An exploit corpus blocks + logs **every documented in-sandbox cheat class**.
- Real **Terminal-Bench 2** and **SWE-bench** tasks run end-to-end (cheat blocked + logged).
- **Green in CI on a stock GitHub runner**; ships as a **GitHub Action** + prebuilt binary.

**Why adopt it.**
- **Defensible integrity** — results are signed, auditable artifacts, not "trust me."
- **By construction** — prevention beats a cheat-detector arms race agents win as they improve.
- **A standard, not a patch** — one harness, benchmark-agnostic adapters (Terminal-Bench, SWE-bench).
- **Drop-in** — a few lines of CI; no root, no VM, no daemon.

**Honest scope.** Proctor blocks *in-sandbox access* cheats (filesystem, git,
network, process table). It does not block answers injected from outside the
sandbox (scaffold/prompt injection, in-binary solutions) or grader-fooling
(`PASS`-greps, mocks) — stated plainly, because an integrity tool that overclaims
is worse than none.

**Get started.**
```
gh release download v0.1.0 --repo dylanp12/proctor --pattern 'proctor-x86_64-unknown-linux-gnu.tar.gz*'
tar -xzf proctor-x86_64-unknown-linux-gnu.tar.gz && ./proctor-x86_64-unknown-linux-gnu/proctor --version
```
Docs: **[Why Proctor](why-proctor.md)** · **[usage](../usage.md)** · **[FAQ](faq.md)**

**The ask.** If you operate a benchmark or run agent evals: put one task under
Proctor and see what your "passes" were actually doing.
