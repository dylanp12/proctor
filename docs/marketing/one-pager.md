# Proctor — one-page brief

**An answer-isolating execution harness for AI coding-agent benchmarks — every run becomes
a signed, independently verifiable integrity bundle.**
Open source (MIT) · Linux · unprivileged.

---

**The problem.** AI coding-agent leaderboards drive model launches and purchasing
decisions — and they're contaminated. A 2026 UPenn study
([DebugML](https://debugml.github.io/cheating-agents/)) found **1,000+ harness-level
cheating traces** across nine major benchmarks. Agents `cat` the test oracle (in one removed
Terminal-Bench 2 submission, 415 of 429 "successful" runs were just that), `git log` the fix
commit, `curl` the answer, or pre-write the reward file — all *access* failures, not modeling
ones. (The study's headline 1st→14th drop came from a *different* class, scaffold-injected
answer keys, which arrives from outside the sandbox and is a documented non-goal here — see
Honest scope.)

**The solution.** Proctor runs a benchmark task under enforced OS-level isolation
so the configured hidden evaluator artifacts (oracle/tests, fix history, network) are not
reachable from the agent's sandbox, and emits a **signed verdict** plus a **tamper-evident
log of covered forbidden-access attempts**.

**How it works (by construction, not detection):**
- Oracle/test/solution files **aren't in the agent's mount namespace** → `open()` → ENOENT.
- The **network namespace is empty** → `curl` fails (allowlist bridges only approved hosts).
- The repo is **materialized at the base commit** → `git log` can't reach the fix.
- The grader runs in a **second isolated sandbox** against the true oracle; the
  result is an **ed25519-signed bundle** anyone can `verify-bundle`.

**Proof.**
- An exploit corpus blocks + logs the **documented in-sandbox access-cheat classes** it covers.
- Real **Terminal-Bench 2** and **SWE-bench** tasks run end-to-end (cheat blocked + logged).
- **Green in CI on a stock GitHub runner**; ships as a **GitHub Action** + prebuilt binary.

**Why adopt it.**
- **Defensible integrity** — results are signed, auditable artifacts, not "trust me."
- **By construction** — prevention beats a cheat-detector arms race agents win as they improve.
- **Benchmark-agnostic, not a one-off patch** — one harness, adapters for Terminal-Bench + SWE-bench.
- **Drop-in** — a few lines of CI; no root, no VM, no daemon.

**Honest scope.** Proctor blocks *in-sandbox access* cheats (filesystem, git,
network, process table). It does not block answers injected from outside the
sandbox (scaffold/prompt injection, in-binary solutions) or grader-fooling
(`PASS`-greps, mocks) — stated plainly, because an integrity tool that overclaims
is worse than none.

**Get started.**
```
gh release download v0.1.1 --repo dylanp12/proctor --pattern 'proctor-x86_64-unknown-linux-gnu.tar.gz*'
sha256sum -c proctor-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf proctor-x86_64-unknown-linux-gnu.tar.gz && ./proctor-x86_64-unknown-linux-gnu/proctor --version
```
Docs: **[Why Proctor](why-proctor.md)** · **[usage](../usage.md)** · **[FAQ](faq.md)**

**The ask.** If you operate a benchmark or run agent evals: put one task under
Proctor and see what your "passes" were actually doing.
