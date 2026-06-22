# Contributing to Proctor

Thanks for your interest. Proctor is a Rust, Linux-only execution harness that runs AI
coding-agent benchmark tasks under answer-isolating namespaces and emits a signed,
independently verifiable integrity bundle. Contributions that strengthen the isolation, the
attestation, or the corpus are very welcome.

## Scope (please read first)

Proctor's threat model is a **capable coding agent taking the easy path to the answer during
a benchmark** — not a malicious actor seeking kernel escape or host compromise (see
[`SECURITY.md`](SECURITY.md)). Contributions should stay on that core:

- **In scope:** answer-isolation (masked mounts, cut network, sanitized git), the
  tamper-evident violation log, the signed `bundle.json` + `verify-bundle`, benchmark
  adapters, and the exploit corpus.
- **Out of scope (by design):** grader/reward *design* (an ML-research concern), and
  microVM/escape-hardening (a different threat model). PRs that drift here will be redirected.

The honest-scope discipline is a feature: Proctor blocks *in-sandbox access* cheats and says
so plainly. Please don't add language or features that imply broader guarantees than the code
delivers.

## Dev setup

Requires Linux ≥ 5.11 with unprivileged user namespaces, C `libseccomp` ≥ 2.5, and `git`.

```
./scripts/dev-setup.sh        # links libseccomp for the build (one-time)
# Ubuntu 24.04 (and the GitHub CI runner) disable unprivileged userns by default:
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
cargo run -p proctor-cli -- probe   # confirm the host can sandbox
```

## Build, test, lint

```
cargo test --workspace        # unit + isolation integration tests
cargo fmt --all -- --check    # CI enforces formatting
cargo clippy --workspace --all-targets -- -D warnings   # CI enforces a clean clippy
```

Integration tests that need real namespaces **skip with a message** on hosts that can't
sandbox, so `cargo test` is green on any machine. CI sets `PROCTOR_REQUIRE_SANDBOX=1` to turn
those skips into hard assertions on a capable runner.

## Conventions

- **TDD, always.** Write the failing test (e.g. the cheat that should be blocked) first, then
  the isolation that blocks it. The exploit corpus (`crates/proctor-cli/tests/corpus_test.rs`)
  and the per-module tests are the spec.
- **A new cheat class needs a corpus test.** If you add coverage for an in-sandbox access
  cheat, add a corpus replay that plants a per-run nonce as the "answer" and asserts the agent
  never sees it.
- **Fail closed.** If isolation can't be established, the run *errors* — never proceed
  under-protected.
- **Small, focused crates;** typed errors (`thiserror`); no hand-rolled syscall ABI (build on
  `nix` / `libseccomp`).

## Pull requests

- Keep CI green (fmt + clippy + tests).
- Describe what cheat class / guarantee the change affects, and add/extend tests.
- Security-relevant findings: please follow [`SECURITY.md`](SECURITY.md) rather than opening a
  public issue.

Proctor is MIT-licensed; by contributing you agree your contributions are licensed under the
same terms.
