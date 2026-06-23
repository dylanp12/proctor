# Changelog

All notable changes to Proctor. Format follows [Keep a Changelog](https://keepachangelog.com).
Releases ship a prebuilt binary with a published `.sha256`.

## [0.1.1] — unreleased

The "verifiable integrity bundle" release: a Proctor run now records *what ran*, and a third
party can confirm it.

### Added
- **Run-environment binding (`bundle_version: 2`).** Every run records a cleartext
  `environment` — agent command, rootfs kind + image reference, Proctor version **and build
  commit**, and policy/spec hashes — folded into the signed `env_digest`. `proctor
  verify-bundle` gains a **4th check** that recomputes `env_digest` from the recorded
  environment, so the binding is independently verifiable rather than signed-opaque.
- **`docs/bundle-spec.md`** — the bundle format spec: what's in `bundle.json`, the four
  `verify-bundle` checks, and precisely what a verifier can and cannot conclude.
- **`docs/examples/sample-bundle.json`** — a real signed v2 bundle of a *caught* masked-oracle
  read (`status: compromised`, one logged violation), verifiable with a published demo key.
- `CONTRIBUTING.md` and a threat-model-scoped `SECURITY.md`.

### Changed
- Bundles are now `bundle_version: 2`; **v1 bundles still verify** on the original three checks.
- The build records the git commit (`build.rs`) into the binary for environment binding.
- Docs: positioning tightened to "signed, independently verifiable integrity bundle"; Honest
  scope promoted to a top-level README section; the cheating-study citation corrected (DebugML
  blog + the paper's real title) and the 1st→14th figure correctly attributed to the
  scaffold-injection **non-goal**, not an in-sandbox access cheat.

### Fixed
- `cargo test` no longer false-fails on hosts without unprivileged user namespaces: the host
  capability probe test skips with a message off-CI, while CI enforces it via
  `PROCTOR_REQUIRE_SANDBOX=1`.

### Known limitations (documented, not regressions)
- The image **content** digest and an agent-**binary** hash are not yet bound (only the image
  *reference* and agent *command* are) — see the `docs/bundle-spec.md` roadmap.
- Out-of-sandbox answer injection (scaffold/`AGENTS.md`, in-binary answers) and grader-fooling
  remain explicit non-goals; submission-provenance is the v0.2 direction.

## [0.1.0] — 2026-06-12

### Added
- Initial release. By-construction in-sandbox answer isolation (masked mounts over an overlay
  workspace, empty network namespace + host-proxy allowlist, base-commit git sanitization);
  seccomp user-notification violation audit; ed25519-signed verdict + hash-chained violation
  timeline + portable `bundle.json` and `proctor verify-bundle`; Terminal-Bench (Harbor) and
  SWE-bench adapters; a composite GitHub Action; and the exploit corpus replaying the
  documented in-sandbox access-cheat classes (green in CI on a stock runner).
