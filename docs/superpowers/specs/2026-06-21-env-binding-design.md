# Bind the run environment into the signed bundle — Design Spec

**Date:** 2026-06-21
**Status:** Draft for review → writing-plans
**Motivation:** `bundle-spec.md` honestly documents that the signed `env_digest` binds only
policy + task-spec + Proctor version — **not** the agent command, the rootfs/container image,
or the Proctor build commit. For an "integrity bundle" product, a verifier should be able to
confirm *which agent, in which image, built from which commit* produced a result. External
review rated closing this higher-priority than another adapter. This spec closes it.

## Goal

Make the bundle **bind and record** the run environment, so `verify-bundle` can independently
recompute and confirm it — turning today's opaque `env_digest` into a verifiable claim.

## Design

### 1. A recorded `environment` section in the bundle

Add to `Bundle` (and persist in `bundle.json`):

```rust
pub struct Environment {
    pub agent_command: String,        // exact argv the agent was launched with
    pub rootfs_kind: String,          // "host" | "image"
    pub image_ref: Option<String>,    // e.g. "ghcr.io/…/task@sha256:…" (image mode)
    pub image_digest: Option<String>, // resolved sha256 (image mode)
    pub proctor_version: String,      // CARGO_PKG_VERSION
    pub proctor_commit: String,       // git short SHA at build, or "unknown"
    pub policy_sha256: String,        // hash of the policy YAML
    pub spec_sha256: String,          // hash of the task spec JSON
}
```

These are **recorded in cleartext** (not just hashed) so a third party can read *what* ran and
recompute the digest over it.

### 2. `env_digest` folds the recorded fields

`env_digest` is computed over the labeled `Environment` fields (sorted), replacing today's
`(policy, spec, versions)` triple. Because it's in the signed `VerdictBody`, the signature
binds the whole environment. (Policy/spec are bound by their `*_sha256`; the full policy/spec
text need not be embedded.)

### 3. `verify-bundle` gains a 4th check

After signature / chain / artifacts, recompute `env_digest` from the bundle's recorded
`environment` section and require it equals `body.env_digest`. A tampered environment field
(e.g. a swapped `image_digest`) then fails verification — the binding becomes **checkable**,
not merely signed-opaque.

### 4. Capturing the inputs

- **agent_command:** already available at run time in all three run paths (`run`, `run-tb`,
  `run-swebench`); thread it into the verdict build.
- **proctor_commit:** a `build.rs` writes `PROCTOR_GIT_COMMIT` (`git rev-parse --short HEAD`,
  fallback `"unknown"` when not a git checkout / no git); read via `env!`/`option_env!`.
- **image_ref / image_digest:** the `ociroot` (docker/podman) path already resolves a pinned
  image; record its reference + resolved `sha256` digest. `RootfsSpec::HostSystem` → `rootfs_kind
  = "host"`, image fields `None`.
- **policy_sha256 / spec_sha256:** hash the existing policy YAML / spec JSON bytes.

### 5. Versioning

Bump `bundle_version` → **2** (the signed-body inputs and the verify checks changed).
`verify-bundle` accepts v1 (3 checks, no env recompute) and v2 (4 checks). v1 bundles remain
verifiable; new runs emit v2.

## Non-goals

- Hashing the agent **binary contents** (we bind the command + image + Proctor build; agent-
  binary attestation is deeper provenance — a later item, and overlaps the v0.2 submission-
  provenance work).
- TEE / remote attestation (unchanged honesty boundary — still operator provenance, not host-
  integrity proof).

## Testing (TDD)

- `env_digest` recomputed from a round-tripped `Environment` equals the signed value.
- Tamper any `environment` field → `verify-bundle` fails on the new env check (named).
- Image-mode run records `image_ref` + non-empty `image_digest`; host-mode records
  `rootfs_kind = "host"` and `None` image fields.
- `proctor_commit` is populated (or a clean `"unknown"`); build works outside a git checkout.
- v1 bundle still verifies (3 checks); v2 bundle verifies (4 checks); regression: corpus / tb /
  swebench / e2e green.

## Docs

Update `docs/bundle-spec.md`: move agent-command + rootfs/image digest + Proctor build from
"not bound" to "bound + recorded"; document the 4th verify check + the `environment` section;
bump the version note; trim the Roadmap item to just agent-binary attestation + v0.2
submission-provenance.
