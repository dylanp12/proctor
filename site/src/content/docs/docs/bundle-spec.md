---
title: Bundle spec
description: What's in a Proctor bundle.json, what verify-bundle checks, and precisely what a third party can and cannot conclude from a signed run.
sidebar:
  order: 4
---

A Proctor run emits a portable `bundle.json` — the product of a run and the thing a third party
verifies. This page defines what's in it, what `proctor verify-bundle` checks, and **precisely
what a verifier can and cannot conclude**. An integrity artifact that implies more than it
proves is worse than none. (See a [real example bundle](/docs/example-bundle/).)

## What's in `bundle.json` (v2)

- **`verdict`** — the signed body (flat, `#[serde(flatten)]`): `task_id`, `pass`,
  `status` (`clean`|`compromised`), `reward`, `violations_head`, `violations_count`,
  `env_digest`, `artifacts_digest`, `proctor_version` — plus `public_key` and `signature`
  (ed25519 over RFC-8785 canonical JSON).
- **`violations`** — the hash-chained timeline records, in order.
- **`manifest`** — agent-log hashes (`{name, sha256, bytes}`). Logs are *hashed, not embedded*.
- **`environment`** — recorded in cleartext so a verifier can recompute `env_digest`:
  `agent_command`, `rootfs_kind`, `image_ref`, `proctor_version`, `proctor_commit`,
  `policy_sha256`, `spec_sha256`.

## What `verify-bundle` checks

`proctor verify-bundle --bundle <path> [--pubkey <hex>]` fails closed on any mismatch:

1. **Signature** valid for the body under the embedded `public_key` (and `== --pubkey` if given).
2. **Violation chain** head recomputed from `violations` equals `violations_head`, and the
   count matches.
3. **Artifacts** digest recomputed from the manifest equals `artifacts_digest`.
4. **Environment** digest recomputed from the recorded `environment` equals `env_digest`.

One signature binds the verdict, the timeline, the log hashes, and the environment.

## What a verifier CAN conclude

- The verdict and the full violation timeline are exactly what the signer signed.
- The run used the recorded agent command, policy, spec, image reference, and Proctor
  version/commit (confirmed by recomputing `env_digest`).
- With a **published operator key** (`--pubkey`): *which operator* produced this result.

## What a verifier CANNOT conclude

- Nothing about host integrity — the signature is **not remote attestation** (no TEE); it
  proves the bundle is unmodified relative to what that key signed, not that the operator's
  machine was clean.
- That the exact image *contents* or agent *binary* matched (the reference/command are bound;
  the deeper content hashes are a [roadmap](/docs/roadmap/) item).
- That the agent didn't cheat via a [non-goal class](/docs/honest-scope/) (scaffold injection,
  in-binary answers, grader-fooling).

## Publishing bundles (operators)

Generate a stable key once (`proctor keygen`), **publish the pubkey**, run submissions under
Proctor with it, and attach `bundle.json` to each result. Verifiers run
`proctor verify-bundle --bundle <file> --pubkey <your published hex>`. A leaderboard backed by
verifiable bundles is auditable, not "trust me."

`bundle_version` is `2`; v1 bundles still verify on the original three checks.
