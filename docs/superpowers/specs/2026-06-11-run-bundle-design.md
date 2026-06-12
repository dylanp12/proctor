# Signed run-bundle + verify-bundle — Design Spec

**Date:** 2026-06-11
**Status:** Draft for review
**Sub-project:** #3 of the productionization program.

## Summary

Package a Proctor run into one portable, self-contained, independently
verifiable artifact — `bundle.json` — and add `proctor verify-bundle` that
re-checks everything a third party needs to trust the result: the ed25519
signature, the violation hash-chain (bound to the signed verdict), and the
agent-log hashes. Add a stable operator signing key so a signature proves
"operator X produced this", not just "internally consistent".

## Context

Sub-project #3 of the program (done: #1 SWE-bench adapter, #2 grader network;
remaining after this: #4 GitHub Action / CI wrapper, #5 release & packaging, #6
full SWE-bench harness). Today a run emits `verdict.json` (signed) and
`violations.jsonl` (hash-chained) as **separate files with no binding at verify
time** — `proctor verify` only checks the verdict signature, never that the
timeline or logs match what was signed. And run commands mostly mint a **fresh
key per run**, so a signature only proves post-signing immutability, not
provenance.

## Goals

- `bundle.json`: a single file embedding the signed verdict, the violation
  records, and a manifest of agent-log hashes.
- The log hashes are bound to the **existing** verdict signature via a new
  signed `artifacts_digest` field — no second signature.
- `proctor verify-bundle --bundle <path> [--pubkey <hex>]` that checks:
  signature validity, the recomputed chain head/count against the signed
  verdict, and the recomputed artifacts digest against the manifest.
- A stable operator key (`--signing-key <file>` / `PROCTOR_SIGNING_SEED`),
  fresh-and-save fallback; used by all run commands. A `proctor keygen` helper.
- The loose `verdict.json` / `violations.jsonl` keep being written (no regression
  to existing tests/reports); `bundle.json` is the new portable artifact.

## Non-goals

- Tarball/zip packaging (chosen: single JSON, no archive dependency).
- Embedding logs inline (chosen: hashes only; logs stay in the run dir).
- A second bundle-level signature (chosen: bind via the verdict signature).
- Remote attestation / TEE / key custody infrastructure — the signature proves
  operator provenance against a published pubkey, nothing stronger (unchanged
  honesty boundary from the viability review).
- Repacking arbitrary old run dirs into a bundle (`proctor bundle <dir>`) — the
  run commands emit `bundle.json` directly; a standalone repacker is YAGNI.

## Architecture

### `proctor-verdict::bundle` (new module)

```rust
pub struct Bundle {
    pub bundle_version: u32,        // 1
    pub verdict: Verdict,          // full signed verdict (body + public_key + signature)
    pub violations: Vec<serde_json::Value>, // the violations.jsonl records, in order
    pub manifest: Manifest,
}
pub struct Manifest { pub artifacts: Vec<Artifact> }
pub struct Artifact { pub name: String, pub sha256: String, pub bytes: u64 }
```

- `Bundle::build(verdict, violations_path, artifacts: &[(name, host_path)]) -> Result<Bundle>`
  — read the violation records from `violations_path`, hash each artifact file.
- `save(path)` / `load(path)` via `serde_json`.
- `verify(&self, expected_pubkey: Option<&str>) -> Result<(), BundleError>`:
  1. `verdict.verify(verdict.public_key)`; if `expected_pubkey` is `Some`, also
     require `verdict.public_key == expected_pubkey`.
  2. recompute the chain from `violations` (reusing the monitor's `next_hash`
     logic — exposed as `chain::head_of(records)` so `proctor-verdict` doesn't
     duplicate it); require head `== verdict.body.violations_head` and
     `violations.len() == verdict.body.violations_count`.
  3. recompute `artifacts_digest` from `manifest.artifacts`; require
     `== verdict.body.artifacts_digest`.

To avoid `proctor-verdict` depending on `proctor-monitor`, the chain
head-recompute used by `verify` lives where the digest logic already is: add a
small pure helper `chain_head(records: &[serde_json::Value]) -> String` in
`proctor-verdict::digest` (it mirrors `monitor::chain::next_hash`:
`SHA256(prev || canonical(record-without-chain-field))`). `proctor-monitor`'s
writer stays the source of truth for *writing*; this is the *reading*/verify
side. (Both are covered by tests that assert they agree on a known vector.)

### `VerdictBody` change

Add `artifacts_digest: String` to the signed body and to `VerdictBuilder`.
`artifacts_digest = digest::env_digest(&[(name, sha256_hex.as_bytes()), ...])`
over the sorted artifact list (empty list → its well-defined empty digest). The
canonical-JSON signing automatically covers the new field.

### Signing — stable key

`sign::resolve_signer(explicit_seed_hex: Option<&str>, out_dir: &Path) -> Result<Signer>`:
1. `explicit_seed_hex` (from `--signing-key` file contents or `run --signing-seed`)
   → `Signer::from_bytes`.
2. else `PROCTOR_SIGNING_SEED` env (hex) → `Signer::from_bytes`.
3. else generate a fresh `Signer` and write `out_dir/signing-seed.hex` (today's
   behavior).
All three run commands call this. `proctor keygen` prints a fresh seed hex and
its pubkey hex (operator stores the seed, publishes the pubkey).

### CLI

- run commands additionally write `out/bundle.json` (built from the verdict +
  `out/violations.jsonl` + the agent logs in `out/agent-session/`).
- `proctor verify-bundle --bundle <path> [--pubkey <hex>]` → exit 0 + summary on
  success; non-zero + which check failed otherwise.
- `proctor keygen` → prints `seed=<hex>` and `pubkey=<hex>`.

## Data flow

run/run-tb/run-swebench: agent runs → violations finalized → hash agent logs →
build `artifacts_digest` → sign verdict (stable key) → write verdict.json,
violations.jsonl, **bundle.json**. verify-bundle: load bundle → 3 checks → report.

## Error handling — fail closed

`verify-bundle` returns a non-zero exit and names the first failed check
(`signature` / `chain` / `count` / `artifacts` / `pubkey-mismatch`). A malformed
bundle is a parse error, not a pass. `resolve_signer` errors on a malformed
seed (wrong length / non-hex) rather than silently generating a fresh key, so a
mis-set `PROCTOR_SIGNING_SEED` fails loudly.

## Testing

- **`bundle` unit/integration:** round-trip save/load; `verify` passes on a
  good bundle; **fails** when — a violation record is mutated (chain/head
  mismatch), `violations_count` is forged, a manifest log hash is changed
  (`artifacts_digest` mismatch), the signature is altered, or `--pubkey` does
  not match.
- **chain agreement:** `digest::chain_head` over records equals
  `monitor::chain` head for the same violations (shared known vector), so the
  read and write sides cannot drift.
- **stable key:** `resolve_signer` with the same seed (explicit and via env)
  yields the same pubkey across two calls; a malformed seed errors.
- **CLI e2e:** `proctor run` → `bundle.json` exists → `verify-bundle` exits 0;
  byte-tamper a violation in the bundle → `verify-bundle` exits non-zero. With a
  stable `PROCTOR_SIGNING_SEED`, two runs share a pubkey and both verify against
  it.
- **Regression:** existing verdict tests updated for the new `artifacts_digest`
  field; `verify`, corpus, e2e, tb, swebench tests stay green.

## Open questions / risks

- **Chain logic duplication.** Recompute lives in `proctor-verdict::digest`
  (verify side) and `proctor-monitor::chain` (write side). Mitigation: a shared
  test vector both must satisfy. (Alternative — make `proctor-verdict` depend on
  `proctor-monitor` — rejected to keep `verdict` dependency-light.) Resolved:
  duplicate + cross-test.
- **`bundle.json` size.** Bounded: verdict + violation records + a few hashes.
  Large violation counts grow it linearly; acceptable (the timeline is the point).
