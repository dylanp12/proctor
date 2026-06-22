# Proctor bundle spec (`bundle.json` v1)

A Proctor run emits a portable `bundle.json` — the product of a run and the thing a third
party verifies. This document defines what's in it, what `proctor verify-bundle` checks, and
**precisely what a verifier can and cannot conclude**. The scope discipline here is
deliberate: an integrity artifact that implies more than it proves is worse than none.

## What's in `bundle.json`

```jsonc
{
  "bundle_version": 1,
  "verdict": {
    "body": {
      "task_id":          "…",        // the task identifier
      "pass":             true,        // did the agent's output satisfy the grader
      "status":           "clean" | "compromised",  // did it attempt a covered forbidden access
      "reward":           0.0,         // grader reward (benchmark-defined)
      "violations_head":  "<sha256>",  // head of the hash-chained violation timeline
      "violations_count": 1,
      "env_digest":       "<sha256>",  // binds the run inputs (see "What is bound")
      "artifacts_digest": "<sha256>"   // binds the agent-log hashes (see "What is bound")
    },
    "public_key": "<ed25519 pubkey hex>",
    "signature":  "<ed25519 signature hex over canonical(body)>"
  },
  "violations": [ { "step": 8, "kind": "masked_read", "path": "/oracle/answer.txt",
                    "syscall": "openat", "chain": "<sha256>" }, … ],  // the timeline, in order
  "manifest": { "artifacts": [ { "name": "agent-session/stdout.log",
                                 "sha256": "<sha256>", "bytes": 1234 }, … ] }
}
```

The agent **logs themselves are not embedded** — only their hashes (in `manifest`). The logs
stay in the run directory; ship them alongside the bundle if a verifier needs the content.

## What `verify-bundle` checks

`proctor verify-bundle --bundle <path> [--pubkey <hex>]` runs three checks and fails closed
(non-zero exit, naming the first failed check) on any mismatch or malformed input:

1. **Signature.** The ed25519 `signature` is valid for `body` (RFC-8785 canonical JSON) under
   the embedded `public_key`. If `--pubkey` is given, it must equal the embedded key.
2. **Violation chain.** The chain head recomputed from the `violations` records equals
   `body.violations_head`, **and** `violations.len() == body.violations_count`. (The chain is
   `head = SHA256(prev ‖ canonical(record-without-chain))`, folded from a fixed genesis.)
3. **Artifacts.** The digest recomputed from `manifest.artifacts` equals
   `body.artifacts_digest`.

Because all three quantities live inside the single signed `body`, one signature binds the
verdict, the full violation timeline, the run inputs, and the artifact hashes — no second
signature.

## What is bound (and what is not)

`env_digest` binds: **the policy** (the forbidden-access spec), **the task spec**, and **the
Proctor version**. `artifacts_digest` binds: **the agent-session log file hashes**.

Not yet bound (documented limitations, not hidden gaps):

- **The rootfs / container-image digest is not bound.** A run records its policy/spec/version
  but does not yet pin the image the agent ran in. (`tree_digest` exists to enable this; it's
  a planned hardening — see Roadmap.)
- **The exact agent command is not bound** into the signed body.
- The **log content** is bound only by hash — a verifier confirms the logs match the manifest,
  not that their content is benign.

## What a verifier CAN conclude from a passing `verify-bundle`

- The verdict (`pass`, `status`, `reward`) and the **entire violation timeline** (ordered,
  complete, count-checked) are exactly what the signer signed — nothing added, dropped, or
  reordered after signing.
- The run used the **policy + task spec + Proctor version** captured in `env_digest`.
- The named artifacts have the recorded hashes; if you also hold the log files, you can
  confirm they are the ones the verdict was signed over.
- **With a published operator key** (`--pubkey <published hex>`): that **this specific
  operator** produced this exact result — provenance, not just internal consistency.

## What a verifier CANNOT conclude

- **Nothing about the operator's honesty or host integrity.** The signature proves the bundle
  is unmodified relative to what that key signed; it is **not remote attestation** — it does
  not prove the operator's machine, kernel, or Proctor build wasn't tampered with. (No TEE.)
- That the **image/agent command** were as claimed (not yet bound — above).
- That the agent didn't cheat via a **non-goal class**: scaffold/prompt-injected answers,
  solutions baked into the agent binary, or grader-fooling (`PASS`-greps, mocks, hardcoded
  outputs). Proctor covers **in-sandbox answer access** only.
- Without a published pubkey, only **post-signing immutability** (a fresh per-run key proves
  the bundle wasn't edited after signing, not who produced it).

## Publishing bundles (for benchmark operators)

1. Generate a stable operator key once: `proctor keygen` → store the seed
   (`PROCTOR_SIGNING_SEED`), **publish the pubkey**.
2. Run submissions under Proctor with that key; attach `bundle.json` (and the run-dir logs, if
   content review is wanted) to each result.
3. Verifiers run `proctor verify-bundle --bundle <file> --pubkey <your published hex>` — exit 0
   means the result is authentic to your key and internally consistent.

A leaderboard whose entries carry verifiable Proctor bundles is auditable against a published
key, rather than taken on trust.

## Versioning

`bundle_version` is `1`. Additive fields may appear under the same version; a breaking change
to the signed-body shape or the verify checks increments it. `verify-bundle` rejects a bundle
whose structure it doesn't understand rather than passing it.

## Roadmap (binding hardening)

- Bind the **rootfs/image digest** (via `tree_digest`) and the **agent command** into
  `env_digest`, so a verifier can confirm the *environment*, not just the policy/spec/version.
- Submission-provenance (v0.2): capture + bind the agent's *inputs* (scaffold, instruction
  files, binary), extending the bundle to cover the out-of-sandbox injection class.
