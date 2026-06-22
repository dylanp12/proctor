# Proctor bundle spec (`bundle.json` v2)

A Proctor run emits a portable `bundle.json` — the product of a run and the thing a third
party verifies. This document defines what's in it, what `proctor verify-bundle` checks, and
**precisely what a verifier can and cannot conclude**. The scope discipline here is
deliberate: an integrity artifact that implies more than it proves is worse than none.

## What's in `bundle.json`

```jsonc
{
  "bundle_version": 2,
  "verdict": {
    // the signed body fields are flat on the verdict object (#[serde(flatten)]):
    "task_id":          "…",
    "pass":             true,
    "status":           "clean" | "compromised",
    "reward":           0.0,          // optional (benchmark-defined)
    "violations_head":  "<sha256>",   // head of the hash-chained violation timeline
    "violations_count": 1,
    "env_digest":       "<sha256>",   // = digest of the `environment` section below
    "artifacts_digest": "<sha256>",   // binds the agent-log hashes
    "proctor_version":  "0.1.0",
    "public_key":       "<ed25519 pubkey hex>",
    "signature":        "<ed25519 signature hex over canonical(body)>"
  },
  "violations": [ { "step": 8, "kind": "masked_read", "path": "/oracle/answer.txt",
                    "syscall": "openat", "chain": "<sha256>" }, … ],
  "manifest": { "artifacts": [ { "name": "agent-stdout.log",
                                 "sha256": "<sha256>", "bytes": 1234 }, … ] },
  "environment": {                    // recorded in cleartext so a verifier can recompute env_digest
    "agent_command":  "my-agent --solve",
    "rootfs_kind":    "host" | "image",
    "image_ref":      "ghcr.io/…/instance",   // present in image mode
    "proctor_version":"0.1.0",
    "proctor_commit": "<git short sha | unknown>",
    "policy_sha256":  "<sha256 of the policy>",
    "spec_sha256":    "<sha256 of the sandbox spec>"
  }
}
```

The agent **logs are not embedded** — only their hashes (in `manifest`). The logs stay in the
run directory; ship them alongside the bundle if a verifier needs the content.

## What `verify-bundle` checks

`proctor verify-bundle --bundle <path> [--pubkey <hex>]` runs these checks and fails closed
(non-zero exit, naming the first failure) on any mismatch or malformed input:

1. **Signature.** The ed25519 `signature` is valid for the body (RFC-8785 canonical JSON)
   under the embedded `public_key`. If `--pubkey` is given, it must equal the embedded key.
2. **Violation chain.** The chain head recomputed from `violations` equals
   `violations_head`, **and** `violations.len() == violations_count`.
3. **Artifacts.** The digest recomputed from `manifest.artifacts` equals `artifacts_digest`.
4. **Environment (v2+).** The digest recomputed from the recorded `environment` equals the
   signed `env_digest`. (v1 bundles carry no `environment` and skip this check.)

All four quantities live inside the single signed body, so one signature binds the verdict,
the violation timeline, the agent-log hashes, and the run environment.

## What is bound (and what is not)

**Bound and independently recomputable** (recorded in `environment`, folded into the signed
`env_digest`): the **agent command**, the **rootfs kind** (host/image) and **image reference**
(image mode), the **Proctor version and build commit**, and the **policy and sandbox-spec
hashes**. A verifier recomputes `env_digest` from these and confirms it matches the signature.

**Not yet bound** (documented limitations, not hidden gaps):

- **The image *content* digest.** `image_ref` and `rootfs_kind` are bound, but the resolved
  content hash of the container image is not yet pinned into the bundle (see Roadmap).
- **The agent *binary* contents.** The command is bound; a hash of the agent executable is not.
- **Log content** is bound only by hash — a verifier confirms the logs match the manifest, not
  that their content is benign.

## What a verifier CAN conclude from a passing `verify-bundle`

- The verdict (`pass`, `status`, `reward`) and the **entire violation timeline** (ordered,
  complete, count-checked) are exactly what the signer signed.
- The run used the recorded **agent command, policy, sandbox spec, image reference, and
  Proctor version/commit** — all confirmed by recomputing `env_digest`.
- The named artifacts have the recorded hashes; with the log files in hand, you can confirm
  they are the ones the verdict was signed over.
- **With a published operator key** (`--pubkey`): that **this specific operator** produced this
  exact result — provenance, not just internal consistency.

## What a verifier CANNOT conclude

- **Nothing about the operator's honesty or host integrity.** The signature proves the bundle
  is unmodified relative to what that key signed; it is **not remote attestation** — it does
  not prove the operator's machine, kernel, or build wasn't tampered with. (No TEE.)
- That the exact **image contents** or **agent binary** were as claimed (refs/commands are
  bound; the deeper content hashes are not — above).
- That the agent didn't cheat via a **non-goal class**: scaffold/prompt-injected answers,
  solutions baked into the agent binary, or grader-fooling. Proctor covers **in-sandbox answer
  access** only.
- Without a published pubkey, only **post-signing immutability** (not who produced it).

## Publishing bundles (for benchmark operators)

1. Generate a stable operator key once: `proctor keygen` → store the seed
   (`PROCTOR_SIGNING_SEED`), **publish the pubkey**.
2. Run submissions under Proctor with that key; attach `bundle.json` (and the run-dir logs, if
   content review is wanted) to each result.
3. Verifiers run `proctor verify-bundle --bundle <file> --pubkey <your published hex>` — exit 0
   means the result is authentic to your key and internally consistent.

## Versioning

`bundle_version` is `2` (adds the recorded `environment` + the 4th verify check). v1 bundles
(no `environment`) remain verifiable on checks 1–3. `verify-bundle` rejects a bundle whose
structure it doesn't understand rather than passing it.

## Roadmap (binding hardening)

- Pin the **resolved image content digest** (and an agent-**binary** hash) into `environment`,
  so a verifier confirms the exact image/binary, not just the reference/command.
- Submission-provenance (v0.2): capture + bind the agent's *inputs* (scaffold, instruction
  files), extending the bundle to cover the out-of-sandbox injection class.
