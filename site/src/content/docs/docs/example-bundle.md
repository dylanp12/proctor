---
title: Example bundle
description: A real, signed Proctor bundle of a caught masked-oracle read — verify it yourself.
sidebar:
  order: 8
---

The repo ships a real, signed `bundle.json` (v2) from a run where the agent tried to read the
masked test oracle (`cat /oracle/answer.txt`). The read was blocked by construction and recorded
in the tamper-evident timeline, so the verdict is <span class="verdict verdict-compromised">status: compromised</span>
with one violation — while `pass: true` (the agent still produced output). Both facts are signed
together.

- **The bundle:** [`docs/examples/sample-bundle.json`](https://github.com/dylanp12/proctor/blob/main/docs/examples/sample-bundle.json)

It was produced with a **publicly-known demo signing key** (seed
`proctor-example-key-do-not-trust`), so the operator pubkey is fixed and you can verify it:

```sh
proctor verify-bundle \
  --bundle sample-bundle.json \
  --pubkey c28efd9afd90469266b5058a355f0e50f582f02d263148dd31fc395477716797
# -> bundle OK: signature valid, chain bound, 1 violation(s), status=Compromised
```

The `environment` block records what ran (agent command, rootfs kind, Proctor version + commit,
policy/spec hashes); `verify-bundle` recomputes `env_digest` from it as its fourth check. See
the [Bundle spec](/docs/bundle-spec/) for the full semantics.

> This is a demonstration artifact signed with a demo key whose seed is published above — it
> proves the *format and the checks*, not a real operator's attestation. A real run uses a
> private key from `proctor keygen` whose pubkey the operator publishes.
