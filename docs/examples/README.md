# Example Proctor bundle

`sample-bundle.json` is a real, signed `bundle.json` (v2) from a `proctor run` in which the
agent tried to read the masked test oracle (`cat /oracle/answer.txt`). The read was blocked by
construction (the oracle isn't in the agent's mount namespace) and recorded in the
tamper-evident timeline — so the verdict is `status: compromised` with one violation, while
`pass: true` (the agent still produced output). Both facts are signed together.

It was produced with a **publicly-known demo signing key** (seed
`proctor-example-key-do-not-trust`), so the operator pubkey is fixed and you can verify it:

```
proctor verify-bundle \
  --bundle sample-bundle.json \
  --pubkey c28efd9afd90469266b5058a355f0e50f582f02d263148dd31fc395477716797
# -> bundle OK: signature valid, chain bound, 1 violation(s), status=Compromised
```

The `environment` section records what ran (agent command, rootfs kind, Proctor version +
build commit, policy/spec hashes); `verify-bundle` recomputes `env_digest` from it as its
fourth check. See [`../bundle-spec.md`](../bundle-spec.md) for the full semantics of what a
verifier can and cannot conclude.

> This is a demonstration artifact signed with a demo key whose seed is published above — it
> proves the *format and the checks*, not a real operator's attestation. A real run uses a
> private operator key (`proctor keygen`) whose pubkey the operator publishes.
