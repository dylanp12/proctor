# Proctor usage

## Prerequisites

- Linux ≥ 5.11 with **unprivileged user namespaces** enabled
- C `libseccomp` ≥ 2.5 runtime (the build links it via `scripts/dev-setup.sh`,
  or install `libseccomp-dev`)
- `git` on `PATH`
- Ubuntu 24.04 / GitHub CI: `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`

Check the host is capable:

```
cargo run -p proctor-cli -- probe
# Caps { userns: true, overlayfs: true, seccomp: true }
```

If any capability is false, `proctor run` fails closed before the agent starts.

## `proctor run` — generic task

A task directory has:

```
task/
  workspace/      materialized for the agent (the working tree)
  oracle/         the true oracle, grader-only — never shown to the agent
  grade.sh        the grade command (exit 0 = pass), run in the grader sandbox
```

with a policy file:

```yaml
version: 1
workspace: { mount_at: /workspace }
forbidden:
  reads: [/oracle]            # absolute in-sandbox paths; masked + logged
  writes: [/logs/verifier]    # write-deny class (reward-file pre-write)
network: { mode: deny }       # deny | allowlist (allow: ["api.anthropic.com:443"])
env: { allow: [] }            # env passlist; default empty
limits: { wall_time_secs: 1800, pids: 512, memory_bytes: 2147483648 }
```

Run it:

```
proctor run --task ./task --agent "sh /workspace/solve.sh" \
            --policy ./policy.yaml --out ./out
```

Outputs in `./out`: `verdict.json` (signed), `violations.jsonl` (hash-chained
attempt log), `signing-seed.hex` (the generated key; pass `--signing-seed <hex>`
to reuse one), plus the agent and grader session dirs.

## `proctor verify` — check a verdict

```
proctor verify --verdict ./out/verdict.json --pubkey <hex from verdict.public_key>
# verdict OK: signature valid, status=Compromised
```

Verification recomputes the signature over the canonical body, so any edited
field, hidden violation count, or wrong key fails.

## `proctor verify-bundle` — check a portable run bundle

Every run also writes `out/bundle.json`: one self-contained file with the signed
verdict, the violation records, and a manifest of agent-log hashes — all bound
under the verdict's single signature. Hand it to anyone:

```
proctor verify-bundle --bundle ./out/bundle.json [--pubkey <operator-hex>]
# bundle OK: signature valid, chain bound, 1 violation(s), status=Compromised
```

It re-checks the signature, recomputes the violation hash-chain and binds its
head/count to the signed verdict, and binds the manifest's log hashes — strictly
more than `verify`. With `--pubkey`, it also confirms the operator's identity.

## Stable operator key

So a signature proves *operator X produced this* (not just "internally
consistent"), use one keypair across runs:

```
proctor keygen                       # prints seed=<hex> and pubkey=<hex>
export PROCTOR_SIGNING_SEED=<seed>   # all run commands sign with it
# publish the pubkey; verifiers pass it to `verify-bundle --pubkey`
```

Without it, each run mints a fresh key (saved to `out/signing-seed.hex`) — the
bundle is self-consistent but not tied to a known operator.

## `proctor run-tb` — Terminal-Bench (Harbor) task

Point it at a Harbor-format task dir (`task.toml`, `instruction.md`,
`environment/`, `solution/`, `tests/test.sh`). The adapter masks `/tests` and
`/solution`, runs the agent in `/app`, then grades with the task's own
`tests/test.sh` reading the Harbor `/logs/verifier/reward.json`:

```
proctor run-tb --task ./tb-task --agent "my-agent --solve" --out ./out
# add --image to build the task's docker environment as the rootfs
```

Without `--image` (or without docker), the host system rootfs is used.

## Interpreting the verdict

- `status: clean` — the agent attempted no in-sandbox cheat.
- `status: compromised` — at least one attempt was logged; see `violations.jsonl`.
  A compromised run is still graded (the agent may have solved it *and* cheated);
  `pass` reflects the grade, `status` reflects integrity.

## `action.yml` — run Proctor in GitHub Actions

The repo ships a composite action that builds Proctor, runs a task under
isolation, verifies the bundle, and uploads it as a build artifact.

```yaml
- uses: actions/checkout@v5
- uses: dylanp12/proctor@main          # external repos: also set proctor-ref
  with:
    run-args: run --task ./task --agent "sh /workspace/solve.sh" --policy ./policy.yaml
    out: proctor-out
    proctor-ref: main                  # clone+build proctor (omit inside this repo)
    signing-seed: ${{ secrets.PROCTOR_SIGNING_SEED }}   # optional stable key
    pubkey: <operator-hex>             # optional: also assert the signer
```

Outputs: `pass`, `verdict-status`, `violations`, `bundle-path`. The action fails
the job if isolation can't be established, the run errors, or `verify-bundle`
fails. `signing-seed` is the **private** key — supply it only via an Actions
secret; the upload lists files explicitly so an ephemeral run's
`signing-seed.hex` is never published.

The `demo.yml` workflow dogfoods the action on a synthetic task and the real
Terminal-Bench task (honest + cheat) and publishes the bundles as artifacts.
