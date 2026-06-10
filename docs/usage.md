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
