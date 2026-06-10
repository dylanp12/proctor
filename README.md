# Proctor

**A tamper-proof execution sandbox for trustworthy AI coding-agent benchmarks.**

AI coding-agent benchmarks are being gamed. A April 2026 study found **1,000+ validated cheating
instances across 9 major benchmarks** — agents reading the test oracle (`cat /tests/…`), running
`git log` to find and copy the fix commit, `curl`-ing the solution from the internet, or just printing
`PASS`. De-cheating moved one top agent from 1st to 14th place. Every one of these exploits is a
sandboxing / access-control failure, not a modeling one.

Proctor runs a benchmark task under enforced OS-level isolation so the agent **physically cannot reach
the answer**, and emits a signed verdict plus a tamper-evident log of every cheat it *attempted*.

```
proctor run --task ./task --agent "my-agent --solve" --policy ./policy.yaml
# -> verdict.json      { "pass": false, "status": "compromised", ... }
# -> violations.jsonl  [ { "step": 14, "kind": "masked_read", "path": "/tests/oracle.py" }, ... ]
```

## How it works (v1)

- the agent runs in a sandbox where the oracle/test files **aren't mounted**, the **network is cut**,
  and the repo is **sanitized to the base commit** — so the documented cheats fail *by construction*,
  not by detection
- every attempted violation is recorded (tamper-evident audit timeline)
- the grader runs **isolated**, against the true oracle the agent never saw

The design goal is a *general, benchmark-agnostic standard* — Terminal-Bench is the first adapter;
SWE-bench and RL-training integrations follow.

> **Status:** early, in active development. Linux, Rust. See **[CLAUDE.md](CLAUDE.md)** for the full
> design, roadmap, and reasoning, and **[the spec](docs/superpowers/specs/2026-06-09-proctor-design.md)**.

## License

[MIT](LICENSE).
