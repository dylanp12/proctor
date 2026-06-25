---
title: Roadmap
description: What's next for Proctor — submission-provenance (v0.2), deeper environment binding, and more benchmark adapters.
sidebar:
  order: 7
---

Proctor v0.1.x ships by-construction in-sandbox answer isolation + signed, verifiable bundles.
The roadmap closes the gaps named in [Honest scope](/docs/honest-scope/), in priority order.

## v0.2 — attested submission provenance

The biggest documented cheat isolation can't stop is *out-of-sandbox* answer smuggling: answer
keys injected through the agent's scaffold (`AGENTS.md` — the class behind the study's 1st→14th
drop) or compiled into the agent binary. You can't mask an answer that was never reached for.
v0.2 attacks it from the other side: **capture and content-address every input the agent was
handed** (scaffold, instruction files, binary) and bind a signed *submission manifest* into the
bundle — turning "what was this agent fed?" into a verifiable fact. Same move as the violation
log, one layer up.

## Deeper environment binding

The [bundle](/docs/bundle-spec/) already binds the agent command, image *reference*, Proctor
version + commit, and policy/spec hashes. Next: pin the resolved **image content digest** and an
**agent-binary hash**, so a verifier confirms the exact image and binary, not just the
reference.

## More adapters & grader hardening (pulled by demand)

Additional benchmark adapters beyond Terminal-Bench and SWE-bench; and a later **grader
hardening** phase against `PASS`-greps, hardcoded outputs, and mocks — the complementary half to
answer isolation.

*Have a benchmark you'd want an adapter for, or an integrity gap we should prioritize?
[Open an issue.](https://github.com/dylanp12/proctor/issues)*
