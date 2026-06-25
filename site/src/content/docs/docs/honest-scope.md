---
title: Honest scope
description: What Proctor blocks (in-sandbox access cheats) and what it deliberately does not — stated plainly, because an integrity tool that overclaims is worse than none.
sidebar:
  order: 5
---

Proctor blocks **in-sandbox access** cheats — reaching the answer through the filesystem, git
history, the network, or the process table — by construction, and logs every covered attempt.
It does **not** pretend to do more.

## Deliberate non-goals

| Cheat class | Why OS isolation can't block it |
| --- | --- |
| Scaffold-injected answer keys (`AGENTS.md`) | the answer arrives inside the agent's prompt, from *outside* the sandbox |
| Solutions baked into the agent binary | the agent carries the answer in; no mount/netns/git mechanism sees it |
| Grader-fooling (`PASS`-greps, hardcoded outputs, mocks) | a grader-hardening problem, not an isolation one — a later phase |

These need **submission provenance** or **grader hardening**, not agent-side isolation.
Claiming otherwise would be falsified on contact.

## A note on the headline number

The study's most-cited result — a top agent falling from **81.8% → 71.7%** and **1st → 14th**
once de-cheated — came from *scaffold-injected answer keys*, which is in the non-goal list
above. The access cheats Proctor kills by construction are the 415/429 oracle reads,
git-mining, `curl`, and reward-file writes. We're explicit about the difference rather than
borrowing a number we don't earn.

## What a verifier can rely on

That precision is the point: a Proctor [bundle](/docs/bundle-spec/) lets a third party confirm
exactly what was isolated and what the agent attempted — no more, no less. Submission
provenance (binding the agent's *inputs*) is the [v0.2 direction](/docs/roadmap/).
