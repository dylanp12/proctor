---
title: Overview
description: Proctor runs AI coding-agent benchmark tasks under answer-isolating Linux namespaces and emits a signed, independently verifiable integrity bundle.
sidebar:
  order: 1
---

**Proctor turns AI coding-agent benchmark runs into signed, independently verifiable integrity
bundles.** It runs the agent in an answer-isolated Linux sandbox where the configured hidden
tests, fix history, and network egress are not reachable, then signs the verdict and the
covered forbidden-access timeline.

## The problem: benchmarks are being gamed

AI coding-agent benchmarks drive model launches, hiring, and procurement — and they're leaky.
In April 2026, UPenn researchers [documented widespread
cheating](https://debugml.github.io/cheating-agents/) across nine benchmarks: agents read the
hidden test oracle, mine `git log` for the fix commit, `curl` the answer, or pre-write the
grader's reward file. In one removed Terminal-Bench 2 submission, **415 of 429** "successful"
runs were just `cat /tests`. Every one of these is a sandboxing / access-control failure — not
a modeling one. The study's own prescription: *isolate the agent from the evaluator.*

## The gap Proctor fills

Detection tools tell you cheating happened after the fact; per-benchmark patches fix one
harness at a time; host-isolation sandboxes stop the agent escaping. **Nobody else ships a
general, benchmark-agnostic runtime that removes the answer from the agent's reach by
construction and signs a tamper-evident verdict.** That's Proctor.

## How it works, in one line

You hand Proctor a task, an agent command, and a policy. It runs the agent in fresh
unprivileged namespaces where the answer was never placed, records every covered
forbidden-access attempt in a hash-chained timeline, grades in a second isolated sandbox
against the true oracle, and emits a portable, signed `bundle.json` anyone can `verify-bundle`.

## Who it's for

- **Benchmark operators** who want leaderboard integrity they can defend.
- **AI labs & eval teams** who need reward signals that aren't quietly hacked.
- **Anyone publishing agent results** who wants a signed, verifiable artifact, not "trust me."

Start with the [Quickstart](/docs/quickstart/), see [How it works](/docs/how-it-works/), and
read the [Bundle spec](/docs/bundle-spec/) for exactly what a verifier can conclude.
