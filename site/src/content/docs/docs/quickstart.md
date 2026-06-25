---
title: Quickstart
description: Install Proctor and verify in 60 seconds that documented in-sandbox benchmark cheats are blocked by construction.
sidebar:
  order: 2
---

Proctor is Rust, Linux-only, and unprivileged (no root, no VM, no daemon).

## Verify the claim yourself (60 seconds)

The corpus is the proof: documented in-sandbox cheat classes, each replayed as a test that
plants a random nonce as the "answer" and asserts the agent never sees it.

```sh
git clone https://github.com/dylanp12/proctor && cd proctor
./scripts/dev-setup.sh        # links libseccomp for the build
# Ubuntu 24.04 (and the GitHub CI runner) disable unprivileged user namespaces by
# default — enable once, or every sandbox run fails:
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
cargo test -p proctor-cli --test corpus_test -- --nocapture
```

## Install the prebuilt binary

```sh
gh release download v0.1.1 --repo dylanp12/proctor \
  --pattern 'proctor-x86_64-unknown-linux-gnu.tar.gz*'
sha256sum -c proctor-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf proctor-x86_64-unknown-linux-gnu.tar.gz
sudo install proctor-x86_64-unknown-linux-gnu/proctor /usr/local/bin/
proctor probe   # confirm your host can sandbox
```

Needs `libseccomp2` at runtime (default on most distros; `sudo apt-get install -y libseccomp2`
otherwise) and Linux ≥ 5.11 with unprivileged user namespaces.

## Run a task

```sh
proctor run --task ./task --agent "my-agent --solve" --policy ./policy.yaml
# -> verdict.json   { "pass": true, "status": "compromised", ... }
# -> bundle.json    signed; check it with:
proctor verify-bundle --bundle out/bundle.json
```

Benchmark adapters: `proctor run-tb` (Terminal-Bench / Harbor) and `proctor run-swebench`
(SWE-bench) run existing tasks unmodified. Or drop the **GitHub Action** into your CI.
