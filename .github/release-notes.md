**Proctor** — a tamper-proof execution sandbox for trustworthy AI coding-agent benchmarks.

## Install

Download the prebuilt binary (Linux x86_64, glibc ≥ 2.35) and verify it:

```
gh release download <this-tag> --repo dylanp12/proctor \
  --pattern 'proctor-x86_64-unknown-linux-gnu.tar.gz*'
sha256sum -c proctor-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf proctor-x86_64-unknown-linux-gnu.tar.gz
sudo install proctor-x86_64-unknown-linux-gnu/proctor /usr/local/bin/
proctor --version
```

Requires `libseccomp2` (the runtime library) present — installed by default on
most distributions. See the README for full prerequisites and usage.
