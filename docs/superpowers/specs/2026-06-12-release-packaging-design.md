# Release & packaging — Design Spec

**Date:** 2026-06-12
**Status:** Draft for review
**Sub-project:** #5 of the productionization program.

## Summary

Make Proctor installable without cloning the repo, and let the composite action
consume a prebuilt binary instead of building from source. A tag-triggered
release workflow builds a glibc-dynamic Linux `x86_64` `proctor` binary on
`ubuntu-22.04` (broad glibc compat), packages it with a SHA256 checksum, and
publishes it to a GitHub Release. The README documents both install paths
(download the binary, or `cargo install --git`). `action.yml` gains an optional
`proctor-version` fast-path that downloads + checksum-verifies the release binary
and skips the ~1 min build. Finally, cut **v0.1.0**.

## Context

Sub-project #5 of the program (done: #1 SWE-bench adapter, #2 grader network, #3
signed run-bundle, #4 GitHub Action / CI wrapper; remaining after this: #6 full
SWE-bench harness). Today the only way to get `proctor` is to clone and
`cargo build`; the #4 action builds from source on every run (acceptable, but the
#4 spec explicitly deferred a prebuilt-binary fast-path to #5). The workspace is
already at `version = "0.1.0"`, `license = "MIT"`, `repository` set; the binary
target is named `proctor` (in `proctor-cli`); a `LICENSE` file exists.

**Load-bearing constraint:** the binary **dynamically links `libseccomp`**
(the `libseccomp` crate is FFI to the C library). Build time needs
`libseccomp-dev` (provides the `libseccomp.so` link symlink); runtime needs
`libseccomp.so.2` (the `libseccomp2` package), which is near-ubiquitous on Linux
and is already a documented prerequisite. This is why the prebuilt binary is
glibc-dynamic, not a hand-wave "static binary".

## Goals

- **`.github/workflows/release.yml`** — on `push` of a `v*` tag, build and publish
  a GitHub Release with `proctor-x86_64-unknown-linux-gnu.tar.gz` (binary +
  `LICENSE` + `README.md`) and a matching `.sha256`.
- **`action.yml` `proctor-version` input** — when set, download that release's
  tarball, verify its checksum, extract, and use it (skipping toolchain + clone +
  build); when empty, build from source exactly as today.
- **Install docs** — README "Install" section: prebuilt-binary download (with
  checksum verification) and `cargo install --git`; `usage.md` documents the
  `proctor-version` fast-path.
- **`demo.yml` test hook** — a `workflow_dispatch` input `proctor-version`,
  threaded into the action (default empty → unchanged behavior), so the fast-path
  is exercisable on demand.
- **Cut v0.1.0** — tag `v0.1.0`, produce the release, verify the artifact.

## Non-goals

- **crates.io publishing** (`cargo install proctor-cli` from the registry) —
  rejected for v0.1.0: 8 interdependent workspace crates must be version-published
  in dependency order and the libseccomp C-dep adds friction. `cargo install --git`
  covers the build-it-yourself audience.
- **musl fully-static binary** — rejected for v0.1.0: removing the libseccomp/libc
  runtime dep requires building/vendoring a static `libseccomp.a` for musl; the
  target audience already runs Linux with libseccomp present. A future option.
- **Multi-arch / aarch64** — `x86_64-linux` only (the benchmark-runner audience).
- **A third-party release action** — use `gh release create` (preinstalled,
  no extra Node-deprecation surface) rather than `softprops/action-gh-release`.
- **Auto-bumping the version / changelog automation** — manual `v0.1.0` tag.

## Architecture

### `.github/workflows/release.yml` (new)

```yaml
name: release
on:
  push:
    tags: ['v*']
permissions:
  contents: write          # create the GitHub Release
jobs:
  release:
    runs-on: ubuntu-22.04  # build against older glibc for forward compat
    steps:
      - uses: actions/checkout@v5
      - run: |
          sudo apt-get update && sudo apt-get install -y libseccomp-dev
      - uses: dtolnay/rust-toolchain@stable
      - run: ./scripts/dev-setup.sh
      - run: cargo build --release -p proctor-cli
      - name: smoke
        run: ./target/release/proctor --version   # also proves libseccomp.so.2 loads
      - name: package
        run: |
          set -euo pipefail
          NAME=proctor-x86_64-unknown-linux-gnu
          mkdir -p "dist/$NAME"
          cp target/release/proctor LICENSE README.md "dist/$NAME/"
          tar -C dist -czf "dist/$NAME.tar.gz" "$NAME"
          ( cd dist && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256" )
      - name: publish
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          set -euo pipefail
          TAG="${GITHUB_REF_NAME}"
          gh release create "$TAG" \
            dist/proctor-x86_64-unknown-linux-gnu.tar.gz \
            dist/proctor-x86_64-unknown-linux-gnu.tar.gz.sha256 \
            --title "$TAG" --notes "$(cat .github/release-notes.md)"
```

`.github/release-notes.md` is a short checked-in notes body (install snippet +
the corpus/demo claim + the libseccomp2 runtime note). Keeping it in-repo avoids
an unreadable heredoc in YAML and lets the notes be reviewed like code.

### `action.yml` change — `proctor-version` fast-path

- Add input `proctor-version` (default `""`).
- Make the source-build steps conditional on `inputs.proctor-version == ''`:
  `rust toolchain`, `checkout proctor (proctor-ref)`, `resolve source path`,
  `build proctor`.
- `host deps` stays **unconditional** (runtime libseccomp2 + the apparmor sysctl
  are needed either way).
- New step, `if: inputs.proctor-version != ''`:
  ```bash
  set -euo pipefail
  NAME=proctor-x86_64-unknown-linux-gnu
  base="https://github.com/dylanp12/proctor/releases/download/${PROCTOR_VERSION}"
  curl -fsSL "$base/$NAME.tar.gz"        -o "$NAME.tar.gz"
  curl -fsSL "$base/$NAME.tar.gz.sha256" -o "$NAME.tar.gz.sha256"
  sha256sum -c "$NAME.tar.gz.sha256"      # fail closed on mismatch
  tar -xzf "$NAME.tar.gz"
  echo "PROCTOR_BIN=$PWD/$NAME/proctor" >> "$GITHUB_ENV"
  ```
- `run proctor` / `verify bundle` / `read verdict outputs` / `upload bundle`
  are unchanged (they consume `PROCTOR_BIN`).

### Docs

- **`README.md` — new "Install" section** (above "Building"):
  - Prebuilt: download `…tar.gz` + `.sha256` from the latest release,
    `sha256sum -c …`, extract, ensure `libseccomp2` is present, run.
  - From source: `sudo apt-get install -y libseccomp-dev` then
    `cargo install --git https://github.com/dylanp12/proctor proctor-cli`
    (the dev package provides the link-time `libseccomp.so`, so the repo-local
    `dev-setup.sh` symlink hack is **not** needed for an external `cargo install`).
- **`docs/usage.md`** — extend the action section with the `proctor-version`
  fast-path example.

### `demo.yml` change — fast-path test hook

Add `workflow_dispatch.inputs.proctor-version` (default `""`) and pass it to every
`uses: ./` step as `proctor-version: ${{ inputs.proctor-version || '' }}`. Normal
`push: main` runs leave it empty (build from source — unchanged); a manual
`gh workflow run demo.yml -f proctor-version=v0.1.0` exercises the prebuilt path.

## Data flow

Tag `vX.Y.Z` pushed → `release.yml` builds + packages + `gh release create` →
Release has `…tar.gz` + `.sha256`. Later, a consumer sets the action's
`proctor-version: vX.Y.Z` → action downloads + checksum-verifies + extracts the
binary → runs the task with it (no build).

## Error handling — fail closed

- Release job: `set -euo pipefail` in every script step; any failure → the job
  fails and **no Release is created** (the `publish` step is last).
- Action fast-path: `curl -f` (HTTP errors fail) and `sha256sum -c` (mismatch
  fails) → the step errors before any run; an unverified binary is never executed.
- `cargo install --git` without `libseccomp-dev` fails at link time with a clear
  `-lseccomp` error; the docs state the prerequisite up front.

## Testing / verification

Packaging/release is verified on the real platform (a workflow on a tag) plus a
local dry-run of the packaging:

1. **Local:** `cargo build --release -p proctor-cli` then run the `package` block
   against `target/release/proctor` in a tempdir; confirm the tarball extracts and
   `sha256sum -c` passes. `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"`.
2. **Release:** push `v0.1.0`; watch `release.yml` to green; confirm
   `gh release view v0.1.0` lists both assets; download the tarball + `.sha256`,
   `sha256sum -c`, extract, and run `./proctor --version` → `proctor 0.1.0`.
3. **Fast-path:** `gh workflow run demo.yml -f proctor-version=v0.1.0`; watch it
   green; confirm the "obtain prebuilt" step ran (and the build steps were
   skipped) and the produced bundle still `verify-bundle`s.
4. **Regression:** a normal `push: main` still runs `demo.yml` building from
   source (empty `proctor-version`); `ci.yml` unaffected.

## Open questions / risks

- **glibc floor.** Building on `ubuntu-22.04` targets glibc ≥ 2.35; consumers on
  older distros must `cargo install` instead. Acceptable for the audience;
  documented.
- **Tag re-runs.** `gh release create` fails if the tag's release already exists;
  re-releasing a version requires deleting the release first. Acceptable (versions
  are immutable by intent).
- **Release notes drift.** `.github/release-notes.md` is generic (install +
  claim), not per-version changelog — fine for v0.1.0; a future enhancement can
  generate per-tag notes.
- **Fast-path availability.** `proctor-version` only works after that release
  exists; an unknown version fails closed at `curl -f`. The repo's own `demo.yml`
  defaults to source-build so it never depends on a release existing.
