# Release & packaging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish a prebuilt `proctor` binary via a tag-triggered GitHub Release, let the composite action consume it (`proctor-version` fast-path), document install, and cut v0.1.0.

**Architecture:** A `release.yml` workflow builds a glibc-dynamic linux x86_64 binary on ubuntu-22.04, packages it + a SHA256, and publishes with `gh release create`. `action.yml` gains a `proctor-version` input that `gh release download`s + checksum-verifies the binary (the repo is private, so auth via the job token), skipping the build. Docs + a `demo.yml` dispatch hook complete it; then tag v0.1.0.

**Tech Stack:** GitHub Actions, `gh` CLI (preinstalled), bash, the existing Rust `proctor` CLI.

---

## Spec

`docs/superpowers/specs/2026-06-12-release-packaging-design.md`.

## File Structure

- **Create `.github/release-notes.md`** — static release-notes body (install snippet + claim + libseccomp2 note).
- **Create `.github/workflows/release.yml`** — on `v*` tag: build → smoke → package → `gh release create`.
- **Modify `action.yml`** — add `proctor-version` input; gate build-chain steps on it; add a `gh release download` fast-path step.
- **Modify `.github/workflows/demo.yml`** — add `workflow_dispatch` input `proctor-version`, thread it to each `uses: ./`.
- **Modify `README.md`** — add an "Install" section.
- **Modify `docs/usage.md`** — add the `proctor-version` fast-path example.

## Pre-flight

- [ ] **Step 0: Confirm clean tree on `main`, #4 merged**

Run: `git status -sb && git log --oneline -3`
Expected: clean; top commits include the #5 spec and the #4 docs/badge commit.

---

### Task 1: Release workflow + notes

**Files:**
- Create: `.github/release-notes.md`
- Create: `.github/workflows/release.yml`

- [ ] **Step 1: Write `.github/release-notes.md`**

```markdown
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
```

- [ ] **Step 2: Write `.github/workflows/release.yml`**

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
      - name: host deps
        run: sudo apt-get update && sudo apt-get install -y libseccomp-dev
      - uses: dtolnay/rust-toolchain@stable
      - run: ./scripts/dev-setup.sh
      - run: cargo build --release -p proctor-cli
      - name: smoke
        run: ./target/release/proctor --version
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
          gh release create "$GITHUB_REF_NAME" \
            dist/proctor-x86_64-unknown-linux-gnu.tar.gz \
            dist/proctor-x86_64-unknown-linux-gnu.tar.gz.sha256 \
            --title "$GITHUB_REF_NAME" --notes-file .github/release-notes.md
```

- [ ] **Step 3: Validate YAML syntax**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml')); print('release.yml OK')"`
Expected: `release.yml OK`.

- [ ] **Step 4: Local dry-run of the package block**

Run:
```bash
./scripts/dev-setup.sh >/dev/null && cargo build -q --release -p proctor-cli
D=$(mktemp -d); NAME=proctor-x86_64-unknown-linux-gnu
mkdir -p "$D/dist/$NAME"
cp target/release/proctor LICENSE README.md "$D/dist/$NAME/"
tar -C "$D/dist" -czf "$D/dist/$NAME.tar.gz" "$NAME"
( cd "$D/dist" && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256" && sha256sum -c "$NAME.tar.gz.sha256" )
tar -tzf "$D/dist/$NAME.tar.gz"; rm -rf "$D"
```
Expected: `…tar.gz: OK` from `sha256sum -c`; the tar listing shows `proctor`, `LICENSE`, `README.md` under the `proctor-x86_64-unknown-linux-gnu/` dir.

- [ ] **Step 5: Commit**

```bash
git add .github/release-notes.md .github/workflows/release.yml
git commit -m "feat(release): tag-triggered release.yml building the linux x86_64 binary"
```

---

### Task 2: `action.yml` prebuilt fast-path

**Files:**
- Modify: `action.yml`

- [ ] **Step 1: Add the `proctor-version` input**

Find the `working-directory` input block (the last input) and add after it:

```yaml
  proctor-version:
    description: "If set, download this release's prebuilt binary (gh release download) instead of building."
    default: ""
```

- [ ] **Step 2: Gate the toolchain step on source-build mode**

Change:
```yaml
    - name: rust toolchain
      uses: dtolnay/rust-toolchain@stable
```
to:
```yaml
    - name: rust toolchain
      if: ${{ inputs.proctor-version == '' }}
      uses: dtolnay/rust-toolchain@stable
```

- [ ] **Step 3: Gate the proctor-ref checkout on both conditions**

Change:
```yaml
    - name: checkout proctor (proctor-ref)
      if: ${{ inputs.proctor-ref != '' }}
```
to:
```yaml
    - name: checkout proctor (proctor-ref)
      if: ${{ inputs.proctor-ref != '' && inputs.proctor-version == '' }}
```

- [ ] **Step 4: Gate the resolve + build steps**

Change:
```yaml
    - name: resolve source path
      shell: bash
```
to:
```yaml
    - name: resolve source path
      if: ${{ inputs.proctor-version == '' }}
      shell: bash
```
and change:
```yaml
    - name: build proctor
      shell: bash
```
to:
```yaml
    - name: build proctor
      if: ${{ inputs.proctor-version == '' }}
      shell: bash
```

- [ ] **Step 5: Insert the prebuilt fast-path step before `run proctor`**

Immediately before `- name: run proctor`, insert:

```yaml
    - name: obtain prebuilt proctor
      if: ${{ inputs.proctor-version != '' }}
      shell: bash
      env:
        PROCTOR_VERSION: ${{ inputs.proctor-version }}
        GH_TOKEN: ${{ github.token }}
      run: |
        set -euo pipefail
        NAME=proctor-x86_64-unknown-linux-gnu
        # repo may be private -> gh authenticates with the job token
        # --clobber so a second invocation in the same job re-downloads cleanly
        gh release download "$PROCTOR_VERSION" --repo dylanp12/proctor \
          --pattern "$NAME.tar.gz" --pattern "$NAME.tar.gz.sha256" --dir . --clobber
        sha256sum -c "$NAME.tar.gz.sha256"   # fail closed on mismatch
        tar -xzf "$NAME.tar.gz"
        echo "PROCTOR_BIN=$PWD/$NAME/proctor" >> "$GITHUB_ENV"
```

- [ ] **Step 6: Validate YAML syntax**

Run: `python3 -c "import yaml; yaml.safe_load(open('action.yml')); print('action.yml OK')"`
Expected: `action.yml OK`.

- [ ] **Step 7: Commit**

```bash
git add action.yml
git commit -m "feat(action): proctor-version fast-path (download prebuilt, verify checksum)"
```

---

### Task 3: `demo.yml` dispatch hook for the fast-path

**Files:**
- Modify: `.github/workflows/demo.yml`

- [ ] **Step 1: Add the dispatch input**

Change:
```yaml
on:
  push: { branches: [main] }
  workflow_dispatch:
```
to:
```yaml
on:
  push: { branches: [main] }
  workflow_dispatch:
    inputs:
      proctor-version:
        description: "If set, the action downloads this release's prebuilt binary instead of building."
        default: ""
```

- [ ] **Step 2: Thread the input into all three `uses: ./` steps**

In each of the three action invocations (`proctor run (synthetic)`,
`proctor run-tb (honest)`, `proctor run-tb (cheat)`), add this line to its `with:`
block (alongside `signing-seed:`):

```yaml
          proctor-version: ${{ inputs.proctor-version || '' }}
```

- [ ] **Step 3: Validate YAML + confirm three occurrences**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/demo.yml')); print('demo.yml OK')" && grep -c 'proctor-version:' .github/workflows/demo.yml`
Expected: `demo.yml OK` then `3`.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/demo.yml
git commit -m "feat(ci): demo.yml workflow_dispatch hook to exercise the prebuilt fast-path"
```

---

### Task 4: Install docs

**Files:**
- Modify: `README.md`
- Modify: `docs/usage.md`

- [ ] **Step 1: Add an "Install" section to `README.md` before "## Building"**

Find `## Building` and insert before it:

```markdown
## Install

**Prebuilt binary** (Linux x86_64, glibc ≥ 2.35):

```
gh release download v0.1.0 --repo dylanp12/proctor \
  --pattern 'proctor-x86_64-unknown-linux-gnu.tar.gz*'
sha256sum -c proctor-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf proctor-x86_64-unknown-linux-gnu.tar.gz
sudo install proctor-x86_64-unknown-linux-gnu/proctor /usr/local/bin/
proctor --version
```

Needs `libseccomp2` (the runtime library) present — installed by default on most
distributions (`sudo apt-get install -y libseccomp2` otherwise).

**From source** with `cargo`:

```
sudo apt-get install -y libseccomp-dev          # link-time libseccomp
cargo install --git https://github.com/dylanp12/proctor proctor-cli
```

```

- [ ] **Step 2: Add the fast-path example to the action section of `docs/usage.md`**

Find the line `The \`demo.yml\` workflow dogfoods the action` (end of the action
section) and insert before it:

```markdown
To skip the ~1 min source build, point the action at a published release — it
`gh release download`s and checksum-verifies the prebuilt binary instead:

```yaml
- uses: dylanp12/proctor@main
  with:
    proctor-version: v0.1.0        # download the prebuilt binary (skips the build)
    run-args: run --task ./task --agent "sh /workspace/solve.sh" --policy ./policy.yaml
```

```

- [ ] **Step 3: Commit**

```bash
git add README.md docs/usage.md
git commit -m "docs: install section (prebuilt + cargo) and action fast-path"
```

---

### Task 5: Push and confirm regression-clean

**Files:** none (verification).

- [ ] **Step 1: Push the accumulated commits**

Run: `git push origin main`
Expected: push succeeds; `ci` and `demo` trigger (no tag yet → `release` does NOT run).

- [ ] **Step 2: Watch `ci` and `demo` stay green (build-from-source path unchanged)**

Run:
```bash
for wf in ci.yml demo.yml; do
  id=$(gh run list --workflow=$wf --limit 1 --json databaseId -q '.[0].databaseId')
  echo "watching $wf ($id)"; gh run watch "$id" --exit-status --interval 10 >/dev/null && echo "$wf OK"
done
```
Expected: `ci.yml OK` and `demo.yml OK` (demo still builds from source because `proctor-version` defaults empty). If a job fails, `gh run view <id> --log-failed | tail -60`, fix, commit, push, re-watch.

---

### Task 6: Cut v0.1.0 and verify the release

**Files:** none (release).

- [ ] **Step 1: Tag and push v0.1.0**

Run: `git tag v0.1.0 && git push origin v0.1.0`
Expected: the tag push triggers `release.yml`.

- [ ] **Step 2: Watch `release.yml` to green**

Run: `id=$(gh run list --workflow=release.yml --limit 1 --json databaseId -q '.[0].databaseId'); gh run watch "$id" --exit-status --interval 10 2>&1 | tail -5`
Expected: the `release` job succeeds. On failure: `gh run view "$id" --log-failed | tail -60`, fix, delete the partial release/tag if needed (`gh release delete v0.1.0 -y; git push --delete origin v0.1.0; git tag -d v0.1.0`), and retry.

- [ ] **Step 3: Confirm the release has both assets**

Run: `gh release view v0.1.0 --json assets -q '.assets[].name'`
Expected: `proctor-x86_64-unknown-linux-gnu.tar.gz` and `proctor-x86_64-unknown-linux-gnu.tar.gz.sha256`.

- [ ] **Step 4: Download, verify checksum, run**

Run:
```bash
cd "$(mktemp -d)"
gh release download v0.1.0 --repo dylanp12/proctor --pattern 'proctor-x86_64-unknown-linux-gnu.tar.gz*'
sha256sum -c proctor-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf proctor-x86_64-unknown-linux-gnu.tar.gz
./proctor-x86_64-unknown-linux-gnu/proctor --version
```
Expected: `…tar.gz: OK`; `proctor 0.1.0`. (If `libseccomp.so.2` is missing it would fail to load — install `libseccomp2`; on the dev host it is present.)

---

### Task 7: Verify the action fast-path end-to-end

**Files:** none (verification).

- [ ] **Step 1: Dispatch `demo.yml` against the release binary**

Run: `gh workflow run demo.yml -f proctor-version=v0.1.0`
Expected: a new `demo` run is queued using the prebuilt binary.

- [ ] **Step 2: Watch it to green**

Run: `sleep 6; id=$(gh run list --workflow=demo.yml --limit 1 --json databaseId -q '.[0].databaseId'); gh run watch "$id" --exit-status --interval 15 2>&1 | tail -8`
Expected: both jobs succeed.

- [ ] **Step 3: Confirm the fast-path ran (build steps skipped, download ran)**

Run: `id=$(gh run list --workflow=demo.yml --limit 1 --json databaseId -q '.[0].databaseId'); gh run view "$id" --log | grep -E "obtain prebuilt proctor|build proctor" | head`
Expected: lines for `obtain prebuilt proctor` appear; `build proctor` does not run (it was gated off). Sanity that the prebuilt path executed.

- [ ] **Step 4: Download a fast-path bundle and verify it**

Run:
```bash
id=$(gh run list --workflow=demo.yml --limit 1 --json databaseId -q '.[0].databaseId')
rm -rf /tmp/fp && gh run download "$id" -D /tmp/fp
target/release/proctor verify-bundle --bundle /tmp/fp/proctor-bundle-synthetic/bundle.json
```
Expected: `bundle OK: …` — the bundle produced via the downloaded prebuilt binary still verifies. (Proves the fast-path is functionally equivalent.)

---

## Self-Review

**1. Spec coverage:**
- `release.yml` (tag → build on 22.04 → smoke → package tar.gz+sha256 → `gh release create --notes-file`) → Task 1. ✅
- `.github/release-notes.md` → Task 1. ✅
- `action.yml` `proctor-version` fast-path (gated build steps + `gh release download` + checksum + extract) → Task 2. ✅
- `demo.yml` `workflow_dispatch` input threaded to all 3 `uses: ./` → Task 3. ✅
- README Install (prebuilt + `cargo install --git` with libseccomp-dev) + usage fast-path → Task 4. ✅
- Cut v0.1.0 + verify assets/checksum/`--version` → Task 6. ✅
- Fast-path end-to-end verification → Task 7. ✅
- Regression (source-build demo unchanged on push) → Task 5. ✅

**2. Placeholder scan:** No TBD/TODO; every file/edit has complete content and every command an expected result. The `<this-tag>` token in `.github/release-notes.md` is intentional human-facing prose in the published notes (generic across versions), not an unfilled plan placeholder.

**3. Type/contract consistency:**
- Artifact base name `proctor-x86_64-unknown-linux-gnu` is identical in `release.yml` (package + publish), `action.yml` (download), README, and Task 6/7 verification. ✅
- `PROCTOR_BIN` is set by either `build proctor` (source) or `obtain prebuilt proctor` (fast-path) and consumed unchanged by `run proctor`. ✅
- `proctor-version` empty ⇒ source build (all gated steps run, fast-path skipped); non-empty ⇒ fast-path only. The two `if:` conditions are exact complements. ✅
- `demo.yml` passes `${{ inputs.proctor-version || '' }}`; on `push` (no inputs) this is `''` ⇒ unchanged behavior. ✅
```
