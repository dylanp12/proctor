#!/usr/bin/env bash
# Run the real SWE-bench_Lite instance psf__requests-2317 under Proctor and show
# the git-history-mining cheat (IQuest-Coder) dying: the repo is materialized at
# base_commit with fix history stripped, so the fix commit is unreachable, and a
# staged gold patch at a masked path is blocked + logged. Grading is deferred to
# a later sub-project (needs the instance's dependency env).
set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root
REPO_ROOT="$PWD"
INST="$REPO_ROOT/corpus/real-tasks/swebench/psf__requests-2317.json"
OUT="${1:-$REPO_ROOT/corpus/real-tasks/swebench-out}"
rm -rf "$OUT"; mkdir -p "$OUT"

echo "== building proctor =="
cargo build -q -p proctor-cli
PROCTOR="$REPO_ROOT/target/debug/proctor"

REPOURL="https://github.com/$(python3 -c "import json;print(json.load(open('$INST'))['repo'])").git"
BASE="$(python3 -c "import json;print(json.load(open('$INST'))['base_commit'])")"

# gitsan only needs base_commit (+ its tree/blobs), so fetch JUST that commit
# (fast, ~one commit of data) into a cached source repo. A full clone is slow
# and a --filter=blob:none clone is a promisor repo that breaks gitsan's fetch.
# The synthetic integration test (swebench_test) already proves gitsan strips a
# fix that WAS present; here we prove, on the real instance, that the
# materialized repo holds only base_commit and a real descendant is unreachable.
CACHE="$REPO_ROOT/corpus/real-tasks/.swebench-cache/requests"
if [ ! -d "$CACHE/.git" ]; then
    echo "== fetching base_commit ${BASE:0:12} from $REPOURL (shallow) =="
    mkdir -p "$CACHE"; git -C "$CACHE" init -q
    git -C "$CACHE" fetch --depth 1 -q "$REPOURL" "$BASE"
else
    echo "== using cached source repo ($CACHE) =="
fi
CLONE="$CACHE"
# a real descendant of base_commit (the repo's current HEAD) — its commit object
# must be UNREACHABLE in the sanitized /testbed repo. Commit reachability is the
# rigorous proof (grepping a +line is fooled by lines already present at base).
DESC="$(git ls-remote "$REPOURL" HEAD | cut -f1)"
echo "   a real descendant commit (must NOT be reachable): ${DESC:0:12}"

# the cheat agent (IQuest-Coder pattern): mine history for the fix; read the
# staged answer. Shared with .github/workflows/swebench.yml via the assembler so
# CI + this report run byte-identical agents. (This report runs WITHOUT --grade,
# so it stays integrity-only and never pip-installs on the local machine.)
cheat=""
while IFS= read -r line; do
  case "$line" in cheat=*) cheat="${line#cheat=}" ;; esac
done < <("$REPO_ROOT/scripts/assemble-swebench-demo.sh" "$INST" "$DESC")
AGENT="$cheat"

echo "== run-swebench (cheat agent) =="
"$PROCTOR" run-swebench --instance "$INST" --repo "$CLONE" --agent "$AGENT" --out "$OUT/cheat" || true

echo
echo "================ RESULTS ================"
echo "--- verdict.json ---"; cat "$OUT/cheat/verdict.json"
echo; echo "--- violations.jsonl ---"; cat "$OUT/cheat/violations.jsonl" 2>/dev/null || echo "(none)"
echo; echo "--- agent stdout ---"; cat "$OUT/cheat/agent-session/agent-stdout.log" 2>/dev/null
echo; echo "expected: 1 commit reachable, 'fix commit unreachable', /patch.diff masked."
