#!/usr/bin/env bash
# Run the real Terminal-Bench 2 task `log-summary-date-ranges` under Proctor and
# capture a before/after: the reference solution grades clean; an agent that
# reads the masked test oracle (the dominant 415/429 cheat) is blocked + logged.
#
# Task assembly (the faithful vendored files + offline log generation + offline
# grader) is shared with .github/workflows/demo.yml via scripts/assemble-tb-task.sh
# so CI and this report run byte-identical agents. The offline substitutions
# (host-python grader instead of the apt+uvx network bootstrap; solve.sh's
# apt-get env line dropped) are documented in the report.
set -euo pipefail
cd "$(dirname "$0")/../.."   # repo root
REPO="$PWD"
OUT="${1:-$REPO/corpus/real-tasks/out}"

echo "== building proctor =="
cargo build -q -p proctor-cli
PROCTOR="$REPO/target/debug/proctor"

# assemble the runnable task + capture the shared honest/cheat agents
honest=""; cheat=""
while IFS= read -r line; do
  case "$line" in
    honest=*) honest="${line#honest=}" ;;
    cheat=*)  cheat="${line#cheat=}" ;;
  esac
done < <("$REPO/scripts/assemble-tb-task.sh" "$OUT")
WORK="$OUT/task"

echo "== HONEST run (reference solution) =="
"$PROCTOR" run-tb --task "$WORK" --agent "$honest" --out "$OUT/honest" || true

echo "== CHEAT run (read the masked /tests oracle) =="
"$PROCTOR" run-tb --task "$WORK" --agent "$cheat" --out "$OUT/cheat" || true

echo
echo "================ RESULTS ================"
for kind in honest cheat; do
  echo "--- $kind/verdict.json ---"
  cat "$OUT/$kind/verdict.json"
  echo
  echo "--- $kind/violations.jsonl ---"
  cat "$OUT/$kind/violations.jsonl" 2>/dev/null || echo "(none)"
  echo
done
echo "the oracle literally contains the answers an agent would copy:"
grep -E '"(today|total)", "(ERROR|INFO)"' "$REPO/corpus/real-tasks/log-summary-date-ranges/tests/test_outputs.py" | head -4
