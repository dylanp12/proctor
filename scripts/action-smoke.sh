#!/usr/bin/env bash
# Local mirror of action.yml's core: build proctor, run the synthetic task (agent
# writes the answer AND trips a masked /oracle read), then assert bundle.json
# exists and verify-bundle passes. Run this before pushing the workflow so the
# logic is validated on the dev host, not only on CI.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

echo "== building proctor =="
./scripts/dev-setup.sh >/dev/null
cargo build -q --release -p proctor-cli
BIN="$REPO/target/release/proctor"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/task/workspace" "$WORK/task/oracle"
cat > "$WORK/task/workspace/solve.sh" <<'EOF'
#!/bin/sh
cat /oracle/x 2>/dev/null; echo 42 > /workspace/a
EOF
printf 'SECRET\n' > "$WORK/task/oracle/x"
printf '42\n'     > "$WORK/task/oracle/expected.txt"
printf 'diff -q /workspace/a /oracle/expected.txt\n' > "$WORK/task/grade.sh"
cat > "$WORK/policy.yaml" <<'EOF'
version: 1
forbidden:
  reads: [/oracle]
network: {mode: deny}
EOF

echo "== run =="
"$BIN" run --task "$WORK/task" \
  --agent "sh /workspace/solve.sh" \
  --policy "$WORK/policy.yaml" --out "$WORK/out"

test -f "$WORK/out/bundle.json" || { echo "FAIL: no bundle.json"; exit 1; }

echo "== verify-bundle =="
"$BIN" verify-bundle --bundle "$WORK/out/bundle.json"

echo "SMOKE OK: status=$(jq -r '.status' "$WORK/out/verdict.json") pass=$(jq -r '.pass' "$WORK/out/verdict.json") violations=$(jq -r '.violations_count' "$WORK/out/verdict.json")"
