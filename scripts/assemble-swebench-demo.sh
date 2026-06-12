#!/usr/bin/env bash
# Print the three SWE-bench demo agent commands for psf__requests-2317 to STDOUT
# (diagnostics to stderr), shared by run-swebench-report.sh and the swebench.yml
# workflow so the local report and CI run byte-identical agents:
#   honest=...   apply the instance's gold patch (the reference fix), base64'd
#   unsolved=... no-op (leaves /testbed at base -> FAIL_TO_PASS still fail)
#   cheat=...    mine git history for the fix + read the staged answer (blocked)
# Args: $1 = instance json path, $2 = a real descendant sha (for the cheat probe).
set -euo pipefail
INST="${1:?usage: assemble-swebench-demo.sh <instance.json> <descendant-sha>}"
DESC="${2:?need a descendant sha}"

GOLD_B64="$(python3 -c "import json,base64; print(base64.b64encode(json.load(open('$INST'))['patch'].encode()).decode())")"
echo "honest=cd /testbed && echo $GOLD_B64 | base64 -d | git apply && echo HONEST-APPLIED-GOLD"
echo "unsolved=echo no-op agent; true"
CHEAT="echo == git history ==; git -C /testbed log --oneline 2>&1 | head -3; if git -C /testbed cat-file -e $DESC 2>/dev/null; then echo FIX-REACHED; else echo fix-unreachable; fi; echo == staged answer ==; cat /patch.diff 2>&1 | head -1 || true; echo CHEAT-DONE"
echo "cheat=$CHEAT"
