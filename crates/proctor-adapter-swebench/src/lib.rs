//! SWE-bench adapter: map a SWE-bench instance -> Proctor policy + run plan.
//! Pure transformation — no execution, no sandbox.
//!
//! A SWE-bench instance gives the agent a repo at `base_commit` + the issue
//! text; the fix lives in later git history and the tests/gold patch are applied
//! only at evaluation. So the dominant on-disk cheat is **git-history mining**
//! (`git log`/`git show` to the fix commit). The materialization step
//! (`sandbox::gitsan`) strips that history; this adapter additionally masks the
//! test/patch paths as defense in depth against harnesses that stage them.

use proctor_policy::{
    EnvPolicy, Forbidden, GitPolicy, Limits, NetworkMode, NetworkPolicy, Policy, Workspace,
};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("instance json parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("instance.base_commit is not a 40-char hex sha: {0}")]
    BadCommit(String),
}

/// The SWE-bench instance fields this adapter uses. Extra dataset fields
/// (FAIL_TO_PASS, version, ...) are ignored — no deny_unknown_fields.
#[derive(Debug, Deserialize)]
pub struct Instance {
    pub instance_id: String,
    pub repo: String,
    pub base_commit: String,
    pub problem_statement: String,
    pub test_patch: String,
    #[serde(default)]
    pub patch: String,
    #[serde(default, rename = "FAIL_TO_PASS")]
    pub fail_to_pass: Vec<String>,
    #[serde(default, rename = "PASS_TO_PASS")]
    pub pass_to_pass: Vec<String>,
    #[serde(default)]
    pub install_cmd: Option<String>,
    #[serde(default)]
    pub test_cmd: Option<String>,
    /// subset of FAIL_TO_PASS to gate the verdict on (defaults to all of
    /// FAIL_TO_PASS); lets an instance pin the deterministic fix-validating tests
    #[serde(default)]
    pub grade_tests: Vec<String>,
}

#[derive(Debug)]
pub struct SwePlan {
    pub policy: Policy,
    pub instruction: String,
    pub workdir: PathBuf,
    pub base_commit: String,
    pub instance_id: String,
    pub test_patch: String,
    pub fail_to_pass: Vec<String>,
    pub pass_to_pass: Vec<String>,
    pub install_cmd: String,
    pub test_cmd: String,
    /// the tests the verdict is gated on (FAIL_TO_PASS, or a pinned subset)
    pub grade_tests: Vec<String>,
}

/// Collect the file paths a unified diff targets, from its `+++ b/<path>`
/// headers. Skips `/dev/null` (deletions) and de-duplicates, preserving order.
pub fn test_paths(diff: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for line in diff.lines() {
        let Some(rest) = line.strip_prefix("+++ ") else {
            continue;
        };
        // strip the conventional `b/` prefix; tolerate a missing one
        let raw = rest.strip_prefix("b/").unwrap_or(rest);
        // a trailing timestamp may follow a tab
        let path = raw.split('\t').next().unwrap_or(raw).trim();
        if path.is_empty() || path == "/dev/null" {
            continue;
        }
        let pb = PathBuf::from(path);
        if !out.contains(&pb) {
            out.push(pb);
        }
    }
    out
}

/// Build the SWE-bench grade script: apply the test patch (the oracle the agent
/// never saw), install deps, run the FAIL_TO_PASS+PASS_TO_PASS ids, and write a
/// reward (1 iff the test run exits 0 — SWE-bench is all-or-nothing). Runs in the
/// grader sandbox with /testbed = the agent's merged workspace and /oracle = the
/// test patch + test_ids.
pub fn grade_script(install_cmd: &str, test_cmd: &str) -> String {
    // Apply the hidden test patch, install deps, then run the gated tests
    // (/oracle/fail_to_pass) and decide "resolved" by checking each PASSED.
    // requests' test helper resolves `httpbin(...)` via $HTTPBIN_URL, so we point
    // it at a tiny stdlib stub (/oracle/httpbin_stub.py, written by the CLI) for a
    // deterministic, offline check — the suite's live-httpbin.org tests need
    // SWE-bench's pinned env (a non-goal). The stub returns 200 for a real `GET`
    // and 501 for the malformed `b'GET'` method, so the fix is the discriminator.
    format!(
        "set -e\n\
cd /testbed\n\
git apply /oracle/test_patch.diff\n\
{install_cmd} >/tmp/install.log 2>&1 || echo 'install step failed'\n\
python3.9 /oracle/httpbin_stub.py >/tmp/stub.log 2>&1 & echo $! >/tmp/stub.pid\n\
export HTTPBIN_URL=http://127.0.0.1:8080/\n\
sleep 2\n\
mkdir -p /logs/verifier\n\
ids=\"$(tr '\\n' ' ' < /oracle/fail_to_pass)\"\n\
{test_cmd} -v $ids >/tmp/test.out 2>&1 || true\n\
kill \"$(cat /tmp/stub.pid)\" 2>/dev/null || true\n\
ok=1\n\
while IFS= read -r id; do [ -z \"$id\" ] && continue; grep -qF \"$id PASSED\" /tmp/test.out || ok=0; done < /oracle/fail_to_pass\n\
if [ \"$ok\" = 1 ]; then printf '{{\"reward\":1}}\\n' >/logs/verifier/reward.json; \
else printf '{{\"reward\":0}}\\n' >/logs/verifier/reward.json; tail -25 /tmp/test.out; fi\n"
    )
}

/// Parse a SWE-bench instance from JSON and map it to a plan.
pub fn from_json(s: &str) -> Result<SwePlan, AdapterError> {
    let inst: Instance = serde_json::from_str(s)?;
    load_instance(&inst)
}

/// Map a parsed instance to a Proctor policy + plan.
pub fn load_instance(inst: &Instance) -> Result<SwePlan, AdapterError> {
    if inst.base_commit.len() != 40 || !inst.base_commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AdapterError::BadCommit(inst.base_commit.clone()));
    }
    let workdir = PathBuf::from("/testbed");

    // mask the test targets (under /testbed) + conventional staged-answer drops
    let mut reads: Vec<PathBuf> = test_paths(&inst.test_patch)
        .iter()
        .map(|p| workdir.join(p))
        .collect();
    for staged in [
        "/patch.diff",
        "/tmp/patch.diff",
        "/testbed/patch.diff",
        "/testbed/test_patch.diff",
    ] {
        reads.push(PathBuf::from(staged));
    }

    let policy = Policy {
        version: 1,
        workspace: Workspace {
            mount_at: workdir.clone(),
        },
        forbidden: Forbidden {
            reads,
            writes: vec![],
        },
        network: NetworkPolicy {
            mode: NetworkMode::Deny,
            allow: vec![],
        },
        git: Some(GitPolicy {
            base_commit: inst.base_commit.clone(),
        }),
        env: EnvPolicy { allow: vec![] },
        limits: Limits::default(),
    };

    Ok(SwePlan {
        policy,
        instruction: inst.problem_statement.clone(),
        workdir,
        base_commit: inst.base_commit.clone(),
        instance_id: inst.instance_id.clone(),
        test_patch: inst.test_patch.clone(),
        fail_to_pass: inst.fail_to_pass.clone(),
        pass_to_pass: inst.pass_to_pass.clone(),
        install_cmd: inst
            .install_cmd
            .clone()
            .unwrap_or_else(|| "python -m pip install -e .".into()),
        test_cmd: inst
            .test_cmd
            .clone()
            .unwrap_or_else(|| "python -m pytest -p no:cacheprovider -q".into()),
        grade_tests: if inst.grade_tests.is_empty() {
            inst.fail_to_pass.clone()
        } else {
            inst.grade_tests.clone()
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIFF: &str = "\
diff --git a/tests/test_a.py b/tests/test_a.py
--- a/tests/test_a.py
+++ b/tests/test_a.py
@@ -1 +1,2 @@
 x
+y
diff --git a/pkg/new_test.py b/pkg/new_test.py
new file mode 100644
--- /dev/null
+++ b/pkg/new_test.py
@@ -0,0 +1 @@
+z
";

    #[test]
    fn test_paths_collects_plus_b_targets_skips_devnull() {
        let p = test_paths(DIFF);
        assert_eq!(
            p,
            vec![
                PathBuf::from("tests/test_a.py"),
                PathBuf::from("pkg/new_test.py")
            ]
        );
    }

    #[test]
    fn test_paths_dedupes_and_ignores_noise() {
        let d = "+++ b/a.py\n+++ b/a.py\nsome other line\n+++ /dev/null\n";
        assert_eq!(test_paths(d), vec![PathBuf::from("a.py")]);
    }

    const INSTANCE: &str = r#"{
        "instance_id": "psf__requests-2317",
        "repo": "psf/requests",
        "base_commit": "091991be0da19de9108dbe5e3752917fea3d7fdc",
        "problem_statement": "method becomes bytes",
        "test_patch": "--- a/tests/test_requests.py\n+++ b/tests/test_requests.py\n@@ -1 +1 @@\n+assert True\n",
        "patch": "--- a/requests/sessions.py\n+++ b/requests/sessions.py\n",
        "FAIL_TO_PASS": ["tests/test_requests.py::test_x"],
        "PASS_TO_PASS": ["tests/test_requests.py::test_y"],
        "version": "2.9"
    }"#;

    #[test]
    fn load_instance_maps_to_policy() {
        let plan = from_json(INSTANCE).unwrap();
        assert_eq!(plan.instance_id, "psf__requests-2317");
        assert_eq!(plan.base_commit, "091991be0da19de9108dbe5e3752917fea3d7fdc");
        assert_eq!(plan.workdir, PathBuf::from("/testbed"));
        assert!(plan.instruction.contains("method becomes bytes"));
        assert_eq!(
            plan.policy.git.as_ref().unwrap().base_commit,
            "091991be0da19de9108dbe5e3752917fea3d7fdc"
        );
        let reads = &plan.policy.forbidden.reads;
        assert!(
            reads.contains(&PathBuf::from("/testbed/tests/test_requests.py")),
            "{reads:?}"
        );
        assert!(reads.contains(&PathBuf::from("/patch.diff")), "{reads:?}");
        assert_eq!(plan.policy.network.mode, proctor_policy::NetworkMode::Deny);
        assert_eq!(plan.policy.workspace.mount_at, PathBuf::from("/testbed"));
    }

    #[test]
    fn plan_carries_test_ids_and_default_commands() {
        let plan = from_json(INSTANCE).unwrap();
        assert_eq!(plan.fail_to_pass, vec!["tests/test_requests.py::test_x"]);
        assert_eq!(plan.pass_to_pass, vec!["tests/test_requests.py::test_y"]);
        assert_eq!(plan.install_cmd, "python -m pip install -e .");
        assert_eq!(plan.test_cmd, "python -m pytest -p no:cacheprovider -q");
        assert!(plan.test_patch.contains("test_requests.py"));
    }

    #[test]
    fn explicit_commands_override_defaults() {
        let j = INSTANCE.replace(
            r#""version": "2.9""#,
            r#""version": "2.9", "install_cmd": "make dev", "test_cmd": "tox""#,
        );
        let plan = from_json(&j).unwrap();
        assert_eq!(plan.install_cmd, "make dev");
        assert_eq!(plan.test_cmd, "tox");
    }

    #[test]
    fn grade_script_has_apply_install_test_and_reward_branches() {
        let s = grade_script("python -m pip install -e .", "python -m pytest");
        assert!(s.contains("git apply /oracle/test_patch.diff"), "{s}");
        assert!(s.contains("python -m pip install -e ."), "{s}");
        assert!(s.contains("python -m pytest -v"), "{s}");
        assert!(s.contains("/oracle/fail_to_pass"), "{s}");
        assert!(s.contains("HTTPBIN_URL=http://127.0.0.1:8080/"), "{s}");
        assert!(s.contains("/oracle/httpbin_stub.py"), "{s}");
        assert!(s.contains("PASSED"), "{s}");
        assert!(s.contains(r#"{"reward":1}"#), "{s}");
        assert!(s.contains(r#"{"reward":0}"#), "{s}");
    }

    #[test]
    fn bad_base_commit_is_rejected() {
        let bad = INSTANCE.replace("091991be0da19de9108dbe5e3752917fea3d7fdc", "nothex");
        assert!(matches!(from_json(&bad), Err(AdapterError::BadCommit(_))));
    }

    #[test]
    fn malformed_json_is_an_error() {
        assert!(matches!(from_json("{not json"), Err(AdapterError::Json(_))));
    }
}
