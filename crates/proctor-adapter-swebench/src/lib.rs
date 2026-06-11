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
}

#[derive(Debug)]
pub struct SwePlan {
    pub policy: Policy,
    pub instruction: String,
    pub workdir: PathBuf,
    pub base_commit: String,
    pub instance_id: String,
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
    fn bad_base_commit_is_rejected() {
        let bad = INSTANCE.replace("091991be0da19de9108dbe5e3752917fea3d7fdc", "nothex");
        assert!(matches!(from_json(&bad), Err(AdapterError::BadCommit(_))));
    }

    #[test]
    fn malformed_json_is_an_error() {
        assert!(matches!(from_json("{not json"), Err(AdapterError::Json(_))));
    }
}
