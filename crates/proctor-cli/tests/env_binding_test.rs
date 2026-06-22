//! A real `proctor run` emits a v2 bundle that records the run environment, and
//! `verify-bundle` (all four checks, including the env recompute) passes on it.

use proctor_sandbox::require_sandbox;
use std::path::Path;
use std::process::Command;

fn proctor() -> Command {
    Command::new(env!("CARGO_BIN_EXE_proctor"))
}
fn write(p: &Path, s: &str) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, s).unwrap();
}

const POLICY_DENY: &str =
    "version: 1\nforbidden:\n  reads: [/oracle]\n  writes: [/logs/verifier]\nnetwork: {mode: deny}\n";

#[test]
fn run_emits_v2_bundle_that_verifies() {
    require_sandbox!();
    let d = tempfile::tempdir().unwrap();
    let root = d.path();
    write(
        &root.join("task/workspace/solve.sh"),
        "#!/bin/sh\necho hello > /workspace/out.txt\n",
    );
    write(&root.join("task/grade.sh"), "#!/bin/sh\nexit 0\n");
    write(&root.join("task/oracle/answer.txt"), "ok\n"); // grader binds task/oracle
    write(&root.join("policy.yaml"), POLICY_DENY);
    let out = root.join("out");

    let st = proctor()
        .args(["run", "--task"])
        .arg(root.join("task"))
        .args(["--agent", "sh /workspace/solve.sh"])
        .args(["--policy"])
        .arg(root.join("policy.yaml"))
        .args(["--out"])
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&st.stderr)
    );

    let bundle: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("bundle.json")).unwrap()).unwrap();
    assert_eq!(bundle["bundle_version"], 2, "bundle is v2");
    let env = &bundle["environment"];
    assert!(
        env["agent_command"].as_str().unwrap().contains("solve.sh"),
        "agent_command recorded"
    );
    assert_eq!(env["rootfs_kind"], "host");
    assert!(
        !env["proctor_commit"].as_str().unwrap().is_empty(),
        "proctor_commit recorded"
    );
    assert!(!env["policy_sha256"].as_str().unwrap().is_empty());

    // the CLI verify (signature + chain + artifacts + the new env recompute) passes
    let v = proctor()
        .args(["verify-bundle", "--bundle"])
        .arg(out.join("bundle.json"))
        .output()
        .unwrap();
    assert!(
        v.status.success(),
        "verify-bundle failed: {}",
        String::from_utf8_lossy(&v.stderr)
    );
}
