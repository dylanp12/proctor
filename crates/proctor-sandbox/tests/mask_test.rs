use proctor_sandbox::require_sandbox;
use proctor_sandbox::spawn::{run_sandboxed, InitInvoker};
use proctor_sandbox::spec::{NetSpec, RootfsSpec, SandboxSpec};
use std::path::{Path, PathBuf};

fn invoker() -> InitInvoker {
    InitInvoker {
        program: PathBuf::from(env!("CARGO_BIN_EXE_sandbox-helper")),
        prefix_args: vec![],
    }
}

/// Build a session whose workspace lower contains a benign file.
fn pivoted_spec(session: &Path, masks: Vec<PathBuf>, cmd: &str) -> SandboxSpec {
    let lower = session.join("ws_lower");
    std::fs::create_dir_all(lower.join("src")).unwrap();
    std::fs::write(lower.join("src/app.sh"), "echo hi\n").unwrap();
    std::fs::write(lower.join("readme.txt"), "workspace file\n").unwrap();
    SandboxSpec {
        rootfs: RootfsSpec::HostSystem,
        workspace_lower: Some(lower),
        mount_at: PathBuf::from("/workspace"),
        masks,
        network: NetSpec::Deny,
        env: vec![("PATH".into(), "/usr/bin:/bin".into())],
        agent_cmd: cmd.into(),
        agent_cwd: PathBuf::from("/workspace"),
        session: session.to_path_buf(),
        wall_time_secs: 30,
        pids_limit: 64,
        memory_bytes: 256 * 1024 * 1024,
        pivot: true,
        seccomp: false,
        host_proxy_sock: None,
        extra_binds: vec![],
    }
}

fn out(session: &Path) -> String {
    std::fs::read_to_string(session.join("agent-stdout.log")).unwrap_or_default()
}

#[test]
fn workspace_file_is_readable() {
    require_sandbox!();
    let s = tempfile::tempdir().unwrap();
    let r = run_sandboxed(
        &pivoted_spec(s.path(), vec![], "cat /workspace/readme.txt"),
        &invoker(),
    )
    .unwrap();
    assert_eq!(r.agent_exit, Some(0));
    assert_eq!(out(s.path()).trim(), "workspace file");
}

#[test]
fn masked_oracle_dir_is_empty_and_unreadable() {
    require_sandbox!();
    let s = tempfile::tempdir().unwrap();
    let oracle = s.path().join("ws_lower/secret_oracle");
    let spec = pivoted_spec(
        s.path(),
        vec![PathBuf::from("/oracle")],
        "cat /oracle/answer.txt 2>&1; echo EXIT=$?",
    );
    std::fs::create_dir_all(&oracle).unwrap();
    std::fs::write(oracle.join("answer.txt"), "THE-ANSWER\n").unwrap();
    let r = run_sandboxed(&spec, &invoker()).unwrap();
    assert_eq!(r.agent_exit, Some(0));
    let o = out(s.path());
    assert!(!o.contains("THE-ANSWER"), "oracle leaked: {o}");
    assert!(o.contains("EXIT=1"), "cat of masked path should fail: {o}");
}

#[test]
fn masked_path_inside_workspace_hides_just_that_subtree() {
    require_sandbox!();
    let s = tempfile::tempdir().unwrap();
    let spec = pivoted_spec(
        s.path(),
        vec![PathBuf::from("/workspace/tests")],
        "ls /workspace; echo ---; cat /workspace/tests/expected.txt 2>&1; echo EXIT=$?",
    );
    let tests = s.path().join("ws_lower/tests");
    std::fs::create_dir_all(&tests).unwrap();
    std::fs::write(tests.join("expected.txt"), "ORACLE\n").unwrap();
    let r = run_sandboxed(&spec, &invoker()).unwrap();
    assert_eq!(r.agent_exit, Some(0));
    let o = out(s.path());
    assert!(
        o.contains("readme.txt"),
        "rest of workspace should be visible: {o}"
    );
    assert!(!o.contains("ORACLE"), "masked subtree leaked: {o}");
    assert!(o.contains("EXIT=1"));
}

#[test]
fn system_dirs_are_read_only() {
    require_sandbox!();
    let s = tempfile::tempdir().unwrap();
    let r = run_sandboxed(
        &pivoted_spec(
            s.path(),
            vec![],
            "touch /usr/proctor-probe 2>&1; echo EXIT=$?",
        ),
        &invoker(),
    )
    .unwrap();
    assert_eq!(r.agent_exit, Some(0));
    assert!(
        out(s.path()).contains("EXIT=1"),
        "/usr must be read-only: {}",
        out(s.path())
    );
}

#[test]
fn host_root_is_not_visible() {
    require_sandbox!();
    let s = tempfile::tempdir().unwrap();
    let _r = run_sandboxed(
        &pivoted_spec(
            s.path(),
            vec![],
            "test -e /home/dylan && echo LEAK || echo clean",
        ),
        &invoker(),
    )
    .unwrap();
    assert_eq!(out(s.path()).trim(), "clean");
}
