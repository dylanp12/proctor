use proctor_monitor::chain::verify_chain;
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

fn spec(session: &Path, masks: Vec<PathBuf>, net: NetSpec, cmd: &str) -> SandboxSpec {
    let lower = session.join("ws_lower");
    std::fs::create_dir_all(&lower).unwrap();
    std::fs::write(lower.join("readme.txt"), "hi\n").unwrap();
    SandboxSpec {
        rootfs: RootfsSpec::HostSystem,
        workspace_lower: Some(lower),
        mount_at: PathBuf::from("/workspace"),
        masks,
        network: net,
        env: vec![("PATH".into(), "/usr/bin:/bin".into())],
        agent_cmd: cmd.into(),
        agent_cwd: PathBuf::from("/workspace"),
        session: session.to_path_buf(),
        wall_time_secs: 30,
        pids_limit: 64,
        memory_bytes: 256 * 1024 * 1024,
        pivot: true,
        seccomp: true,
        host_proxy_sock: None,
        extra_binds: vec![],
    }
}

fn violations(session: &Path) -> Vec<serde_json::Value> {
    let p = session.join("violations.jsonl");
    std::fs::read_to_string(&p)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn reading_a_masked_oracle_is_logged_as_masked_read() {
    require_sandbox!();
    let s = tempfile::tempdir().unwrap();
    let oracle = s.path().join("ws_lower/secret");
    std::fs::create_dir_all(&oracle).unwrap();
    std::fs::write(oracle.join("answer.txt"), "ANSWER\n").unwrap();
    let spec = spec(
        s.path(),
        vec![PathBuf::from("/oracle")],
        NetSpec::Deny,
        "cat /oracle/answer.txt 2>/dev/null; cat /workspace/readme.txt",
    );
    let r = run_sandboxed(&spec, &invoker()).unwrap();
    assert_eq!(r.agent_exit, Some(0));
    let vs = violations(s.path());
    let read = vs
        .iter()
        .find(|v| v["kind"] == "masked_read" && v["path"] == "/oracle/answer.txt")
        .expect("a masked_read of /oracle/answer.txt must be logged");
    assert!(read["step"].as_u64().is_some());
    assert!(verify_chain(&s.path().join("violations.jsonl")).is_ok());
    let out = std::fs::read_to_string(s.path().join("agent-stdout.log")).unwrap();
    assert!(!out.contains("ANSWER"));
    assert!(out.contains("hi"));
}

#[test]
fn legitimate_workspace_reads_are_not_logged() {
    require_sandbox!();
    let s = tempfile::tempdir().unwrap();
    let spec = spec(
        s.path(),
        vec![PathBuf::from("/oracle")],
        NetSpec::Deny,
        "cat /workspace/readme.txt",
    );
    let r = run_sandboxed(&spec, &invoker()).unwrap();
    assert_eq!(r.agent_exit, Some(0));
    let vs = violations(s.path());
    assert!(vs
        .iter()
        .all(|v| v["kind"] != "masked_read" || v["path"] != "/workspace/readme.txt"));
}

#[test]
fn blocked_connect_is_logged_with_host() {
    require_sandbox!();
    let s = tempfile::tempdir().unwrap();
    let cmd =
        "python3 -c \"import socket; socket.socket().connect(('1.2.3.4',443))\" 2>/dev/null; true";
    let spec = spec(s.path(), vec![], NetSpec::Deny, cmd);
    let r = run_sandboxed(&spec, &invoker()).unwrap();
    if std::fs::read_to_string(s.path().join("agent-stderr.log"))
        .map(|e| e.contains("No such file"))
        .unwrap_or(false)
    {
        return; // python3 absent: skip the connect assertion
    }
    assert_eq!(r.agent_exit, Some(0));
    let vs = violations(s.path());
    let c = vs
        .iter()
        .find(|v| v["kind"] == "blocked_connect")
        .expect("connect must be logged");
    assert_eq!(c["host"], "1.2.3.4:443");
}
