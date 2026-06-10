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
fn spec(session: &Path, cmd: &str) -> SandboxSpec {
    SandboxSpec {
        rootfs: RootfsSpec::HostSystem,
        workspace_lower: None,
        mount_at: PathBuf::from("/workspace"),
        masks: vec![],
        network: NetSpec::Deny,
        env: vec![("PATH".into(), "/usr/bin:/bin".into())],
        agent_cmd: cmd.into(),
        agent_cwd: PathBuf::from("/"),
        session: session.to_path_buf(),
        wall_time_secs: 30,
        pids_limit: 64,
        memory_bytes: 256 * 1024 * 1024,
        pivot: true,
        seccomp: false,
        host_proxy_sock: None,
    }
}
fn out(s: &Path) -> String {
    std::fs::read_to_string(s.join("agent-stdout.log")).unwrap_or_default()
}

#[test]
fn egress_to_public_ip_is_unreachable() {
    require_sandbox!();
    let s = tempfile::tempdir().unwrap();
    // raw connect via /dev/tcp (bash); numeric IP so no DNS is needed
    let cmd = "timeout 5 sh -c 'echo > /dev/tcp/1.1.1.1/443' 2>&1; echo EXIT=$?";
    let r = run_sandboxed(&spec(s.path(), cmd), &invoker()).unwrap();
    assert_eq!(r.agent_exit, Some(0));
    let o = out(s.path());
    assert!(
        !o.contains("EXIT=0"),
        "egress must fail by construction: {o}"
    );
}

#[test]
fn loopback_is_up() {
    require_sandbox!();
    let s = tempfile::tempdir().unwrap();
    let cmd = "python3 -c \"import socket as s; l=s.socket(); l.bind(('127.0.0.1',0)); l.listen(); p=l.getsockname()[1]; c=s.socket(); c.connect(('127.0.0.1',p)); print('LO_OK')\" 2>&1";
    let r = run_sandboxed(&spec(s.path(), cmd), &invoker()).unwrap();
    let o = out(s.path());
    assert_eq!(r.agent_exit, Some(0));
    if !o.contains("No such file") && !o.contains("not found") {
        assert!(o.contains("LO_OK"), "loopback should work: {o}");
    }
}
