use proctor_sandbox::require_sandbox;
use proctor_sandbox::spawn::{run_sandboxed, InitInvoker};
use proctor_sandbox::spec::{NetSpec, RootfsSpec, SandboxSpec};
use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};

fn invoker() -> InitInvoker {
    InitInvoker {
        program: PathBuf::from(env!("CARGO_BIN_EXE_sandbox-helper")),
        prefix_args: vec![],
    }
}

/// A host origin that accepts one connection (proves reachability).
fn origin() -> (u16, std::thread::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let h = std::thread::spawn(move || {
        if let Ok((mut c, _)) = l.accept() {
            let mut b = [0u8; 16];
            let _ = c.read(&mut b);
        }
    });
    (port, h)
}

fn spec(session: &Path, net: NetSpec, cmd: &str) -> SandboxSpec {
    SandboxSpec {
        rootfs: RootfsSpec::HostSystem,
        workspace_lower: None,
        mount_at: PathBuf::from("/workspace"),
        masks: vec![],
        network: net,
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
        extra_binds: vec![],
    }
}

fn out(s: &Path) -> String {
    std::fs::read_to_string(s.join("agent-stdout.log")).unwrap_or_default()
}

#[test]
fn host_network_reaches_host_local_origin() {
    require_sandbox!();
    if !Path::new("/usr/bin/python3").exists() {
        eprintln!("SKIP: python3 absent");
        return;
    }
    let (port, oh) = origin();
    let s = tempfile::tempdir().unwrap();
    let cmd = format!(
        "python3 -c \"import socket; socket.create_connection(('127.0.0.1',{port}),3); print('CONNECTED')\" 2>&1"
    );
    let r = run_sandboxed(&spec(s.path(), NetSpec::Host, &cmd), &invoker()).unwrap();
    oh.join().ok();
    assert_eq!(
        r.agent_exit,
        Some(0),
        "host-net agent should exit 0: {}",
        out(s.path())
    );
    assert!(
        out(s.path()).contains("CONNECTED"),
        "host net should reach origin: {}",
        out(s.path())
    );
}

#[test]
fn deny_network_cannot_reach_host_local_origin() {
    require_sandbox!();
    if !Path::new("/usr/bin/python3").exists() {
        eprintln!("SKIP: python3 absent");
        return;
    }
    let (port, oh) = origin();
    let s = tempfile::tempdir().unwrap();
    let cmd = format!(
        "python3 -c \"import socket; socket.create_connection(('127.0.0.1',{port}),3); print('CONNECTED')\" 2>&1; echo EXIT=$?"
    );
    let r = run_sandboxed(&spec(s.path(), NetSpec::Deny, &cmd), &invoker()).unwrap();
    drop(oh); // origin never receives a connection; don't join (would block)
    assert_eq!(r.agent_exit, Some(0)); // the shell runs; the python connect fails inside
    assert!(
        !out(s.path()).contains("CONNECTED"),
        "deny net must NOT reach origin: {}",
        out(s.path())
    );
}
