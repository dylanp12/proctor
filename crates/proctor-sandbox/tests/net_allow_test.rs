use proctor_sandbox::proxy::HostProxy;
use proctor_sandbox::require_sandbox;
use proctor_sandbox::spawn::{run_sandboxed, InitInvoker};
use proctor_sandbox::spec::{NetSpec, RootfsSpec, SandboxSpec};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};

fn invoker() -> InitInvoker {
    InitInvoker {
        program: PathBuf::from(env!("CARGO_BIN_EXE_sandbox-helper")),
        prefix_args: vec![],
    }
}
fn out(s: &Path) -> String {
    std::fs::read_to_string(s.join("agent-stdout.log")).unwrap_or_default()
}

/// A trivial origin server on the host: accepts a connection, replies a banner.
fn origin() -> (String, std::thread::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let h = std::thread::spawn(move || {
        if let Ok((mut c, _)) = l.accept() {
            let mut b = [0u8; 256];
            let _ = c.read(&mut b);
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nORIGIN-OK");
        }
    });
    (addr.to_string(), h)
}

#[test]
fn allowlisted_host_reachable_denied_host_refused_and_logged() {
    require_sandbox!();
    let (origin_addr, oh) = origin();
    let s = tempfile::tempdir().unwrap();
    let sock = s.path().join("egress.sock");
    let proxy = HostProxy::start(&sock, vec![origin_addr.clone()]).unwrap();

    let cmd = format!(
        "curl -s -m 5 http://{origin}/ 2>&1; echo; \
         curl -s -m 5 -o /dev/null -w 'DENIED=%{{http_code}}' http://10.255.255.1:9/ 2>&1; echo",
        origin = origin_addr
    );
    let spec = SandboxSpec {
        rootfs: RootfsSpec::HostSystem,
        workspace_lower: None,
        mount_at: PathBuf::from("/workspace"),
        masks: vec![],
        network: NetSpec::Allowlist {
            proxy_sock: PathBuf::from("/run/proctor/egress.sock"),
        },
        env: vec![("PATH".into(), "/usr/bin:/bin".into())],
        agent_cmd: cmd,
        agent_cwd: PathBuf::from("/"),
        session: s.path().to_path_buf(),
        wall_time_secs: 30,
        pids_limit: 64,
        memory_bytes: 256 * 1024 * 1024,
        pivot: true,
        seccomp: false,
        host_proxy_sock: Some(sock.clone()),
    };
    let _r = run_sandboxed(&spec, &invoker()).unwrap();
    let o = out(s.path());
    let decisions = proxy.decisions();
    oh.join().ok();

    // proxy enforced the allowlist regardless of whether curl is present
    assert!(
        decisions
            .iter()
            .any(|d| d.allowed && d.target == origin_addr),
        "allowlisted target should be recorded as allowed: {decisions:?}"
    );
    assert!(
        decisions
            .iter()
            .any(|d| !d.allowed && d.target.contains("10.255.255.1:9")),
        "denied target should be recorded as denied: {decisions:?}"
    );
    // if curl is present, the allowlisted fetch returned the banner; denied got 403
    if o.contains("ORIGIN-OK") {
        assert!(o.contains("DENIED=403"), "denied host should get 403: {o}");
    }
}
