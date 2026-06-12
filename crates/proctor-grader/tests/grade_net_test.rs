use proctor_grader::{grade, GradeProtocol, GradeRequest, GraderNet};
use proctor_sandbox::require_sandbox;
use proctor_sandbox::spawn::InitInvoker;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};

fn invoker() -> InitInvoker {
    InitInvoker {
        program: PathBuf::from(env!("CARGO_BIN_EXE_grade-helper")),
        prefix_args: vec![],
    }
}

fn staged() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("ws")).unwrap();
    std::fs::create_dir_all(d.path().join("oracle")).unwrap();
    d
}

/// host origin: accepts one connection, replies a minimal HTTP 200 (so curl is happy too)
fn origin() -> (String, std::thread::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let h = std::thread::spawn(move || {
        if let Ok((mut c, _)) = l.accept() {
            let mut b = [0u8; 256];
            let _ = c.read(&mut b);
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        }
    });
    (addr, h)
}

fn req(d: &Path, net: GraderNet, cmd: &str, tag: &str) -> GradeRequest {
    GradeRequest {
        workspace: d.join("ws"),
        workspace_mount: PathBuf::from("/workspace"),
        oracle: d.join("oracle"),
        oracle_mount: PathBuf::from("/oracle"),
        grade_cmd: cmd.into(),
        protocol: GradeProtocol::ExitCode,
        session: d.join(tag),
        wall_time_secs: 30,
        network: net,
        rootfs: proctor_sandbox::spec::RootfsSpec::HostSystem,
    }
}

#[test]
fn host_grader_reaches_origin_deny_does_not() {
    require_sandbox!();
    if !Path::new("/usr/bin/python3").exists() {
        eprintln!("SKIP: python3 absent");
        return;
    }
    let (addr, oh) = origin();
    let port = addr.rsplit(':').next().unwrap().to_string();
    let d = staged();
    let probe =
        format!("python3 -c \"import socket; socket.create_connection(('127.0.0.1',{port}),3)\"");

    // host: connect succeeds -> exit 0 -> pass
    let r = grade(
        &req(d.path(), GraderNet::Host, &probe, "g-host"),
        &invoker(),
    )
    .unwrap();
    oh.join().ok();
    assert!(r.pass, "host grader should reach the origin (pass)");

    // deny: empty netns -> connect fails -> nonzero -> fail
    let (_addr2, oh2) = origin();
    let r2 = grade(
        &req(d.path(), GraderNet::Deny, &probe, "g-deny"),
        &invoker(),
    )
    .unwrap();
    drop(oh2);
    assert!(!r2.pass, "deny grader must not reach the origin (fail)");
}

#[test]
fn allowlist_grader_reaches_allowed_origin() {
    require_sandbox!();
    if !Path::new("/usr/bin/curl").exists() {
        eprintln!("SKIP: curl absent");
        return;
    }
    let (addr, oh) = origin();
    let d = staged();
    // curl uses HTTP_PROXY (injected for allowlist) to reach the allowed origin
    let cmd = format!("curl -s -m 5 -o /dev/null http://{addr}/");
    let r = grade(
        &req(
            d.path(),
            GraderNet::Allowlist(vec![addr.clone()]),
            &cmd,
            "g-allow",
        ),
        &invoker(),
    )
    .unwrap();
    oh.join().ok();
    assert!(
        r.pass,
        "allowlisted origin should be reachable through the grader proxy"
    );
}
