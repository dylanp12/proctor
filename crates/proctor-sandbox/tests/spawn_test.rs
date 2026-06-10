use proctor_sandbox::require_sandbox;
use proctor_sandbox::spawn::{run_sandboxed, InitInvoker};
use proctor_sandbox::spec::{NetSpec, RootfsSpec, SandboxSpec};
use std::path::PathBuf;
use std::time::Instant;

fn invoker() -> InitInvoker {
    InitInvoker {
        program: PathBuf::from(env!("CARGO_BIN_EXE_sandbox-helper")),
        prefix_args: vec![],
    }
}

fn spec(session: &std::path::Path, cmd: &str, wall: u64) -> SandboxSpec {
    SandboxSpec {
        rootfs: RootfsSpec::HostSystem,
        workspace_lower: None,
        mount_at: PathBuf::from("/workspace"),
        masks: vec![],
        network: NetSpec::Deny,
        env: vec![
            ("PATH".into(), "/usr/bin:/bin:/usr/sbin:/sbin".into()),
            ("MARKER".into(), "proctor-test".into()),
        ],
        agent_cmd: cmd.to_string(),
        agent_cwd: PathBuf::from("/"),
        session: session.to_path_buf(),
        wall_time_secs: wall,
        pids_limit: 64,
        memory_bytes: 256 * 1024 * 1024,
        pivot: false,   // Task 6 flips this in real runs
        seccomp: false, // Task 11
        host_proxy_sock: None,
        extra_binds: vec![],
    }
}

fn stdout_of(session: &std::path::Path) -> String {
    std::fs::read_to_string(session.join("agent-stdout.log")).unwrap_or_default()
}

#[test]
fn true_exits_zero_with_full_event_sequence() {
    require_sandbox!();
    let session = tempfile::tempdir().unwrap();
    let out = run_sandboxed(&spec(session.path(), "true", 30), &invoker()).unwrap();
    assert_eq!(out.agent_exit, Some(0));
    assert!(!out.timed_out);
    let kinds: Vec<&str> = out.events.iter().map(|e| e.kind()).collect();
    assert_eq!(kinds, ["mounts_ready", "pid1", "sandboxed", "agent_exit"]);
}

#[test]
fn false_exit_code_propagates() {
    require_sandbox!();
    let session = tempfile::tempdir().unwrap();
    let out = run_sandboxed(&spec(session.path(), "exit 7", 30), &invoker()).unwrap();
    assert_eq!(out.agent_exit, Some(7));
}

#[test]
fn agent_runs_in_fresh_pid_namespace() {
    require_sandbox!();
    let session = tempfile::tempdir().unwrap();
    let out = run_sandboxed(&spec(session.path(), "echo $$", 30), &invoker()).unwrap();
    assert_eq!(out.agent_exit, Some(0));
    assert_eq!(stdout_of(session.path()).trim(), "2");
}

#[test]
fn hostname_is_isolated() {
    require_sandbox!();
    let host = nix::unistd::gethostname().unwrap();
    let session = tempfile::tempdir().unwrap();
    let out = run_sandboxed(&spec(session.path(), "hostname", 30), &invoker()).unwrap();
    assert_eq!(out.agent_exit, Some(0));
    assert_eq!(stdout_of(session.path()).trim(), "proctor");
    assert_eq!(
        nix::unistd::gethostname().unwrap(),
        host,
        "host hostname must be untouched"
    );
}

#[test]
fn env_is_scrubbed_to_spec_exactly() {
    require_sandbox!();
    let session = tempfile::tempdir().unwrap();
    let out = run_sandboxed(&spec(session.path(), "env | sort", 30), &invoker()).unwrap();
    assert_eq!(out.agent_exit, Some(0));
    let env = stdout_of(session.path());
    let keys: Vec<&str> = env.lines().filter_map(|l| l.split('=').next()).collect();
    for k in &keys {
        assert!(
            ["PATH", "MARKER", "PWD", "SHLVL", "_"].contains(k),
            "unexpected env leaked into sandbox: {k} (full env: {env})"
        );
    }
    assert!(keys.contains(&"MARKER"));
}

#[test]
fn pid1_environ_is_empty() {
    require_sandbox!();
    let session = tempfile::tempdir().unwrap();
    let out = run_sandboxed(
        &spec(session.path(), "cat /proc/1/environ | wc -c", 30),
        &invoker(),
    )
    .unwrap();
    assert_eq!(out.agent_exit, Some(0));
    assert_eq!(stdout_of(session.path()).trim(), "0");
}

#[test]
fn wall_clock_timeout_kills_the_namespace() {
    require_sandbox!();
    let session = tempfile::tempdir().unwrap();
    let t0 = Instant::now();
    let out = run_sandboxed(&spec(session.path(), "sleep 30", 1), &invoker()).unwrap();
    assert!(out.timed_out);
    assert_eq!(out.agent_exit, None);
    assert!(
        t0.elapsed().as_secs() < 10,
        "kill must be prompt, took {:?}",
        t0.elapsed()
    );
}

#[test]
fn setup_failure_fails_closed() {
    let session = tempfile::tempdir().unwrap();
    let bad = InitInvoker {
        program: PathBuf::from("/bin/false"),
        prefix_args: vec![],
    };
    let err = run_sandboxed(&spec(session.path(), "true", 5), &bad).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("setup"),
        "expected fail-closed setup error, got: {msg}"
    );
}
