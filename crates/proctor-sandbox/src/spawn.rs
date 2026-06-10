//! Parent-side sandbox launch: re-exec self as sandbox-init inside fresh
//! namespaces, run the fail-closed handshake, wire the monitor, enforce the
//! wall clock.

use crate::ipc::{self, StatusEvent, ACK_FD, SECCOMP_FD, STATUS_FD};
use crate::spec::SandboxSpec;
use proctor_monitor::supervisor::MonitorHandle;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("sandbox setup failed (fail closed) at {stage}: {detail}")]
    SetupFailed { stage: String, detail: String },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("os: {0}")]
    Os(#[from] nix::Error),
}

pub struct InitInvoker {
    /// binary that calls proctor_sandbox::init::init_main on `__sandbox-init`
    pub program: PathBuf,
    pub prefix_args: Vec<String>,
}

#[derive(Debug)]
pub struct RunOutcome {
    pub agent_exit: Option<i32>,
    pub timed_out: bool,
    pub events: Vec<StatusEvent>,
    pub limits_degraded: bool,
    pub violations_head: String,
    pub violations_count: u64,
}

fn set_cloexec(fd: std::os::fd::RawFd) {
    unsafe {
        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
    }
}

pub fn run_sandboxed(
    spec: &SandboxSpec,
    invoker: &InitInvoker,
) -> Result<RunOutcome, SandboxError> {
    // allowlist mode: inject the proxy env so the agent's tooling uses it
    let mut spec = spec.clone();
    if matches!(spec.network, crate::spec::NetSpec::Allowlist { .. }) {
        for k in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            spec.env.push((k.into(), "http://127.0.0.1:3128".into()));
        }
    }

    std::fs::create_dir_all(&spec.session)?;
    let spec_path = spec.session.join("spec.json");
    spec.save(&spec_path)?;

    // pipes/sockets; child ends must survive exec (no CLOEXEC on those)
    let (status_r, status_w) = nix::unistd::pipe()?;
    let (sec_parent, sec_child) = nix::sys::socket::socketpair(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::Stream,
        None,
        nix::sys::socket::SockFlag::empty(),
    )?;
    let (ack_r, ack_w) = nix::unistd::pipe()?;

    // parent-retained ends must not leak across the child's exec
    set_cloexec(status_r.as_raw_fd());
    set_cloexec(sec_parent.as_raw_fd());
    set_cloexec(ack_w.as_raw_fd());

    let stdout = std::fs::File::create(spec.session.join("agent-stdout.log"))?;
    let stderr = std::fs::File::create(spec.session.join("agent-stderr.log"))?;

    // preformat to avoid allocation in pre_exec (post-fork)
    let uid_map = format!("0 {} 1\n", nix::unistd::getuid().as_raw()).into_bytes();
    let gid_map = format!("0 {} 1\n", nix::unistd::getgid().as_raw()).into_bytes();
    let status_fd = status_w.as_raw_fd();
    let sec_fd = sec_child.as_raw_fd();
    let ack_fd = ack_r.as_raw_fd();

    let mut cmd = Command::new(&invoker.program);
    cmd.args(&invoker.prefix_args)
        .arg("--spec")
        .arg(&spec_path)
        .env_clear() // init starts with NO env; /proc/1/environ stays empty
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    unsafe {
        cmd.pre_exec(move || {
            // 1. own session so the parent can signal the whole subtree
            nix::unistd::setsid().map_err(std::io::Error::from)?;
            // 2. pin the ipc fds to the fixed numbers the child expects
            for (from, to) in [
                (status_fd, STATUS_FD),
                (sec_fd, SECCOMP_FD),
                (ack_fd, ACK_FD),
            ] {
                if libc::dup2(from, to) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            // 3. enter the namespaces
            nix::sched::unshare(
                nix::sched::CloneFlags::CLONE_NEWUSER
                    | nix::sched::CloneFlags::CLONE_NEWNS
                    | nix::sched::CloneFlags::CLONE_NEWPID
                    | nix::sched::CloneFlags::CLONE_NEWNET
                    | nix::sched::CloneFlags::CLONE_NEWIPC
                    | nix::sched::CloneFlags::CLONE_NEWUTS,
            )
            .map_err(std::io::Error::from)?;
            // 4. self-map root (the only mapping an unprivileged process may write)
            write_proc_self("setgroups", b"deny")?;
            write_proc_self("gid_map", &gid_map)?;
            write_proc_self("uid_map", &uid_map)?;
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    // parent keeps only its own ends
    drop((status_w, sec_child, ack_r));

    // event pump on a thread so the parent can enforce the deadline
    let (tx, rx) = mpsc::channel::<StatusEvent>();
    let status_file = std::fs::File::from(status_r);
    let pump = std::thread::spawn(move || {
        for ev in ipc::read_events(status_file) {
            match ev {
                Ok(ev) => {
                    if tx.send(ev).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let deadline = Instant::now() + Duration::from_secs(spec.wall_time_secs);
    let mut events = Vec::new();
    let mut agent_exit = None;
    let mut timed_out = false;
    let mut pid1_host_pid: Option<i32> = None;
    let mut limits_degraded = false;
    let mut acked = false;
    let mut monitor: Option<std::thread::JoinHandle<MonitorHandle>> = None;
    let monitor_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(ev) => {
                match &ev {
                    StatusEvent::Pid1 { pid } => {
                        pid1_host_pid = Some(*pid);
                        limits_degraded =
                            !crate::cgroup::try_apply(*pid, spec.pids_limit, spec.memory_bytes)
                                .unwrap_or(false);
                    }
                    StatusEvent::Sandboxed => {
                        if spec.seccomp {
                            let fd: OwnedFd =
                                ipc::recv_fd(sec_parent.as_raw_fd()).map_err(|e| {
                                    SandboxError::SetupFailed {
                                        stage: "seccomp-fd".into(),
                                        detail: e.to_string(),
                                    }
                                })?;
                            let chain = std::sync::Arc::new(std::sync::Mutex::new(
                                proctor_monitor::chain::ChainWriter::create(
                                    &spec.session.join("violations.jsonl"),
                                )
                                .map_err(|e| {
                                    SandboxError::SetupFailed {
                                        stage: "chain".into(),
                                        detail: e.to_string(),
                                    }
                                })?,
                            ));
                            let ctx = proctor_monitor::classify::ClassifyCtx {
                                mask_set: spec.masks.iter().cloned().collect(),
                            };
                            let cwd = spec.agent_cwd.display().to_string();
                            let stop = monitor_stop.clone();
                            monitor = Some(std::thread::spawn(move || {
                                proctor_monitor::supervisor::run(fd, chain, ctx, cwd, stop)
                            }));
                        }
                        // release pid1 to fork the agent (cgroup + monitor armed)
                        nix::unistd::write(&ack_w, b"G")?;
                        acked = true;
                    }
                    StatusEvent::AgentExit { code } => agent_exit = Some(*code),
                    _ => {}
                }
                events.push(ev);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                timed_out = true;
                if let Some(p) = pid1_host_pid {
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(p),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                }
                let _ = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(child.id() as i32),
                    nix::sys::signal::Signal::SIGKILL,
                );
                break;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        if agent_exit.is_some() {
            break;
        }
    }

    let _ = child.wait();
    let _ = pump.join();
    drop(ack_w);

    // the agent is reaped; tell the monitor to drain and exit (POLLHUP usually
    // already fired, this is the backstop so join() never blocks forever)
    monitor_stop.store(true, std::sync::atomic::Ordering::Relaxed);

    let (violations_head, violations_count) = match monitor {
        Some(h) => match h.join() {
            Ok(m) => (m.head, m.count),
            Err(_) => {
                return Err(SandboxError::SetupFailed {
                    stage: "monitor".into(),
                    detail: "supervisor thread panicked".into(),
                })
            }
        },
        None => (proctor_monitor::chain::GENESIS.to_string(), 0),
    };

    // fail closed: no agent_exit and no timeout means setup never completed
    if agent_exit.is_none() && !timed_out {
        let detail = events
            .iter()
            .rev()
            .find_map(|e| match e {
                StatusEvent::SetupError { stage, error } => Some(format!("{stage}: {error}")),
                StatusEvent::ExecFailed { error } => Some(format!("agent exec: {error}")),
                _ => None,
            })
            .unwrap_or_else(|| format!("no handshake (events: {}, acked: {acked})", events.len()));
        return Err(SandboxError::SetupFailed {
            stage: "handshake".into(),
            detail,
        });
    }

    Ok(RunOutcome {
        agent_exit,
        timed_out,
        events,
        limits_degraded,
        violations_head,
        violations_count,
    })
}

/// alloc-free write to /proc/self/<name> for use inside pre_exec
fn write_proc_self(name: &str, content: &[u8]) -> std::io::Result<()> {
    use nix::fcntl::{open, OFlag};
    use nix::sys::stat::Mode;
    let path: &std::ffi::CStr = match name {
        "setgroups" => c"/proc/self/setgroups",
        "gid_map" => c"/proc/self/gid_map",
        "uid_map" => c"/proc/self/uid_map",
        _ => unreachable!(),
    };
    let fd = open(path, OFlag::O_WRONLY, Mode::empty()).map_err(std::io::Error::from)?;
    nix::unistd::write(fd, content).map_err(std::io::Error::from)?;
    Ok(())
}
