//! pid1 shim: first process in the new pid namespace. Mounts /proc, scrubs its
//! own environment, installs seccomp + passes the notify fd, waits for the
//! parent's ACK, then forks+execs the agent and reaps.

use crate::ipc::{emit, StatusEvent, ACK_FD, STATUS_FD};
use crate::spec::SandboxSpec;
use std::ffi::CString;
use std::os::fd::BorrowedFd;

pub fn pid1_main(spec: &SandboxSpec) -> ! {
    // /proc must be mounted by a member of the new pid namespace
    if let Err(e) = nix::mount::mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        nix::mount::MsFlags::MS_NOSUID
            | nix::mount::MsFlags::MS_NODEV
            | nix::mount::MsFlags::MS_NOEXEC,
        None::<&str>,
    ) {
        emit(
            STATUS_FD,
            &StatusEvent::SetupError {
                stage: "proc".into(),
                error: e.to_string(),
            },
        );
        std::process::exit(112);
    }
    // env-leak class: /proc/1/environ reads the startup environ from the stack,
    // which remove_var can't touch — the parent's `.env_clear()` on the init
    // Command is what keeps it empty. This loop clears the in-memory copy too.
    let keys: Vec<std::ffi::OsString> = std::env::vars_os().map(|(k, _)| k).collect();
    for k in keys {
        std::env::remove_var(k);
    }

    if spec.seccomp {
        if let Err(e) = crate::seccomp::install_and_send() {
            emit(
                STATUS_FD,
                &StatusEvent::SetupError {
                    stage: "seccomp".into(),
                    error: e,
                },
            );
            std::process::exit(112);
        }
    }
    emit(STATUS_FD, &StatusEvent::Sandboxed);

    // wait for the parent's ACK: cgroup applied + monitor armed before any agent syscall
    let mut b = [0u8; 1];
    let acked = matches!(
        nix::unistd::read(unsafe { BorrowedFd::borrow_raw(ACK_FD) }, &mut b),
        Ok(1)
    );
    if !acked {
        emit(
            STATUS_FD,
            &StatusEvent::SetupError {
                stage: "ack".into(),
                error: "no ack".into(),
            },
        );
        std::process::exit(112);
    }

    // allowlist mode: bind the in-ns forwarder listener BEFORE forking the
    // agent so its backlog absorbs an early connect (no race), but spawn the
    // accept thread only AFTER the fork (no fork-after-thread hazard). A bind
    // failure fails safe — the agent simply has no egress (over-isolated).
    let forwarder = match &spec.network {
        crate::spec::NetSpec::Allowlist { .. } => match crate::proxy::bind_in_ns_forwarder() {
            Ok(l) => Some(l),
            Err(e) => {
                eprintln!("proctor: forwarder bind failed, egress disabled: {e}");
                None
            }
        },
        crate::spec::NetSpec::Deny => None,
    };

    let agent = match spawn_agent(spec) {
        Ok(pid) => pid,
        Err(e) => {
            emit(STATUS_FD, &StatusEvent::ExecFailed { error: e });
            std::process::exit(127);
        }
    };

    if let (Some(listener), crate::spec::NetSpec::Allowlist { proxy_sock }) =
        (forwarder, &spec.network)
    {
        crate::proxy::serve_in_ns_forwarder(listener, proxy_sock);
    }

    // reap everything; exit with the agent's code when it finishes
    let code = loop {
        match nix::sys::wait::wait() {
            Ok(nix::sys::wait::WaitStatus::Exited(pid, c)) if pid == agent => break c,
            Ok(nix::sys::wait::WaitStatus::Signaled(pid, sig, _)) if pid == agent => {
                break 128 + sig as i32
            }
            Ok(_) => continue,                           // reaped an orphan
            Err(nix::errno::Errno::ECHILD) => break 111, // agent vanished
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => break 111,
        }
    };
    emit(STATUS_FD, &StatusEvent::AgentExit { code });
    std::process::exit(code);
}

fn spawn_agent(spec: &SandboxSpec) -> Result<nix::unistd::Pid, String> {
    match unsafe { nix::unistd::fork() }.map_err(|e| e.to_string())? {
        nix::unistd::ForkResult::Parent { child } => Ok(child),
        nix::unistd::ForkResult::Child => {
            let r = (|| -> Result<std::convert::Infallible, String> {
                std::env::set_current_dir(&spec.agent_cwd).map_err(|e| e.to_string())?;
                let sh = CString::new("/bin/sh").unwrap();
                let argv = [
                    sh.clone(),
                    CString::new("-c").unwrap(),
                    CString::new(spec.agent_cmd.as_str()).map_err(|e| e.to_string())?,
                ];
                let envp: Vec<CString> = spec
                    .env
                    .iter()
                    .map(|(k, v)| CString::new(format!("{k}={v}")).unwrap())
                    .collect();
                nix::unistd::execve(&sh, &argv, &envp).map_err(|e| e.to_string())
            })();
            emit(
                STATUS_FD,
                &StatusEvent::ExecFailed {
                    error: r.unwrap_err(),
                },
            );
            std::process::exit(127);
        }
    }
}
