//! sandbox-init: the first process inside the new namespaces (except pid —
//! unshare(CLONE_NEWPID) only applies to children, which is why pid1 is a
//! separate fork). Fresh exec => single-threaded => fork is safe.

use crate::ipc::{emit, StatusEvent, STATUS_FD};
use crate::spec::SandboxSpec;
use std::path::Path;

pub fn init_main(spec_path: &Path) -> ! {
    let spec = match SandboxSpec::load(spec_path) {
        Ok(s) => s,
        Err(e) => fail("load-spec", &e.to_string()),
    };
    if let Err(e) = setup(&spec) {
        fail(&e.0, &e.1);
    }
    // fork pid1 — the first process of the new pid namespace
    match unsafe { nix::unistd::fork() } {
        Ok(nix::unistd::ForkResult::Child) => crate::pid1::pid1_main(&spec), // never returns
        Ok(nix::unistd::ForkResult::Parent { child }) => {
            emit(
                STATUS_FD,
                &StatusEvent::Pid1 {
                    pid: child.as_raw(),
                },
            );
            let code = match nix::sys::wait::waitpid(child, None) {
                Ok(nix::sys::wait::WaitStatus::Exited(_, c)) => c,
                Ok(nix::sys::wait::WaitStatus::Signaled(_, sig, _)) => 128 + sig as i32,
                _ => 111,
            };
            std::process::exit(code);
        }
        Err(e) => fail("fork-pid1", &e.to_string()),
    }
}

struct Stage(String, String);

fn setup(spec: &SandboxSpec) -> Result<(), Stage> {
    let st = |stage: &'static str| move |e: nix::Error| Stage(stage.into(), e.to_string());
    // stop mount events from leaking back to the host
    nix::mount::mount(
        None::<&str>,
        "/",
        None::<&str>,
        nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(st("mount-private"))?;

    if spec.pivot {
        crate::mounts::build_and_pivot(spec).map_err(|e| Stage("mounts".into(), e.to_string()))?;
    }
    crate::net::setup(&spec.network).map_err(|e| Stage("net".into(), e))?;
    nix::unistd::sethostname("proctor").map_err(st("hostname"))?;
    emit(STATUS_FD, &StatusEvent::MountsReady);
    Ok(())
}

fn fail(stage: &str, error: &str) -> ! {
    emit(
        STATUS_FD,
        &StatusEvent::SetupError {
            stage: stage.to_string(),
            error: error.to_string(),
        },
    );
    std::process::exit(112); // distinct from any agent code path: setup failed, fail closed
}
