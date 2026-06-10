//! Build + install the unotify filter in pid1, and hand the notify fd to the
//! parent over the fd-101 socketpair. The filter notifies on openat/openat2/
//! connect and allows everything else. None of the syscalls pid1 runs between
//! load() and the agent exec are on the notify list, so there is no deadlock
//! before the parent's monitor is armed.

use crate::ipc::{send_fd, SECCOMP_FD};
use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};
use std::os::fd::{FromRawFd, OwnedFd};

pub fn install_and_send() -> Result<(), String> {
    let mut ctx = ScmpFilterContext::new(ScmpAction::Allow).map_err(|e| e.to_string())?;
    ctx.set_ctl_nnp(true).map_err(|e| e.to_string())?;
    // notify on the file-open and connect syscalls. `open` is included for
    // hostile harnesses that issue the raw syscall (glibc routes open()->openat,
    // but a crafted binary need not); it is skipped on arches without it.
    for name in ["open", "openat", "openat2", "connect"] {
        if let Ok(sc) = ScmpSyscall::from_name(name) {
            ctx.add_rule(ScmpAction::Notify, sc)
                .map_err(|e| e.to_string())?;
        }
    }
    ctx.load().map_err(|e| e.to_string())?;
    let notify_fd = ctx.get_notify_fd().map_err(|e| e.to_string())?;
    send_fd(SECCOMP_FD, notify_fd).map_err(|e| format!("send notify fd: {e}"))?;
    // close pid1's copy; the parent's SCM_RIGHTS dup keeps the channel alive
    unsafe {
        drop(OwnedFd::from_raw_fd(notify_fd));
    }
    Ok(())
}
