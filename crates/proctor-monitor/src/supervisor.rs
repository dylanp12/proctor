//! Seccomp user-notification supervisor. Runs on a parent thread, owns the
//! notify fd, and turns intercepted syscalls into chained violation records.
//! ALWAYS replies CONTINUE: the monitor is audit-only; the mounts/netns do the
//! actual blocking. If this thread died, isolation would still hold.

use crate::chain::ChainWriter;
use crate::classify::{self, ClassifyCtx};
use crate::event::Violation;
use libseccomp::{notify_id_valid, ScmpNotifReq, ScmpNotifResp, ScmpNotifRespFlags};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::{Arc, Mutex};

pub struct MonitorHandle {
    pub head: String,
    pub count: u64,
}

/// Consume notifications on `notify_fd` until EOF (the sandbox exits), writing
/// violations to `chain`. `cwd` is the agent's working dir (for relative paths).
pub fn run(
    notify_fd: OwnedFd,
    chain: Arc<Mutex<ChainWriter>>,
    ctx: ClassifyCtx,
    cwd: String,
) -> MonitorHandle {
    let fd = notify_fd.as_raw_fd();
    let mut step: u64 = 0;
    let mut count: u64 = 0;
    loop {
        let req = match ScmpNotifReq::receive(fd) {
            Ok(r) => r,
            Err(_) => break, // fd closed / all filtered procs gone
        };
        step += 1;
        // TOCTOU bracket: only read target memory while the request is live
        let still_valid = notify_id_valid(fd, req.id).is_ok();
        let violation = if still_valid {
            classify(step, &req, &ctx, &cwd)
        } else {
            None
        };
        if let Some(v) = violation {
            if chain.lock().unwrap().append(&v).is_ok() {
                count += 1;
            }
        }
        // always continue: the syscall proceeds and fails on the masked fs / dead netns
        let resp = ScmpNotifResp::new_continue(req.id, ScmpNotifRespFlags::empty());
        if resp.respond(fd).is_err() {
            break;
        }
    }
    let head = chain.lock().unwrap().head().to_string();
    MonitorHandle { head, count }
}

fn classify(step: u64, req: &ScmpNotifReq, ctx: &ClassifyCtx, cwd: &str) -> Option<Violation> {
    let pid = req.pid as i32;
    let sc = req.data.syscall;
    let args = req.data.args;
    if sc == libc::SYS_openat as i32 {
        // openat(dirfd, pathname, flags, ...): path=args[1], flags=args[2]
        let raw = classify::read_path(pid, args[1])?;
        let abs = classify::absolutize(&raw, cwd);
        classify::classify_open(step, pid, abs, args[2], ctx)
    } else if sc == libc::SYS_openat2 as i32 {
        // openat2(dirfd, pathname, struct open_how*, size): flags in how.flags
        let raw = classify::read_path(pid, args[1])?;
        let abs = classify::absolutize(&raw, cwd);
        let flags = read_u64(pid, args[2]).unwrap_or(0);
        classify::classify_open(step, pid, abs, flags, ctx)
    } else if sc == libc::SYS_connect as i32 {
        // connect(fd, sockaddr*, addrlen): addr=args[1], len=args[2]
        classify::classify_connect(step, pid, args[1], args[2], ctx)
    } else {
        None
    }
}

fn read_u64(pid: i32, addr: u64) -> Option<u64> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
    f.seek(SeekFrom::Start(addr)).ok()?;
    let mut b = [0u8; 8];
    f.read_exact(&mut b).ok()?;
    Some(u64::from_ne_bytes(b))
}
