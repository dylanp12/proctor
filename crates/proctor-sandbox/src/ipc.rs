//! Status events (init/pid1 -> parent, JSON lines over fd 100) and
//! SCM_RIGHTS fd passing (pid1 -> parent over the fd-101 socketpair).

use serde::{Deserialize, Serialize};
use std::io::BufRead;
use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd, RawFd};

pub const STATUS_FD: RawFd = 100;
pub const SECCOMP_FD: RawFd = 101;
pub const ACK_FD: RawFd = 102;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum StatusEvent {
    MountsReady,
    /// pid1's pid as seen from the HOST pid namespace (init's fork return)
    Pid1 {
        pid: i32,
    },
    Sandboxed,
    ExecFailed {
        error: String,
    },
    AgentExit {
        code: i32,
    },
    SetupError {
        stage: String,
        error: String,
    },
}

impl StatusEvent {
    pub fn kind(&self) -> &'static str {
        match self {
            StatusEvent::MountsReady => "mounts_ready",
            StatusEvent::Pid1 { .. } => "pid1",
            StatusEvent::Sandboxed => "sandboxed",
            StatusEvent::ExecFailed { .. } => "exec_failed",
            StatusEvent::AgentExit { .. } => "agent_exit",
            StatusEvent::SetupError { .. } => "setup_error",
        }
    }
}

/// Child side: write one event line to the status fd (does not take ownership,
/// so later events can still be emitted). Failure to report is fatal context.
pub fn emit(fd: RawFd, ev: &StatusEvent) {
    let mut line = serde_json::to_vec(ev).expect("event serializes");
    line.push(b'\n');
    let bfd = unsafe { BorrowedFd::borrow_raw(fd) };
    let mut off = 0;
    while off < line.len() {
        match nix::unistd::write(bfd, &line[off..]) {
            Ok(0) => break,
            Ok(n) => off += n,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => break,
        }
    }
}

/// Parent side: blocking line reader over the status pipe read end.
pub fn read_events(read_end: std::fs::File) -> impl Iterator<Item = std::io::Result<StatusEvent>> {
    let reader = std::io::BufReader::new(read_end);
    reader.lines().map(|l| {
        let l = l?;
        serde_json::from_str(&l)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e}: {l}")))
    })
}

/// SCM_RIGHTS: send one fd over a unix socket (by raw fd numbers).
pub fn send_fd(sock: RawFd, fd: RawFd) -> nix::Result<()> {
    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags};
    let fds = [fd];
    let cmsg = [ControlMessage::ScmRights(&fds)];
    let iov = [std::io::IoSlice::new(b"F")];
    sendmsg::<()>(sock, &iov, &cmsg, MsgFlags::empty(), None)?;
    Ok(())
}

/// SCM_RIGHTS: receive one fd.
pub fn recv_fd(sock: RawFd) -> nix::Result<OwnedFd> {
    use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
    let mut buf = [0u8; 1];
    let mut iov = [std::io::IoSliceMut::new(&mut buf)];
    let mut cmsg = nix::cmsg_space!([RawFd; 1]);
    let msg = recvmsg::<()>(sock, &mut iov, Some(&mut cmsg), MsgFlags::empty())?;
    for c in msg.cmsgs()? {
        if let ControlMessageOwned::ScmRights(fds) = c {
            if let Some(&fd) = fds.first() {
                return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
            }
        }
    }
    Err(nix::errno::Errno::EBADMSG)
}
