//! Decode an intercepted syscall into a Violation (or None if benign):
//! read the path arg from the target's memory, or decode the sockaddr.

use crate::event::{Violation, ViolationKind};
use std::collections::BTreeSet;
use std::path::PathBuf;

/// Policy slice the supervisor needs to classify, passed from the parent.
#[derive(Debug, Clone)]
pub struct ClassifyCtx {
    pub mask_set: BTreeSet<PathBuf>,
    /// in deny mode: every connect is a violation; in allowlist: only non-allow
    pub net_deny_all: bool,
    pub net_allow: Vec<String>, // "host:port" — proxy enforces; this is belt
}

/// Read a NUL-terminated path from the target process memory at `addr`.
pub fn read_path(pid: i32, addr: u64) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
    f.seek(SeekFrom::Start(addr)).ok()?;
    let mut buf = [0u8; 4096];
    let n = f.read(&mut buf).ok()?;
    let end = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
    Some(String::from_utf8_lossy(&buf[..end]).into_owned())
}

/// Normalize a path to absolute (openat with AT_FDCWD gives a relative path
/// rooted at the agent cwd; we resolve against `cwd`).
pub fn absolutize(raw: &str, cwd: &str) -> String {
    if raw.starts_with('/') {
        normalize(raw)
    } else {
        normalize(&format!("{}/{}", cwd.trim_end_matches('/'), raw))
    }
}

fn normalize(p: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    format!("/{}", out.join("/"))
}

/// True if `path` is equal to or under any mask entry.
pub fn is_masked(path: &str, mask_set: &BTreeSet<PathBuf>) -> bool {
    let p = PathBuf::from(path);
    mask_set.iter().any(|m| p.starts_with(m))
}

/// open flags: O_WRONLY=1, O_RDWR=2 (low two bits) or O_CREAT => write intent.
pub fn classify_open(
    step: u64,
    pid: i32,
    path: String,
    flags: u64,
    ctx: &ClassifyCtx,
) -> Option<Violation> {
    if !is_masked(&path, &ctx.mask_set) {
        return None;
    }
    let write = (flags & 0b11) != 0 || (flags & libc::O_CREAT as u64) != 0;
    Some(Violation {
        step,
        kind: if write {
            ViolationKind::MaskedWrite
        } else {
            ViolationKind::MaskedRead
        },
        path: Some(path),
        host: None,
        pid,
        syscall: "openat".into(),
    })
}

/// Decode a sockaddr_in / sockaddr_in6 from target memory into "ip:port".
pub fn classify_connect(
    step: u64,
    pid: i32,
    addr_ptr: u64,
    addrlen: u64,
    ctx: &ClassifyCtx,
) -> Option<Violation> {
    let host = read_sockaddr(pid, addr_ptr, addrlen)?;
    let blocked = ctx.net_deny_all || !ctx.net_allow.iter().any(|a| a == &host);
    if !blocked {
        return None;
    }
    Some(Violation {
        step,
        kind: ViolationKind::BlockedConnect,
        path: None,
        host: Some(host),
        pid,
        syscall: "connect".into(),
    })
}

fn read_sockaddr(pid: i32, addr: u64, len: u64) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let len = len.min(128) as usize;
    if len < 4 {
        return None;
    }
    let mut f = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
    f.seek(SeekFrom::Start(addr)).ok()?;
    let mut buf = [0u8; 128];
    f.read_exact(&mut buf[..len]).ok()?;
    let family = u16::from_ne_bytes([buf[0], buf[1]]);
    match family as i32 {
        libc::AF_INET => {
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            Some(format!("{ip}:{port}"))
        }
        libc::AF_INET6 => {
            let port = u16::from_be_bytes([buf[2], buf[3]]);
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[8..24]);
            Some(format!("[{}]:{port}", std::net::Ipv6Addr::from(o)))
        }
        _ => None, // AF_UNIX etc. — not an egress attempt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(masks: &[&str]) -> ClassifyCtx {
        ClassifyCtx {
            mask_set: masks.iter().map(PathBuf::from).collect(),
            net_deny_all: true,
            net_allow: vec![],
        }
    }

    #[test]
    fn absolutize_resolves_relative_against_cwd() {
        assert_eq!(absolutize("a/b", "/work"), "/work/a/b");
        assert_eq!(absolutize("/oracle/x", "/work"), "/oracle/x");
        assert_eq!(absolutize("../escape", "/work/sub"), "/work/escape");
    }

    #[test]
    fn is_masked_matches_subtrees() {
        let c = ctx(&["/oracle"]);
        assert!(is_masked("/oracle/answer.txt", &c.mask_set));
        assert!(is_masked("/oracle", &c.mask_set));
        assert!(!is_masked("/workspace/readme", &c.mask_set));
    }

    #[test]
    fn classify_open_read_vs_write() {
        let c = ctx(&["/oracle"]);
        let r = classify_open(1, 9, "/oracle/a".into(), 0, &c).unwrap();
        assert_eq!(r.kind, ViolationKind::MaskedRead);
        let w = classify_open(2, 9, "/oracle/a".into(), 1, &c).unwrap();
        assert_eq!(w.kind, ViolationKind::MaskedWrite);
        let create = classify_open(3, 9, "/oracle/a".into(), libc::O_CREAT as u64, &c).unwrap();
        assert_eq!(create.kind, ViolationKind::MaskedWrite);
        assert!(classify_open(4, 9, "/workspace/ok".into(), 0, &c).is_none());
    }
}
