//! Network namespace finishing. Default-deny is free (empty netns has no
//! route); we only bring loopback up. The allowlist forwarder is started later
//! in pid1 (init cannot create threads after unshare(CLONE_NEWPID): its
//! pid_ns_for_children differs from its own, so clone(CLONE_THREAD) -> EINVAL).

use crate::spec::NetSpec;

pub fn setup(net: &NetSpec) -> Result<(), String> {
    // Host shares the host's network namespace; do not touch host interfaces.
    if matches!(net, NetSpec::Host) {
        return Ok(());
    }
    bring_loopback_up().map_err(|e| format!("lo up: {e}"))
}

/// Equivalent of `ip link set lo up`: SIOCGIFFLAGS / SIOCSIFFLAGS with IFF_UP.
fn bring_loopback_up() -> nix::Result<()> {
    use std::os::fd::AsRawFd;
    let sock = nix::sys::socket::socket(
        nix::sys::socket::AddressFamily::Inet,
        nix::sys::socket::SockType::Datagram,
        nix::sys::socket::SockFlag::empty(),
        None,
    )?;
    #[repr(C)]
    struct IfReq {
        name: [libc::c_char; libc::IFNAMSIZ],
        flags: libc::c_short,
        _pad: [u8; 22],
    }
    let mut req: IfReq = unsafe { std::mem::zeroed() };
    for (i, b) in b"lo".iter().enumerate() {
        req.name[i] = *b as libc::c_char;
    }
    let fd = sock.as_raw_fd();
    // SIOCGIFFLAGS = 0x8913, SIOCSIFFLAGS = 0x8914
    if unsafe { libc::ioctl(fd, 0x8913, &mut req) } < 0 {
        return Err(nix::errno::Errno::last());
    }
    req.flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
    if unsafe { libc::ioctl(fd, 0x8914, &req) } < 0 {
        return Err(nix::errno::Errno::last());
    }
    Ok(())
}
