//! Host capability probe. Proctor fails closed at runtime if the host cannot
//! establish isolation; tests use `require_sandbox!` to skip-with-a-message.

use std::os::unix::process::CommandExt;
use std::process::Command;

#[derive(Debug, Clone, Copy)]
pub struct Caps {
    /// unshare(USER|MOUNT|PID|NET|IPC|UTS) works unprivileged
    pub userns: bool,
    /// overlayfs is available (listed in /proc/filesystems)
    pub overlayfs: bool,
    /// seccomp user-notification is available (actions_avail lists user_notif)
    pub seccomp: bool,
}

impl Caps {
    pub fn all(&self) -> bool {
        self.userns && self.overlayfs && self.seccomp
    }
}

pub fn probe() -> Caps {
    Caps {
        userns: probe_userns(),
        overlayfs: probe_overlayfs(),
        seccomp: probe_seccomp(),
    }
}

/// Spawn /bin/true under the full unshare set. Must be a spawned child:
/// unshare(CLONE_NEWUSER) fails in threaded processes (EINVAL), and the test
/// runner is threaded.
fn probe_userns() -> bool {
    let mut cmd = Command::new("/bin/true");
    unsafe {
        cmd.pre_exec(|| {
            use nix::sched::{unshare, CloneFlags};
            unshare(
                CloneFlags::CLONE_NEWUSER
                    | CloneFlags::CLONE_NEWNS
                    | CloneFlags::CLONE_NEWPID
                    | CloneFlags::CLONE_NEWNET
                    | CloneFlags::CLONE_NEWIPC
                    | CloneFlags::CLONE_NEWUTS,
            )
            .map_err(std::io::Error::from)?;
            Ok(())
        });
    }
    matches!(cmd.status(), Ok(s) if s.success())
}

fn probe_overlayfs() -> bool {
    std::fs::read_to_string("/proc/filesystems")
        .map(|s| s.lines().any(|l| l.trim_end().ends_with("overlay")))
        .unwrap_or(false)
}

fn probe_seccomp() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/seccomp/actions_avail")
        .map(|s| s.contains("user_notif"))
        .unwrap_or(false)
}

/// In tests that need a real sandbox: skip (with a loud message) on hosts that
/// cannot sandbox. Never silently pass.
#[macro_export]
macro_rules! require_sandbox {
    () => {
        let caps = $crate::caps::probe();
        if !caps.all() {
            eprintln!("SKIP: host cannot sandbox ({caps:?}); see README dev setup");
            return;
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_reports_all_capabilities_on_a_sandbox_capable_host() {
        // A host that cannot sandbox (e.g. Ubuntu 24.04 with unprivileged user
        // namespaces disabled by default) is not a Proctor failure — skip loudly
        // so a fresh clone's `cargo test` never shows a spurious red. CI sets
        // PROCTOR_REQUIRE_SANDBOX=1 to turn this back into a hard assertion.
        let c = probe();
        if std::env::var_os("PROCTOR_REQUIRE_SANDBOX").is_none() && !c.all() {
            eprintln!(
                "SKIP: host cannot sandbox ({c:?}); see README dev setup. \
                 Set PROCTOR_REQUIRE_SANDBOX=1 to make this a hard assertion (CI does)."
            );
            return;
        }
        assert!(c.userns, "unprivileged user namespaces unavailable");
        assert!(c.all(), "host cannot sandbox: {c:?}");
    }
}
