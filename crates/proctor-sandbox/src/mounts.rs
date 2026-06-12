//! New-root assembly and pivot_root. Runs inside sandbox-init (root in the
//! user namespace, single-threaded). Forbidden paths are masked with empty
//! read-only tmpfs; the workspace is an overlay; system dirs are ro-binds.

use crate::spec::{NetSpec, RootfsSpec, SandboxSpec};
use nix::mount::{mount, MsFlags};
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum MountError {
    #[error("{op} {target}: {source}")]
    Op {
        op: String,
        target: String,
        source: nix::Error,
    },
    #[error("io {target}: {source}")]
    Io {
        target: String,
        source: std::io::Error,
    },
}

fn m(op: &str, target: &Path, r: nix::Result<()>) -> Result<(), MountError> {
    r.map_err(|source| MountError::Op {
        op: op.into(),
        target: target.display().to_string(),
        source,
    })
}
fn mkdir(p: &Path) -> Result<(), MountError> {
    std::fs::create_dir_all(p).map_err(|source| MountError::Io {
        target: p.display().to_string(),
        source,
    })
}

pub fn build_and_pivot(spec: &SandboxSpec) -> Result<(), MountError> {
    let newroot = spec.session.join("newroot");
    mkdir(&newroot)?;
    // a tmpfs we fully own becomes the new root
    m(
        "tmpfs-newroot",
        &newroot,
        mount(
            Some("tmpfs"),
            &newroot,
            Some("tmpfs"),
            MsFlags::empty(),
            None::<&str>,
        ),
    )?;

    match &spec.rootfs {
        RootfsSpec::HostSystem => bind_system_dirs(&newroot)?,
        RootfsSpec::Dir(lower) => overlay_rootfs(spec, &newroot, lower)?,
    }

    // workspace overlay (writable upper)
    if let Some(lower) = &spec.workspace_lower {
        let at = join_abs(&newroot, &spec.mount_at);
        mkdir(&at)?;
        let upper = spec.session.join("ws_upper");
        let work = spec.session.join("ws_work");
        mkdir(&upper)?;
        mkdir(&work)?;
        let opts = format!(
            "lowerdir={},upperdir={},workdir={}",
            lower.display(),
            upper.display(),
            work.display()
        );
        m(
            "overlay-workspace",
            &at,
            mount(
                Some("overlay"),
                &at,
                Some("overlay"),
                MsFlags::empty(),
                Some(opts.as_str()),
            ),
        )?;
    }

    // extra binds (grader oracle ro + writable /logs). Before masks so a mask
    // always wins over an accidental overlap.
    for b in &spec.extra_binds {
        let target = join_abs(&newroot, &b.sandbox);
        if b.host.is_dir() {
            mkdir(&target)?;
        } else {
            if let Some(parent) = target.parent() {
                mkdir(parent)?;
            }
            let _ = std::fs::File::create(&target);
        }
        m(
            "extra-bind",
            &target,
            mount(
                Some(b.host.as_path()),
                &target,
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                None::<&str>,
            ),
        )?;
        if !b.writable {
            m(
                "extra-bind-ro",
                &target,
                mount(
                    None::<&str>,
                    &target,
                    None::<&str>,
                    MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_RDONLY,
                    None::<&str>,
                ),
            )?;
        }
    }

    // masks: hide each forbidden path. A path that already exists in the
    // workspace (e.g. a SWE-bench test file in the materialized repo) may be a
    // regular FILE — tmpfs needs a directory mountpoint, so we bind an empty
    // read-only file over a file, and use an empty read-only tmpfs over a
    // directory / absent path. Either way the open is intercepted + logged.
    let empty_mask = spec.session.join(".proctor-empty-mask");
    let _ = std::fs::File::create(&empty_mask);
    for mask in &spec.masks {
        let target = join_abs(&newroot, mask);
        if target.is_file() {
            m(
                "bind-file-mask",
                &target,
                mount(
                    Some(empty_mask.as_path()),
                    &target,
                    None::<&str>,
                    MsFlags::MS_BIND,
                    None::<&str>,
                ),
            )?;
            m(
                "bind-file-mask-ro",
                &target,
                mount(
                    None::<&str>,
                    &target,
                    None::<&str>,
                    MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                    None::<&str>,
                ),
            )?;
        } else {
            mkdir(&target)?;
            m(
                "tmpfs-mask",
                &target,
                mount(
                    Some("tmpfs"),
                    &target,
                    Some("tmpfs"),
                    MsFlags::MS_RDONLY,
                    None::<&str>,
                ),
            )?;
        }
    }

    // /dev (minimal), /tmp, /run/proctor
    dev_setup(&newroot)?;
    let tmp = newroot.join("tmp");
    mkdir(&tmp)?;
    m(
        "tmpfs-tmp",
        &tmp,
        mount(
            Some("tmpfs"),
            &tmp,
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            None::<&str>,
        ),
    )?;
    let run = newroot.join("run/proctor");
    mkdir(&run)?;
    m(
        "tmpfs-run",
        &run,
        mount(
            Some("tmpfs"),
            &run,
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            None::<&str>,
        ),
    )?;

    // allowlist mode: bridge the host proxy socket into the sandbox
    if let (NetSpec::Allowlist { proxy_sock }, Some(host)) = (&spec.network, &spec.host_proxy_sock)
    {
        let target = join_abs(&newroot, proxy_sock);
        if let Some(parent) = target.parent() {
            mkdir(parent)?;
        }
        let _ = std::fs::File::create(&target);
        m(
            "bind-proxy-sock",
            &target,
            mount(
                Some(host.as_path()),
                &target,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            ),
        )?;
    }

    // Host-net sandboxes (the grader) need working DNS. /etc is bound read-only
    // and /etc/resolv.conf is typically a symlink to the systemd-resolved stub
    // under /run — a fresh tmpfs here — so the symlink dangles and name
    // resolution fails. Recreate the stub target with the host's nameservers so
    // the symlink resolves (127.0.0.53 works over the shared host loopback).
    if matches!(spec.network, NetSpec::Host) {
        let content = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        let content = if content.contains("nameserver") {
            content
        } else {
            "nameserver 8.8.8.8\n".to_string()
        };
        let stub = newroot.join("run/systemd/resolve");
        let _ = std::fs::create_dir_all(&stub);
        let _ = std::fs::write(stub.join("stub-resolv.conf"), &content);
        let _ = std::fs::write(stub.join("resolv.conf"), &content);
    }

    // /proc mountpoint must exist for pid1 to mount onto
    mkdir(&newroot.join("proc"))?;

    pivot(&newroot)
}

fn bind_system_dirs(newroot: &Path) -> Result<(), MountError> {
    for dir in ["usr", "bin", "sbin", "lib", "lib64", "etc"] {
        let src = PathBuf::from("/").join(dir);
        if !src.exists() || src.is_symlink() {
            continue; // e.g. /bin -> usr/bin on merged-usr systems
        }
        let dst = newroot.join(dir);
        mkdir(&dst)?;
        m(
            "bind",
            &dst,
            mount(
                Some(&src),
                &dst,
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                None::<&str>,
            ),
        )?;
        // a bind cannot be created read-only in one call; remount to enforce ro
        m(
            "remount-ro",
            &dst,
            mount(
                None::<&str>,
                &dst,
                None::<&str>,
                MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_RDONLY,
                None::<&str>,
            ),
        )?;
    }
    // recreate merged-usr symlinks (/bin -> usr/bin) we skipped above
    for (link, target) in [
        ("bin", "usr/bin"),
        ("sbin", "usr/sbin"),
        ("lib", "usr/lib"),
        ("lib64", "usr/lib64"),
    ] {
        let lp = newroot.join(link);
        if !lp.exists() && Path::new("/").join(link).is_symlink() {
            let _ = std::os::unix::fs::symlink(target, &lp);
        }
    }
    Ok(())
}

fn overlay_rootfs(spec: &SandboxSpec, newroot: &Path, lower: &Path) -> Result<(), MountError> {
    let upper = spec.session.join("root_upper");
    let work = spec.session.join("root_work");
    mkdir(&upper)?;
    mkdir(&work)?;
    let opts = format!(
        "lowerdir={},upperdir={},workdir={}",
        lower.display(),
        upper.display(),
        work.display()
    );
    m(
        "overlay-root",
        newroot,
        mount(
            Some("overlay"),
            newroot,
            Some("overlay"),
            MsFlags::empty(),
            Some(opts.as_str()),
        ),
    )
}

fn dev_setup(newroot: &Path) -> Result<(), MountError> {
    // A tmpfs we own, so /dev/null is writable. In a single-uid user namespace
    // we cannot mknod, and a bind-mounted host device node is owned by an
    // unmapped uid (host root -> "nobody"), so the shell's `>` redirect
    // (O_CREAT|O_TRUNC) is denied — and we cannot map host uid 0 in (it is not
    // in our subuid range). So null/full become regular writable files we own
    // (writes discarded on teardown), while the read-only devices are bound
    // from the host (reads work fine). Safe under our threat model: /dev holds
    // no oracle and we are not defending against privilege escalation.
    let dev = newroot.join("dev");
    mkdir(&dev)?;
    m(
        "tmpfs-dev",
        &dev,
        mount(
            Some("tmpfs"),
            &dev,
            Some("tmpfs"),
            MsFlags::MS_NOSUID,
            None::<&str>,
        ),
    )?;
    // null + full: regular writable files we own so `cmd >/dev/null` works.
    for f in ["null", "full"] {
        let _ = std::fs::File::create(dev.join(f));
    }
    // zero/random/urandom/tty: real devices, bound from host (read works).
    for node in ["zero", "random", "urandom", "tty"] {
        let src = PathBuf::from("/dev").join(node);
        let dst = dev.join(node);
        if !src.exists() {
            continue;
        }
        let _ = std::fs::File::create(&dst);
        let _ = mount(
            Some(&src),
            &dst,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        );
    }
    // stdio symlinks many tools expect
    let _ = std::os::unix::fs::symlink("/proc/self/fd", dev.join("fd"));
    let _ = std::os::unix::fs::symlink("/proc/self/fd/0", dev.join("stdin"));
    let _ = std::os::unix::fs::symlink("/proc/self/fd/1", dev.join("stdout"));
    let _ = std::os::unix::fs::symlink("/proc/self/fd/2", dev.join("stderr"));
    Ok(())
}

/// Join an absolute sandbox path under newroot (strip leading '/').
fn join_abs(newroot: &Path, abs: &Path) -> PathBuf {
    newroot.join(abs.strip_prefix("/").unwrap_or(abs))
}

fn pivot(newroot: &Path) -> Result<(), MountError> {
    // pivot_root needs newroot to be a mount point: bind it onto itself
    m(
        "bind-self",
        newroot,
        mount(
            Some(newroot),
            newroot,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        ),
    )?;
    let oldroot = newroot.join(".oldroot");
    mkdir(&oldroot)?;
    nix::unistd::pivot_root(newroot, &oldroot).map_err(|source| MountError::Op {
        op: "pivot_root".into(),
        target: newroot.display().to_string(),
        source,
    })?;
    nix::unistd::chdir("/").map_err(|source| MountError::Op {
        op: "chdir".into(),
        target: "/".into(),
        source,
    })?;
    // The old root (carrying the host's /proc) stays mounted at /.oldroot on
    // purpose. pid1 mounts a fresh /proc next, and a non-initial user namespace
    // only permits `mount -t proc` when another proc instance is already visible
    // to vouch for it — the kernel's mount_too_revealing / mnt_already_visible
    // check. (WSL2's 6.18 kernel is lax and allows it regardless; ubuntu-24.04
    // CI runners are strict and return EPERM.) pid1 calls detach_oldroot()
    // immediately after the proc mount, before the agent is ever forked, so the
    // host root is never reachable from the agent.
    Ok(())
}

/// Detach the old root left mounted by `pivot`. Called from pid1 AFTER the fresh
/// /proc is mounted and BEFORE the agent is forked. Fails closed: the agent must
/// never see the host filesystem, so a failure to remove it aborts the run.
pub fn detach_oldroot() -> Result<(), MountError> {
    nix::mount::umount2("/.oldroot", nix::mount::MntFlags::MNT_DETACH).map_err(|source| {
        MountError::Op {
            op: "umount-oldroot".into(),
            target: "/.oldroot".into(),
            source,
        }
    })?;
    let _ = std::fs::remove_dir("/.oldroot");
    Ok(())
}
