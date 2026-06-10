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

    // masks: empty read-only tmpfs over each forbidden path
    for mask in &spec.masks {
        let target = join_abs(&newroot, mask);
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

    // /dev (minimal), /tmp, /run/proctor
    dev_minimal(&newroot)?;
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

fn dev_minimal(newroot: &Path) -> Result<(), MountError> {
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
    for node in ["null", "zero", "full", "random", "urandom", "tty"] {
        let src = PathBuf::from("/dev").join(node);
        let dst = dev.join(node);
        if !src.exists() {
            continue;
        }
        // bind-mount the device node (mknod is blocked in userns)
        let _ = std::fs::File::create(&dst);
        m(
            "bind-dev",
            &dst,
            mount(
                Some(&src),
                &dst,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            ),
        )?;
    }
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
