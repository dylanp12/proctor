//! Build a Terminal-Bench task's Docker image and export its filesystem to a
//! directory usable as an overlay lower (RootfsSpec::Dir). Requires docker.

use std::path::Path;
use std::process::Command;

#[derive(Debug, thiserror::Error)]
pub enum RootfsError {
    #[error("docker {step} failed: {stderr}")]
    Docker { step: String, stderr: String },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub fn docker_available() -> bool {
    Command::new("docker")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Build `context`/Dockerfile as `tag`, then export a container's rootfs to
/// `dest` (created). Uses `docker create` + `docker export | tar -x`.
pub fn export_rootfs(context: &Path, tag: &str, dest: &Path) -> Result<(), RootfsError> {
    let build = Command::new("docker")
        .args(["build", "-t", tag])
        .arg(context)
        .output()?;
    if !build.status.success() {
        return Err(RootfsError::Docker {
            step: "build".into(),
            stderr: String::from_utf8_lossy(&build.stderr).into(),
        });
    }
    let create = Command::new("docker").args(["create", tag]).output()?;
    if !create.status.success() {
        return Err(RootfsError::Docker {
            step: "create".into(),
            stderr: String::from_utf8_lossy(&create.stderr).into(),
        });
    }
    let cid = String::from_utf8_lossy(&create.stdout).trim().to_string();
    std::fs::create_dir_all(dest)?;
    let export = Command::new("docker")
        .args(["export", &cid])
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    let tar = Command::new("tar")
        .arg("-x")
        .arg("-C")
        .arg(dest)
        .stdin(export.stdout.unwrap())
        .output()?;
    let _ = Command::new("docker").args(["rm", "-f", &cid]).output();
    if !tar.status.success() {
        return Err(RootfsError::Docker {
            step: "export|tar".into(),
            stderr: String::from_utf8_lossy(&tar.stderr).into(),
        });
    }
    Ok(())
}
