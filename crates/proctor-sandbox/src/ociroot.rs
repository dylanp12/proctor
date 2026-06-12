//! Daemonless container-image -> rootfs directory (an overlay lower for
//! RootfsSpec::Dir). Prefers podman (rootless/daemonless), falls back to docker.
//! Used to materialize a benchmark's pinned image BEFORE sandboxing — Proctor
//! never runs a container runtime; this only fetches + unpacks the image.

use std::path::Path;
use std::process::{Command, Stdio};

#[derive(Debug, thiserror::Error)]
pub enum OciError {
    #[error("no container tool found (need podman or docker on PATH)")]
    NoTool,
    #[error("{tool} {step} failed: {stderr}")]
    Tool {
        tool: String,
        step: String,
        stderr: String,
    },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// First working container CLI, preferring the daemonless one.
pub fn container_tool() -> Option<String> {
    for t in ["podman", "docker"] {
        let ok = Command::new(t)
            .arg("version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return Some(t.to_string());
        }
    }
    None
}

/// Fetch `image_ref` (auto-pulls) and export its filesystem into `dest` (created).
/// `<tool> create <ref>` -> cid -> `<tool> export <cid> | tar -x -C dest`.
pub fn export_image_rootfs(image_ref: &str, dest: &Path) -> Result<(), OciError> {
    let tool = container_tool().ok_or(OciError::NoTool)?;
    let create = Command::new(&tool).args(["create", image_ref]).output()?;
    if !create.status.success() {
        return Err(OciError::Tool {
            tool,
            step: "create".into(),
            stderr: String::from_utf8_lossy(&create.stderr).into(),
        });
    }
    let cid = String::from_utf8_lossy(&create.stdout).trim().to_string();
    std::fs::create_dir_all(dest)?;
    let export = Command::new(&tool)
        .args(["export", &cid])
        .stdout(Stdio::piped())
        .spawn()?;
    let tar = Command::new("tar")
        .arg("-x")
        .arg("-C")
        .arg(dest)
        .stdin(export.stdout.unwrap())
        .output()?;
    let _ = Command::new(&tool).args(["rm", "-f", &cid]).output();
    if !tar.status.success() {
        return Err(OciError::Tool {
            tool,
            step: "export|tar".into(),
            stderr: String::from_utf8_lossy(&tar.stderr).into(),
        });
    }
    Ok(())
}
