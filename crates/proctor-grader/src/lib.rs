//! Isolated grading. The grader runs in its own sandbox that *can* see the
//! oracle and the agent's resulting workspace, but the agent is not present.
//! v1 supports two result protocols: process exit code, or a reward file.

use proctor_sandbox::spawn::{run_sandboxed, InitInvoker, SandboxError};
use proctor_sandbox::spec::{BindMount, NetSpec, RootfsSpec, SandboxSpec};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum GradeProtocol {
    /// pass iff the grade command exits 0
    ExitCode,
    /// pass iff the reward file parses to a positive reward (json {"reward":x}
    /// preferred; a bare number is the fallback)
    RewardFile { path: PathBuf },
}

#[derive(Debug, Clone)]
pub struct GradeRequest {
    pub workspace: PathBuf,       // host path: the agent's resulting workspace
    pub workspace_mount: PathBuf, // where the workspace is mounted (/workspace, /app)
    pub oracle: PathBuf,          // host path: the true oracle/tests
    pub oracle_mount: PathBuf,    // where the oracle is mounted for the grader
    pub grade_cmd: String,
    pub protocol: GradeProtocol,
    pub session: PathBuf,
    pub wall_time_secs: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GradeResult {
    pub pass: bool,
    pub reward: Option<f64>,
    pub exit_code: Option<i32>,
}

#[derive(Debug, thiserror::Error)]
pub enum GradeError {
    #[error(transparent)]
    Sandbox(#[from] SandboxError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("could not interpret reward file: {0}")]
    Reward(String),
}

pub fn grade(req: &GradeRequest, invoker: &InitInvoker) -> Result<GradeResult, GradeError> {
    // The grader sandbox sees the agent workspace (copied to an overlay lower)
    // plus the true oracle bound read-only at oracle_mount, and a writable
    // /logs the verifier can drop a reward file into.
    std::fs::create_dir_all(&req.session)?;
    let lower = req.session.join("grade_lower");
    let _ = std::fs::remove_dir_all(&lower);
    copy_tree(&req.workspace, &lower)?;

    let logs_host = req.session.join("grade_logs");
    std::fs::create_dir_all(&logs_host)?;

    let spec = SandboxSpec {
        rootfs: RootfsSpec::HostSystem,
        workspace_lower: Some(lower),
        mount_at: req.workspace_mount.clone(),
        masks: vec![],          // grader may see everything
        network: NetSpec::Deny, // grading is offline in v1
        env: vec![("PATH".into(), "/usr/bin:/bin:/usr/local/bin".into())],
        agent_cmd: req.grade_cmd.clone(),
        agent_cwd: req.workspace_mount.clone(),
        session: req.session.clone(),
        wall_time_secs: req.wall_time_secs,
        pids_limit: 256,
        memory_bytes: 2 * 1024 * 1024 * 1024,
        pivot: true,
        seccomp: false, // no audit needed for the grader
        host_proxy_sock: None,
        extra_binds: vec![
            BindMount {
                host: req.oracle.clone(),
                sandbox: req.oracle_mount.clone(),
                writable: false,
            },
            BindMount {
                host: logs_host.clone(),
                sandbox: "/logs".into(),
                writable: true,
            },
        ],
    };
    let out = run_sandboxed(&spec, invoker)?;
    let exit_code = out.agent_exit;

    match &req.protocol {
        GradeProtocol::ExitCode => Ok(GradeResult {
            pass: exit_code == Some(0),
            reward: None,
            exit_code,
        }),
        GradeProtocol::RewardFile { path } => {
            // the reward file landed in the writable /logs bind on the host side.
            // Harbor writes reward.json (preferred) or reward.txt (bare number);
            // accept whichever the verifier produced in that directory.
            let rel = path.strip_prefix("/logs").unwrap_or(path);
            let host_path = logs_host.join(rel);
            let candidates = [
                host_path.clone(),
                host_path.with_file_name("reward.json"),
                host_path.with_file_name("reward.txt"),
            ];
            let found = candidates.iter().find(|p| p.exists()).ok_or_else(|| {
                GradeError::Reward(format!("no reward file in {}", logs_host.display()))
            })?;
            let reward = read_reward(found)?;
            Ok(GradeResult {
                pass: reward > 0.0,
                reward: Some(reward),
                exit_code,
            })
        }
    }
}

fn read_reward(path: &std::path::Path) -> Result<f64, GradeError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| GradeError::Reward(format!("{}: {e}", path.display())))?;
    let raw = raw.trim();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
        if let Some(r) = v.get("reward").and_then(|x| x.as_f64()) {
            return Ok(r);
        }
        if let Some(r) = v.as_f64() {
            return Ok(r);
        }
    }
    raw.parse::<f64>()
        .map_err(|_| GradeError::Reward(format!("not a reward: {raw:?}")))
}

fn copy_tree(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in walkdir::WalkDir::new(src).follow_links(false) {
        let entry = entry.map_err(|e| std::io::Error::other(e.to_string()))?;
        let rel = entry.path().strip_prefix(src).unwrap();
        if rel.as_os_str().is_empty() {
            continue;
        }
        let target = dst.join(rel);
        if entry.file_type().is_dir() {
            std::fs::create_dir_all(&target)?;
        } else if entry.file_type().is_symlink() {
            let l = std::fs::read_link(entry.path())?;
            let _ = std::os::unix::fs::symlink(l, &target);
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}
