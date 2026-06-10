//! The serialized contract between `proctor run` (parent) and the re-exec'd
//! sandbox-init process. Everything init needs is in this one JSON file.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RootfsSpec {
    /// ro-bind the host's system dirs (/usr, /etc, ...) into the new root
    HostSystem,
    /// overlay an exported container rootfs (lower) — TB image mode
    Dir(PathBuf),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetSpec {
    /// empty netns, lo up: egress impossible by construction
    Deny,
    /// empty netns + unix-socket CONNECT proxy bridged at proxy_sock
    Allowlist { proxy_sock: PathBuf },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxSpec {
    pub rootfs: RootfsSpec,
    /// materialized workspace lower dir (host path); None = no workspace mount
    pub workspace_lower: Option<PathBuf>,
    pub mount_at: PathBuf,
    /// sandbox-absolute paths to tmpfs-mask (policy mask_set + adapter additions)
    pub masks: Vec<PathBuf>,
    pub network: NetSpec,
    /// the agent's exact environment (parent computes from policy passlist)
    pub env: Vec<(String, String)>,
    pub agent_cmd: String,
    pub agent_cwd: PathBuf,
    /// session dir (host path): spec.json, upper/, work/, newroot/, logs
    pub session: PathBuf,
    pub wall_time_secs: u64,
    pub pids_limit: u64,
    pub memory_bytes: u64,
    /// build + pivot into the isolated rootfs. false = host fs (tests only)
    pub pivot: bool,
    /// install the unotify filter and pass the fd to the parent monitor
    pub seccomp: bool,
    /// host path of the proxy unix socket (bind-mounted to network.proxy_sock)
    #[serde(default)]
    pub host_proxy_sock: Option<PathBuf>,
}

impl SandboxSpec {
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        std::fs::write(path, serde_json::to_vec_pretty(self)?)
    }
    pub fn load(path: &std::path::Path) -> std::io::Result<Self> {
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    }
    pub fn with_host_proxy_sock(mut self, p: &std::path::Path) -> Self {
        self.host_proxy_sock = Some(p.to_path_buf());
        self
    }
}
