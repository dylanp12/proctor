//! Declarative per-task policy: what the agent must not reach.
//! Parsing is fail-closed: unknown fields, relative paths, malformed entries
//! are errors, never warnings.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("yaml parse error: {0}")]
    Parse(#[from] serde_yaml::Error),
    #[error("unsupported policy version {0} (expected 1)")]
    Version(u32),
    #[error("forbidden path must be absolute: {0}")]
    RelativePath(PathBuf),
    #[error("workspace.mount_at must be absolute: {0}")]
    RelativeMount(PathBuf),
    #[error("network.mode is allowlist but network.allow is empty")]
    EmptyAllowlist,
    #[error("network.allow entries present but mode is deny")]
    AllowEntriesInDenyMode,
    #[error("invalid host:port entry: {0}")]
    BadHostPort(String),
    #[error("git.base_commit is not a 40-char hex sha: {0}")]
    BadCommit(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    #[serde(default)]
    pub workspace: Workspace,
    #[serde(default)]
    pub forbidden: Forbidden,
    #[serde(default)]
    pub network: NetworkPolicy,
    #[serde(default)]
    pub git: Option<GitPolicy>,
    #[serde(default)]
    pub env: EnvPolicy,
    #[serde(default)]
    pub limits: Limits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workspace {
    pub mount_at: PathBuf,
}
impl Default for Workspace {
    fn default() -> Self {
        Self {
            mount_at: PathBuf::from("/workspace"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Forbidden {
    #[serde(default)]
    pub reads: Vec<PathBuf>,
    #[serde(default)]
    pub writes: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    Deny,
    Allowlist,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    pub mode: NetworkMode,
    #[serde(default, with = "hostport_strings")]
    pub allow: Vec<HostPort>,
}
impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            mode: NetworkMode::Deny,
            allow: vec![],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPort {
    pub host: String,
    pub port: u16,
}

/// Serialize HostPort as "host:port" strings inside the YAML list.
mod hostport_strings {
    use super::HostPort;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[HostPort], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(v.iter().map(|hp| format!("{}:{}", hp.host, hp.port)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<HostPort>, D::Error> {
        let raw = Vec::<String>::deserialize(d)?;
        raw.iter()
            .map(|s| super::parse_hostport(s).map_err(serde::de::Error::custom))
            .collect()
    }
}

fn parse_hostport(s: &str) -> Result<HostPort, String> {
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| format!("missing port in {s:?}"))?;
    let port: u16 = port.parse().map_err(|_| format!("bad port in {s:?}"))?;
    if host.is_empty() || port == 0 {
        return Err(format!("bad host:port {s:?}"));
    }
    Ok(HostPort {
        host: host.to_ascii_lowercase(),
        port,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitPolicy {
    pub base_commit: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvPolicy {
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default = "default_wall")]
    pub wall_time_secs: u64,
    #[serde(default = "default_pids")]
    pub pids: u64,
    #[serde(default = "default_mem")]
    pub memory_bytes: u64,
}
fn default_wall() -> u64 {
    1800
}
fn default_pids() -> u64 {
    512
}
fn default_mem() -> u64 {
    2 * 1024 * 1024 * 1024
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            wall_time_secs: default_wall(),
            pids: default_pids(),
            memory_bytes: default_mem(),
        }
    }
}

impl Policy {
    pub fn from_yaml(s: &str) -> Result<Self, PolicyError> {
        let p: Policy = serde_yaml::from_str(s)?;
        p.validate()?;
        Ok(p)
    }

    pub fn to_yaml(&self) -> Result<String, PolicyError> {
        Ok(serde_yaml::to_string(self)?)
    }

    fn validate(&self) -> Result<(), PolicyError> {
        if self.version != 1 {
            return Err(PolicyError::Version(self.version));
        }
        if !self.workspace.mount_at.is_absolute() {
            return Err(PolicyError::RelativeMount(self.workspace.mount_at.clone()));
        }
        for p in self.forbidden.reads.iter().chain(&self.forbidden.writes) {
            if !p.is_absolute() {
                return Err(PolicyError::RelativePath(p.clone()));
            }
        }
        match self.network.mode {
            NetworkMode::Allowlist if self.network.allow.is_empty() => {
                return Err(PolicyError::EmptyAllowlist)
            }
            NetworkMode::Deny if !self.network.allow.is_empty() => {
                return Err(PolicyError::AllowEntriesInDenyMode)
            }
            _ => {}
        }
        if let Some(g) = &self.git {
            if g.base_commit.len() != 40 || !g.base_commit.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(PolicyError::BadCommit(g.base_commit.clone()));
            }
        }
        Ok(())
    }

    /// The union of forbidden reads and writes: the set of paths that are
    /// masked in the agent's mount namespace and watched by the monitor.
    pub fn mask_set(&self) -> BTreeSet<PathBuf> {
        self.forbidden
            .reads
            .iter()
            .chain(&self.forbidden.writes)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"
version: 1
workspace: { mount_at: /workspace }
forbidden:
  reads: [/oracle, /tests]
  writes: [/logs/verifier]
network: { mode: allowlist, allow: ["api.anthropic.com:443"] }
git: { base_commit: "0123456789abcdef0123456789abcdef01234567" }
env: { allow: [ANTHROPIC_API_KEY] }
limits: { wall_time_secs: 60, pids: 64, memory_bytes: 1048576 }
"#;

    #[test]
    fn full_policy_round_trips() {
        let p = Policy::from_yaml(FULL).unwrap();
        assert_eq!(
            p.forbidden.reads,
            vec![PathBuf::from("/oracle"), PathBuf::from("/tests")]
        );
        assert_eq!(p.network.mode, NetworkMode::Allowlist);
        assert_eq!(
            p.network.allow,
            vec![HostPort {
                host: "api.anthropic.com".into(),
                port: 443
            }]
        );
        let y = p.to_yaml().unwrap();
        assert_eq!(Policy::from_yaml(&y).unwrap(), p);
    }

    #[test]
    fn minimal_policy_gets_closed_defaults() {
        let p = Policy::from_yaml("version: 1\n").unwrap();
        assert_eq!(p.network.mode, NetworkMode::Deny); // deny by default
        assert!(p.env.allow.is_empty()); // empty env by default
        assert_eq!(p.workspace.mount_at, PathBuf::from("/workspace"));
        assert_eq!(p.limits.wall_time_secs, 1800);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        // fail closed: a typo must not silently weaken policy
        assert!(matches!(
            Policy::from_yaml("version: 1\nforbiden: {reads: [/oracle]}\n"),
            Err(PolicyError::Parse(_))
        ));
    }

    #[test]
    fn wrong_version_rejected() {
        assert!(matches!(
            Policy::from_yaml("version: 2\n"),
            Err(PolicyError::Version(2))
        ));
    }

    #[test]
    fn relative_forbidden_path_rejected() {
        let e = Policy::from_yaml("version: 1\nforbidden: {reads: [oracle]}\n").unwrap_err();
        assert!(matches!(e, PolicyError::RelativePath(_)));
    }

    #[test]
    fn allowlist_mode_requires_entries_and_deny_requires_none() {
        assert!(matches!(
            Policy::from_yaml("version: 1\nnetwork: {mode: allowlist}\n"),
            Err(PolicyError::EmptyAllowlist)
        ));
        assert!(matches!(
            Policy::from_yaml("version: 1\nnetwork: {mode: deny, allow: [\"x:1\"]}\n"),
            Err(PolicyError::AllowEntriesInDenyMode)
        ));
    }

    #[test]
    fn bad_hostport_rejected() {
        for bad in ["no-port", "host:notanum", ":443", "host:0"] {
            let y = format!("version: 1\nnetwork: {{mode: allowlist, allow: [\"{bad}\"]}}\n");
            assert!(Policy::from_yaml(&y).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn bad_git_sha_rejected() {
        assert!(matches!(
            Policy::from_yaml("version: 1\ngit: {base_commit: nothex}\n"),
            Err(PolicyError::BadCommit(_))
        ));
    }

    #[test]
    fn mask_set_unions_reads_and_writes() {
        let p = Policy::from_yaml(FULL).unwrap();
        let m = p.mask_set();
        assert!(m.contains(&PathBuf::from("/oracle")));
        assert!(m.contains(&PathBuf::from("/logs/verifier")));
        assert_eq!(m.len(), 3);
    }
}
