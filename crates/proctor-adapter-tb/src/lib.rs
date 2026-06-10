//! Terminal-Bench (Harbor format) adapter: map a task directory into a Proctor
//! policy + a run plan. Pure transformation — no execution, no sandbox.
//!
//! Harbor task layout (Terminal-Bench 2.x):
//! ```text
//! <task>/
//!   task.toml            metadata; agent.timeout_sec + environment.allow_internet
//!   instruction.md       the prompt
//!   environment/         Dockerfile + build context
//!   solution/solve.sh    reference solution (never shown to the agent)
//!   tests/{test.sh, test_outputs.py}   the oracle; writes /logs/verifier/reward.json
//! ```

pub mod rootfs;

use proctor_policy::{
    EnvPolicy, Forbidden, HostPort, Limits, NetworkMode, NetworkPolicy, Policy, Workspace,
};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("not a Terminal-Bench task: missing {0}")]
    MissingComponent(String),
    #[error("task.toml parse error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug)]
pub struct TbPlan {
    pub policy: Policy,
    pub instruction: String,
    pub oracle_dir: PathBuf,   // host path of tests/
    pub solution_dir: PathBuf, // host path of solution/ (may not exist)
    pub env_dir: PathBuf,      // host path of environment/
    pub workdir: PathBuf,      // in-sandbox agent cwd (Dockerfile WORKDIR, /app)
    pub grade_cmd: String,
}

#[derive(Debug, Default, Deserialize)]
struct TaskToml {
    #[serde(default)]
    agent: AgentSection,
    #[serde(default)]
    environment: EnvSection,
}

#[derive(Debug, Default, Deserialize)]
struct AgentSection {
    // real Harbor task.toml writes this as a float (e.g. 900.0)
    #[serde(default)]
    timeout_sec: Option<f64>,
}

#[derive(Debug, Default, Deserialize)]
struct EnvSection {
    // real Harbor gates egress here ([environment].allow_internet)
    #[serde(default)]
    allow_internet: bool,
}

pub fn load_task(dir: &Path) -> Result<TbPlan, AdapterError> {
    let require = |rel: &str| -> Result<PathBuf, AdapterError> {
        let p = dir.join(rel);
        if p.exists() {
            Ok(p)
        } else {
            Err(AdapterError::MissingComponent(rel.into()))
        }
    };
    let toml_path = require("task.toml")?;
    let tests = require("tests")?;
    let env_dir = require("environment")?;
    let instruction = std::fs::read_to_string(require("instruction.md")?)?;
    let solution = dir.join("solution"); // present in real tasks; mask if exists

    let cfg: TaskToml = toml::from_str(&std::fs::read_to_string(&toml_path)?)?;

    // the agent works in /app (TB Dockerfiles WORKDIR /app); mask the oracle +
    // solution paths the harness would otherwise stage there.
    let workdir = PathBuf::from("/app");
    let mut reads = vec![PathBuf::from("/tests"), PathBuf::from("/solution")];
    reads.push(tests.clone()); // also mask the host path if it leaks in
    if solution.exists() {
        reads.push(solution.clone());
    }

    let network = if cfg.environment.allow_internet {
        NetworkPolicy {
            mode: NetworkMode::Allowlist,
            allow: vec![
                HostPort {
                    host: "api.anthropic.com".into(),
                    port: 443,
                },
                HostPort {
                    host: "pypi.org".into(),
                    port: 443,
                },
                HostPort {
                    host: "files.pythonhosted.org".into(),
                    port: 443,
                },
            ],
        }
    } else {
        NetworkPolicy {
            mode: NetworkMode::Deny,
            allow: vec![],
        }
    };

    let policy = Policy {
        version: 1,
        workspace: Workspace {
            mount_at: workdir.clone(),
        },
        forbidden: Forbidden {
            reads,
            writes: vec![PathBuf::from("/logs/verifier")],
        },
        network,
        git: None,
        env: EnvPolicy {
            allow: if cfg.environment.allow_internet {
                vec!["ANTHROPIC_API_KEY".into()]
            } else {
                vec![]
            },
        },
        limits: Limits {
            wall_time_secs: cfg
                .agent
                .timeout_sec
                .map(|t| t.ceil() as u64)
                .unwrap_or(1800),
            ..Limits::default()
        },
    };

    // grade: run the task's own tests/test.sh against the true oracle (mounted
    // at /tests in the grader sandbox), which writes /logs/verifier/reward.json.
    let grade_cmd = "sh /tests/test.sh".to_string();

    Ok(TbPlan {
        policy,
        instruction,
        oracle_dir: tests,
        solution_dir: solution,
        env_dir,
        workdir,
        grade_cmd,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(p: &Path, s: &str) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, s).unwrap();
    }

    fn sample_task() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        let t = d.path();
        write(
            &t.join("task.toml"),
            "schema_version = \"1.1\"\n[metadata]\ndifficulty = \"medium\"\n[agent]\ntimeout_sec = 600.0\n[environment]\nallow_internet = false\n",
        );
        write(&t.join("instruction.md"), "Make the tests pass.\n");
        write(
            &t.join("environment/Dockerfile"),
            "FROM ubuntu:24.04\nWORKDIR /app\n",
        );
        write(
            &t.join("solution/solve.sh"),
            "#!/bin/sh\necho secret-solution\n",
        );
        write(
            &t.join("tests/test.sh"),
            "#!/bin/sh\npytest -q /tests/test_outputs.py\n",
        );
        write(
            &t.join("tests/test_outputs.py"),
            "def test_x():\n    assert open('/app/answer.txt').read().strip() == '42'\n",
        );
        d
    }

    #[test]
    fn maps_layout_to_policy_masking_oracle_and_solution() {
        let task = sample_task();
        let plan = load_task(task.path()).unwrap();
        let reads = &plan.policy.forbidden.reads;
        assert!(
            reads.contains(&PathBuf::from("/tests")),
            "tests must be masked: {reads:?}"
        );
        assert!(
            reads.contains(&PathBuf::from("/solution")),
            "solution must be masked: {reads:?}"
        );
        assert_eq!(plan.policy.network.mode, NetworkMode::Deny);
        assert_eq!(plan.policy.limits.wall_time_secs, 600);
        assert!(plan
            .policy
            .forbidden
            .writes
            .contains(&PathBuf::from("/logs/verifier")));
    }

    #[test]
    fn plan_points_at_oracle_and_grade_entrypoint() {
        let task = sample_task();
        let plan = load_task(task.path()).unwrap();
        assert!(plan.oracle_dir.ends_with("tests"));
        assert!(plan.instruction.contains("Make the tests pass"));
        assert_eq!(plan.workdir.to_str().unwrap(), "/app");
        assert!(plan.grade_cmd.contains("test.sh"));
    }

    #[test]
    fn allow_internet_becomes_allowlist_with_llm_api() {
        let task = sample_task();
        std::fs::write(
            task.path().join("task.toml"),
            "schema_version=\"1.1\"\n[environment]\nallow_internet = true\n",
        )
        .unwrap();
        let plan = load_task(task.path()).unwrap();
        assert_eq!(plan.policy.network.mode, NetworkMode::Allowlist);
        assert!(plan
            .policy
            .network
            .allow
            .iter()
            .any(|hp| hp.host.contains("anthropic")));
    }

    #[test]
    fn missing_required_dir_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("task.toml"), "version=\"1.0\"\n").unwrap();
        assert!(load_task(d.path()).is_err());
    }
}
