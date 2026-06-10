//! `proctor run` pipeline: policy -> materialize -> sandbox(agent) -> grade ->
//! signed verdict. Fail-closed: any setup error aborts before grading.

use anyhow::{Context, Result};
use proctor_grader::{grade, GradeProtocol, GradeRequest};
use proctor_policy::{NetworkMode, Policy};
use proctor_sandbox::spawn::{run_sandboxed, InitInvoker};
use proctor_sandbox::spec::{NetSpec, RootfsSpec, SandboxSpec};
use proctor_verdict::digest::env_digest;
use proctor_verdict::sign::Signer;
use proctor_verdict::verdict::{Status, Verdict, VerdictBuilder};
use std::path::Path;

fn self_invoker() -> InitInvoker {
    InitInvoker {
        program: std::env::current_exe().expect("current exe"),
        prefix_args: vec!["__sandbox-init".into()],
    }
}

pub fn run(
    task: &Path,
    agent_cmd: &str,
    policy_path: &Path,
    out: &Path,
    signing_seed: Option<&str>,
) -> Result<Verdict> {
    let caps = proctor_sandbox::caps::probe();
    anyhow::ensure!(caps.all(), "host cannot sandbox (fail closed): {caps:?}");

    let policy_yaml = std::fs::read_to_string(policy_path).context("read policy")?;
    let policy = Policy::from_yaml(&policy_yaml).context("parse policy")?;

    std::fs::create_dir_all(out)?;
    let session = out.join("agent-session");

    // materialize the agent workspace (forbidden paths excluded)
    let workspace_src = task.join("workspace");
    let lower = session.join("ws_lower");
    let _ = std::fs::remove_dir_all(&lower);
    std::fs::create_dir_all(&lower)?;
    let mask_set = policy.mask_set();
    proctor_sandbox::materialize::materialize_workspace(
        &workspace_src,
        &policy.workspace.mount_at,
        &mask_set,
        &lower,
    )
    .context("materialize workspace")?;

    // build the agent env from the policy passlist
    let mut env: Vec<(String, String)> =
        vec![("PATH".into(), "/usr/bin:/bin:/usr/local/bin".into())];
    for key in &policy.env.allow {
        if let Ok(val) = std::env::var(key) {
            env.push((key.clone(), val));
        }
    }

    let network = match policy.network.mode {
        NetworkMode::Deny => NetSpec::Deny,
        NetworkMode::Allowlist => NetSpec::Allowlist {
            proxy_sock: "/run/proctor/egress.sock".into(),
        },
    };

    // host proxy for allowlist mode (kept alive for the run's duration)
    let _proxy = if let NetworkMode::Allowlist = policy.network.mode {
        let sock = session.join("egress.sock");
        let allow: Vec<String> = policy
            .network
            .allow
            .iter()
            .map(|hp| format!("{}:{}", hp.host, hp.port))
            .collect();
        Some(proctor_sandbox::proxy::HostProxy::start(&sock, allow).context("start egress proxy")?)
    } else {
        None
    };

    let mut spec = SandboxSpec {
        rootfs: RootfsSpec::HostSystem,
        workspace_lower: Some(lower),
        mount_at: policy.workspace.mount_at.clone(),
        masks: mask_set.iter().cloned().collect(),
        network,
        env,
        agent_cmd: agent_cmd.to_string(),
        agent_cwd: policy.workspace.mount_at.clone(),
        session: session.clone(),
        wall_time_secs: policy.limits.wall_time_secs,
        pids_limit: policy.limits.pids,
        memory_bytes: policy.limits.memory_bytes,
        pivot: true,
        seccomp: true,
        host_proxy_sock: None,
        extra_binds: vec![],
    };
    if let NetworkMode::Allowlist = policy.network.mode {
        spec.host_proxy_sock = Some(session.join("egress.sock"));
    }

    let outcome = run_sandboxed(&spec, &self_invoker()).context("agent sandbox run")?;

    // canonical artifact: the violations timeline
    let violations_out = out.join("violations.jsonl");
    let _ = std::fs::copy(session.join("violations.jsonl"), &violations_out);

    // grade in a second sandbox vs. the true oracle (overlay upper holds the
    // agent's writes; merge lower+upper into a flat view for grading)
    let merged = out.join("graded-workspace");
    let _ = std::fs::remove_dir_all(&merged);
    merge_overlay(
        &session.join("ws_lower"),
        &session.join("ws_upper"),
        &merged,
    )?;

    let grade_cmd = std::fs::read_to_string(task.join("grade.sh")).context("read grade.sh")?;
    let gr = grade(
        &GradeRequest {
            workspace: merged,
            oracle: task.join("oracle"),
            oracle_mount: "/oracle".into(),
            grade_cmd,
            protocol: GradeProtocol::ExitCode,
            session: out.join("grade-session"),
            wall_time_secs: policy.limits.wall_time_secs,
        },
        &self_invoker(),
    )
    .context("grade")?;

    // env digest binds policy + spec + tool versions
    let spec_json = serde_json::to_vec(&spec)?;
    let versions = format!("proctor={}", env!("CARGO_PKG_VERSION"));
    let digest = env_digest(&[
        ("policy", policy_yaml.as_bytes()),
        ("spec", &spec_json),
        ("versions", versions.as_bytes()),
    ]);

    let signer = match signing_seed {
        Some(hex_seed) => {
            let seed: [u8; 32] = hex::decode(hex_seed)
                .context("decode seed")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("seed must be 32 bytes"))?;
            Signer::from_bytes(&seed)
        }
        None => {
            let s = Signer::generate();
            std::fs::write(out.join("signing-seed.hex"), s.to_seed_hex())?;
            s
        }
    };

    let status = if outcome.violations_count > 0 {
        Status::Compromised
    } else {
        Status::Clean
    };
    let verdict = VerdictBuilder {
        task_id: task
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "task".into()),
        pass: gr.pass,
        status,
        violations_head: outcome.violations_head.clone(),
        violations_count: outcome.violations_count,
        env_digest: digest,
        reward: gr.reward,
    }
    .sign(&signer);

    verdict
        .save(&out.join("verdict.json"))
        .context("write verdict")?;
    Ok(verdict)
}

/// Compose lower + overlay-upper into a flat directory for grading.
fn merge_overlay(lower: &Path, upper: &Path, dest: &Path) -> Result<()> {
    copy_tree(lower, dest)?;
    if upper.exists() {
        copy_tree(upper, dest)?; // upper wins (agent's writes)
    }
    Ok(())
}

fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for e in walkdir::WalkDir::new(src).follow_links(false) {
        let e = e?;
        let rel = e.path().strip_prefix(src).unwrap();
        if rel.as_os_str().is_empty() {
            continue;
        }
        let t = dst.join(rel);
        if e.file_type().is_dir() {
            std::fs::create_dir_all(&t)?;
        } else if e.file_type().is_symlink() {
            let l = std::fs::read_link(e.path())?;
            let _ = std::os::unix::fs::symlink(l, &t);
        } else {
            std::fs::copy(e.path(), &t)?;
        }
    }
    Ok(())
}
