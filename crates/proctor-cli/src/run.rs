//! `proctor run` pipeline: policy -> materialize -> sandbox(agent) -> grade ->
//! signed verdict. Fail-closed: any setup error aborts before grading.

use anyhow::{Context, Result};
use proctor_grader::{grade, GradeProtocol, GradeRequest};
use proctor_policy::{NetworkMode, Policy};
use proctor_sandbox::spawn::{run_sandboxed, InitInvoker};
use proctor_sandbox::spec::{NetSpec, RootfsSpec, SandboxSpec};
use proctor_verdict::digest::env_digest;
use proctor_verdict::verdict::{Status, Verdict, VerdictBuilder};
use std::path::Path;

fn self_invoker() -> InitInvoker {
    InitInvoker {
        program: std::env::current_exe().expect("current exe"),
        prefix_args: vec!["__sandbox-init".into()],
    }
}

/// the agent-log artifacts of a run, as (name, host-path) pairs
fn agent_log_artifacts(session: &Path) -> Vec<(String, std::path::PathBuf)> {
    vec![
        ("agent-stdout.log".into(), session.join("agent-stdout.log")),
        ("agent-stderr.log".into(), session.join("agent-stderr.log")),
    ]
}

/// digest of the agent logs, folded into the signed verdict body
fn artifacts_digest_for(session: &Path) -> Result<String> {
    let arts = proctor_verdict::bundle::hash_artifacts(&agent_log_artifacts(session))?;
    Ok(proctor_verdict::digest::artifacts_digest(&arts))
}

/// write the portable bundle.json from the signed verdict + violations + logs
fn write_bundle(verdict: &Verdict, session: &Path, out: &Path) -> Result<()> {
    let arts = proctor_verdict::bundle::hash_artifacts(&agent_log_artifacts(session))?;
    let bundle = proctor_verdict::bundle::Bundle::build(
        verdict.clone(),
        &out.join("violations.jsonl"),
        &arts,
    )?;
    bundle.save(&out.join("bundle.json"))?;
    Ok(())
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
    let proxy = if let NetworkMode::Allowlist = policy.network.mode {
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

    run_sandboxed(&spec, &self_invoker()).context("agent sandbox run")?;

    // fold the proxy's egress denials into the timeline, then source the
    // verdict's head/count from the final file (monitor records + proxy denials)
    let (violations_head, violations_count) = finalize_violations(
        proxy.as_ref(),
        &session.join("violations.jsonl"),
        &out.join("violations.jsonl"),
    )?;

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
            workspace_mount: "/workspace".into(),
            oracle: task.join("oracle"),
            oracle_mount: "/oracle".into(),
            grade_cmd,
            protocol: GradeProtocol::ExitCode,
            session: out.join("grade-session"),
            wall_time_secs: policy.limits.wall_time_secs,
            network: proctor_grader::GraderNet::Deny,
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

    let signer =
        proctor_verdict::sign::resolve_signer(signing_seed, out).map_err(|e| anyhow::anyhow!(e))?;
    let art_digest = artifacts_digest_for(&session)?;

    let status = if violations_count > 0 {
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
        violations_head,
        violations_count,
        env_digest: digest,
        artifacts_digest: art_digest,
        reward: gr.reward,
    }
    .sign(&signer);

    verdict
        .save(&out.join("verdict.json"))
        .context("write verdict")?;
    write_bundle(&verdict, &session, out)?;
    Ok(verdict)
}

/// `proctor run-tb`: run a Terminal-Bench (Harbor) task under Proctor. With
/// `use_image` and docker present, the task's environment image becomes the
/// overlay-lower rootfs; otherwise the host system rootfs is used.
pub fn run_tb(task: &Path, agent_cmd: &str, out: &Path, use_image: bool) -> Result<Verdict> {
    let caps = proctor_sandbox::caps::probe();
    anyhow::ensure!(caps.all(), "host cannot sandbox (fail closed): {caps:?}");
    let plan = proctor_adapter_tb::load_task(task).context("load TB task")?;
    std::fs::create_dir_all(out)?;
    let session = out.join("agent-session");

    let rootfs = if use_image && proctor_adapter_tb::rootfs::docker_available() {
        let rootfs_dir = out.join("rootfs");
        let _ = std::fs::remove_dir_all(&rootfs_dir);
        let tag = format!(
            "proctor-tb-{}:latest",
            task.file_name().unwrap_or_default().to_string_lossy()
        );
        proctor_adapter_tb::rootfs::export_rootfs(&plan.env_dir, &tag, &rootfs_dir)
            .context("export task image rootfs")?;
        RootfsSpec::Dir(rootfs_dir)
    } else {
        if use_image {
            eprintln!("proctor: docker unavailable; using host rootfs (task env may differ)");
        }
        RootfsSpec::HostSystem
    };

    // materialize the agent workdir (/app). Seed from an optional task/workspace
    // dir if present; otherwise start empty (the agent creates files).
    let lower = session.join("ws_lower");
    let _ = std::fs::remove_dir_all(&lower);
    std::fs::create_dir_all(&lower)?;
    let seed = task.join("workspace");
    let mask_set = plan.policy.mask_set();
    if seed.is_dir() {
        proctor_sandbox::materialize::materialize_workspace(
            &seed,
            &plan.workdir,
            &mask_set,
            &lower,
        )
        .context("materialize workspace")?;
    }

    let network = match plan.policy.network.mode {
        NetworkMode::Deny => NetSpec::Deny,
        NetworkMode::Allowlist => NetSpec::Allowlist {
            proxy_sock: "/run/proctor/egress.sock".into(),
        },
    };
    let proxy = if let NetworkMode::Allowlist = plan.policy.network.mode {
        let sock = session.join("egress.sock");
        let allow: Vec<String> = plan
            .policy
            .network
            .allow
            .iter()
            .map(|hp| format!("{}:{}", hp.host, hp.port))
            .collect();
        Some(proctor_sandbox::proxy::HostProxy::start(&sock, allow).context("start egress proxy")?)
    } else {
        None
    };

    let mut env: Vec<(String, String)> =
        vec![("PATH".into(), "/usr/bin:/bin:/usr/local/bin:/app".into())];
    for k in &plan.policy.env.allow {
        if let Ok(v) = std::env::var(k) {
            env.push((k.clone(), v));
        }
    }

    let mut spec = SandboxSpec {
        rootfs,
        workspace_lower: Some(lower),
        mount_at: plan.workdir.clone(),
        masks: mask_set.iter().cloned().collect(),
        network,
        env,
        agent_cmd: agent_cmd.to_string(),
        agent_cwd: plan.workdir.clone(),
        session: session.clone(),
        wall_time_secs: plan.policy.limits.wall_time_secs,
        pids_limit: plan.policy.limits.pids,
        memory_bytes: plan.policy.limits.memory_bytes,
        pivot: true,
        seccomp: true,
        host_proxy_sock: None,
        extra_binds: vec![],
    };
    if let NetworkMode::Allowlist = plan.policy.network.mode {
        spec.host_proxy_sock = Some(session.join("egress.sock"));
    }

    run_sandboxed(&spec, &self_invoker()).context("agent sandbox run")?;
    let (violations_head, violations_count) = finalize_violations(
        proxy.as_ref(),
        &session.join("violations.jsonl"),
        &out.join("violations.jsonl"),
    )?;

    // grade: stage the agent's /app result + the oracle at /tests, run test.sh,
    // read the reward file the verifier wrote.
    let merged = out.join("graded-workspace");
    let _ = std::fs::remove_dir_all(&merged);
    merge_overlay(
        &session.join("ws_lower"),
        &session.join("ws_upper"),
        &merged,
    )?;
    let gr = grade(
        &GradeRequest {
            workspace: merged,
            workspace_mount: plan.workdir.clone(),
            oracle: plan.oracle_dir.clone(),
            oracle_mount: "/tests".into(),
            grade_cmd: plan.grade_cmd.clone(),
            protocol: GradeProtocol::RewardFile {
                path: "/logs/verifier/reward.json".into(),
            },
            session: out.join("grade-session"),
            wall_time_secs: plan.policy.limits.wall_time_secs,
            network: proctor_grader::GraderNet::Deny,
        },
        &self_invoker(),
    )
    .context("grade")?;

    let spec_json = serde_json::to_vec(&spec)?;
    let policy_yaml = plan.policy.to_yaml().context("policy to yaml")?;
    let versions = format!("proctor={}", env!("CARGO_PKG_VERSION"));
    let digest = env_digest(&[
        ("policy", policy_yaml.as_bytes()),
        ("spec", &spec_json),
        ("versions", versions.as_bytes()),
    ]);

    let signer =
        proctor_verdict::sign::resolve_signer(None, out).map_err(|e| anyhow::anyhow!(e))?;
    let art_digest = artifacts_digest_for(&session)?;
    let status = if violations_count > 0 {
        Status::Compromised
    } else {
        Status::Clean
    };
    let verdict = VerdictBuilder {
        task_id: task
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        pass: gr.pass,
        status,
        violations_head,
        violations_count,
        env_digest: digest,
        artifacts_digest: art_digest,
        reward: gr.reward,
    }
    .sign(&signer);
    verdict
        .save(&out.join("verdict.json"))
        .context("write verdict")?;
    write_bundle(&verdict, &session, out)?;
    Ok(verdict)
}

/// `proctor run-swebench`: materialize a SWE-bench instance's repo at its base
/// commit (fix history stripped), mask the answer artifacts, run the agent under
/// the sandbox + monitor, and emit a signed verdict + violations. This
/// sub-project does NOT grade (status + violations are the value); a graded run
/// needs the instance env and lands in a later sub-project.
pub fn run_swebench(
    instance_path: &Path,
    repo_clone: &Path,
    agent_cmd: &str,
    out: &Path,
) -> Result<Verdict> {
    let caps = proctor_sandbox::caps::probe();
    anyhow::ensure!(caps.all(), "host cannot sandbox (fail closed): {caps:?}");

    let instance_json = std::fs::read_to_string(instance_path).context("read instance")?;
    let plan = proctor_adapter_swebench::from_json(&instance_json).context("parse instance")?;

    std::fs::create_dir_all(out)?;
    let session = out.join("agent-session");

    // materialize the repo at base_commit with fix history stripped
    let lower = session.join("ws_lower");
    let _ = std::fs::remove_dir_all(&lower);
    proctor_sandbox::gitsan::sanitize_repo_at(repo_clone, &plan.base_commit, &lower)
        .context("git-sanitize repo to base commit")?;

    let masks: Vec<_> = plan.policy.mask_set().into_iter().collect();
    let spec = SandboxSpec {
        rootfs: RootfsSpec::HostSystem,
        workspace_lower: Some(lower),
        mount_at: plan.workdir.clone(),
        masks,
        network: NetSpec::Deny,
        env: vec![("PATH".into(), "/usr/bin:/bin:/usr/local/bin".into())],
        agent_cmd: agent_cmd.to_string(),
        agent_cwd: plan.workdir.clone(),
        session: session.clone(),
        wall_time_secs: plan.policy.limits.wall_time_secs,
        pids_limit: plan.policy.limits.pids,
        memory_bytes: plan.policy.limits.memory_bytes,
        pivot: true,
        seccomp: true,
        host_proxy_sock: None,
        extra_binds: vec![],
    };

    // grading (pass/reward) is deferred to a later sub-project; the value here is
    // the integrity verdict (status) + the violation timeline.
    run_sandboxed(&spec, &self_invoker()).context("agent sandbox run")?;
    let (violations_head, violations_count) = finalize_violations(
        None,
        &session.join("violations.jsonl"),
        &out.join("violations.jsonl"),
    )?;

    let spec_json = serde_json::to_vec(&spec)?;
    let policy_yaml = plan.policy.to_yaml().context("policy to yaml")?;
    let versions = format!("proctor={}", env!("CARGO_PKG_VERSION"));
    let digest = env_digest(&[
        ("policy", policy_yaml.as_bytes()),
        ("spec", &spec_json),
        ("versions", versions.as_bytes()),
    ]);

    let signer =
        proctor_verdict::sign::resolve_signer(None, out).map_err(|e| anyhow::anyhow!(e))?;
    let art_digest = artifacts_digest_for(&session)?;
    let status = if violations_count > 0 {
        Status::Compromised
    } else {
        Status::Clean
    };
    let verdict = VerdictBuilder {
        task_id: plan.instance_id.clone(),
        pass: false, // not graded in this sub-project
        status,
        violations_head,
        violations_count,
        env_digest: digest,
        artifacts_digest: art_digest,
        reward: None,
    }
    .sign(&signer);
    verdict
        .save(&out.join("verdict.json"))
        .context("write verdict")?;
    write_bundle(&verdict, &session, out)?;
    Ok(verdict)
}

/// Fold the host proxy's DENIED egress decisions into the monitor's
/// hash-chained timeline, copy it to the canonical output path, and return the
/// final `(head, count)` for the verdict — so the signed artifact reflects both
/// monitor-observed syscalls and proxy-refused egress in one chain.
fn finalize_violations(
    proxy: Option<&proctor_sandbox::proxy::HostProxy>,
    session_violations: &Path,
    out_violations: &Path,
) -> Result<(String, u64)> {
    use proctor_monitor::chain::{summary, ChainWriter, GENESIS};
    use proctor_monitor::event::{Violation, ViolationKind};

    if let Some(proxy) = proxy {
        let denied: Vec<_> = proxy
            .decisions()
            .into_iter()
            .filter(|d| !d.allowed)
            .collect();
        if !denied.is_empty() {
            let (_, existing) = summary(session_violations)?;
            let mut w = ChainWriter::open_append(session_violations)
                .context("open violations for append")?;
            for (i, d) in denied.iter().enumerate() {
                w.append(&Violation {
                    step: existing + 1 + i as u64,
                    kind: ViolationKind::BlockedConnect,
                    path: None,
                    host: Some(d.target.clone()),
                    pid: 0,
                    syscall: "proxy_connect".into(),
                })
                .context("append proxy denial")?;
            }
        }
    }
    let _ = std::fs::copy(session_violations, out_violations);
    Ok(summary(out_violations).unwrap_or((GENESIS.to_string(), 0)))
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
