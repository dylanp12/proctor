mod run;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "proctor",
    version,
    about = "Tamper-proof sandbox for trustworthy agent benchmarks"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run an agent on a task under isolation; emit a signed verdict + violations log.
    Run {
        #[arg(long)]
        task: PathBuf,
        #[arg(long)]
        agent: String,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// hex ed25519 seed (32 bytes); generated + saved if omitted
        #[arg(long)]
        signing_seed: Option<String>,
    },
    /// Run a Terminal-Bench (Harbor) task directory under Proctor.
    RunTb {
        #[arg(long)]
        task: PathBuf,
        #[arg(long)]
        agent: String,
        #[arg(long)]
        out: PathBuf,
        /// build the task's docker image as the rootfs (default: host rootfs)
        #[arg(long)]
        image: bool,
    },
    /// Run a SWE-bench instance under Proctor (repo at base commit, fix history
    /// stripped, answer artifacts masked). Does not grade in v1.
    RunSwebench {
        #[arg(long)]
        instance: PathBuf,
        #[arg(long)]
        repo: PathBuf,
        #[arg(long)]
        agent: String,
        #[arg(long)]
        out: PathBuf,
        /// run the SWE-bench tests and grade pass/reward (needs network for
        /// dep install; intended for CI, not the local machine)
        #[arg(long)]
        grade: bool,
    },
    /// Verify a verdict's signature against a public key.
    Verify {
        #[arg(long)]
        verdict: PathBuf,
        #[arg(long)]
        pubkey: String,
    },
    /// Verify a run bundle: signature, violation chain, and artifact hashes.
    VerifyBundle {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        pubkey: Option<String>,
    },
    /// Print a fresh signing seed + its public key (for PROCTOR_SIGNING_SEED).
    Keygen,
    /// Print host sandbox capabilities.
    Probe,
    /// Internal: sandbox-init re-exec target. Not for direct use.
    #[command(name = "__sandbox-init", hide = true)]
    SandboxInit {
        #[arg(long)]
        spec: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.cmd {
        Cmd::SandboxInit { spec } => proctor_sandbox::init::init_main(&spec), // never returns
        Cmd::Run {
            task,
            agent,
            policy,
            out,
            signing_seed,
        } => match run::run(&task, &agent, &policy, &out, signing_seed.as_deref()) {
            Ok(v) => {
                println!(
                    "verdict: pass={} status={:?} violations={}",
                    v.body.pass, v.body.status, v.body.violations_count
                );
                0
            }
            Err(e) => {
                eprintln!("proctor: run failed: {e:#}");
                1
            }
        },
        Cmd::RunTb {
            task,
            agent,
            out,
            image,
        } => match run::run_tb(&task, &agent, &out, image) {
            Ok(v) => {
                println!(
                    "verdict: pass={} status={:?} violations={} reward={:?}",
                    v.body.pass, v.body.status, v.body.violations_count, v.body.reward
                );
                0
            }
            Err(e) => {
                eprintln!("proctor: run-tb failed: {e:#}");
                1
            }
        },
        Cmd::RunSwebench {
            instance,
            repo,
            agent,
            out,
            grade,
        } => match run::run_swebench(&instance, &repo, &agent, &out, grade) {
            Ok(v) => {
                println!(
                    "verdict: pass={} status={:?} violations={} reward={:?}",
                    v.body.pass, v.body.status, v.body.violations_count, v.body.reward
                );
                0
            }
            Err(e) => {
                eprintln!("proctor: run-swebench failed: {e:#}");
                1
            }
        },
        Cmd::Verify { verdict, pubkey } => {
            let raw = std::fs::read(&verdict).expect("read verdict");
            let v: proctor_verdict::verdict::Verdict =
                serde_json::from_slice(&raw).expect("parse verdict");
            match v.verify(&pubkey) {
                Ok(()) => {
                    println!("verdict OK: signature valid, status={:?}", v.body.status);
                    0
                }
                Err(e) => {
                    eprintln!("verdict INVALID: {e}");
                    2
                }
            }
        }
        Cmd::VerifyBundle { bundle, pubkey } => {
            match proctor_verdict::bundle::Bundle::load(&bundle) {
                Ok(b) => match b.verify(pubkey.as_deref()) {
                    Ok(()) => {
                        println!(
                            "bundle OK: signature valid, chain bound, {} violation(s), status={:?}",
                            b.verdict.body.violations_count, b.verdict.body.status
                        );
                        0
                    }
                    Err(e) => {
                        eprintln!("bundle INVALID: {e}");
                        2
                    }
                },
                Err(e) => {
                    eprintln!("bundle INVALID: {e}");
                    2
                }
            }
        }
        Cmd::Keygen => {
            let s = proctor_verdict::sign::Signer::generate();
            println!("seed={}", s.to_seed_hex());
            println!("pubkey={}", s.public_key_hex());
            0
        }
        Cmd::Probe => {
            let c = proctor_sandbox::caps::probe();
            println!("{c:?}");
            if c.all() {
                0
            } else {
                1
            }
        }
    };
    std::process::exit(code);
}
