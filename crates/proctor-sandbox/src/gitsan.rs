//! Git sanitization: materialize a repo at exactly one commit (the base),
//! with no way to reach later (fix) history. Fetching a single commit by sha
//! brings its ancestors but never its descendants.

use std::path::Path;
use std::process::Command;

#[derive(Debug, thiserror::Error)]
pub enum GitSanError {
    #[error("git {args:?} failed: {stderr}")]
    Git { args: Vec<String>, stderr: String },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

fn run(dir: &Path, args: &[&str]) -> Result<String, GitSanError> {
    let out = Command::new("git").current_dir(dir).args(args).output()?;
    if !out.status.success() {
        return Err(GitSanError::Git {
            args: args.iter().map(|s| s.to_string()).collect(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Build, at `dest`, a git repo whose only commit is `base_commit`, with the
/// working tree checked out to it. `source` is the original (full-history) repo.
pub fn sanitize_repo_at(source: &Path, base_commit: &str, dest: &Path) -> Result<(), GitSanError> {
    std::fs::create_dir_all(dest)?;
    run(dest, &["init", "-q"])?;
    let src_url = format!("file://{}", source.canonicalize()?.display());
    // fetch exactly one commit by sha (allow single-sha file:// fetch explicitly)
    run(
        dest,
        &[
            "-c",
            "protocol.file.allow=always",
            "-c",
            "uploadpack.allowAnySHA1InWant=true",
            "fetch",
            "-q",
            "--depth",
            "1",
            &src_url,
            base_commit,
        ],
    )?;
    run(dest, &["checkout", "-q", "--detach", base_commit])?;
    // remove remote-tracking plumbing so no later sha is even namable
    let _ = run(dest, &["remote", "remove", "origin"]);
    let _ = std::fs::remove_file(dest.join(".git/FETCH_HEAD"));
    Ok(())
}
