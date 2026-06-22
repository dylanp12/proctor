use std::process::Command;

/// Capture the git short commit at build time into PROCTOR_GIT_COMMIT, so a run's
/// recorded environment can bind which Proctor build produced it. Falls back to
/// "unknown" outside a git checkout (e.g. a packaged crate build).
fn main() {
    let commit = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=PROCTOR_GIT_COMMIT={commit}");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
}
