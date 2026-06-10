use proctor_sandbox::gitsan::sanitize_repo_at;
use std::process::Command;

fn git(dir: &std::path::Path, args: &[&str]) -> String {
    let o = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

fn build_source_repo() -> (tempfile::TempDir, String) {
    let d = tempfile::tempdir().unwrap();
    let p = d.path();
    git(p, &["init", "-q", "-b", "main"]);
    git(p, &["config", "user.email", "t@t"]);
    git(p, &["config", "user.name", "t"]);
    std::fs::write(p.join("bug.txt"), "buggy\n").unwrap();
    git(p, &["add", "."]);
    git(p, &["commit", "-q", "-m", "base: the buggy state"]);
    let base = git(p, &["rev-parse", "HEAD"]);
    std::fs::write(p.join("bug.txt"), "fixed\n").unwrap();
    std::fs::write(p.join("FIX_SECRET.txt"), "THE-FIX-PATCH\n").unwrap();
    git(p, &["add", "."]);
    git(p, &["commit", "-q", "-m", "fix: the answer commit"]);
    (d, base)
}

#[test]
fn sanitized_repo_is_at_base_and_cannot_reach_the_fix() {
    let (src, base) = build_source_repo();
    let dst = tempfile::tempdir().unwrap();
    sanitize_repo_at(src.path(), &base, dst.path()).unwrap();

    assert_eq!(git(dst.path(), &["rev-parse", "HEAD"]), base);
    // working tree is the buggy state, not the fix
    assert_eq!(
        std::fs::read_to_string(dst.path().join("bug.txt")).unwrap(),
        "buggy\n"
    );
    assert!(!dst.path().join("FIX_SECRET.txt").exists());
    // the entire history is one commit; the fix sha is unknown to this repo
    let log = git(dst.path(), &["log", "--all", "--oneline"]);
    assert_eq!(
        log.lines().count(),
        1,
        "only the base commit may exist: {log}"
    );
    assert!(
        !log.contains("fix"),
        "fix commit must be unreachable: {log}"
    );
}

#[test]
fn rejects_sha_not_in_source() {
    let (src, _base) = build_source_repo();
    let dst = tempfile::tempdir().unwrap();
    let bogus = "0".repeat(40);
    assert!(sanitize_repo_at(src.path(), &bogus, dst.path()).is_err());
}
