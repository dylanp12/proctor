use proctor_sandbox::require_sandbox;
use std::path::Path;
use std::process::Command;

fn proctor() -> Command {
    Command::new(env!("CARGO_BIN_EXE_proctor"))
}
fn write(p: &Path, s: &str) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, s).unwrap();
}

fn make_task(root: &Path) {
    write(
        &root.join("task/workspace/solve.sh"),
        "#!/bin/sh\ncat /oracle/x 2>/dev/null; echo 42 > /workspace/a\n",
    );
    write(&root.join("task/oracle/x"), "SECRET\n");
    write(&root.join("task/oracle/expected.txt"), "42\n");
    write(
        &root.join("task/grade.sh"),
        "diff -q /workspace/a /oracle/expected.txt",
    );
    write(
        &root.join("policy.yaml"),
        "version: 1\nforbidden:\n  reads: [/oracle]\nnetwork: {mode: deny}\n",
    );
}

fn run(root: &Path, out: &str, seed_env: Option<&str>) {
    let mut c = proctor();
    c.args(["run", "--task"])
        .arg(root.join("task"))
        .args(["--agent", "sh /workspace/solve.sh"])
        .args(["--policy"])
        .arg(root.join("policy.yaml"))
        .args(["--out"])
        .arg(root.join(out));
    if let Some(s) = seed_env {
        c.env("PROCTOR_SIGNING_SEED", s);
    }
    let st = c.output().unwrap();
    assert!(
        st.status.success(),
        "run failed: {}",
        String::from_utf8_lossy(&st.stderr)
    );
}

#[test]
fn bundle_emitted_and_verifies_then_tamper_fails() {
    require_sandbox!();
    let d = tempfile::tempdir().unwrap();
    make_task(d.path());
    run(d.path(), "out", None);
    let bundle = d.path().join("out/bundle.json");
    assert!(bundle.exists(), "run must emit bundle.json");

    let v = proctor()
        .args(["verify-bundle", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(
        v.status.success(),
        "verify-bundle should pass: {}",
        String::from_utf8_lossy(&v.stderr)
    );

    // tamper a violation record in the bundle -> verify fails
    let txt = std::fs::read_to_string(&bundle)
        .unwrap()
        .replace("/oracle/x", "/oracle/Y");
    std::fs::write(&bundle, txt).unwrap();
    let v2 = proctor()
        .args(["verify-bundle", "--bundle"])
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(
        !v2.status.success(),
        "tampered bundle must fail verification"
    );
}

#[test]
fn stable_seed_gives_shared_pubkey() {
    require_sandbox!();
    let d = tempfile::tempdir().unwrap();
    make_task(d.path());
    let kg = proctor().arg("keygen").output().unwrap();
    let kg_out = String::from_utf8_lossy(&kg.stdout);
    let seed = kg_out
        .lines()
        .find_map(|l| l.strip_prefix("seed="))
        .unwrap()
        .trim()
        .to_string();
    let pubkey = kg_out
        .lines()
        .find_map(|l| l.strip_prefix("pubkey="))
        .unwrap()
        .trim()
        .to_string();

    run(d.path(), "out1", Some(&seed));
    run(d.path(), "out2", Some(&seed));
    for out in ["out1", "out2"] {
        let b = d.path().join(out).join("bundle.json");
        let v = proctor()
            .args(["verify-bundle", "--bundle"])
            .arg(&b)
            .args(["--pubkey", &pubkey])
            .output()
            .unwrap();
        assert!(
            v.status.success(),
            "{out}: should verify against the operator pubkey: {}",
            String::from_utf8_lossy(&v.stderr)
        );
    }
}
