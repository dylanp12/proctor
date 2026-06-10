//! End-to-end allowlist egress audit (claims 2 + 3 from the external review):
//! with the seccomp monitor ON, the agent's sanctioned hop to the in-ns proxy
//! (127.0.0.1:3128, loopback) is NOT logged as a violation, while the proxy's
//! DENIED egress decisions ARE folded into the signed violation timeline.

use proctor_sandbox::require_sandbox;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;

fn proctor() -> Command {
    Command::new(env!("CARGO_BIN_EXE_proctor"))
}
fn write(p: &Path, s: &str) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, s).unwrap();
}

/// A one-shot host origin server; returns its 127.0.0.1:port address.
fn origin() -> (String, std::thread::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let h = std::thread::spawn(move || {
        if let Ok((mut c, _)) = l.accept() {
            let mut b = [0u8; 256];
            let _ = c.read(&mut b);
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nORIGIN-OK");
        }
    });
    (addr, h)
}

fn run(root: &Path, policy: &str, agent: &str) -> (serde_json::Value, String) {
    write(&root.join("task/workspace/.keep"), "");
    write(&root.join("task/oracle/.keep"), "");
    write(&root.join("task/grade.sh"), "true");
    write(&root.join("policy.yaml"), policy);
    let out = root.join("out");
    let st = proctor()
        .args(["run", "--task"])
        .arg(root.join("task"))
        .args(["--agent", agent])
        .args(["--policy"])
        .arg(root.join("policy.yaml"))
        .args(["--out"])
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "proctor failed: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    let verdict =
        serde_json::from_slice(&std::fs::read(out.join("verdict.json")).unwrap()).unwrap();
    let violations = std::fs::read_to_string(out.join("violations.jsonl")).unwrap_or_default();
    (verdict, violations)
}

#[test]
fn allowlisted_egress_is_clean_proxy_hop_not_logged() {
    require_sandbox!();
    if !Path::new("/usr/bin/curl").exists() {
        eprintln!("SKIP: curl absent");
        return;
    }
    let (origin_addr, oh) = origin();
    let d = tempfile::tempdir().unwrap();
    let policy = format!("version: 1\nnetwork: {{mode: allowlist, allow: [\"{origin_addr}\"]}}\n");
    let (verdict, violations) = run(
        d.path(),
        &policy,
        &format!("curl -s -m 5 http://{origin_addr}/"),
    ); // only the allowed host
    oh.join().ok();
    // the sanctioned loopback hop to 127.0.0.1:3128 must not appear as a violation
    assert!(
        !violations.contains("127.0.0.1:3128"),
        "the proxy hop must NOT be logged as a violation: {violations}"
    );
    assert_eq!(
        verdict["status"], "clean",
        "allowlisted-only egress should be clean: {verdict}"
    );
    assert_eq!(verdict["violations_count"], 0);
}

#[test]
fn denied_egress_is_folded_into_the_timeline_and_compromises() {
    require_sandbox!();
    if !Path::new("/usr/bin/curl").exists() {
        eprintln!("SKIP: curl absent");
        return;
    }
    let (origin_addr, oh) = origin();
    let d = tempfile::tempdir().unwrap();
    // allow only the origin; the agent also tries a non-allowlisted host
    let policy = format!("version: 1\nnetwork: {{mode: allowlist, allow: [\"{origin_addr}\"]}}\n");
    let agent = format!(
        "curl -s -m 5 http://{origin_addr}/ >/dev/null 2>&1; \
         curl -s -m 5 http://10.255.255.1:9/ >/dev/null 2>&1; true"
    );
    let (verdict, violations) = run(d.path(), &policy, &agent);
    oh.join().ok();
    // the proxy's denial of the non-allowlisted host is in the signed timeline
    assert!(
        violations.contains("blocked_connect") && violations.contains("10.255.255.1:9"),
        "denied egress must be folded into the timeline: {violations}"
    );
    assert!(
        !violations.contains("127.0.0.1:3128"),
        "the proxy hop must NOT be logged: {violations}"
    );
    assert_eq!(
        verdict["status"], "compromised",
        "a denied egress attempt compromises: {verdict}"
    );
    assert!(verdict["violations_count"].as_u64().unwrap() >= 1);
    // chain still verifies through the appended proxy-denial record
    let pk = verdict["public_key"].as_str().unwrap();
    let vr = proctor()
        .args(["verify", "--verdict"])
        .arg(d.path().join("out/verdict.json"))
        .args(["--pubkey", pk])
        .output()
        .unwrap();
    assert!(
        vr.status.success(),
        "verdict must verify: {}",
        String::from_utf8_lossy(&vr.stderr)
    );
}
