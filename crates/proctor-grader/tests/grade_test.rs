use proctor_grader::{grade, GradeProtocol, GradeRequest, GradeResult};
use proctor_sandbox::require_sandbox;
use proctor_sandbox::spawn::InitInvoker;
use std::path::PathBuf;

fn invoker() -> InitInvoker {
    // the grader uses the same init entrypoint; the sandbox helper bin provides it
    InitInvoker {
        program: PathBuf::from(env!("CARGO_BIN_EXE_grade-helper")),
        prefix_args: vec![],
    }
}

fn staged() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("ws")).unwrap();
    std::fs::create_dir_all(d.path().join("oracle")).unwrap();
    d
}

#[test]
fn exit_code_protocol_pass_and_fail() {
    require_sandbox!();
    let d = staged();
    std::fs::write(d.path().join("ws/out.txt"), "42\n").unwrap();
    std::fs::write(d.path().join("oracle/expected.txt"), "42\n").unwrap();
    let req = GradeRequest {
        workspace: d.path().join("ws"),
        oracle: d.path().join("oracle"),
        oracle_mount: PathBuf::from("/oracle"),
        grade_cmd: "diff -q /workspace/out.txt /oracle/expected.txt".into(),
        protocol: GradeProtocol::ExitCode,
        session: d.path().join("grade-session-pass"),
        wall_time_secs: 30,
    };
    assert!(matches!(
        grade(&req, &invoker()).unwrap(),
        GradeResult { pass: true, .. }
    ));

    std::fs::write(d.path().join("oracle/expected.txt"), "99\n").unwrap();
    let req2 = GradeRequest {
        session: d.path().join("grade-session-fail"),
        ..req
    };
    assert!(matches!(
        grade(&req2, &invoker()).unwrap(),
        GradeResult { pass: false, .. }
    ));
}

#[test]
fn reward_file_protocol_reads_json_reward() {
    require_sandbox!();
    let d = staged();
    let req = GradeRequest {
        workspace: d.path().join("ws"),
        oracle: d.path().join("oracle"),
        oracle_mount: PathBuf::from("/oracle"),
        grade_cmd:
            "mkdir -p /logs/verifier && echo '{\"reward\": 1.0}' > /logs/verifier/reward.json"
                .into(),
        protocol: GradeProtocol::RewardFile {
            path: PathBuf::from("/logs/verifier/reward.json"),
        },
        session: d.path().join("grade-session-reward"),
        wall_time_secs: 30,
    };
    let r = grade(&req, &invoker()).unwrap();
    assert!(r.pass);
    assert_eq!(r.reward, Some(1.0));
}
