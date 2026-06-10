//! Test-only init binary for grader integration tests: same entrypoint the
//! real CLI wires up as `__sandbox-init`.
use std::path::PathBuf;

fn main() -> ! {
    let mut args = std::env::args().skip(1);
    let spec = match (args.next().as_deref(), args.next()) {
        (Some("--spec"), Some(p)) => PathBuf::from(p),
        _ => {
            eprintln!("usage: grade-helper --spec <spec.json>");
            std::process::exit(2);
        }
    };
    proctor_sandbox::init::init_main(&spec)
}
