//! Test-only init binary: the same entrypoint proctor-cli wires up as the
//! hidden `__sandbox-init` subcommand.
use std::path::PathBuf;

fn main() -> ! {
    let mut args = std::env::args().skip(1);
    let spec = match (args.next().as_deref(), args.next()) {
        (Some("--spec"), Some(p)) => PathBuf::from(p),
        _ => {
            eprintln!("usage: sandbox-helper --spec <spec.json>");
            std::process::exit(2);
        }
    };
    proctor_sandbox::init::init_main(&spec)
}
