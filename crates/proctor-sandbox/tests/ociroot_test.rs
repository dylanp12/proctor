//! Exercises the real fetch+unpack on a tiny image. Gated: only runs with
//! PROCTOR_OCI_SMOKE=1 (needs a container tool + network), so the default
//! `cargo test` / CI stays hermetic.
use std::path::Path;

#[test]
fn export_alpine_rootfs_has_sh() {
    if std::env::var("PROCTOR_OCI_SMOKE").is_err() {
        eprintln!("SKIP: set PROCTOR_OCI_SMOKE=1 to run the image smoke test");
        return;
    }
    let Some(tool) = proctor_sandbox::ociroot::container_tool() else {
        eprintln!("SKIP: no container tool");
        return;
    };
    eprintln!("using container tool: {tool}");
    let d = tempfile::tempdir().unwrap();
    proctor_sandbox::ociroot::export_image_rootfs("docker.io/library/alpine:3.19", d.path())
        .expect("export alpine rootfs");
    // check a real file (bin/busybox), not bin/sh — the latter is a symlink to the
    // absolute /bin/busybox, which Path::exists() would resolve against the host.
    assert!(
        Path::new(&d.path().join("bin/busybox")).exists(),
        "rootfs should contain bin/busybox"
    );
    assert!(
        std::fs::symlink_metadata(d.path().join("bin/sh")).is_ok(),
        "rootfs should contain a bin/sh entry"
    );
}
