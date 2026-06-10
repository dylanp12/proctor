//! Builds the agent-visible workspace lower dir: a copy of the task workspace
//! with every forbidden path excluded. The agent's world never contains the
//! oracle; the tmpfs masks (mounts.rs) are defense in depth on top.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum MaterializeError {
    #[error("io error at {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("a forbidden path masks the entire workspace mount ({0}); nothing to run")]
    MaskSwallowsWorkspace(PathBuf),
}

#[derive(Debug, Default)]
pub struct MaterializeReport {
    pub files_copied: u64,
    /// workspace-relative paths excluded because they fall under a mask
    pub excluded: Vec<PathBuf>,
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> MaterializeError + '_ {
    move |source| MaterializeError::Io { path: path.to_path_buf(), source }
}

/// Copy `src` -> `dest`, excluding any entry whose in-sandbox path
/// (mount_at / relpath) equals or falls under a mask entry.
pub fn materialize_workspace(
    src: &Path,
    mount_at: &Path,
    mask_set: &BTreeSet<PathBuf>,
    dest: &Path,
) -> Result<MaterializeReport, MaterializeError> {
    for m in mask_set {
        if mount_at.starts_with(m) {
            return Err(MaterializeError::MaskSwallowsWorkspace(m.clone()));
        }
    }
    let mut report = MaterializeReport::default();
    let mut walker = walkdir::WalkDir::new(src).follow_links(false).into_iter();
    while let Some(entry) = walker.next() {
        let entry = entry.map_err(|e| MaterializeError::Io {
            path: src.to_path_buf(),
            source: e.into_io_error().unwrap_or_else(|| std::io::Error::other("walk error")),
        })?;
        let rel = entry.path().strip_prefix(src).expect("walkdir yields children of src");
        if rel.as_os_str().is_empty() {
            continue; // the root itself
        }
        let sandbox_path = mount_at.join(rel);
        if mask_set.iter().any(|m| sandbox_path.starts_with(m)) {
            report.excluded.push(rel.to_path_buf());
            if entry.file_type().is_dir() {
                walker.skip_current_dir();
            }
            continue;
        }
        let target = dest.join(rel);
        let ft = entry.file_type();
        if ft.is_dir() {
            std::fs::create_dir_all(&target).map_err(io_err(&target))?;
            let perms = entry
                .metadata()
                .map_err(|e| MaterializeError::Io {
                    path: entry.path().to_path_buf(),
                    source: e.into(),
                })?
                .permissions();
            std::fs::set_permissions(&target, perms).map_err(io_err(&target))?;
        } else if ft.is_symlink() {
            let link = std::fs::read_link(entry.path()).map_err(io_err(entry.path()))?;
            std::os::unix::fs::symlink(&link, &target).map_err(io_err(&target))?;
        } else {
            std::fs::copy(entry.path(), &target).map_err(io_err(&target))?; // copies perms
            report.files_copied += 1;
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    fn setup_src() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("src")).unwrap();
        std::fs::write(d.path().join("src/app.sh"), "echo wrong\n").unwrap();
        let mut perms = std::fs::metadata(d.path().join("src/app.sh")).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(d.path().join("src/app.sh"), perms).unwrap();
        std::fs::create_dir_all(d.path().join("tests")).unwrap();
        std::fs::write(d.path().join("tests/expected.txt"), "ORACLE\n").unwrap();
        std::os::unix::fs::symlink("src/app.sh", d.path().join("run")).unwrap();
        d
    }

    fn masks(paths: &[&str]) -> BTreeSet<PathBuf> {
        paths.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn forbidden_paths_under_mount_are_excluded_rest_copied() {
        let src = setup_src();
        let dst = tempfile::tempdir().unwrap();
        let report = materialize_workspace(
            src.path(),
            Path::new("/workspace"),
            &masks(&["/workspace/tests", "/oracle"]),
            dst.path(),
        )
        .unwrap();
        assert!(dst.path().join("src/app.sh").exists());
        assert!(!dst.path().join("tests").exists(), "oracle dir must not be materialized");
        assert_eq!(report.excluded, vec![PathBuf::from("tests")]);
        let mode = std::fs::metadata(dst.path().join("src/app.sh")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
        let md = std::fs::symlink_metadata(dst.path().join("run")).unwrap();
        assert!(md.file_type().is_symlink());
        assert_eq!(
            std::fs::read_link(dst.path().join("run")).unwrap(),
            PathBuf::from("src/app.sh")
        );
    }

    #[test]
    fn mask_outside_mount_at_does_not_affect_copy() {
        let src = setup_src();
        let dst = tempfile::tempdir().unwrap();
        materialize_workspace(src.path(), Path::new("/workspace"), &masks(&["/oracle"]), dst.path())
            .unwrap();
        assert!(dst.path().join("tests/expected.txt").exists());
    }

    #[test]
    fn exact_file_mask_excludes_just_that_file() {
        let src = setup_src();
        let dst = tempfile::tempdir().unwrap();
        materialize_workspace(
            src.path(),
            Path::new("/workspace"),
            &masks(&["/workspace/tests/expected.txt"]),
            dst.path(),
        )
        .unwrap();
        assert!(dst.path().join("tests").exists());
        assert!(!dst.path().join("tests/expected.txt").exists());
    }

    #[test]
    fn mask_covering_whole_workspace_is_an_error() {
        let src = setup_src();
        let dst = tempfile::tempdir().unwrap();
        let e = materialize_workspace(
            src.path(),
            Path::new("/workspace"),
            &masks(&["/workspace"]),
            dst.path(),
        );
        assert!(matches!(e, Err(MaterializeError::MaskSwallowsWorkspace(_))));
    }
}
