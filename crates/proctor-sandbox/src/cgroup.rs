//! Best-effort cgroup v2 limits. Resource limits may degrade (recorded);
//! isolation may not — that's why this returns Ok(false) instead of erroring.

use std::path::PathBuf;

/// Try to put `pid` in a fresh sub-cgroup with pids/memory limits.
/// Returns Ok(true) if applied, Ok(false) if the host doesn't allow it.
pub fn try_apply(pid: i32, pids_max: u64, memory_max: u64) -> std::io::Result<bool> {
    let own = std::fs::read_to_string("/proc/self/cgroup")?;
    // format: "0::/user.slice/...": take the path after "0::"
    let Some(rel) = own.lines().find_map(|l| l.strip_prefix("0::")) else {
        return Ok(false); // not pure cgroup v2
    };
    let base = PathBuf::from("/sys/fs/cgroup").join(rel.trim().trim_start_matches('/'));
    let dir = base.join(format!("proctor-{pid}"));
    let apply = || -> std::io::Result<()> {
        std::fs::create_dir(&dir)?;
        std::fs::write(dir.join("pids.max"), pids_max.to_string())?;
        std::fs::write(dir.join("memory.max"), memory_max.to_string())?;
        std::fs::write(dir.join("cgroup.procs"), pid.to_string())?;
        Ok(())
    };
    match apply() {
        Ok(()) => Ok(true),
        Err(_) => {
            let _ = std::fs::remove_dir(&dir);
            Ok(false) // degraded: caller records it in the verdict
        }
    }
}
