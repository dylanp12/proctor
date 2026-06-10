//! The violation record: one attempted cheat, captured by the monitor.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationKind {
    /// open()/openat() for read on a masked path
    MaskedRead,
    /// open()/openat() with write intent on a masked path
    MaskedWrite,
    /// connect() to a host not on the allowlist (or any host in deny mode)
    BlockedConnect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violation {
    /// monotonically increasing index of the intercepted syscall in this run
    pub step: u64,
    pub kind: ViolationKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub pid: i32,
    pub syscall: String,
}
