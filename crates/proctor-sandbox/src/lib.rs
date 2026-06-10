//! Sandbox assembly: namespaces, mounts, masks, network, seccomp wiring.
//!
//! The agent runs in a re-exec'd sandbox-init process inside fresh user/mount/
//! pid/net/ipc/uts namespaces. Enforcement is *by construction*: forbidden
//! paths are absent from the mount namespace, the netns has no route. The
//! seccomp monitor is audit-only — it records attempts and always continues.

pub mod caps;
pub mod cgroup;
pub mod gitsan;
pub mod init;
pub mod ipc;
pub mod materialize;
pub mod mounts;
pub mod net;
pub mod pid1;
pub mod proxy;
pub mod seccomp;
pub mod spawn;
pub mod spec;
