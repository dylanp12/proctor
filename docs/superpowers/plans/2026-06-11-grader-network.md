# Grader Network Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the grader phase run with a configurable network mode (deny | host | allowlist), default deny, so a real test harness can fetch dependencies during grading.

**Architecture:** Add a third sandbox network mode `NetSpec::Host` (skip the network namespace — share the host's) by making `CLONE_NEWNET` conditional in `spawn.rs`. Add a grader-facing `GraderNet` enum on `GradeRequest`; `grade()` translates it into the grade sandbox's `NetSpec` (+ a `HostProxy` for allowlist, reusing the hardened proxy). All existing call sites default to `Deny` — no behavior change.

**Tech Stack:** Rust 2021 workspace. `proctor-sandbox` (namespaces/proxy), `proctor-grader`. Spec: [`docs/superpowers/specs/2026-06-11-grader-network-design.md`](../specs/2026-06-11-grader-network-design.md).

---

## Context primer (read before Task 1)

- This is **sub-project #2**. It ships the *mechanism*; call sites stay on `Deny`, so TB/SWE-bench grading is unchanged (the offline-substitution reports stay valid). Sub-project #6 wires real networked grading on top.
- `Host` = the sandbox is NOT placed in a network namespace; it shares the host's. All other isolation (user/mount/pid/ipc/uts ns, mount masking, seccomp) is unchanged. `Host` is **grader-only** — the agent is never given it.
- Why `Host` works: not unsharing `CLONE_NEWNET` leaves the process in the host netns; `connect()` needs no capability, so the userns-root grader reaches the network via the host's routes. `net::setup` must NOT touch host interfaces in this mode.
- The current `unshare` set is a fixed literal in `spawn.rs` `pre_exec` (`CLONE_NEWUSER|NEWNS|NEWPID|NEWNET|NEWIPC|NEWUTS`). `CloneFlags` is `Copy` (bitflags), so compute the flag set before `pre_exec` and capture it.
- Tests use a **host-local origin server** (127.0.0.1) so `Host` vs `Deny` is provable offline: in `Host` mode the sandbox shares the host netns and can reach `127.0.0.1:<origin>`; in `Deny` mode the empty netns has only its own dead `lo`, so the connect fails.
- TCP-connect probe in the agent/grade command: use `python3` (the sandbox `/bin/sh` is dash, which lacks bash's `/dev/tcp`). Gate `python3`-dependent asserts on `/usr/bin/python3` existing.

### File structure

```
crates/proctor-sandbox/src/spec.rs    # add NetSpec::Host
crates/proctor-sandbox/src/spawn.rs   # conditional CLONE_NEWNET
crates/proctor-sandbox/src/net.rs     # setup() no-op for Host
crates/proctor-sandbox/tests/net_host_test.rs   # Host reaches host-local origin; Deny doesn't
crates/proctor-grader/src/lib.rs      # GraderNet enum + GradeRequest.network + grade() translation
crates/proctor-grader/tests/grade_test.rs       # +network field on existing reqs
crates/proctor-grader/tests/grade_net_test.rs   # Host passes / Deny fails / Allowlist passes
crates/proctor-cli/src/run.rs         # 2 GradeRequest sites: network: GraderNet::Deny
```

---

## Task 1: `NetSpec::Host` in the sandbox

**Files:**
- Modify: `crates/proctor-sandbox/src/spec.rs`, `crates/proctor-sandbox/src/spawn.rs`, `crates/proctor-sandbox/src/net.rs`
- Test: `crates/proctor-sandbox/tests/net_host_test.rs`

**Prove:** a `Host` sandbox reaches a host-local origin; a `Deny` sandbox cannot.

- [ ] **Step 1: Write the failing test** (`crates/proctor-sandbox/tests/net_host_test.rs`)

```rust
use proctor_sandbox::require_sandbox;
use proctor_sandbox::spawn::{run_sandboxed, InitInvoker};
use proctor_sandbox::spec::{NetSpec, RootfsSpec, SandboxSpec};
use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};

fn invoker() -> InitInvoker {
    InitInvoker { program: PathBuf::from(env!("CARGO_BIN_EXE_sandbox-helper")), prefix_args: vec![] }
}

/// A host origin that accepts one connection (proves reachability).
fn origin() -> (u16, std::thread::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let h = std::thread::spawn(move || {
        if let Ok((mut c, _)) = l.accept() {
            let mut b = [0u8; 16];
            let _ = c.read(&mut b);
        }
    });
    (port, h)
}

fn spec(session: &Path, net: NetSpec, cmd: &str) -> SandboxSpec {
    SandboxSpec {
        rootfs: RootfsSpec::HostSystem,
        workspace_lower: None,
        mount_at: PathBuf::from("/workspace"),
        masks: vec![],
        network: net,
        env: vec![("PATH".into(), "/usr/bin:/bin".into())],
        agent_cmd: cmd.into(),
        agent_cwd: PathBuf::from("/"),
        session: session.to_path_buf(),
        wall_time_secs: 30,
        pids_limit: 64,
        memory_bytes: 256 * 1024 * 1024,
        pivot: true,
        seccomp: false,
        host_proxy_sock: None,
        extra_binds: vec![],
    }
}

fn out(s: &Path) -> String {
    std::fs::read_to_string(s.join("agent-stdout.log")).unwrap_or_default()
}

#[test]
fn host_network_reaches_host_local_origin() {
    require_sandbox!();
    if !Path::new("/usr/bin/python3").exists() {
        eprintln!("SKIP: python3 absent");
        return;
    }
    let (port, oh) = origin();
    let s = tempfile::tempdir().unwrap();
    let cmd = format!(
        "python3 -c \"import socket; socket.create_connection(('127.0.0.1',{port}),3); print('CONNECTED')\" 2>&1"
    );
    let r = run_sandboxed(&spec(s.path(), NetSpec::Host, &cmd), &invoker()).unwrap();
    oh.join().ok();
    assert_eq!(r.agent_exit, Some(0), "host-net agent should exit 0: {}", out(s.path()));
    assert!(out(s.path()).contains("CONNECTED"), "host net should reach origin: {}", out(s.path()));
}

#[test]
fn deny_network_cannot_reach_host_local_origin() {
    require_sandbox!();
    if !Path::new("/usr/bin/python3").exists() {
        eprintln!("SKIP: python3 absent");
        return;
    }
    let (port, oh) = origin();
    let s = tempfile::tempdir().unwrap();
    let cmd = format!(
        "python3 -c \"import socket; socket.create_connection(('127.0.0.1',{port}),3); print('CONNECTED')\" 2>&1; echo EXIT=$?"
    );
    let r = run_sandboxed(&spec(s.path(), NetSpec::Deny, &cmd), &invoker()).unwrap();
    // origin never receives a connection; don't join (it would block) — detach
    drop(oh);
    assert_eq!(r.agent_exit, Some(0)); // the shell runs; the python connect fails inside
    assert!(!out(s.path()).contains("CONNECTED"), "deny net must NOT reach origin: {}", out(s.path()));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p proctor-sandbox --test net_host_test`
Expected: COMPILE ERROR (`NetSpec::Host` undefined).

- [ ] **Step 3: Add `NetSpec::Host`** in `crates/proctor-sandbox/src/spec.rs`

Change the `NetSpec` enum to:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetSpec {
    /// empty netns, lo up: egress impossible by construction
    Deny,
    /// empty netns + unix-socket CONNECT proxy bridged at proxy_sock
    Allowlist { proxy_sock: PathBuf },
    /// no network namespace — share the host's network (trusted grader only)
    Host,
}
```

- [ ] **Step 4: Make `CLONE_NEWNET` conditional** in `crates/proctor-sandbox/src/spawn.rs`

Just before the `unsafe { cmd.pre_exec(move || { ... }) }` block, compute the
clone flags (network namespace omitted for `Host`):

```rust
    // network namespace is created for Deny/Allowlist; Host shares the host's net
    let mut clone_flags = nix::sched::CloneFlags::CLONE_NEWUSER
        | nix::sched::CloneFlags::CLONE_NEWNS
        | nix::sched::CloneFlags::CLONE_NEWPID
        | nix::sched::CloneFlags::CLONE_NEWIPC
        | nix::sched::CloneFlags::CLONE_NEWUTS;
    if !matches!(spec.network, crate::spec::NetSpec::Host) {
        clone_flags |= nix::sched::CloneFlags::CLONE_NEWNET;
    }
```

Then replace the inline `nix::sched::unshare( CLONE_NEWUSER | ... | CLONE_NEWUTS )`
call inside `pre_exec` with:

```rust
            nix::sched::unshare(clone_flags).map_err(std::io::Error::from)?;
```

(`clone_flags` is captured by the `move` closure; `CloneFlags` is `Copy`.) The
existing `Allowlist`-only `HTTP_PROXY` env injection above is unchanged — `Host`
gets no proxy env (direct egress).

- [ ] **Step 5: Skip interface setup for `Host`** in `crates/proctor-sandbox/src/net.rs`

```rust
pub fn setup(net: &NetSpec) -> Result<(), String> {
    // Host shares the host's network namespace; do not touch host interfaces.
    if matches!(net, NetSpec::Host) {
        return Ok(());
    }
    bring_loopback_up().map_err(|e| format!("lo up: {e}"))
}
```

(The parameter was `_net`; rename to `net` and match. `bring_loopback_up` and the
rest are unchanged. The allowlist forwarder is started in `pid1.rs` only for
`Allowlist`, so no change there.)

- [ ] **Step 6: Run to verify it passes**

Run: `cargo test -p proctor-sandbox --test net_host_test`
Expected: both PASS (host reaches origin, deny does not). Then regression:
`cargo test -p proctor-sandbox --test net_deny_test --test net_allow_test --test spawn_test`
Expected: all green. Then `cargo clippy -p proctor-sandbox --all-targets -- -D warnings`.

- [ ] **Step 7: Commit**

```bash
cargo fmt --all
git add -A && git commit -m "feat(sandbox): NetSpec::Host (share host network) for the trusted grader"
```

---

## Task 2: `GraderNet` on `GradeRequest`

**Files:**
- Modify: `crates/proctor-grader/src/lib.rs`, `crates/proctor-grader/tests/grade_test.rs`, `crates/proctor-cli/src/run.rs`
- Test: `crates/proctor-grader/tests/grade_net_test.rs`

**Prove:** a grade with `GraderNet::Host` reaches a host-local origin (passes); `GraderNet::Deny` does not (fails); `GraderNet::Allowlist` reaches an allowed origin through the grader's proxy.

- [ ] **Step 1: Write the failing test** (`crates/proctor-grader/tests/grade_net_test.rs`)

```rust
use proctor_grader::{grade, GradeProtocol, GradeRequest, GraderNet};
use proctor_sandbox::require_sandbox;
use proctor_sandbox::spawn::InitInvoker;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};

fn invoker() -> InitInvoker {
    InitInvoker { program: PathBuf::from(env!("CARGO_BIN_EXE_grade-helper")), prefix_args: vec![] }
}

fn staged() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("ws")).unwrap();
    std::fs::create_dir_all(d.path().join("oracle")).unwrap();
    d
}

/// host origin: accepts one connection, replies a minimal HTTP 200 (so curl is happy too)
fn origin() -> (String, std::thread::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let h = std::thread::spawn(move || {
        if let Ok((mut c, _)) = l.accept() {
            let mut b = [0u8; 256];
            let _ = c.read(&mut b);
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        }
    });
    (addr, h)
}

fn req(d: &Path, net: GraderNet, cmd: &str, tag: &str) -> GradeRequest {
    GradeRequest {
        workspace: d.join("ws"),
        workspace_mount: PathBuf::from("/workspace"),
        oracle: d.join("oracle"),
        oracle_mount: PathBuf::from("/oracle"),
        grade_cmd: cmd.into(),
        protocol: GradeProtocol::ExitCode,
        session: d.join(tag),
        wall_time_secs: 30,
        network: net,
    }
}

#[test]
fn host_grader_reaches_origin_deny_does_not() {
    require_sandbox!();
    if !Path::new("/usr/bin/python3").exists() {
        eprintln!("SKIP: python3 absent");
        return;
    }
    let (addr, oh) = origin();
    let port = addr.rsplit(':').next().unwrap().to_string();
    let d = staged();
    let probe =
        format!("python3 -c \"import socket; socket.create_connection(('127.0.0.1',{port}),3)\"");

    // host: connect succeeds -> exit 0 -> pass
    let r = grade(&req(d.path(), GraderNet::Host, &probe, "g-host"), &invoker()).unwrap();
    oh.join().ok();
    assert!(r.pass, "host grader should reach the origin (pass)");

    // deny: empty netns -> connect fails -> nonzero -> fail
    let (_addr2, oh2) = origin();
    let r2 = grade(&req(d.path(), GraderNet::Deny, &probe, "g-deny"), &invoker()).unwrap();
    drop(oh2);
    assert!(!r2.pass, "deny grader must not reach the origin (fail)");
}

#[test]
fn allowlist_grader_reaches_allowed_origin() {
    require_sandbox!();
    if !Path::new("/usr/bin/curl").exists() {
        eprintln!("SKIP: curl absent");
        return;
    }
    let (addr, oh) = origin();
    let d = staged();
    // curl uses HTTP_PROXY (injected for allowlist) to reach the allowed origin
    let cmd = format!("curl -s -m 5 -o /dev/null http://{addr}/");
    let r = grade(
        &req(d.path(), GraderNet::Allowlist(vec![addr.clone()]), &cmd, "g-allow"),
        &invoker(),
    )
    .unwrap();
    oh.join().ok();
    assert!(r.pass, "allowlisted origin should be reachable through the grader proxy");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p proctor-grader --test grade_net_test`
Expected: COMPILE ERROR (`GraderNet` undefined, `GradeRequest.network` missing).

- [ ] **Step 3: Add `GraderNet` + the field + translation** in `crates/proctor-grader/src/lib.rs`

Change the imports at the top from:

```rust
use proctor_sandbox::spec::{BindMount, NetSpec, RootfsSpec, SandboxSpec};
```

to also use the proxy:

```rust
use proctor_sandbox::proxy::HostProxy;
use proctor_sandbox::spec::{BindMount, NetSpec, RootfsSpec, SandboxSpec};
```

Add the enum (above `GradeRequest`):

```rust
/// Network available to the grade command. The grader is trusted (it runs the
/// operator's test harness), so it may use Host; the agent never can.
#[derive(Debug, Clone)]
pub enum GraderNet {
    /// empty network namespace — no egress (default)
    Deny,
    /// share the host's network — full egress (for test bootstraps: uv/pip/apt)
    Host,
    /// reach only these "host:port" targets, through the grader's CONNECT proxy
    Allowlist(Vec<String>),
}
```

Add the field to `GradeRequest` (after `wall_time_secs`):

```rust
    pub network: GraderNet,
```

In `grade()`, replace the hardcoded `network: NetSpec::Deny,` and
`host_proxy_sock: None,` lines in the `SandboxSpec` with values derived from
`req.network`. Just before building the spec, add:

```rust
    // translate the grader network mode; keep the proxy (if any) alive for the run
    let proxy_sock = req.session.join("egress.sock");
    let (net_spec, host_proxy_sock, _proxy) = match &req.network {
        GraderNet::Deny => (NetSpec::Deny, None, None),
        GraderNet::Host => (NetSpec::Host, None, None),
        GraderNet::Allowlist(hosts) => {
            let p = HostProxy::start(&proxy_sock, hosts.clone())
                .map_err(|e| GradeError::Reward(format!("start egress proxy: {e}")))?;
            (
                NetSpec::Allowlist { proxy_sock: PathBuf::from("/run/proctor/egress.sock") },
                Some(proxy_sock.clone()),
                Some(p),
            )
        }
    };
```

and in the `SandboxSpec { ... }` literal set:

```rust
        network: net_spec,
        ...
        host_proxy_sock,
```

(`_proxy` holds the `HostProxy` until the end of `grade()`, keeping its listener
thread alive across `run_sandboxed`. Reuse `GradeError::Reward` for the proxy
start error to avoid adding an error variant for this one path.)

- [ ] **Step 4: Default the existing call sites to `Deny`**

In `crates/proctor-grader/tests/grade_test.rs`, add `network: GraderNet::Deny,` to
each `GradeRequest { ... }` literal that does NOT use `..req` (there are three:
the exit-code pass req, the reward.json req, the reward.txt req — the `req2`
struct-update inherits `network` from `req`). Add the import
`use proctor_grader::GraderNet;` (or extend the existing `use proctor_grader::{...}`).

In `crates/proctor-cli/src/run.rs`, add `network: proctor_grader::GraderNet::Deny,`
to both `GradeRequest { ... }` literals (in `run` and `run_tb`).

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p proctor-grader --test grade_net_test`
Expected: `host_grader_reaches_origin_deny_does_not` PASS; `allowlist_grader_reaches_allowed_origin` PASS where curl exists. Then regression:
`cargo test -p proctor-grader --test grade_test` (exit-code + reward variants still pass).

- [ ] **Step 6: Full gate + commit**

Run: `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: green across the workspace (existing agent + grader + corpus tests unaffected by the default `Deny`).

```bash
git add -A && git commit -m "feat(grader): configurable GraderNet (deny|host|allowlist) network for grading"
```

---

## Self-review

**Spec coverage:**
- `NetSpec::Host` (skip netns) → Task 1 (spec.rs/spawn.rs/net.rs) ✓
- conditional `CLONE_NEWNET`, no proxy env for Host → Task 1 step 4 ✓
- `net::setup` no-op for Host → Task 1 step 5 ✓
- `GraderNet` + `GradeRequest.network` + translation (+ HostProxy for allowlist) → Task 2 step 3 ✓
- call sites default `Deny` (no regression) → Task 2 step 4 ✓
- grader-only Host (agent never gets it) → enforced by construction: `Host` is only reachable via `GraderNet` → `grade()`; `run`/`run_tb`/`run_swebench` build the *agent* spec's network from the policy (`Deny`/`Allowlist`) and never set `Host` ✓
- tests: Host reaches / Deny doesn't (sandbox + grader), allowlist via proxy → Tasks 1 & 2 ✓

**Placeholder scan:** every step has full code + exact commands. The python3/curl gates are real availability checks (mirroring `net_allow_test`/`net_deny_test`), not placeholders.

**Type consistency:** `NetSpec::Host` added in Task 1 and matched in `spawn.rs`/`net.rs`/`grade()`. `GraderNet { Deny, Host, Allowlist(Vec<String>) }` defined in Task 2 and used in `GradeRequest.network`, the test `req()` helper, and the two `run.rs` call sites. `GradeRequest` field order: the test `req()` helper lists fields including `network` last — matches the struct after step 3. `HostProxy::start(sock, Vec<String>)` and `host_proxy_sock: Option<PathBuf>` match the existing `proxy.rs` / `spec.rs` signatures used in `run.rs`.

---

## Execution handoff

Recommended: **inline** — both tasks touch `proctor-sandbox`/`proctor-grader` internals already in context, and Task 2 depends directly on Task 1's `NetSpec::Host`. Both tasks need a sandbox-capable host; the network tests need `python3` (and `curl` for the allowlist case), gated by availability.
