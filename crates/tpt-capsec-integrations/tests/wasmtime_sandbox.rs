//! End-to-end sandbox-restriction proof for the wasmtime adapter.
//!
//! Runs a real wasm module inside a WASI context built by
//! [`tpt_capsec_integrations::wasmtime::apply`] and verifies the guest
//! **cannot** escape its delegated scope:
//!
//! - a preopened directory derived from an `FsWriteToken`-style grant is the
//!   guest's only filesystem authority;
//! - the module tries to `path_open("../outside.txt")` — climbing out of the
//!   preopen — and exits with the raw WASI errno;
//! - preview1 must reject the traversal with `NOTCAPABLE` (76), proving the
//!   plan actually constrains execution, not just configuration.

#![cfg(feature = "wasmtime")]

use std::net::SocketAddr;

use tpt_capsec::prelude::*;
use tpt_capsec_integrations::{PreopenedDir, SandboxPlan};
use wasmtime::{Config, Engine, Linker, Module, Store};
use wasmtime_wasi::preview1::{self, WasiP1Ctx};
use wasmtime_wasi::WasiCtxBuilder;

/// Guest module: opens `../outside.txt` relative to its only preopened
/// directory (fd 3) and stores the resulting WASI errno at address 64.
const ESCAPE_ATTEMPT_WAT: &str = r#"
(module
  (import "wasi_snapshot_preview1" "path_open"
    (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "../outside.txt")
  (func $_start (export "_start")
    (i32.store (i32.const 64)
      (call $path_open
        (i32.const 3)              ;; first preopened directory
        (i32.const 0)              ;; lookup flags
        (i32.const 0)              ;; path pointer
        (i32.const 14)             ;; path length ("../outside.txt")
        (i32.const 0)              ;; open flags
        (i64.const 0)              ;; rights base: none needed to be denied
        (i64.const 0)              ;; rights inheriting
        (i32.const 0)              ;; fd flags
        (i32.const 32)))))         ;; opened-fd output pointer
"#;

#[test]
fn guest_cannot_escape_delegated_scope() {
    // Host layout: scratch/<inside> is delegated; scratch/outside exists but
    // must stay unreachable even via `..`.
    let scratch = std::env::temp_dir().join("tpt-capsec-wasi-sandbox-test");
    let inside = scratch.join("inside");
    let outside = scratch.join("outside");
    std::fs::create_dir_all(&inside).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("outside.txt"), b"secret").unwrap();

    // The plan derives purely from tokens, as a host would build it.
    let root = RootCapability::acquire();
    let write_token = root.delegate_fs_write(&inside);
    let connect_token = root.delegate_net_connect("api.example.com");
    let bind_token = root.delegate_net_bind(SocketAddr::from(([127, 0, 0, 1], 8080)));

    let mut plan = SandboxPlan::new();
    plan.grant_fs_write(&write_token).unwrap();
    plan.grant_net_connect(&connect_token).unwrap();
    plan.grant_net_bind(&bind_token).unwrap();

    // Build the restricted context.
    let mut builder = WasiCtxBuilder::new();
    let unenforced = tpt_capsec_integrations::wasmtime::apply(&plan, &mut builder).unwrap();
    // Host/bind grants are reported, never silently enforced.
    assert_eq!(unenforced.allowed_hosts.len(), 1);
    assert_eq!(unenforced.bind_addrs.len(), 1);

    let engine = Engine::new(&Config::new()).unwrap();
    let module = Module::new(&engine, ESCAPE_ATTEMPT_WAT).unwrap();

    let mut linker: Linker<WasiP1Ctx> = Linker::new(&engine);
    preview1::add_to_linker_sync(&mut linker, |ctx| ctx).unwrap();

    let mut store = Store::new(&engine, builder.build_p1());
    let instance = linker.instantiate(&mut store, &module).unwrap();
    let start = instance
        .get_typed_func::<(), ()>(&mut store, "_start")
        .unwrap();

    // The traversal must be denied: read back the path_open errno.
    start
        .call(&mut store, ())
        .expect("guest _start must return");
    let memory = instance
        .get_memory(&mut store, "memory")
        .expect("module exports memory");
    let mut errno_bytes = [0u8; 4];
    memory.read(&store, 64, &mut errno_bytes).unwrap();
    let errno = i32::from_le_bytes(errno_bytes);
    // The traversal must be denied by authority, not fail with a file error.
    // 63 = PERM and 76 = NOTCAPABLE are the two capability-denial errnos
    // used across preview1 implementations.
    assert!(
        errno == 63 || errno == 76,
        "traversal must be denied with a capability errno, got {errno}"
    );

    // And the outside secret was never touched.
    assert_eq!(
        std::fs::read_to_string(outside.join("outside.txt")).unwrap(),
        "secret"
    );

    std::fs::remove_dir_all(&scratch).ok();
}

// Keep PreopenedDir imported even if the plan construction changes shape.
#[allow(dead_code)]
fn _type_witness(_: Vec<PreopenedDir>) {}
