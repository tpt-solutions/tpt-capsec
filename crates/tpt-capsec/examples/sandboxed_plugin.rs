//! Building a `SandboxPlan` end-to-end from delegated capability tokens.
//!
//! This is the host side of the plugin story: the same authority model used
//! inside the host compiles down to a WASI-style sandbox configuration that
//! can be handed to wasmtime / extism (or any equivalent runtime).

use std::net::SocketAddr;

use tpt_capsec::prelude::*;
use tpt_capsec_integrations::SandboxPlan;

fn main() {
    let root = RootCapability::acquire();

    // The host decides what the plugin may do, using ordinary tokens.
    let data_dir = root.delegate_fs_read("data");
    let scratch_dir = root.delegate_fs_write("scratch");
    let api_host = root.delegate_net_connect("api.example.com");
    let bind = root.delegate_net_bind(SocketAddr::from(([127, 0, 0, 1], 8080)));

    // Compile the tokens into a sandbox plan.
    let mut plan = SandboxPlan::new();
    plan.grant_fs_read(&data_dir)
        .expect("read token is live")
        .grant_fs_write(&scratch_dir)
        .expect("write token is live")
        .grant_net_connect(&api_host)
        .expect("connect token is live")
        .grant_net_bind(&bind)
        .expect("bind token is live");

    println!("sandbox plan for the guest module:");
    for dir in &plan.preopened_dirs {
        println!(
            "  preopen {} ({})",
            dir.guest_path.display(),
            if dir.write { "read-write" } else { "read-only" }
        );
    }
    for host in &plan.allowed_hosts {
        println!("  allow outbound connect to {host}");
    }
    for addr in &plan.bind_addrs {
        println!("  allow bind to {addr}");
    }

    // Feed `plan` into your engine of choice, e.g.:
    //   WasiCtxBuilder::preopened_dir(host_path, guest_path, ...)
    //   extism manifest `allowed_hosts` / wasm filesystem maps
}
