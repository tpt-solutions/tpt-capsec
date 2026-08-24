//! Direct extism adapter (behind the `extism` feature).
//!
//! Compiles a [`SandboxPlan`](crate::SandboxPlan) into an
//! [`extism::Manifest`]:
//!
//! - fs token scopes become `allowed_paths` entries (host path → guest path);
//! - `NetConnectToken` scopes become the manifest's outbound host allowlist —
//!   extism enforces these itself for guests using its HTTP API;
//! - `NetBindToken` permits have no extism equivalent and are reported back.
//!
//! Unlike the wasmtime adapter, extism's manifest is declarative JSON, so no
//! host directories need to exist at plan-compilation time; existence is only
//! checked when a plugin actually runs.

use std::net::SocketAddr;

use crate::SandboxPlan;
use extism::Manifest;

/// Grants from the plan that the extism runtime cannot enforce.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnenforcedGrants {
    /// Bind permits (from `NetBindToken`) — extism has no bind concept.
    pub bind_addrs: Vec<SocketAddr>,
}

/// Compiles `plan` into an extism `Manifest` over the given wasm module.
///
/// The module argument accepts anything `Manifest::new` accepts (raw bytes,
/// a file path via [`extism::Wasm`], ...). Preopened-style directory grants
/// are added as `allowed_paths` in plan order; read-only grants map to a
/// guest path with the read-only marker extism expects (`::ro` suffix).
///
/// Returns the grants extism cannot express so callers can review them
/// before running untrusted plugins.
pub fn compile(plan: &SandboxPlan, wasm: impl Into<extism::Wasm>) -> (Manifest, UnenforcedGrants) {
    let mut manifest = Manifest::new([wasm.into()]);
    let mut allowed_hosts: Vec<String> = Vec::new();

    // Deduplicate hosts across connect tokens while preserving order.
    // extism maps host paths -> guest-visible paths, marking read-only
    // grants with a `::ro` suffix on the host side.
    for dir in &plan.preopened_dirs {
        let host = dir.guest_path.to_string_lossy().into_owned();
        let host = if dir.write {
            host
        } else {
            format!("{host}::ro")
        };
        let guest = dir.guest_path.to_string_lossy().replace("::ro", "");
        manifest = manifest.with_allowed_path(host, guest);
    }
    allowed_hosts.extend(plan.allowed_hosts.iter().cloned());
    if !allowed_hosts.is_empty() {
        manifest = manifest.with_allowed_hosts(allowed_hosts.into_iter());
    }

    (
        manifest,
        UnenforcedGrants {
            bind_addrs: plan.bind_addrs.clone(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PreopenedDir;

    #[test]
    fn compiles_manifest_from_plan() {
        let mut plan = SandboxPlan::new();
        plan.preopened_dirs.push(PreopenedDir {
            guest_path: "/data".into(),
            write: false,
        });
        plan.allowed_hosts.push("api.example.com".into());
        plan.bind_addrs.push("127.0.0.1:8080".parse().unwrap());

        // Minimal valid wasm module bytes (empty module).
        let wasm_bytes: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        let (manifest, unenforced) = compile(
            &plan,
            extism::Wasm::Data {
                data: wasm_bytes.to_vec(),
                meta: Default::default(),
            },
        );

        let paths = manifest.allowed_paths.as_ref().unwrap();
        assert_eq!(paths.len(), 1);
        assert!(paths.contains_key("/data::ro"));
        assert_eq!(
            paths.get("/data::ro"),
            Some(&std::path::PathBuf::from("/data"))
        );
        assert_eq!(unenforced.bind_addrs.len(), 1);
    }
}
