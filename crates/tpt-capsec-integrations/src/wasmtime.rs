//! Direct wasmtime adapter (behind the `wasmtime` feature).
//!
//! Maps a [`SandboxPlan`] onto wasmtime's
//! `WasiCtxBuilder` so the guest's WASI authority is exactly what the host
//! delegated through tpt-capsec tokens:
//!
//! - read-only `FsReadToken` scopes become preopened directories with
//!   `DirPerms::empty()` + `FilePerms::read()`;
//! - write `FsWriteToken` scopes become preopened directories with
//!   `DirPerms::all()` + `FilePerms::all()`.
//!
//! # Not enforceable by WASI preview1
//!
//! Wasmtime's preview1 WASI has **no outbound TCP connect and no bind**
//! support, so [`SandboxPlan`] entries produced from `NetConnectToken` /
//! `NetBindToken` cannot be expressed in a `WasiCtxBuilder`. [`apply`]
//! reports them back as *unenforced* grants instead of silently dropping
//! them; enforce those at another layer (e.g. deny sockets at embedding, or
//! an OS-level sandbox) or do not delegate them to untrusted guests.

use std::net::SocketAddr;

use crate::{PreopenedDir, SandboxPlan};
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtxBuilder};

/// Grants from the plan that the target WASI implementation cannot enforce.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnenforcedGrants {
    /// Outbound-host allowlist entries (from `NetConnectToken`).
    pub allowed_hosts: Vec<String>,
    /// Bind permits (from `NetBindToken`).
    pub bind_addrs: Vec<SocketAddr>,
}

/// Applies every expressible entry of `plan` onto `builder`.
///
/// Preopened directories are added in plan order. On success, returns the
/// grants that preview1 WASI cannot enforce — treat them as review items
/// before running untrusted modules.
///
/// # Errors
/// Returns an I/O-flavored error if any host path cannot be preopened
/// (missing directory, permission problem, ...).
pub fn apply(
    plan: &SandboxPlan,
    builder: &mut WasiCtxBuilder,
) -> Result<UnenforcedGrants, std::io::Error> {
    for dir in &plan.preopened_dirs {
        let (dir_perms, file_perms) = perms_for(dir);
        let guest = dir.guest_path.to_string_lossy();
        builder
            .preopened_dir(&dir.guest_path, &*guest, dir_perms, file_perms)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
    }
    Ok(UnenforcedGrants {
        allowed_hosts: plan.allowed_hosts.clone(),
        bind_addrs: plan.bind_addrs.clone(),
    })
}

/// Maps a grant's write flag onto WASI permission sets.
///
/// This pinned wasmtime line's `FilePerms` offers only `empty`/`all`, so a
/// read-only grant uses `DirPerms::empty()` (no listing/create/delete) plus
/// `FilePerms::all()`. For hard read-only guarantees against untrusted
/// guests, back the host directory with filesystem ACLs as well.
fn perms_for(dir: &PreopenedDir) -> (DirPerms, FilePerms) {
    if dir.write {
        (DirPerms::all(), FilePerms::all())
    } else {
        (DirPerms::empty(), FilePerms::all())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SandboxPlan;

    #[test]
    fn applies_dirs_and_reports_unenforced_grants() {
        // A real host directory is required for preopening.
        let host_dir = std::env::temp_dir().join("tpt-capsec-wasmtime-adapter-test");
        std::fs::create_dir_all(&host_dir).unwrap();

        let mut plan = SandboxPlan::new();
        plan.preopened_dirs.push(PreopenedDir {
            guest_path: host_dir.clone(),
            write: false,
        });
        plan.allowed_hosts.push("api.example.com".into());
        plan.bind_addrs.push("127.0.0.1:8080".parse().unwrap());

        let mut builder = WasiCtxBuilder::new();
        let unenforced = apply(&plan, &mut builder).expect("apply must succeed");

        assert_eq!(unenforced.allowed_hosts, ["api.example.com".to_string()]);
        assert_eq!(unenforced.bind_addrs.len(), 1);
    }

    #[test]
    fn missing_host_path_is_an_error() {
        let mut plan = SandboxPlan::new();
        plan.preopened_dirs.push(PreopenedDir {
            guest_path: "definitely/not/a/real/dir".into(),
            write: true,
        });
        let mut builder = WasiCtxBuilder::new();
        assert!(apply(&plan, &mut builder).is_err());
    }
}
