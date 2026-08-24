//! Plugin / AI-agent integration layer for `tpt-capsec`.
//!
//! # Purpose
//!
//! `tpt-capsec` constrains *trusted Rust code* by construction. To run
//! genuinely **untrusted** code you need a real isolation boundary, such as a
//! WebAssembly runtime with WASI-style permissions or an OS-level sandbox.
//! This crate bridges the two worlds: it maps delegated
//! [`tpt_capsec`] tokens onto the permission vocabulary those sandboxes use,
//! so a host application can derive a guest's sandbox configuration from the
//! same authority model it uses internally.
//!
//! # One-way mapping (v0.1 decision)
//!
//! The v0.1 adapter is **one-way only**: tokens configure a sandbox for a
//! guest module. Guest-initiated requests are *not* surfaced back as gated
//! Rust host functions — that reverse adapter requires per-engine callback
//! plumbing and is planned post-v0.1.
//!
//! # Mapping table (WASI vocabulary)
//!
//! | tpt-capsec token      | Sandbox concept                        |
//! |-----------------------|----------------------------------------|
//! | `FsReadToken`         | preopened directory, read-only          |
//! | `FsWriteToken`        | preopened directory, read-write         |
//! | `NetConnectToken`     | outbound host allowlist                 |
//! | `NetBindToken`        | socket-address bind permit              |
//!
//! # Engine adapters
//!
//! Direct `wasmtime` and `extism` bindings are intentionally **not**
//! included in v0.1: both move fast and pinning them in this release would
//! force every downstream build to compile multi-minute dependency trees.
//! The feature flags exist so the API surface stays stable when the
//! adapters land. Until then, use [`SandboxPlan`] output to configure your
//! engine of choice manually.
//!
//! # Version-compatibility policy
//!
//! When engine adapters ship behind `wasmtime` / `extism` features, each
//! release will document the exact supported engine versions in the
//! changelog, and Cargo semver requirements will be conservative
//! (`=MAJOR.MINOR` ranges for wasmtime until it reaches 1.0 stability).

#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![forbid(unsafe_code)]

// Both engines embed wasmtime's C support code; linking two copies of it
// into one binary collides on duplicate C symbols (e.g.
// `__jit_debug_register_code`). Pick one engine per build.
#[cfg(all(feature = "wasmtime", feature = "extism"))]
compile_error!(
    "features `wasmtime` and `extism` are mutually exclusive: \
     each embeds its own wasmtime runtime and their C symbols collide at link time"
);

#[cfg(feature = "extism")]
pub mod extism;
#[cfg(feature = "wasmtime")]
pub mod wasmtime;

use std::net::SocketAddr;
use std::path::PathBuf;

use tpt_capsec::core::{FsReadToken, FsWriteToken, NetBindToken, NetConnectToken};

/// A single preopened-directory grant derived from an fs token.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PreopenedDir {
    /// Host path exposed to the guest.
    pub guest_path: PathBuf,
    /// Whether the guest may write (read-only otherwise).
    pub write: bool,
}

/// The complete sandbox configuration derived from a set of tokens.
///
/// Feed this into `WasiCtxBuilder::preopened_dir`, extism manifest fields, or
/// any equivalent mechanism of your runtime.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SandboxPlan {
    /// Filesystem grants.
    pub preopened_dirs: Vec<PreopenedDir>,
    /// Hosts the guest may open connections to (exact or subdomain match).
    pub allowed_hosts: Vec<String>,
    /// Exact addresses the guest may bind.
    pub bind_addrs: Vec<SocketAddr>,
}

impl SandboxPlan {
    /// Creates an empty plan.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a read-only preopened directory from an `FsReadToken`'s scope.
    ///
    /// Returns `Err` if the token has been revoked.
    pub fn grant_fs_read(
        &mut self,
        token: &FsReadToken<'_>,
    ) -> Result<&mut Self, tpt_capsec::CapsecError> {
        if token.is_revoked() {
            return Err(tpt_capsec::CapsecError::Revoked);
        }
        self.preopened_dirs.push(PreopenedDir {
            guest_path: token.scope().to_path_buf(),
            write: false,
        });
        Ok(self)
    }

    /// Adds a read-write preopened directory from an `FsWriteToken`'s scope.
    ///
    /// Returns `Err` if the token has been revoked.
    pub fn grant_fs_write(
        &mut self,
        token: &FsWriteToken<'_>,
    ) -> Result<&mut Self, tpt_capsec::CapsecError> {
        if token.is_revoked() {
            return Err(tpt_capsec::CapsecError::Revoked);
        }
        self.preopened_dirs.push(PreopenedDir {
            guest_path: token.scope().to_path_buf(),
            write: true,
        });
        Ok(self)
    }

    /// Adds an outbound-host allowlist entry from a `NetConnectToken`.
    ///
    /// Returns `Err` if the token has been revoked.
    pub fn grant_net_connect(
        &mut self,
        token: &NetConnectToken<'_>,
    ) -> Result<&mut Self, tpt_capsec::CapsecError> {
        if token.is_revoked() {
            return Err(tpt_capsec::CapsecError::Revoked);
        }
        self.allowed_hosts.push(token.scope().clone());
        Ok(self)
    }

    /// Adds a bind permit from a `NetBindToken`.
    ///
    /// Returns `Err` if the token has been revoked.
    pub fn grant_net_bind(
        &mut self,
        token: &NetBindToken<'_>,
    ) -> Result<&mut Self, tpt_capsec::CapsecError> {
        if token.is_revoked() {
            return Err(tpt_capsec::CapsecError::Revoked);
        }
        self.bind_addrs.push(*token.scope());
        Ok(self)
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use super::*;

    #[test]
    fn plan_round_trips_through_json() {
        let mut plan = SandboxPlan::new();
        plan.preopened_dirs.push(PreopenedDir {
            guest_path: "/data".into(),
            write: false,
        });
        plan.allowed_hosts.push("api.example.com".into());
        plan.bind_addrs.push("127.0.0.1:8080".parse().unwrap());

        let json = serde_json::to_string(&plan).unwrap();
        let back: SandboxPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(plan, back);
    }
}
