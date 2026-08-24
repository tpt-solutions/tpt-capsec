//! Core capability primitives for `tpt-capsec`.
//!
//! # The two-layer enforcement model
//!
//! `tpt-capsec` enforces authority in two cooperating layers:
//!
//! 1. **Type-level gate.** Authority is represented by unforgeable,
//!    correctly-typed tokens ([`FsReadToken`], [`NetConnectToken`], ...).
//!    Tokens have private constructors and are sealed behind the
//!    [`Capability`] trait, so external crates cannot mint fake tokens.
//!    Tokens carry a lifetime link (`PhantomData<&'a ...>`) back to the
//!    delegating parent, so a delegated child cannot outlive its parent.
//!    A function's signature therefore *is* its authority declaration: if it
//!    does not ask for an [`FsWriteToken`], it cannot delete files through
//!    the sandboxed wrappers at all.
//! 2. **Runtime scope check.** Each token carries a *scope* (a path prefix,
//!    host pattern, socket address, or program allowlist). Wrapper functions
//!    validate every operation against this scope before touching `std`,
//!    failing fast when the request exceeds the delegated authority.
//!
//! # Type-state token pattern
//!
//! Tokens are plain data structures whose constructors are private. The only
//! way to obtain one is to delegate from a [`RootCapability`] (or to narrow
//! an existing token). Because delegation methods take `&self`, the returned
//! child token's lifetime is tied to the borrow of the parent — emulating a
//! linear "cannot outlive the grantor" rule with the ordinary borrow checker.
//!
//! Tokens deliberately do **not** implement `Clone` or `Copy`: moving a token
//! consumes it, so "use after hand-off" is a compile error. This emulates
//! linear-type discipline without nightly features.
//!
//! # `RootCapability`
//!
//! [`RootCapability::acquire`] is a **documentation-only convention** for
//! v0.1: any code may call it, representing "this program's root of trust".
//! We deliberately do not enforce a process-wide singleton: a runtime
//! singleton would add global mutable state, complicate testing and
//! multi-threaded initialization, and provide no real security boundary —
//! anything able to call `acquire()` in-process could equally call `std`
//! directly. See `SECURITY.md` in the repository for the full threat model.
//!
//! # Scope-matching semantics (v0.1)
//!
//! - Filesystem scopes match **lexically by path-component prefix**
//!   ([`permits_path`]). Scopes may additionally contain glob wildcards
//!   (`*`, `?`, and a lone `**` component spanning directories).
//! - Network connect scopes match **exact hosts or dot-suffix subdomains**
//!   ([`permits_host`]), or glob patterns when the scope contains
//!   wildcards; bind scopes match **exact socket addresses**.
//! - Process scopes are **exact-name allowlists** ([`permits_program`]).
//!
//! # Runtime revocation (opt-in)
//!
//! Compile-time revocation is drop/move based. For tokens handed across
//! threads or tasks, [`RevocationGroup`] provides opt-in cooperative
//! revocation: wrappers check the shared flag and fail with a revoked error
//! once [`RevocationGroup::revoke`] has been called.
//!
//! # Thread safety
//!
//! Tokens are plain data (paths, strings, an optional shared atomic flag)
//! and are `Send + Sync`, supporting the AI-agent-orchestration use case of
//! delegating authority into spawned threads or async tasks.

#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![forbid(unsafe_code)]

mod bundle;
mod capability;
mod narrow;
mod revocation;
mod scope;
mod tokens;

pub use bundle::CapabilitySet;
pub use capability::{Capability, RootCapability};
pub use revocation::RevocationGroup;
pub use scope::{permits_host, permits_path, permits_program};
pub use tokens::{FsReadToken, FsWriteToken, NetBindToken, NetConnectToken, ProcessSpawnToken};
