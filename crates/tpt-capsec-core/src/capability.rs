//! Sealed capability trait and the root capability.

use std::net::SocketAddr;
use std::path::Path;

use crate::tokens::{FsReadToken, FsWriteToken, NetBindToken, NetConnectToken, ProcessSpawnToken};

pub(crate) mod private {
    /// Prevents downstream crates from implementing [`crate::Capability`].
    pub trait Sealed {}
}

/// Marker trait implemented by every capability token in this crate.
///
/// This trait is *sealed*: external crates cannot implement it, which means
/// they cannot forge tokens. The only way to obtain a token is to delegate
/// from a [`RootCapability`] or to narrow an existing token.
pub trait Capability: private::Sealed + std::fmt::Debug {}

/// The root of the capability hierarchy.
///
/// `RootCapability` represents total ambient authority over the process.
///
/// # Singleton policy
///
/// For v0.1 this is a **documentation-only convention**: [`acquire`](Self::acquire)
/// simply constructs a fresh root. It is intentionally not a runtime-enforced
/// singleton because in-process global state adds no security boundary
/// (anything able to call `acquire()` can call `std` directly) while
/// complicating tests and threaded initialization. See `SECURITY.md` in the
/// repository for the full threat model.
///
/// # Example
///
/// ```
/// use tpt_capsec_core::RootCapability;
///
/// let root = RootCapability::acquire();
/// let read = root.delegate_fs_read("/var/data");
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct RootCapability {
    /// Prevents structural construction outside this module.
    _private: (),
}

impl private::Sealed for RootCapability {}
impl Capability for RootCapability {}

impl RootCapability {
    /// Acquires the root capability for this program.
    ///
    /// By convention, call this exactly once, at the top of `main`, and
    /// delegate narrowly-scoped tokens from it.
    #[must_use]
    pub fn acquire() -> Self {
        Self { _private: () }
    }

    /// Delegates a scoped filesystem-read authority.
    ///
    /// `scope` is a path prefix; only reads underneath it are permitted.
    #[must_use]
    pub fn delegate_fs_read<'a, P: AsRef<Path>>(&'a self, scope: P) -> FsReadToken<'a> {
        FsReadToken::new(scope.as_ref().to_path_buf(), None)
    }

    /// Delegates a scoped filesystem-write authority.
    #[must_use]
    pub fn delegate_fs_write<'a, P: AsRef<Path>>(&'a self, scope: P) -> FsWriteToken<'a> {
        FsWriteToken::new(scope.as_ref().to_path_buf(), None)
    }

    /// Delegates a scoped TCP-connect authority.
    ///
    /// `host` permits the exact host and any dot-suffix subdomain.
    #[must_use]
    pub fn delegate_net_connect<'a>(&'a self, host: &str) -> NetConnectToken<'a> {
        NetConnectToken::new(host.to_ascii_lowercase(), None)
    }

    /// Delegates authority to bind exactly one socket address.
    #[must_use]
    pub fn delegate_net_bind<'a>(&'a self, addr: SocketAddr) -> NetBindToken<'a> {
        NetBindToken::new(addr, None)
    }

    /// Delegates authority to spawn exactly the listed programs.
    #[must_use]
    pub fn delegate_process_spawn<'a, I, S>(&'a self, programs: I) -> ProcessSpawnToken<'a>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        ProcessSpawnToken::new(programs.into_iter().map(Into::into).collect(), None)
    }
}
