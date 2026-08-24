//! Groups of related tokens delegated together.
//!
//! [`CapabilitySet`] bundles one token per authority kind so functions that
//! need several authorities can take a single parameter instead of five,
//! while keeping every token's lifetime tied to the delegating
//! [`RootCapability`] borrow.

use crate::tokens::{FsReadToken, FsWriteToken, NetBindToken, NetConnectToken, ProcessSpawnToken};
use std::fmt;

/// A bundle holding at most one token per authority kind.
///
/// Build one with the `with_*` builder methods; read the held tokens back
/// with the matching accessors. The set is deliberately **not** `Clone`:
/// like its contents it moves linearly.
#[derive(Default)]
pub struct CapabilitySet<'a> {
    fs_read: Option<FsReadToken<'a>>,
    fs_write: Option<FsWriteToken<'a>>,
    net_connect: Option<NetConnectToken<'a>>,
    net_bind: Option<NetBindToken<'a>>,
    process_spawn: Option<ProcessSpawnToken<'a>>,
}

impl<'a> CapabilitySet<'a> {
    /// Creates an empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds (or replaces) the filesystem-read token.
    #[must_use]
    pub fn with_fs_read(self, token: FsReadToken<'a>) -> Self {
        Self {
            fs_read: Some(token),
            ..self
        }
    }

    /// Adds (or replaces) the filesystem-write token.
    #[must_use]
    pub fn with_fs_write(self, token: FsWriteToken<'a>) -> Self {
        Self {
            fs_write: Some(token),
            ..self
        }
    }

    /// Adds (or replaces) the outbound-connect token.
    #[must_use]
    pub fn with_net_connect(self, token: NetConnectToken<'a>) -> Self {
        Self {
            net_connect: Some(token),
            ..self
        }
    }

    /// Adds (or replaces) the bind token.
    #[must_use]
    pub fn with_net_bind(self, token: NetBindToken<'a>) -> Self {
        Self {
            net_bind: Some(token),
            ..self
        }
    }

    /// Adds (or replaces) the process-spawn token.
    #[must_use]
    pub fn with_process_spawn(self, token: ProcessSpawnToken<'a>) -> Self {
        Self {
            process_spawn: Some(token),
            ..self
        }
    }

    /// Borrows the bundled filesystem-read token, if any.
    #[must_use]
    pub fn fs_read(&self) -> Option<&FsReadToken<'_>> {
        self.fs_read.as_ref()
    }

    /// Borrows the bundled filesystem-write token, if any.
    #[must_use]
    pub fn fs_write(&self) -> Option<&FsWriteToken<'_>> {
        self.fs_write.as_ref()
    }

    /// Borrows the bundled outbound-connect token, if any.
    #[must_use]
    pub fn net_connect(&self) -> Option<&NetConnectToken<'_>> {
        self.net_connect.as_ref()
    }

    /// Borrows the bundled bind token, if any.
    #[must_use]
    pub fn net_bind(&self) -> Option<&NetBindToken<'_>> {
        self.net_bind.as_ref()
    }

    /// Borrows the bundled process-spawn token, if any.
    #[must_use]
    pub fn process_spawn(&self) -> Option<&ProcessSpawnToken<'_>> {
        self.process_spawn.as_ref()
    }
}

impl fmt::Debug for CapabilitySet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redacted like individual tokens: kinds only, never scopes.
        let present = [
            self.fs_read.as_ref().map(|_| "fs_read"),
            self.fs_write.as_ref().map(|_| "fs_write"),
            self.net_connect.as_ref().map(|_| "net_connect"),
            self.net_bind.as_ref().map(|_| "net_bind"),
            self.process_spawn.as_ref().map(|_| "process_spawn"),
        ];
        let list: Vec<&str> = present.into_iter().flatten().collect();
        write!(f, "CapabilitySet {{ {} }}", list.join(", "))
    }
}
