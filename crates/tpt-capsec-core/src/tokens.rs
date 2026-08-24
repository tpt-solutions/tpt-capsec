//! The concrete capability token types.
//!
//! Tokens are generated from a small internal `macro_rules!` definition to
//! avoid repeating the type-state boilerplate (private constructors,
//! lifetime linkage, revocation plumbing) five times. A dedicated proc-macro
//! crate was evaluated and deliberately **not** adopted for v0.1: the shared
//! shape across token kinds fits comfortably in one declarative macro, and
//! dropping the proc-macro crate removes an entire publish/build dependency.
//!
//! Tokens intentionally do **not** implement `Clone` or `Copy`: moving a
//! token consumes it, so handing authority to a callee is irrevocable at the
//! type level ("use after move" is a compile error). This emulates linear
//! types with the standard borrow checker.
//!
//! `Debug` implementations are **redacted**: they print the token kind but
//! never the delegated scope, so accidental logging cannot leak the security
//! topology of an application.

use std::fmt;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use crate::capability::{private, Capability};
use crate::revocation::{RevocationGroup, SharedFlag};
use crate::scope;

/// Defines a capability token struct with private constructors, lifetime
/// linkage, redacted `Debug`, revocation support, and its scope accessor.
macro_rules! define_token {
    (
        $(#[$doc:meta])*
        $name:ident {
            scope: $scope_ty:ty,
            doc_scope: $scope_doc:expr,
        }
    ) => {
        $(#[$doc])*
        pub struct $name<'a> {
            pub(crate) scope: $scope_ty,
            pub(crate) live: Option<SharedFlag>,
            _marker: PhantomData<&'a ()>,
        }

        impl<'a> $name<'a> {
            pub(crate) fn new(scope: $scope_ty, live: Option<SharedFlag>) -> Self {
                Self { scope, live, _marker: PhantomData }
            }

            /// Attaches an opt-in runtime revocation group to this token.
            ///
            /// After [`RevocationGroup::revoke`] is called on any clone of
            /// the group, every wrapper operation performed through this
            /// token fails fast.
            #[must_use]
            pub fn with_revocation(mut self, group: &RevocationGroup) -> Self {
                self.live = Some(group.flag());
                self
            }

            /// Returns `true` if this token's revocation group (if any) has
            /// been revoked. Non-revocable tokens always return `false`.
            #[must_use]
            pub fn is_revoked(&self) -> bool {
                scope::flag_revoked(&self.live)
            }

            #[doc = $scope_doc]
            #[must_use]
            pub fn scope(&self) -> &$scope_ty {
                &self.scope
            }
        }

        impl private::Sealed for $name<'_> {}
        impl Capability for $name<'_> {}

        impl fmt::Debug for $name<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{} {{ <redacted> }}", stringify!($name))
            }
        }
    };
}

define_token! {
    /// Authority to *read* from paths at or beneath a directory prefix.
    ///
    /// Obtain one via [`crate::RootCapability::delegate_fs_read`] or by
    /// narrowing an existing token ([`FsReadToken::narrow`]).
    FsReadToken {
        scope: PathBuf,
        doc_scope: "The path prefix this token grants read access to.",
    }
}

define_token! {
    /// Authority to *write* (create/modify/delete) at or beneath a prefix.
    FsWriteToken {
        scope: PathBuf,
        doc_scope: "The path prefix this token grants write access to.",
    }
}

define_token! {
    /// Authority to open TCP connections to a host and its subdomains.
    NetConnectToken {
        scope: String,
        doc_scope: "The host pattern this token grants outbound connections to.",
    }
}

define_token! {
    /// Authority to bind exactly one socket address.
    NetBindToken {
        scope: SocketAddr,
        doc_scope: "The exact socket address this token may bind.",
    }
}

define_token! {
    /// Authority to spawn programs from an exact-name allowlist.
    ProcessSpawnToken {
        scope: Vec<String>,
        doc_scope: "The exact program names this token may spawn.",
    }
}

// Keep Arc referenced so imports stay valid if expansions change.
#[allow(unused)]
fn _assert_arc_used(_: Option<Arc<()>>) {}
