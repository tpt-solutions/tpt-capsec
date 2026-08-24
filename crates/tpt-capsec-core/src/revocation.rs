//! Opt-in cooperative runtime revocation.
//!
//! Compile-time revocation in `tpt-capsec` is move/drop based: consuming or
//! dropping a token ends its usefulness. That covers single-threaded,
//! lexically-scoped delegation, but not tokens handed across threads or
//! stored inside long-lived tasks where the borrow checker cannot see the
//! end of the "logical" grant.
//!
//! [`RevocationGroup`] fills that gap as an **opt-in** mechanism: attach one
//! to a token at delegation time via `with_revocation`, share clones of it
//! anywhere, and call [`revoke`](RevocationGroup::revoke). Every wrapper call
//! checks the shared atomic flag before performing its operation.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// The shared live/revoked flag stored inside tokens.
pub(crate) type SharedFlag = Arc<AtomicBool>;

/// A cloneable handle controlling cooperative revocation of delegated tokens.
///
/// Clone it to hand out additional revoke triggers (e.g. to a supervisor
/// thread), or keep it private and drop it when the ability to revoke should
/// itself expire.
///
/// # Example
///
/// ```
/// use tpt_capsec_core::{RevocationGroup, RootCapability};
///
/// let root = RootCapability::acquire();
/// let group = RevocationGroup::new();
/// let token = root.delegate_fs_read("/var/data").with_revocation(&group);
/// group.revoke();
/// assert!(token.is_revoked());
/// ```
#[derive(Debug, Clone, Default)]
pub struct RevocationGroup(SharedFlag);

impl RevocationGroup {
    /// Creates a new group in the "live" state.
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    /// Revokes every token attached to this group.
    ///
    /// Subsequent wrapper calls on attached tokens fail fast. This is
    /// idempotent and thread-safe (`Release` ordering pairs with the
    /// `Acquire` load performed by token checks).
    pub fn revoke(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Returns `true` if this group has been revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    /// Attaches this group's flag to a token being constructed.
    pub(crate) fn flag(&self) -> SharedFlag {
        Arc::clone(&self.0)
    }
}
