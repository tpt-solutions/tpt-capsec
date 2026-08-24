//! Scope-check and narrowing methods for the generated token types.
//!
//! These impls live in a sibling module purely to keep `tokens.rs` focused
//! on the macro-generated structure; they are part of the same public API.

use std::path::Path;

use crate::scope;
use crate::tokens::{FsReadToken, FsWriteToken, NetBindToken, NetConnectToken, ProcessSpawnToken};

impl FsReadToken<'_> {
    /// Checks whether `candidate` falls within this token's path scope.
    #[must_use]
    pub fn permits_path(&self, candidate: &Path) -> bool {
        scope::permits_path(&self.scope, candidate)
    }

    /// Narrows this token to a sub-path of its scope.
    ///
    /// The child shares this token's revocation flag, if any, and cannot
    /// outlive the borrow of its parent.
    ///
    /// # Panics
    /// Panics if `sub` lies outside the current scope; use
    /// [`try_narrow`](Self::try_narrow) for a fallible variant.
    #[must_use]
    pub fn narrow<'a, P: AsRef<Path>>(&'a self, sub: P) -> FsReadToken<'a> {
        self.try_narrow(sub).expect("narrow: sub-path out of scope")
    }

    /// Fallibly narrows this token to a sub-path of its scope, returning
    /// `None` if `sub` is not covered.
    #[must_use]
    pub fn try_narrow<'a, P: AsRef<Path>>(&'a self, sub: P) -> Option<FsReadToken<'a>> {
        if !self.permits_path(sub.as_ref()) {
            return None;
        }
        Some(FsReadToken::new(
            sub.as_ref().to_path_buf(),
            self.live.clone(),
        ))
    }
}

impl FsWriteToken<'_> {
    /// Checks whether `candidate` falls within this token's path scope.
    #[must_use]
    pub fn permits_path(&self, candidate: &Path) -> bool {
        scope::permits_path(&self.scope, candidate)
    }

    /// Narrows this write token to a sub-path of its scope.
    ///
    /// # Panics
    /// Panics if `sub` lies outside the current scope.
    #[must_use]
    pub fn narrow<'a, P: AsRef<Path>>(&'a self, sub: P) -> FsWriteToken<'a> {
        assert!(
            self.permits_path(sub.as_ref()),
            "narrow: sub-path out of scope"
        );
        FsWriteToken::new(sub.as_ref().to_path_buf(), self.live.clone())
    }
}

impl NetConnectToken<'_> {
    /// Checks whether `host` matches this token's scope exactly or as a
    /// dot-suffix subdomain.
    #[must_use]
    pub fn permits_host(&self, host: &str) -> bool {
        scope::permits_host(&self.scope, host)
    }

    /// Narrows the connect scope to a subdomain of the current scope.
    ///
    /// # Panics
    /// Panics if `sub` is not covered by the current scope.
    #[must_use]
    pub fn narrow<'a>(&'a self, sub: &str) -> NetConnectToken<'a> {
        assert!(self.permits_host(sub), "narrow: host out of scope");
        NetConnectToken::new(sub.to_ascii_lowercase(), self.live.clone())
    }
}

impl NetBindToken<'_> {
    /// Checks whether `addr` is exactly the address this token may bind.
    #[must_use]
    pub fn permits_addr(&self, addr: std::net::SocketAddr) -> bool {
        self.scope == addr
    }
}

impl ProcessSpawnToken<'_> {
    /// Checks whether `program` appears in this token's allowlist.
    #[must_use]
    pub fn permits_program(&self, program: &str) -> bool {
        scope::permits_program(self.scope.iter(), program)
    }

    /// Narrows this token to a subset of its allowlist.
    ///
    /// # Panics
    /// Panics if any entry of `programs` is not already allowed.
    #[must_use]
    pub fn narrow<'a, I, S>(&'a self, programs: I) -> ProcessSpawnToken<'a>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let items: Vec<String> = programs
            .into_iter()
            .map(|p| p.as_ref().to_string())
            .collect();
        for p in &items {
            assert!(
                self.permits_program(p),
                "narrow: program '{p}' out of scope"
            );
        }
        ProcessSpawnToken::new(items, self.live.clone())
    }
}
