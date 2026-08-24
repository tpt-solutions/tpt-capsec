//! Internal scope-matching helpers shared by the wrapper crate.
//!
//! These functions define the v0.1 matching semantics:
//! component-wise path-prefix matching, exact-or-dot-suffix host matching,
//! and exact-name program allowlists. Glob support is deliberately deferred.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Returns `true` if `candidate` is equal to or lexically beneath `scope`.
///
/// Matching compares *path components*, so `permits_path("/var/data",
/// "/var/database")` is `false` even though the strings share a string
/// prefix. Relative/absolute mismatches never match.
#[must_use]
pub fn permits_path(scope: &Path, candidate: &Path) -> bool {
    let mut candidate_components = candidate.components();
    for s in scope.components() {
        match candidate_components.next() {
            Some(c) if c == s => continue,
            _ => return false,
        }
    }
    true
}

/// Returns `true` if `candidate` matches the host `scope` exactly or is a
/// dot-separated subdomain of it (`"a.b.example.com"` matches
/// `"example.com"`). Comparison is ASCII case-insensitive.
#[must_use]
pub fn permits_host(scope: &str, candidate: &str) -> bool {
    let scope = scope.trim().to_ascii_lowercase();
    let candidate = candidate.trim().to_ascii_lowercase();
    debug_assert!(!scope.is_empty(), "host scope must not be empty");
    candidate == scope || candidate.ends_with(&format!(".{scope}"))
}

/// Returns `true` if `program` is contained in the exact-name allowlist.
#[must_use]
pub fn permits_program<'a>(allowlist: impl IntoIterator<Item = &'a String>, program: &str) -> bool {
    allowlist.into_iter().any(|p| p == program)
}

/// Loads the live flag with acquire ordering; `None` means "never revocable".
pub(crate) fn flag_revoked(flag: &Option<Arc<AtomicBool>>) -> bool {
    flag.as_ref().is_some_and(|f| f.load(Ordering::Acquire))
}
