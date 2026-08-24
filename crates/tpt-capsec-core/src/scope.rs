//! Internal scope-matching helpers shared by the wrapper crate.
//!
//! These functions define the matching semantics:
//! component-wise path-prefix matching, exact-or-dot-suffix host matching,
//! and exact-name program allowlists.
//!
//! # Glob support
//!
//! Both [`permits_path`] and [`permits_host`] additionally interpret the
//! wildcard characters `*` (any run of characters within one path component)
//! and `?` (exactly one character) whenever they appear in the scope. A path
//! component consisting solely of `**` matches any number of intermediate
//! directories. Scopes without wildcards keep the exact/prefix semantics
//! described below, so existing delegation graphs behave unchanged.
//!
//! Candidates containing wildcard characters are matched literally against
//! non-glob scopes; avoid delegating authority over paths whose real names
//! contain `*` or `?`.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Returns `true` if `candidate` is equal to or lexically beneath `scope`.
///
/// Matching compares *path components*, so `permits_path("/var/data",
/// "/var/database")` is `false` even though the strings share a string
/// prefix. Relative/absolute mismatches never match.
///
/// Both paths are **lexically normalized** before comparison:
/// `.` components are removed and each `..` component cancels the preceding
/// normal component. A `..` that would climb above the path's anchor
/// (`/var/data/../../etc/passwd`, bare `../x`) causes the check to fail
/// rather than escape the scope. This closes the traversal bypass where an
/// attacker-supplied candidate could smuggle parent components past a naive
/// prefix comparison.
///
/// If the scope contains wildcard characters (`*`, `?`; a lone `**`
/// component spans directories), the comparison switches to glob semantics
/// over the normalized components — see the module documentation.
///
/// Note this is purely lexical: no filesystem access is performed and
/// symlinks are not resolved (the underlying OS may still follow them).
#[must_use]
pub fn permits_path(scope: &Path, candidate: &Path) -> bool {
    let Some(scope_components) = normalized_components(scope) else {
        return false;
    };
    let Some(candidate_components) = normalized_components(candidate) else {
        return false;
    };
    let scope_strs: Vec<String> = scope_components.iter().map(component_string).collect();
    let candidate_strs: Vec<String> = candidate_components.iter().map(component_string).collect();

    if scope_strs.iter().any(|s| has_wildcards(s)) {
        return glob_match(&scope_strs, &candidate_strs);
    }

    scope_components.len() <= candidate_components.len()
        && scope_components
            .iter()
            .zip(&candidate_components)
            .all(|(s, c)| s == c)
}

/// Lexically normalizes `path` into a flat component list.
///
/// Returns `None` if normalization escapes above the path's anchor (a `..`
/// with no preceding normal component to cancel), meaning the path climbs
/// out of any conceivable scope and must never be permitted.
fn normalized_components(path: &Path) -> Option<Vec<std::path::Component<'_>>> {
    use std::path::Component;

    let mut out: Vec<Component<'_>> = Vec::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => match out.last() {
                // Only a normal component can be cancelled; popping a root,
                // prefix, or nothing at all would leave the anchor.
                Some(Component::Normal(_)) => {
                    out.pop();
                }
                _ => return None,
            },
            other => out.push(other),
        }
    }
    Some(out)
}

/// Returns `true` if `candidate` matches the host `scope` exactly or is a
/// dot-separated subdomain of it (`"a.b.example.com"` matches
/// `"example.com"`). Comparison is ASCII case-insensitive.
///
/// If the scope contains wildcards, glob semantics apply over the whole
/// lowercased host string instead: `*.example.com` matches subdomains,
/// `api.*.example.com` fixes label positions. A wildcard `*` may span
/// multiple labels, so prefer anchored patterns like `*.example.com`.
#[must_use]
pub fn permits_host(scope: &str, candidate: &str) -> bool {
    let scope = scope.trim().to_ascii_lowercase();
    let candidate = candidate.trim().to_ascii_lowercase();
    debug_assert!(!scope.is_empty(), "host scope must not be empty");
    if has_wildcards(&scope) || has_wildcards(&candidate) {
        return wildcard_match(&scope, &candidate);
    }
    candidate == scope || candidate.ends_with(&format!(".{scope}"))
}

/// Returns `true` if `program` is contained in the exact-name allowlist.
#[must_use]
pub fn permits_program<'a>(allowlist: impl IntoIterator<Item = &'a String>, program: &str) -> bool {
    allowlist.into_iter().any(|p| p == program)
}

/// Returns `true` if `text` contains a glob metacharacter.
fn has_wildcards(text: &str) -> bool {
    text.contains('*') || text.contains('?')
}

/// Renders a path component as an owned string for glob comparisons.
fn component_string(component: &std::path::Component<'_>) -> String {
    component.as_os_str().to_string_lossy().into_owned()
}

/// Matches `segments` against the possibly-globbed `pattern` segments.
///
/// A segment equal to `"**"` consumes zero or more segments; every other
/// pattern segment must match exactly one segment via [`wildcard_match`].
fn glob_match(pattern: &[String], segments: &[String]) -> bool {
    let Some((head, rest)) = pattern.split_first() else {
        return segments.is_empty();
    };
    if head == "**" {
        return (0..=segments.len()).any(|skip| glob_match(rest, &segments[skip..]));
    }
    let Some((first, tail)) = segments.split_first() else {
        return false;
    };
    wildcard_match(head, first) && glob_match(rest, tail)
}

/// Classic single-segment wildcard matcher supporting `*` (any run of
/// characters, including none) and `?` (exactly one character), with
/// iterative backtracking.
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut backtrack): (Option<usize>, usize) = (None, 0);

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            backtrack = ti;
            pi += 1;
        } else if let Some(star_pos) = star {
            backtrack += 1;
            ti = backtrack;
            pi = star_pos + 1;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Loads the live flag with acquire ordering; `None` means "never revocable".
pub(crate) fn flag_revoked(flag: &Option<Arc<AtomicBool>>) -> bool {
    flag.as_ref().is_some_and(|f| f.load(Ordering::Acquire))
}
