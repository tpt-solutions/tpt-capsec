//! Source scanner that flags direct `std::fs` / `std::net` /
//! `std::process` usage in crates that also depend on `tpt-capsec`.
//!
//! The point: a crate that adopts the capability model should route its
//! privileged operations through the sandboxed wrappers. Direct `std` calls
//! silently bypass every scope check, so they are worth surfacing in review
//! and CI.
//!
//! This is a heuristic text scanner, not a rustc plugin: it catches the
//! common forms (`std::fs::read`, `use std::fs;`, `Command::new` via
//! `std::process`, ...) but cannot see macro-generated or fully-qualified
//! aliased paths. Treat findings as review hints, not proof of violation.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// A single finding: direct privileged-`std` usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Path of the source file containing the hit.
    pub file: PathBuf,
    /// One-based line number.
    pub line: usize,
    /// The matched source line, trimmed.
    pub snippet: String,
    /// Which privileged module was used (`fs`, `net`, or `process`).
    pub module: &'static str,
}

/// Patterns that indicate direct use of a privileged `std` module.
const PATTERNS: &[(&str, &str)] = &[
    ("std::fs::", "fs"),
    ("std::net::", "net"),
    ("std::process::", "process"),
    ("use std::fs", "fs"),
    ("use std::net", "net"),
    ("use std::process", "process"),
    ("use std::{fs", "fs"),
    ("use std::{net", "net"),
    ("use std::{process", "process"),
    ("std::process", "process"),
];

/// Returns `true` if a `Cargo.toml` declares a dependency on `tpt-capsec`
/// (any of the workspace crates). Purely textual, matching the common
/// `[dependencies]` entry forms.
#[must_use]
pub fn depends_on_capsec(manifest: &str) -> bool {
    manifest.contains("tpt-capsec")
}

/// Scans `root` recursively for Rust crates depending on `tpt-capsec` whose
/// `.rs` sources use `std::fs` / `std::net` / `std::process` directly.
///
/// Directories named `target` and files under `tests/`/`examples/` of
/// non-capsec crates are still scanned; `target/` is always skipped.
#[must_use]
pub fn scan(root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut manifests = Vec::new();
    collect_manifests(root, &mut manifests);

    for manifest_path in manifests {
        let Ok(manifest) = fs::read_to_string(&manifest_path) else {
            continue;
        };
        if !depends_on_capsec(&manifest) {
            continue;
        }
        let package_dir = manifest_path.parent().unwrap_or(root);
        // Skip this workspace's own implementation crates: they are the
        // sanctioned bridge to `std`.
        let dir_name = package_dir.file_name().unwrap_or_default();
        if IMPLEMENTATION_CRATES.contains(&dir_name.to_string_lossy().as_ref()) {
            continue;
        }
        scan_sources(package_dir, &mut findings);
    }
    findings.sort_by(|a, b| (&a.file, a.line).cmp(&(&b.file, b.line)));
    findings
}

/// Package directories that are exempt from scanning.
const IMPLEMENTATION_CRATES: &[&str] = &["tpt-capsec", "tpt-capsec-core", "tpt-capsec-audit"];

/// Collects every `Cargo.toml` beneath `root`, skipping `target/` dirs.
fn collect_manifests(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "target" || name == ".git" {
            continue;
        }
        if path.is_dir() {
            collect_manifests(&path, out);
        } else if name == "Cargo.toml" {
            out.push(path);
        }
    }
}

/// Scans all `.rs` files under a package directory for direct `std` usage.
fn scan_sources(dir: &Path, findings: &mut Vec<Finding>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan_sources(&path, findings);
        } else if path.extension().is_some_and(|e| e == "rs") {
            scan_file(&path, findings);
        }
    }
}

/// Scans one source file, line by line.
fn scan_file(path: &Path, findings: &mut Vec<Finding>) {
    let Ok(contents) = fs::read_to_string(path) else {
        return;
    };
    for (idx, line) in contents.lines().enumerate() {
        // Skip comments and the scanner crate's own pattern table.
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        for (pattern, module) in PATTERNS {
            if line.contains(pattern) && !is_capsec_source(path) {
                findings.push(Finding {
                    file: path.to_path_buf(),
                    line: idx + 1,
                    snippet: trimmed.to_string(),
                    module,
                });
                break;
            }
        }
    }
}

/// The audit crate itself must talk to the filesystem directly; never
/// report its own sources.
fn is_capsec_source(path: &Path) -> bool {
    path.components()
        .any(|c| c.as_os_str() == "tpt-capsec-audit")
}

/// Formats findings as human-readable report lines.
#[must_use]
pub fn format_report(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "no direct std::fs/std::net/std::process usage found in tpt-capsec crates\n".into();
    }
    let mut by_module: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut out = String::new();
    for f in findings {
        *by_module.entry(f.module).or_insert(0) += 1;
        out.push_str(&format!(
            "{}:{}: direct std::{} usage: {}\n",
            f.file.display(),
            f.line,
            f.module,
            f.snippet
        ));
    }
    let summary: Vec<String> = by_module.iter().map(|(m, n)| format!("{n} {m}")).collect();
    out.push_str(&format!(
        "\n{} finding(s): {}\n",
        findings.len(),
        summary.join(", ")
    ));
    out
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_detection() {
        assert!(depends_on_capsec("tpt-capsec = { version = \"0.1\" }"));
        assert!(depends_on_capsec("tpt-capsec-core = \"0.1\""));
        assert!(!depends_on_capsec("serde = \"1\""));
    }

    #[test]
    fn report_is_stable_and_empty_case_works() {
        let out = format_report(&[]);
        assert!(out.contains("no direct"));
        assert_eq!(scan(Path::new("definitely/not/a/dir")), Vec::new());
    }
}
