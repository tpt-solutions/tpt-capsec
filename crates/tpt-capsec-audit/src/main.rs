//! CLI entry point for the `tpt-capsec-audit` scanner.
//!
//! Usage: `tpt-capsec-audit [PATH]` (defaults to the current directory).
//! Exits with status 1 when any finding is reported, so it can gate CI.

use std::process::ExitCode;

fn main() -> ExitCode {
    let root = std::env::args()
        .nth(1)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().expect("no current directory"));

    if !root.is_dir() {
        eprintln!("error: '{}' is not a directory", root.display());
        return ExitCode::from(2);
    }

    let findings = tpt_capsec_audit::scan(&root);
    print!("{}", tpt_capsec_audit::format_report(&findings));
    if findings.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
