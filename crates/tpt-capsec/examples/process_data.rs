//! Runnable version of the README/spec "process data" scenario.
//!
//! A service reads a configuration file and writes a report. The config
//! directory is delegated as read authority, the output directory as write
//! authority, and an out-of-scope request is rejected at runtime.

use std::path::Path;

use tpt_capsec::fs;
use tpt_capsec::prelude::*;

fn main() {
    // Prepare two scratch directories out-of-band (setup is ambient authority;
    // the sandboxed code below only ever sees scoped tokens).
    let base = std::env::temp_dir().join("tpt-capsec-example-process-data");
    std::fs::create_dir_all(base.join("config")).unwrap();
    std::fs::create_dir_all(base.join("out")).unwrap();
    std::fs::write(base.join("config/settings.json"), br#"{"verbose": true}"#).unwrap();

    let root = RootCapability::acquire();
    let config_dir = root.delegate_fs_read(base.join("config"));
    let out_dir = root.delegate_fs_write(base.join("out"));

    // In-scope read succeeds.
    let raw = fs::read_to_string(base.join("config/settings.json"), &config_dir)
        .expect("config read must be in scope");
    println!("config: {raw}");

    // Write the derived report inside the write scope.
    let report_path = base.join("out/report.txt");
    fs::write(&report_path, format!("derived from: {raw}"), &out_dir).unwrap();
    println!("wrote {}", report_path.display());

    // Out-of-scope read fails fast instead of leaking outside the scope.
    let escape = Path::new(&base).join("out").join("../../etc/passwd");
    match fs::read_to_string(&escape, &config_dir) {
        Err(CapsecError::OutOfScope(msg)) => println!("rejected out-of-scope read: {msg}"),
        other => panic!("expected OutOfScope, got {other:?}"),
    }

    // Cleanup via the write token itself.
    fs::remove(&report_path, &out_dir).unwrap();
}
