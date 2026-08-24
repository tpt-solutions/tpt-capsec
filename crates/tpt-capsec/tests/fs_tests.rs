//! Integration tests for the sandboxed `fs` wrappers and revocation.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tpt_capsec::prelude::*;
use tpt_capsec::{fs, CapsecError};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Unique per-test temp dir (portable; no hardcoded Unix paths).
pub(crate) fn temp_dir(label: &str) -> std::path::PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "tpt-capsec-it-{}-{}-{}",
        label,
        std::process::id(),
        id
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn fs_read_write_in_scope_succeeds() {
    let root = RootCapability::acquire();
    let dir = temp_dir("rw");
    let read = root.delegate_fs_read(&dir);
    let write = root.delegate_fs_write(&dir);
    let file = dir.join("config.json");

    fs::write(&file, b"hello", &write).unwrap();
    assert_eq!(fs::read(&file, &read).unwrap(), b"hello");
    assert_eq!(fs::read_to_string(&file, &read).unwrap(), "hello");
    assert!(fs::metadata(&file, &read).unwrap().is_file());
    assert_eq!(fs::read_dir(&dir, &read).unwrap().len(), 1);

    fs::remove(&file, &write).unwrap();
    assert!(!file.exists());
}

#[test]
fn fs_out_of_scope_is_rejected() {
    let root = RootCapability::acquire();
    let allowed = temp_dir("in");
    let denied = temp_dir("out");
    let read = root.delegate_fs_read(&allowed);
    let write = root.delegate_fs_write(&allowed);

    match fs::read(denied.join("nope"), &read) {
        Err(CapsecError::OutOfScope(_)) => {}
        other => panic!("expected OutOfScope, got {other:?}"),
    }
    match fs::write(denied.join("nope"), b"x", &write) {
        Err(CapsecError::OutOfScope(_)) => {}
        other => panic!("expected OutOfScope, got {other:?}"),
    }
}

#[test]
fn fs_io_errors_pass_through() {
    let root = RootCapability::acquire();
    let dir = temp_dir("ioerr");
    let read = root.delegate_fs_read(&dir);
    match fs::read(dir.join("missing.txt"), &read) {
        Err(CapsecError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
        other => panic!("expected Io error, got {other:?}"),
    }
}

#[test]
fn fs_dual_token_operations() {
    let root = RootCapability::acquire();
    let dir = temp_dir("dual");
    let read = root.delegate_fs_read(&dir);
    let write = root.delegate_fs_write(&dir);
    let src = dir.join("a.txt");
    let dst = dir.join("b.txt");

    fs::write(&src, b"payload", &write).unwrap();
    fs::copy(&src, &dst, &read, &write).unwrap();
    assert_eq!(fs::read(&dst, &read).unwrap(), b"payload");

    // rename requires BOTH paths inside one write token.
    fs::rename(&src, dir.join("c.txt"), &write).unwrap();

    // Copy whose SOURCE lies outside the read token's scope is rejected
    // even with a valid write token for the destination.
    let outside = temp_dir("elsewhere");
    let src2 = outside.join("x");
    std::fs::write(&src2, b"secret").unwrap();
    match fs::copy(&src2, &dst, &read, &write) {
        Err(CapsecError::OutOfScope(_)) => {}
        other => panic!("expected OutOfScope, got {other:?}"),
    }
}

#[test]
fn create_dir_all_and_remove_dir_all() {
    let root = RootCapability::acquire();
    let dir = temp_dir("mkdir");
    let write = root.delegate_fs_write(&dir);
    let nested = dir.join("a").join("b").join("c");

    fs::create_dir_all(&nested, &write).unwrap();
    assert!(nested.is_dir());

    // Removing a parent of the scope must be rejected: it lies OUTSIDE the
    // token's prefix, so a child cannot delete its own grantor's tree.
    let parent = dir.parent().unwrap().to_path_buf();
    assert!(matches!(
        fs::remove_dir_all(parent, &write),
        Err(CapsecError::OutOfScope(_))
    ));

    fs::remove_dir_all(&dir, &write).unwrap();
    assert!(!dir.exists());
}

#[test]
fn revoked_tokens_fail_every_wrapper() {
    let root = RootCapability::acquire();
    let dir = temp_dir("revoked");
    let group = RevocationGroup::new();
    let read = Arc::new(root.delegate_fs_read(&dir).with_revocation(&group));

    // Revoke mid-flight from another thread while a call is queued up.
    // Scoped threads let the lifetime-bound token move into the worker.
    std::thread::scope(|s| {
        let reader = Arc::clone(&read);
        let handle = s.spawn(move || {
            let f = reader.scope().join("f");
            fs::read(f, &reader)
        });
        group.revoke();
        match handle.join().unwrap() {
            Err(CapsecError::Revoked) => {}
            other => panic!("expected Revoked, got {other:?}"),
        }
    });
}
