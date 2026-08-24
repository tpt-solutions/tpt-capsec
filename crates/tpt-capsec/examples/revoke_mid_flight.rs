//! Revoking authority mid-flight across a spawned thread.
//!
//! A worker thread holds a revocable read token and keeps serving requests.
//! The coordinator revokes the shared [`RevocationGroup`] while the worker is
//! still running; every subsequent wrapper call fails fast with
//! [`CapsecError::Revoked`].

use std::path::PathBuf;

use tpt_capsec::fs;
use tpt_capsec::prelude::*;

fn main() {
    // Setup: a scratch file the worker will be allowed to read.
    let dir = std::env::temp_dir().join("tpt-capsec-example-revoke");
    std::fs::create_dir_all(&dir).unwrap();
    let file: PathBuf = dir.join("payload.txt");
    std::fs::write(&file, b"secret payload").unwrap();

    let root = RootCapability::acquire();
    let group = RevocationGroup::new();
    let token = root.delegate_fs_read(&dir).with_revocation(&group);

    let worker_file = file.clone();
    // Tokens borrow the root, so they cannot enter a `'static` thread; a
    // scoped thread keeps the borrow valid for the duration of the section.
    std::thread::scope(|s| {
        let worker = s.spawn(|| {
            for i in 0..10 {
                match fs::read_to_string(&worker_file, &token) {
                    Ok(data) => println!("worker read #{i}: {data}"),
                    Err(CapsecError::Revoked) => {
                        println!("worker saw revocation at iteration {i}; stopping");
                        return i;
                    }
                    Err(e) => panic!("unexpected error: {e}"),
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            10
        });

        // Let the worker get started, then pull its authority.
        std::thread::sleep(std::time::Duration::from_millis(50));
        group.revoke();
        println!("coordinator revoked the group");

        let iterations = worker.join().unwrap();
        assert!(iterations < 10, "revocation must stop the worker early");
        println!("worker stopped after {iterations} successful reads");
    });

    std::fs::remove_file(&file).ok();
}
