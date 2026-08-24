//! Sandboxed standard-library wrappers enforcing `tpt-capsec` capabilities.
//!
//! This crate wires [`tpt_capsec_core`] primitives to real operations:
//!
//! - [`fs`] — one-shot read/write/list/delete/copy/rename wrappers around
//!   `std::fs`, gated by `FsReadToken` / `FsWriteToken`.
//! - [`net`] — TCP connect/bind gated by `NetConnectToken` / `NetBindToken`.
//!   UDP is deliberately deferred past v0.1.
//! - [`process`] — spawn/output gated by `ProcessSpawnToken`.
//!
//! Every wrapper performs an opt-in revocation check and a scope check
//! before delegating to `std`; violations surface as
//! [`CapsecError::OutOfScope`] or [`CapsecError::Revoked`]. A `CryptoSignToken`
//! mentioned in the project overview is explicitly deferred to post-v0.1.
//!
//! # Example (the spec's `process_data` scenario)
//!
//! ```
//! use tpt_capsec::prelude::*;
//! use tpt_capsec::{fs, CapsecError};
//!
//! fn process_data(fs_tok: FsReadToken<'_>, net: NetConnectToken<'_>)
//!     -> Result<(), CapsecError>
//! {
//!     let cfg = std::env::temp_dir().join("tpt-capsec-lib-doc").join("config.json");
//!     let _data = fs::read(&cfg, &fs_tok)?;
//!     Ok(())
//! }
//!
//! let root = RootCapability::acquire();
//! let dir = std::env::temp_dir().join("tpt-capsec-lib-doc");
//! std::fs::create_dir_all(&dir).unwrap();
//! std::fs::write(dir.join("config.json"), b"{}").unwrap();
//!
//! let fs_tok = root.delegate_fs_read(&dir);
//! let net = root.delegate_net_connect("api.example.com");
//! assert!(process_data(fs_tok, net).is_ok());
//! ```

#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![forbid(unsafe_code)]

pub mod error;
pub mod fs;
pub mod net;
pub mod prelude;
pub mod process;

pub use error::CapsecError;
pub use tpt_capsec_core as core;
