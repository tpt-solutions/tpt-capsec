//! Everything typically needed to use `tpt-capsec` in one import.
//!
//! ```
//! use tpt_capsec::prelude::*;
//!
//! let root = RootCapability::acquire();
//! let token = root.delegate_fs_read("/tmp");
//! assert!(token.permits_path(std::path::Path::new("/tmp/x")));
//! ```

pub use crate::CapsecError;
pub use tpt_capsec_core::{
    Capability, FsReadToken, FsWriteToken, NetBindToken, NetConnectToken, ProcessSpawnToken,
    RevocationGroup, RootCapability,
};
