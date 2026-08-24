//! Sandboxed filesystem operations.
//!
//! Every function performs, in order:
//!
//! 1. a **revocation check** on the token (opt-in; fails with
//!    [`CapsecError::Revoked`]), and
//! 2. a **scope check** of the requested path against the token's prefix
//!    (fails with [`CapsecError::OutOfScope`]),
//!
//! before delegating to the corresponding `std::fs` operation. `std` I/O
//! errors are passed through unchanged.
//!
//! The fs API is deliberately **one-shot** (slurp/write): wrappers return
//! owned data rather than long-lived handles, preventing capability
//! laundering through unchecked `File` objects that outlive scope
//! validation.

use std::fs::Metadata;
use std::path::Path;

use tpt_capsec_core::{FsReadToken, FsWriteToken};

use crate::error::CapsecError;

/// Checks revocation + scope before touching `std`.
fn authorize(token: &FsReadToken<'_>, path: &Path) -> Result<(), CapsecError> {
    if token.is_revoked() {
        return Err(CapsecError::Revoked);
    }
    if !token.permits_path(path) {
        return Err(CapsecError::OutOfScope(format!(
            "read of '{}' outside token scope",
            path.display()
        )));
    }
    Ok(())
}

fn authorize_write(token: &FsWriteToken<'_>, path: &Path) -> Result<(), CapsecError> {
    if token.is_revoked() {
        return Err(CapsecError::Revoked);
    }
    if !token.permits_path(path) {
        return Err(CapsecError::OutOfScope(format!(
            "write of '{}' outside token scope",
            path.display()
        )));
    }
    Ok(())
}

/// Reads a file's full contents as bytes, requiring read authority.
///
/// # Example
///
/// ```
/// use tpt_capsec::prelude::*;
/// use tpt_capsec::fs;
///
/// let root = RootCapability::acquire();
/// let dir = std::env::temp_dir().join("tpt-capsec-doctest-read");
/// std::fs::create_dir_all(&dir).unwrap();
/// std::fs::write(dir.join("config.json"), b"{}").unwrap();
///
/// let token = root.delegate_fs_read(&dir);
/// let data = fs::read(dir.join("config.json"), &token).unwrap();
/// assert_eq!(data, b"{}");
/// ```
pub fn read(path: impl AsRef<Path>, token: &FsReadToken<'_>) -> Result<Vec<u8>, CapsecError> {
    let path = path.as_ref();
    authorize(token, path)?;
    Ok(std::fs::read(path)?)
}

/// Reads a file's full contents as UTF-8, requiring read authority.
pub fn read_to_string(
    path: impl AsRef<Path>,
    token: &FsReadToken<'_>,
) -> Result<String, CapsecError> {
    let path = path.as_ref();
    authorize(token, path)?;
    Ok(std::fs::read_to_string(path)?)
}

/// Writes bytes to a file (creating or truncating it), requiring write
/// authority for the destination.
pub fn write(
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
    token: &FsWriteToken<'_>,
) -> Result<(), CapsecError> {
    let path = path.as_ref();
    authorize_write(token, path)?;
    Ok(std::fs::write(path, contents)?)
}

/// Removes a file, requiring write authority.
pub fn remove(path: impl AsRef<Path>, token: &FsWriteToken<'_>) -> Result<(), CapsecError> {
    let path = path.as_ref();
    authorize_write(token, path)?;
    Ok(std::fs::remove_file(path)?)
}

/// Recursively removes a directory tree, requiring write authority.
pub fn remove_dir_all(path: impl AsRef<Path>, token: &FsWriteToken<'_>) -> Result<(), CapsecError> {
    let path = path.as_ref();
    authorize_write(token, path)?;
    Ok(std::fs::remove_dir_all(path)?)
}

/// Creates a directory and all missing parents, requiring write authority.
pub fn create_dir_all(path: impl AsRef<Path>, token: &FsWriteToken<'_>) -> Result<(), CapsecError> {
    let path = path.as_ref();
    authorize_write(token, path)?;
    Ok(std::fs::create_dir_all(path)?)
}

/// Lists a directory's entries as an eagerly-collected vector of paths.
///
/// A live iterator is intentionally not returned: it would escape scope
/// validation for entries listed after the initial check.
pub fn read_dir(
    path: impl AsRef<Path>,
    token: &FsReadToken<'_>,
) -> Result<Vec<std::path::PathBuf>, CapsecError> {
    let path = path.as_ref();
    authorize(token, path)?;
    let mut out = Vec::new();
    for entry in std::fs::read_dir(path)? {
        out.push(entry?.path());
    }
    Ok(out)
}

/// Returns the metadata of a path, requiring read authority.
pub fn metadata(path: impl AsRef<Path>, token: &FsReadToken<'_>) -> Result<Metadata, CapsecError> {
    let path = path.as_ref();
    authorize(token, path)?;
    Ok(std::fs::metadata(path)?)
}

/// Renames (moves) `from` to `to`.
///
/// This is a **dual-token** operation: `from` must be within the read
/// token's scope and `to` within the *same* write token's scope. Requiring
/// both authorities from one token prevents using two unrelated tokens to
/// exfiltrate data across trust boundaries.
pub fn rename(
    from: impl AsRef<Path>,
    to: impl AsRef<Path>,
    token: &FsWriteToken<'_>,
) -> Result<(), CapsecError> {
    let from = from.as_ref();
    let to = to.as_ref();
    if token.is_revoked() {
        return Err(CapsecError::Revoked);
    }
    if !(token.permits_path(from) && token.permits_path(to)) {
        return Err(CapsecError::OutOfScope(format!(
            "rename '{}' -> '{}' not fully within token scope",
            from.display(),
            to.display()
        )));
    }
    Ok(std::fs::rename(from, to)?)
}

/// Copies `from` to `to`.
///
/// Dual-token variant of [`rename`]: the source needs read authority, the
/// destination write authority — they may be different tokens.
pub fn copy(
    from: impl AsRef<Path>,
    to: impl AsRef<Path>,
    read_token: &FsReadToken<'_>,
    write_token: &FsWriteToken<'_>,
) -> Result<u64, CapsecError> {
    let from = from.as_ref();
    let to = to.as_ref();
    authorize(read_token, from)?;
    authorize_write(write_token, to)?;
    Ok(std::fs::copy(from, to)?)
}
