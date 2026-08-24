//! Shared error type for all sandboxed wrappers.

use std::fmt;
use std::io;

/// Errors produced by `tpt-capsec` sandboxed operations.
///
/// Two variants are produced by the enforcement layer itself
/// ([`OutOfScope`](CapsecError::OutOfScope) and
/// [`Revoked`](CapsecError::Revoked)); everything else is transparent
/// passthrough from the underlying `std` operation.
#[derive(Debug)]
pub enum CapsecError {
    /// The requested target lies outside the token's delegated scope.
    ///
    /// The payload describes what was requested; it never contains secret
    /// material beyond the caller's own arguments.
    OutOfScope(String),
    /// The token's revocation group has been revoked.
    Revoked,
    /// The underlying `std` operation failed.
    Io(io::Error),
    /// A wrapper-specific failure that is neither a scope violation nor I/O.
    Other(String),
}

impl fmt::Display for CapsecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfScope(detail) => write!(f, "operation outside delegated scope: {detail}"),
            Self::Revoked => write!(f, "capability has been revoked"),
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::Other(detail) => write!(f, "{detail}"),
        }
    }
}

impl std::error::Error for CapsecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for CapsecError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
