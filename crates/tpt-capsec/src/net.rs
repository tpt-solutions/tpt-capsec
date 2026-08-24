//! Sandboxed TCP networking operations.
//!
//! `tcp_connect` validates the host against a `NetConnectToken`'s
//! exact-or-dot-suffix scope; `tcp_bind` requires an exact-address
//! `NetBindToken`. Revoked tokens fail fast with [`CapsecError::Revoked`];
//! out-of-scope requests with [`CapsecError::OutOfScope`]. UDP support is
//! deliberately deferred past v0.1.

use std::net::{SocketAddr, TcpListener, TcpStream};
use tpt_capsec_core::{NetBindToken, NetConnectToken};

use crate::error::CapsecError;

fn authorize_connect(token: &NetConnectToken<'_>, host: &str) -> Result<(), CapsecError> {
    if token.is_revoked() {
        return Err(CapsecError::Revoked);
    }
    if !token.permits_host(host) {
        return Err(CapsecError::OutOfScope(format!(
            "connect to '{host}' outside token scope"
        )));
    }
    Ok(())
}

/// Opens a TCP connection to `host:port`, requiring connect authority for
/// the host.
///
/// # Example
///
/// ```no_run
/// use tpt_capsec::prelude::*;
/// use tpt_capsec::net;
///
/// let root = RootCapability::acquire();
/// let token = root.delegate_net_connect("example.com");
/// let stream = net::tcp_connect("example.com", 443, &token).unwrap();
/// ```
pub fn tcp_connect(
    host: &str,
    port: u16,
    token: &NetConnectToken<'_>,
) -> Result<TcpStream, CapsecError> {
    authorize_connect(token, host)?;
    Ok(TcpStream::connect((host, port))?)
}

fn authorize_bind(token: &NetBindToken<'_>, addr: SocketAddr) -> Result<(), CapsecError> {
    if token.is_revoked() {
        return Err(CapsecError::Revoked);
    }
    if !token.permits_addr(addr) {
        return Err(CapsecError::OutOfScope(format!(
            "bind to '{addr}' outside token scope"
        )));
    }
    Ok(())
}

/// Binds a TCP listener to exactly `addr`, requiring bind authority for that
/// address.
pub fn tcp_bind(addr: SocketAddr, token: &NetBindToken<'_>) -> Result<TcpListener, CapsecError> {
    authorize_bind(token, addr)?;
    Ok(TcpListener::bind(addr)?)
}
