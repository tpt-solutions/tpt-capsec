//! Authorization audit logging.
//!
//! Every wrapper's authorization choke point reports through this module.
//! Without the `tracing` feature the calls compile to no-ops; with it, each
//! decision is emitted on the `tpt_capsec` target: `debug` for grants,
//! `warn` for denials. Events carry the operation kind and the failure
//! reason (which includes caller-supplied paths/hosts, matching the
//! existing `CapsecError` payloads).

/// Records a granted authorization.
pub(crate) fn granted(op: &'static str) {
    #[cfg(feature = "tracing")]
    tracing::debug!(target: "tpt_capsec", op = op, "capability check granted");
    #[cfg(not(feature = "tracing"))]
    let _ = op;
}

/// Records a denied authorization or failed operation.
pub(crate) fn denied(op: &'static str, reason: &dyn std::fmt::Display) {
    #[cfg(feature = "tracing")]
    tracing::warn!(target: "tpt_capsec", op = op, reason = %reason, "capability check denied");
    #[cfg(not(feature = "tracing"))]
    let _ = (op, reason);
}
