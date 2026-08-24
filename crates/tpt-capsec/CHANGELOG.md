# Changelog — tpt-capsec

All notable changes to `tpt-capsec` are documented in this file. See the
[workspace changelog](../../CHANGELOG.md) for the combined history across
all `tpt-capsec` crates.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Pre-1.0 policy: minor (`0.x`) releases may contain breaking API changes.

## [Unreleased]

### Added

- Sandboxed wrappers for `std::fs`, `std::net` (TCP), and `std::process`,
  gated by the corresponding `tpt-capsec-core` capability tokens; shared
  `CapsecError`; `prelude` module re-exporting everything needed for
  typical usage.
- Opt-in `tracing` feature emitting audit events (`debug` on grant, `warn`
  on denial) on the `tpt_capsec` target from every authorization choke
  point.
- Runnable examples: `process_data`, `sandboxed_plugin`,
  `revoke_mid_flight` (see [`examples/`](examples)).

### Changed

- `SECURITY.md` now explicitly states that process tokens scope program
  names only, not arguments.
