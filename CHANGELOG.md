# Changelog

All notable changes to `tpt-capsec` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Pre-1.0 policy: minor (`0.x`) releases may contain breaking API changes.

## [Unreleased]

### Added

- `tpt-capsec-core`: sealed `Capability` trait, `RootCapability`, scoped tokens
  (`FsReadToken`, `FsWriteToken`, `NetConnectToken`, `NetBindToken`,
  `ProcessSpawnToken`), scope-check helpers (`permits_path`, `permits_host`,
  `permits_program`), sub-delegation (`narrow`), and opt-in runtime revocation
  (`RevocationGroup`).
- `tpt-capsec`: sandboxed wrappers for `std::fs`, `std::net` (TCP) and
  `std::process`, gated by the corresponding capability tokens; shared
  `CapsecError`; `prelude` module re-exporting everything needed for typical
  usage.
- `tpt-capsec-integrations`: std-only WASI-style mapping layer describing how
  token authority translates into preopened directories / socket permissions;
  engine adapters (wasmtime, extism) planned behind feature flags.
- `tpt-capsec-core`: glob-style path/host scopes (`*`, `?`, `**`) interpreted
  automatically when present in a delegated scope; `CapabilitySet` bundle type
  grouping one token per authority kind.
- `tpt-capsec`: opt-in `tracing` feature emitting audit events
  (`debug`/`warn` on the `tpt_capsec` target) from every authorization choke
  point.
- `tpt-capsec-integrations`: opt-in `serde` feature for `SandboxPlan` /
  `PreopenedDir`.
- New `tpt-capsec-audit` crate: heuristic scanner flagging direct
  `std::fs`/`std::net`/`std::process` usage in crates depending on
  `tpt-capsec`; CI-friendly exit codes.
- Direct wasmtime adapter (`wasmtime` feature, pinned `wasmtime-wasi = "=24"`):
  maps `SandboxPlan` preopened directories onto a restricted `WasiCtxBuilder`
  and reports host/bind grants as unenforceable under preview1 WASI.
- Direct extism adapter (`extism` feature, pinned `extism = "=1"`): compiles
  `SandboxPlan` into an extism `Manifest` (`allowed_paths` with `::ro`
  read-only markers, native outbound-host allowlist); the two engine features
  are mutually exclusive (their wasmtime C runtimes collide at link time).
- End-to-end sandbox-restriction integration test: a checked-in WAT module
  runs inside the token-derived WASI context and its `../` traversal attempt
  is denied with a capability errno while the outside file stays untouched.
- CI: `cargo-semver-checks` and `cargo-deny` jobs; checked-in `cargo-fuzz`
  targets for `permits_path` / `permits_host` / `permits_program`.
- Copy-paste starter skeleton under `template/`; runnable examples
  (`process_data`, `sandboxed_plugin`, `revoke_mid_flight`); `GUIDE.md`.

### Fixed

- **Security:** lexical path-traversal bypass in `permits_path` — candidates
  containing `..` are now lexically normalized first, so paths like
  `/var/data/../../etc/passwd` can no longer pass a prefix check. Regression
  tests added.
- `RootCapability` no longer derives `Clone`/`Copy`, matching the linear-use
  discipline of all other tokens.

### Changed

- `NetBindToken` documents why it has no `narrow` method.
- `SECURITY.md` now explicitly states that process tokens scope program
  names only, not arguments.
