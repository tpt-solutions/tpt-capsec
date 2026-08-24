# Changelog — tpt-capsec-integrations

All notable changes to `tpt-capsec-integrations` are documented in this
file. See the [workspace changelog](../../CHANGELOG.md) for the combined
history across all `tpt-capsec` crates.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Pre-1.0 policy: minor (`0.x`) releases may contain breaking API changes.

## [Unreleased]

### Added

- Std-only WASI-style mapping layer (`SandboxPlan`, `PreopenedDir`)
  describing how token authority translates into preopened directories and
  socket permissions.
- Direct `wasmtime` adapter (`wasmtime::apply`, behind the `wasmtime`
  feature) mapping a `SandboxPlan` onto a restricted `WasiCtxBuilder`;
  reports `NetConnectToken`/`NetBindToken` grants back as
  `UnenforcedGrants` since preview1 WASI cannot express outbound
  connect/bind. Pinned to `wasmtime-wasi = "=24"`.
- Opt-in `serde` feature for `SandboxPlan` / `PreopenedDir`.
- `extism` feature flag reserved for a future manifest adapter (not yet
  implemented).
