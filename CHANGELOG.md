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
