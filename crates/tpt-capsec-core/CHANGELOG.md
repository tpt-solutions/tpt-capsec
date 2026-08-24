# Changelog — tpt-capsec-core

All notable changes to `tpt-capsec-core` are documented in this file. See
the [workspace changelog](../../CHANGELOG.md) for the combined history
across all `tpt-capsec` crates.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Pre-1.0 policy: minor (`0.x`) releases may contain breaking API changes.

## [Unreleased]

### Added

- Sealed `Capability` trait, `RootCapability`, scoped tokens (`FsReadToken`,
  `FsWriteToken`, `NetConnectToken`, `NetBindToken`, `ProcessSpawnToken`),
  scope-check helpers (`permits_path`, `permits_host`, `permits_program`),
  sub-delegation (`narrow`), and opt-in runtime revocation
  (`RevocationGroup`).
- Glob-style path/host scopes (`*`, `?`, `**`) interpreted automatically
  when present in a delegated scope.
- `CapabilitySet` bundle type grouping one token per authority kind.
- `cargo-fuzz` targets for `permits_path` / `permits_host` /
  `permits_program`.

### Fixed

- **Security:** lexical path-traversal bypass in `permits_path` —
  candidates containing `..` are now lexically normalized first, so paths
  like `/var/data/../../etc/passwd` can no longer pass a prefix check.
  Regression tests added.
- `RootCapability` no longer derives `Clone`/`Copy`, matching the
  linear-use discipline of every token type.

### Changed

- `NetBindToken` documents why it has no `narrow` method (its scope is a
  single exact address with nothing to narrow to).
