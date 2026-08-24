# Changelog — tpt-capsec-audit

All notable changes to `tpt-capsec-audit` are documented in this file. See
the [workspace changelog](../../CHANGELOG.md) for the combined history
across all `tpt-capsec` crates.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Pre-1.0 policy: minor (`0.x`) releases may contain breaking API changes.

## [Unreleased]

### Added

- Initial scaffold: heuristic scanner flagging direct `std::fs`/
  `std::net`/`std::process` usage in crates that also depend on
  `tpt-capsec`; CI-friendly exit codes (`0` clean, `1` findings present,
  `2` invalid path).
