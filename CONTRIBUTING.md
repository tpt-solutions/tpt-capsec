# Contributing to tpt-capsec

Thank you for your interest in contributing! This document describes the
local development workflow.

## Prerequisites

- A stable Rust toolchain (MSRV 1.75; `rustup update stable`)
- Git

## Build and test

```sh
cargo build --workspace --all-features
cargo test  --workspace --all-features
```

Run doctests explicitly if you want them isolated:

```sh
cargo test --workspace --doc
```

## Lint and format

CI enforces zero warnings:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-features --all-targets -- -D warnings
```

## Docs

Documentation builds must be warning-free (CI treats doc warnings as errors):

```sh
cargo doc --workspace --all-features --no-deps
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
```

## Conventions

- Every public item must have documentation (`#![deny(missing_docs)]`).
- Prefer portable paths (`std::env::temp_dir()`) in tests/examples; no
  hardcoded Unix paths.
- Tokens must never derive `Clone`/`Copy`; delegation must remain explicit.
- Security-relevant changes require an update to `SECURITY.md`.

## Submitting

1. Fork, create a topic branch.
2. Ensure `fmt`, `clippy -D warnings`, and the full test suite pass.
3. Open a pull request with a clear description of the change.

## License

By contributing you agree your contributions are dual-licensed under
MIT OR Apache-2.0.
