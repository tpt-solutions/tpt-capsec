# tpt-capsec-core

[![crates.io](https://img.shields.io/crates/v/tpt-capsec-core.svg)](https://crates.io/crates/tpt-capsec-core)
[![docs.rs](https://docs.rs/tpt-capsec-core/badge.svg)](https://docs.rs/tpt-capsec-core)

Core capability primitives for [`tpt-capsec`](../tpt-capsec) — the sealed
`Capability` trait, `RootCapability`, the five scoped token types, and the
scope-matching helpers the wrapper crate builds on.

This crate has **zero dependencies** and is the one place the type-state
pattern and scope semantics are defined; you normally depend on the
higher-level [`tpt-capsec`](https://crates.io/crates/tpt-capsec) crate
instead unless you're building your own sandboxed wrapper layer on top of
these primitives.

## What's in here

- **`RootCapability`** — the root of trust for a process. `acquire()` is a
  documentation-only convention (not a runtime singleton); see
  [SECURITY.md](../../SECURITY.md) for why.
- **Token types** — `FsReadToken`, `FsWriteToken`, `NetConnectToken`,
  `NetBindToken`, `ProcessSpawnToken`. Each is:
  - sealed (only this crate can construct one — no forging tokens),
  - lifetime-linked to the parent it was delegated from,
  - **not** `Clone`/`Copy` (moving a token consumes it — "use after
    hand-off" is a compile error),
  - `Debug`-redacted (prints the token kind only, never the scope, so
    accidental logging can't leak your security topology).
- **`narrow` / `try_narrow`** — delegate a tighter sub-scope from an existing
  token without going back to the root.
- **`RevocationGroup`** — opt-in cooperative runtime revocation for tokens
  that cross thread/task boundaries, where the borrow checker can no longer
  see the "logical" end of a grant.
- **`CapabilitySet`** — a bundle holding one token per authority kind, for
  functions that need several without a five-parameter signature.
- **`permits_path` / `permits_host` / `permits_program`** — the pure
  scope-matching functions, exported for reuse by wrapper crates.

## Scope-matching semantics

- **Filesystem** — lexical, component-wise path-prefix matching (a
  string-prefix lookalike like `/var/database` does **not** match a
  `/var/data` scope); optional glob wildcards (`*`, `?`, one `**`) are
  supported when the scope contains them.
- **Network connect** — exact host or dot-suffix subdomain match, ASCII
  case-insensitive; bind scopes require an exact socket address.
- **Process** — exact-name allowlist; arguments are not scoped.

See the crate's rustdoc (`cargo doc -p tpt-capsec-core --open`) for the full
model and doctested examples of delegation, narrowing, and revocation.

## Example

```rust
use tpt_capsec_core::RootCapability;

let root = RootCapability::acquire();
let read = root.delegate_fs_read("/var/data");
let child = read.narrow("/var/data/config.json");
assert!(child.permits_path(std::path::Path::new("/var/data/config.json")));
```

## See also

- [`tpt-capsec`](../tpt-capsec) — sandboxed `std::fs`/`std::net`/
  `std::process` wrappers built on these tokens.
- [`tpt-capsec-integrations`](../tpt-capsec-integrations) — maps tokens onto
  plugin/WASI-style sandbox configuration.
- [`tpt-capsec-audit`](../tpt-capsec-audit) — scans for code that bypasses
  the token model by calling `std` directly.
- Root [README](../../README.md), [SECURITY.md](../../SECURITY.md) for the
  full threat model.
- [CHANGELOG](CHANGELOG.md) for this crate's release history.

## License

Dual-licensed under [MIT](../../LICENSE-MIT) or
[Apache-2.0](../../LICENSE-APACHE), at your option.
