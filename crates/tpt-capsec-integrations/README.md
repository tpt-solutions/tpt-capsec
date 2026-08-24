# tpt-capsec-integrations

[![crates.io](https://img.shields.io/crates/v/tpt-capsec-integrations.svg)](https://crates.io/crates/tpt-capsec-integrations)
[![docs.rs](https://docs.rs/tpt-capsec-integrations/badge.svg)](https://docs.rs/tpt-capsec-integrations)

Maps delegated [`tpt-capsec`](../tpt-capsec) capability tokens onto the
permission vocabulary used by plugin/WASI-style sandboxes (`wasmtime`,
`extism`, or an equivalent runtime), so a host application can derive a
guest module's sandbox configuration from the same authority model it uses
internally.

## Why this crate exists

`tpt-capsec` constrains *trusted* Rust code by construction — the type
system and a runtime scope check. To run genuinely **untrusted** code you
need a real isolation boundary, such as a WebAssembly runtime with WASI-
style permissions or an OS-level sandbox. This crate bridges the two: it
turns tokens your host already delegated into a plan you feed to that real
boundary, instead of maintaining a second, separate permission
configuration by hand.

## `SandboxPlan`

The core type. Build one from tokens with the `grant_*` builder methods
(each returns `Err(CapsecError::Revoked)` if the token's revocation group
has fired):

| Method | From token | Sandbox concept |
|---|---|---|
| `grant_fs_read` | `&FsReadToken` | preopened directory, read-only |
| `grant_fs_write` | `&FsWriteToken` | preopened directory, read-write |
| `grant_net_connect` | `&NetConnectToken` | outbound host allowlist |
| `grant_net_bind` | `&NetBindToken` | socket-address bind permit |

```rust
use tpt_capsec::prelude::*;
use tpt_capsec_integrations::SandboxPlan;

let root = RootCapability::acquire();
let fs = root.delegate_fs_read("data");
let net = root.delegate_net_connect("api.example.com");

let mut plan = SandboxPlan::new();
plan.grant_fs_read(&fs)?.grant_net_connect(&net)?;
// Feed `plan` into WasiCtxBuilder::preopened_dir, an extism manifest, etc.
# Ok::<(), tpt_capsec::CapsecError>(())
```

See [`examples/sandboxed_plugin.rs`](../tpt-capsec/examples/sandboxed_plugin.rs)
in the `tpt-capsec` crate for a complete, runnable walkthrough.

## One-way mapping (v0.1 decision)

The adapter is **one-way only**: tokens configure a sandbox for a guest
module. Guest-initiated requests are not surfaced back as gated Rust host
functions — that reverse adapter needs per-engine callback plumbing and is
planned post-v0.1.

## Features

- `serde` — (de)serializes `SandboxPlan` and `PreopenedDir`, for debugging
  or handing a plan to an engine configured out-of-process.
- `wasmtime` — a direct adapter (`wasmtime::apply`) that applies a
  `SandboxPlan` onto a wasmtime `WasiCtxBuilder`: read/write `Fs*Token`
  scopes become preopened directories with the matching `DirPerms`/
  `FilePerms`. Preview1 WASI has no outbound-TCP-connect or bind support,
  so `NetConnectToken`/`NetBindToken` grants can't be expressed there —
  `apply` returns them back as `UnenforcedGrants` instead of silently
  dropping them; enforce those at another layer (embedding-level deny, an
  OS sandbox) or don't delegate them to untrusted guests. Pinned to
  `wasmtime-wasi = "=24"` per the version-compatibility policy below.
- `extism` — **reserved, not yet implemented.** The flag exists so the
  public API stays stable once a manifest adapter lands; enabling it today
  pulls in nothing extra. Until then, consume `SandboxPlan`'s output and
  wire it into extism manually.

## Version-compatibility policy

When engine adapters ship, each release will document the exact supported
engine versions in the changelog, with conservative (`=MAJOR.MINOR`) semver
requirements for `wasmtime` until it reaches 1.0 stability.

## See also

- [`tpt-capsec-core`](../tpt-capsec-core) — the token/capability primitives
  this crate consumes.
- [`tpt-capsec`](../tpt-capsec) — the sandboxed wrapper crate most hosts
  delegate tokens from.
- [`tpt-capsec-audit`](../tpt-capsec-audit) — scans for code bypassing the
  token model.
- Root [README](../../README.md), [SECURITY.md](../../SECURITY.md) for the
  full threat model.
- [CHANGELOG](CHANGELOG.md) for this crate's release history.

## License

Dual-licensed under [MIT](../../LICENSE-MIT) or
[Apache-2.0](../../LICENSE-APACHE), at your option.
