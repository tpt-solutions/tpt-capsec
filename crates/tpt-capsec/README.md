# tpt-capsec

[![crates.io](https://img.shields.io/crates/v/tpt-capsec.svg)](https://crates.io/crates/tpt-capsec)
[![docs.rs](https://docs.rs/tpt-capsec/badge.svg)](https://docs.rs/tpt-capsec)

Sandboxed, capability-gated wrappers around `std::fs`, `std::net` (TCP), and
`std::process` — the crate most users of
[`tpt-capsec`](https://github.com/tpt-solutions/tpt-capsec) depend on
directly. Re-exports [`tpt-capsec-core`](../tpt-capsec-core) as `core` and a
`prelude` module for a one-line import.

## What's in here

| Module | Requires | Operations |
|---|---|---|
| [`fs`](src/fs.rs) | `&FsReadToken` / `&FsWriteToken` | `read`, `read_to_string`, `read_dir`, `metadata`, `write`, `remove`, `remove_dir_all`, `create_dir_all`, `rename`, `copy` |
| [`net`](src/net.rs) | `&NetConnectToken` / `&NetBindToken` | `tcp_connect`, `tcp_bind` (UDP deferred past v0.1) |
| [`process`](src/process.rs) | `&ProcessSpawnToken` | `spawn`, `output` |

Every wrapper, in order:

1. checks the token's opt-in revocation flag (`CapsecError::Revoked`),
2. checks the requested path/host/program against the token's delegated
   scope (`CapsecError::OutOfScope`),
3. delegates to the real `std` operation, passing its `io::Error` through
   unchanged.

The `fs` API is deliberately **one-shot** (slurp/write, eagerly-collected
`read_dir`): wrappers return owned data rather than long-lived handles, so a
`File` can't outlive the scope check that authorized it.

## Features

- `tracing` (optional) — emits a `debug` event on grant and a `warn` event
  on denial from every authorization choke point, on the `tpt_capsec`
  tracing target. Gives you a security audit trail for free; enable with:

  ```toml
  tpt-capsec = { version = "0.1", features = ["tracing"] }
  ```

## Example

```rust
use tpt_capsec::prelude::*;
use tpt_capsec::fs;

fn process_data(fs: FsReadToken<'_>) -> Result<(), tpt_capsec::CapsecError> {
    let data = fs::read(fs.scope().join("config.json"), &fs)?;
    // fs::remove(...) would be a COMPILE ERROR here: needs FsWriteToken.
    Ok(())
}

let root = RootCapability::acquire();
let dir = std::env::temp_dir().join("tpt-capsec-readme");
std::fs::create_dir_all(&dir)?;
std::fs::write(dir.join("config.json"), b"{}")?;

process_data(root.delegate_fs_read(&dir))?;
# Ok::<(), tpt_capsec::CapsecError>(())
```

See [`examples/`](examples) for three complete, runnable programs:
[`process_data.rs`](examples/process_data.rs) (the scenario above),
[`sandboxed_plugin.rs`](examples/sandboxed_plugin.rs) (building a
`SandboxPlan` for a plugin host), and
[`revoke_mid_flight.rs`](examples/revoke_mid_flight.rs) (cross-thread
`RevocationGroup` revocation). Run one with:

```sh
cargo run -p tpt-capsec --example process_data
```

## See also

- [`tpt-capsec-core`](../tpt-capsec-core) — the underlying token/capability
  primitives this crate wraps.
- [`tpt-capsec-integrations`](../tpt-capsec-integrations) — maps these
  tokens onto plugin/WASI-style sandboxes.
- [`tpt-capsec-audit`](../tpt-capsec-audit) — scans for code bypassing this
  crate's wrappers via direct `std` calls.
- Root [README](../../README.md), [SECURITY.md](../../SECURITY.md),
  [GUIDE.md](../../GUIDE.md) for the full model and threat model.
- [CHANGELOG](CHANGELOG.md) for this crate's release history.

## License

Dual-licensed under [MIT](../../LICENSE-MIT) or
[Apache-2.0](../../LICENSE-APACHE), at your option.
