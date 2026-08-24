# tpt-capsec

Compile-time capability-based security for Rust.

`tpt-capsec` is a native, ergonomic capability model that removes *ambient
authority* from your code: a function can only touch the filesystem, the
network, or spawn processes if its signature says so — enforced by the Rust
type system and borrow checker, with an additional runtime scope check in
every wrapper call.

> **Scope disclaimer:** enforcement is purely at the Rust type/borrow-checker
> level plus in-process scope checks. This is **not** an OS sandbox: there is
> no syscall interception and no protection against `unsafe`, raw `std`
> bypass, or malicious build scripts/dependencies. See
> [SECURITY.md](SECURITY.md) for the full threat model.

## Quickstart

```rust
use tpt_capsec::prelude::*;
use tpt_capsec::fs;

fn main() -> Result<(), tpt_capsec::CapsecError> {
    // The main function holds the root authority.
    let root = RootCapability::acquire();

    // Delegate specific, scoped permissions to a worker.
    let data_dir = std::env::temp_dir().join("tpt-capsec-demo");
    let fs_token = root.delegate_fs_read(&data_dir);
    let net_token = root.delegate_net_connect("api.example.com");

    process_data(fs_token, net_token)
}

// The signature explicitly declares required authority.
fn process_data(fs: FsReadToken<'_>, _net: NetConnectToken<'_>)
    -> Result<(), tpt_capsec::CapsecError>
{
    let config = std::env::temp_dir().join("tpt-capsec-demo").join("config.json");
    // OK: within the token's path scope.
    let _data = fs::read(&config, &fs)?;
    // COMPILE ERROR: requires an FsWriteToken.
    // tpt_capsec::fs::remove(&config, &fs);
    Ok(())
}
```

## Crates

| Crate | Purpose |
|---|---|
| [`tpt-capsec-core`](crates/tpt-capsec-core) | Sealed capability trait, root capability, scoped tokens, scope checks |
| [`tpt-capsec`](crates/tpt-capsec) | Sandboxed wrappers for `std::fs`, TCP networking and process spawning |
| [`tpt-capsec-integrations`](crates/tpt-capsec-integrations) | Mapping token authority onto plugin/WASI-style sandboxes |

## How it works

Two layers of enforcement:

1. **Type-level gate** — every wrapper function requires a correctly-typed,
   lifetime-bound token reference (`&FsReadToken`, `&NetConnectToken`, ...).
   Tokens cannot be constructed outside this crate (sealed constructors) and
   cannot outlive the parent capability they were delegated from.
2. **Runtime scope check** — each wrapper validates the requested path/host/
   program against the token's delegated scope and fails fast with
   `CapsecError::OutOfScope` on mismatch.

Tokens do not implement `Clone`/`Copy`: delegation is explicit, which emulates
linear-type discipline ("use after move" is a compile error).

## Documentation

- [CONTRIBUTING.md](CONTRIBUTING.md) — build/test/lint workflow
- [SECURITY.md](SECURITY.md) — threat model and limitations
- [CHANGELOG.md](CHANGELOG.md) — release notes

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE),
at your option. Copyright TPT Solutions.

<!-- Badges: CI / crates.io / docs.rs placeholders
[![CI](https://github.com/tpt-solutions/tpt-capsec/actions/workflows/ci.yml/badge.svg)]()
[![crates.io](https://img.shields.io/crates/v/tpt-capsec.svg)]()
[![docs.rs](https://docs.rs/tpt-capsec/badge.svg)]()
-->

## MSRV

The minimum supported Rust version is **1.75**.
