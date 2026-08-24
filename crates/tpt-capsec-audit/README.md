# tpt-capsec-audit

[![crates.io](https://img.shields.io/crates/v/tpt-capsec-audit.svg)](https://crates.io/crates/tpt-capsec-audit)
[![docs.rs](https://docs.rs/tpt-capsec-audit/badge.svg)](https://docs.rs/tpt-capsec-audit)

A heuristic source scanner that flags direct `std::fs` / `std::net` /
`std::process` usage in crates that also depend on
[`tpt-capsec`](../tpt-capsec). It exists because nothing about the type
system stops a crate that has adopted the capability model from quietly
calling `std` directly and bypassing every scope check — this crate turns
that gap into something you can catch in review or gate in CI.

## What it checks

For every `Cargo.toml` under the scanned root whose manifest text mentions
`tpt-capsec` (any workspace crate), `tpt-capsec-audit` walks that package's
`.rs` files looking for direct-`std` patterns: `std::fs::`, `std::net::`,
`std::process::`, and the corresponding `use std::{fs,net,process}` forms.
This workspace's own implementation crates (`tpt-capsec`, `tpt-capsec-core`,
`tpt-capsec-audit` itself) are exempt — they are the sanctioned bridge to
`std` that everything else should route through instead of calling it
directly.

## Limitations

This is a **heuristic text scanner, not a rustc plugin or lint**. It cannot
see through macro-generated code, re-exported/aliased import paths, or
`std` calls reached indirectly. Treat every finding as a review hint worth
a second look, not proof of a violation — and treat a clean run as
"nothing obvious found," not a formal guarantee.

## CLI usage

```sh
tpt-capsec-audit [PATH]   # defaults to the current directory
```

Exits `0` with a summary line when nothing is found, `1` when any finding is
reported (so it can gate CI), or `2` if `PATH` isn't a directory. Example
output:

```text
src/plugin.rs:12: direct std::fs usage: std::fs::read_to_string(path)?;

1 finding(s): 1 fs
```

## As a library

The scanning logic is also exported for programmatic use (custom tooling,
a `build.rs` check, etc.):

```rust
use std::path::Path;

let findings = tpt_capsec_audit::scan(Path::new("."));
print!("{}", tpt_capsec_audit::format_report(&findings));
```

## See also

- [`tpt-capsec`](../tpt-capsec) / [`tpt-capsec-core`](../tpt-capsec-core) —
  the capability model this scanner checks adoption of.
- [`tpt-capsec-integrations`](../tpt-capsec-integrations) — the sandbox
  mapping layer for genuinely untrusted code (`tpt-capsec-audit` only
  covers *trusted* code that should be using the wrappers).
- Root [README](../../README.md), [SECURITY.md](../../SECURITY.md) for the
  full threat model.
- [CHANGELOG](CHANGELOG.md) for this crate's release history.

## License

Dual-licensed under [MIT](../../LICENSE-MIT) or
[Apache-2.0](../../LICENSE-APACHE), at your option.
