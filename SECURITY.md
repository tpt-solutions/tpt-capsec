# Security Policy

## What tpt-capsec IS

`tpt-capsec` is a **compile-time discipline layer** on top of the Rust type
system, plus per-call in-process scope checks. It prevents *accidental*
ambient-authority use by well-typed safe code: functions that lack a
capability token cannot compile calls to the sandboxed wrappers, and wrapper
calls outside a token's delegated scope fail at runtime.

## What tpt-capsec is NOT

It is **not** an operating-system-level sandbox. Specifically, it provides:

- **No syscall interception.** Wrappers call plain `std::fs` / `std::net` /
  `std::process`. The kernel sees ordinary process activity.
- **No protection against `unsafe`.** Code marked `unsafe` can construct raw
  file/socket handles and bypass every wrapper.
- **No protection against direct `std` use.** Any crate in your dependency
  graph can call `std::fs::remove_dir_all` directly; nothing intercepts it.
- **No protection against malicious build scripts or dependencies**
  ([supply-chain attacks](https://github.com/rust-lang/rfcs/blob/master/text/3502-supply-chain-infra.md)).
- **No memory-safety guarantees beyond what Rust already provides.**

## Recommended pairing

For executing **untrusted code**, pair `tpt-capsec` with a true isolation
boundary such as a Wasm runtime (see `tpt-capsec-integrations`) or an OS-level
sandbox (seccomp, AppContainer, sandbox-exec, containers). `tpt-capsec` gives
you structured, auditable authority delegation between *trusted* components;
the Wasm/OS boundary constrains the untrusted payload itself.

## Scope-matching semantics

- Filesystem scopes match lexically by path component prefix (no symlink
  resolution at check time; the underlying OS may still follow symlinks).
- Network connect scopes match exact host names or subdomains via dot-suffix;
  bind scopes match exact socket addresses.
- Process scopes are exact program-name allowlists.

Glob-based matching: path scopes may contain `*`, `?`, and a lone `**`
component; host scopes may contain `*`/`?` wildcards. Non-glob scopes keep
the exact/prefix semantics above.

## Process arguments are not scoped

`ProcessSpawnToken` checks only the **program name** against its allowlist.
Arguments, environment variables, and working directory passed to
`process::spawn` / `process::output` are forwarded verbatim to
`std::process::Command` and are *not* validated by tpt-capsec. A permitted
program invoked with hostile arguments can therefore act far outside your
intended scope (e.g. `git` invoked with a config-injection argument). Keep
allowlists minimal, prefer argument-free invocations, and treat argument
construction as trusted-code responsibility.

## Reporting vulnerabilities

Open a private security advisory via GitHub ("Report a vulnerability") or
contact **security@tpt.solutions**. Do not open public issues for
vulnerability reports.
