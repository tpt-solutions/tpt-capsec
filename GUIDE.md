# tpt-capsec Guide: The Three Failure Modes

`tpt-capsec` turns authority misuse into **compile errors** wherever possible
and fast runtime failures otherwise. This guide walks through the three ways
an integration goes wrong and shows what each looks like.

All snippets are compile-fail examples (marked `// COMPILE ERROR`) — they
exist to show the *diagnostic*, not to be pasted in. Runnable counterparts
live in `crates/tpt-capsec/examples/`.

---

## 1. Use after move (linear tokens)

Tokens deliberately do not implement `Clone` or `Copy`. Handing a token to a
callee consumes it; the caller cannot keep using it.

```rust,ignore
use tpt_capsec::prelude::*;

let root = RootCapability::acquire();
let token = root.delegate_fs_read("/var/data");

serve_requests(token);
fs::read("/var/data/config.json", &token); // COMPILE ERROR:
// use of moved value: `token`
```

**Why this is good:** "who currently holds the authority" is tracked by the
borrow checker itself. There is no hidden copy of the capability floating
around after you thought you handed it off.

**Fix:** if you need the token again, delegate a *narrower* child instead of
giving away the parent:

```rust
let child = token.narrow("/var/data/config.json");
serve_requests(child); // parent `token` still usable here
```

The same rule applies to [`RootCapability`] itself — it is not `Clone`/`Copy`
either, so passing it by value to another component is an irrevocable
hand-off.

## 2. Wrong token type

Authority is typed. A function that needs write access must ask for an
`FsWriteToken`; a read token does not fit.

```rust,ignore
fn install_update(token: &FsReadToken<'_>) -> Result<(), CapsecError> {
    tpt_capsec::fs::write("/var/data/update.bin", payload, token) // COMPILE ERROR:
    // expected `&FsWriteToken`, found `&FsReadToken`
}
```

**Why this is good:** the function signature *is* its authority declaration.
Reviewing a PR means reading signatures: anything touching the network must
name a `NetConnectToken`/`NetBindToken` in its parameters, and there is no
way to sneak around it through the sandboxed wrappers.

**Fix:** delegate the correct kind from the root (or widen deliberately at a
single, reviewed call site):

```rust
let write = root.delegate_fs_write("/var/data");
install_update(&write)
```

## 3. Out-of-scope path / host / program

Scope checks happen at every wrapper call. A path outside the delegated
prefix — including anything smuggling `..` components — fails with
[`CapsecError::OutOfScope`] rather than silently succeeding:

```rust,ignore
let token = root.delegate_fs_read("/var/data");

// Ok: inside scope.
fs::read("/var/data/config.json", &token).unwrap();

// Err(OutOfScope): sibling directory.
fs::read("/etc/passwd", &token);

// Err(OutOfScope): traversal is normalized first, then rejected.
fs::read("/var/data/../../etc/passwd", &token);
```

Host scopes behave the same way (`api.example.com` permits its subdomains,
not lookalike hosts like `evil-example.com`), as do process allowlists
(exact names only).

**Fix:** narrow tokens to the smallest prefix that covers real use, and treat
any `OutOfScope` error at runtime as a bug report about your delegation
graph, not something to work around.

---

## Bonus failure mode: revoked mid-flight

With opt-in [`RevocationGroup`] revocation, every wrapper call re-checks a
shared atomic flag. After `group.revoke()`, all holders fail fast with
[`CapsecError::Revoked`]. See `examples/revoke_mid_flight.rs`.

## What tpt-capsec does NOT catch

It is not an OS sandbox: direct `std` calls, `unsafe` code, and hostile
dependencies bypass everything. Process **arguments** are not scoped by
tokens. Read `SECURITY.md` for the full threat model before relying on this
for untrusted input.
