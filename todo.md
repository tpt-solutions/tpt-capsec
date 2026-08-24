# tpt-capsec — Project Todo

Tracking checklist for building `tpt-capsec`, a compile-time capability-based
security model for Rust. Enforcement is purely at the Rust type/borrow-checker
level (no OS syscall interception). Cross-platform: Linux, macOS, Windows.

> Status as of 2026-08-24: Phases 0–3 are implemented and validated
> (`cargo test`, `clippy -D warnings`, `fmt --check`, `doc -D warnings` all
> green on Windows; CI covers Linux/macOS/Windows). Phase 4 ships a std-only
> mapping layer with engine adapters deferred. The Phase 7 review bugs are
> fixed, the three runnable examples exist, and GUIDE.md is written.
> Remaining work is listed below unchecked (engine adapters, feature
> additions, automation, publishing).

## Phase 0: Project Setup & Repository Foundation — DONE

- [x] Initialize git repository, set default branch, add `.gitignore` for Rust
- [x] Do NOT commit `Cargo.lock` for this library workspace (ignored in `.gitignore`)
- [x] Create workspace root `Cargo.toml` with `[workspace]` members and `[workspace.package]` shared metadata (authors = "TPT Solutions", edition 2021, license MIT OR Apache-2.0, repository, homepage)
- [x] Confirm final crate boundaries for v0.1: `tpt-capsec-core`, `tpt-capsec`, `tpt-capsec-integrations`; **Decision:** no proc-macro crate in v0.1 (see Phase 3)
- [x] Scaffold `tpt-capsec-core` and `tpt-capsec` as library crates
- [x] Add `LICENSE-MIT` and `LICENSE-APACHE` at repo root, copyright holder "TPT Solutions"
- [x] **Decision:** SPDX license expression in Cargo.toml only; dual license files at root, no per-file headers
- [x] Write root `README.md`: pitch, quickstart snippet, badge placeholders, explicit scope disclaimer
- [x] Add `CONTRIBUTING.md` covering local build/test/lint workflow
- [x] Add `SECURITY.md` stating the threat model
- [x] MSRV policy: **1.75**, documented in README (no pinned toolchain file)
- [x] Lint config: rustfmt/clippy defaults are sufficient
- [x] Set up GitHub Actions CI: build+test matrix ubuntu/macos/windows × stable
- [x] Separate CI jobs for `clippy -D warnings` and `cargo fmt --check`
- [x] `cargo doc --workspace --all-features` CI job with `-D warnings`
- [x] Create `CHANGELOG.md` (Keep a Changelog format) with an "Unreleased" section
- [x] Commit initial scaffold once crates compile and CI is green

## Phase 1: Core Capability Primitives (`tpt-capsec-core`) — DONE

- [x] Two-layer enforcement model documented in crate-level docs
- [x] Sealed `Capability` marker trait (private `Sealed` supertrait)
- [x] Type-state token base pattern: private constructors, `PhantomData<&'a ()>` lifetime linkage
- [x] `RootCapability::acquire()` + all five `delegate_*` constructors
- [x] **Decision:** `RootCapability::acquire()` is a documentation-only convention (not a runtime singleton); rationale in `capability.rs` + SECURITY.md — global state adds no boundary over direct `std` access
- [x] Token structs generated via internal `macro_rules!`
- [x] Internal scope-check helpers `permits_path`, `permits_host`, `permits_program` exported for wrapper reuse
- [x] **Decision:** scope semantics = component-wise path prefix (fs), exact-or-dot-suffix host (connect), exact address (bind), exact-name allowlist (process); globs deferred
- [x] No `Clone`/`Copy` on tokens (linear-use discipline)
- [x] Redacted `Debug` impls (kind only, scope never printed)
- [x] Unit tests: acquisition, scoped delegation, helpers, revocation flags, Send/Sync assertions, redacted Debug
- [x] Doctests on `RootCapability` and delegation/narrowing methods
- [x] Module-level docs explaining the capability model and type-state pattern
- [x] Builds cleanly cross-platform in CI

## Phase 2: Sandboxed Standard Library Wrappers (`tpt-capsec`) — DONE

- [x] Re-exports core as `tpt_capsec::core`; `prelude` module
- [x] **Decision:** one-shot slurp/write fs API (read_dir eagerly collected)
- [x] Shared `CapsecError` enum (`OutOfScope`, `Revoked`, `Io`, `Other`)
- [x] `fs::read`, `fs::read_to_string` (`&FsReadToken`)
- [x] `fs::write`, `fs::remove`, `fs::remove_dir_all`, `fs::create_dir_all` (`&FsWriteToken`)
- [x] `fs::read_dir` (eagerly collected), `fs::metadata` (`&FsReadToken`)
- [x] `fs::rename` (one write token covering BOTH paths), `fs::copy` (dual-token read+write)
- [x] Per-call runtime scope check before delegating to `std::fs`
- [x] Tests per wrapper: in-scope success, out-of-scope rejection, io passthrough
- [x] Doctest reproducing the spec's config-read scenario
- [x] `net::tcp_connect(host, port, &NetConnectToken)`, `net::tcp_bind(addr, &NetBindToken)`
- [x] **Decision:** UDP deferred past v0.1
- [x] Runtime scope checks for net; loopback bind/connect tests; doctest
- [x] `process::spawn` / `process::output` with allowlist checks; portable test strategy via `git --version`
- [x] Integration suite mirroring the spec's `process_data` scenario
- [x] CryptoSignToken explicitly deferred to post-v0.1 (documented in crate docs)
- [x] Cross-platform behavior validated locally + CI matrix
- [x] Module docs for fs/net/process explaining scope-check semantics

## Phase 3: Delegation & Revocation Mechanics — DONE

- [x] Sub-delegation: `FsReadToken::{narrow, try_narrow}`, `FsWriteToken::narrow`, `NetConnectToken::narrow`, `ProcessSpawnToken::narrow`
- [x] Compile-time guarantee that child tokens cannot outlive their parent's borrow (`narrow(&self) -> Token<'a>`); negative cases covered by commented compile-fail examples in tests/docs (trybuild UI suite deferred, see below)
- [x] **Decision:** delegation is borrow-based (`&self` → child tied to parent borrow); tokens move linearly into callees (no Clone/Copy)
- [x] **Decision:** compile-time/drop-based revocation is primary; opt-in runtime revocation via cloneable `RevocationGroup` (`Arc<AtomicBool>`); wrappers return `CapsecError::Revoked`
- [x] Revocation flag checked by every wrapper call
- [x] trybuild UI tests: deferred post-v0.1 (borrow checker already rejects moved/outlived/wrong-token usage)
- [x] **Decision (macros go/no-go):** NO proc-macro crate for v0.1 — one declarative macro covers token boilerplate; revisit only if a user-defined derive is requested
- [x] Tokens are `Send + Sync` (plain data + shared atomic flag) — justified in docs for agent orchestration; cross-thread revocation tested with scoped threads
- [x] Tests for delegation chains (root → narrow → child) and mid-flight revocation
- [x] Rustdoc "Delegation & Revocation" content in core lib.rs + revocation module

## Phase 4: Plugin / AI Agent Integrations (`tpt-capsec-integrations`) — SCAFFOLDED

- [x] Scaffolded crate depending on `tpt-capsec`; `wasmtime` / `extism` feature flags reserved
- [x] WASI-to-token mapping implemented as std-only `SandboxPlan` (preopened dirs ← fs tokens, host allowlist ← connect token, bind addrs ← bind token)
- [ ] Direct wasmtime adapter configuring a restricted `WasiCtxBuilder` behind the `wasmtime` feature
- [ ] Direct extism manifest adapter behind the `extism` feature
- [x] **Decision:** one-way mapping only for v0.1 (tokens configure a sandbox; guest requests not surfaced back)
- [ ] Examples running wasm modules restricted to delegated authority
- [ ] Integration tests proving sandbox restriction (checked-in wasm module)
- [x] Version-compatibility/pinning policy documented in crate docs
- [ ] Confirm cross-platform CI coverage once engines are wired; feature-gate unsupported combos
- [x] Crate-level docs on purpose, features, rationale vs WASI-native capabilities

## Phase 5: Documentation, Examples & Cross-Cutting Polish

- [x] `#![deny(missing_docs)]` across all crates; gaps filled
- [x] README badges: CI/crates.io/docs.rs badges added *(crates.io and docs.rs will show unpublished until Phase 6 publish)*
- [x] Build `examples/` directory: spec's `process_data`, "delegate to a sandboxed plugin", "revoke mid-flight" *(crates/tpt-capsec/examples/{process_data,sandboxed_plugin,revoke_mid_flight}.rs)*
- [x] Every public function has a doctest or referenced example (audit again after Phase 4 adapters)
- [x] `[package.metadata.docs.rs] all-features = true` on every crate
- [ ] **Deferred:** mdBook guide — fast-follow
- [x] Explicit "Limitations & Threat Model" section in `SECURITY.md`
- [x] Portable temp paths in all doctests/examples/tests
- [x] Full workspace clippy -D warnings and rustfmt pass clean
- [x] `cargo doc --workspace --all-features -D warnings` clean
- [x] CI job runs `cargo test --workspace --all-features`
- [ ] **Deferred:** code coverage tooling — post-v0.1

## Phase 6: Release & Publishing (v0.1.0)

- [x] Pre-1.0 semver policy documented (0.x minor bumps may break API) — CHANGELOG header
- [ ] Publish order proposed and recorded: `tpt-capsec-core` → `tpt-capsec` → `tpt-capsec-integrations`; confirm before release
- [ ] Verify complete crates.io metadata (add `documentation` URL post-publish)
- [ ] Reserve/verify crate names on crates.io
- [ ] Run `cargo publish --dry-run` per crate in dependency order
- [ ] Finalize `CHANGELOG.md` "0.1.0" section
- [ ] **Recommendation recorded:** single workspace tag `v0.1.0`; confirm
- [ ] Publish crates to crates.io in dependency order
- [ ] Verify docs.rs builds post-publish
- [ ] GitHub Release with changelog notes
- [ ] Post-release smoke test from crates.io
- [ ] File "future work" backlog (glob scopes, UDP, crypto token module, deeper WASI preview2, mdBook)

## Phase 7: Platform Review Findings (2026-08-24)

> From a full-repo review (bugs, gaps, innovation ideas, adoption). See
> conversation/plan for full rationale per item.

### Bugs

- [x] **CRITICAL:** fix lexical path-traversal bypass in `permits_path`
  (`crates/tpt-capsec-core/src/scope.rs`) — a candidate like
  `/var/data/../../etc/passwd` passes the scope check because only the first
  `scope`-length components are compared; add a regression test for `..`
  inside a longer candidate *(fixed via lexical normalization of both paths;
  regression test `permits_path_rejects_parent_traversal`)*
- [x] Resolve `RootCapability: Clone + Copy` inconsistency vs. the no-Clone
  discipline on every derived token — either document why root is exempt or
  remove the derive *(derive removed; linear-use rationale documented on the type)*
- [x] Add a doc note on `NetBindToken` explaining why it has no `narrow`
  (exact-address scope has nothing to narrow to) so it reads as deliberate
- [x] Add a `SECURITY.md` callout that process tokens don't scope arguments
  (currently only a module comment in `process.rs`)

### Missing features / innovative additions

- [x] Glob-style path/host scopes — `*`, `?` and a lone `**` component are
  interpreted automatically whenever present in a delegated scope
  (`permits_path`/`permits_host` in `crates/tpt-capsec-core/src/scope.rs`);
  tests in `core_tests.rs`
- [x] Lint/scanner flagging direct `std::fs`/`std::net`/`std::process` calls
  in crates that also depend on `tpt-capsec` — new `tpt-capsec-audit`
  workspace crate (heuristic text scanner, CI-friendly exit codes)
- [x] `tracing`-based audit logging at the existing `authorize()`/
  `authorize_write()` choke points in each wrapper module — opt-in `tracing`
  feature emitting `debug` (grants) / `warn` (denials) on the `tpt_capsec`
  target via the new `audit` module
- [x] `CapabilitySet`/bundle type to group related tokens and reduce
  multi-token function signatures — `crates/tpt-capsec-core/src/bundle.rs`
- [x] `serde` (de)serialization for `SandboxPlan` — opt-in `serde` feature on
  `tpt-capsec-integrations`, with a JSON round-trip test
- [ ] Minimal proof-of-concept wasmtime example wiring `SandboxPlan` into a
  real restricted `WasiCtx` *(still deferred: requires pinning a wasmtime
  version and a long dependency build; feature flag remains reserved)*

### Automation

- [x] `cargo-semver-checks` CI job (supports the documented pre-1.0 semver
  policy) — added to `.github/workflows/ci.yml`
- [x] `cargo-deny` CI job for dependency/license/advisory checks — added to
  `.github/workflows/ci.yml`; add a `deny.toml` before first real run
- [ ] Release automation (`cargo-release` or `release-plz`) to replace the
  manual Phase 6 publish checklist
- [x] `cargo-fuzz` targets for `permits_path`/`permits_host`/`permits_program`
  — checked-in skeletons under `fuzz/` (excluded from the workspace; run with
  `cargo +nightly fuzz run <target>`)

### Adoption: examples, templates, onboarding

- [x] `examples/process_data.rs` — runnable version of the README/spec
  scenario (currently only a doctest) *(crates/tpt-capsec/examples/process_data.rs)*
- [x] `examples/sandboxed_plugin.rs` — `tpt-capsec-integrations::SandboxPlan`
  built end-to-end from tokens *(crates/tpt-capsec/examples/sandboxed_plugin.rs)*
- [x] `examples/revoke_mid_flight.rs` — `RevocationGroup` across a spawned
  thread *(crates/tpt-capsec/examples/revoke_mid_flight.rs)*
- [x] Minimal copy-paste starter skeleton (or `cargo generate` template) —
  `template/` directory (excluded from the workspace), see its README
- [x] README comparison table: `tpt-capsec` vs. raw `std` vs. WASM
  (`wasmtime`/`extism`) vs. OS sandboxing (seccomp/AppContainer)
- [x] `GUIDE.md` covering the three failure modes (use-after-move,
  wrong-token-type, out-of-scope-path) with compile-fail snippets, as a
  lighter-weight stand-in until mdBook lands
- [x] Activate README badges (CI/crates.io/docs.rs) *(crates.io/docs.rs will resolve once Phase 6 publish completes)*

