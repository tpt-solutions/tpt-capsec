# tpt-capsec — Project Todo

Tracking checklist for building `tpt-capsec`, a compile-time capability-based
security model for Rust. Enforcement is purely at the Rust type/borrow-checker
level (no OS syscall interception). Cross-platform: Linux, macOS, Windows.

## Phase 0: Project Setup & Repository Foundation

- [ ] Initialize git repository, set default branch, add `.gitignore` for Rust
- [ ] Decide whether to commit `Cargo.lock` for this library workspace (recommended: no, since all crates are libraries)
- [ ] Create workspace root `Cargo.toml` with `[workspace]` members and `[workspace.package]` shared metadata (authors = "TPT Solutions", edition, license, repository, homepage)
- [ ] Confirm final crate boundaries for v0.1: `tpt-capsec-core`, `tpt-capsec`, `tpt-capsec-macros` (conditional, see Phase 3), `tpt-capsec-integrations` (Phase 4 only)
- [ ] Scaffold `tpt-capsec-core` and `tpt-capsec` as library crates with placeholder `lib.rs`; leave macros/integrations crates unscaffolded until justified
- [ ] Add `LICENSE-MIT` and `LICENSE-APACHE` at repo root, copyright holder "TPT Solutions"
- [ ] Decide SPDX per-file license headers vs. `license = "MIT OR Apache-2.0"` in Cargo.toml only; document the choice
- [ ] Write root `README.md`: pitch, quickstart snippet, badge placeholders (CI, crates.io, docs.rs), explicit scope disclaimer (compile-time-only enforcement, not an OS sandbox)
- [ ] Add `CONTRIBUTING.md` covering local build/test/lint workflow
- [ ] Add `SECURITY.md` stating the threat model: no syscall interception, no protection against `unsafe`/raw `std` bypass/malicious build-scripts or deps
- [ ] Decide MSRV policy; add `rust-toolchain.toml` or document MSRV in README
- [ ] Add `rustfmt.toml` / `clippy.toml` if defaults are insufficient
- [ ] Set up GitHub Actions CI: build+test matrix on ubuntu-latest / macos-latest / windows-latest × stable Rust
- [ ] Add separate CI jobs for `clippy -D warnings` and `cargo fmt --check`
- [ ] Add `cargo doc --workspace` build-check CI job (warnings as errors)
- [ ] Create `CHANGELOG.md` (Keep a Changelog format) with an "Unreleased" section
- [ ] Commit initial scaffold once empty crates compile and CI is green

## Phase 1: Core Capability Primitives (`tpt-capsec-core`)

- [ ] Document the two-layer enforcement model in crate-level docs: type-level gate (must hold correctly-typed token reference) + runtime scope check inside each wrapper
- [ ] Define a sealed `Capability` marker trait so external crates cannot implement it or mint fake tokens
- [ ] Design the type-state token base pattern: private constructors, lifetime linkage (`PhantomData<&'a ...>`) to the delegating parent
- [ ] Implement `RootCapability` and `RootCapability::acquire()`
- [ ] **Decision:** is `RootCapability` a runtime-enforced process-wide singleton, or a documentation-only convention? Implement accordingly
- [ ] Design token scope representation (e.g. `FsReadToken<'a>` holding a path prefix, `NetConnectToken<'a>` holding a host pattern, `ProcessSpawnToken<'a>` holding a program allowlist)
- [ ] Implement token structs: `FsReadToken`, `FsWriteToken`, `NetConnectToken`, `NetBindToken`, `ProcessSpawnToken`
- [ ] Implement delegation constructors on `RootCapability`: `delegate_fs_read`, `delegate_fs_write`, `delegate_net_connect`, `delegate_net_bind`, `delegate_process_spawn`
- [ ] **Decision:** scope-matching semantics for v0.1 — exact path vs. prefix match (fs), exact vs. suffix match (net host), exact vs. allowlist (process). Recommend simple prefix/exact matching now; defer glob support
- [ ] Implement internal scope-check helpers (`permits_path`, `permits_host`, `permits_program`) for reuse by the wrapper crate
- [ ] **Decision:** `macro_rules!` now vs. a `tpt-capsec-macros` proc-macro crate later to reduce per-token boilerplate — prototype with `macro_rules!` first; revisit crate decision in Phase 3
- [ ] Do NOT derive `Clone`/`Copy` on token types; document why (linear-use discipline)
- [ ] Decide `Debug`/`Display` impls for tokens (avoid leaking sensitive scope data by default)
- [ ] Unit tests: successful acquisition, correctly-scoped delegation, scope-check helper correctness (match/mismatch/prefix cases)
- [ ] Unit tests for the chosen `RootCapability` singleton behavior
- [ ] Doctests on `RootCapability` and each `delegate_*` method
- [ ] Rustdoc: module-level docs explaining the capability model and type-state pattern
- [ ] Verify `tpt-capsec-core` builds cleanly on Linux/macOS/Windows in CI

## Phase 2: Sandboxed Standard Library Wrappers (`tpt-capsec`)

- [ ] Wire `tpt-capsec` to depend on and re-export `tpt-capsec-core`; build the `prelude` module
- [ ] **Decision:** one-shot slurp/write wrapper API (matches spec's `fs::read(path, &token)`) vs. handle-returning API — recommend one-shot for fs to avoid capability laundering via long-lived unchecked handles
- [ ] Define shared `CapsecError` enum (`OutOfScope`, `Io(std::io::Error)`, etc.) implementing `Error`/`Display`
- [ ] `fs` module: implement `fs::read`, `fs::read_to_string` (require `&FsReadToken`)
- [ ] `fs` module: implement `fs::write`, `fs::remove`, `fs::remove_dir_all`, `fs::create_dir_all` (require `&FsWriteToken`)
- [ ] `fs` module: implement `fs::read_dir` (eagerly collected, not a lifetime-escaping iterator) and `fs::metadata` (require `&FsReadToken`)
- [ ] `fs` module: implement `fs::rename` and `fs::copy` (first dual-token function: `&FsReadToken` + `&FsWriteToken`); decide whether both paths must satisfy the same token's scope
- [ ] Add per-call runtime scope check against the token's path prefix before delegating to `std::fs`; return `CapsecError::OutOfScope` on mismatch
- [ ] Unit tests per `fs` wrapper: in-scope success, out-of-scope rejection, `std::io` error passthrough
- [ ] Doctest reproducing the spec's `config.json` read example
- [ ] `net` module: implement `net::tcp_connect(host, port, &NetConnectToken)`, `net::tcp_bind(addr, &NetBindToken)`
- [ ] **Decision:** defer UDP support (`net::udp_bind`) past v0.1 unless needed
- [ ] Add runtime scope check (host allowlist/suffix match, bind-address match) for `net`
- [ ] Tests using loopback listeners; scope-mismatch rejection tests; doctest for `net::tcp_connect`
- [ ] `process` module: implement `process::spawn(program, args, &ProcessSpawnToken)` and `process::output(...)`
- [ ] Add runtime scope check against the token's allowed-program list
- [ ] **Decision:** portable cross-platform test command strategy (Windows `cmd /C echo` vs. Unix `echo`) for CI
- [ ] Doctest for `process::spawn`
- [ ] Add `tests/` integration suite exercising fs + net + process together, mirroring the spec's `process_data` scenario
- [ ] **Scope note:** `CryptoSignToken` is mentioned in the spec's overview but not the Phase 2 wrapper list — explicitly defer a crypto module to post-v0.1
- [ ] Verify cross-platform behavior in CI (path separators, loopback binding, process-spawn differences)
- [ ] Rustdoc: module docs for fs/net/process explaining scope-check semantics

## Phase 3: Delegation & Revocation Mechanics

- [ ] Implement narrower sub-delegation from a held token (e.g. a directory `FsReadToken` delegates a child `FsReadToken` scoped to one file) via `narrow()` / `delegate_subpath()`
- [ ] Compile-fail test confirming delegated child tokens cannot outlive their parent's lifetime
- [ ] **Decision:** move-based delegation (consumes the token) vs. borrow-based (`&self`) — support both where appropriate and document which methods take which
- [ ] **Decision:** is revocation purely compile-time/drop-based for v0.1, or does an opt-in runtime revocation flag (e.g. `Arc<AtomicBool>` "live" check) cover tokens delegated across threads/tasks? Record rationale
- [ ] If runtime revocation chosen: implement the live-flag mechanism, a `revoke()` method, and a `CapsecError::Revoked` check in every wrapper call
- [ ] Add `trybuild` compile-fail tests: token used after move; child token outliving parent; wrong token type substituted for a required capability
- [ ] Wire `trybuild` UI test fixtures into CI
- [ ] **Decision (macros crate go/no-go):** reassess whether `tpt-capsec-macros` is justified now (boilerplate reduction, or `#[derive(Capability)]` for user-defined token types)
- [ ] If justified: scaffold `tpt-capsec-macros`, implement the macro(s), add `trybuild` tests, wire in as an optional feature
- [ ] If not justified: document the decision and leave the crate out of workspace members for v0.1
- [ ] **Decision:** are tokens `Send`/`Sync`? Needed for the AI-agent-orchestration use case (delegating into spawned threads/async tasks) — implement and justify, or explicitly leave `!Send`/`!Sync` with rationale
- [ ] Tests for delegation chains (root → app → plugin narrowing) and revocation behavior (including cross-thread, if implemented)
- [ ] Rustdoc: dedicated "Delegation & Revocation" guide explaining the linear-type emulation model and its explicit limits

## Phase 4: Plugin / AI Agent Integrations (`tpt-capsec-integrations`)

- [ ] Scaffold `tpt-capsec-integrations` depending on `tpt-capsec`; gate `wasmtime` and `extism` support behind separate feature flags
- [ ] Design the WASI-to-token mapping: preopened directories → `FsReadToken`/`FsWriteToken`; socket permissions → `NetConnectToken`/`NetBindToken`
- [ ] Implement a wasmtime adapter configuring a `WasiCtx`/`WasiCtxBuilder` restricted to exactly the authorities represented by the passed-in tokens
- [ ] Implement an extism adapter mapping manifest allowed-path/allowed-host config from tpt-capsec tokens
- [ ] **Decision:** one-way mapping only (tokens configure a sandbox for a guest module) vs. a reverse adapter (guest requests surfaced as gated Rust host functions) — recommend one-way for v0.1
- [ ] Add `examples/`: running a wasm module via wasmtime restricted to delegated fs/net authority; running an extism plugin similarly
- [ ] Integration tests proving the sandbox actually restricts wasmtime's WASI access to the delegated scope (using a small checked-in wasm module)
- [ ] Document version-compatibility/pinning policy for the fast-moving `wasmtime`/`extism` dependencies
- [ ] Confirm cross-platform CI coverage; feature-gate/skip anything unsupported on a given OS
- [ ] Rustdoc: crate-level docs on purpose, feature flags, and rationale vs. using WASI capabilities directly

## Phase 5: Documentation, Examples & Cross-Cutting Polish

- [ ] Enable `#![deny(missing_docs)]` (or warn) on public items across all crates; fill gaps
- [ ] Add README badges (crates.io, docs.rs, CI, license) to each published crate
- [ ] Build `examples/` in `tpt-capsec`: the spec's `process_data` example, "delegate to a sandboxed plugin", "revoke mid-flight"
- [ ] Ensure every public function has a doctest or a referenced example
- [ ] Configure `[package.metadata.docs.rs]` (e.g. `all-features = true`) for each published crate
- [ ] **Decision:** mdBook guide in scope for v0.1? If yes, scaffold `book/` (Threat Model, Getting Started, Core Concepts, Delegation & Revocation, Wrapping fs/net/process, Plugin Integrations, Limitations/FAQ); if deferred, note as fast-follow
- [ ] Write an explicit "Limitations & Threat Model" section feeding `SECURITY.md`: no protection against `unsafe`/raw `std` bypass/malicious deps; not a replacement for OS-level sandboxing — recommend pairing with Phase 4 integrations for untrusted-code execution
- [ ] Cross-platform doc pass: ensure all doctests/examples use portable temp paths, not hardcoded Unix paths
- [ ] Full workspace `clippy -D warnings` and `rustfmt` pass; fix all findings
- [ ] Run `cargo doc --workspace --all-features` and fix all warnings/broken intra-doc links
- [ ] Add a full `cargo test --workspace --all-features` CI job now that all crates exist
- [ ] **Decision:** add code coverage tooling (`cargo-llvm-cov`/`tarpaulin`) to CI, or defer

## Phase 6: Release & Publishing (v0.1.0)

- [ ] Decide and document pre-1.0 semver policy (0.x minor bumps may break API)
- [ ] Decide publish order given inter-crate deps: `tpt-capsec-core` → (`tpt-capsec-macros` if it exists) → `tpt-capsec` → `tpt-capsec-integrations`
- [ ] Verify complete crates.io metadata on every crate (description, license, repository, homepage, documentation, keywords ≤5, categories, readme)
- [ ] Reserve/verify crate name availability on crates.io for all crates being published
- [ ] Run `cargo publish --dry-run` per crate in dependency order; fix packaging issues
- [ ] Finalize `CHANGELOG.md` "0.1.0" section summarizing all phases' user-facing functionality
- [ ] **Decision:** tagging convention — single workspace tag (`v0.1.0`) vs. per-crate tags
- [ ] Publish crates to crates.io in dependency order
- [ ] Verify docs.rs successfully builds documentation for all published crates post-publish
- [ ] Create a GitHub Release with changelog notes
- [ ] Post-release smoke test: fresh throwaway project depending on `tpt-capsec` from crates.io, reproducing the spec's example end-to-end
- [ ] File a "future work" backlog (glob-based scope matching, UDP support, crypto token module, deeper WASI preview2 integration, mdBook if deferred) to close out v0.1 cleanly
