# Starter skeleton for a `tpt-capsec` application

Copy this directory to bootstrap a new project:

```sh
cp -r template my-app && cd my-app
# edit Cargo.toml: set your package name
cargo run
```

The pattern in `src/main.rs`:

1. Call `RootCapability::acquire()` once, by convention, at the top of `main`.
2. Delegate the **narrowest** scope each component needs
   (`delegate_fs_read`, `delegate_fs_write`, `delegate_net_connect`,
   `delegate_net_bind`, `delegate_process_spawn`).
3. Perform privileged operations only through `tpt_capsec::{fs, net,
   process}` — never through raw `std`.
4. Optionally attach a `RevocationGroup` for runtime revocation across
   threads; see `examples/revoke_mid_flight.rs` in the repository.
