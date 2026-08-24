//! Unit tests for `tpt-capsec-core` primitives.

use std::net::SocketAddr;
use std::path::Path;

use tpt_capsec_core::{
    permits_host, permits_path, permits_program, FsReadToken, FsWriteToken, NetBindToken,
    NetConnectToken, ProcessSpawnToken, RevocationGroup, RootCapability,
};

#[test]
fn delegation_produces_correct_scopes() {
    let root = RootCapability::acquire();
    let read = root.delegate_fs_read("/var/data");
    let write = root.delegate_fs_write("/var/data/out");
    let connect = root.delegate_net_connect("Api.Example.com");
    let bind = root.delegate_net_bind(SocketAddr::from(([127, 0, 0, 1], 8080)));
    let spawn = root.delegate_process_spawn(["git", "cargo"]);

    assert_eq!(read.scope(), std::path::Path::new("/var/data"));
    assert_eq!(write.scope(), std::path::Path::new("/var/data/out"));
    assert_eq!(connect.scope(), "api.example.com");
    assert_eq!(bind.scope(), &SocketAddr::from(([127, 0, 0, 1], 8080)));
    assert_eq!(spawn.scope(), &["git".to_string(), "cargo".to_string()]);
}

#[test]
fn permits_path_component_prefix_semantics() {
    assert!(permits_path(
        std::path::Path::new("/var/data"),
        std::path::Path::new("/var/data")
    ));
    assert!(permits_path(
        std::path::Path::new("/var/data"),
        std::path::Path::new("/var/data/config.json")
    ));
    // String-prefix lookalike must NOT match.
    assert!(!permits_path(
        std::path::Path::new("/var/data"),
        std::path::Path::new("/var/database")
    ));
    // Sibling directory must not match.
    assert!(!permits_path(
        std::path::Path::new("/var/data"),
        std::path::Path::new("/var/dat/x")
    ));
    // Parent escape must not match.
    assert!(!permits_path(
        std::path::Path::new("/var/data/sub"),
        std::path::Path::new("/var/data")
    ));
}

#[test]
fn permits_host_exact_and_suffix() {
    assert!(permits_host("example.com", "example.com"));
    assert!(permits_host("example.com", "api.example.com"));
    assert!(permits_host("example.com", "a.b.EXAMPLE.COM"));
    assert!(!permits_host("example.com", "notexample.com"));
    assert!(!permits_host("api.example.com", "example.com"));
    assert!(!permits_host("example.com", "evil-example.com"));
}

#[test]
fn permits_program_exact_allowlist() {
    let list = ["git".to_string(), "cargo".to_string()];
    assert!(permits_program(list.iter(), "git"));
    assert!(!permits_program(list.iter(), "git-lfs"));
    assert!(!permits_program(list.iter(), "rm"));
}

#[test]
fn token_scope_check_methods() {
    let root = RootCapability::acquire();
    let read = root.delegate_fs_read("/var/data");
    assert!(read.permits_path(Path::new("/var/data/a/b")));
    assert!(!read.permits_path(Path::new("/var/other")));

    let connect = root.delegate_net_connect("example.com");
    assert!(connect.permits_host("sub.example.com"));
    assert!(!connect.permits_host("example.org"));

    let bind = root.delegate_net_bind(SocketAddr::from(([10, 0, 0, 1], 9090)));
    assert!(bind.permits_addr(SocketAddr::from(([10, 0, 0, 1], 9090))));
    assert!(!bind.permits_addr(SocketAddr::from(([10, 0, 0, 1], 9091))));

    let spawn = root.delegate_process_spawn(["echo"]);
    assert!(spawn.permits_program("echo"));
    assert!(!spawn.permits_program("sh"));
}

#[test]
fn narrowing_restricts_scope() {
    let root = RootCapability::acquire();
    let read = root.delegate_fs_read("/var/data");
    let child = read.narrow("/var/data/config.json");
    assert_eq!(child.scope(), std::path::Path::new("/var/data/config.json"));
    assert!(read.permits_path(Path::new("/var/data/other"))); // parent unaffected

    assert!(read.try_narrow("/etc/passwd").is_none());

    let connect = root.delegate_net_connect("example.com");
    let sub = connect.narrow("api.example.com");
    assert_eq!(sub.scope(), "api.example.com");

    let spawn = root.delegate_process_spawn(["git", "cargo"]);
    let narrowed = spawn.narrow(["git"]);
    assert!(narrowed.permits_program("git"));
    assert!(!narrowed.permits_program("cargo"));
}

#[test]
fn revocation_group_flags_tokens() {
    let root = RootCapability::acquire();
    let group = RevocationGroup::new();
    let read = root.delegate_fs_read("/var/data").with_revocation(&group);

    assert!(!read.is_revoked());
    assert!(!group.is_revoked());
    group.revoke();
    assert!(read.is_revoked());
    assert!(group.is_revoked());
}

#[test]
fn revocation_survives_narrowing() {
    let root = RootCapability::acquire();
    let group = RevocationGroup::new();
    let read = root.delegate_fs_read("/var/data").with_revocation(&group);
    let child = read.narrow("/var/data/config.json");
    group.revoke();
    assert!(child.is_revoked());
}

#[test]
fn non_revocable_tokens_report_live() {
    let root = RootCapability::acquire();
    let read = root.delegate_fs_read("/var/data");
    assert!(!read.is_revoked());
}

#[test]
fn tokens_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<FsReadToken<'static>>();
    assert_send_sync::<FsWriteToken<'static>>();
    assert_send_sync::<NetConnectToken<'static>>();
    assert_send_sync::<NetBindToken<'static>>();
    assert_send_sync::<ProcessSpawnToken<'static>>();
}

#[test]
fn debug_impls_are_redacted() {
    let root = RootCapability::acquire();
    let read = root.delegate_fs_read("/var/data/secret");
    let rendered = format!("{read:?}");
    assert_eq!(rendered, "FsReadToken { <redacted> }");
    assert!(!rendered.contains("secret"));
}
