//! Integration tests for the sandboxed `net` and `process` wrappers, plus
//! the end-to-end scenario from the design spec.

use std::net::{Ipv4Addr, SocketAddr};

use tpt_capsec::prelude::*;
use tpt_capsec::{net, process, CapsecError};

#[test]
fn net_bind_requires_exact_address() {
    let root = RootCapability::acquire();
    let probe = std::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    // Wrong address is rejected before any socket work.
    let wrong = root.delegate_net_bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 1)));
    assert!(matches!(
        net::tcp_bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)), &wrong),
        Err(CapsecError::OutOfScope(_))
    ));

    let bind_token = root.delegate_net_bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
    let listener = net::tcp_bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)), &bind_token)
        .expect("bind within scope");

    // Loopback connect through the sandboxed wrapper succeeds in-scope.
    let connect = root.delegate_net_connect("localhost");
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            use std::io::Write;
            let _ = s.write_all(b"ok");
        }
    });
    let mut stream = net::tcp_connect("localhost", addr.port(), &connect).unwrap();
    use std::io::Read;
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"ok");
}

#[test]
fn net_connect_out_of_scope_host_rejected() {
    let root = RootCapability::acquire();
    let token = root.delegate_net_connect("localhost");
    assert!(matches!(
        net::tcp_connect("evil.example.net", 80, &token),
        Err(CapsecError::OutOfScope(_))
    ));
}

#[test]
fn process_scope_check_and_spawn() {
    let root = RootCapability::acquire();
    let token = root.delegate_process_spawn(["git"]);

    // Out-of-allowlist program is rejected without execution.
    assert!(matches!(
        process::output("definitely-not-a-program-zzz", Vec::<&str>::new(), &token),
        Err(CapsecError::OutOfScope(_))
    ));

    // In-allowlist program: expect success or an Io passthrough if git is
    // not installed on this machine.
    match process::output("git", ["--version"], &token) {
        Ok(out) => assert!(out.status.success()),
        Err(CapsecError::Io(_)) => {}
        other => panic!("unexpected result: {other:?}"),
    }
}

#[test]
fn spec_process_data_scenario() {
    fn process_data(
        fs_tok: FsReadToken<'_>,
        _net: NetConnectToken<'_>,
        cfg: &std::path::Path,
    ) -> Result<Vec<u8>, CapsecError> {
        tpt_capsec::fs::read(cfg, &fs_tok)
        // COMPILE ERROR (commented): requires FsWriteToken.
        // tpt_capsec::fs::remove(cfg, &fs_tok);
    }

    let root = RootCapability::acquire();
    let dir = std::env::temp_dir().join(format!("tpt-capsec-spec-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, b"{}").unwrap();

    let fs_tok = root.delegate_fs_read(&dir);
    let net_tok = root.delegate_net_connect("api.example.com");

    assert_eq!(process_data(fs_tok, net_tok, &cfg).unwrap(), b"{}");
}
