use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rand::rngs::{StdRng, SysRng};
use rand::SeedableRng;
use rmpv::Value;

use reticulum_sdk::destination::DestinationName;
use reticulum_sdk::identity::PrivateIdentity;
use reticulum_sdk::iface::udp::UdpInterface;
use reticulum_sdk::transport::{Transport, TransportConfig};

use super::client::Client;
use super::config::{Cfg, APP_ASPECT, APP_NAME};
use super::gitutil::{self, TempDir};
use super::server::Rngit;
use super::transfer::{PATH_CREATE, PATH_DELETE, PATH_FETCH, PATH_PUSH};
use super::{check_ok, fetch_request, ls_remote_refs, push_request};

    fn make_identity() -> PrivateIdentity {
        let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();
        PrivateIdentity::new_from_rand(&mut rng)
    }

    fn make_transport(identity: PrivateIdentity, _bind: &str, _forward: &str) -> Transport {
        let mut tcfg = TransportConfig::new("rngit-test", &identity, false);
        tcfg.set_respond_to_probes(true);
        Transport::new(tcfg)
    }

    fn git_ok(dir: &Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .current_dir(dir)
            .args(args)
            .output()
            .expect("run git");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).to_string()
    }

    /// Exercise the full protocol over a local loopback pair of UDP
    /// interfaces: create, push (with a bundle large enough to require
    /// resource transfer), ls-remote, clone, and delete.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn end_to_end() {
        let _ = env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or("info"),
        )
        .is_test(true)
        .try_init();

        let tmp = TempDir::new("rngit-e2e").unwrap();
        let repos = tmp.path().join("repos");
        let group = repos.join("public");
        fs::create_dir_all(&group).unwrap();

        let server_ident = make_identity();
        let client_ident = make_identity();

        let server_t = make_transport(server_ident.clone(), "127.0.0.1:7001", "127.0.0.1:7002");
        let client_t = make_transport(client_ident.clone(), "127.0.0.1:7002", "127.0.0.1:7001");

        let smgr = server_t.iface_manager();
        smgr.lock().await.spawn(
            UdpInterface::new("127.0.0.1:7001", Some("127.0.0.1:7002")),
            UdpInterface::spawn,
        );
        let cmgr = client_t.iface_manager();
        cmgr.lock().await.spawn(
            UdpInterface::new("127.0.0.1:7002", Some("127.0.0.1:7001")),
            UdpInterface::spawn,
        );

        let mut cfg = Cfg::default();
        cfg.repositories
            .insert("public".into(), group.to_string_lossy().into_owned());
        cfg.access.insert(
            "public".into(),
            vec!["r:all".into(), "w:all".into(), "c:all".into()],
        );
        cfg.rngit.announce_interval = 0;

        let mut server_t = server_t;
        let dest = server_t
            .add_destination(server_ident.clone(), DestinationName::new(APP_NAME, APP_ASPECT))
            .await;
        let dest_hash = dest.lock().await.desc.address_hash;
        for _ in 0..3 {
            server_t.send_announce(&dest, None).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let server_t = Arc::new(server_t);

        let rngit = Rngit::new(cfg);
        let st = server_t.clone();
        let server_task = tokio::spawn(async move { rngit.run(st).await });

        let client_t = Arc::new(client_t);
        let mut client = Client::connect(
            client_t.clone(),
            &client_ident,
            dest_hash,
            Duration::from_secs(30),
        )
        .await
        .unwrap_or_else(|e| panic!("connect failed: {e}"));

        let repo_path = "public/testrepo";

        // Create the repository.
        let create_data = Value::Map(vec![(Value::from(0i64), Value::from(repo_path))]);
        let resp = client
            .request(PATH_CREATE, create_data, Duration::from_secs(30))
            .await
            .unwrap();
        check_ok(resp, "create").unwrap();

        // ls-remote on the fresh repository: no refs.
        let remote = ls_remote_refs(&mut client, repo_path, false)
            .await
            .unwrap();
        assert!(remote.refs.is_empty(), "expected no refs, got {:?}", remote.refs);

        // Build a local repository with a large, incompressible file so the
        // push bundle forces a resource transfer.
        let local = tmp.path().join("local");
        fs::create_dir_all(&local).unwrap();
        git_ok(&local, &["init", "-b", "main"]);
        fs::write(local.join("small.txt"), "hello rngit\n").unwrap();
        let mut blob = Vec::with_capacity(5 * 1024 * 1024);
        let mut x: u32 = 12345;
        for _ in 0..(5 * 1024 * 1024 / 4) {
            x = x.wrapping_mul(1664525).wrapping_add(1013904223);
            blob.extend_from_slice(&x.to_le_bytes());
        }
        fs::write(local.join("large.bin"), &blob).unwrap();
        git_ok(&local, &["add", "."]);
        git_ok(
            &local,
            &[
                "-c", "user.name=test", "-c", "user.email=test@test",
                "commit", "-m", "initial",
            ],
        );
        let head_sha = git_ok(&local, &["rev-parse", "HEAD"]).trim().to_string();

        // Push the refs.
        let local_refs = gitutil::local_refs(&local).unwrap();
        assert!(!local_refs.is_empty());
        let ref_names: Vec<String> = local_refs.iter().map(|(_, r)| r.clone()).collect();
        let push_tmp = TempDir::new("rngit-e2e-push").unwrap();
        let bundle_path = push_tmp.path().join("push.bundle");
        gitutil::create_push_bundle(&local, &bundle_path, &ref_names, &[]).unwrap();
        let bundle_bytes = fs::read(&bundle_path).unwrap();
        assert!(bundle_bytes.len() > 100_000, "expected a sizeable bundle");
        for refname in &ref_names {
            let data = push_request(repo_path, refname, refname, false, &bundle_bytes);
            let resp = client
                .request(PATH_PUSH, data, Duration::from_secs(45))
                .await
                .unwrap();
            check_ok(resp, "push").unwrap();
        }

        // ls-remote now shows the pushed ref at the expected SHA.
        let remote = ls_remote_refs(&mut client, repo_path, false)
            .await
            .unwrap();
        let remote_sha = remote
            .refs
            .iter()
            .find(|(_, r)| r == "refs/heads/main")
            .map(|(s, _)| s.clone())
            .expect("refs/heads/main missing after push");
        assert_eq!(remote_sha, head_sha);
        assert!(remote.head.as_deref() == Some("refs/heads/main"));

        // Clone the repository (the bundle must arrive as a resource).
        let clone_dir = tmp.path().join("clone");
        fs::create_dir_all(&clone_dir).unwrap();
        gitutil::init_repository(&clone_dir, Some("main")).unwrap();
        let fetch_data = fetch_request(repo_path, &remote.refs);
        let resp = client
            .request(PATH_FETCH, fetch_data, Duration::from_secs(180))
            .await
            .unwrap();
        let bundle = match resp {
            super::ClientResponse::Resource(data) => {
                assert!(data.len() > 3);
                let meta_len =
                    ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | data[2] as usize;
                data[3 + meta_len..].to_vec()
            }
            super::ClientResponse::Bytes(b) => {
                assert_eq!(b.first(), Some(&0x00), "unexpected inline fetch response");
                Vec::new()
            }
        };
        assert!(!bundle.is_empty(), "clone bundle should not be empty");
        let fetch_tmp = TempDir::new("rngit-e2e-fetch").unwrap();
        let fb_path = fetch_tmp.path().join("fetch.bundle");
        fs::write(&fb_path, &bundle).unwrap();
        gitutil::verify_bundle(&clone_dir, &fb_path).unwrap();
        gitutil::fetch_bundle(
            &clone_dir,
            &fb_path,
            &[
                "+refs/heads/*:refs/remotes/origin/*",
                "+refs/tags/*:refs/tags/*",
            ],
        )
        .unwrap();
        gitutil::checkout_branch(&clone_dir, "refs/heads/main").unwrap();

        // Verify the clone matches the original repository.
        assert_eq!(
            git_ok(&clone_dir, &["rev-parse", "HEAD"]).trim(),
            head_sha
        );
        assert_eq!(fs::read(clone_dir.join("small.txt")).unwrap(), b"hello rngit\n");
        let cloned_blob = fs::read(clone_dir.join("large.bin")).unwrap();
        assert_eq!(cloned_blob.len(), blob.len());
        assert_eq!(cloned_blob, blob);

        // Delete the branch ref and confirm it is gone.
        let delete_data = Value::Map(vec![
            (Value::from(0i64), Value::from(repo_path)),
            (Value::from("ref"), Value::from("refs/heads/main")),
        ]);
        let resp = client
            .request(PATH_DELETE, delete_data.clone(), Duration::from_secs(30))
            .await
            .unwrap();
        check_ok(resp, "delete").unwrap();
        let remote = ls_remote_refs(&mut client, repo_path, false)
            .await
            .unwrap();
        assert!(
            !remote.refs.iter().any(|(_, r)| r == "refs/heads/main"),
            "deleted ref still present"
        );

        // Deleting an already-deleted ref should fail cleanly.
        let resp = client
            .request(PATH_DELETE, delete_data.clone(), Duration::from_secs(30))
            .await
            .unwrap();
        assert!(
            !resp_matches(resp, &[0x00]),
            "second delete should not succeed"
        );

        server_task.abort();
        let _ = server_task.await;
    }

    fn resp_matches(resp: super::ClientResponse, expect: &[u8]) -> bool {
        match resp {
            super::ClientResponse::Bytes(b) => b == expect,
            super::ClientResponse::Resource(_) => false,
        }
    }

    #[test]
    fn parse_url() {
        let url = format!("rns://{}/public/myrepo", "ab".repeat(16));
        let (hash, repo) = super::client::parse_rns_url(&url).unwrap();
        assert_eq!(hash.to_hex_string(), "ab".repeat(16));
        assert_eq!(repo, "public/myrepo");

        assert!(super::client::parse_rns_url("rns://short/group/repo").is_err());
        assert!(super::client::parse_rns_url("rns://0123456789abcdef0123456789abcdef").is_err());
    }
