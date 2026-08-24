use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rand::rngs::{StdRng, SysRng};
use rand::SeedableRng;
use rmpv::Value;

use reticulum_sdk::destination::DestinationName;
use reticulum_sdk::identity::PrivateIdentity;
use reticulum_sdk::iface::backbone::{BackboneClient, BackboneServer};
use reticulum_sdk::iface::tcp_client::TcpClient;
use reticulum_sdk::iface::tcp_server::TcpServer;
use reticulum_sdk::iface::udp::UdpInterface;
use reticulum_sdk::transport::{Transport, TransportConfig};

#[path = "rngit/config.rs"]
mod config;
#[path = "../config.rs"]
mod router_config;
#[path = "rngit/client.rs"]
mod client;
#[path = "rngit/gitutil.rs"]
mod gitutil;
#[path = "rngit/perms.rs"]
mod perms;
#[path = "rngit/transfer.rs"]
mod transfer;
#[path = "rngit/server.rs"]
mod server;
#[cfg(test)]
#[path = "rngit/e2e.rs"]
mod e2e;

use client::{Client, ClientResponse};
use config::{APP_ASPECT, APP_NAME};
use server::Rngit;
use transfer::{PATH_DELETE, PATH_FETCH, PATH_LIST, PATH_PUSH};

/// Number of announces sent at startup so late-subscribing peers can
/// discover this destination and resolve its identity for link crypto.
const STARTUP_ANNOUNCES: u32 = 5;

fn load_identity() -> Result<PrivateIdentity, Box<dyn std::error::Error>> {
    let path = config::ident_path();
    if path.is_file() {
        let hex = std::fs::read_to_string(&path)?;
        return PrivateIdentity::new_from_hex_string(hex.trim())
            .map_err(|e| format!("bad identity {path:?}: {e:?}").into());
    }
    let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();
    let id = PrivateIdentity::new_from_rand(&mut rng);
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let hex = format!("{}\n", id.to_hex_string());
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        f.write_all(hex.as_bytes())?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&path, hex)?;
    }
    log::info!("rngit: created identity at {path:?}");
    Ok(id)
}

async fn make_transport(identity: &PrivateIdentity) -> Result<Transport, Box<dyn std::error::Error>> {
    let mut tcfg = TransportConfig::new("rngit", identity, false);
    tcfg.set_respond_to_probes(true);
    tcfg.set_rpc_instance(true);
    let t = Transport::new(tcfg);
    let on_rpc = t.rpc_connected().await;
    let mgr = t.iface_manager();

    if on_rpc {
        log::info!("rngit: connected to local reticulum instance over rpc");
        return Ok(t);
    }

    // Load explicit interfaces from the Reticulum config only when running
    // standalone (no rpc instance). When connected to a running daemon via
    // the rpc instance, the daemon already manages all network connectivity.
    if let Some(path) = router_config::Config::find_existing() {
        match router_config::Config::from_file(&path) {
            Ok(cfg) => {
                log::info!("rngit: loading interfaces from {}", path.display());
                for iface in &cfg.interfaces {
                    let enabled = match &iface.config {
                        router_config::InterfaceConfig::TCPServerInterface { enabled, .. } => *enabled,
                        router_config::InterfaceConfig::TCPClientInterface { enabled, .. } => *enabled,
                        router_config::InterfaceConfig::BackboneInterface { enabled, .. } => *enabled,
                        router_config::InterfaceConfig::UDPInterface { enabled, .. } => *enabled,
                        router_config::InterfaceConfig::AutoInterface { enabled, .. } => *enabled,
                        _ => false,
                    };
                    if !enabled {
                        continue;
                    }
                    match &iface.config {
                        router_config::InterfaceConfig::TCPServerInterface { bind_host, bind_port, .. } => {
                            let addr = format!("{bind_host}:{bind_port}");
                            log::info!("rngit: TCP server on {addr}");
                            let _ = mgr.lock().await.spawn(
                                TcpServer::new(addr, mgr.clone()),
                                TcpServer::spawn,
                            );
                        }
                        router_config::InterfaceConfig::TCPClientInterface { target_host, target_port, .. } => {
                            let addr = format!("{target_host}:{target_port}");
                            log::info!("rngit: TCP client to {addr}");
                            let _ = mgr.lock().await.spawn(TcpClient::new(addr), TcpClient::spawn);
                        }
                        router_config::InterfaceConfig::BackboneInterface { bind_host, target_host, port, .. } => {
                            match (bind_host, target_host) {
                                (Some(host), None) => {
                                    let addr = format!("{host}:{port}");
                                    log::info!("rngit: backbone server on {addr}");
                                    let _ = mgr.lock().await.spawn(
                                        BackboneServer::new(addr, mgr.clone()),
                                        BackboneServer::spawn,
                                    );
                                }
                                (None, Some(host)) => {
                                    let addr = format!("{host}:{port}");
                                    log::info!("rngit: backbone client to {addr}");
                                    let _ = mgr.lock().await.spawn(
                                        BackboneClient::new(addr),
                                        BackboneClient::spawn,
                                    );
                                }
                                _ => log::warn!("rngit: skipping invalid backbone interface"),
                            }
                        }
                        router_config::InterfaceConfig::UDPInterface { listen_ip, listen_port, forward_ip, forward_port, .. } => {
                            let bind = format!("{listen_ip}:{listen_port}");
                            let forward = format!("{forward_ip}:{forward_port}");
                            log::info!("rngit: UDP {bind} -> {forward}");
                            let _ = mgr.lock().await.spawn(
                                UdpInterface::new(bind, Some(forward)),
                                UdpInterface::spawn,
                            );
                        }
                        router_config::InterfaceConfig::AutoInterface { .. } => {
                            log::warn!("rngit: AutoInterface unsupported")
                        }
                        _ => log::warn!("rngit: skipping unsupported interface"),
                    }
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => log::warn!("rngit: could not load Reticulum config: {e}"),
        }
    } else {
        log::warn!("rngit: no Reticulum config found; running with no interfaces");
    }

    Ok(t)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("ls-remote") => cmd_ls_remote(&args).await,
        Some("clone") => cmd_clone(&args).await,
        Some("push") => cmd_push(&args).await,
        Some("delete") => cmd_delete(&args).await,
        Some("help") | Some("-h") | Some("--help") => {
            print_usage();
            Ok(())
        }
        _ => server_main().await,
    }
}

fn print_usage() {
    eprintln!("rngit - Reticulum Git server and client\n");
    eprintln!("Usage:");
    eprintln!("  rngit                       Run the repository server");
    eprintln!("  rngit ls-remote <url>       List refs of a remote repository");
    eprintln!("  rngit clone <url> [dir]     Clone a remote repository");
    eprintln!("  rngit push [--force] <dir> <url>");
    eprintln!("                              Push local refs to a remote repository");
    eprintln!("  rngit delete <url> <ref>    Delete a ref on a remote repository\n");
    eprintln!("<url> is rns://<destination_hash>/<group>/<repository>\n");
    eprintln!("Server options:");
    eprintln!("  -b, --announce <sec>       Announce interval in seconds (default: 600, 0 disables)");
}

async fn server_main() -> Result<(), Box<dyn std::error::Error>> {
    let mut cfg = config::load_cfg(None);

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-b" | "--announce" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or("--announce needs a value")
                    .map_err(|e: &str| e.to_string())?;
                cfg.rngit.announce_interval = v.parse().map_err(|_| "bad announce interval")?;
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            _ => return Err(format!("unrecognized argument: {}", args[i]).into()),
        }
        i += 1;
    }

    let identity = load_identity()?;
    let mut transport = make_transport(&identity).await?;

    let dest = transport
        .add_destination(identity, DestinationName::new(APP_NAME, APP_ASPECT))
        .await;
    let dest_hash = dest.lock().await.desc.address_hash;
    log::info!(
        "rngit: identity {} listening on {}.{} at {}",
        dest.lock().await.desc.identity.address_hash.to_hex_string(),
        APP_NAME,
        APP_ASPECT,
        dest_hash.to_hex_string()
    );

    for _ in 0..STARTUP_ANNOUNCES {
        transport.send_announce(&dest, None).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let transport = Arc::new(transport);

    let announce_interval = cfg.rngit.announce_interval;
    if announce_interval > 0 {
        let t2 = transport.clone();
        let d2 = dest.clone();
        tokio::spawn(async move {
            loop {
                t2.send_announce(&d2, None).await;
                tokio::time::sleep(Duration::from_secs(announce_interval)).await;
            }
        });
    }

    let rngit = Rngit::new(cfg);
    rngit.run(transport).await?;
    Ok(())
}

// ------------------------------------------------------------------
// Client
// ------------------------------------------------------------------

struct RemoteRefs {
    refs: Vec<(String, String)>,
    head: Option<String>,
}

/// Build the `/git/list` request payload.
fn list_request(repo: &str, for_push: bool) -> Value {
    Value::Map(vec![
        (Value::from(0i64), Value::from(repo)),
        (Value::from("for_push"), Value::from(for_push)),
    ])
}

/// Build the `/git/fetch` request payload for the given refs.
fn fetch_request(repo: &str, refs: &[(String, String)]) -> Value {
    let ref_array: Vec<Value> = refs
        .iter()
        .map(|(_, name)| Value::Map(vec![(Value::from("ref"), Value::from(name.as_str()))]))
        .collect();
    Value::Map(vec![
        (Value::from(0i64), Value::from(repo)),
        (Value::from("refs"), Value::Array(ref_array)),
        (Value::from("have"), Value::Array(vec![])),
    ])
}

/// Build the `/git/push` request payload carrying a bundle.
fn push_request(repo: &str, local_ref: &str, remote_ref: &str, force: bool, bundle: &[u8]) -> Value {
    Value::Map(vec![
        (Value::from(0i64), Value::from(repo)),
        (Value::from("local_ref"), Value::from(local_ref)),
        (Value::from("remote_ref"), Value::from(remote_ref)),
        (Value::from("force"), Value::from(force)),
        (Value::from("bundle"), Value::Binary(bundle.to_vec())),
    ])
}

fn response_bytes(resp: ClientResponse) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match resp {
        ClientResponse::Bytes(b) => Ok(b),
        ClientResponse::Resource(b) => Ok(b),
    }
}

/// Check a push/delete response for the success marker (0x00).
fn check_ok(resp: ClientResponse, context: &str) -> Result<(), Box<dyn std::error::Error>> {
    match resp {
        ClientResponse::Bytes(b) if b.first() == Some(&0x00) => Ok(()),
        ClientResponse::Bytes(b) => {
            let code = b.first().copied().unwrap_or(0);
            let msg = String::from_utf8_lossy(&b[1..]).trim().to_string();
            Err(format!("{context}: server error {code}: {msg}").into())
        }
        ClientResponse::Resource(_) => {
            Err(format!("{context}: unexpected resource response").into())
        }
    }
}

/// Parse the `/git/list` response payload (refs text + `@<head> HEAD`).
fn parse_list_response(bytes: &[u8]) -> Result<RemoteRefs, Box<dyn std::error::Error>> {
    if bytes.first() != Some(&0x00) {
        let code = bytes.first().copied().unwrap_or(0);
        let msg = String::from_utf8_lossy(&bytes[1..]).trim().to_string();
        return Err(format!("server error {code}: {msg}").into());
    }
    let body = &bytes[1..];
    let mut refs = Vec::new();
    let mut head = None;
    for line in String::from_utf8_lossy(body).lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('@') {
            if let Some(name) = rest.strip_suffix(" HEAD") {
                head = Some(name.to_string());
            }
        } else if let Some((sha, refname)) = line.split_once(' ') {
            refs.push((sha.to_string(), refname.to_string()));
        }
    }
    Ok(RemoteRefs { refs, head })
}

fn print_ls_remote(remote: &RemoteRefs) {
    for (sha, refname) in &remote.refs {
        println!("{sha}\t{refname}");
    }
    if let Some(head) = &remote.head
        && let Some((sha, _)) = remote.refs.iter().find(|(_, r)| r == head)
    {
        println!("{sha}\tHEAD");
    }
}

async fn client_setup() -> Result<(Arc<Transport>, PrivateIdentity), Box<dyn std::error::Error>> {
    let identity = load_identity()?;
    let transport = Arc::new(make_transport(&identity).await?);
    Ok((transport, identity))
}

/// Issue a `/git/list` request and return the parsed refs.
async fn ls_remote_refs(
    c: &mut Client,
    repo: &str,
    for_push: bool,
) -> Result<RemoteRefs, Box<dyn std::error::Error>> {
    let resp = c
        .request(
            PATH_LIST,
            list_request(repo, for_push),
            client::REQUEST_TIMEOUT,
        )
        .await?;
    parse_list_response(&response_bytes(resp)?)
}

async fn cmd_ls_remote(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let url = args.get(2).ok_or("usage: rngit ls-remote <rns://hash/group/repo>")?;
    let (hash, repo) = client::parse_rns_url(url)?;
    let (transport, identity) = client_setup().await?;
    let mut c = Client::connect(transport, &identity, hash, client::CONNECT_TIMEOUT).await?;
    let remote = ls_remote_refs(&mut c, &repo, false).await?;
    print_ls_remote(&remote);
    Ok(())
}

async fn cmd_clone(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let url = args.get(2).ok_or("usage: rngit clone <rns://hash/group/repo> [dir]")?;
    let dir_arg = args.get(3).cloned();
    let (hash, repo) = client::parse_rns_url(url)?;
    let dir = match dir_arg {
        Some(d) => Path::new(&d).to_path_buf(),
        None => {
            let name = repo
                .rsplit_once('/')
                .map(|(_, r)| r)
                .unwrap_or("repo");
            Path::new(name).to_path_buf()
        }
    };
    if dir.exists() {
        return Err(format!("destination {} already exists", dir.display()).into());
    }

    let (transport, identity) = client_setup().await?;
    let mut c = Client::connect(transport, &identity, hash, client::CONNECT_TIMEOUT).await?;
    let remote = ls_remote_refs(&mut c, &repo, false).await?;
    let head_branch = remote
        .head
        .as_ref()
        .and_then(|h| h.strip_prefix("refs/heads/"))
        .map(|s| s.to_string());

    let fetch_data = fetch_request(&repo, &remote.refs);
    let resp = c
        .request(PATH_FETCH, fetch_data, client::REQUEST_TIMEOUT)
        .await?;
    let mut bundle: Option<Vec<u8>> = None;
    match resp {
        ClientResponse::Bytes(b) if b.first() == Some(&0x00) => {
            log::info!("rngit: remote repository is empty");
        }
        ClientResponse::Bytes(b) => {
            let code = b.first().copied().unwrap_or(0);
            let msg = String::from_utf8_lossy(&b[1..]).trim().to_string();
            return Err(format!("fetch failed: server error {code}: {msg}").into());
        }
        ClientResponse::Resource(data) => {
            // Skip the resource metadata prefix: 3-byte length + msgpack.
            if data.len() < 3 {
                return Err("fetch response too short".into());
            }
            let meta_len = ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | data[2] as usize;
            if data.len() < 3 + meta_len {
                return Err("fetch response truncated".into());
            }
            bundle = Some(data[3 + meta_len..].to_vec());
        }
    }

    gitutil::init_repository(&dir, head_branch.as_deref())?;
    if let Some(bundle_data) = bundle {
        let tmp = gitutil::TempDir::new("rngit-clone")?;
        let bundle_path = tmp.path().join("fetch.bundle");
        fs::write(&bundle_path, &bundle_data)
            .map_err(|e| format!("could not write bundle: {e}"))?;
        gitutil::verify_bundle(&dir, &bundle_path)?;
        gitutil::fetch_bundle(
            &dir,
            &bundle_path,
            &[
                "+refs/heads/*:refs/remotes/origin/*",
                "+refs/tags/*:refs/tags/*",
            ],
        )?;
    }
    gitutil::remote_add(&dir, "origin", url)?;
    gitutil::config_set(&dir, "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")?;
    if let Some(branch) = &head_branch
        && gitutil::checkout_branch(&dir, &format!("refs/heads/{branch}"))?
    {
        gitutil::config_set(&dir, &format!("branch.{branch}.remote"), "origin")?;
        gitutil::config_set(&dir, &format!("branch.{branch}.merge"), &format!("refs/heads/{branch}"))?;
    }

    println!("Cloned {repo} into {}", dir.display());
    Ok(())
}

async fn cmd_push(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut force = false;
    let mut positional: Vec<String> = Vec::new();
    for a in &args[2..] {
        match a.as_str() {
            "-f" | "--force" => force = true,
            other => positional.push(other.to_string()),
        }
    }
    let dir = positional.first().ok_or("usage: rngit push [--force] <dir> <rns://hash/group/repo>")?;
    let url = positional.get(1).ok_or("usage: rngit push [--force] <dir> <rns://hash/group/repo>")?;
    let (hash, repo) = client::parse_rns_url(url)?;
    let dir_path = Path::new(dir);
    if !dir_path.is_dir() {
        return Err(format!("{dir} is not a directory").into());
    }

    let local = gitutil::local_refs(dir_path)?;
    if local.is_empty() {
        println!("No refs to push");
        return Ok(());
    }

    let (transport, identity) = client_setup().await?;
    let mut c = Client::connect(transport, &identity, hash, client::CONNECT_TIMEOUT).await?;
    let remote = ls_remote_refs(&mut c, &repo, true).await?;
    let server: HashMap<String, String> = remote.refs.iter().cloned().collect();

    let mut refs_to_push: Vec<String> = Vec::new();
    for (sha, refname) in &local {
        match server.get(refname) {
            None => refs_to_push.push(refname.clone()),
            Some(old) if old != sha => {
                if !force && !gitutil::is_ancestor(dir_path, old, sha) {
                    return Err(
                        format!("non-fast-forward update for {refname}; use --force").into()
                    );
                }
                refs_to_push.push(refname.clone());
            }
            Some(_) => {}
        }
    }
    if refs_to_push.is_empty() {
        println!("Everything up-to-date");
        return Ok(());
    }

    let mut prerequisites: Vec<String> = Vec::new();
    for (sha, _) in &remote.refs {
        if gitutil::object_exists(dir_path, sha) {
            prerequisites.push(sha.clone());
        }
    }

    let tmp = gitutil::TempDir::new("rngit-push")?;
    let bundle_path = tmp.path().join("push.bundle");
    gitutil::create_push_bundle(dir_path, &bundle_path, &refs_to_push, &prerequisites)?;
    let bundle_bytes = fs::read(&bundle_path)
        .map_err(|e| format!("could not read bundle: {e}"))?;

    for refname in &refs_to_push {
        let op_force = force && server.contains_key(refname);
        let data = push_request(&repo, refname, refname, op_force, &bundle_bytes);
        let resp = c
            .request(PATH_PUSH, data, client::REQUEST_TIMEOUT)
            .await?;
        check_ok(resp, "push failed")?;
        println!("Pushed {refname}");
    }
    Ok(())
}

async fn cmd_delete(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let url = args.get(2).ok_or("usage: rngit delete <rns://hash/group/repo> <ref>")?;
    let refname = args.get(3).ok_or("usage: rngit delete <rns://hash/group/repo> <ref>")?;
    let (hash, repo) = client::parse_rns_url(url)?;
    let (transport, identity) = client_setup().await?;
    let mut c = Client::connect(transport, &identity, hash, client::CONNECT_TIMEOUT).await?;
    let data = Value::Map(vec![
        (Value::from(0i64), Value::from(repo)),
        (Value::from("ref"), Value::from(refname.as_str())),
    ]);
    let resp = c
        .request(PATH_DELETE, data, client::REQUEST_TIMEOUT)
        .await?;
    check_ok(resp, "delete failed")?;
    println!("Deleted {refname}");
    Ok(())
}
