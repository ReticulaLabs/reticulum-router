//! git-remote-rns — a git remote helper that lets the native git CLI use
//! repositories served over Reticulum by an rngit server.
//!
//! Invoked by git as `git-remote-rns <remote> <url>` for URLs of the form
//! `rns://<hash>/<group>/<repo>`. It speaks the git remote helper protocol
//! on stdin/stdout and reuses the rngit client to fetch git bundles and push
//! refs over the Reticulum mesh.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;

use rand::rngs::{StdRng, SysRng};
use rand::SeedableRng;
use rmpv::Value;
use tokio::io::AsyncBufReadExt;

use reticulum_sdk::hash::AddressHash;
use reticulum_sdk::identity::PrivateIdentity;
use reticulum_sdk::iface::backbone::{BackboneClient, BackboneServer};
use reticulum_sdk::iface::tcp_client::TcpClient;
use reticulum_sdk::iface::tcp_server::TcpServer;
use reticulum_sdk::iface::udp::UdpInterface;
use reticulum_sdk::transport::{Transport, TransportConfig};

// Shared rngit modules; the helper only exercises a subset of each.
#[allow(dead_code)]
#[path = "rngit/config.rs"]
mod config;
#[path = "rngit/client.rs"]
mod client;
#[allow(dead_code)]
#[path = "rngit/transfer.rs"]
mod transfer;
#[allow(dead_code)]
#[path = "rngit/gitutil.rs"]
mod gitutil;
#[path = "../config.rs"]
mod router_config;
#[cfg(test)]
#[allow(dead_code)]
#[path = "rngit/perms.rs"]
mod perms;
#[cfg(test)]
#[allow(dead_code)]
#[path = "rngit/server.rs"]
mod server;

use client::{Client, ClientResponse};

type HResult<T> = Result<T, String>;

// ── URL parsing ─────────────────────────────────────────────────────

/// Parse a git remote URL into the server destination hash and the
/// `group/repo` path.
///
/// Accepted forms:
/// - `rns://<hash>/<group>/<repo>`
/// - `rns::<hash>/<group>/<repo>` (address-only form)
/// - `<hash>/<group>/<repo>` (bare address)
fn parse_url(raw: &str) -> HResult<(AddressHash, String)> {
    let rest = raw.strip_prefix("rns::").unwrap_or(raw);
    client::parse_rns_url(rest)
}

// ── Identity and transport ──────────────────────────────────────────

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
    log::info!("git-remote-rns: created identity at {path:?}");
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
        log::info!("git-remote-rns: connected to local reticulum instance over rpc");
        return Ok(t);
    }

    // Load explicit interfaces from the Reticulum config only when running
    // standalone (no rpc instance).
    if let Some(path) = router_config::Config::find_existing() {
        match router_config::Config::from_file(&path) {
            Ok(cfg) => {
                log::info!("git-remote-rns: loading interfaces from {}", path.display());
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
                            let _ = mgr.lock().await.spawn(
                                TcpServer::new(addr, mgr.clone()),
                                TcpServer::spawn,
                            );
                        }
                        router_config::InterfaceConfig::TCPClientInterface { target_host, target_port, .. } => {
                            let addr = format!("{target_host}:{target_port}");
                            let _ = mgr.lock().await.spawn(TcpClient::new(addr), TcpClient::spawn);
                        }
                        router_config::InterfaceConfig::BackboneInterface { bind_host, target_host, port, .. } => {
                            match (bind_host, target_host) {
                                (Some(host), None) => {
                                    let addr = format!("{host}:{port}");
                                    let _ = mgr.lock().await.spawn(
                                        BackboneServer::new(addr, mgr.clone()),
                                        BackboneServer::spawn,
                                    );
                                }
                                (None, Some(host)) => {
                                    let addr = format!("{host}:{port}");
                                    let _ = mgr.lock().await.spawn(
                                        BackboneClient::new(addr),
                                        BackboneClient::spawn,
                                    );
                                }
                                _ => log::warn!("git-remote-rns: skipping invalid backbone interface"),
                            }
                        }
                        router_config::InterfaceConfig::UDPInterface { listen_ip, listen_port, forward_ip, forward_port, .. } => {
                            let bind = format!("{listen_ip}:{listen_port}");
                            let forward = format!("{forward_ip}:{forward_port}");
                            let _ = mgr.lock().await.spawn(
                                UdpInterface::new(bind, Some(forward)),
                                UdpInterface::spawn,
                            );
                        }
                        router_config::InterfaceConfig::AutoInterface { .. } => {
                            log::warn!("git-remote-rns: AutoInterface unsupported")
                        }
                        _ => log::warn!("git-remote-rns: skipping unsupported interface"),
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            Err(e) => log::warn!("git-remote-rns: could not load Reticulum config: {e}"),
        }
    } else {
        log::warn!("git-remote-rns: no Reticulum config found; running with no interfaces");
    }

    Ok(t)
}

// ── Helper state ────────────────────────────────────────────────────

struct Helper {
    hash: AddressHash,
    repo: String,
    client: Option<Client>,
    /// `option dry-run` state: pretend a push succeeded without sending it.
    dry_run: bool,
    verbosity: u8,
    /// Refs observed from the most recent `list for-push`.
    server_refs: Vec<(String, String)>,
}

impl Helper {
    fn new(hash: AddressHash, repo: String) -> Self {
        Helper {
            hash,
            repo,
            client: None,
            dry_run: false,
            verbosity: 1,
            server_refs: Vec::new(),
        }
    }

    async fn client_mut(&mut self) -> HResult<&mut Client> {
        if self.client.is_none() {
            let identity = load_identity().map_err(|e| e.to_string())?;
            let t = Arc::new(make_transport(&identity).await.map_err(|e| e.to_string())?);
            let c = Client::connect(t, &identity, self.hash, client::CONNECT_TIMEOUT).await?;
            self.client = Some(c);
        }
        Ok(self.client.as_mut().unwrap())
    }
}

// ── Local git plumbing ──────────────────────────────────────────────

/// The repository git is operating on, passed via the environment.
fn git_dir() -> Option<String> {
    env::var("GIT_DIR").ok()
}

/// Run a git plumbing command with inherited environment/GIT_DIR.
fn run_git(args: &[&str]) -> HResult<Vec<u8>> {
    let out = Command::new("git")
        .args(args)
        .output()
        .map_err(|e| format!("could not run git: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(out.stdout)
}

/// The object ids of every local ref, used as bundle prerequisites so the
/// server only sends objects we do not already have.
fn local_have_shas() -> HResult<Vec<String>> {
    git_dir().ok_or("GIT_DIR is not set")?;
    let out = run_git(&["for-each-ref", "--format=%(objectname)"])?;
    let mut shas = Vec::new();
    for line in String::from_utf8_lossy(&out).lines() {
        let s = line.trim();
        if !s.is_empty() {
            shas.push(s.to_string());
        }
    }
    Ok(shas)
}

/// Split a git bundle into (header, pack). The pack is the raw packfile
/// `git index-pack` can ingest without touching any refs.
fn split_bundle(bundle: &[u8]) -> Option<&[u8]> {
    let mut line_start = 0usize;
    let mut i = 0usize;
    while i < bundle.len() {
        if bundle[i] == b'\n' {
            if line_start == i {
                return Some(&bundle[i + 1..]);
            }
            line_start = i + 1;
        }
        i += 1;
    }
    None
}

/// Ingest a bundle's pack into the local object database without updating
/// refs, so git remains in charge of ref management.
fn index_bundle(bundle: &[u8]) -> HResult<()> {
    let git_dir = git_dir().ok_or("GIT_DIR is not set")?;
    index_bundle_into(&git_dir, bundle)
}

/// Ingest a bundle's pack into a specific repository's object database.
fn index_bundle_into(git_dir: &str, bundle: &[u8]) -> HResult<()> {
    let pack = split_bundle(bundle).ok_or("invalid bundle: missing pack section")?;
    let mut child = Command::new("git")
        .env("GIT_DIR", git_dir)
        .args(["index-pack", "--stdin", "--fix-thin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not run git index-pack: {e}"))?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or("could not open git index-pack stdin")?;
        stdin
            .write_all(pack)
            .map_err(|e| format!("could not write pack to git index-pack: {e}"))?;
    }
    child.stdin.take();
    let out = child
        .wait_with_output()
        .map_err(|e| format!("git index-pack failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git index-pack failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// Parse the server's `/git/list` body into `(sha, refname)` pairs.
fn parse_server_refs(body: &[u8]) -> Vec<(String, String)> {
    let mut refs = Vec::new();
    for line in String::from_utf8_lossy(body).lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('@') {
            continue;
        }
        if let Some((sha, name)) = line.split_once(' ') {
            if sha.len() == 40 && name.starts_with("refs/") {
                refs.push((sha.to_string(), name.to_string()));
            }
        }
    }
    refs
}

fn parse_push_spec(spec: &str) -> HResult<(bool, String, String)> {
    let (force, spec) = match spec.strip_prefix('+') {
        Some(rest) => (true, rest),
        None => (false, spec),
    };
    let (src, dst) = spec
        .split_once(':')
        .ok_or_else(|| format!("invalid push spec: {spec}"))?;
    Ok((force, src.to_string(), dst.to_string()))
}

fn check_ok_bytes(resp: ClientResponse, context: &str) -> HResult<()> {
    match resp {
        ClientResponse::Bytes(b) if b.first() == Some(&0x00) => Ok(()),
        ClientResponse::Bytes(b) => {
            let code = b.first().copied().unwrap_or(0);
            let msg = String::from_utf8_lossy(&b[1..]).trim().to_string();
            Err(format!("{context}: server error {code}: {msg}"))
        }
        ClientResponse::Resource(_) => Err(format!("{context}: unexpected resource response")),
    }
}

// ── Protocol handlers ───────────────────────────────────────────────

async fn do_list(h: &mut Helper, for_push: bool, out: &mut impl Write) -> HResult<()> {
    let data = Value::Map(vec![
        (Value::from(0i64), Value::from(h.repo.as_str())),
        (Value::from("for_push"), Value::from(for_push)),
    ]);
    let client = h.client_mut().await?;
    let resp = client
        .request(transfer::PATH_LIST, data, client::REQUEST_TIMEOUT)
        .await?;
    let bytes = match resp {
        ClientResponse::Bytes(b) => b,
        ClientResponse::Resource(_) => return Err("unexpected resource response".into()),
    };
    if bytes.first() != Some(&0x00) {
        let code = bytes.first().copied().unwrap_or(0);
        let msg = String::from_utf8_lossy(&bytes[1..]).trim().to_string();
        return Err(format!("server error {code}: {msg}"));
    }
    let body = &bytes[1..];
    h.server_refs = parse_server_refs(body);
    for line in String::from_utf8_lossy(body).lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        writeln!(out, "{line}").map_err(|e| e.to_string())?;
    }
    out.write_all(b"\n").map_err(|e| e.to_string())
}

async fn do_fetch(h: &mut Helper, batch: &[(String, String)], out: &mut impl Write) -> HResult<()> {
    if !batch.is_empty() {
        let refs: Vec<Value> = batch
            .iter()
            .map(|(_, name)| Value::Map(vec![(Value::from("ref"), Value::from(name.as_str()))]))
            .collect();
        let have = local_have_shas().unwrap_or_default();
        let data = Value::Map(vec![
            (Value::from(0i64), Value::from(h.repo.as_str())),
            (Value::from("refs"), Value::Array(refs)),
            (
                Value::from("have"),
                Value::Array(have.into_iter().map(Value::from).collect()),
            ),
        ]);
        let client = h.client_mut().await?;
        let resp = client
            .request(transfer::PATH_FETCH, data, client::REQUEST_TIMEOUT)
            .await?;
        match resp {
            ClientResponse::Bytes(b) if b.first() == Some(&0x00) => {
                log::info!("git-remote-rns: remote repository is empty");
            }
            ClientResponse::Bytes(b) => {
                let code = b.first().copied().unwrap_or(0);
                let msg = String::from_utf8_lossy(&b[1..]).trim().to_string();
                return Err(format!("fetch failed: server error {code}: {msg}"));
            }
            ClientResponse::Resource(data) => {
                if data.len() < 3 {
                    return Err("fetch response too short".into());
                }
                let meta_len =
                    ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | data[2] as usize;
                if data.len() < 3 + meta_len {
                    return Err("fetch response truncated".into());
                }
                index_bundle(&data[3 + meta_len..])?;
            }
        }
    }
    out.write_all(b"\n").map_err(|e| e.to_string())
}

async fn do_push(h: &mut Helper, force: bool, src: &str, dst: &str) -> HResult<()> {
    git_dir().ok_or("GIT_DIR is not set")?;

    if src.is_empty() {
        if h.dry_run {
            return Ok(());
        }
        let data = Value::Map(vec![
            (Value::from(0i64), Value::from(h.repo.as_str())),
            (Value::from("ref"), Value::from(dst)),
        ]);
        let client = h.client_mut().await?;
        let resp = client
            .request(transfer::PATH_DELETE, data, client::REQUEST_TIMEOUT)
            .await?;
        return check_ok_bytes(resp, "delete failed");
    }

    if h.dry_run {
        return Ok(());
    }

    let tmp = gitutil::TempDir::new("rngit-push")?;
    let bundle_path = tmp.path().join("push.bundle");

    // Prerequisites are objects the server already has: its advertised refs
    // that are also present locally.
    let mut prereqs: Vec<String> = Vec::new();
    for (sha, _) in &h.server_refs {
        if gitutil::object_exists(Path::new("."), sha) {
            prereqs.push(sha.clone());
        }
    }
    let refs = vec![src.to_string()];
    gitutil::create_push_bundle(Path::new("."), &bundle_path, &refs, &prereqs)?;
    let bundle_bytes = fs::read(&bundle_path).map_err(|e| format!("could not read bundle: {e}"))?;

    let data = Value::Map(vec![
        (Value::from(0i64), Value::from(h.repo.as_str())),
        (Value::from("local_ref"), Value::from(src)),
        (Value::from("remote_ref"), Value::from(dst)),
        (Value::from("force"), Value::from(force)),
        (Value::from("bundle"), Value::Binary(bundle_bytes)),
    ]);
    let client = h.client_mut().await?;
    let resp = client
        .request(transfer::PATH_PUSH, data, client::REQUEST_TIMEOUT)
        .await?;
    check_ok_bytes(resp, "push failed")
}

async fn do_push_batch(h: &mut Helper, batch: &[String], out: &mut impl Write) -> HResult<()> {
    for spec in batch {
        let (force, src, dst) = parse_push_spec(spec)?;
        match do_push(h, force, &src, &dst).await {
            Ok(()) => writeln!(out, "ok {dst}").map_err(|e| e.to_string())?,
            Err(e) => writeln!(out, "error {dst} {e}").map_err(|e| e.to_string())?,
        }
    }
    out.write_all(b"\n").map_err(|e| e.to_string())
}

fn handle_option(h: &mut Helper, rest: &str, out: &mut impl Write) -> HResult<()> {
    let (name, value) = rest.split_once(' ').unwrap_or((rest, ""));
    let supported = match name {
        "verbosity" => {
            h.verbosity = value.parse().unwrap_or(1);
            true
        }
        "dry-run" => {
            h.dry_run = value == "true";
            true
        }
        "progress" | "followtags" | "cloning" | "update-shallow" | "refetch" | "force"
        | "atomic" | "push-cert" | "push-option" => true,
        _ => false,
    };
    if supported {
        out.write_all(b"ok\n").map_err(|e| e.to_string())
    } else {
        out.write_all(b"unsupported\n").map_err(|e| e.to_string())
    }
}

// ── Main protocol loop ──────────────────────────────────────────────

async fn run<R, W>(mut h: Helper, stdin: R, out: W) -> HResult<()>
where
    R: tokio::io::AsyncBufRead + Unpin,
    W: Write,
{
    let mut lines = stdin.lines();
    let mut out = out;

    loop {
        let line = match lines.next_line().await.map_err(|e| format!("stdin: {e}"))? {
            Some(l) => l,
            None => break,
        };
        if line.is_empty() {
            break;
        }
        match line.as_str() {
            "capabilities" => {
                out.write_all(b"fetch\npush\noption\n\n")
                    .map_err(|e| e.to_string())?;
            }
            "list" => do_list(&mut h, false, &mut out).await?,
            "list for-push" => do_list(&mut h, true, &mut out).await?,
            _ if line.starts_with("option ") => handle_option(&mut h, &line[7..], &mut out)?,
            _ if line.starts_with("fetch ") => {
                let mut batch = vec![parse_fetch_line(&line)?];
                loop {
                    let l = match lines
                        .next_line()
                        .await
                        .map_err(|e| format!("stdin: {e}"))?
                    {
                        Some(l) => l,
                        None => return Err("unexpected EOF in fetch batch".into()),
                    };
                    if l.is_empty() {
                        break;
                    }
                    if let Some(rest) = l.strip_prefix("fetch ") {
                        batch.push(parse_fetch_line(rest)?);
                    } else {
                        return Err(format!("unexpected line in fetch batch: {l}"));
                    }
                }
                do_fetch(&mut h, &batch, &mut out).await?;
            }
            _ if line.starts_with("push ") => {
                let mut batch = vec![line[5..].to_string()];
                loop {
                    let l = match lines
                        .next_line()
                        .await
                        .map_err(|e| format!("stdin: {e}"))?
                    {
                        Some(l) => l,
                        None => return Err("unexpected EOF in push batch".into()),
                    };
                    if l.is_empty() {
                        break;
                    }
                    if let Some(rest) = l.strip_prefix("push ") {
                        batch.push(rest.to_string());
                    } else if l.starts_with("option ") {
                        // Protocol option within a push batch; ignore.
                    } else {
                        return Err(format!("unexpected line in push batch: {l}"));
                    }
                }
                do_push_batch(&mut h, &batch, &mut out).await?;
            }
            _ => return Err(format!("unknown command: {line}")),
        }
        out.flush().map_err(|e| e.to_string())?;
    }
    out.flush().map_err(|e| e.to_string())
}

fn parse_fetch_line(rest: &str) -> HResult<(String, String)> {
    let mut it = rest.splitn(2, ' ');
    let oid = it.next().ok_or("invalid fetch line")?.to_string();
    let name = it.next().ok_or("invalid fetch line")?.to_string();
    Ok((oid, name))
}

fn print_usage() {
    eprintln!(
        "git-remote-rns - git remote helper for Reticulum (rngit)\n\n\
         This program is invoked by git for URLs of the form:\n\
           rns://<hash>/<group>/<repo>\n\n\
         Usage: git clone rns://<hash>/<group>/<repo>\n\
                git fetch  rns://<hash>/<group>/<repo>\n\
                git push   rns://<hash>/<group>/<repo> <refspec>\n\
                git ls-remote rns://<hash>/<group>/<repo>"
    );
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = env::args().collect();
    if args.len() >= 2 && (args[1] == "-h" || args[1] == "--help" || args[1] == "--version") {
        print_usage();
        return;
    }
    let raw_url = args
        .get(2)
        .cloned()
        .or_else(|| args.get(1).cloned())
        .unwrap_or_default();
    let (hash, repo) = match parse_url(&raw_url) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("git-remote-rns: {e}");
            std::process::exit(1);
        }
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("could not build tokio runtime");
    let code = rt.block_on(async {
        let stdin = tokio::io::BufReader::new(tokio::io::stdin());
        let out = io::BufWriter::new(io::stdout().lock());
        match run(Helper::new(hash, repo), stdin, out).await {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("git-remote-rns: {e}");
                1
            }
        }
    });
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::client::Client;
    use super::config::{Cfg, APP_ASPECT, APP_NAME};
    use super::gitutil;
    use super::server::Rngit;
    use super::transfer::{PATH_CREATE, PATH_FETCH, PATH_PUSH};
    use super::{
        do_list, index_bundle_into, parse_push_spec, parse_server_refs, parse_url, run,
        split_bundle, Helper,
    };
    use super::ClientResponse;
    use rand::SeedableRng;
    use rmpv::Value;
    use std::path::Path;
    use std::process::Command;
    use std::sync::Arc;
    use std::{fs, time::Duration};

    use reticulum_sdk::destination::DestinationName;
    use reticulum_sdk::hash::AddressHash;
    use reticulum_sdk::identity::PrivateIdentity;
    use reticulum_sdk::iface::udp::UdpInterface;
    use reticulum_sdk::transport::{Transport, TransportConfig};

    #[test]
    fn bundle_split_skips_header() {
        let bundle = b"# v2 git bundle\n\
0123456789abcdef0123456789abcdef01234567 refs/heads/main\n\
\n\
PACKDATA";
        assert_eq!(split_bundle(bundle), Some(&b"PACKDATA"[..]));
    }

    #[test]
    fn bundle_split_no_pack() {
        assert_eq!(split_bundle(b"# v2 git bundle\n"), None);
    }

    #[test]
    fn parse_url_forms() {
        let hash = "ab".repeat(16);
        for url in [
            format!("rns://{hash}/public/myrepo"),
            format!("rns::{hash}/public/myrepo"),
            format!("{hash}/public/myrepo"),
        ] {
            let (h, repo) = parse_url(&url).unwrap();
            assert_eq!(h.to_hex_string(), hash);
            assert_eq!(repo, "public/myrepo");
        }
        assert!(parse_url("rns://short/group/repo").is_err());
    }

    #[test]
    fn push_spec_parsing() {
        assert_eq!(
            parse_push_spec("refs/heads/main:refs/heads/main").unwrap(),
            (false, "refs/heads/main".into(), "refs/heads/main".into())
        );
        assert_eq!(
            parse_push_spec("+refs/heads/a:refs/heads/b").unwrap(),
            (true, "refs/heads/a".into(), "refs/heads/b".into())
        );
        assert_eq!(
            parse_push_spec(":refs/heads/old").unwrap(),
            (false, String::new(), "refs/heads/old".into())
        );
    }

    #[test]
    fn server_refs_parsing() {
        let body = b"0123456789abcdef0123456789abcdef01234567 refs/heads/main\n@refs/heads/main HEAD\n";
        let refs = parse_server_refs(body);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].1, "refs/heads/main");
    }

    // ── In-process integration over a UDP loopback pair ─────────────

    fn make_identity() -> PrivateIdentity {
        use rand::rngs::{StdRng, SysRng};
        let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();
        PrivateIdentity::new_from_rand(&mut rng)
    }

    fn make_transport(identity: PrivateIdentity) -> Transport {
        let mut tcfg = TransportConfig::new("rngit-helper-test", &identity, false);
        tcfg.set_respond_to_probes(true);
        Transport::new(tcfg)
    }

    fn git_in(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
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

    /// Grab an ephemeral UDP port, so tests using loopback UDP pairs do not
    /// collide when run in parallel.
    fn free_udp_port() -> u16 {
        use std::net::UdpSocket;
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = s.local_addr().unwrap().port();
        drop(s);
        port
    }

    /// Start an rngit server over a UDP loopback pair and return the
    /// server task, the destination hash and a connected client.
    async fn start_server(
        repos: &Path,
    ) -> (
        tokio::task::JoinHandle<()>,
        AddressHash,
        crate::client::Client,
    ) {
        let server_ident = make_identity();
        let client_ident = make_identity();

        let server_t = make_transport(server_ident.clone());
        let client_t = make_transport(client_ident.clone());

        let p1 = free_udp_port();
        let p2 = free_udp_port();
        let bind1 = format!("127.0.0.1:{p1}");
        let bind2 = format!("127.0.0.1:{p2}");

        let smgr = server_t.iface_manager();
        smgr.lock().await.spawn(
            UdpInterface::new(&bind1, Some(&bind2)),
            UdpInterface::spawn,
        );
        let cmgr = client_t.iface_manager();
        cmgr.lock().await.spawn(
            UdpInterface::new(&bind2, Some(&bind1)),
            UdpInterface::spawn,
        );

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

        let mut cfg = Cfg::default();
        cfg.repositories
            .insert("public".into(), repos.to_string_lossy().into_owned());
        cfg.access.insert(
            "public".into(),
            vec!["r:all".into(), "w:all".into(), "c:all".into()],
        );
        cfg.rngit.announce_interval = 0;
        let rngit = Rngit::new(cfg);
        let server_task = tokio::spawn(async move {
            let _ = rngit.run(server_t).await;
        });

        let client_t = Arc::new(client_t);
        let client = Client::connect(
            client_t.clone(),
            &client_ident,
            dest_hash,
            Duration::from_secs(30),
        )
        .await
        .expect("connect to server");
        (server_task, dest_hash, client)
    }

    /// Create `public/testrepo` through the server and push a commit into
    /// it, returning the head sha. Mirrors how a real repo is populated.
    async fn seed_repo(client: &mut Client, tmp: &Path) -> String {
        let ok = |resp: ClientResponse| matches!(resp, ClientResponse::Bytes(b) if b.first() == Some(&0x00));

        // Create the repository (grants the creator admin access).
        let create_data = Value::Map(vec![(Value::from(0i64), Value::from("public/testrepo"))]);
        let resp = client
            .request(PATH_CREATE, create_data, Duration::from_secs(30))
            .await
            .unwrap();
        assert!(ok(resp), "create should succeed");

        // Build a local repo with a commit and push it.
        let work = tmp.join("work");
        fs::create_dir_all(&work).unwrap();
        git_in(&work, &["init", "-b", "main"]);
        fs::write(work.join("hello.txt"), "hi\n").unwrap();
        git_in(&work, &["add", "."]);
        git_in(&work, &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-m", "init"]);
        let head_sha = git_in(&work, &["rev-parse", "HEAD"]).trim().to_string();

        let refs = gitutil::local_refs(&work).unwrap();
        let ref_names: Vec<String> = refs.iter().map(|(_, r)| r.clone()).collect();
        let push_tmp = gitutil::TempDir::new("rngit-helper-push").unwrap();
        let bundle_path = push_tmp.path().join("push.bundle");
        gitutil::create_push_bundle(&work, &bundle_path, &ref_names, &[]).unwrap();
        let bundle_bytes = fs::read(&bundle_path).unwrap();
        for refname in &ref_names {
            let data = Value::Map(vec![
                (Value::from(0i64), Value::from("public/testrepo")),
                (Value::from("local_ref"), Value::from(refname.as_str())),
                (Value::from("remote_ref"), Value::from(refname.as_str())),
                (Value::from("force"), Value::from(false)),
                (Value::from("bundle"), Value::Binary(bundle_bytes.clone())),
            ]);
            let resp = client
                .request(PATH_PUSH, data, Duration::from_secs(45))
                .await
                .unwrap();
            assert!(ok(resp), "push should succeed");
        }
        head_sha
    }

    /// The helper `list` output for a populated server repo must match the
    /// git remote helper ref list format (refs plus a HEAD symref).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn helper_list_roundtrip() {
        let _ = env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or("info"),
        )
        .is_test(true)
        .try_init();

        let tmp = gitutil::TempDir::new("rngit-helper-list").unwrap();
        let repos = tmp.path().join("repos");
        fs::create_dir_all(&repos).unwrap();

        let (server_task, dest_hash, mut client) = start_server(&repos).await;
        let head_sha = seed_repo(&mut client, tmp.path()).await;

        let mut h = Helper {
            hash: dest_hash,
            repo: "public/testrepo".into(),
            client: Some(client),
            dry_run: false,
            verbosity: 1,
            server_refs: Vec::new(),
        };
        let mut out = Vec::new();
        do_list(&mut h, false, &mut out).await.unwrap();
        let stdout = String::from_utf8(out).unwrap();
        assert!(
            stdout.contains(&format!("{head_sha} refs/heads/main")),
            "expected ref in list output: {stdout}"
        );
        assert!(
            stdout.contains("@refs/heads/main HEAD"),
            "expected HEAD symref in list output: {stdout}"
        );

        server_task.abort();
        let _ = server_task.await;
    }

    /// A fetched bundle must be indexable into a fresh object database
    /// without touching refs (the `fetch` capability contract).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn helper_fetch_indexes_into_object_db() {
        let _ = env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or("info"),
        )
        .is_test(true)
        .try_init();

        let tmp = gitutil::TempDir::new("rngit-helper-fetch").unwrap();
        let repos = tmp.path().join("repos");
        fs::create_dir_all(&repos).unwrap();

        let (server_task, _dest_hash, mut client) = start_server(&repos).await;
        let head_sha = seed_repo(&mut client, tmp.path()).await;

        // Request a fetch for refs/heads/main exactly as do_fetch would.
        let refs = vec![Value::Map(vec![(
            Value::from("ref"),
            Value::from("refs/heads/main"),
        )])];
        let data = Value::Map(vec![
            (Value::from(0i64), Value::from("public/testrepo")),
            (Value::from("refs"), Value::Array(refs)),
            (Value::from("have"), Value::Array(vec![])),
        ]);
        let resp = client
            .request(PATH_FETCH, data, Duration::from_secs(180))
            .await
            .unwrap();
        let bundle = match resp {
            ClientResponse::Resource(d) => {
                assert!(d.len() > 3);
                let meta_len =
                    ((d[0] as usize) << 16) | ((d[1] as usize) << 8) | d[2] as usize;
                d[3 + meta_len..].to_vec()
            }
            ClientResponse::Bytes(b) => {
                assert_eq!(b.first(), Some(&0x00), "unexpected inline fetch response");
                Vec::new()
            }
        };
        assert!(!bundle.is_empty(), "fetch bundle should not be empty");

        // Ingest the pack into a fresh bare repo; the commit must appear.
        let clone_dir = tmp.path().join("clone.git");
        git_in(&tmp.path(), &["init", "--bare", "clone.git"]);
        index_bundle_into(clone_dir.to_str().unwrap(), &bundle).unwrap();
        let cat = Command::new("git")
            .current_dir(&clone_dir)
            .args(["cat-file", "-t", &head_sha])
            .output()
            .unwrap();
        assert!(
            cat.status.success(),
            "fetched commit {} missing after index-pack",
            head_sha
        );

        server_task.abort();
        let _ = server_task.await;
    }

    /// Drive the whole helper loop with simulated git commands
    /// (capabilities, options, list) and verify the responses.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn helper_protocol_loop() {
        let _ = env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or("info"),
        )
        .is_test(true)
        .try_init();

        let tmp = gitutil::TempDir::new("rngit-helper-loop").unwrap();
        let repos = tmp.path().join("repos");
        fs::create_dir_all(&repos).unwrap();

        let (server_task, dest_hash, mut client) = start_server(&repos).await;
        let head_sha = seed_repo(&mut client, tmp.path()).await;

        let h = Helper {
            hash: dest_hash,
            repo: "public/testrepo".into(),
            client: Some(client),
            dry_run: false,
            verbosity: 1,
            server_refs: Vec::new(),
        };

        let (mut tx, rx) = tokio::io::duplex(1024 * 1024);
        let cmds = format!("capabilities\noption verbosity 2\noption depth 1\nlist\n\n");
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            tx.write_all(cmds.as_bytes()).await.unwrap();
            tx.shutdown().await.unwrap();
        });

        let mut out: Vec<u8> = Vec::new();
        run(h, tokio::io::BufReader::new(rx), &mut out)
            .await
            .unwrap();
        let stdout = String::from_utf8(out).unwrap();
        assert!(
            stdout.starts_with("fetch\npush\noption\n\n"),
            "unexpected capabilities: {stdout}"
        );
        assert!(stdout.contains("ok\n"), "verbosity option should be ok: {stdout}");
        assert!(
            stdout.contains("unsupported\n"),
            "depth option should be unsupported: {stdout}"
        );
        assert!(
            stdout.contains(&format!("{head_sha} refs/heads/main")),
            "expected ref in list output: {stdout}"
        );
        assert!(
            stdout.contains("@refs/heads/main HEAD"),
            "expected HEAD symref in list output: {stdout}"
        );

        server_task.abort();
        let _ = server_task.await;
    }
}