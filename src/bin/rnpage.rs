use std::collections::HashMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rand::rngs::OsRng;
use reticulum_sdk::destination::link::LinkEvent;
use reticulum_sdk::destination::DestinationName;
use reticulum_sdk::hash::AddressHash;
use reticulum_sdk::identity::PrivateIdentity;
use reticulum_sdk::transport::{Transport, TransportConfig};
use rmpv::Value;
use sha2::{Digest, Sha256};

const APP_NAME: &str = "nomadnetwork";
const APP_ASPECT: &str = "node";
const TOOL_NAME: &str = "rnpage";

type RResult<T> = Result<T, Box<dyn std::error::Error>>;

macro_rules! bail {
    ($($arg:tt)*) => { return Err(format!($($arg)*).into()) };
}

#[derive(serde::Deserialize)]
struct Cfg {
    #[serde(default)]
    interfaces: Vec<CfgIface>,
}

#[derive(serde::Deserialize)]
struct CfgIface {
    #[serde(default)]
    name: String,
    #[serde(default = "yes")]
    enabled: bool,
    #[serde(flatten)]
    config: CfgIfaceType,
}

#[derive(serde::Deserialize)]
#[serde(tag = "type")]
enum CfgIfaceType {
    TCPServerInterface { #[serde(alias = "listen_ip")] bind_host: String, #[serde(default = "p4242", alias = "listen_port")] bind_port: u16 },
    TCPClientInterface { target_host: String, #[serde(default = "p4242")] target_port: u16 },
    UDPInterface { listen_ip: String, #[serde(default = "p4242")] listen_port: u16, forward_ip: String, forward_port: u16 },
    AutoInterface {},
    #[serde(other)]
    Unsupported,
}

fn yes() -> bool { true }
fn p4242() -> u16 { 4242 }

fn reticulum_cfg_dir() -> PathBuf {
    dirs::home_dir().unwrap().join(".config/reticulum")
}

fn rnpage_dir() -> PathBuf {
    dirs::home_dir().unwrap().join(".config/rnpage")
}

fn public_dir() -> PathBuf {
    rnpage_dir().join("public")
}

fn load_cfg() -> Option<Cfg> {
    let f = reticulum_cfg_dir().join("config.toml");
    if !f.exists() { return None; }
    let s = fs::read_to_string(&f).ok()?;
    toml::from_str(&s).ok()
}

fn ident_path() -> PathBuf {
    rnpage_dir().join(TOOL_NAME)
}

fn load_ident(path: Option<&str>) -> RResult<PrivateIdentity> {
    if let Some(p) = path {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            let hex = fs::read_to_string(&pb)?.trim().to_string();
            return PrivateIdentity::new_from_hex_string(&hex)
                .map_err(|e| format!("bad identity {pb:?}: {e:?}").into());
        }
        bail!("identity not found: {p}");
    }
    let pb = ident_path();
    if pb.is_file() {
        let hex = fs::read_to_string(&pb)?.trim().to_string();
        let id = PrivateIdentity::new_from_hex_string(&hex)
            .map_err(|e| format!("bad identity {pb:?}: {e:?}"))?;
        return Ok(id);
    }
    let id = PrivateIdentity::new_from_rand(OsRng);
    if let Some(p) = pb.parent() { fs::create_dir_all(p)?; }
    let hex = format!("{}\n", id.to_hex_string());
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&pb)?;
        f.write_all(hex.as_bytes())?;
        f.sync_all()?;
    }
    Ok(id)
}

async fn make_transport(id: PrivateIdentity) -> RResult<Transport> {
    let mut tcfg = TransportConfig::new(TOOL_NAME, &id, false);
    tcfg.set_respond_to_probes(true);
    tcfg.set_share_instance(true);
    let t = Transport::new(tcfg);
    let on_shared = t.is_connected_to_shared_instance().await;
    let mgr = t.iface_manager();

    if on_shared {
        return Ok(t);
    }

    if let Some(cfg) = load_cfg() {
        for iface in &cfg.interfaces {
            if !iface.enabled { continue; }
            match &iface.config {
                CfgIfaceType::TCPServerInterface { bind_host, bind_port } => {
                    let a = format!("{bind_host}:{bind_port}");
                    let _ = mgr.lock().await.spawn(
                        reticulum_sdk::iface::tcp_server::TcpServer::new(a, mgr.clone()),
                        reticulum_sdk::iface::tcp_server::TcpServer::spawn,
                    );
                }
                CfgIfaceType::TCPClientInterface { target_host, target_port } => {
                    let a = format!("{target_host}:{target_port}");
                    let _ = mgr.lock().await.spawn(
                        reticulum_sdk::iface::tcp_client::TcpClient::new(a),
                        reticulum_sdk::iface::tcp_client::TcpClient::spawn,
                    );
                }
                CfgIfaceType::UDPInterface { listen_ip, listen_port, forward_ip, forward_port } => {
                    let b = format!("{listen_ip}:{listen_port}");
                    let f = format!("{forward_ip}:{forward_port}");
                    let _ = mgr.lock().await.spawn(
                        reticulum_sdk::iface::udp::UdpInterface::new(b, Some(f)),
                        reticulum_sdk::iface::udp::UdpInterface::spawn,
                    );
                }
                CfgIfaceType::AutoInterface {} => (),
                CfgIfaceType::Unsupported => (),
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    Ok(t)
}

fn compute_path_hash(path: &str) -> AddressHash {
    let mut hasher = Sha256::new();
    hasher.update(path.as_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&result[..16]);
    AddressHash::new(hash)
}

type PageMap = HashMap<AddressHash, PathBuf>;

fn scan_pages(dir: &Path, prefix: &str, pages: &mut PageMap) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if name_str.starts_with('.') {
            continue;
        }

        if path.is_dir() {
            let sub = if prefix.is_empty() {
                format!("{}/", name_str)
            } else {
                format!("{}{}/", prefix, name_str)
            };
            scan_pages(&path, &sub, pages);
        } else if path.is_file() && !name_str.ends_with(".allowed") {
            let rel_path = format!("{}{}", prefix, name_str);
            let request_path = format!("/page/{}", rel_path);
            let hash = compute_path_hash(&request_path);
            pages.insert(hash, path);
        }
    }
}

fn load_page_map() -> PageMap {
    let dir = public_dir();
    let mut pages = PageMap::new();
    if dir.exists() {
        scan_pages(&dir, "", &mut pages);
    } else {
        let _ = fs::create_dir_all(&dir);
    }
    pages
}

fn serve_file(path: &Path) -> Vec<u8> {
    match fs::read(path) {
        Ok(data) => data,
        Err(_) => Vec::new(),
    }
}

async fn listener(node_name: &str) -> RResult<()> {
    let ident = load_ident(None)?;
    let mut transport = make_transport(ident.clone()).await?;

    let dest = transport.add_destination(ident.clone(), DestinationName::new(APP_NAME, APP_ASPECT)).await;
    let dest_hash = dest.lock().await.desc.address_hash;
    let ident_hash = ident.address_hash().to_hex_string();

    let page_map = load_page_map();
    let page_count = page_map.len();
    let default_index_hash = compute_path_hash("/page/index.mu");
    let app_data = if node_name.is_empty() { None } else { Some(node_name.as_bytes()) };

    println!("Identity     : {}", ident_hash);
    println!("Listening on : {}", dest_hash.to_hex_string());
    println!("Node name    : {}", if node_name.is_empty() { "rnpage" } else { node_name });
    println!("Serving from : {}", public_dir().display());
    println!("Pages loaded : {}", page_count);

    for _ in 0..5 {
        transport.send_announce(&dest, app_data).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let transport = Arc::new(transport);
    let mut in_ev = transport.in_link_events();

    let at = transport.clone();
    let ad = dest.clone();
    let announce_data = if node_name.is_empty() { None } else { Some(node_name.to_string()) };
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            at.send_announce(&ad, announce_data.as_deref().map(|s| s.as_bytes())).await;
        }
    });

    loop {
        match in_ev.recv().await {
            Ok(ev) => {
                match ev.event {
                    LinkEvent::Request(request) => {
                        let content =
                            if let Some(path) = page_map.get(&request.path_hash) {
                                serve_file(path)
                            } else if request.path_hash == default_index_hash {
                                b">rnpage\n\nThis rnpage server is running, but no pages are available yet.\n".to_vec()
                            } else {
                                b">404 Not Found\n\nThe requested page was not found.\n".to_vec()
                            };

                        if !content.is_empty() {
                            let data = Value::Binary(content);
                            transport.link_response(ev.id, request.request_id, data).await.ok();
                        }
                    }
                    LinkEvent::Activated => {
                        log::info!("rnpage: inbound link {}", ev.id);
                    }
                    LinkEvent::Closed => {
                        log::info!("rnpage: link closed {}", ev.id);
                    }
                    _ => {}
                }
            }
            Err(e) => {
                log::error!("rnpage: event error: {e:?}");
                break;
            }
        }
    }

    Ok(())
}

fn print_help() {
    eprintln!("rnpage - NomadNet Page Server\n");
    eprintln!("Usage: rnpage [options]\n");
    eprintln!("Options:");
    eprintln!("  -n, --name <name>         Node name (shown in NomadNet)");
    eprintln!("  -i, --identity <path>     Identity file");
    eprintln!("  -p, --print-identity      Print identity and exit");
    eprintln!("  -v, --verbose             Verbose output");
    eprintln!("  -q, --quiet               Quiet output");
    eprintln!("  --version                 Print version and exit");
    eprintln!("  -h, --help                Show this help\n");
    eprintln!("Serves pages from: ~/.config/rnpage/public/");
    eprintln!("Compatible with NomadNet page protocol.");
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    let mut ident_path_arg = None;
    let mut print_ident = false;
    let mut node_name = String::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => { print_help(); return; }
            "--version" => { println!("rnpage {}", env!("CARGO_PKG_VERSION")); return; }
            "-n" | "--name" => {
                i += 1;
                node_name = args.get(i).cloned().unwrap_or_default();
            }
            "-i" | "--identity" => {
                i += 1;
                ident_path_arg = args.get(i).cloned();
            }
            "-p" | "--print-identity" => { print_ident = true; }
            "-v" | "--verbose" => {}
            "-q" | "--quiet" => {}
            _ => { eprintln!("rnpage: unrecognized: {}", args[i]); std::process::exit(1); }
        }
        i += 1;
    }

    if print_ident {
        match load_ident(ident_path_arg.as_deref()) {
            Ok(id) => {
                let name_hash = Sha256::new()
                    .chain_update(b"nomadnetwork.node")
                    .finalize();
                let mut addr_material = name_hash[..10].to_vec();
                addr_material.extend_from_slice(id.address_hash().as_slice());
                let dest_hash = Sha256::new()
                    .chain_update(&addr_material)
                    .finalize();
                let mut addr = [0u8; 16];
                addr.copy_from_slice(&dest_hash[..16]);
                let addr_hash = AddressHash::new(addr);

                println!("Identity     : {}", id.address_hash().to_hex_string());
                println!("Listening on : {}", addr_hash.to_hex_string());
            }
            Err(e) => { eprintln!("rnpage: {e}"); std::process::exit(1); }
        }
        return;
    }

    if let Err(e) = listener(&node_name).await {
        eprintln!("rnpage: {e}");
        std::process::exit(1);
    }
}
