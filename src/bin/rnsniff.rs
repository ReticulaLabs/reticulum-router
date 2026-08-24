//! rnsniff — live rendering of Reticulum network announcements.
//!
//! Connects to the local Reticulum instance (or runs standalone over the
//! interfaces configured in the Reticulum config) and prints every announce
//! it hears: the destination, the endpoint type (e.g. a NomadNet website,
//! an rnsh shell server, or an rngit server), the announcing identity, the
//! hop count and any app data carried by the announce.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use rand::rngs::{StdRng, SysRng};
use rand::SeedableRng;

use reticulum_sdk::destination::DestinationName;
use reticulum_sdk::identity::PrivateIdentity;
use reticulum_sdk::iface::backbone::{BackboneClient, BackboneServer};
use reticulum_sdk::iface::tcp_client::TcpClient;
use reticulum_sdk::iface::tcp_server::TcpServer;
use reticulum_sdk::iface::udp::UdpInterface;
use reticulum_sdk::transport::{AnnounceEvent, Transport, TransportConfig};

#[path = "../config.rs"]
mod router_config;

const TOOL_NAME: &str = "rnsniff";

type RResult<T> = Result<T, Box<dyn std::error::Error>>;

macro_rules! bail {
    ($($arg:tt)*) => { return Err(format!($($arg)*).into()) };
}

/// Known application destinations mapped to a human-readable endpoint type.
/// The announce only carries a truncated hash of `app.aspect`, so a known
/// name is recognized by recomputing that hash.
const KNOWN_ENDPOINTS: &[(&str, &str, &str)] = &[
    ("nomadnetwork", "node", "nomadnetwork website"),
    ("nomadnetwork", "conversation", "nomadnetwork conversation"),
    ("nomadnetwork", "attachments", "nomadnetwork attachments"),
    ("nomadnetwork", "gossip", "nomadnetwork gossip"),
    ("lxmf", "delivery", "lxmf delivery"),
    ("lxmf", "propagation", "lxmf propagation node"),
    ("rrc", "hub", "rrc relay chat hub"),
    ("rnsh", "", "rnsh shell server"),
    ("git", "repositories", "rngit server"),
    ("rnperf", "", "rnperf bandwidth test"),
];

struct Args {
    identity: Option<String>,
    verbose: bool,
    json: bool,
    once: Option<usize>,
}

fn parse_args() -> RResult<Args> {
    let mut a = Args {
        identity: None,
        verbose: false,
        json: false,
        once: None,
    };
    let mut it = env::args().skip(1).peekable();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "--version" => {
                println!("rnsniff {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-i" | "--identity" => {
                a.identity = Some(next_val(&mut it, &arg)?);
            }
            "-v" | "--verbose" => {
                a.verbose = true;
            }
            "-j" | "--json" => {
                a.json = true;
            }
            "--once" => {
                let v = next_val(&mut it, "--once")?;
                a.once = Some(v.parse().map_err(|_| "bad --once count")?);
            }
            _ => bail!("unrecognized: {arg}"),
        }
    }
    Ok(a)
}

fn next_val<I: Iterator<Item = String>>(it: &mut std::iter::Peekable<I>, f: &str) -> RResult<String> {
    it.next().ok_or_else(|| format!("{f} needs a value").into())
}

fn print_help() {
    eprintln!("rnsniff - render live Reticulum network announcements\n");
    eprintln!("Usage: rnsniff [options]\n");
    eprintln!("Options:");
    eprintln!("  -i, --identity <path>     Identity file (default: ~/.config/rnsniff/rnsniff)");
    eprintln!("  -v, --verbose             Show radio metadata (SNR/RSSI)");
    eprintln!("  -j, --json                Emit one JSON object per announcement");
    eprintln!("  --once <n>                Exit after <n> announcements");
    eprintln!("  --version                 Show version");
    eprintln!("  -h, --help                Show this help");
}

// ── Identity and transport ──────────────────────────────────────────

fn rnsniff_dir() -> PathBuf {
    dirs::home_dir().unwrap().join(".config/rnsniff")
}

fn ident_path() -> PathBuf {
    rnsniff_dir().join(TOOL_NAME)
}

fn load_identity(path: Option<&str>) -> RResult<PrivateIdentity> {
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
        return PrivateIdentity::new_from_hex_string(&hex)
            .map_err(|e| format!("bad identity {pb:?}: {e:?}").into());
    }
    let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();
    let id = PrivateIdentity::new_from_rand(&mut rng);
    if let Some(p) = pb.parent() {
        fs::create_dir_all(p)?;
    }
    let hex = format!("{}\n", id.to_hex_string());
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&pb)?;
        f.write_all(hex.as_bytes())?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&pb, hex)?;
    }
    log::info!("rnsniff: created identity at {pb:?}");
    Ok(id)
}

async fn make_transport(id: PrivateIdentity) -> RResult<Transport> {
    let mut tcfg = TransportConfig::new("rnsniff", &id, false);
    tcfg.set_respond_to_probes(true);
    tcfg.set_rpc_instance(true);
    let t = Transport::new(tcfg);
    let on_rpc = t.rpc_connected().await;
    let mgr = t.iface_manager();

    if on_rpc {
        log::info!("rnsniff: connected to local reticulum instance over rpc");
        return Ok(t);
    }

    // Load explicit interfaces from the Reticulum config only when running
    // standalone (no rpc instance).
    if let Some(path) = router_config::Config::find_existing() {
        match router_config::Config::from_file(&path) {
            Ok(cfg) => {
                log::info!("rnsniff: loading interfaces from {}", path.display());
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
                                _ => log::warn!("rnsniff: skipping invalid backbone interface"),
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
                            log::warn!("rnsniff: AutoInterface unsupported")
                        }
                        _ => log::warn!("rnsniff: skipping unsupported interface"),
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            Err(e) => log::warn!("rnsniff: could not load Reticulum config: {e}"),
        }
    } else {
        log::warn!("rnsniff: no Reticulum config found; running with no interfaces");
    }

    Ok(t)
}

// ── Rendering ───────────────────────────────────────────────────────

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Result of classifying a destination's endpoint.
struct EndpointInfo {
    label: String,
    /// Reachable endpoint address, when the announce advertises one.
    address: Option<String>,
    /// True when the label was inferred from announce app data rather than
    /// matched against a known destination name.
    guessed: bool,
}

/// Human-readable label for a destination, considering both the name hash
/// and any announce app data.
///
/// Some newer services announce under a destination name that is not yet in
/// the known table (or is private), but carry a JSON descriptor in their
/// announce app data that identifies the service.
fn endpoint_type(name_hash: &[u8], app_data: &[u8]) -> EndpointInfo {
    for (app, aspect, label) in KNOWN_ENDPOINTS {
        if DestinationName::new(app, aspect).as_name_hash_slice() == name_hash {
            return EndpointInfo {
                label: label.to_string(),
                address: None,
                guessed: false,
            };
        }
    }
    if let Some((label, addr)) = endpoint_from_app_data(app_data) {
        return EndpointInfo {
            label: label.to_string(),
            address: addr,
            guessed: true,
        };
    }
    EndpointInfo {
        label: format!("unknown endpoint ({})", hex(name_hash)),
        address: None,
        guessed: false,
    }
}

/// Identify a service from its announce app data when the name hash does
/// not match a known application name. Returns a label and, when the
/// announce advertises one, a reachable endpoint address.
///
/// Known descriptors:
/// - rngit: `{"v":"<version>","rngit":"<hash>","repos":["<repo>", ...]}`
/// - reachable TCP endpoint:
///   `{"v":1,"h":"<host>","p":<port>,"x":<timestamp>}`
/// - presence beacon: plain text such as `presence-full`, `presence-lite`
fn endpoint_from_app_data(app_data: &[u8]) -> Option<(&'static str, Option<String>)> {
    let s = std::str::from_utf8(app_data).ok()?;
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(s) {
        if let Some(obj) = value.as_object() {
            if obj.contains_key("rngit") && obj.contains_key("repos") {
                return Some(("rngit server", None));
            }
            if let (Some(host), Some(port)) = (
                obj.get("h").and_then(|v| v.as_str()),
                obj.get("p").and_then(|v| v.as_u64()),
            ) {
                return Some(("reachable TCP endpoint", Some(format!("{host}:{port}"))));
            }
        }
    }
    // Presence beacons announce a plain-text presence level.
    let trimmed = s.trim();
    if !trimmed.is_empty()
        && trimmed.len() <= 32
        && trimmed.to_ascii_lowercase().starts_with("presence")
    {
        return Some(("presence beacon", None));
    }
    None
}

/// Render app data as text when it is valid UTF-8, otherwise as hex.
fn app_data_str(app_data: &[u8]) -> String {
    match std::str::from_utf8(app_data) {
        Ok(s) if !s.chars().any(|c| c.is_control()) => s.to_string(),
        _ => hex(app_data),
    }
}

/// Local wall-clock time (HH:MM:SS) for the announce banner.
fn now_str() -> String {
    unsafe {
        let mut t: libc::time_t = 0;
        libc::time(&mut t);
        let tm = libc::localtime(&t);
        if tm.is_null() {
            return "--:--:--".to_string();
        }
        let tm = *tm;
        format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
    }
}

async fn render(ev: &AnnounceEvent, a: &Args, out: &mut impl Write) -> io::Result<()> {
    let dest = ev.destination.lock().await;
    let addr = dest.desc.address_hash.to_hex_string();
    let ident = dest.desc.identity.address_hash.to_hex_string();
    let app_data = app_data_str(ev.app_data.as_slice());
    let endpoint = endpoint_type(dest.desc.name.as_name_hash_slice(), ev.app_data.as_slice());
    let guessed_suffix = if endpoint.guessed {
        " (guessed from app data)"
    } else {
        ""
    };
    let hops = ev.hops;

    if a.json {
        let mut obj = serde_json::Map::new();
        obj.insert("time".into(), serde_json::Value::String(now_str()));
        obj.insert("destination".into(), serde_json::Value::String(addr));
        obj.insert(
            "endpoint".into(),
            serde_json::Value::String(format!("{}{}", endpoint.label, guessed_suffix)),
        );
        obj.insert("identity".into(), serde_json::Value::String(ident));
        obj.insert("hops".into(), serde_json::Value::from(hops));
        if let Some(ea) = &endpoint.address {
            obj.insert(
                "endpoint_address".into(),
                serde_json::Value::String(format!("{ea}{guessed_suffix}")),
            );
        }
        if !app_data.is_empty() {
            obj.insert("app_data".into(), serde_json::Value::String(app_data));
        }
        if a.verbose {
            if let Some(snr) = ev.snr {
                obj.insert("snr".into(), serde_json::Value::from(snr));
            }
            if let Some(rssi) = ev.rssi {
                obj.insert("rssi".into(), serde_json::Value::from(rssi));
            }
        }
        writeln!(out, "{}", serde_json::Value::Object(obj))
    } else {
        writeln!(out, "── {} ──", now_str())?;
        writeln!(out, "  Destination : {addr}")?;
        writeln!(out, "  Endpoint    : {}{guessed_suffix}", endpoint.label)?;
        if let Some(ea) = &endpoint.address {
            writeln!(out, "  Endpoint    : {ea}{guessed_suffix}")?;
        }
        writeln!(out, "  Identity    : {ident}")?;
        writeln!(out, "  Hops        : {hops}")?;
        if !app_data.is_empty() {
            writeln!(out, "  App data    : {app_data}")?;
        }
        if a.verbose {
            if let Some(snr) = ev.snr {
                writeln!(out, "  SNR         : {snr} dB")?;
            }
            if let Some(rssi) = ev.rssi {
                writeln!(out, "  RSSI        : {rssi} dBm")?;
            }
        }
        writeln!(out)
    }
}

// ── Main loop ───────────────────────────────────────────────────────

async fn sniff(a: &Args) -> RResult<()> {
    let ident = load_identity(a.identity.as_deref())?;
    let transport = make_transport(ident).await?;
    let stdout = io::stdout();
    let mut out = stdout.lock();
    run_sniffer(a, transport, &mut out).await
}

async fn run_sniffer(a: &Args, transport: Transport, out: &mut impl Write) -> RResult<()> {
    let mut rx = transport.recv_announces().await;

    writeln!(out, "rnsniff: listening for Reticulum announcements...")?;
    writeln!(out)?;
    out.flush().ok();

    let mut count = 0usize;
    loop {
        match rx.recv().await {
            Ok(ev) => {
                render(&ev, a, out).await?;
                out.flush().ok();
                count += 1;
                if let Some(n) = a.once
                    && count >= n
                {
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                log::warn!("rnsniff: missed {n} announcements");
                continue;
            }
            Err(_) => break,
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let a = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("rnsniff: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = sniff(&a).await {
        eprintln!("rnsniff: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::rngs::{StdRng, SysRng};
    use std::time::Duration;

    fn name_hash(app: &str, aspect: &str) -> Vec<u8> {
        DestinationName::new(app, aspect).as_name_hash_slice().to_vec()
    }

    #[test]
    fn known_endpoint_types() {
        assert_eq!(endpoint_type(&name_hash("git", "repositories"), b"").label, "rngit server");
        assert_eq!(endpoint_type(&name_hash("rnsh", ""), b"").label, "rnsh shell server");
        assert_eq!(endpoint_type(&name_hash("nomadnetwork", "node"), b"").label, "nomadnetwork website");
        assert_eq!(endpoint_type(&name_hash("nomadnetwork", "conversation"), b"").label, "nomadnetwork conversation");
        assert_eq!(endpoint_type(&name_hash("nomadnetwork", "gossip"), b"").label, "nomadnetwork gossip");
        assert_eq!(endpoint_type(&name_hash("lxmf", "delivery"), b"").label, "lxmf delivery");
        assert_eq!(endpoint_type(&name_hash("lxmf", "propagation"), b"").label, "lxmf propagation node");
        assert_eq!(endpoint_type(&name_hash("rrc", "hub"), b"").label, "rrc relay chat hub");
        assert_eq!(endpoint_type(&name_hash("rnperf", ""), b"").label, "rnperf bandwidth test");
        // Matches by known name hash are not guesses.
        assert!(!endpoint_type(&name_hash("git", "repositories"), b"").guessed);
    }

    #[test]
    fn unknown_endpoint_type() {
        let unknown = name_hash("someapp", "aspect");
        let info = endpoint_type(&unknown, b"");
        assert!(info.label.starts_with("unknown endpoint ("), "got: {}", info.label);
        assert!(info.label.contains(&hex(&unknown)));
        assert!(info.address.is_none());
        assert!(!info.guessed);
    }

    #[test]
    fn rngit_detected_via_app_data() {
        // A newer rngit server announces under a name hash that is not
        // "git.repositories" but carries a JSON service descriptor.
        let app_data = br#"{"v":"0.0.0","rngit":"afed52d300a075ea0e37f09139acbad3","repos":["resilum-core","resilum-mobile"]}"#;
        let unknown = name_hash("someapp", "aspect");
        let info = endpoint_type(&unknown, app_data);
        assert_eq!(info.label, "rngit server");
        assert!(info.guessed);
        // A non-descriptor announce stays unknown.
        assert!(endpoint_type(&unknown, b"hello").label.starts_with("unknown endpoint"));
    }

    #[test]
    fn reachable_tcp_endpoint_detected() {
        // A node advertising direct TCP reachability.
        let app_data = br#"{"v":1,"h":"174.17.254.246","p":47321,"x":1787604250}"#;
        let unknown = name_hash("someapp", "aspect");
        let info = endpoint_type(&unknown, app_data);
        assert_eq!(info.label, "reachable TCP endpoint");
        assert_eq!(info.address.as_deref(), Some("174.17.254.246:47321"));
        assert!(info.guessed);
    }

    #[test]
    fn presence_beacon_detected() {
        let app_data = b"presence-full";
        let unknown = name_hash("someapp", "aspect");
        let info = endpoint_type(&unknown, app_data);
        assert_eq!(info.label, "presence beacon");
        assert!(info.guessed);
        // Non-presence plain text stays unknown.
        assert!(endpoint_type(&unknown, b"hello").label.starts_with("unknown endpoint"));
    }

    #[test]
    fn app_data_rendering() {
        assert_eq!(app_data_str(b"mynode"), "mynode");
        assert_eq!(app_data_str(&[0xff, 0x00, 0x01]), "ff0001");
        assert_eq!(app_data_str(b""), "");
    }

    // ── Integration over a UDP loopback pair ────────────────────────

    fn make_identity() -> PrivateIdentity {
        let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();
        PrivateIdentity::new_from_rand(&mut rng)
    }

    fn make_transport(identity: PrivateIdentity) -> Transport {
        let mut tcfg = TransportConfig::new("rnsniff-test", &identity, false);
        tcfg.set_respond_to_probes(true);
        Transport::new(tcfg)
    }

    fn free_udp_port() -> u16 {
        use std::net::UdpSocket;
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = s.local_addr().unwrap().port();
        drop(s);
        port
    }

    /// A destination announced by the server must be rendered with the
    /// matching endpoint type by the sniffer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sniff_renders_announce() {
        let _ = env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or("info"),
        )
        .is_test(true)
        .try_init();

        let server_ident = make_identity();
        let client_ident = make_identity();
        let server_t = make_transport(server_ident.clone());
        let client_t = make_transport(client_ident.clone());

        let p1 = free_udp_port();
        let p2 = free_udp_port();
        let bind1 = format!("127.0.0.1:{p1}");
        let bind2 = format!("127.0.0.1:{p2}");

        let smgr = server_t.iface_manager();
        smgr.lock()
            .await
            .spawn(
                UdpInterface::new(&bind1, Some(&bind2)),
                UdpInterface::spawn,
            );
        let cmgr = client_t.iface_manager();
        cmgr.lock()
            .await
            .spawn(
                UdpInterface::new(&bind2, Some(&bind1)),
                UdpInterface::spawn,
            );

        // Server: announce an rngit repository destination.
        let mut server_t = server_t;
        let dest = server_t
            .add_destination(server_ident.clone(), DestinationName::new("git", "repositories"))
            .await;
        let dest_hash = dest.lock().await.desc.address_hash.to_hex_string();
        let server_task = tokio::spawn(async move {
            for _ in 0..5 {
                server_t.send_announce(&dest, None).await;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });

        // Client: sniff one announce and capture the rendering.
        let a = Args {
            identity: None,
            verbose: true,
            json: false,
            once: Some(1),
        };
        let mut out = Vec::new();
        run_sniffer(&a, client_t, &mut out)
            .await
            .expect("sniffer should run");
        let stdout = String::from_utf8(out).unwrap();
        assert!(
            stdout.contains(&dest_hash),
            "expected destination in output: {stdout}"
        );
        assert!(
            stdout.contains("rngit server"),
            "expected endpoint type in output: {stdout}"
        );

        server_task.abort();
        let _ = server_task.await;
    }
}
