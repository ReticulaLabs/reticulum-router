use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::rngs::{StdRng, SysRng};
use rand::SeedableRng;
use reticulum_sdk::destination::link::{Link, LinkEvent};
use reticulum_sdk::destination::{DestinationName, DestinationDesc};
use reticulum_sdk::hash::ADDRESS_HASH_SIZE;
use reticulum_sdk::identity::{Identity, PrivateIdentity};
use reticulum_sdk::transport::{Transport, TransportConfig};
use rmpv::{Value, decode::read_value, encode::write_value};
use tokio::sync::Mutex;

const APP_NAME: &str = "rnperf";
const PROTOCOL_VERSION: u8 = 1;
const MSG_MAGIC: u16 = 0xAC;

const MSG_TYPE_VERSION: u16 = msg_type(1);
const MSG_TYPE_TEST_CONFIG: u16 = msg_type(2);
const MSG_TYPE_DATA: u16 = msg_type(3);
const MSG_TYPE_RESULT: u16 = msg_type(4);
const MSG_TYPE_ERROR: u16 = msg_type(5);

const DEFAULT_DURATION: f64 = 10.0;

type RResult<T> = Result<T, Box<dyn std::error::Error>>;

macro_rules! bail {
    ($($arg:tt)*) => { return Err(format!($($arg)*).into()) };
}

const fn msg_type(id: u8) -> u16 {
    ((MSG_MAGIC as u16) << 8) | (id as u16)
}

// ── Args ────────────────────────────────────────────────────────────

struct Args {
    listen: bool,
    duration: f64,
    packet_size: Option<usize>,
    verbose: u8,
    dest: Option<String>,
    remote_identity: Option<String>,
    announce_interval: Option<u64>,
    rate: f64,
}

impl Args {
    fn empty() -> Self {
        Args {
            listen: false,
            duration: DEFAULT_DURATION,
            packet_size: None,
            verbose: 0,
            dest: None,
            remote_identity: None,
            announce_interval: None,
            rate: 5_000_000_000.0,
        }
    }
}

fn parse_args() -> RResult<Args> {
    let raw: Vec<String> = env::args().skip(1).collect();
    let mut a = Args::empty();
    let mut it = raw.into_iter().peekable();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => { print_help(); std::process::exit(0); }
            "--version" => {
                println!("rnperf {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-l" | "--listen" => { a.listen = true; }
            "-d" | "--duration" => {
                let v = next_val(&mut it, &arg)?;
                a.duration = v.parse::<f64>().map_err(|_| "bad duration")?;
            }
            "-s" | "--size" => {
                let v = next_val(&mut it, &arg)?;
                a.packet_size = Some(v.parse::<usize>().map_err(|_| "bad packet size")?);
            }
            "-b" | "--announce" => {
                let v = next_val(&mut it, &arg)?;
                a.announce_interval = Some(v.parse::<u64>().map_err(|_| "bad announce interval")?);
            }
            "-R" | "--remote-identity" => {
                a.remote_identity = Some(next_val(&mut it, &arg)?);
            }
            "-r" | "--rate" => {
                let v = next_val(&mut it, &arg)?;
                a.rate = v.parse::<f64>().map_err(|_| "bad rate")?;
            }
            "-v" | "--verbose" => { a.verbose += 1; }
            _ if arg.starts_with('-') => { bail!("unrecognized: {arg}") }
            _ => {
                if a.dest.is_some() { bail!("unexpected: {arg}"); }
                a.dest = Some(arg);
            }
        }
    }
    Ok(a)
}

fn next_val<I: Iterator<Item = String>>(it: &mut std::iter::Peekable<I>, f: &str) -> Result<String, String> {
    it.next().ok_or_else(|| format!("{f} needs a value"))
}

fn print_help() {
    eprintln!("Reticulum Bandwidth Measurement Utility\n");
    eprintln!("Usage: rnperf [options] [destination]\n");
    eprintln!("Listener:");
    eprintln!("  -l, --listen              Listen mode");
    eprintln!("  -b, --announce <sec>      Re-announce interval (default: no periodic announce)\n");
    eprintln!("Initiator:");
    eprintln!("  <destination>             Target destination hash to test\n");
    eprintln!("Options:");
    eprintln!("  -d, --duration <sec>      Test duration in seconds (default: {DEFAULT_DURATION})");
    eprintln!("  -s, --size <bytes>        Packet payload size (default: MDU)");
    eprintln!("  -R, --remote-identity <hash>  Listener's public identity hash (hex)");
    eprintln!("  -r, --rate <bps>          Target send rate in bits/sec (default: 5G)");
    eprintln!("  -v, --verbose             Verbose output");
    eprintln!("  --version                 Show version");
    eprintln!("  -h, --help                Help");
}

// ── Identity ────────────────────────────────────────────────────────

fn rnperf_dir() -> PathBuf {
    dirs::home_dir().unwrap().join(".config/rnperf")
}

fn load_ident() -> RResult<PrivateIdentity> {
    let pb = rnperf_dir().join(APP_NAME);
    if pb.is_file() {
        let hex = fs::read_to_string(&pb)?.trim().to_string();
        let id = PrivateIdentity::new_from_hex_string(&hex)
            .map_err(|e| format!("bad identity {pb:?}: {e:?}"))?;
        log::info!("rnperf: loaded identity from {pb:?}");
        return Ok(id);
    }
    let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();
    let id = PrivateIdentity::new_from_rand(&mut rng);
    if let Some(p) = pb.parent() { fs::create_dir_all(p)?; }
    let hex = format!("{}\n", id.to_hex_string());
    {
        let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&pb)?;
        f.write_all(hex.as_bytes())?;
        f.sync_all()?;
    }
    log::info!("rnperf: created identity at {pb:?}");
    Ok(id)
}

// ── Transport ───────────────────────────────────────────────────────

async fn make_transport(id: PrivateIdentity) -> RResult<Transport> {
    let mut tcfg = TransportConfig::new(APP_NAME, &id, false);
    tcfg.set_respond_to_probes(true);
    tcfg.set_rpc_instance(true);
    // Allow overriding the RPC data/control ports for testing against a
    // non-default local instance (e.g. a second router on the same host).
    if let Ok(port) = std::env::var("RNPERF_RPC_PORT") {
        let port: u16 = port.parse().map_err(|_| "bad RNPERF_RPC_PORT")?;
        tcfg.set_rpc_data_port(port);
        tcfg.set_rpc_control_port(port + 1);
    }
    let t = Transport::new(tcfg);
    let on_rpc = t.rpc_connected().await;
    if on_rpc {
        log::info!("rnperf: connected to local reticulum instance over rpc");
        return Ok(t);
    }
    bail!("could not connect to local reticulum instance over rpc (is reticulum-router running?)");
}

// ── Protocol helpers ────────────────────────────────────────────────

async fn send_channel(
    link: &Arc<Mutex<Link>>, transport: &Transport, msg_type: u16, payload: &[u8],
) -> RResult<()> {
    let packet = link.lock().await.channel_raw_packet(msg_type, payload)?;
    transport.send_packet(packet).await;
    Ok(())
}

/// Send the listener's test statistics back to the initiator as a
/// `MSG_TYPE_RESULT` channel message.
async fn send_result_message(
    link: &Arc<Mutex<Link>>,
    transport: &Transport,
    test_duration: f64,
    bytes_received: u64,
    packets_received: u64,
    first_data_time: Option<Instant>,
) -> RResult<()> {
    let recv_duration_ns = match first_data_time {
        Some(t0) => Instant::now().duration_since(t0).as_nanos() as u64,
        None => Duration::from_secs_f64(test_duration).as_nanos() as u64,
    };
    let result = pack_result(bytes_received, packets_received, recv_duration_ns);
    send_channel(link, transport, MSG_TYPE_RESULT, &result).await?;
    Ok(())
}

/// Drain and discard any pending out-link events (message proofs). The
/// transport posts a `LinkEvent::Proof` for every packet the peer
/// acknowledges; rnperf does not consume those, and leaving them unread
/// during the high-rate data phase overflows the link event channel.
fn drain_out_link_events(
    recv: &mut tokio::sync::broadcast::Receiver<reticulum_sdk::destination::link::LinkEventData>,
) {
    loop {
        match recv.try_recv() {
            Ok(_) => {}
            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => {}
            Err(_) => break,
        }
    }
}

fn pack_version() -> Vec<u8> {
    let v = Value::Array(vec![
        Value::from(env!("CARGO_PKG_VERSION")),
        Value::from(PROTOCOL_VERSION as i64),
    ]);
    let mut b = Vec::new();
    write_value(&mut b, &v).ok();
    b
}

fn unpack_version(raw: &[u8]) -> RResult<(String, u8)> {
    let a = read_value(&mut io::Cursor::new(raw))?
        .as_array().ok_or("version not array")?.clone();
    Ok((
        a[0].as_str().unwrap_or("?").to_string(),
        a[1].as_u64().unwrap_or(0) as u8,
    ))
}

fn pack_test_config(duration: f64, packet_size: u64) -> Vec<u8> {
    let v = Value::Map(vec![
        (Value::from("duration"), Value::from(duration)),
        (Value::from("packet_size"), Value::from(packet_size as i64)),
    ]);
    let mut b = Vec::new();
    write_value(&mut b, &v).ok();
    b
}

fn unpack_test_config(raw: &[u8]) -> RResult<(f64, u64)> {
    let map = read_value(&mut io::Cursor::new(raw))?
        .as_map().ok_or("test_config not map")?.clone();
    let duration = map_get_f64(&map, "duration").unwrap_or(DEFAULT_DURATION);
    let packet_size = map_get_u64(&map, "packet_size").unwrap_or(0);
    Ok((duration, packet_size))
}

fn pack_result(bytes: u64, packets: u64, duration_ns: u64) -> Vec<u8> {
    let v = Value::Map(vec![
        (Value::from("bytes_received"), Value::from(bytes as i64)),
        (Value::from("packets_received"), Value::from(packets as i64)),
        (Value::from("duration_ns"), Value::from(duration_ns as i64)),
    ]);
    let mut b = Vec::new();
    write_value(&mut b, &v).ok();
    b
}

fn unpack_result(raw: &[u8]) -> RResult<(u64, u64, u64)> {
    let map = read_value(&mut io::Cursor::new(raw))?
        .as_map().ok_or("result not map")?.clone();
    let bytes = map_get_u64(&map, "bytes_received").unwrap_or(0);
    let packets = map_get_u64(&map, "packets_received").unwrap_or(0);
    let duration_ns = map_get_u64(&map, "duration_ns").unwrap_or(0);
    Ok((bytes, packets, duration_ns))
}

fn pack_result_request() -> Vec<u8> {
    let v = Value::Map(vec![(Value::from("request"), Value::from(true))]);
    let mut b = Vec::new();
    write_value(&mut b, &v).ok();
    b
}

fn pack_err(msg: &str) -> Vec<u8> {
    let v = Value::Array(vec![Value::from(msg), Value::from(false)]);
    let mut b = Vec::new();
    write_value(&mut b, &v).ok();
    b
}

fn map_get_u64(map: &[(Value, Value)], key: &str) -> Option<u64> {
    map.iter().find_map(|(k, v)| {
        if k.as_str() == Some(key) { v.as_u64() } else { None }
    })
}

fn map_get_f64(map: &[(Value, Value)], key: &str) -> Option<f64> {
    map.iter().find_map(|(k, v)| {
        if k.as_str() == Some(key) { v.as_f64() } else { None }
    })
}

fn pretty_bytes(bytes: f64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB"];
    let mut v = bytes;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.2} {}", UNITS[u])
}

fn pretty_rate(bytes_per_sec: f64) -> String {
    const UNITS: &[&str] = &["bps", "Kbps", "Mbps", "Gbps"];
    let bits_per_sec = bytes_per_sec * 8.0;
    let mut v = bits_per_sec;
    let mut u = 0;
    while v >= 1000.0 && u < UNITS.len() - 1 {
        v /= 1000.0;
        u += 1;
    }
    format!("{v:.2} {}", UNITS[u])
}

fn pretty_duration(secs: f64) -> String {
    if secs < 1.0 {
        format!("{:.0} ms", secs * 1000.0)
    } else {
        format!("{:.2} s", secs)
    }
}

// ── Link helpers ────────────────────────────────────────────────────

async fn get_link(t: &Transport, id: &reticulum_sdk::hash::AddressHash)
    -> Option<Arc<Mutex<Link>>>
{
    if let Some(l) = t.find_in_link(id).await { return Some(l); }
    if let Some(l) = t.find_out_link(id).await { return Some(l); }
    None
}

// ── Resolve identity ────────────────────────────────────────────────

/// Try to load the listener's public identity from the local identity file.
///
/// On the same machine (both listener and initiator share the identity file),
/// this returns the correct identity. On different machines, the user must
/// use `--remote-identity` or rely on announce-based resolution.
async fn resolve_listener_identity(a: &Args) -> RResult<Identity> {
    if let Some(hex) = &a.remote_identity {
        let id = Identity::new_from_hex_string(hex)
            .map_err(|e| format!("invalid remote identity hex: {e:?}"))?;
        log::info!("rnperf: using remote identity from command line");
        return Ok(id);
    }

    // Try loading existing identity file (same-machine case)
    let pb = rnperf_dir().join(APP_NAME);
    if pb.is_file() {
        let hex = fs::read_to_string(&pb)?.trim().to_string();
        let priv_id = PrivateIdentity::new_from_hex_string(&hex)
            .map_err(|e| format!("bad identity {pb:?}: {e:?}"))?;
        log::info!("rnperf: using identity from {pb:?} as remote identity (same-machine mode)");
        return Ok(priv_id.as_identity().clone());
    }

    bail!("could not resolve listener identity: provide --remote-identity <hash> or ensure the listener's announce is reachable")
}

// ── Listener ────────────────────────────────────────────────────────

async fn listener(a: &Args) -> RResult<()> {
    let ident = load_ident()?;
    let mut transport = make_transport(ident.clone()).await?;

    let dest = transport.add_destination(ident.clone(), DestinationName::new(APP_NAME, "")).await;
    let dest_hash = dest.lock().await.desc.address_hash;
    println!("Identity hash  : {}", ident.as_identity().address_hash.to_hex_string());
    println!("Identity pubkey: {}", ident.as_identity().to_hex_string());
    println!("Listening on   : {}", dest_hash.to_hex_string());
    println!();
    println!("On the initiator, run:");
    println!("  rnperf -R {} {}", ident.as_identity().to_hex_string(), dest_hash.to_hex_string());
    println!();

    // Announce at startup for late-subscribing peers
    for _ in 0..3 {
        transport.send_announce(&dest, None).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    let transport = Arc::new(transport);

    // Periodic re-announce
    if let Some(interval) = a.announce_interval {
        let announce_t = transport.clone();
        let announce_d = dest.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(interval)).await;
                announce_t.send_announce(&announce_d, None).await;
            }
        });
        println!("Re-announcing every {interval}s");
    }

    let mut in_ev = transport.in_link_events();
    println!("Waiting for incoming connections...");

    loop {
        match in_ev.recv().await {
            Ok(ev) if matches!(ev.event, LinkEvent::Activated) => {
                log::info!("rnperf: inbound link {}", ev.id);
                let t = transport.clone();
                let ev_recv = in_ev.resubscribe();
                tokio::spawn(async move {
                    if let Err(e) = handle_session(ev.id, t, ev_recv).await {
                        log::error!("rnperf: session failed: {e}");
                    }
                });
            }
            Ok(_) => {}
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                log::warn!("rnperf: main loop lagged ({} missed)", n);
                continue;
            }
            Err(_) => break,
        }
    }

    Ok(())
}

async fn handle_session(
    link_id: reticulum_sdk::hash::AddressHash,
    transport: Arc<Transport>,
    mut in_ev: tokio::sync::broadcast::Receiver<reticulum_sdk::destination::link::LinkEventData>,
) -> RResult<()> {
    let link_arc = get_link(&transport, &link_id).await
        .ok_or("no link handle")?;
    let mdu = link_arc.lock().await.channel_mdu();

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut got_ver = false;
    let mut got_config = false;
    let mut test_duration = DEFAULT_DURATION;
    let mut test_packet_size = mdu;

    // ── Handshake: version + test config ──
    while Instant::now() < deadline {
        match in_ev.recv().await {
            Ok(ev) if ev.id == link_id => match &ev.event {
                LinkEvent::Channel(ch) if ch.msg_type == MSG_TYPE_VERSION => {
                    let (_sw, pv) = unpack_version(&ch.payload)?;
                    if pv != PROTOCOL_VERSION {
                        send_channel(&link_arc, &transport, MSG_TYPE_ERROR,
                            &pack_err(&format!("incompatible protocol {pv}"))).await?;
                        bail!("incompatible protocol {pv}");
                    }
                    send_channel(&link_arc, &transport, MSG_TYPE_VERSION, &pack_version()).await?;
                    got_ver = true;
                }
                LinkEvent::Channel(ch) if ch.msg_type == MSG_TYPE_TEST_CONFIG => {
                    let (dur, pkt_sz) = unpack_test_config(&ch.payload)?;
                    test_duration = dur;
                    if pkt_sz > 0 && pkt_sz < mdu as u64 {
                        test_packet_size = pkt_sz as usize;
                    }
                    log::info!("rnperf: test config: duration={test_duration}s, packet_size={test_packet_size}B");
                    got_config = true;
                }
                LinkEvent::Channel(ch) if ch.msg_type == MSG_TYPE_ERROR => {
                    let m = ch.payload.iter().map(|&b| b as char).collect::<String>();
                    bail!("remote error: {m}");
                }
                LinkEvent::Closed => bail!("link closed during handshake"),
                _ => {}
            },
            Ok(_) => {}
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                log::warn!("rnperf: handshake receiver lagged ({n} missed)");
                continue;
            }
            Err(_) => bail!("event channel closed"),
        }
        if got_ver && got_config { break; }
    }
    if !got_ver { bail!("version handshake timeout"); }
    if !got_config { bail!("test config timeout"); }

    // ── Test phase: count incoming data packets ──
    let mut bytes_received: u64 = 0;
    let mut packets_received: u64 = 0;
    let mut first_data_time: Option<Instant> = None;
    // Generous overall budget so a congested link can drain its backlog
    // before the session is torn down. The initiator's result request is
    // delivered in channel-sequence order (after the data backlog), so the
    // response below reflects the final packet count.
    let session_deadline =
        Instant::now() + Duration::from_secs_f64(test_duration.max(10.0) * 2.0 + 45.0);
    let mut results_sent = false;

    loop {
        tokio::select! {
            result = in_ev.recv() => {
                match result {
                    Ok(ev) if ev.id == link_id => match &ev.event {
                        LinkEvent::Channel(ch) if ch.msg_type == MSG_TYPE_DATA => {
                            if ch.payload.len() >= 4 {
                                let data_bytes = (ch.payload.len() - 4) as u64;
                                bytes_received += data_bytes;
                                packets_received += 1;
                                if first_data_time.is_none() {
                                    first_data_time = Some(Instant::now());
                                }
                            }
                        }
                        LinkEvent::Channel(ch) if ch.msg_type == MSG_TYPE_RESULT => {
                            // Initiator requested results: send back our stats.
                            // Keep the session open so a result that gets lost
                            // can be re-sent if the initiator retries.
                            send_result_message(
                                &link_arc,
                                &transport,
                                test_duration,
                                bytes_received,
                                packets_received,
                                first_data_time,
                            ).await?;
                            results_sent = true;
                            log::info!("rnperf: test complete: received {packets_received} packets, {bytes_received} bytes");
                        }
                        LinkEvent::Closed => break,
                        _ => {}
                    },
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        log::warn!("rnperf: data receiver lagged ({n} missed)");
                        continue;
                    }
                    Err(_) => break,
                }
            }
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(session_deadline)) => {
                // Final fallback: if the initiator's result request never made
                // it through, deliver whatever we have so it is not left
                // hanging. By this point the backlog has long since drained.
                if !results_sent && packets_received > 0 {
                    send_result_message(
                        &link_arc,
                        &transport,
                        test_duration,
                        bytes_received,
                        packets_received,
                        first_data_time,
                    ).await?;
                    log::info!("rnperf: session timed out, sent result proactively: received {packets_received} packets, {bytes_received} bytes");
                } else {
                    log::info!("rnperf: session timed out after {test_duration}s, received {packets_received} packets, {bytes_received} bytes");
                }
                break;
            }
        }
    }

    transport.link_close(link_id).await.ok();
    Ok(())
}

// ── Initiator ───────────────────────────────────────────────────────

async fn initiator(a: &Args) -> RResult<()> {
    let ident = load_ident()?;
    let transport = make_transport(ident.clone()).await?;

    let dest_hex = a.dest.as_ref().ok_or("no destination")?;
    if dest_hex.len() != ADDRESS_HASH_SIZE * 2 {
        bail!("destination must be {} hex chars", ADDRESS_HASH_SIZE * 2);
    }
    let dest_hash = reticulum_sdk::hash::AddressHash::new_from_hex_string(dest_hex)
        .map_err(|_| "invalid destination hash")?;

    let timeout = 30.0_f64.max(a.duration + 5.0);
    let deadline = Instant::now() + Duration::from_secs_f64(timeout);

    // Request path and resolve identity
    // Use --remote-identity if provided (skip announce resolution)
    let remote_identity = if a.remote_identity.is_some() {
        resolve_listener_identity(a).await?
    } else {
        log::info!("rnperf: requesting path to destination, waiting for announce...");
        transport.request_path(&dest_hash, None, None).await;
        let rem_id = 'ident: loop {
            if let Some(dest) = transport.get_out_destination(&dest_hash).await {
                let identity = dest.lock().await.desc.identity;
                if a.verbose > 0 {
                    log::info!("rnperf: resolved destination identity from announce: {}", identity.to_hex_string());
                }
                log::info!("rnperf: resolved destination identity from announce");
                break 'ident identity;
            }
            if Instant::now() >= deadline {
                log::warn!("rnperf: could not resolve destination from announce, trying local identity file");
                break 'ident resolve_listener_identity(a).await?;
            }
            transport.request_path(&dest_hash, None, None).await;
            tokio::time::sleep(Duration::from_millis(500)).await;
        };
        rem_id
    };
    if a.verbose > 0 {
        log::info!("rnperf: using remote identity: {}", remote_identity.to_hex_string());
    }

    let dest_desc = DestinationDesc {
        identity: remote_identity,
        address_hash: dest_hash,
        name: DestinationName::new(APP_NAME, ""),
        ratchet_public_key: None,
    };

    log::info!("rnperf: linking to {dest_hex}");
    let link_arc = transport.link(dest_desc).await;
    let link_id = *link_arc.lock().await.id();
    let mut out_ev = transport.out_link_events();

    // Wait for activation
    let mut activated = false;
    while Instant::now() < deadline {
        match out_ev.recv().await {
            Ok(ev) if ev.id == link_id => match ev.event {
                LinkEvent::Activated => { activated = true; break; }
                LinkEvent::Closed => bail!("link closed during activation"),
                _ => {}
            },
            Ok(_) => {}
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                log::warn!("rnperf: activation receiver lagged ({n} missed)");
                continue;
            }
            Err(_) => bail!("event channel gone"),
        }
    }
    if !activated { bail!("link activation timed out"); }
    log::info!("rnperf: link active");

    // Small delay before starting handshake
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ── Version handshake ──
    send_channel(&link_arc, &transport, MSG_TYPE_VERSION, &pack_version()).await?;

    let mut ver_ok = false;
    let hs_deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < hs_deadline {
        match out_ev.recv().await {
            Ok(ev) if ev.id == link_id => match &ev.event {
                LinkEvent::Channel(ch) if ch.msg_type == MSG_TYPE_VERSION => {
                    let (sw, pv) = unpack_version(&ch.payload)?;
                    log::info!("rnperf: remote {sw} protocol {pv}");
                    if pv != PROTOCOL_VERSION {
                        bail!("incompatible protocol {pv}");
                    }
                    ver_ok = true;
                    break;
                }
                LinkEvent::Channel(ch) if ch.msg_type == MSG_TYPE_ERROR => {
                    let m = ch.payload.iter().map(|&b| b as char).collect::<String>();
                    bail!("remote: {m}");
                }
                LinkEvent::Closed => bail!("link closed during version handshake"),
                _ => {}
            },
            Ok(_) => {}
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                log::warn!("rnperf: version handshake receiver lagged ({n} missed)");
                continue;
            }
            Err(_) => bail!("event channel gone"),
        }
    }
    if !ver_ok { bail!("version handshake failed"); }

    // ── Send test config ──
    let mdu = link_arc.lock().await.channel_mdu();
    let data_size = a.packet_size.unwrap_or(mdu.saturating_sub(4));
    let data_size = data_size.min(mdu.saturating_sub(4)).max(1);
    log::info!("rnperf: MDU={mdu}, using packet payload size={data_size}B, rate={:.0} bps", a.rate);

    send_channel(&link_arc, &transport, MSG_TYPE_TEST_CONFIG,
        &pack_test_config(a.duration, data_size as u64)).await?;

    // ── DATA phase ──
    let start = Instant::now();
    let send_deadline = start + Duration::from_secs_f64(a.duration);
    let mut seq: u32 = 0;
    let mut data_buf = vec![0u8; data_size + 4]; // +4 for seq number
    let mut total_bytes_sent: u64 = 0;
    let mut total_packets_sent: u64 = 0;

    // Cap send rate to avoid overwhelming the transport
    let burst_size: u64 = 100;
    let burst_sleep = Duration::from_secs_f64(
        burst_size as f64 * data_size as f64 * 8.0 / a.rate,
    );
    let mut burst_start = Instant::now();

    while Instant::now() < send_deadline {
        data_buf[..4].copy_from_slice(&seq.to_be_bytes());
        send_channel(&link_arc, &transport, MSG_TYPE_DATA, &data_buf).await?;
        total_bytes_sent += data_size as u64;
        total_packets_sent += 1;
        seq = seq.wrapping_add(1);

        if total_packets_sent % burst_size == 0 {
            // Keep the out-link event channel from overflowing: one proof
            // event per acknowledged packet is posted, and it is only safe
            // to let them accumulate if we consume them.
            drain_out_link_events(&mut out_ev);
            let elapsed = burst_start.elapsed();
            if elapsed < burst_sleep {
                tokio::time::sleep(burst_sleep - elapsed).await;
            }
            burst_start = Instant::now();
        }
    }
    let send_elapsed = start.elapsed();
    drain_out_link_events(&mut out_ev);

    log::info!("rnperf: sent {total_packets_sent} packets ({total_bytes_sent} bytes) in {send_elapsed:?}");

    // ── Request results from listener ──
    // Wait a moment for in-flight packets to arrive
    tokio::time::sleep(Duration::from_secs(2)).await;

    send_channel(&link_arc, &transport, MSG_TYPE_RESULT, &pack_result_request()).await?;

    // ── Receive results ──
    let mut recv_bytes: u64 = 0;
    let mut recv_packets: u64 = 0;
    let mut recv_duration_ns: u64 = 0;
    let mut got_result = false;
    // Generous budget so results sent after a congested backlog drains (or
    // delivered proactively by the listener) still have time to arrive.
    let result_deadline = Instant::now() + Duration::from_secs(60);
    let mut retry_interval = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(3),
        Duration::from_secs(3),
    );

    while Instant::now() < result_deadline {
        tokio::select! {
            result = out_ev.recv() => {
                match result {
                    Ok(ev) if ev.id == link_id => match &ev.event {
                        LinkEvent::Channel(ch) if ch.msg_type == MSG_TYPE_RESULT => {
                            if let Ok((br, bp, dn)) = unpack_result(&ch.payload) {
                                recv_bytes = br;
                                recv_packets = bp;
                                recv_duration_ns = dn;
                                got_result = true;
                                break;
                            }
                        }
                        LinkEvent::Channel(ch) if ch.msg_type == MSG_TYPE_ERROR => {
                            let m = ch.payload.iter().map(|&b| b as char).collect::<String>();
                            log::error!("rnperf: remote error: {m}");
                            break;
                        }
                        LinkEvent::Closed => break,
                        _ => {}
                    },
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        log::warn!("rnperf: result receiver lagged ({n} missed)");
                        continue;
                    }
                    Err(_) => break,
                }
            }
            _ = retry_interval.tick() => {
                log::warn!("rnperf: result not yet received, retrying request");
                send_channel(&link_arc, &transport, MSG_TYPE_RESULT, &pack_result_request()).await?;
            }
        }
    }

    // ── Report ──
    let send_duration = send_elapsed.as_secs_f64();
    let sender_bps = if send_duration > 0.0 {
        total_bytes_sent as f64 / send_duration
    } else {
        0.0
    };

    let recv_duration = if recv_duration_ns > 0 {
        recv_duration_ns as f64 / 1_000_000_000.0
    } else {
        send_duration
    };

    let receiver_bps = if recv_duration > 0.0 {
        recv_bytes as f64 / recv_duration
    } else {
        0.0
    };

    let loss_pct = if total_packets_sent > 0 {
        100.0 * (1.0 - recv_packets as f64 / total_packets_sent as f64)
    } else {
        0.0
    };

    println!();
    println!("═══ rnperf Test Results ═══");
    println!();
    println!("Sender:");
    println!("  Duration:     {}", pretty_duration(send_duration));
    println!("  Data sent:    {} ({} bytes in {} packets)",
        pretty_bytes(total_bytes_sent as f64), total_bytes_sent, total_packets_sent);
    println!("  Throughput:   {}", pretty_rate(sender_bps));
    println!();
    println!("Receiver:");
    if got_result {
        println!("  Duration:     {}", pretty_duration(recv_duration));
        println!("  Data received: {} ({} bytes in {} packets)",
            pretty_bytes(recv_bytes as f64), recv_bytes, recv_packets);
        println!("  Throughput:   {}", pretty_rate(receiver_bps));
        println!();
        println!("  Packet loss:  {loss_pct:.1}%");
    } else {
        println!("  No result received from remote");
    }

    transport.link_close(link_id).await.ok();
    Ok(())
}

// ── Main ────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    env_logger::init();

    let a = match parse_args() {
        Ok(a) => a,
        Err(e) => { eprintln!("rnperf: {e}"); std::process::exit(1); }
    };

    if a.listen {
        if let Err(e) = listener(&a).await {
            eprintln!("rnperf: {e}");
            std::process::exit(1);
        }
    } else if a.dest.is_some() {
        if let Err(e) = initiator(&a).await {
            eprintln!("rnperf: {e}");
            std::process::exit(1);
        }
    } else {
        print_help();
        std::process::exit(1);
    }
}
