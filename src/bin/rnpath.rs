use hmac::{Hmac, Mac};
use rand::rngs::{StdRng, SysRng};
use rand::Rng;
use rand::SeedableRng;
use rmpv::{Value, decode::read_value, encode::write_value};
use sha2::Sha256;
use std::collections::HashMap;
use std::env;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const PY_CONN_CHALLENGE: &[u8] = b"#CHALLENGE#";
const PY_CONN_WELCOME: &[u8] = b"#WELCOME#";
const PY_CONN_FAILURE: &[u8] = b"#FAILURE#";
const PY_CONN_AUTH_MAX_FRAME: usize = 256;
const MAX_RPC_FRAME: usize = 1024 * 1024;
const DEFAULT_CONTROL_HOST: &str = "127.0.0.1";
const DEFAULT_CONTROL_PORT: u16 = 37429;
const ADDRESS_HASH_SIZE: usize = 16;

#[derive(Default)]
struct Args {
    destination: Option<String>,
    table: bool,
    max_hops: Option<u8>,
    rates: bool,
    drop: bool,
    drop_announces: bool,
    drop_via: bool,
    blackholed: bool,
    blackhole: bool,
    unblackhole: bool,
    blackhole_duration: Option<f64>,
    blackhole_reason: Option<String>,
    host: String,
    port: u16,
    rpc_key: Option<String>,
    json: bool,
    verbose: u8,
}

fn main() {
    let code = match run() {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("{msg}");
            1
        }
    };
    std::process::exit(code);
}

fn run() -> Result<i32, String> {
    let args = parse_args()?;
    validate_args(&args)?;

    let rpc_key = resolve_rpc_key(&args)?;

    let conn = Conn {
        host: args.host.clone(),
        port: args.port,
        rpc_key,
    };

    // Fail fast if the instance is unreachable or rejects our RPC key.
    let _ = conn.connect()?;

    if args.blackholed {
        return do_blackholed(&conn, &args);
    }

    if args.blackhole {
        return do_blackhole(&conn, &args);
    }

    if args.unblackhole {
        return do_unblackhole(&conn, &args);
    }

    if args.table {
        return do_table(&conn, &args);
    }

    if args.rates {
        return do_rates(&conn, &args);
    }

    if args.drop {
        return do_drop(&conn, &args);
    }

    if args.drop_announces {
        return do_drop_announces(&conn);
    }

    if args.drop_via {
        return do_drop_via(&conn, &args);
    }

    if let Some(dest) = &args.destination {
        return do_path_info(&conn, dest, &args);
    }

    print_help();
    Ok(0)
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        host: DEFAULT_CONTROL_HOST.to_string(),
        port: DEFAULT_CONTROL_PORT,
        ..Args::default()
    };
    let mut it = env::args().skip(1).peekable();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            "--version" => {
                println!("rnpath {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-t" | "--table" => args.table = true,
            "-m" | "--max" => {
                let val = next_value(&mut it, &arg)?;
                args.max_hops = Some(val.parse::<u8>().map_err(|_| "Invalid max hops".to_string())?);
            }
            "-r" | "--rates" => args.rates = true,
            "-d" | "--drop" => args.drop = true,
            "-D" | "--drop-announces" => args.drop_announces = true,
            "-x" | "--drop-via" => args.drop_via = true,
            "-b" | "--blackholed" => args.blackholed = true,
            "-B" | "--blackhole" => args.blackhole = true,
            "-U" | "--unblackhole" => args.unblackhole = true,
            "--duration" => {
                let val = next_value(&mut it, "--duration")?;
                args.blackhole_duration = Some(val.parse::<f64>().map_err(|_| "Invalid duration".to_string())?);
            }
            "--reason" => args.blackhole_reason = Some(next_value(&mut it, "--reason")?),
            "-H" | "--host" => {
                args.host = next_value(&mut it, &arg)?;
            }
            "-p" | "--port" => {
                let val = next_value(&mut it, &arg)?;
                args.port = val.parse::<u16>().map_err(|_| "Invalid port".to_string())?;
            }
            "-k" | "--rpc-key" => args.rpc_key = Some(next_value(&mut it, &arg)?),
            "-j" | "--json" => args.json = true,
            "-v" | "--verbose" => args.verbose = args.verbose.saturating_add(1),
            _ if arg.starts_with('-') => {
                return Err(format!("unrecognized argument: {arg}"));
            }
            _ => {
                if args.destination.is_some() {
                    return Err(format!("unexpected argument: {arg}"));
                }
                args.destination = Some(arg);
            }
        }
    }

    // If user didn't set rpc-key, check env
    if args.rpc_key.is_none() {
        args.rpc_key = match std::env::var("RETICULUM_RPC_KEY") {
            Ok(key) => Some(key),
            Err(_) => None,
        }
    }
    Ok(args)
}

fn next_value<I>(it: &mut std::iter::Peekable<I>, flag: &str) -> Result<String, String>
where
    I: Iterator<Item = String>,
{
    it.next().ok_or_else(|| format!("argument {flag} expected one value"))
}

fn validate_args(args: &Args) -> Result<(), String> {
    let ops = [
        args.table,
        args.rates,
        args.drop,
        args.drop_announces,
        args.drop_via,
        args.blackholed,
        args.blackhole,
        args.unblackhole,
    ]
    .iter()
    .filter(|x| **x)
    .count();

    if ops > 1 {
        return Err("Only one operation per invocation is supported".to_string());
    }

    if (args.blackhole || args.unblackhole || args.drop || args.drop_via) && args.destination.is_none() {
        return Err("A destination hash is required for this operation".to_string());
    }

    if args.table && args.max_hops.is_some() && args.destination.is_some() {
        return Err("Cannot specify both destination and max hops".to_string());
    }

    Ok(())
}

fn resolve_rpc_key(args: &Args) -> Result<Vec<u8>, String> {
    if let Some(key) = &args.rpc_key {
        let path = std::path::Path::new(key);
        if path.is_file() {
            let data = std::fs::read_to_string(path)
                .map_err(|e| format!("Could not read RPC key file: {e}"))?;
            let key_hex = data.trim().to_string();
            return decode_hex(&key_hex);
        }
        return decode_hex(key);
    }
    Err("No RPC key specified. Use --rpc-key <hex> to provide the shared instance RPC key.".to_string())
}

/// Connection parameters for the shared instance RPC interface.
///
/// The server handles exactly one request per authenticated connection, so
/// each RPC round-trip needs a fresh connection. `Conn` bundles the
/// parameters needed to open one on demand.
struct Conn {
    host: String,
    port: u16,
    rpc_key: Vec<u8>,
}

impl Conn {
    fn connect(&self) -> Result<TcpStream, String> {
        connect_rpc(&self.host, self.port, &self.rpc_key)
    }
}

/// Perform a single RPC request/response round-trip over a fresh connection.
fn rpc_call(conn: &Conn, request: &Value) -> Result<Value, String> {
    let mut stream = conn.connect()?;
    send_rpc_request(&mut stream, request)
}

/// Map interface address hashes to human-readable interface names by
/// querying the `interfaces` RPC. Falls back to an empty map when the
/// instance does not support it.
fn interface_names(conn: &Conn) -> HashMap<Vec<u8>, String> {
    let request = Value::Map(vec![(Value::from("get"), Value::from("interfaces"))]);
    match rpc_call(conn, &request) {
        Ok(Value::Array(list)) => list
            .iter()
            .filter_map(|entry| {
                let map = entry.as_map()?;
                let address = map_get_bytes(map, "identity")?.to_vec();
                let name = map_get_str(map, "name")?.to_string();
                Some((address, name))
            })
            .collect(),
        _ => HashMap::new(),
    }
}

/// Render an interface address from a path entry as its name when known,
/// falling back to the raw hash.
fn format_iface(iface: Option<&[u8]>, names: &HashMap<Vec<u8>, String>) -> String {
    if let Some(bytes) = iface {
        if let Some(name) = names.get(bytes) {
            return name.clone();
        }
        return pretty_hex(bytes);
    }
    "?".to_string()
}

fn connect_rpc(host: &str, port: u16, rpc_key: &[u8]) -> Result<TcpStream, String> {
    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect(&addr)
        .map_err(|e| format!("Could not connect to {addr}: {e}"))?;

    stream.set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| format!("Could not set timeout: {e}"))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| format!("Could not set timeout: {e}"))?;

    // Server sends challenge; client responds with HMAC
    let challenge = read_frame(&mut stream, PY_CONN_AUTH_MAX_FRAME)?;

    if !challenge.starts_with(PY_CONN_CHALLENGE) {
        return Err("Server did not send a challenge".to_string());
    }

    let message = &challenge[PY_CONN_CHALLENGE.len()..];
    let response = shared_rpc_hmac_response(rpc_key, message)?;
    write_frame(&mut stream, &response)?;

    let welcome = read_frame(&mut stream, PY_CONN_AUTH_MAX_FRAME)?;
    if welcome == PY_CONN_FAILURE {
        return Err("Authentication failed: server rejected RPC key".to_string());
    }
    if welcome != PY_CONN_WELCOME {
        return Err("Unexpected response during authentication".to_string());
    }

    // Client-side mutual auth: challenge the server to prove it knows the key
    let peer_challenge = shared_rpc_challenge();
    write_frame(&mut stream, &peer_challenge)?;

    let peer_response = read_frame(&mut stream, PY_CONN_AUTH_MAX_FRAME)?;
    if !shared_rpc_response_is_authenticated(&peer_challenge, &peer_response, rpc_key)? {
        return Err("Server failed mutual authentication".to_string());
    }

    write_frame(&mut stream, PY_CONN_WELCOME)?;

    Ok(stream)
}

fn shared_rpc_challenge() -> Vec<u8> {
    let mut random = [0u8; 40];
    let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();
    rng.fill_bytes(&mut random);

    let mut challenge = Vec::with_capacity(PY_CONN_CHALLENGE.len() + 7 + random.len());
    challenge.extend_from_slice(PY_CONN_CHALLENGE);
    challenge.extend_from_slice(b"{sha256}");
    challenge.extend_from_slice(&random);
    challenge
}

fn shared_rpc_response_is_authenticated(
    challenge: &[u8],
    response: &[u8],
    auth_key: &[u8],
) -> Result<bool, String> {
    let message = &challenge[PY_CONN_CHALLENGE.len()..];
    let expected = shared_rpc_hmac_response(auth_key, message)?;
    let expected_raw = &expected[b"{sha256}".len()..];
    Ok(response == expected.as_slice() || response == expected_raw)
}

fn shared_rpc_hmac_response(auth_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(auth_key).map_err(|e| e.to_string())?;
    mac.update(message);
    let digest = mac.finalize().into_bytes();

    let mut response = Vec::with_capacity(b"{sha256}".len() + digest.len());
    response.extend_from_slice(b"{sha256}");
    response.extend_from_slice(&digest);
    Ok(response)
}

fn read_frame(stream: &mut TcpStream, max_size: usize) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)
        .map_err(|e| format!("Failed to read frame length: {e}"))?;

    let len = i32::from_be_bytes(len_buf);
    let data_len: usize = if len == -1 {
        let mut big_len_buf = [0u8; 8];
        stream.read_exact(&mut big_len_buf)
            .map_err(|e| format!("Failed to read large frame length: {e}"))?;
        u64::from_be_bytes(big_len_buf) as usize
    } else if len < 0 {
        return Err("Invalid frame length".to_string());
    } else {
        len as usize
    };

    if data_len > max_size {
        return Err(format!("Frame too large: {data_len} > {max_size}"));
    }

    let mut data = vec![0u8; data_len];
    if data_len > 0 {
        stream.read_exact(&mut data)
            .map_err(|e| format!("Failed to read frame data: {e}"))?;
    }

    Ok(data)
}

fn write_frame(stream: &mut TcpStream, data: &[u8]) -> Result<(), String> {
    let len = data.len();
    if len <= i32::MAX as usize {
        let len_buf = (len as i32).to_be_bytes();
        stream.write_all(&len_buf)
            .map_err(|e| format!("Failed to write frame length: {e}"))?;
    } else {
        let len_buf = (-1i32).to_be_bytes();
        stream.write_all(&len_buf)
            .map_err(|e| format!("Failed to write frame length: {e}"))?;
        let big_len_buf = (len as u64).to_be_bytes();
        stream.write_all(&big_len_buf)
            .map_err(|e| format!("Failed to write large frame length: {e}"))?;
    }

    stream.write_all(data)
        .map_err(|e| format!("Failed to write frame data: {e}"))?;
    stream.flush()
        .map_err(|e| format!("Failed to flush: {e}"))?;

    Ok(())
}

fn send_rpc_request(stream: &mut TcpStream, request: &Value) -> Result<Value, String> {
    let mut encoded = Vec::new();
    write_value(&mut encoded, request).map_err(|e| format!("Failed to encode request: {e}"))?;

    write_frame(stream, &encoded)?;

    let response_data = read_frame(stream, MAX_RPC_FRAME)?;
    let response = read_value(&mut &response_data[..])
        .map_err(|e| format!("Failed to decode response: {e}"))?;

    Ok(response)
}

fn do_table(conn: &Conn, args: &Args) -> Result<i32, String> {
    let request = Value::Map(vec![
        (Value::from("get"), Value::from("path_table")),
    ]);
    let response = rpc_call(conn, &request)?;

    let entries = response.as_array()
        .ok_or_else(|| "Invalid response: expected array".to_string())?;

    if args.json {
        let json_entries: Vec<serde_json::Value> = entries.iter()
            .filter_map(|e| path_entry_to_json(e))
            .collect();
        println!("{}", serde_json::to_string(&json_entries).unwrap_or_default());
        return Ok(0);
    }

    if entries.is_empty() {
        println!("No paths known");
        return Ok(0);
    }

    let dest_filter = args.destination.as_ref();
    let max_hops = args.max_hops;

    let names = interface_names(conn);
    let mut displayed = 0;
    for entry in entries {
        let map = match entry.as_map() {
            Some(m) => m,
            None => continue,
        };

        let hash = map_get_bytes(map, "hash");
        let hops = map_get_u64(map, "hops").unwrap_or(0);
        let via = map_get_bytes(map, "via");
        let iface = map_get_bytes(map, "interface");
        let expires_secs = map_get_f64(map, "expires").unwrap_or(0.0);

        if let Some(max) = max_hops {
            if hops > max as u64 {
                continue;
            }
        }

        if let Some(filter) = dest_filter {
            if let Ok(filter_bytes) = decode_hex(filter) {
                if let Some(h) = hash {
                    if h != filter_bytes.as_slice() {
                        continue;
                    }
                }
            }
        }

        displayed += 1;

        let hash_str = hash.as_ref().map(|h| pretty_hex(h)).unwrap_or_default();
        let via_str = via.as_ref().map(|h| pretty_hex(h)).unwrap_or_default();
        let iface_str = format_iface(iface, &names);
        let expires_str = pretty_duration(expires_secs);

        let hop_str = if hops == 1 { " hop" } else { " hops" };
        print!("{hash_str} is {hops}{hop_str} away via {via_str} on {iface_str} expires {expires_str}");

        // Render first-hop radio signal if relevant
        let snr = fetch_snr(conn).unwrap_or(None);
        let rssi = fetch_rssi(conn).unwrap_or(None);
        if snr.is_some() || rssi.is_some() {
            print!(" (via radio: ");
            if let Some(snr_value) = snr {
                print!("SNR: {snr_value:.1} dB");
            }
            if let Some(rssi_value) = rssi {
                if snr.is_some() {
                    print!(" ");
                }
                print!("RSSI: {rssi_value} dBm");
            }
            print!(")");
        }
        print!("\n");
    }

    if displayed == 0 && dest_filter.is_some() {
        println!("No path known");
        return Ok(1);
    }

    Ok(0)
}

fn do_rates(conn: &Conn, args: &Args) -> Result<i32, String> {
    let request = Value::Map(vec![
        (Value::from("get"), Value::from("rate_table")),
    ]);
    let response = rpc_call(conn, &request)?;

    let entries = response.as_array()
        .ok_or_else(|| "Invalid response: expected array".to_string())?;

    if args.json {
        let json_entries: Vec<serde_json::Value> = entries.iter()
            .filter_map(|e| rate_entry_to_json(e))
            .collect();
        println!("{}", serde_json::to_string(&json_entries).unwrap_or_default());
        return Ok(0);
    }

    if entries.is_empty() {
        println!("No information available");
        return Ok(0);
    }

    let dest_filter = args.destination.as_ref();
    let mut displayed = 0;

    for entry in entries {
        let map = match entry.as_map() {
            Some(m) => m,
            None => continue,
        };

        let hash = map_get_bytes(map, "hash");
        let last_secs = map_get_f64(map, "last").unwrap_or(0.0);
        let violations = map_get_u64(map, "rate_violations").unwrap_or(0);
        let blocked_secs = map_get_f64(map, "blocked_until").unwrap_or(0.0);

        if let Some(filter) = dest_filter {
            if let Ok(filter_bytes) = decode_hex(filter) {
                if let Some(h) = hash {
                    if h != filter_bytes.as_slice() {
                        continue;
                    }
                }
            }
        }

        displayed += 1;

        let hash_str = hash.as_ref().map(|h| pretty_hex(h)).unwrap_or_default();
        let last_str = pretty_duration(last_secs);
        let mut output = format!("{hash_str} last heard {last_str} ago");

        if violations > 0 {
            let s = if violations == 1 { "" } else { "s" };
            output.push_str(&format!(", {violations} active rate violation{s}"));
        }

        if blocked_secs > 0.0 {
            output.push_str(&format!(", blocked for {}", pretty_duration(blocked_secs)));
        }

        println!("{output}");
    }

    if displayed == 0 && dest_filter.is_some() {
        println!("No information available");
        return Ok(1);
    }

    Ok(0)
}

fn do_drop(conn: &Conn, args: &Args) -> Result<i32, String> {
    let dest = args.destination.as_ref().unwrap();
    let dest_bytes = decode_hex(dest)?;
    if dest_bytes.len() != ADDRESS_HASH_SIZE {
        return Err("Invalid destination hash length".to_string());
    }
    let dest_hex = pretty_hex(&dest_bytes);

    let request = Value::Map(vec![
        (Value::from("drop"), Value::from("path")),
        (Value::from("destination_hash"), Value::Binary(dest_bytes)),
    ]);
    let response = rpc_call(conn, &request)?;

    if response.as_bool().unwrap_or(false) {
        println!("Dropped path to {dest_hex}");
        Ok(0)
    } else {
        println!("Unable to drop path to {dest_hex}. Does it exist?");
        Ok(1)
    }
}

fn do_drop_announces(conn: &Conn) -> Result<i32, String> {
    let request = Value::Map(vec![
        (Value::from("drop"), Value::from("announce_queues")),
    ]);
    rpc_call(conn, &request)?;

    println!("Dropped announce queues on all interfaces");
    Ok(0)
}

fn do_drop_via(conn: &Conn, args: &Args) -> Result<i32, String> {
    let dest = args.destination.as_ref().unwrap();
    let dest_bytes = decode_hex(dest)?;
    if dest_bytes.len() != ADDRESS_HASH_SIZE {
        return Err("Invalid transport identity hash length".to_string());
    }
    let dest_hex = pretty_hex(&dest_bytes);

    let request = Value::Map(vec![
        (Value::from("drop"), Value::from("all_via")),
        (Value::from("destination_hash"), Value::Binary(dest_bytes)),
    ]);
    let response = rpc_call(conn, &request)?;

    let count = response.as_u64().unwrap_or(0);
    println!("Dropped {count} paths via {dest_hex}");
    Ok(0)
}

fn do_blackholed(conn: &Conn, args: &Args) -> Result<i32, String> {
    let request = Value::Map(vec![
        (Value::from("get"), Value::from("blackholed_identities")),
    ]);
    let response = rpc_call(conn, &request)?;

    let map = response.as_map()
        .ok_or_else(|| "Invalid response".to_string())?;

    if map.is_empty() {
        println!("No blackholed identities");
        return Ok(0);
    }

    let dest_filter = args.destination.as_ref();
    let mut displayed = 0;

    for (key, val) in map {
        let identity_bytes = match key.as_slice() {
            Some(bytes) => bytes,
            None => continue,
        };

        let entry_map = match val.as_map() {
            Some(m) => m,
            None => continue,
        };

        let until_secs = map_get_f64(entry_map, "until").unwrap_or(0.0);
        let reason = map_get_str(entry_map, "reason");
        let source = map_get_bytes(entry_map, "source");

        if let Some(filter) = dest_filter {
            let filter_lower = filter.to_lowercase();
            let hash_hex = hex_encode(identity_bytes);
            if !hash_hex.contains(&filter_lower) {
                continue;
            }
        }

        displayed += 1;

        let hash_str = pretty_hex(identity_bytes);
        let until_str = if until_secs > 0.0 {
            format!("for {}", pretty_duration(until_secs))
        } else {
            "indefinitely".to_string()
        };
        let reason_str = reason.map(|r| format!(" ({r})")).unwrap_or_default();
        let by_str = source.map(|s| format!(" by {}", pretty_hex(&s))).unwrap_or_default();

        println!("{hash_str} blackholed {until_str}{reason_str}{by_str}");
    }

    if displayed == 0 {
        println!("No matching blackholed identities");
    }

    Ok(0)
}

fn do_blackhole(conn: &Conn, args: &Args) -> Result<i32, String> {
    let dest = args.destination.as_ref().unwrap();
    let dest_bytes = decode_hex(dest)?;
    if dest_bytes.len() != ADDRESS_HASH_SIZE {
        return Err("Invalid identity hash length".to_string());
    }

    let mut map = vec![
        (Value::from("blackhole_identity"), Value::Binary(dest_bytes)),
    ];

    if let Some(hours) = args.blackhole_duration {
        let secs = hours * 3600.0;
        map.push((Value::from("duration"), Value::from(secs)));
    }

    if let Some(ref reason) = args.blackhole_reason {
        map.push((Value::from("reason"), Value::from(reason.clone())));
    }

    let request = Value::Map(map);
    let response = rpc_call(conn, &request)?;

    if response.as_bool().unwrap_or(false) {
        println!("Blackholed identity {dest}");
        Ok(0)
    } else {
        println!("Could not blackhole identity {dest}");
        Ok(1)
    }
}

fn do_unblackhole(conn: &Conn, args: &Args) -> Result<i32, String> {
    let dest = args.destination.as_ref().unwrap();
    let dest_bytes = decode_hex(dest)?;
    if dest_bytes.len() != ADDRESS_HASH_SIZE {
        return Err("Invalid identity hash length".to_string());
    }

    let request = Value::Map(vec![
        (Value::from("unblackhole_identity"), Value::Binary(dest_bytes)),
    ]);
    let response = rpc_call(conn, &request)?;

    if response.as_bool().unwrap_or(false) {
        println!("Lifted blackhole for identity {dest}");
        Ok(0)
    } else {
        println!("Identity {dest} was not blackholed");
        Ok(1)
    }
}

fn do_path_info(conn: &Conn, dest: &str, _args: &Args) -> Result<i32, String> {
    let dest_bytes = decode_hex(dest)?;
    if dest_bytes.len() != ADDRESS_HASH_SIZE {
        return Err("Invalid destination hash length".to_string());
    }
    let dest_hex = pretty_hex(&dest_bytes);

    // Prefer an already-known path: display it without re-broadcasting a
    // path request (matches Python rnpath's has_path() short-circuit).
    let path_map = match lookup_path_entry(conn, &dest_bytes) {
        Some(entry) => entry,
        None => {
            let request = Value::Map(vec![
                (Value::from("get"), Value::from("request_path")),
                (Value::from("destination_hash"), Value::Binary(dest_bytes)),
            ]);
            let response = rpc_call(conn, &request)?;
            match response.as_map() {
                Some(map) => map.clone(),
                None => return Err("Invalid response from request_path".to_string()),
            }
        }
    };

    if map_get_bool(&path_map, "found").unwrap_or(false)
        || map_get_bytes(&path_map, "hash").is_some()
    {
        let names = interface_names(conn);

        let hops = map_get_u64(&path_map, "hops").unwrap_or(1);
        let via = map_get_bytes(&path_map, "next_hop").or_else(|| map_get_bytes(&path_map, "via"));
        let iface = map_get_bytes(&path_map, "interface");
        let expires = map_get_f64(&path_map, "expires");

        let hop_str = if hops == 1 { " hop" } else { " hops" };
        if let Some(nh) = via {
            let iface_str = format_iface(iface, &names);
            print!(
                "Path found, destination {dest_hex} is {hops}{hop_str} away via {} on {iface_str}",
                pretty_hex(nh),
            );
        } else {
            print!("Path found, destination {dest_hex} is {hops}{hop_str} away");
        }

        if let Some(exp) = expires {
            if exp > 0.0 {
                print!(" expires {}", pretty_duration(exp));
            }
        }

        // Render first-hop radio signal if relevant
        let snr = fetch_snr(conn).unwrap_or(None);
        let rssi = fetch_rssi(conn).unwrap_or(None);
        if snr.is_some() || rssi.is_some() {
            print!(" (via radio: ");
            if let Some(snr_value) = snr {
                print!("SNR: {snr_value:.1} dB");
            }
            if let Some(rssi_value) = rssi {
                if snr.is_some() {
                    print!(" ");
                }
                print!("RSSI: {rssi_value} dBm");
            }
            print!(")");
        }
        print!("\n");
        Ok(0)
    } else {
        println!("No path known");
        Ok(1)
    }
}

/// Look up the path-table entry for `dest`, if one is currently known.
fn lookup_path_entry(conn: &Conn, dest: &[u8]) -> Option<Vec<(Value, Value)>> {
    let request = Value::Map(vec![(Value::from("get"), Value::from("path_table"))]);
    let response = rpc_call(conn, &request).ok()?;
    let entries = response.as_array()?;
    for entry in entries {
        let map = entry.as_map()?;
        if map_get_bytes(map, "hash") == Some(dest) {
            return Some(map.clone());
        }
    }
    None
}

// ── Helpers ──

fn map_get_bytes<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a [u8]> {
    map.iter().find_map(|(k, v)| {
        if k.as_str() == Some(key) { v.as_slice() } else { None }
    })
}

fn map_get_u64(map: &[(Value, Value)], key: &str) -> Option<u64> {
    map.iter().find_map(|(k, v)| {
        if k.as_str() == Some(key) { v.as_u64() } else { None }
    })
}

fn map_get_bool(map: &[(Value, Value)], key: &str) -> Option<bool> {
    map.iter().find_map(|(k, v)| {
        if k.as_str() == Some(key) { v.as_bool() } else { None }
    })
}

fn map_get_f64(map: &[(Value, Value)], key: &str) -> Option<f64> {
    map.iter().find_map(|(k, v)| {
        if k.as_str() == Some(key) { v.as_f64() } else { None }
    })
}

fn map_get_str<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a str> {
    map.iter().find_map(|(k, v)| {
        if k.as_str() == Some(key) { v.as_str() } else { None }
    })
}

fn fetch_snr(conn: &Conn) -> Result<Option<f64>, String> {
    let request = Value::Map(vec![
        (Value::from("get"), Value::from("packet_snr")),
    ]);
    let response = rpc_call(conn, &request)?;
    Ok(response.as_f64())
}

fn fetch_rssi(conn: &Conn) -> Result<Option<i64>, String> {
    let request = Value::Map(vec![
        (Value::from("get"), Value::from("packet_rssi")),
    ]);
    let response = rpc_call(conn, &request)?;
    Ok(response.as_i64())
}

fn path_entry_to_json(entry: &Value) -> Option<serde_json::Value> {
    let map = entry.as_map()?;
    let hash = map_get_bytes(map, "hash")?;
    let hops = map_get_u64(map, "hops").unwrap_or(0);
    let via = map_get_bytes(map, "via")?;
    let iface = map_get_bytes(map, "interface")?;
    let expires = map_get_f64(map, "expires").unwrap_or(0.0);

    Some(serde_json::json!({
        "hash": hex_encode(hash),
        "hops": hops,
        "via": hex_encode(via),
        "interface": hex_encode(iface),
        "expires": expires,
    }))
}

fn rate_entry_to_json(entry: &Value) -> Option<serde_json::Value> {
    let map = entry.as_map()?;
    let hash = map_get_bytes(map, "hash")?;
    let last = map_get_f64(map, "last").unwrap_or(0.0);
    let violations = map_get_u64(map, "rate_violations").unwrap_or(0);
    let blocked = map_get_f64(map, "blocked_until").unwrap_or(0.0);

    Some(serde_json::json!({
        "hash": hex_encode(hash),
        "last": last,
        "rate_violations": violations,
        "blocked_until": blocked,
    }))
}

fn pretty_hex(bytes: &[u8]) -> String {
    format!("/{}/", hex_encode(bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut out, "{byte:02x}").unwrap();
    }
    out
}

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    let input = input.trim();
    if input.len() % 2 != 0 {
        return Err("Invalid hexadecimal input".to_string());
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    for i in (0..input.len()).step_by(2) {
        let byte = u8::from_str_radix(&input[i..i + 2], 16)
            .map_err(|_| "Invalid hexadecimal input".to_string())?;
        out.push(byte);
    }
    Ok(out)
}

fn pretty_duration(secs: f64) -> String {
    if secs <= 0.0 {
        return "now".to_string();
    }
    let total_secs = secs as u64;
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    if days > 0 {
        format!("{days}d {hours}h {minutes}m {seconds}s")
    } else if hours > 0 {
        format!("{hours}h {minutes}m {seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

fn print_help() {
    println!("Reticulum Path Management Utility");
    println!();
    println!("Usage: rnpath [OPTIONS] [destination]");
    println!();
    println!("Operations:");
    println!("  <destination>           Get path information to a destination");
    println!("  -t, --table             Show all known paths");
    println!("  -m, --max <hops>        Maximum hops to filter path table by");
    println!("  -r, --rates             Show announce rate information");
    println!("  -d, --drop              Remove the path to a destination");
    println!("  -D, --drop-announces    Drop all queued announces");
    println!("  -x, --drop-via          Drop all paths via specified transport");
    println!("  -b, --blackholed        List blackholed identities");
    println!("  -B, --blackhole         Blackhole an identity");
    println!("  -U, --unblackhole       Lift a blackhole");
    println!();
    println!("Blackhole options:");
    println!("  --duration <hours>      Duration of blackhole enforcement");
    println!("  --reason <text>         Reason for blackholing");
    println!();
    println!("Connection:");
    println!("  -H, --host <host>       RPC control host (default: {DEFAULT_CONTROL_HOST})");
    println!("  -p, --port <port>       RPC control port (default: {DEFAULT_CONTROL_PORT})");
    println!("  -k, --rpc-key <key>     RPC key for authentication (hex, file path, or RETICULUM_RPC_KEY env)");
    println!();
    println!("Output:");
    println!("  -j, --json              Output in JSON format");
    println!("  -v, --verbose           Increase verbosity");
    println!("  -h, --help              Show this help");
    println!("  --version               Show version");
}
