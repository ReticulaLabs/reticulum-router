use hmac::{Hmac, Mac};
use rand::rngs::{StdRng, SysRng};
use rand::Rng;
use rand::SeedableRng;
use rmpv::{Value, decode::read_value, encode::write_value};
use sha2::Sha256;
use std::env;
use std::io::{self, BufRead, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const PY_CONN_CHALLENGE: &[u8] = b"#CHALLENGE#";
const PY_CONN_WELCOME: &[u8] = b"#WELCOME#";
const PY_CONN_FAILURE: &[u8] = b"#FAILURE#";
const PY_CONN_AUTH_MAX_FRAME: usize = 256;
const MAX_RPC_FRAME: usize = 1024 * 1024;
const DEFAULT_CONTROL_PORT: u16 = 37429;
const ADDRESS_HASH_SIZE: usize = 16;
const MIN_RPC_KEY_BYTES: usize = 16; // minimum HMAC key length (32 hex chars)

const MCP_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "rnmcp";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let port = parse_args()?;

    let rpc_key = resolve_rpc_key()?;
    let rpc = RpcConnection::new(port, rpc_key);

    let mut server = McpServer { rpc };
    server.run()
}

fn parse_args() -> Result<u16, String> {
    let mut port = DEFAULT_CONTROL_PORT;
    let mut it = env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            "--version" => {
                println!("rnmcp {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-p" | "--port" => {
                let val = it
                    .next()
                    .ok_or_else(|| "--port requires a value".to_string())?;
                port = val
                    .parse::<u16>()
                    .map_err(|_| format!("invalid port: {val}"))?;
            }
            _ => return Err(format!("unrecognized argument: {arg}")),
        }
    }
    Ok(port)
}

fn print_help() {
    eprintln!("Reticulum MCP Server — Model Context Protocol for LLM debugging");
    eprintln!();
    eprintln!("Reads JSON-RPC requests from stdin, writes responses to stdout.");
    eprintln!("Connects to the reticulum-router daemon's RPC control port.");
    eprintln!();
    eprintln!("Usage: rnmcp [OPTIONS]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -p, --port <port>   RPC control port (default: {DEFAULT_CONTROL_PORT})");
    eprintln!("  -h, --help          Show this help");
    eprintln!("  --version           Show version");
    eprintln!();
    eprintln!("Environment:");
    eprintln!("  RETICULUM_RPC_KEY   RPC key for daemon authentication (required)");
}

fn resolve_rpc_key() -> Result<Vec<u8>, String> {
    let key = match std::env::var("RETICULUM_RPC_KEY") {
        Ok(key) => key,
        Err(_) => return Err(
            "No RPC key specified. Set RETICULUM_RPC_KEY env var to the hex RPC key.".to_string(),
        ),
    };

    let key_bytes = {
        let path = std::path::Path::new(&key);
        if path.is_file() {
            let data =
                std::fs::read_to_string(path).map_err(|e| format!("read key file: {e}"))?;
            decode_hex(data.trim())?
        } else {
            decode_hex(&key)?
        }
    };

    if key_bytes.len() < MIN_RPC_KEY_BYTES {
        return Err(format!(
            "RPC key is too short ({} bytes); minimum is {MIN_RPC_KEY_BYTES} bytes ({} hex characters)",
            key_bytes.len(),
            MIN_RPC_KEY_BYTES * 2,
        ));
    }

    Ok(key_bytes)
}

// ── RPC Connection ──
// The daemon's RPC handler processes one request per connection and closes.
// We create a fresh connection for every RPC call.

struct RpcConnection {
    port: u16,
    rpc_key: Vec<u8>,
}

impl RpcConnection {
    fn new(port: u16, rpc_key: Vec<u8>) -> Self {
        Self { port, rpc_key }
    }

    fn send_rpc(&mut self, request: &Value) -> Result<Value, String> {
        let addr = format!("127.0.0.1:{}", self.port);
        let mut stream = TcpStream::connect(&addr)
            .map_err(|e| format!("connect to {addr}: {e}"))?;

        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| format!("set timeout: {e}"))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| format!("set timeout: {e}"))?;

        // Server sends challenge; client responds with HMAC
        let challenge = read_frame(&mut stream, PY_CONN_AUTH_MAX_FRAME)?;

        if !challenge.starts_with(PY_CONN_CHALLENGE) {
            return Err("server did not send a challenge".to_string());
        }

        let message = &challenge[PY_CONN_CHALLENGE.len()..];
        let response = hmac_response(&self.rpc_key, message)?;
        write_frame(&mut stream, &response)?;

        let welcome = read_frame(&mut stream, PY_CONN_AUTH_MAX_FRAME)?;
        if welcome == PY_CONN_FAILURE {
            return Err("authentication failed: RPC key rejected".to_string());
        }
        if welcome != PY_CONN_WELCOME {
            return Err("unexpected response during authentication".to_string());
        }

        // Mutual auth: challenge the server
        let peer_challenge = generate_challenge();
        write_frame(&mut stream, &peer_challenge)?;

        let peer_response = read_frame(&mut stream, PY_CONN_AUTH_MAX_FRAME)?;
        if !verify_response(&peer_challenge, &peer_response, &self.rpc_key)? {
            return Err("server failed mutual authentication".to_string());
        }

        write_frame(&mut stream, PY_CONN_WELCOME)?;

        // Send the actual RPC request and receive response
        let mut encoded = Vec::new();
        write_value(&mut encoded, request).map_err(|e| format!("encode: {e}"))?;

        write_frame(&mut stream, &encoded)?;

        let response_data = read_frame(&mut stream, MAX_RPC_FRAME)?;
        read_value(&mut &response_data[..])
            .map_err(|e| format!("decode response: {e}"))
    }
}

// ── Frame Protocol (same as rnpath) ──

fn read_frame(stream: &mut TcpStream, max_size: usize) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("read frame length: {e}"))?;

    let len = i32::from_be_bytes(len_buf);
    let data_len: usize = if len == -1 {
        let mut big_len_buf = [0u8; 8];
        stream
            .read_exact(&mut big_len_buf)
            .map_err(|e| format!("read large frame length: {e}"))?;
        u64::from_be_bytes(big_len_buf) as usize
    } else if len < 0 {
        return Err("invalid frame length".to_string());
    } else {
        len as usize
    };

    if data_len > max_size {
        return Err(format!("frame too large: {data_len} > {max_size}"));
    }

    let mut data = vec![0u8; data_len];
    if data_len > 0 {
        stream
            .read_exact(&mut data)
            .map_err(|e| format!("read frame data: {e}"))?;
    }

    Ok(data)
}

fn write_frame(stream: &mut TcpStream, data: &[u8]) -> Result<(), String> {
    let len = data.len();
    if len <= i32::MAX as usize {
        let len_buf = (len as i32).to_be_bytes();
        stream
            .write_all(&len_buf)
            .map_err(|e| format!("write length: {e}"))?;
    } else {
        stream
            .write_all(&(-1i32).to_be_bytes())
            .map_err(|e| format!("write length: {e}"))?;
        stream
            .write_all(&(len as u64).to_be_bytes())
            .map_err(|e| format!("write big length: {e}"))?;
    }

    stream
        .write_all(data)
        .map_err(|e| format!("write data: {e}"))?;
    stream.flush().map_err(|e| format!("flush: {e}"))?;
    Ok(())
}

fn hmac_response(auth_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(auth_key).map_err(|e| format!("HMAC init: {e}"))?;
    mac.update(message);
    let digest = mac.finalize().into_bytes();

    let mut response = Vec::with_capacity(b"{sha256}".len() + digest.len());
    response.extend_from_slice(b"{sha256}");
    response.extend_from_slice(&digest);
    Ok(response)
}

fn generate_challenge() -> Vec<u8> {
    let mut random = [0u8; 40];
    let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();
    rng.fill_bytes(&mut random);

    let mut challenge = Vec::with_capacity(PY_CONN_CHALLENGE.len() + 7 + random.len());
    challenge.extend_from_slice(PY_CONN_CHALLENGE);
    challenge.extend_from_slice(b"{sha256}");
    challenge.extend_from_slice(&random);
    challenge
}

fn verify_response(
    challenge: &[u8],
    response: &[u8],
    auth_key: &[u8],
) -> Result<bool, String> {
    let message = &challenge[PY_CONN_CHALLENGE.len()..];
    let expected = hmac_response(auth_key, message)?;
    let expected_raw = &expected[b"{sha256}".len()..];
    Ok(response == expected.as_slice() || response == expected_raw)
}

// ── MCP Server ──

struct McpServer {
    rpc: RpcConnection,
}

impl McpServer {
    fn run(&mut self) -> Result<(), String> {
        let stdin = io::stdin();
        let reader = stdin.lock();

        for line in reader.lines() {
            let line = line.map_err(|e| format!("stdin read error: {e}"))?;
            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }

            let response = match self.handle_message(&line) {
                Ok(Some(resp)) => resp,
                Ok(None) => continue,
                Err(err) => {
                    // Try to extract request id for proper error response
                    let id = extract_id(&line);
                    make_error_response(id, -32603, &err)
                }
            };

            let resp_json = serde_json::to_string(&response)
                .map_err(|e| format!("serialize response: {e}"))?;
            let mut stdout = io::stdout().lock();
            writeln!(stdout, "{resp_json}").map_err(|e| format!("stdout write: {e}"))?;
            stdout.flush().map_err(|e| format!("stdout flush: {e}"))?;
        }

        Ok(())
    }

    fn handle_message(&mut self, line: &str) -> Result<Option<JsonValue>, String> {
        let msg: JsonValue =
            serde_json::from_str(line).map_err(|e| format!("invalid JSON: {e}"))?;

        let method = msg
            .get("method")
            .and_then(|m| m.as_str())
            .ok_or_else(|| "missing method".to_string())?;

        let id = msg.get("id").cloned();

        match method {
            "initialize" => {
                let result = json_obj(&[
                    ("protocolVersion", JsonValue::String(MCP_VERSION.into())),
                    (
                        "capabilities",
                        json_obj(&[("tools", json_obj(&[]))]),
                    ),
                    (
                        "serverInfo",
                        json_obj(&[
                            ("name", JsonValue::String(SERVER_NAME.into())),
                            ("version", JsonValue::String(SERVER_VERSION.into())),
                        ]),
                    ),
                ]);
                Ok(Some(make_success_response(id, result)))
            }
            "notifications/initialized" => {
                // No response for notifications
                Ok(None)
            }
            "tools/list" => {
                let tools = list_tools();
                let result = json_obj(&[("tools", JsonValue::Array(tools))]);
                Ok(Some(make_success_response(id, result)))
            }
            "tools/call" => {
                let params = msg
                    .get("params")
                    .and_then(|p| p.as_object())
                    .ok_or_else(|| "tools/call requires params object".to_string())?;

                let tool_name = params
                    .get("name")
                    .and_then(|n| n.as_str())
                    .ok_or_else(|| "tool name required".to_string())?;

                let arguments = params
                    .get("arguments")
                    .and_then(|a| a.as_object())
                    .cloned()
                    .unwrap_or_default();

                let result = self.call_tool(tool_name, &arguments)?;
                Ok(Some(make_success_response(id, result)))
            }
            _ => Err(format!("unknown method: {method}")),
        }
    }

    fn call_tool(
        &mut self,
        name: &str,
        args: &JsonMap,
    ) -> Result<JsonValue, String> {
        let text = match name {
            "get_path_table" => self.get_path_table(args)?,
            "get_path_info" => self.get_path_info(args)?,
            "get_rate_table" => self.get_rate_table(args)?,
            "get_signal_info" => self.get_signal_info()?,
            "list_blackholed" => self.list_blackholed(args)?,
            "blackhole_identity" => self.blackhole_identity(args)?,
            "unblackhole_identity" => self.unblackhole_identity(args)?,
            "drop_path" => self.drop_path(args)?,
            "drop_announces" => self.drop_announces()?,
            "get_metrics" => self.get_metrics()?,
            _ => return Err(format!("unknown tool: {name}")),
        };

        Ok(json_obj(&[(
            "content",
            JsonValue::Array(vec![json_obj(&[
                ("type", JsonValue::String("text".into())),
                ("text", JsonValue::String(text)),
            ])]),
        )]))
    }

    // ── Tool Implementations ──

    fn get_path_table(&mut self, args: &JsonMap) -> Result<String, String> {
        let request = Value::Map(vec![(Value::from("get"), Value::from("path_table"))]);
        let response = self.rpc.send_rpc(&request)?;

        let entries = response
            .as_array()
            .ok_or_else(|| "invalid response: expected array".to_string())?;

        let dest_filter = args
            .get("destination")
            .and_then(|v| v.as_str())
            .map(|s| s.to_lowercase());
        let max_hops = args
            .get("max_hops")
            .and_then(|v| v.as_u64())
            .or_else(|| args.get("max_hops").and_then(|v| v.as_i64()).map(|i| i as u64));

        let mut output = format!("Path Table ({} entries):\n", entries.len());
        let mut found = false;

        for entry in entries {
            let map = match entry.as_map() {
                Some(m) => m,
                None => continue,
            };

            let hash = map_get_bytes(map, "hash");
            let hops = map_get_u64(map, "hops").unwrap_or(0);
            let via = map_get_bytes(map, "via");
            let iface = map_get_bytes(map, "interface");
            let expires = map_get_f64(map, "expires").unwrap_or(0.0);

            if let Some(max) = max_hops {
                if hops > max {
                    continue;
                }
            }

            if let Some(ref filter) = dest_filter {
                if let Some(h) = hash {
                    let hex = hex_encode(h);
                    if !hex.contains(filter) {
                        continue;
                    }
                }
            }

            found = true;
            let hash_str = hash.map(|h| hex_encode(h)).unwrap_or_default();
            let via_str = via.map(|h| hex_encode(h)).unwrap_or_default();
            let iface_str = iface.map(|h| hex_encode(h)).unwrap_or_default();
            let expires_str = pretty_duration(expires);

            let hop_label = if hops == 1 { "hop" } else { "hops" };
            output.push_str(&format!(
                "  {hash_str} | {hops} {hop_label} via {via_str} on {iface_str} | expires {expires_str}\n"
            ));
        }

        if !found {
            output.push_str("  (no matching entries)\n");
        }

        Ok(output)
    }

    fn get_path_info(&mut self, args: &JsonMap) -> Result<String, String> {
        let dest = args
            .get("destination")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "destination required".to_string())?;

        let dest_bytes = decode_hex(dest)?;
        if dest_bytes.len() != ADDRESS_HASH_SIZE {
            return Err("invalid destination hash length".to_string());
        }

        let request = Value::Map(vec![
            (Value::from("get"), Value::from("request_path")),
            (
                Value::from("destination_hash"),
                Value::Binary(dest_bytes.clone()),
            ),
        ]);
        let response = self.rpc.send_rpc(&request)?;

        let map = match response.as_map() {
            Some(m) => m,
            None => return Ok("No path known\n".to_string()),
        };

        if map_get_bool(map, "found").unwrap_or(false) {
            let hops = map_get_u64(map, "hops").unwrap_or(1);
            let next_hop = map_get_bytes(map, "next_hop");
            let iface = map_get_bytes(map, "interface");

            let hop_label = if hops == 1 { "hop" } else { "hops" };
            let mut out = format!("Path to {dest}: {hops} {hop_label} away");
            if let Some(nh) = next_hop {
                let iface_str = iface.map(hex_encode).unwrap_or_else(|| "?".to_string());
                out.push_str(&format!(" via {} on {}", hex_encode(nh), iface_str));
            }
            out.push('\n');

            // Also fetch signal info
            let snr = self.rpc.send_rpc(&Value::Map(vec![
                (Value::from("get"), Value::from("packet_snr")),
            ]));
            let rssi = self.rpc.send_rpc(&Value::Map(vec![
                (Value::from("get"), Value::from("packet_rssi")),
            ]));

            if let (Ok(snr_val), Ok(rssi_val)) = (snr, rssi) {
                let has_snr = snr_val.as_f64().is_some();
                let has_rssi = rssi_val.as_i64().is_some();
                if has_snr || has_rssi {
                    out.push_str("  First-hop radio: ");
                    if let Some(snr_v) = snr_val.as_f64() {
                        out.push_str(&format!("SNR {snr_v:.1} dB"));
                    }
                    if let Some(rssi_v) = rssi_val.as_i64() {
                        if has_snr {
                            out.push_str(", ");
                        }
                        out.push_str(&format!("RSSI {rssi_v} dBm"));
                    }
                    out.push('\n');
                }
            }

            Ok(out)
        } else {
            Ok("No path known\n".to_string())
        }
    }

    fn get_rate_table(&mut self, args: &JsonMap) -> Result<String, String> {
        let request = Value::Map(vec![(Value::from("get"), Value::from("rate_table"))]);
        let response = self.rpc.send_rpc(&request)?;

        let entries = response
            .as_array()
            .ok_or_else(|| "invalid response".to_string())?;

        let dest_filter = args
            .get("destination")
            .and_then(|v| v.as_str())
            .map(|s| s.to_lowercase());

        let mut output = format!("Rate Table ({} entries):\n", entries.len());
        let mut found = false;

        for entry in entries {
            let map = match entry.as_map() {
                Some(m) => m,
                None => continue,
            };

            let hash = map_get_bytes(map, "hash");
            let last = map_get_f64(map, "last").unwrap_or(0.0);
            let violations = map_get_u64(map, "rate_violations").unwrap_or(0);
            let blocked = map_get_f64(map, "blocked_until").unwrap_or(0.0);

            if let Some(ref filter) = dest_filter {
                if let Some(h) = hash {
                    let hex = hex_encode(h);
                    if !hex.contains(filter) {
                        continue;
                    }
                }
            }

            found = true;
            let hash_str = hash.map(|h| hex_encode(h)).unwrap_or_default();
            output.push_str(&format!("  {hash_str} | last heard {} ago", pretty_duration(last)));
            if violations > 0 {
                let s = if violations == 1 { "" } else { "s" };
                output.push_str(&format!(", {violations} rate violation{s}"));
            }
            if blocked > 0.0 {
                output.push_str(&format!(", blocked {}", pretty_duration(blocked)));
            }
            output.push('\n');
        }

        if !found {
            output.push_str("  (no matching entries)\n");
        }

        Ok(output)
    }

    fn get_signal_info(&mut self) -> Result<String, String> {
        let snr_req = Value::Map(vec![(Value::from("get"), Value::from("packet_snr"))]);
        let rssi_req = Value::Map(vec![(Value::from("get"), Value::from("packet_rssi"))]);

        let snr = self.rpc.send_rpc(&snr_req)?;
        let rssi = self.rpc.send_rpc(&rssi_req)?;

        let mut output = String::from("Signal Information:\n");
        let has_data = match snr.as_f64() {
            Some(v) => {
                output.push_str(&format!("  SNR: {v:.1} dB\n"));
                true
            }
            None => {
                output.push_str("  SNR: N/A\n");
                false
            }
        };
        match rssi.as_i64() {
            Some(v) => {
                output.push_str(&format!("  RSSI: {v} dBm\n"));
            }
            None => {
                output.push_str("  RSSI: N/A\n");
            }
        }
        if !has_data && rssi.as_i64().is_none() {
            output.push_str("  (no signal data available yet)\n");
        }

        Ok(output)
    }

    fn list_blackholed(&mut self, args: &JsonMap) -> Result<String, String> {
        let request = Value::Map(vec![(
            Value::from("get"),
            Value::from("blackholed_identities"),
        )]);
        let response = self.rpc.send_rpc(&request)?;

        let map = match response.as_map() {
            Some(m) => m,
            None => return Ok("No blackholed identities\n".to_string()),
        };

        let dest_filter = args
            .get("destination")
            .and_then(|v| v.as_str())
            .map(|s| s.to_lowercase());

        if map.is_empty() {
            return Ok("No blackholed identities\n".to_string());
        }

        let mut output = format!("Blackholed Identities ({}):\n", map.len());
        let mut found = false;

        for (key, val) in map {
            let identity_bytes = match key.as_slice() {
                Some(b) => b,
                None => continue,
            };

            let entry_map = match val.as_map() {
                Some(m) => m,
                None => continue,
            };

            let until = map_get_f64(entry_map, "until").unwrap_or(0.0);
            let reason = map_get_str(entry_map, "reason");
            let source = map_get_bytes(entry_map, "source");

            let hash_hex = hex_encode(identity_bytes);
            if let Some(ref filter) = dest_filter {
                if !hash_hex.contains(filter) {
                    continue;
                }
            }

            found = true;
            let until_str = if until > 0.0 {
                format!("for {}", pretty_duration(until))
            } else {
                "indefinitely".to_string()
            };
            let reason_str = reason
                .map(|r| format!(" ({r})"))
                .unwrap_or_default();
            let by_str = source
                .map(|s| format!(" by {}", hex_encode(s)))
                .unwrap_or_default();

            output.push_str(&format!(
                "  {hash_hex} blackholed {until_str}{reason_str}{by_str}\n"
            ));
        }

        if !found {
            output.push_str("  (no matching entries)\n");
        }

        Ok(output)
    }

    fn blackhole_identity(&mut self, args: &JsonMap) -> Result<String, String> {
        let dest = args
            .get("destination")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "destination required".to_string())?;

        let dest_bytes = decode_hex(dest)?;
        if dest_bytes.len() != ADDRESS_HASH_SIZE {
            return Err("invalid identity hash length".to_string());
        }

        let mut map = vec![(
            Value::from("blackhole_identity"),
            Value::Binary(dest_bytes),
        )];

        if let Some(hours) = args
            .get("duration")
            .and_then(|v| v.as_f64())
            .or_else(|| args.get("duration").and_then(|v| v.as_i64()).map(|i| i as f64))
        {
            map.push((Value::from("duration"), Value::from(hours * 3600.0)));
        }

        if let Some(reason) = args.get("reason").and_then(|v| v.as_str()) {
            map.push((Value::from("reason"), Value::from(reason.to_string())));
        }

        let request = Value::Map(map);
        let response = self.rpc.send_rpc(&request)?;

        if response.as_bool().unwrap_or(false) {
            Ok(format!("Blackholed identity {dest}\n"))
        } else {
            Ok(format!("Could not blackhole identity {dest}\n"))
        }
    }

    fn unblackhole_identity(
        &mut self,
        args: &JsonMap,
    ) -> Result<String, String> {
        let dest = args
            .get("destination")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "destination required".to_string())?;

        let dest_bytes = decode_hex(dest)?;
        if dest_bytes.len() != ADDRESS_HASH_SIZE {
            return Err("invalid identity hash length".to_string());
        }

        let request = Value::Map(vec![(
            Value::from("unblackhole_identity"),
            Value::Binary(dest_bytes),
        )]);
        let response = self.rpc.send_rpc(&request)?;

        if response.as_bool().unwrap_or(false) {
            Ok(format!("Lifted blackhole for identity {dest}\n"))
        } else {
            Ok(format!("Identity {dest} was not blackholed\n"))
        }
    }

    fn drop_path(&mut self, args: &JsonMap) -> Result<String, String> {
        let dest = args
            .get("destination")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "destination required".to_string())?;

        let dest_bytes = decode_hex(dest)?;
        if dest_bytes.len() != ADDRESS_HASH_SIZE {
            return Err("invalid destination hash length".to_string());
        }

        let request = Value::Map(vec![
            (Value::from("drop"), Value::from("path")),
            (
                Value::from("destination_hash"),
                Value::Binary(dest_bytes),
            ),
        ]);
        let response = self.rpc.send_rpc(&request)?;

        if response.as_bool().unwrap_or(false) {
            Ok(format!("Dropped path to {dest}\n"))
        } else {
            Ok(format!("No path to {dest} exists\n"))
        }
    }

    fn drop_announces(&mut self) -> Result<String, String> {
        let request = Value::Map(vec![(
            Value::from("drop"),
            Value::from("announce_queues"),
        )]);
        self.rpc.send_rpc(&request)?;
        Ok("Dropped announce queues on all interfaces\n".to_string())
    }

    fn get_metrics(&mut self) -> Result<String, String> {
        let mut output = String::from("Transport Metrics:\n");

        // Path table
        let pt = self.rpc.send_rpc(&Value::Map(vec![
            (Value::from("get"), Value::from("path_table")),
        ]))?;
        let pt_len = pt.as_array().map(|a| a.len()).unwrap_or(0);
        output.push_str(&format!("  Path table entries: {pt_len}\n"));

        // Rate table
        let rt = self.rpc.send_rpc(&Value::Map(vec![
            (Value::from("get"), Value::from("rate_table")),
        ]))?;
        let rt_len = rt.as_array().map(|a| a.len()).unwrap_or(0);
        output.push_str(&format!("  Rate table entries: {rt_len}\n"));

        // Blackholed identities
        let bh = self.rpc.send_rpc(&Value::Map(vec![
            (Value::from("get"), Value::from("blackholed_identities")),
        ]))?;
        let bh_len = bh.as_map().map(|m| m.len()).unwrap_or(0);
        output.push_str(&format!("  Blackholed identities: {bh_len}\n"));

        // Signal info
        let snr = self.rpc.send_rpc(&Value::Map(vec![
            (Value::from("get"), Value::from("packet_snr")),
        ]))?;
        let rssi = self.rpc.send_rpc(&Value::Map(vec![
            (Value::from("get"), Value::from("packet_rssi")),
        ]))?;
        if let Some(snr_v) = snr.as_f64() {
            output.push_str(&format!("  Last SNR: {snr_v:.1} dB\n"));
        }
        if let Some(rssi_v) = rssi.as_i64() {
            output.push_str(&format!("  Last RSSI: {rssi_v} dBm\n"));
        }

        Ok(output)
    }
}

// ── MCP Tool Definitions ──

fn list_tools() -> Vec<JsonValue> {
    vec![
        json_obj(&[
            ("name", JsonValue::String("get_path_table".into())),
            ("description", JsonValue::String("List all known paths in the routing table. Optionally filter by destination hash or max hops.".into())),
            ("inputSchema", json_obj(&[
                ("type", JsonValue::String("object".into())),
                ("properties", json_obj(&[
                    ("destination", json_obj(&[
                        ("type", JsonValue::String("string".into())),
                        ("description", JsonValue::String("Optional hex destination hash filter".into())),
                    ])),
                    ("max_hops", json_obj(&[
                        ("type", JsonValue::String("number".into())),
                        ("description", JsonValue::String("Optional max hop count filter".into())),
                    ])),
                ])),
            ])),
        ]),
        json_obj(&[
            ("name", JsonValue::String("get_path_info".into())),
            ("description", JsonValue::String("Get detailed path information to a specific destination including first-hop radio signal data.".into())),
            ("inputSchema", json_obj(&[
                ("type", JsonValue::String("object".into())),
                ("properties", json_obj(&[
                    ("destination", json_obj(&[
                        ("type", JsonValue::String("string".into())),
                        ("description", JsonValue::String("Hex destination hash".into())),
                    ])),
                ])),
                ("required", JsonValue::Array(vec![
                    JsonValue::String("destination".into()),
                ])),
            ])),
        ]),
        json_obj(&[
            ("name", JsonValue::String("get_rate_table".into())),
            ("description", JsonValue::String("Show announce rate limiting information. Optionally filter by destination hash.".into())),
            ("inputSchema", json_obj(&[
                ("type", JsonValue::String("object".into())),
                ("properties", json_obj(&[
                    ("destination", json_obj(&[
                        ("type", JsonValue::String("string".into())),
                        ("description", JsonValue::String("Optional hex destination hash filter".into())),
                    ])),
                ])),
            ])),
        ]),
        json_obj(&[
            ("name", JsonValue::String("get_signal_info".into())),
            ("description", JsonValue::String("Get SNR and RSSI from the last received packet on the first-hop radio interface.".into())),
            ("inputSchema", json_obj(&[
                ("type", JsonValue::String("object".into())),
                ("properties", json_obj(&[])),
            ])),
        ]),
        json_obj(&[
            ("name", JsonValue::String("list_blackholed".into())),
            ("description", JsonValue::String("List all blackholed identities. Optionally filter by identity hash.".into())),
            ("inputSchema", json_obj(&[
                ("type", JsonValue::String("object".into())),
                ("properties", json_obj(&[
                    ("destination", json_obj(&[
                        ("type", JsonValue::String("string".into())),
                        ("description", JsonValue::String("Optional hex identity hash filter".into())),
                    ])),
                ])),
            ])),
        ]),
        json_obj(&[
            ("name", JsonValue::String("blackhole_identity".into())),
            ("description", JsonValue::String("Blackhole an identity — removes all paths from and via this identity, and ignores their announces. Optionally set a duration (in hours) and reason.".into())),
            ("inputSchema", json_obj(&[
                ("type", JsonValue::String("object".into())),
                ("properties", json_obj(&[
                    ("destination", json_obj(&[
                        ("type", JsonValue::String("string".into())),
                        ("description", JsonValue::String("Hex identity hash to blackhole".into())),
                    ])),
                    ("duration", json_obj(&[
                        ("type", JsonValue::String("number".into())),
                        ("description", JsonValue::String("Blackhole duration in hours (omit for indefinite)".into())),
                    ])),
                    ("reason", json_obj(&[
                        ("type", JsonValue::String("string".into())),
                        ("description", JsonValue::String("Reason for blackholing".into())),
                    ])),
                ])),
                ("required", JsonValue::Array(vec![
                    JsonValue::String("destination".into()),
                ])),
            ])),
        ]),
        json_obj(&[
            ("name", JsonValue::String("unblackhole_identity".into())),
            ("description", JsonValue::String("Lift a blackhole for a previously blackholed identity.".into())),
            ("inputSchema", json_obj(&[
                ("type", JsonValue::String("object".into())),
                ("properties", json_obj(&[
                    ("destination", json_obj(&[
                        ("type", JsonValue::String("string".into())),
                        ("description", JsonValue::String("Hex identity hash to unblackhole".into())),
                    ])),
                ])),
                ("required", JsonValue::Array(vec![
                    JsonValue::String("destination".into()),
                ])),
            ])),
        ]),
        json_obj(&[
            ("name", JsonValue::String("drop_path".into())),
            ("description", JsonValue::String("Drop (remove) the path to a specific destination from the routing table.".into())),
            ("inputSchema", json_obj(&[
                ("type", JsonValue::String("object".into())),
                ("properties", json_obj(&[
                    ("destination", json_obj(&[
                        ("type", JsonValue::String("string".into())),
                        ("description", JsonValue::String("Hex destination hash".into())),
                    ])),
                ])),
                ("required", JsonValue::Array(vec![
                    JsonValue::String("destination".into()),
                ])),
            ])),
        ]),
        json_obj(&[
            ("name", JsonValue::String("drop_announces".into())),
            ("description", JsonValue::String("Drop all queued announces on all interfaces.".into())),
            ("inputSchema", json_obj(&[
                ("type", JsonValue::String("object".into())),
                ("properties", json_obj(&[])),
            ])),
        ]),
        json_obj(&[
            ("name", JsonValue::String("get_metrics".into())),
            ("description", JsonValue::String("Get a summary of transport metrics including path table size, rate table size, blackhole count, and last signal data.".into())),
            ("inputSchema", json_obj(&[
                ("type", JsonValue::String("object".into())),
                ("properties", json_obj(&[])),
            ])),
        ]),
    ]
}

// ── JSON-RPC Helpers ──

type JsonValue = serde_json::Value;
type JsonMap = serde_json::Map<String, JsonValue>;

fn json_obj(pairs: &[(&str, JsonValue)]) -> JsonValue {
    let mut map = serde_json::Map::new();
    for (k, v) in pairs {
        map.insert(k.to_string(), v.clone());
    }
    JsonValue::Object(map)
}

fn make_success_response(id: Option<JsonValue>, result: JsonValue) -> JsonValue {
    let mut resp = json_obj(&[
        ("jsonrpc", JsonValue::String("2.0".into())),
        ("result", result),
    ]);
    if let Some(id) = id {
        resp.as_object_mut()
            .unwrap()
            .insert("id".into(), id);
    }
    resp
}

fn make_error_response(id: Option<JsonValue>, code: i64, message: &str) -> JsonValue {
    let mut resp = json_obj(&[
        ("jsonrpc", JsonValue::String("2.0".into())),
        (
            "error",
            json_obj(&[
                ("code", JsonValue::Number(code.into())),
                ("message", JsonValue::String(message.into())),
            ]),
        ),
    ]);
    if let Some(id) = id {
        resp.as_object_mut()
            .unwrap()
            .insert("id".into(), id);
    }
    resp
}

fn extract_id(line: &str) -> Option<JsonValue> {
    serde_json::from_str::<JsonValue>(line)
        .ok()
        .and_then(|v| v.get("id").cloned())
}

// ── MessagePack Helpers ──

fn map_get_bytes<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a [u8]> {
    map.iter()
        .find_map(|(k, v)| if k.as_str() == Some(key) { v.as_slice() } else { None })
}

fn map_get_u64(map: &[(Value, Value)], key: &str) -> Option<u64> {
    map.iter()
        .find_map(|(k, v)| if k.as_str() == Some(key) { v.as_u64() } else { None })
}

fn map_get_bool(map: &[(Value, Value)], key: &str) -> Option<bool> {
    map.iter()
        .find_map(|(k, v)| if k.as_str() == Some(key) { v.as_bool() } else { None })
}

fn map_get_f64(map: &[(Value, Value)], key: &str) -> Option<f64> {
    map.iter()
        .find_map(|(k, v)| if k.as_str() == Some(key) { v.as_f64() } else { None })
}

fn map_get_str<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a str> {
    map.iter()
        .find_map(|(k, v)| if k.as_str() == Some(key) { v.as_str() } else { None })
}

// ── Formatting Helpers ──

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut out, "{byte:02x}").unwrap();
    }
    out
}

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    let input = input.trim().trim_start_matches('/').trim_end_matches('/');
    if input.len() % 2 != 0 {
        return Err("invalid hexadecimal input".to_string());
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    for i in (0..input.len()).step_by(2) {
        let byte = u8::from_str_radix(&input[i..i + 2], 16)
            .map_err(|_| "invalid hexadecimal input".to_string())?;
        out.push(byte);
    }
    Ok(out)
}

fn pretty_duration(secs: f64) -> String {
    if secs <= 0.0 {
        return "now".to_string();
    }
    let total = secs as u64;
    let days = total / 86400;
    let hours = (total % 86400) / 3600;
    let minutes = (total % 3600) / 60;
    let seconds = total % 60;

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
