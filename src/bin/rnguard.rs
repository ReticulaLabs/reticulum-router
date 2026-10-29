//! rnguard — announce-rate watchdog for a local Reticulum instance.
//!
//! Subscribes to the instance RPC event stream, counts every announce heard
//! on the mesh per destination inside a rolling one-hour window, and
//! blackholes any destination that exceeds the threshold.
//!
//! Announce floods are the primary way a single misbehaving node degrades a
//! Reticulum transport: every announce is re-broadcast by each node that
//! hears it. The transport's own rate limiter only reacts when an interface
//! configures `announce_rate_target`, so on a default instance nothing stops
//! a destination announcing several times a minute. rnguard watches the
//! announce stream and enforces a ceiling itself.
//!
//! Announce identity is tracked by destination address hash (the only stable
//! key the RPC event stream exposes), and the blackhole is filed against
//! same hash.

use std::collections::{HashMap, HashSet};
use std::env;
use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::{StdRng, SysRng};
use rmpv::{Value, decode::read_value, encode::write_value};
use sha2::Sha256;

const TOOL_NAME: &str = "rnguard";

const PY_CONN_CHALLENGE: &[u8] = b"#CHALLENGE#";
const PY_CONN_WELCOME: &[u8] = b"#WELCOME#";
const PY_CONN_FAILURE: &[u8] = b"#FAILURE#";
const PY_CONN_AUTH_MAX_FRAME: usize = 256;
const MAX_RPC_FRAME: usize = 16 * 1024 * 1024;

const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_CONTROL_PORT: u16 = 37429;

const ADDRESS_HASH_SIZE: usize = 16;
/// `PacketType::Announce` as reported in the `listen` `packet_type` field.
const PACKET_TYPE_ANNOUNCE: u64 = 0b01;

/// Announcements per window tolerated before a destination is blackholed.
const DEFAULT_THRESHOLD: u32 = 50;
/// Rolling window over which announcements are counted.
const DEFAULT_WINDOW_SECS: u64 = 3600;
/// Interface fan-out for a single logical announce lands within a couple of
/// seconds; 30s coalesces that burst without merging genuine re-announces
/// (Reticulum nodes re-announce on the order of every 10 minutes).
const DEFAULT_COALESCE_SECS: u64 = 30;
/// How often expired per-destination histories are swept out of the table.
const PRUNE_INTERVAL: Duration = Duration::from_secs(60);
/// How often `--verbose` prints a progress summary.
const REPORT_INTERVAL: Duration = Duration::from_secs(10);
/// Delay before retrying a dropped subscription.
const RECONNECT_DELAY: Duration = Duration::from_secs(5);
/// Read timeout on the event stream, so periodic work still runs while idle.
const LISTEN_READ_TIMEOUT: Duration = Duration::from_secs(1);

type RResult<T> = Result<T, String>;

// ── CLI ──────────────────────────────────────────────────────────────

#[derive(Clone)]
struct Args {
    host: String,
    control_port: u16,
    rpc_key: Vec<u8>,
    threshold: u32,
    window: Duration,
    coalesce: Duration,
    /// Blackhole lifetime in hours; `None` files an indefinite blackhole.
    duration: Option<f64>,
    dry_run: bool,
    /// Exit after this many blackhole actions (0 = run forever).
    once: Option<u32>,
    verbose: bool,
}

fn print_help() {
    println!("rnguard — announce-rate watchdog for reticulum-router");
    println!();
    println!("Usage: rnguard [options]");
    println!();
    println!("Options:");
    println!("  -H, --host <host>          RPC bind host (default: {DEFAULT_HOST})");
    println!("  -P, --control-port <port>  RPC control port (default: {DEFAULT_CONTROL_PORT})");
    println!("  -k, --rpc-key <hex|path>   Shared instance RPC key");
    println!(
        "  -l, --threshold <n>        Announcements per window before blackholing (default: {DEFAULT_THRESHOLD})"
    );
    println!(
        "  -w, --window <secs>        Counting window in seconds (default: {DEFAULT_WINDOW_SECS})"
    );
    println!(
        "  -c, --coalesce <secs>     Merge announces for one destination arriving within this many seconds (default: {DEFAULT_COALESCE_SECS})"
    );
    println!("  -d, --duration <hours>     Blackhole duration in hours (default: indefinite)");
    println!("  -n, --dry-run              Report offenders without blackholing");
    println!("  --once <n>                 Exit after <n> blackhole actions");
    println!("  -v, --verbose              Log every announce counted");
    println!("  --version                  Show version");
    println!("  -h, --help                 Show this help");
    println!();
    println!("The RPC key may also be supplied via the RETICULUM_RPC_KEY environment variable.");
}

fn next_value<I>(it: &mut std::iter::Peekable<I>, flag: &str) -> RResult<String>
where
    I: Iterator<Item = String>,
{
    it.next()
        .ok_or_else(|| format!("argument {flag} expected one value"))
}

fn parse_args() -> RResult<Args> {
    let mut host = DEFAULT_HOST.to_string();
    let mut control_port = DEFAULT_CONTROL_PORT;
    let mut rpc_key: Option<String> = None;
    let mut threshold = DEFAULT_THRESHOLD;
    let mut window_secs = DEFAULT_WINDOW_SECS;
    let mut coalesce_secs = DEFAULT_COALESCE_SECS;
    let mut duration = None;
    let mut dry_run = false;
    let mut once = None;
    let mut verbose = false;

    let mut it = env::args().skip(1).peekable();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            "--version" => {
                println!("{TOOL_NAME} {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-H" | "--host" => host = next_value(&mut it, &arg)?,
            "-P" | "--control-port" => {
                let val = next_value(&mut it, &arg)?;
                control_port = val
                    .parse::<u16>()
                    .map_err(|_| "Invalid control port".to_string())?;
            }
            "-k" | "--rpc-key" => rpc_key = Some(next_value(&mut it, &arg)?),
            "-l" | "--threshold" => {
                let val = next_value(&mut it, &arg)?;
                threshold = val
                    .parse::<u32>()
                    .map_err(|_| "Invalid threshold".to_string())?;
                if threshold == 0 {
                    return Err("Threshold must be at least 1".to_string());
                }
            }
            "-w" | "--window" => {
                let val = next_value(&mut it, &arg)?;
                window_secs = val
                    .parse::<u64>()
                    .map_err(|_| "Invalid window".to_string())?;
                if window_secs == 0 {
                    return Err("Window must be at least 1 second".to_string());
                }
            }
            "-c" | "--coalesce" => {
                let val = next_value(&mut it, &arg)?;
                coalesce_secs = val
                    .parse::<u64>()
                    .map_err(|_| "Invalid coalesce window".to_string())?;
            }
            "-d" | "--duration" => {
                let val = next_value(&mut it, &arg)?;
                duration = Some(
                    val.parse::<f64>()
                        .map_err(|_| "Invalid duration".to_string())?,
                );
            }
            "-n" | "--dry-run" => dry_run = true,
            "--once" => {
                let val = next_value(&mut it, &arg)?;
                once = Some(
                    val.parse::<u32>()
                        .map_err(|_| "Invalid --once count".to_string())?,
                );
            }
            "-v" | "--verbose" => verbose = true,
            other => return Err(format!("unrecognized argument: {other}")),
        }
    }

    let key = match rpc_key {
        Some(k) => k,
        None => env::var("RETICULUM_RPC_KEY").map_err(|_| {
            "No RPC key specified. Use --rpc-key <hex|path> or set RETICULUM_RPC_KEY.".to_string()
        })?,
    };

    Ok(Args {
        host,
        control_port,
        rpc_key: resolve_rpc_key(&key)?,
        threshold,
        window: Duration::from_secs(window_secs),
        coalesce: Duration::from_secs(coalesce_secs),
        duration,
        dry_run,
        once,
        verbose,
    })
}

/// Accept an RPC key either as a hex string or as a path to a key file.
fn resolve_rpc_key(key: &str) -> RResult<Vec<u8>> {
    let path = std::path::Path::new(key);
    if path.is_file() {
        let data = std::fs::read_to_string(path)
            .map_err(|e| format!("Could not read RPC key file: {e}"))?;
        return decode_hex(data.trim());
    }
    decode_hex(key)
}

// ── Announce rate accounting ─────────────────────────────────────────

/// Rolling per-destination announce counter.
///
/// Each destination keeps the timestamps of the announces seen inside the
/// configured window; the count is simply the number of live timestamps. A
/// destination is reported once per exceedance — while it keeps announcing
/// past the threshold the report is not repeated, but the destination stays
/// out of the table only after its history ages out of the window.
///
/// Raw packet counts are not announce counts. A single announce is re-broadcast
/// by every node that hears it and arrives once *per interface*: on a mesh
/// node with ~19 backbone links, one logical announce shows up as ~19 packets
/// within a second or two. Counting raw packets therefore inflates a
/// well-behaved node by an order of magnitude. `coalesce` collapses that
/// fan-out by treating announces for one destination arriving within
/// `coalesce_window` of each other as a single announce.
struct AnnounceRateTracker {
    window: Duration,
    threshold: u32,
    /// Minimum spacing between two *counted* announces for one destination.
    coalesce: Duration,
    history: HashMap<Vec<u8>, Vec<Instant>>,
    reported: HashSet<Vec<u8>>,
}

impl AnnounceRateTracker {
    fn new(window: Duration, threshold: u32, coalesce: Duration) -> Self {
        Self {
            window,
            threshold,
            coalesce,
            history: HashMap::new(),
            reported: HashSet::new(),
        }
    }

    /// Record an announce for `destination`. Returns the announce count in
    /// the current window the first time the destination crosses the
    /// threshold, and `None` on every other announce.
    ///
    /// Packets arriving within `coalesce` of this destination's previous
    /// packet are the same logical announce fanned out across interfaces and
    /// are discarded without counting.
    fn record(&mut self, destination: &[u8], now: Instant) -> Option<u32> {
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        let stamps = self.history.entry(destination.to_vec()).or_default();
        stamps.retain(|stamp| *stamp > cutoff);

        // Collapse interface fan-out for one logical announce.
        if let Some(last) = stamps.last()
            && now.duration_since(*last) < self.coalesce
        {
            return None;
        }
        stamps.push(now);

        let count = stamps.len() as u32;
        if count > self.threshold && self.reported.insert(destination.to_vec()) {
            return Some(count);
        }
        None
    }

    /// Announce count currently observed for a destination, aging out
    /// timestamps that have fallen outside the window.
    fn count(&mut self, destination: &[u8], now: Instant) -> u32 {
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        match self.history.get_mut(destination) {
            Some(stamps) => {
                stamps.retain(|stamp| *stamp > cutoff);
                stamps.len() as u32
            }
            None => 0,
        }
    }

    /// Drop destinations that have been quiet for a full window, and clear
    /// the reported flag so a fresh flood is reported again.
    fn prune(&mut self, now: Instant) -> usize {
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        let before = self.history.len();
        self.history.retain(|_, stamps| {
            stamps.retain(|stamp| *stamp > cutoff);
            !stamps.is_empty()
        });
        let removed = before - self.history.len();
        self.reported.retain(|dest| self.history.contains_key(dest));
        removed
    }

    /// Number of destinations currently being tracked.
    fn tracked(&self) -> usize {
        self.history.len()
    }
}

// ── RPC plumbing ─────────────────────────────────────────────────────

/// Connection parameters for the RPC control port. The server handles one
/// request per authenticated connection, so every call dials afresh.
struct Control {
    host: String,
    port: u16,
    rpc_key: Vec<u8>,
}

impl Control {
    /// File a blackhole for `destination`, recording `reason` and optionally
    /// an expiry after `duration_hours`. Returns whether the instance added
    /// a new entry (an already-blackholed identity reports false).
    fn blackhole(
        &self,
        destination: &[u8],
        reason: &str,
        duration_hours: Option<f64>,
    ) -> RResult<bool> {
        let mut map = vec![(
            Value::from("blackhole_identity"),
            Value::Binary(destination.to_vec()),
        )];
        if let Some(hours) = duration_hours {
            map.push((Value::from("duration"), Value::from(hours * 3600.0)));
        }
        map.push((Value::from("reason"), Value::from(reason.to_string())));

        let mut stream = connect_rpc(&self.host, self.port, &self.rpc_key)?;
        send_rpc_request(&mut stream, &Value::Map(map))
            .map(|response| response.as_bool().unwrap_or(false))
    }
}

fn connect_rpc(host: &str, port: u16, rpc_key: &[u8]) -> RResult<TcpStream> {
    let addr = format!("{host}:{port}");
    let mut stream =
        TcpStream::connect(&addr).map_err(|e| format!("Could not connect to {addr}: {e}"))?;

    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| format!("Could not set read timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|e| format!("Could not set write timeout: {e}"))?;

    // Server sends a challenge; answer it with the shared-key HMAC.
    let challenge = read_frame(&mut stream, PY_CONN_AUTH_MAX_FRAME)?;
    if !challenge.starts_with(PY_CONN_CHALLENGE) {
        return Err("Server did not send a challenge".to_string());
    }
    let message = &challenge[PY_CONN_CHALLENGE.len()..];
    write_frame(&mut stream, &hmac_response(rpc_key, message)?)?;

    let welcome = read_frame(&mut stream, PY_CONN_AUTH_MAX_FRAME)?;
    if welcome == PY_CONN_FAILURE {
        return Err("Authentication failed: server rejected RPC key".to_string());
    }
    if welcome != PY_CONN_WELCOME {
        return Err("Unexpected response during authentication".to_string());
    }

    // Client-side mutual auth: challenge the server to prove it knows the key.
    let peer_challenge = shared_rpc_challenge();
    write_frame(&mut stream, &peer_challenge)?;

    let peer_response = read_frame(&mut stream, PY_CONN_AUTH_MAX_FRAME)?;
    if !response_is_authenticated(&peer_challenge, &peer_response, rpc_key)? {
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

fn response_is_authenticated(challenge: &[u8], response: &[u8], auth_key: &[u8]) -> RResult<bool> {
    let message = &challenge[PY_CONN_CHALLENGE.len()..];
    let expected = hmac_response(auth_key, message)?;
    let expected_raw = &expected[b"{sha256}".len()..];
    Ok(response == expected.as_slice() || response == expected_raw)
}

fn hmac_response(auth_key: &[u8], message: &[u8]) -> RResult<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(auth_key).map_err(|e| e.to_string())?;
    mac.update(message);
    let digest = mac.finalize().into_bytes();

    let mut response = Vec::with_capacity(b"{sha256}".len() + digest.len());
    response.extend_from_slice(b"{sha256}");
    response.extend_from_slice(&digest);
    Ok(response)
}

fn read_frame(stream: &mut TcpStream, max_size: usize) -> RResult<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("Failed to read frame length: {e}"))?;

    let len = i32::from_be_bytes(len_buf);
    let data_len: usize = if len == -1 {
        let mut big_len_buf = [0u8; 8];
        stream
            .read_exact(&mut big_len_buf)
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
        stream
            .read_exact(&mut data)
            .map_err(|e| format!("Failed to read frame data: {e}"))?;
    }
    Ok(data)
}

fn write_frame(stream: &mut TcpStream, data: &[u8]) -> RResult<()> {
    let len = data.len();
    if len <= i32::MAX as usize {
        stream
            .write_all(&(len as i32).to_be_bytes())
            .map_err(|e| format!("Failed to write frame length: {e}"))?;
    } else {
        stream
            .write_all(&(-1i32).to_be_bytes())
            .map_err(|e| format!("Failed to write frame length: {e}"))?;
        stream
            .write_all(&(len as u64).to_be_bytes())
            .map_err(|e| format!("Failed to write large frame length: {e}"))?;
    }
    stream
        .write_all(data)
        .map_err(|e| format!("Failed to write frame data: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("Failed to flush: {e}"))?;
    Ok(())
}

fn send_rpc_request(stream: &mut TcpStream, request: &Value) -> RResult<Value> {
    let mut encoded = Vec::new();
    write_value(&mut encoded, request).map_err(|e| format!("Failed to encode request: {e}"))?;
    write_frame(stream, &encoded)?;
    let response_data = read_frame(stream, MAX_RPC_FRAME)?;
    read_value(&mut &response_data[..]).map_err(|e| format!("Failed to decode response: {e}"))
}

/// Non-blocking frame reader over an RPC event stream.
///
/// The event stream keeps the connection open indefinitely and pushes frames
/// traffic arrives, so the socket carries a read timeout. A timeout mid-frame
/// must not lose the bytes already buffered, which is why partial reads are
/// retained here rather than discarded.
struct FrameReader {
    stream: TcpStream,
    buf: Vec<u8>,
    start: usize,
}

impl FrameReader {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            buf: Vec::new(),
            start: 0,
        }
    }

    /// Read the next frame, or `Ok(None)` when the read timed out with
    /// nothing buffered.
    fn next_frame(&mut self, max_size: usize) -> RResult<Option<Vec<u8>>> {
        loop {
            if let Some(frame) = self.take_frame(max_size)? {
                return Ok(Some(frame));
            }
            if !self.fill()? {
                return Ok(None);
            }
        }
    }

    /// Returns a complete frame when the buffer already holds one.
    fn take_frame(&mut self, max_size: usize) -> RResult<Option<Vec<u8>>> {
        let available = self.buf.len() - self.start;
        if available < 4 {
            return Ok(None);
        }

        let len = i32::from_be_bytes([
            self.buf[self.start],
            self.buf[self.start + 1],
            self.buf[self.start + 2],
            self.buf[self.start + 3],
        ]);
        let header_len = if len == -1 { 12 } else { 4 };
        if available < header_len {
            return Ok(None);
        }

        let data_len: usize = if len == -1 {
            let mut big = [0u8; 8];
            big.copy_from_slice(&self.buf[self.start + 4..self.start + 12]);
            u64::from_be_bytes(big) as usize
        } else if len < 0 {
            return Err("Invalid frame length".to_string());
        } else {
            len as usize
        };

        if data_len > max_size {
            return Err(format!("Frame too large: {data_len} > {max_size}"));
        }
        if available < header_len + data_len {
            return Ok(None);
        }

        let from = self.start + header_len;
        let frame = self.buf[from..from + data_len].to_vec();
        self.start = from + data_len;

        if self.start > 0 && self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        } else if self.start > 64 * 1024 {
            self.buf.drain(..self.start);
            self.start = 0;
        }

        Ok(Some(frame))
    }

    /// Pull more bytes off the socket. Returns false on a read timeout with
    /// an empty buffer, true otherwise (including on a partial read).
    fn fill(&mut self) -> RResult<bool> {
        self.compact();
        let mut chunk = [0u8; 8192];
        match self.stream.read(&mut chunk) {
            Ok(0) => Err("Instance closed the event stream".to_string()),
            Ok(n) => {
                self.buf.extend_from_slice(&chunk[..n]);
                Ok(true)
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) && self.buf.is_empty() =>
            {
                Ok(false)
            }
            Err(e) => Err(format!("Failed to read from event stream: {e}")),
        }
    }

    /// Reclaim consumed bytes so the buffer does not grow without bound.
    fn compact(&mut self) {
        if self.start > 0 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
    }
}

/// Extract the destination address hash from a `listen` `packet_info`
/// frame, provided the frame describes an announce.
fn announce_destination(frame: &[u8]) -> RResult<Option<Vec<u8>>> {
    let value =
        read_value(&mut &frame[..]).map_err(|e| format!("Failed to decode packet info: {e}"))?;
    let Some(map) = value.as_map() else {
        return Ok(None);
    };

    // A lagged subscriber gets a bare {"lagged": n} notification instead of
    // packet info; it is not an announce.
    if map_get_u64(map, "packet_type") != Some(PACKET_TYPE_ANNOUNCE) {
        if let Some(lagged) = map_get_u64(map, "lagged") {
            log::warn!("{TOOL_NAME}: event stream lagged, missed {lagged} events");
        }
        return Ok(None);
    }

    match map_get_bytes(map, "destination") {
        Some(dest) if dest.len() == ADDRESS_HASH_SIZE => Ok(Some(dest.to_vec())),
        Some(dest) => Err(format!(
            "Announce carried a {}-byte destination hash",
            dest.len()
        )),
        None => Ok(None),
    }
}

/// Build the blackhole reason recorded for an offending destination.
fn violation_reason(destination: &[u8], count: u32, window: Duration) -> String {
    format!(
        "({}) announced {count} times in {}",
        pretty_hex(destination),
        window_phrase(window)
    )
}

fn window_phrase(window: Duration) -> String {
    match window.as_secs() {
        3600 => "an hour".to_string(),
        secs => format!("{}s", secs),
    }
}

// ── Main loop ────────────────────────────────────────────────────────

fn run(args: &Args) -> RResult<()> {
    let control = Control {
        host: args.host.clone(),
        port: args.control_port,
        rpc_key: args.rpc_key.clone(),
    };

    // Fail fast if the control port is unreachable or rejects our key, so a
    // misconfiguration surfaces immediately rather than on the first flood.
    drop(connect_rpc(&control.host, control.port, &control.rpc_key)?);

    let mut tracker = AnnounceRateTracker::new(args.window, args.threshold, args.coalesce);
    let mut stats = Stats::new();

    println!(
        "{TOOL_NAME}: watching announces, blackholing above {} per {} on {}:{}",
        args.threshold,
        window_phrase(args.window),
        args.host,
        args.control_port,
    );
    println!(
        "{TOOL_NAME}: coalescing announce bursts within {}s per destination",
        args.coalesce.as_secs()
    );
    if args.dry_run {
        println!("{TOOL_NAME}: dry run, no blackholes will be filed");
    }

    // The subscription is long-lived: the instance pushes a frame per
    // observed packet and holds the connection open. Any failure on that
    // socket is recoverable, so reconnect rather than exiting.
    //
    // The `listen` request is served by the RPC *control* listener, which is
    // the only socket that runs the RPC request handler. The data port is a
    // raw HDLC interface endpoint and speaks no RPC at all.
    'outer: loop {
        let stream = match connect_rpc(&args.host, args.control_port, &args.rpc_key) {
            Ok(stream) => stream,
            Err(e) => {
                log::warn!(
                    "{TOOL_NAME}: {e}; retrying in {}s",
                    RECONNECT_DELAY.as_secs()
                );
                std::thread::sleep(RECONNECT_DELAY);
                continue;
            }
        };

        // Subscribe to every packet the instance observes. An empty listen
        // config means "no destination filter".
        let mut reader = FrameReader::new(stream);
        match subscribe(&mut reader) {
            Ok(()) => println!("{TOOL_NAME}: subscribed to the instance event stream"),
            Err(e) => {
                log::warn!("{TOOL_NAME}: could not subscribe: {e}");
                std::thread::sleep(RECONNECT_DELAY);
                continue;
            }
        }

        // The handshake used a longer timeout; tighten it so an idle stream
        // still ticks for the periodic sweep.
        reader
            .stream_mut()
            .set_read_timeout(Some(LISTEN_READ_TIMEOUT))
            .ok();

        loop {
            let frame = match reader.next_frame(MAX_RPC_FRAME) {
                Ok(Some(frame)) => Some(frame),
                // Nothing arrived before the read timed out: an idle tick.
                Ok(None) => None,
                Err(e) => {
                    log::warn!("{TOOL_NAME}: {e}; resubscribing");
                    break;
                }
            };

            if let Some(frame) = frame {
                handle_frame(&frame, &mut tracker, &control, args, &mut stats);
            }

            // Swept on both ticks and frames, so a busy announce stream still
            // ages silent destinations out of the table.
            if !sweep(&mut tracker, &mut stats, args) {
                break 'outer;
            }
        }

        std::thread::sleep(RECONNECT_DELAY);
    }

    Ok(())
}

/// Send the listen request and wait for the instance to acknowledge it.
fn subscribe(reader: &mut FrameReader) -> RResult<()> {
    let request = Value::Map(vec![(Value::from("listen"), Value::Map(vec![]))]);
    let mut encoded = Vec::new();
    write_value(&mut encoded, &request)
        .map_err(|e| format!("Failed to encode listen request: {e}"))?;
    write_frame(reader.stream_mut(), &encoded)?;

    let frame = reader
        .next_frame(MAX_RPC_FRAME)?
        .ok_or_else(|| "Instance closed the stream before acknowledging".to_string())?;
    let value = read_value(&mut &frame[..])
        .map_err(|e| format!("Failed to decode listen response: {e}"))?;

    match value.as_map().and_then(|map| map_get_str(map, "status")) {
        Some("listening") => Ok(()),
        Some(other) => Err(format!("Instance refused the listen request: {other}")),
        None => Err("Unexpected response to listen request".to_string()),
    }
}

/// Periodic work: age silent destinations out and report progress. Returns
/// false when the tool should exit.
fn sweep(tracker: &mut AnnounceRateTracker, stats: &mut Stats, args: &Args) -> bool {
    // Progress is reported on its own cadence, independently of pruning, so a
    // short run still shows a summary rather than waiting a full prune period.
    if args.verbose && stats.last_report.elapsed() >= REPORT_INTERVAL {
        stats.last_report = Instant::now();
        println!(
            "{TOOL_NAME}: {} announces seen, {} blackholed, {} destinations tracked",
            stats.announces,
            stats.blackholes,
            tracker.tracked(),
        );
    }

    if stats.last_prune.elapsed() < PRUNE_INTERVAL {
        return true;
    }
    stats.last_prune = Instant::now();

    let dropped = tracker.prune(stats.last_prune);
    if args.verbose && dropped > 0 {
        println!("{TOOL_NAME}: {dropped} destination(s) aged out of the window");
    }

    if let Some(limit) = args.once
        && stats.blackholes >= limit
    {
        println!("{TOOL_NAME}: reached --once limit of {limit}, exiting");
        return false;
    }
    true
}

/// Counters surfaced by `--verbose`, and the marker for the periodic sweep.
struct Stats {
    announces: u64,
    blackholes: u32,
    last_prune: Instant,
    last_report: Instant,
}

impl Stats {
    fn new() -> Self {
        Self {
            announces: 0,
            blackholes: 0,
            last_prune: Instant::now(),
            last_report: Instant::now(),
        }
    }
}

/// Process one event-stream frame, filing a blackhole when the announce pushes
/// its destination over the threshold.
fn handle_frame(
    frame: &[u8],
    tracker: &mut AnnounceRateTracker,
    control: &Control,
    args: &Args,
    stats: &mut Stats,
) {
    let destination = match announce_destination(frame) {
        Ok(Some(destination)) => destination,
        // A malformed frame is not worth dropping the subscription over.
        Ok(None) => return,
        Err(e) => {
            log::warn!("{TOOL_NAME}: {e}");
            return;
        }
    };

    stats.announces += 1;
    let now = Instant::now();

    let Some(count) = tracker.record(&destination, now) else {
        if args.verbose {
            // Logged at info, not trace: `-v` is expected to show activity
            // without the operator also having to raise RUST_LOG.
            log::info!(
                "{TOOL_NAME}: announce {} ({} per window)",
                pretty_hex(&destination),
                tracker.count(&destination, now),
            );
        }
        return;
    };

    let reason = violation_reason(&destination, count, args.window);
    println!("{TOOL_NAME}: {reason}");
    stats.blackholes += 1;

    if args.dry_run {
        return;
    }

    match control.blackhole(&destination, &reason, args.duration) {
        Ok(true) => println!("{TOOL_NAME}: blackholed {reason}"),
        Ok(false) => println!(
            "{TOOL_NAME}: {} was already blackholed",
            pretty_hex(&destination)
        ),
        Err(e) => log::warn!(
            "{TOOL_NAME}: could not blackhole {}: {e}",
            pretty_hex(&destination)
        ),
    }
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = match parse_args() {
        Ok(args) => args,
        Err(msg) => {
            eprintln!("{TOOL_NAME}: {msg}");
            std::process::exit(1);
        }
    };

    if let Err(msg) = run(&args) {
        eprintln!("{TOOL_NAME}: {msg}");
        std::process::exit(1);
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

fn map_get_bytes<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a [u8]> {
    map.iter().find_map(|(k, v)| {
        if k.as_str() == Some(key) {
            v.as_slice()
        } else {
            None
        }
    })
}

fn map_get_u64(map: &[(Value, Value)], key: &str) -> Option<u64> {
    map.iter().find_map(|(k, v)| {
        if k.as_str() == Some(key) {
            v.as_u64()
        } else {
            None
        }
    })
}

fn map_get_str<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a str> {
    map.iter().find_map(|(k, v)| {
        if k.as_str() == Some(key) {
            v.as_str()
        } else {
            None
        }
    })
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

fn decode_hex(input: &str) -> RResult<Vec<u8>> {
    let input = input.trim();
    if !input.len().is_multiple_of(2) {
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

impl FrameReader {
    fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dest(byte: u8) -> Vec<u8> {
        vec![byte; ADDRESS_HASH_SIZE]
    }

    const COALESCE: Duration = Duration::from_secs(30);

    /// Feed `n` announces spaced beyond the coalesce window, so each one
    /// counts as a separate logical announce. Returns the final instant used.
    fn feed(tracker: &mut AnnounceRateTracker, d: &[u8], n: u32) -> Instant {
        let mut now = Instant::now();
        for _ in 0..n {
            now += COALESCE + Duration::from_secs(1);
            tracker.record(d, now);
        }
        now
    }

    fn tracker(window: u64, threshold: u32) -> AnnounceRateTracker {
        AnnounceRateTracker::new(Duration::from_secs(window), threshold, COALESCE)
    }

    #[test]
    fn below_threshold_is_not_reported() {
        let mut tracker = tracker(3600, 50);
        let now = feed(&mut tracker, &dest(1), 50);
        assert_eq!(tracker.count(&dest(1), now), 50);
    }

    #[test]
    fn crossing_threshold_reports_the_count() {
        let mut tracker = tracker(3600, 50);
        let now = feed(&mut tracker, &dest(1), 50);
        assert_eq!(tracker.record(&dest(1), now + COALESCE), Some(51));
    }

    /// The core false-positive guard: one logical announce fanned out across
    /// many interfaces must count once, not once per interface.
    #[test]
    fn interface_fanout_counts_as_one_announce() {
        let mut tracker = tracker(3600, 50);
        let start = Instant::now();
        // 19 interfaces receive the same announce within a 2s burst.
        for i in 0..19 {
            assert_eq!(
                tracker.record(&dest(1), start + Duration::from_millis(i * 100)),
                None
            );
        }
        assert_eq!(tracker.count(&dest(1), start + Duration::from_secs(2)), 1);
    }

    /// Fan-out spread slightly wider than the coalesce window still collapses,
    /// matching real mesh propagation.
    #[test]
    fn fanout_within_coalesce_window_counts_once() {
        let mut tracker = tracker(3600, 50);
        let start = Instant::now();
        for i in 0..10 {
            tracker.record(&dest(1), start + Duration::from_secs(i * 3));
        }
        assert_eq!(tracker.count(&dest(1), start + Duration::from_secs(27)), 1);
    }

    /// Genuine flooding — announces spaced beyond the coalesce window —
    /// must still be counted, and still trip the threshold.
    #[test]
    fn genuine_flood_is_still_counted() {
        let mut tracker = tracker(3600, 10);
        let start = Instant::now();
        let mut tripped = None;
        for i in 0..12 {
            if let Some(count) = tracker.record(&dest(1), start + Duration::from_secs(i * 31)) {
                tripped = Some(count);
                break;
            }
        }
        assert_eq!(tripped, Some(11), "a real flood must still trip");
    }

    /// Coalescing must not merge announces for different destinations.
    #[test]
    fn coalescing_is_per_destination() {
        let mut tracker = tracker(3600, 50);
        let start = Instant::now();
        for i in 0..5 {
            tracker.record(&dest(1), start + Duration::from_millis(i));
            tracker.record(&dest(2), start + Duration::from_millis(i));
        }
        let now = start + Duration::from_secs(5);
        assert_eq!(tracker.count(&dest(1), now), 1);
        assert_eq!(tracker.count(&dest(2), now), 1);
    }

    /// A well-behaved node announcing every 10 minutes must stay far below the
    /// 50/h threshold and never trip.
    #[test]
    fn well_behaved_node_never_trips() {
        let mut tracker = tracker(3600, 50);
        let start = Instant::now();
        let mut peak = 0;
        for i in 0..6 {
            let now = start + Duration::from_secs(i * 600);
            tracker.record(&dest(1), now);
            peak = peak.max(tracker.count(&dest(1), now));
        }
        assert_eq!(peak, 6);
        assert!(peak < 50, "a well-behaved node must not trip");
    }

    #[test]
    fn exceedance_is_reported_only_once() {
        let mut tracker = tracker(3600, 2);
        let now = feed(&mut tracker, &dest(1), 2);
        assert_eq!(tracker.record(&dest(1), now + COALESCE), Some(3));
        // Further announces keep the count but do not re-report.
        assert_eq!(tracker.record(&dest(1), now + COALESCE * 3), None);
        assert_eq!(tracker.count(&dest(1), now + COALESCE * 3), 4);
    }

    #[test]
    fn destinations_are_counted_separately() {
        let mut tracker = tracker(3600, 3);
        let mut now = Instant::now();
        for _ in 0..5 {
            now += COALESCE + Duration::from_secs(1);
            tracker.record(&dest(1), now);
            tracker.record(&dest(2), now);
        }
        assert_eq!(tracker.count(&dest(1), now), 5);
        assert_eq!(tracker.count(&dest(2), now), 5);
    }

    #[test]
    fn announces_age_out_of_the_window() {
        let start = Instant::now();
        let mut tracker = tracker(60, 2);
        tracker.record(&dest(1), start);
        // Two hours later every timestamp is outside the window.
        let later = start + Duration::from_secs(7200);
        assert_eq!(tracker.count(&dest(1), later), 0);
    }

    #[test]
    fn prune_forgets_silent_destinations() {
        let start = Instant::now();
        let mut tracker = tracker(3600, 2);
        tracker.record(&dest(1), start);
        tracker.record(&dest(2), start);
        // Quiet for a full window, so both histories age out.
        let later = start + Duration::from_secs(7200);
        assert_eq!(tracker.prune(later), 2);
        assert_eq!(tracker.tracked(), 0);

        // A destination that was reported and then pruned starts a fresh
        // window, so its next crossing is reported again.
        assert_eq!(tracker.record(&dest(1), later), None);
        let t1 = later + COALESCE + Duration::from_secs(1);
        assert_eq!(tracker.record(&dest(1), t1), None);
        assert_eq!(
            tracker.record(&dest(1), t1 + COALESCE + Duration::from_secs(1)),
            Some(3)
        );
    }

    #[test]
    fn reason_names_destination_and_count() {
        let reason = violation_reason(&dest(0xab), 57, Duration::from_secs(3600));
        assert_eq!(
            reason,
            format!("(/{}/) announced 57 times in an hour", "ab".repeat(16))
        );
    }

    #[test]
    fn reason_adapts_to_a_custom_window() {
        let reason = violation_reason(&dest(0x01), 4, Duration::from_secs(900));
        assert!(
            reason.ends_with("announced 4 times in 900s"),
            "got: {reason}"
        );
    }

    #[test]
    fn announce_frames_yield_their_destination() {
        let frame = packet_info_frame(PACKET_TYPE_ANNOUNCE, &dest(0x7e));
        assert_eq!(announce_destination(&frame).unwrap(), Some(dest(0x7e)));
    }

    #[test]
    fn non_announce_frames_are_ignored() {
        let frame = packet_info_frame(0b00, &dest(0x7e));
        assert_eq!(announce_destination(&frame).unwrap(), None);
    }

    #[test]
    fn lagged_notifications_are_not_announces() {
        let mut encoded = Vec::new();
        write_value(
            &mut encoded,
            &Value::Map(vec![(Value::from("lagged"), Value::from(12u64))]),
        )
        .unwrap();
        assert_eq!(announce_destination(&encoded).unwrap(), None);
    }

    #[test]
    fn frames_with_a_wrong_sized_destination_are_rejected() {
        let frame = packet_info_frame(PACKET_TYPE_ANNOUNCE, &[1, 2, 3]);
        assert!(announce_destination(&frame).is_err());
    }

    #[test]
    fn frame_reader_reassembles_split_frames() {
        let reader = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = reader.local_addr().unwrap();
        let payload = packet_info_frame(PACKET_TYPE_ANNOUNCE, &dest(0x11));
        let framed = {
            let mut buf = (payload.len() as i32).to_be_bytes().to_vec();
            buf.extend_from_slice(&payload);
            buf
        };

        let sender = std::thread::spawn(move || {
            let (mut sock, _) = reader.accept().unwrap();
            // Hand the frame over in small, deliberately uneven chunks.
            for chunk in framed.chunks(3) {
                sock.write_all(chunk).unwrap();
                std::thread::sleep(Duration::from_millis(1));
            }
            // Idle, then a second frame.
            std::thread::sleep(Duration::from_millis(50));
            let mut buf = (payload.len() as i32).to_be_bytes().to_vec();
            buf.extend_from_slice(&payload);
            sock.write_all(&buf).unwrap();
            sock.flush().unwrap();
            // Stay connected so the reader observes an idle timeout rather
            // than an end-of-stream.
            std::thread::sleep(Duration::from_millis(900));
        });

        let sock = TcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let mut reader = FrameReader::new(sock);

        let first = reader.next_frame(MAX_RPC_FRAME).unwrap().unwrap();
        assert_eq!(announce_destination(&first).unwrap(), Some(dest(0x11)));
        let second = reader.next_frame(MAX_RPC_FRAME).unwrap().unwrap();
        assert_eq!(announce_destination(&second).unwrap(), Some(dest(0x11)));
        // Nothing pending: the read times out rather than erroring.
        assert!(reader.next_frame(MAX_RPC_FRAME).unwrap().is_none());

        drop(sender);
    }

    fn packet_info_frame(packet_type: u64, destination: &[u8]) -> Vec<u8> {
        let info = Value::Map(vec![
            (
                Value::from("destination"),
                Value::Binary(destination.to_vec()),
            ),
            (Value::from("hops"), Value::from(1u64)),
            (Value::from("header_type"), Value::from(1u64)),
            (Value::from("packet_type"), Value::from(packet_type)),
            (Value::from("context"), Value::from(0u64)),
            (Value::from("payload_len"), Value::from(10u64)),
            (
                Value::from("iface"),
                Value::Binary(vec![0u8; ADDRESS_HASH_SIZE]),
            ),
            (Value::from("snr"), Value::Nil),
            (Value::from("rssi"), Value::Nil),
        ]);
        let mut encoded = Vec::new();
        write_value(&mut encoded, &info).unwrap();
        encoded
    }
}
