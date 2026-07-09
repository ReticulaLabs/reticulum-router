use std::collections::HashSet;
use std::env;
use std::ffi::CString;

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bzip2::write::BzEncoder;
use bzip2::read::BzDecoder;
use bzip2::Compression;
use libc;
use nix::pty::openpty;
use nix::sys::signal::{kill, Signal};
use nix::sys::termios::{tcgetattr, tcsetattr, SetArg, Termios, LocalFlags, InputFlags, OutputFlags, ControlFlags};
use nix::unistd::{dup2, fork, setsid, ForkResult};
use rand::rngs::OsRng;
use reticulum_sdk::destination::link::{Link, LinkEvent};
use reticulum_sdk::destination::{DestinationName, DestinationDesc};
use reticulum_sdk::hash::{ADDRESS_HASH_SIZE, AddressHash};
use reticulum_sdk::identity::{Identity, PrivateIdentity};
use reticulum_sdk::transport::{Transport, TransportConfig};
use rmpv::{Value, decode::read_value, encode::write_value};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;

const APP_NAME: &str = "rnsh";
const PROTOCOL_VERSION: u8 = 1;
const MSG_MAGIC: u16 = 0xAC;
const RNSH_VERSION: &str = "0.2.0";

const MSG_TYPE_WINDOW_SIZE: u16 = msg_type(2);
const MSG_TYPE_EXEC_CMD: u16   = msg_type(3);
const MSG_TYPE_STREAM_DATA: u16 = msg_type(4);
const MSG_TYPE_VERSION_INFO: u16 = msg_type(5);
const MSG_TYPE_ERROR: u16      = msg_type(6);
const MSG_TYPE_CMD_EXITED: u16 = msg_type(7);

const SID_STDIN: u16  = 0;
const SID_STDOUT: u16 = 1;
const SID_STDERR: u16 = 2;
const HDR_EOF: u16         = 0x8000;
const HDR_COMPRESSED: u16  = 0x4000;
const HDR_ID_MASK: u16     = 0x3FFF;

const MAX_CHUNK: usize = 16384;
const COMP_TRIES: u8 = 4;

const fn msg_type(id: u8) -> u16 {
    ((MSG_MAGIC as u16) << 8) | (id as u16)
}

type RResult<T> = Result<T, Box<dyn std::error::Error>>;

macro_rules! bail {
    ($($arg:tt)*) => { return Err(format!($($arg)*).into()) };
}

// ── Config ──────────────────────────────────────────────────────────

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

fn rnsh_dir() -> PathBuf {
    dirs::home_dir().unwrap().join(".config/rnsh")
}

fn load_cfg() -> Option<Cfg> {
    let f = reticulum_cfg_dir().join("config.toml");
    if !f.exists() { return None; }
    let s = fs::read_to_string(&f).ok()?;
    toml::from_str(&s).ok()
}

// ── Identity ────────────────────────────────────────────────────────

fn ident_path(svc: &str) -> PathBuf {
    let d = rnsh_dir();
    if svc.is_empty() || svc == "default" { d.join(APP_NAME) }
    else { d.join(format!("{APP_NAME}.{svc}")) }
}

fn load_ident(path: Option<&str>, svc: &str) -> RResult<PrivateIdentity> {
    if let Some(p) = path {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            let hex = fs::read_to_string(&pb)?.trim().to_string();
            return PrivateIdentity::new_from_hex_string(&hex)
                .map_err(|e| format!("bad identity {pb:?}: {e:?}").into());
        }
        bail!("identity not found: {p}");
    }
    let pb = ident_path(svc);
    if pb.is_file() {
        let hex = fs::read_to_string(&pb)?.trim().to_string();
        let id = PrivateIdentity::new_from_hex_string(&hex)
            .map_err(|e| format!("bad identity {pb:?}: {e:?}"))?;
        log::info!("rnsh: loaded identity from {pb:?}");
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
    log::info!("rnsh: created identity at {pb:?}");
    Ok(id)
}

fn load_allowed() -> Vec<AddressHash> {
    let paths = [rnsh_dir().join("allowed_identities"), dirs::home_dir().unwrap().join(".rnsh/allowed_identities")];
    let mut out = Vec::new();
    for p in &paths {
        if let Ok(f) = fs::File::open(p) {
            for line in BufReader::new(f).lines().flatten() {
                let t = line.trim();
                if t.len() == ADDRESS_HASH_SIZE * 2 {
                    if let Ok(h) = AddressHash::new_from_hex_string(t) { out.push(h); }
                }
            }
        }
    }
    out
}

async fn make_transport(id: PrivateIdentity) -> RResult<Transport> {
    let mut tcfg = TransportConfig::new("rnsh", &id, false);
    tcfg.set_respond_to_probes(true);
    tcfg.set_share_instance(true);
    let t = Transport::new(tcfg);
    let on_shared = t.is_connected_to_shared_instance().await;
    let mgr = t.iface_manager();

    if on_shared {
        log::info!("rnsh: connected to local reticulum shared instance");
        return Ok(t);
    }

    // Load explicit interfaces from the Reticulum config only when
    // running standalone (no shared instance). When connected to a
    // running daemon via the shared instance, the daemon already
    // manages all network connectivity.
    if let Some(cfg) = load_cfg() {
        log::info!("rnsh: loading interfaces from reticulum config");
        for iface in &cfg.interfaces {
            if !iface.enabled { continue; }
            match &iface.config {
                CfgIfaceType::TCPServerInterface { bind_host, bind_port } => {
                    let a = format!("{bind_host}:{bind_port}");
                    log::info!("rnsh: TCP server on {a}");
                    let _ = mgr.lock().await.spawn(
                        reticulum_sdk::iface::tcp_server::TcpServer::new(a, mgr.clone()),
                        reticulum_sdk::iface::tcp_server::TcpServer::spawn,
                    );
                }
                CfgIfaceType::TCPClientInterface { target_host, target_port } => {
                    let a = format!("{target_host}:{target_port}");
                    log::info!("rnsh: TCP client to {a}");
                    let _ = mgr.lock().await.spawn(
                        reticulum_sdk::iface::tcp_client::TcpClient::new(a),
                        reticulum_sdk::iface::tcp_client::TcpClient::spawn,
                    );
                }
                CfgIfaceType::UDPInterface { listen_ip, listen_port, forward_ip, forward_port } => {
                    let b = format!("{listen_ip}:{listen_port}");
                    let f = format!("{forward_ip}:{forward_port}");
                    log::info!("rnsh: UDP {b} -> {f}");
                    let _ = mgr.lock().await.spawn(
                        reticulum_sdk::iface::udp::UdpInterface::new(b, Some(f)),
                        reticulum_sdk::iface::udp::UdpInterface::spawn,
                    );
                }
                CfgIfaceType::AutoInterface {} => log::warn!("rnsh: AutoInterface unsupported"),
                CfgIfaceType::Unsupported => log::warn!("rnsh: skipping unsupported interface"),
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    Ok(t)
}

// ── Protocol ────────────────────────────────────────────────────────

fn pack_ver(sw: &str, pv: u8) -> Vec<u8> {
    let mut b = Vec::new();
    write_value(&mut b, &Value::Array(vec![Value::from(sw), Value::from(pv as i64)])).ok();
    b
}

fn unpack_ver(raw: &[u8]) -> RResult<(String, u8)> {
    let a = read_value(&mut io::Cursor::new(raw))?.as_array().ok_or("ver not array")?.clone();
    Ok((a[0].as_str().unwrap_or("").to_string(), a[1].as_u64().unwrap_or(0) as u8))
}

fn pack_exec(cmd: &[String], pin: bool, pou: bool, per: bool, term: &Option<String>, r: u16, c: u16, h: u16, v: u16) -> Vec<u8> {
    let cmds: Vec<Value> = cmd.iter().map(|s| Value::from(s.as_str())).collect();
    let t = term.as_ref().map(|s| Value::from(s.as_str())).unwrap_or(Value::Nil);
    let val = Value::Array(vec![
        Value::Array(cmds), Value::from(pin), Value::from(pou), Value::from(per), Value::Nil,
        t, Value::from(c as i64), Value::from(r as i64), Value::from(h as i64), Value::from(v as i64),
    ]);
    let mut b = Vec::new();
    write_value(&mut b, &val).ok();
    b
}

fn unpack_exec(raw: &[u8]) -> RResult<(Vec<String>, bool, bool, bool, Option<String>, u16, u16, u16, u16)> {
    let a = read_value(&mut io::Cursor::new(raw))?.as_array().ok_or("exec not array")?.clone();
    let cmd = a.get(0).and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
    let pi = a.get(1).and_then(|v| v.as_bool()).unwrap_or(false);
    let po = a.get(2).and_then(|v| v.as_bool()).unwrap_or(false);
    let pe = a.get(3).and_then(|v| v.as_bool()).unwrap_or(false);
    let term = a.get(5).and_then(|v| v.as_str()).map(String::from);
    let c = a.get(6).and_then(|v| v.as_u64()).unwrap_or(80) as u16;
    let r = a.get(7).and_then(|v| v.as_u64()).unwrap_or(24) as u16;
    let h = a.get(8).and_then(|v| v.as_u64()).unwrap_or(0) as u16;
    let v = a.get(9).and_then(|v| v.as_u64()).unwrap_or(0) as u16;
    Ok((cmd, pi, po, pe, term, r, c, h, v))
}

fn pack_winsz(r: u16, c: u16, h: u16, v: u16) -> Vec<u8> {
    let mut b = Vec::new();
    write_value(&mut b, &Value::Array(vec![Value::from(r as i64), Value::from(c as i64), Value::from(h as i64), Value::from(v as i64)])).ok();
    b
}

fn pack_exit(code: i32) -> Vec<u8> {
    let mut b = Vec::new();
    write_value(&mut b, &Value::from(code as i64)).ok();
    b
}

fn unpack_exit(raw: &[u8]) -> RResult<i32> {
    let v = read_value(&mut io::Cursor::new(raw))?;
    v.as_i64().map(|i| i as i32).ok_or_else(|| "exit decode".into())
}

fn pack_err(msg: &str, fatal: bool) -> Vec<u8> {
    let mut b = Vec::new();
    write_value(&mut b, &Value::Array(vec![Value::from(msg), Value::from(fatal), Value::Nil])).ok();
    b
}

fn unpack_err_msg(raw: &[u8]) -> (String, bool) {
    if let Ok(v) = read_value(&mut io::Cursor::new(raw)) {
        if let Some(a) = v.as_array() {
            return (a[0].as_str().unwrap_or("?").to_string(),
                    a.get(1).and_then(|v| v.as_bool()).unwrap_or(false));
        }
    }
    ("parse error".into(), false)
}

fn stream_hdr(sid: u16, eof: bool, comp: bool) -> Vec<u8> {
    let mut h = sid & HDR_ID_MASK;
    if eof { h |= HDR_EOF; }
    if comp { h |= HDR_COMPRESSED; }
    h.to_be_bytes().to_vec()
}

fn stream_unhdr(raw: &[u8]) -> RResult<(u16, bool, bool)> {
    if raw.len() < 2 { bail!("stream header too short"); }
    let h = u16::from_be_bytes([raw[0], raw[1]]);
    Ok(((h & HDR_ID_MASK), (h & HDR_EOF) != 0, (h & HDR_COMPRESSED) != 0))
}

/// Helper: create and send a channel message on a link.
async fn send_channel(
    link: &Arc<Mutex<Link>>, transport: &Transport, msg_type: u16, payload: &[u8],
) -> RResult<()> {
    let packet = link.lock().await.channel_raw_packet(msg_type, payload)?;
    transport.send_packet(packet).await;
    Ok(())
}

fn compress(buf: &[u8], max: usize) -> (bool, usize, Vec<u8>) {
    let len = buf.len().min(MAX_CHUNK);
    for t in 1..=COMP_TRIES {
        let seg = len / t as usize;
        if seg < 32 { break; }
        let mut enc = BzEncoder::new(Vec::new(), Compression::default());
        if enc.write_all(&buf[..seg]).is_err() { continue; }
        if let Ok(c) = enc.finish() {
            if c.len() < max && c.len() < seg {
                return (true, seg, c);
            }
        }
    }
    let plain = max.min(len);
    (false, plain, buf[..plain].to_vec())
}

fn decompress(data: &[u8], max: usize) -> RResult<Vec<u8>> {
    let mut dec = BzDecoder::new(data);
    let mut out = Vec::with_capacity(max.min(data.len()));
    dec.read_to_end(&mut out)?;
    if out.len() > max { bail!("decompressed data exceeds max"); }
    Ok(out)
}

// ── Terminal ────────────────────────────────────────────────────────

#[repr(C)]
struct WinSz { row: u16, col: u16, xpix: u16, ypix: u16 }

fn winsz(fd: RawFd) -> (u16, u16, u16, u16) {
    let mut ws: WinSz = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws as *mut _) } == 0 {
        (ws.row, ws.col, ws.xpix, ws.ypix)
    } else { (24, 80, 0, 0) }
}

// ── Escape sequences ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum EscapeAction { Disconnect, Help, LineModeEnabled, LineModeDisabled }

#[derive(Default)]
struct EscapeHandler {
    pre_newline: bool,
    esc_active: bool,
    line_mode: bool,
    line_buffer: Vec<u8>,
    blind_write_count: usize,
}

impl EscapeHandler {
    fn process_byte(&mut self, b: u8, out: &mut Vec<u8>) -> Option<EscapeAction> {
        let c = b as char;

        if c == '\r' || c == '\n' {
            self.pre_newline = true;
            self.line_buffer.clear();
            self.blind_write_count = 0;
            out.push(b);
            return None;
        }

        if self.pre_newline && c == '~' {
            self.pre_newline = false;
            self.esc_active = true;
            return None;
        }

        if self.esc_active {
            self.esc_active = false;
            self.pre_newline = false;
            match c {
                '.' => return Some(EscapeAction::Disconnect),
                '?' => return Some(EscapeAction::Help),
                'L' => { self.line_mode = !self.line_mode; return Some(if self.line_mode { EscapeAction::LineModeEnabled } else { EscapeAction::LineModeDisabled }); }
                '~' => { out.push(b'~'); return None; }
                _ => { out.push(b'~'); out.push(b); return None; }
            }
        }

        self.pre_newline = false;

        if self.line_mode {
            if c == '\x08' || c == '\x7f' {
                if !self.line_buffer.is_empty() {
                    self.line_buffer.pop();
                    self.blind_write_count = self.blind_write_count.saturating_sub(1);
                    out.extend_from_slice(b"\x08 \x08");
                }
                return None;
            }
            // Flush on control chars
            if c == '\x01' || c == '\x03' || c == '\x04' || c == '\x05' || c == '\x0c'
                || c == '\x11' || c == '\x13' || c == '\x15' || c == '\x19' || c == '\t'
                || c == '\x1a' || c == '\x1b'
            {
                self.line_buffer.push(b);
                self.flush_line(out);
                return None;
            }
            self.line_buffer.push(b);
            self.blind_write_count += 1;
            out.push(b);
            return None;
        }

        out.push(b);
        None
    }

    fn flush_line(&mut self, out: &mut Vec<u8>) {
        if !self.line_buffer.is_empty() {
            out.extend_from_slice(&self.line_buffer);
            for _ in 0..self.blind_write_count { out.extend_from_slice(b"\x08 \x08"); }
            self.line_buffer.clear();
            self.blind_write_count = 0;
        }
    }
}

struct RawTerm { saved: Option<Termios> }
impl RawTerm {
    fn new() -> Self { RawTerm { saved: None } }
    fn enable(&mut self) -> RResult<()> {
        let mut r = tcgetattr(0)?;
        self.saved = Some(r.clone());
        r.local_flags &= !(LocalFlags::ECHO | LocalFlags::ICANON | LocalFlags::ISIG | LocalFlags::IEXTEN);
        r.input_flags &= !(InputFlags::IGNBRK | InputFlags::BRKINT | InputFlags::PARMRK | InputFlags::ISTRIP
            | InputFlags::INLCR | InputFlags::IGNCR | InputFlags::ICRNL | InputFlags::IXON);
        r.output_flags &= !(OutputFlags::OPOST);
        r.control_flags &= !(ControlFlags::CSIZE);
        r.control_flags |= ControlFlags::CS8;
        r.control_chars[6] = 1; // VMIN
        r.control_chars[5] = 0; // VTIME
        tcsetattr(0, SetArg::TCSANOW, &r)?;
        Ok(())
    }
}
impl Drop for RawTerm {
    fn drop(&mut self) {
        if let Some(ref s) = self.saved {
            let _ = tcsetattr(0, SetArg::TCSANOW, s);
        }
    }
}

// ── Args ────────────────────────────────────────────────────────────

struct Args {
    config: Option<String>, ident: Option<String>, svc: Option<String>,
    listen: bool, scan: bool, verbose: u8, quiet: u8, print_ident: bool,
    announce: Option<u64>, allowed: Vec<String>, no_auth: bool,
    remote_cmd_as_args: bool, no_remote_cmd: bool, no_id: bool,
    mirror: bool, timeout: Option<f64>, dest: Option<String>, cmd: Vec<String>,
}

impl Args {
    fn empty() -> Self {
        Args {
            config: None, ident: None, svc: None, listen: false, scan: false,
            verbose: 0, quiet: 0, print_ident: false, announce: None,
            allowed: vec![], no_auth: false, remote_cmd_as_args: false,
            no_remote_cmd: false, no_id: false, mirror: false,
            timeout: None, dest: None, cmd: vec![],
        }
    }
}

fn parse_args() -> RResult<Args> {
    let raw: Vec<String> = env::args().skip(1).collect();
    let (mine, cmd) = match raw.iter().position(|a| a == "--") {
        Some(i) => (raw[..i].to_vec(), raw[i + 1..].to_vec()),
        None => (raw, vec![]),
    };
    let mut a = Args {
        config: None, ident: None, svc: None, listen: false, scan: false,
        verbose: 0, quiet: 0, print_ident: false, announce: None,
        allowed: vec![], no_auth: false, remote_cmd_as_args: false,
        no_remote_cmd: false, no_id: false, mirror: false,
        timeout: None, dest: None, cmd,
    };
    let mut it = mine.into_iter().peekable();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => { print_help(); std::process::exit(0); }
            "--version" => {
                println!("rnsh {} (protocol {})", env!("CARGO_PKG_VERSION"), PROTOCOL_VERSION);
                std::process::exit(0);
            }
            "--config" => { a.config = Some(next_val(&mut it, "--config")?); }
            "-i" | "--identity" => { a.ident = Some(next_val(&mut it, &arg)?); }
            "-s" | "--service" => { a.svc = Some(next_val(&mut it, &arg)?); }
            "-l" | "--listen" => { a.listen = true; }
            "-S" | "--scan" => { a.scan = true; }
            "-v" | "--verbose" => { a.verbose += 1; }
            "-q" | "--quiet" => { a.quiet += 1; }
            "-p" | "--print-identity" => { a.print_ident = true; }
            "-b" | "--announce" => {
                let p = next_val(&mut it, &arg)?;
                a.announce = Some(p.parse().map_err(|_| "bad announce period")?);
            }
            "-a" | "--allowed" => { a.allowed.push(next_val(&mut it, &arg)?); }
            "-n" | "--no-auth" => { a.no_auth = true; }
            "-A" | "--remote-command-as-args" => { a.remote_cmd_as_args = true; }
            "-C" | "--no-remote-command" => { a.no_remote_cmd = true; }
            "-N" | "--no-id" => { a.no_id = true; }
            "-m" | "--mirror" => { a.mirror = true; }
            "-w" | "--timeout" => {
                let t = next_val(&mut it, &arg)?;
                a.timeout = Some(t.parse().map_err(|_| "bad timeout")?);
            }
            _ if arg.starts_with('-') => { bail!("unrecognized: {arg}") }
            _ => {
                if a.dest.is_some() { bail!("unexpected: {arg}"); }
                a.dest = Some(arg);
            }
        }
    }
    if a.listen && a.svc.is_none() { a.svc = Some("default".into()); }
    Ok(a)
}

fn next_val<I: Iterator<Item = String>>(it: &mut std::iter::Peekable<I>, f: &str) -> Result<String, String> {
    it.next().ok_or_else(|| format!("{f} needs a value"))
}

fn print_help() {
    eprintln!("Reticulum Remote Shell Utility\n");
    eprintln!("Usage: rnsh [options] [destination] [-- command]\n");
    eprintln!("Listener:");
    eprintln!("  -l, --listen              Listen mode");
    eprintln!("  -s, --service <name>      Service name");
    eprintln!("  -b, --announce <sec>      Announce period");
    eprintln!("  -a, --allowed <hash>      Allowed identity");
    eprintln!("  -n, --no-auth             Disable auth");
    eprintln!("  -C, --no-remote-command   Disable remote cmd");
    eprintln!("  -A, --remote-cmd-as-args  Remote cmd as args\n");
    eprintln!("Initiator:");
    eprintln!("  <destination>             Target hash");
    eprintln!("  -N, --no-id               No identity announce");
    eprintln!("  -m, --mirror              Return remote exit code");
    eprintln!("  -w, --timeout <sec>       Timeout\n");
    eprintln!("Scanner:");
    eprintln!("  -S, --scan               Scan for announced rnsh destinations\n");
    eprintln!("Common:");
    eprintln!("  -i, --identity <path>     Identity file");
    eprintln!("  -p, --print-identity      Print identity");
    eprintln!("  -v, --verbose             Verbose");
    eprintln!("  -q, --quiet               Quiet");
    eprintln!("  --version                 Version");
    eprintln!("  -h, --help                Help\n");
    eprintln!("Escapes: ~. quit  ~? help  ~L line mode  ~~ literal ~");
}

// ── Initiator ──────────────────────────────────────────────────────

/// Resolve a remote listener's identity for link crypto.
///
/// Reticulum link proof verification requires knowing the remote peer's
/// public key. On the same host, announces between TCP clients on the
/// same daemon interface don't propagate, so we fall back to loading
/// the identity from the identity file (same file = same keys).
async fn resolve_listener_identity(
    ident_arg: Option<&str>,
    svc: &str,
) -> Identity {
    if let Ok(local_ident) = load_ident(ident_arg, svc) {
        let pubkey = local_ident.as_identity().clone();
        log::info!("rnsh: using identity from file for destination");
        return pubkey;
    }
    log::warn!("rnsh: no identity found, link will fail");
    Identity::default()
}

async fn initiator(a: &Args) -> RResult<i32> {
    let svc = a.svc.as_deref().unwrap_or("");
    let ident = load_ident(a.ident.as_deref(), svc)?;
    let transport = make_transport(ident.clone()).await?;

    let dest_hex = a.dest.as_ref().ok_or("no destination")?;
    if dest_hex.len() != ADDRESS_HASH_SIZE * 2 {
        bail!("destination must be {} hex chars", ADDRESS_HASH_SIZE * 2);
    }
    let dest_hash = AddressHash::new_from_hex_string(dest_hex)
        .map_err(|_| "invalid destination hash")?;

    let timeout = a.timeout.unwrap_or(30.0);
    let deadline = Instant::now() + Duration::from_secs_f64(timeout);

    // Resolve the listener's identity for link crypto verification.
    // The correct identity comes from the destination's announce, which
    // propagates through the Reticulum network. If the announce hasn't
    // arrived yet (e.g. the shared instance doesn't replay cached
    // announces to new clients), proactively request it via a path
    // request.  On same-host setups where both rnsh instances connect to
    // the same daemon via TCP, announces don't propagate between clients,
    // so we fall back to loading the identity from the local identity file
    // (same file = same keys).
    //
    // Kick off the first path request immediately so we don't waste a
    // full sleep cycle before starting discovery.
    transport.request_path(&dest_hash, None, None).await;
    let remote_identity = 'ident: loop {
        if let Some(dest) = transport.get_out_destination(&dest_hash).await {
            let identity = dest.lock().await.desc.identity;
            log::info!("rnsh: resolved destination identity from announce");
            break 'ident identity;
        }
        if Instant::now() >= deadline {
            break 'ident resolve_listener_identity(a.ident.as_deref(), svc).await;
        }
        transport.request_path(&dest_hash, None, None).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
    };

    let dest_desc = DestinationDesc {
        identity: remote_identity,
        address_hash: dest_hash,
        name: DestinationName::new(APP_NAME, ""),
        ratchet_public_key: None,
    };

    log::info!("rnsh: linking to {dest_hex}");
    let link_arc = transport.link(dest_desc).await;
    let link_id = *link_arc.lock().await.id();
    let mut out_ev = transport.out_link_events();

    // Wait for activation
    let mut activated = false;
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(100), out_ev.recv()).await {
            Ok(Ok(ev)) if ev.id == link_id => match ev.event {
                LinkEvent::Activated => { activated = true; break; }
                LinkEvent::Closed => bail!("link closed during activation"),
                _ => {}
            },
            Ok(Ok(_)) => {}
            Ok(Err(_)) => bail!("event channel gone"),
            Err(_) => {}
        }
    }
    if !activated { bail!("link activation timed out"); }
    log::info!("rnsh: link active");

    // Identify
    if !a.no_id {
        tokio::time::sleep(Duration::from_millis(300)).await;
        transport.link_identify(link_id, &ident).await?;
        log::info!("rnsh: identity sent");
    }

    // Version handshake
    send_channel(&link_arc, &transport, MSG_TYPE_VERSION_INFO, &pack_ver(RNSH_VERSION, PROTOCOL_VERSION)).await?;

    let mut ver_ok = false;
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(100), out_ev.recv()).await {
            Ok(Ok(ev)) if ev.id == link_id => match &ev.event {
                LinkEvent::Channel(ch) if ch.msg_type == MSG_TYPE_VERSION_INFO => {
                    let (sw, pv) = unpack_ver(&ch.payload)?;
                    log::info!("rnsh: remote rnsh {sw} protocol {pv}");
                    ver_ok = true;
                    break;
                }
                LinkEvent::Channel(ch) if ch.msg_type == MSG_TYPE_ERROR => {
                    let (m, _) = unpack_err_msg(&ch.payload);
                    bail!("remote: {m}");
                }
                LinkEvent::Closed => bail!("link closed during version"),
                _ => {}
            },
            Ok(Ok(_)) => {}
            Ok(Err(_)) => bail!("event channel gone"),
            Err(_) => {}
        }
    }
    if !ver_ok { bail!("version handshake failed"); }

    // Send execute command
    let (r, c, h, v) = if unsafe { libc::isatty(0) } != 0 { winsz(0) } else { (24, 80, 0, 0) };
    let term = env::var("TERM").ok();
    let piped = unsafe { libc::isatty(0) } == 0;
    let exec = pack_exec(&a.cmd, piped, false, false, &term, r, c, h, v);
    send_channel(&link_arc, &transport, MSG_TYPE_EXEC_CMD, &exec).await?;
    let mdu = link_arc.lock().await.channel_mdu();
    let max_data = mdu.saturating_sub(2);

    // Raw terminal
    let mut raw = RawTerm::new();
    let _ = raw.enable();

    // I/O loop
    let mut ret_code = 0;
    let mut done = false;
    let transport = Arc::new(transport);
    let link_arc2 = link_arc.clone();
    let transport2 = transport.clone();

    let disconnect = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let disconnect_signal = disconnect.clone();
    let _stdin_task = tokio::spawn(async move {
        let mut esc = EscapeHandler::default();
        let mut buf = [0u8; 4096];
        let mut stdin = tokio::io::stdin();
        loop {
            let n = match stdin.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let mut out_data = Vec::new();
            for &b in &buf[..n] {
                if let Some(action) = esc.process_byte(b, &mut out_data) {
                    match action {
                        EscapeAction::Disconnect => {
                            disconnect_signal.store(true, std::sync::atomic::Ordering::Relaxed);
                            return;
                        }
                        EscapeAction::Help => {
                            let help = b"\n\rSupported rnsh escape sequences:\n\r  ~~  Send escape character by typing it twice\n\r  ~.  Terminate session and exit immediately\n\r  ~L  Toggle line-interactive mode\n\r  ~?  Display this quick reference\n\r\n\r";
                            let _ = io::stdout().write_all(help);
                            let _ = io::stdout().flush();
                        }
                        EscapeAction::LineModeEnabled => {
                            let _ = io::stdout().write_all(b"\n\rLine-interactive mode enabled\n\r");
                            let _ = io::stdout().flush();
                        }
                        EscapeAction::LineModeDisabled => {
                            let _ = io::stdout().write_all(b"\n\rLine-interactive mode disabled\n\r");
                            let _ = io::stdout().flush();
                        }
                    }
                }
            }
            if !out_data.is_empty() {
                let (_, _, chunk) = compress(&out_data, max_data);
                let mut p = stream_hdr(SID_STDIN, false, false);
                p.extend_from_slice(&chunk);
                if send_channel(&link_arc2, &transport2, MSG_TYPE_STREAM_DATA, &p).await.is_err() {
                    break;
                }
            }
        }
        let p = stream_hdr(SID_STDIN, true, false);
        let _ = send_channel(&link_arc2, &transport2, MSG_TYPE_STREAM_DATA, &p).await;
    });

    while !done {
        if disconnect.load(std::sync::atomic::Ordering::Relaxed) {
            log::info!("rnsh: disconnected by user");
            break;
        }
        match tokio::time::timeout(Duration::from_millis(50), out_ev.recv()).await {
            Ok(Ok(ev)) if ev.id == link_id => match &ev.event {
                LinkEvent::Channel(ch) if ch.msg_type == MSG_TYPE_STREAM_DATA => {
                    let (sid, _eof, comp) = match stream_unhdr(&ch.payload) {
                        Ok(h) => h, Err(_) => continue,
                    };
                    let data = if ch.payload.len() > 2 { &ch.payload[2..] } else { &[] };
                    let d = if comp { decompress(data, MAX_CHUNK).unwrap_or_default() } else { data.to_vec() };
                    match sid {
                        SID_STDOUT => { let _ = io::stdout().write_all(&d); let _ = io::stdout().flush(); }
                        SID_STDERR => { let _ = io::stderr().write_all(&d); let _ = io::stderr().flush(); }
                        _ => {}
                    }
                }
                LinkEvent::Channel(ch) if ch.msg_type == MSG_TYPE_CMD_EXITED => {
                    ret_code = unpack_exit(&ch.payload).unwrap_or(0);
                    log::info!("rnsh: remote exited {ret_code}");
                    done = true;
                }
                LinkEvent::Channel(ch) if ch.msg_type == MSG_TYPE_ERROR => {
                    let (m, _) = unpack_err_msg(&ch.payload);
                        log::error!("rnsh: remote error: {m}");
                    done = true;
                }
                LinkEvent::Closed => { log::info!("rnsh: link closed"); done = true; }
                _ => {}
            },
            Ok(Ok(_)) => {}
            Ok(Err(_)) => { done = true; }
            Err(_) => { // timeout - winsize check
                if unsafe { libc::isatty(0) } != 0 {
                    let (nr, nc, nh, nv) = winsz(0);
                    let _ = send_channel(&link_arc, &transport, MSG_TYPE_WINDOW_SIZE, &pack_winsz(nr, nc, nh, nv)).await;
                }
            }
        }
    }

    transport.link_close(link_id).await.ok();
    Ok(ret_code)
}

// ── Listener ────────────────────────────────────────────────────────

async fn get_link(t: &Transport, id: &AddressHash) -> Option<Arc<Mutex<Link>>> {
    if let Some(l) = t.find_in_link(id).await { return Some(l); }
    if let Some(l) = t.find_out_link(id).await { return Some(l); }
    None
}

async fn listener(a: &Args) -> RResult<()> {
    let svc = a.svc.as_deref().unwrap_or("default");
    let ident = load_ident(a.ident.as_deref(), svc)?;
    let mut transport = make_transport(ident.clone()).await?;

    let dest = transport.add_destination(ident.clone(), DestinationName::new(APP_NAME, "")).await;
    let dest_hash = dest.lock().await.desc.address_hash;
    println!("Identity     : {:?}", ident.address_hash().to_hex_string());
    println!("Listening on : {:?}", dest_hash.to_hex_string());

    // Send announce a few times at startup so late-subscribing peers can
    // discover this destination and resolve its identity for link crypto.
    let startup_announces = 5;
    for _ in 0..startup_announces {
        transport.send_announce(&dest, None).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let period = a.announce.unwrap_or(0);
    if period > 0 {
        let transport = Arc::new(transport);
        let d2 = dest.clone();
        let t2 = transport.clone();
        tokio::spawn(async move {
            loop {
                t2.send_announce(&d2, None).await;
                tokio::time::sleep(Duration::from_secs(period)).await;
            }
        });
        let mut in_ev = transport.in_link_events();
        loop {
            match in_ev.recv().await {
                Ok(ev) if matches!(ev.event, LinkEvent::Activated) => {
                    log::info!("rnsh: inbound link {}", ev.id);
                    let t = transport.clone();
                    let a3 = Args { svc: Some(svc.into()), cmd: a.cmd.clone(),
                        no_auth: a.no_auth, allowed: a.allowed.clone(),
                        no_remote_cmd: a.no_remote_cmd, remote_cmd_as_args: a.remote_cmd_as_args,
                        ..Args::empty() };
                    // Do version handshake inline using the main loop receiver,
                    // which was subscribed before the VersionInfo was sent.
                    let (_ident, cmd, term, rows, cols) = match do_version_handshake(&t, &ev.id, &a3, &mut in_ev).await {
                        Ok(r) => r,
                        Err(e) => { log::error!("rnsh: handshake failed: {e}"); continue; }
                    };
                    let ev_recv = in_ev.resubscribe();
                    tokio::spawn(async move {
                        if let Err(e) = handle_link(ev.id, t, &a3, cmd, term, rows, cols, ev_recv).await {
                            log::error!("rnsh: session: {e}");
                        }
                    });
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    } else {
        transport.send_announce(&dest, None).await;
        let transport = Arc::new(transport);
        let mut in_ev = transport.in_link_events();
        loop {
            match in_ev.recv().await {
                Ok(ev) if matches!(ev.event, LinkEvent::Activated) => {
                    log::info!("rnsh: inbound link {}", ev.id);
                    let t = transport.clone();
                    let a3 = Args { svc: Some(svc.into()), cmd: a.cmd.clone(),
                        no_auth: a.no_auth, allowed: a.allowed.clone(),
                        no_remote_cmd: a.no_remote_cmd, remote_cmd_as_args: a.remote_cmd_as_args,
                        ..Args::empty() };
                    let (_ident, cmd, term, rows, cols) = match do_version_handshake(&t, &ev.id, &a3, &mut in_ev).await {
                        Ok(r) => r,
                        Err(e) => { log::error!("rnsh: handshake failed: {e}"); continue; }
                    };
                    let ev_recv = in_ev.resubscribe();
                    tokio::spawn(async move {
                        if let Err(e) = handle_link(ev.id, t, &a3, cmd, term, rows, cols, ev_recv).await {
                            log::error!("rnsh: session: {e}");
                        }
                    });
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    }
    Ok(())
}

/// Do version handshake and exec command exchange on the main loop's
/// receiver, which was subscribed before any channel messages arrived.
fn check_allowed(id: &Identity, a: &Args) -> bool {
    let allowed: HashSet<AddressHash> = a.allowed.iter()
        .filter_map(|h| AddressHash::new_from_hex_string(h).ok())
        .chain(load_allowed())
        .collect();
    if allowed.is_empty() { return false; }
    allowed.contains(&id.address_hash)
}

async fn do_version_handshake(
    transport: &Transport, link_id: &AddressHash, a: &Args,
    in_ev: &mut tokio::sync::broadcast::Receiver<reticulum_sdk::destination::link::LinkEventData>,
) -> RResult<(PrivateIdentity, Vec<String>, Option<String>, u16, u16)> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let link_arc = get_link(transport, link_id).await
        .ok_or("no link handle for handshake")?;
    let mut cmd = Vec::new();
    let mut term = None;
    let mut rows = 24u16;
    let mut cols = 80u16;
    let mut got_ver = false;
    let mut got_exec = false;

    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), in_ev.recv()).await {
            Ok(Ok(ev)) if ev.id == *link_id => match &ev.event {
                LinkEvent::RemoteIdentified(id) => {
                    if a.no_auth || check_allowed(id, a) {
                        log::info!("rnsh: remote identified");
                    } else {
                        send_channel(&link_arc, transport, MSG_TYPE_ERROR, &pack_err("not allowed", true)).await?;
                        bail!("identity not allowed");
                    }
                }
                LinkEvent::Channel(ch) if ch.msg_type == MSG_TYPE_VERSION_INFO => {
                    let (_sw, pv) = unpack_ver(&ch.payload)?;
                    if pv != PROTOCOL_VERSION {
                        send_channel(&link_arc, transport, MSG_TYPE_ERROR, &pack_err("incompatible protocol", true)).await?;
                        bail!("incompatible protocol {pv}");
                    }
                    send_channel(&link_arc, transport, MSG_TYPE_VERSION_INFO, &pack_ver(RNSH_VERSION, PROTOCOL_VERSION)).await?;
                    got_ver = true;
                }
                LinkEvent::Channel(ch) if ch.msg_type == MSG_TYPE_EXEC_CMD => {
                    let (rc, _pi, _po, _pe, t, r, c, _hp, _vp) = unpack_exec(&ch.payload)?;
                    term = t; rows = r; cols = c;
                    cmd = rc;
                    got_exec = true;
                }
                LinkEvent::Channel(ch) if ch.msg_type == MSG_TYPE_ERROR => {
                    let (m, _) = unpack_err_msg(&ch.payload);
                    bail!("remote error: {m}");
                }
                LinkEvent::Closed => bail!("link closed during handshake"),
                _ => {}
            },
            Ok(Ok(_)) => {}
            Ok(Err(_)) => bail!("event channel closed"),
            Err(_) => {}
        }
        if got_ver && got_exec { break; }
    }
    if !got_ver { bail!("version handshake timeout"); }
    if !got_exec { bail!("exec command timeout"); }

    // Return raw remote command; handle_link applies overrides/shell
    let dummy_ident = PrivateIdentity::new_from_rand(OsRng);
    Ok((dummy_ident, cmd, term, rows, cols))
}

async fn handle_link(link_id: AddressHash, transport: Arc<Transport>, a: &Args,
    cmd: Vec<String>, term: Option<String>, rows: u16, cols: u16,
    mut in_ev: tokio::sync::broadcast::Receiver<reticulum_sdk::destination::link::LinkEventData>) -> RResult<()> {
    let lk = get_link(&transport, &link_id).await
        .ok_or("no link handle")?;

    // Apply listener-side overrides from args
    let remote_cmd: Vec<String> = cmd; // rename parameter to avoid shadow confusion
    let cmd = if a.no_remote_cmd && !a.cmd.is_empty() {
        a.cmd.clone()
    } else if a.remote_cmd_as_args {
        let mut base = a.cmd.clone();
        base.extend(remote_cmd);
        base
    } else if !remote_cmd.is_empty() {
        remote_cmd
    } else if !a.cmd.is_empty() {
        a.cmd.clone()
    } else {
        vec![env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())]
    };
    if cmd.is_empty() || cmd[0].is_empty() { bail!("no command to execute"); }
    log::info!("rnsh: executing {:?}", cmd);

    // Fork child with PTY for interactive shell support
    let mdu = lk.lock().await.channel_mdu();
    let max_data = mdu.saturating_sub(2);
    let link_out = lk.clone();
    let transport_out = transport.clone();
    drop(lk); // release mutex before forking

    let pty = openpty(None, None)?;
    let master = pty.master;
    let slave = pty.slave;
    let slave_fd = slave.as_raw_fd();

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child: child_pid }) => {
            drop(slave);
            let master_fd = master.as_raw_fd();
            unsafe {
                libc::fcntl(master_fd, libc::F_SETFL, libc::O_NONBLOCK | libc::O_RDWR);
            }
            std::mem::forget(master);
            let thread_fd = unsafe { libc::dup(master_fd) };

            let lo = link_out.clone();
            let to = transport_out.clone();
            let (pty_tx, pty_rx) = std::sync::mpsc::channel::<Vec<u8>>();
            std::thread::spawn(move || {
                let mut buf = [0u8; 65536];
                loop {
                    let n = unsafe { libc::read(thread_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                    if n > 0 {
                        let (comp, _, chunk) = compress(&buf[..n as usize], max_data);
                        let mut p = stream_hdr(SID_STDOUT, false, comp);
                        p.extend_from_slice(&chunk);
                        if pty_tx.send(p).is_err() { break; }
                    } else if n == 0 {
                        break;
                    } else {
                        let err = unsafe { *libc::__errno_location() };
                        if err == libc::EAGAIN || err == libc::EWOULDBLOCK {
                            std::thread::sleep(Duration::from_millis(10));
                        } else {
                            break;
                        }
                    }
                }
                let p = stream_hdr(SID_STDOUT, true, false);
                let _ = pty_tx.send(p);
                unsafe { libc::close(thread_fd); }
            });

            let pty_reader = tokio::spawn(async move {
                loop {
                    match pty_rx.try_recv() {
                        Ok(p) => {
                            if send_channel(&lo, &to, MSG_TYPE_STREAM_DATA, &p).await.is_err() { break; }
                        }
                        Err(std::sync::mpsc::TryRecvError::Empty) => {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
                    }
                }
            });

            let mut child_exited = false;
            let mut child_code = -1;
            let mut child_detect = Instant::now();
            while !child_exited || !pty_reader.is_finished() {
                if pty_reader.is_finished() && child_exited { break; }
                // Safety: don't wait more than 3 seconds after child exit for PTY drain
                if child_exited && child_detect.elapsed() > Duration::from_secs(3) { break; }
                match tokio::time::timeout(Duration::from_millis(50), in_ev.recv()).await {
                    Ok(Ok(ev)) if ev.id == link_id => match &ev.event {
                        LinkEvent::Channel(ch) if ch.msg_type == MSG_TYPE_STREAM_DATA => {
                            let (sid, eof, comp) = match stream_unhdr(&ch.payload) {
                                Ok(h) => h, Err(_) => continue,
                            };
                            let data = if ch.payload.len() > 2 { &ch.payload[2..] } else { &[] };
                            let d = if comp { decompress(data, MAX_CHUNK).unwrap_or_default() } else { data.to_vec() };
                            if sid == SID_STDIN && !d.is_empty() {
                                unsafe { libc::write(master_fd, d.as_ptr() as *const libc::c_void, d.len()); }
                            }
                            if sid == SID_STDIN && eof {
                                unsafe { libc::close(master_fd); }
                            }
                        }
                        LinkEvent::Closed => { if child_code < 0 { child_code = 0; } child_exited = true; }
                        _ => {}
                    },
                    Ok(Ok(_)) => {}
                    Ok(Err(_)) => { if child_code < 0 { child_code = 0; } child_exited = true; }
                    Err(_) => {
                        let mut ws: i32 = 0;
                        let pid: i32 = child_pid.into();
                        let ret = unsafe { libc::waitpid(pid, &mut ws, libc::WNOHANG) };
                        if ret > 0 {
                            child_code = libc::WEXITSTATUS(ws);
                            log::info!("rnsh: child exited {child_code}");
                            child_exited = true;
                            child_detect = Instant::now();
                        }
                    }
                }
            }

            if child_exited || pty_reader.is_finished() {
                // Wait for PTY reader to flush remaining data
                tokio::time::sleep(Duration::from_millis(100)).await;
                send_channel(&link_out, &transport, MSG_TYPE_CMD_EXITED, &pack_exit(child_code.max(0))).await.ok();
            }
            kill(child_pid, Signal::SIGKILL).ok();
            unsafe { libc::close(master_fd); }
            transport.link_close(link_id).await.ok();
        }
        Ok(ForkResult::Child) => {
            drop(master);
            setsid().ok();
            unsafe { libc::ioctl(slave_fd, libc::TIOCSCTTY, 0); }
            dup2(slave_fd, 0).ok();
            dup2(slave_fd, 1).ok();
            dup2(slave_fd, 2).ok();
            if slave_fd > 2 { unsafe { libc::close(slave_fd); } }
            if let Some(ref t) = term { unsafe { env::set_var("TERM", t); } }
            let ws = WinSz { row: rows, col: cols, xpix: 0, ypix: 0 };
            unsafe { libc::ioctl(0, libc::TIOCSWINSZ, &ws as *const _); }
            let prog = CString::new(cmd[0].as_bytes()).unwrap();
            let args: Vec<CString> = cmd.iter().map(|s| CString::new(s.as_bytes()).unwrap()).collect();
            let mut ptrs: Vec<*const libc::c_char> = args.iter().map(|c| c.as_ptr()).collect();
            ptrs.push(std::ptr::null());
            unsafe { libc::execvp(prog.as_ptr(), ptrs.as_ptr()); }
            unsafe { libc::_exit(255); }
        }
        Err(e) => bail!("fork: {e}"),
    }

    Ok(())
}

// ── Scanner ─────────────────────────────────────────────────────────

async fn scanner(a: &Args) -> RResult<()> {
    let svc = a.svc.as_deref().unwrap_or("");
    let ident = load_ident(a.ident.as_deref(), svc)?;
    let transport = make_transport(ident.clone()).await?;
    let mut rx = transport.recv_announces().await;
    let rnsh_name = DestinationName::new(APP_NAME, "");

    println!("Scanning for rnsh destinations...");
    loop {
        match rx.recv().await {
            Ok(ev) => {
                let dest = ev.destination.lock().await;
                if dest.desc.name.as_name_hash_slice() != rnsh_name.as_name_hash_slice() {
                    continue;
                }
                println!(
                    "  {}  (identity {}, {} hops)",
                    dest.desc.address_hash.to_hex_string(),
                    dest.desc.identity.address_hash.to_hex_string(),
                    ev.hops,
                );
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(_) => break,
        }
    }
    Ok(())
}

// ── Main ────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    env_logger::init();

    let a = match parse_args() {
        Ok(a) => a,
        Err(e) => { eprintln!("rnsh: {e}"); std::process::exit(1); }
    };

    if a.print_ident {
        let svc = a.svc.as_deref().unwrap_or("default");
        match load_ident(a.ident.as_deref(), svc) {
            Ok(id) => {
                let ident: &Identity = id.as_identity();
                let name = DestinationName::new(APP_NAME, "");
                let digest = Sha256::new()
                    .chain_update(name.as_name_hash_slice())
                    .chain_update(ident.address_hash.as_slice())
                    .finalize();
                let hash = AddressHash::new_from_hash(
                    &reticulum_sdk::hash::Hash::new_from_slice(&digest)
                );
                println!("Identity     : {:?}", ident.address_hash.to_hex_string());
                println!("Listening on : {:?}", hash.to_hex_string());
            }
            Err(e) => { eprintln!("rnsh: {e}"); std::process::exit(1); }
        }
        return;
    }

    if a.scan {
        if let Err(e) = scanner(&a).await {
            eprintln!("rnsh: {e}");
            std::process::exit(1);
        }
        return;
    }

    if a.listen {
        if let Err(e) = listener(&a).await {
            eprintln!("rnsh: {e}");
            std::process::exit(1);
        }
    } else if a.dest.is_some() {
        let code = match initiator(&a).await {
            Ok(c) => c,
            Err(e) => { eprintln!("rnsh: {e}"); 1 }
        };
        std::process::exit(code);
    } else {
        print_help();
        std::process::exit(1);
    }
}
