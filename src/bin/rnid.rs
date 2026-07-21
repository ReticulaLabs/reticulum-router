use base64::Engine;
use ed25519_dalek::Signature;
use rand::rngs::{StdRng, SysRng};
use rand::SeedableRng;
use reticulum_sdk::destination::{DestinationName, SingleOutputDestination};
use reticulum_sdk::hash::AddressHash;
use reticulum_sdk::identity::{Identity, PUBLIC_KEY_LENGTH, PrivateIdentity};
use rmpv::{Utf8String, Value, decode::read_value, encode::write_value};
use sha2::{Digest, Sha256};
use std::env;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

const DEFAULT_ASPECTS: &str = "rns.id";
const PUB_EXT: &str = "pub";
const SIG_EXT: &str = "rsg";
const MSG_EXT: &str = "rsm";
const ENCRYPT_EXT: &str = "rfe";
const ENC_CHUNK: usize = 1024 * 1024 * 16;
const DEC_CHUNK: usize = ENC_CHUNK + 128;
const SIGNATURE_LENGTH: usize = 64;
const RSG_ROW_WIDTH: usize = 64;
const B256: [&str; 256] = [
    "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s",
    "t", "u", "v", "x", "y", "z", "æ", "ø", "0", "1", "2", "3", "4", "A", "B", "C", "D", "E", "F",
    "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "W", "X", "Y", "Z",
    "Æ", "Ø", "5", "6", "7", "8", "9", "α", "β", "γ", "δ", "ε", "ζ", "η", "θ", "ι", "κ", "λ", "μ",
    "ν", "ξ", "π", "ρ", "σ", "τ", "φ", "χ", "ψ", "ω", "Γ", "Δ", "Θ", "Λ", "Ξ", "Π", "Σ", "Φ", "Ψ",
    "Ω", "Б", "Д", "Ж", "З", "И", "Л", "П", "Ц", "Ч", "Ш", "Щ", "Ъ", "Ы", "Э", "Ю", "Я", "б", "д",
    "ж", "з", "и", "л", "п", "ц", "ч", "ш", "щ", "ъ", "ы", "э", "ю", "я", "Ա", "Բ", "Գ", "Դ", "Ե",
    "Զ", "Է", "Ը", "Թ", "Ժ", "Ի", "Խ", "Ծ", "Կ", "Հ", "Ձ", "Ղ", "Ճ", "Մ", "Յ", "Ն", "Շ", "Ո", "Չ",
    "Պ", "Ջ", "Վ", "Ր", "Ց", "Ւ", "Ք", "Ֆ", "ᚠ", "ᚢ", "ᚦ", "ᚱ", "ᚹ", "ᚺ", "ᚾ", "ᛈ", "ᛇ", "ᛉ", "ᛊ",
    "ᛏ", "ᛒ", "ᛖ", "ᛗ", "ᛟ", "ｲ", "ｳ", "ｵ", "ｶ", "ｷ", "ｹ", "ｻ", "ｼ", "ｽ", "ｾ", "ﾀ", "ﾁ", "ﾃ", "ﾄ",
    "ﾅ", "ﾇ", "ﾈ", "ﾋ", "ﾌ", "ﾍ", "ﾎ", "ﾏ", "ﾐ", "ﾑ", "ﾒ", "ﾓ", "ﾔ", "ﾗ", "ﾘ", "ﾙ", "ﾚ", "ﾜ", "𐑐",
    "𐑑", "𐑒", "𐑔", "𐑕", "𐑗", "𐑙", "𐑳", "𐑶", "𐑸", "𐑹", "𐑺", "𐑻", "𐑽", "𐑾", "𐑿", "᱑", "᱕", "᱘", "᱙",
    "ᱚ", "ᱝ", "ᱟ", "ᱣ", "ᱦ", "ᱨ", "ᱬ", "ᱭ", "ᱰ", "ᱳ", "ᱶ", "ᱷ", "𐌳", "𐌸", "𐌾", "𐐀", "𐐁", "𐐂", "𐐆",
    "𐐇", "𐐈", "𐐉", "𐐊", "𐐋", "𐐌", "𐐍", "𐐎", "𐐏",
];

const R_OK: i32 = 0;
const R_NO_IDENTITY: i32 = 2;
const R_NO_PUBKEY: i32 = 3;
const R_NO_PRVKEY: i32 = 4;
const R_NO_FILE: i32 = 6;
const R_INVALID_FILE: i32 = 7;
const R_INVALID_IDENTITY: i32 = 8;
const R_INVALID_ASPECTS: i32 = 9;
const R_INVALID_SIGNATURE: i32 = 10;
const R_FILE_EXISTS: i32 = 11;
const R_DECRYPT_FAILED: i32 = 12;
const R_INVALID_ARGS: i32 = 250;
const R_SEQUENCE_ERROR: i32 = 251;
const R_READ_ERROR: i32 = 252;
const R_WRITE_ERROR: i32 = 253;
const R_UNKNOWN_ERROR: i32 = 254;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Bin,
    Hex,
    Base32,
    Base64,
    Base256,
}

enum WorkingIdentity {
    Private(PrivateIdentity),
    Public(Identity),
}

impl WorkingIdentity {
    fn identity(&self) -> &Identity {
        match self {
            Self::Private(identity) => identity.as_identity(),
            Self::Public(identity) => identity,
        }
    }

    fn private(&self) -> Option<&PrivateIdentity> {
        match self {
            Self::Private(identity) => Some(identity),
            Self::Public(_) => None,
        }
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        let identity = self.identity();
        [
            identity.public_key_bytes().as_slice(),
            identity.verifying_key_bytes().as_slice(),
        ]
        .concat()
    }

    fn identity_hash(&self) -> &[u8] {
        self.identity().address_hash.as_slice()
    }
}

impl std::fmt::Display for WorkingIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", pretty_hex(self.identity_hash()))
    }
}

#[derive(Default)]
struct Args {
    config: Option<String>,
    identity: Option<String>,
    generate: Option<String>,
    import_pub: Option<String>,
    import_prv: Option<String>,
    export_pub: bool,
    export_prv: bool,
    verbose: u8,
    quiet: u8,
    announce: Option<String>,
    hash: Option<String>,
    decrypt: Option<Vec<String>>,
    encrypt: Option<Vec<String>>,
    validate: Option<Vec<String>>,
    sign: Option<Vec<String>>,
    sign_message: Option<Option<String>>,
    embed_meta: Option<String>,
    meta_spec: Option<String>,
    raw: bool,
    write: Option<String>,
    read: Option<String>,
    force: bool,
    stdin: bool,
    stdout: bool,
    request: bool,
    no_cache: bool,
    timeout: f64,
    print_identity: bool,
    print_private: bool,
    base32: bool,
    base64: bool,
    base256: bool,
    hex: bool,
    meta: bool,
}

fn main() {
    let code = match run() {
        Ok(code) => code,
        Err((code, msg)) => {
            println!("{msg}");
            code
        }
    };
    std::process::exit(code);
}

fn run() -> Result<i32, (i32, String)> {
    let args = parse_args()?;
    validate_args(&args)?;

    let op_requires_identity = args.sign.is_some()
        || args.sign_message.is_some()
        || args.encrypt.is_some()
        || args.decrypt.is_some()
        || args.announce.is_some()
        || args.write.is_some()
        || args.print_identity
        || args.export_pub
        || args.export_prv;

    let identity = get_operating_identity(&args, !op_requires_identity)?;
    if identity.is_none() && op_requires_identity {
        return err(R_NO_IDENTITY, "Could not get working identity");
    }
    let mut op = false;

    if args.print_identity {
        print_identity_information(&args, identity.as_ref().unwrap());
        op = true;
    }
    if args.export_pub {
        export_pub_identity(&args, identity.as_ref().unwrap())?;
        op = true;
    }
    if args.export_prv {
        export_prv_identity(&args, identity.as_ref().unwrap())?;
        op = true;
    }
    if let Some(aspects) = &args.hash {
        print_hash_information(aspects, identity.as_ref(), args.identity.as_deref())?;
        op = true;
    }
    if args.announce.is_some() {
        return err(
            R_UNKNOWN_ERROR,
            "Network announce is not supported by this standalone Rust rnid build",
        );
    }
    if let Some(paths) = &args.validate {
        validate_paths(&args, identity.as_ref(), paths)?;
        op = true;
    }
    if let Some(paths) = &args.sign {
        sign_paths(&args, identity.as_ref().unwrap(), paths)?;
        op = true;
    }
    if args.sign_message.is_some() {
        sign_message(&args, identity.as_ref().unwrap())?;
        op = true;
    }
    if let Some(paths) = &args.encrypt {
        encrypt_paths(&args, identity.as_ref().unwrap(), paths)?;
        op = true;
    }
    if let Some(paths) = &args.decrypt {
        decrypt_paths(&args, identity.as_ref().unwrap(), paths)?;
        op = true;
    }
    if args.write.is_some() {
        write_identity(&args, identity.as_ref().unwrap())?;
        op = true;
    }
    if args.generate.is_some() {
        op = true;
    }

    if !op {
        print_help();
    }

    Ok(R_OK)
}

fn parse_args() -> Result<Args, (i32, String)> {
    let mut args = Args {
        timeout: 6.0,
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
                println!("rnid {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--config" => args.config = Some(next_value(&mut it, "--config")?),
            "-i" | "--identity" => args.identity = Some(next_value(&mut it, &arg)?),
            "-g" | "--generate" => args.generate = Some(next_value(&mut it, &arg)?),
            "-m" | "--import-pub" => args.import_pub = Some(next_value(&mut it, &arg)?),
            "-M" | "--import-prv" => args.import_prv = Some(next_value(&mut it, &arg)?),
            "-x" | "--export-pub" => args.export_pub = true,
            "-X" | "--export-prv" => args.export_prv = true,
            "-v" | "--verbose" => args.verbose = args.verbose.saturating_add(1),
            "-q" | "--quiet" => args.quiet = args.quiet.saturating_add(1),
            "-a" | "--announce" => {
                args.announce =
                    Some(optional_value(&mut it).unwrap_or_else(|| DEFAULT_ASPECTS.to_string()))
            }
            "-H" | "--hash" => args.hash = Some(next_value(&mut it, &arg)?),
            "-d" | "--decrypt" => args.decrypt = Some(collect_values(&mut it)),
            "-e" | "--encrypt" => args.encrypt = Some(collect_values(&mut it)),
            "-V" | "--validate" => args.validate = Some(collect_values(&mut it)),
            "-s" | "--sign" => args.sign = Some(collect_values(&mut it)),
            "-S" | "--sign-message" => args.sign_message = Some(optional_value(&mut it)),
            "-E" | "--embed-meta" => args.embed_meta = optional_value(&mut it),
            "--meta-spec" => args.meta_spec = Some(next_value(&mut it, "--meta-spec")?),
            "--raw" => args.raw = true,
            "-w" | "--write" => args.write = Some(next_value(&mut it, &arg)?),
            "-r" | "--read" => args.read = Some(next_value(&mut it, &arg)?),
            "-f" | "--force" => args.force = true,
            "-I" | "--stdin" => args.stdin = true,
            "-O" | "--stdout" => args.stdout = true,
            "-R" | "--request" => args.request = true,
            "-N" | "--no-cache" => args.no_cache = true,
            "-t" => {
                args.timeout = next_value(&mut it, "-t")?
                    .parse()
                    .map_err(|_| (R_INVALID_ARGS, "Invalid timeout".to_string()))?;
            }
            "-p" | "--print-identity" => args.print_identity = true,
            "-P" | "--print-private" => args.print_private = true,
            "-B" | "--base32" => args.base32 = true,
            "-b" | "--base64" => args.base64 = true,
            "-U" | "--base256" => args.base256 = true,
            "-F" | "--hex" => args.hex = true,
            "--meta" => args.meta = true,
            _ => return err(R_INVALID_ARGS, format!("unrecognized argument: {arg}")),
        }
    }
    Ok(args)
}

fn next_value<I>(it: &mut std::iter::Peekable<I>, flag: &str) -> Result<String, (i32, String)>
where
    I: Iterator<Item = String>,
{
    it.next().ok_or_else(|| {
        (
            R_INVALID_ARGS,
            format!("argument {flag} expected one value"),
        )
    })
}

fn optional_value<I>(it: &mut std::iter::Peekable<I>) -> Option<String>
where
    I: Iterator<Item = String>,
{
    match it.peek() {
        Some(next) if !next.starts_with('-') => it.next(),
        _ => None,
    }
}

fn collect_values<I>(it: &mut std::iter::Peekable<I>) -> Vec<String>
where
    I: Iterator<Item = String>,
{
    let mut values = Vec::new();
    while let Some(next) = it.peek() {
        if next.starts_with('-') {
            break;
        }
        values.push(it.next().unwrap());
    }
    values
}

fn validate_args(args: &Args) -> Result<(), (i32, String)> {
    let ops = [
        args.encrypt.is_some(),
        args.decrypt.is_some(),
        args.validate.is_some(),
        args.sign.is_some(),
        args.sign_message.is_some(),
    ]
    .into_iter()
    .filter(|x| *x)
    .count();
    if ops > 1 {
        return err(
            1,
            "This utility currently only supports one of the encrypt, decrypt, sign or verify operations per invocation",
        );
    }

    let identities = [
        args.import_pub.is_some(),
        args.import_prv.is_some(),
        args.identity.is_some(),
        args.generate.is_some(),
    ]
    .into_iter()
    .filter(|x| *x)
    .count();
    if identities > 1 {
        return err(1, "The -i, -g, -m and -M args are mutually exclusive");
    }

    let encodings = [args.base64, args.base32, args.base256, args.hex]
        .into_iter()
        .filter(|x| *x)
        .count();
    if encodings > 1 {
        return err(
            1,
            "The -b, -B, --hex and --base256 args are mutually exclusive",
        );
    }

    Ok(())
}

fn get_operating_identity(
    args: &Args,
    allow_none: bool,
) -> Result<Option<WorkingIdentity>, (i32, String)> {
    if let Some(path) = &args.generate {
        let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();
        let identity = PrivateIdentity::new_from_rand(&mut rng);
        let path = expand_home(path);
        if path.exists() && !args.force {
            return err(
                R_FILE_EXISTS,
                format!(
                    "Identity file {} already exists. Not overwriting.",
                    path.display()
                ),
            );
        }
        write_private_identity_file(&path, &identity)?;
        println!(
            "New identity {} written to {}",
            pretty_hex(identity.address_hash().as_slice()),
            path.display()
        );
        return Ok(Some(WorkingIdentity::Private(identity)));
    }

    if let Some(input) = &args.identity {
        let path = expand_home(input);
        if path.is_file() {
            let identity = read_private_identity_file(&path)?;
            println!(
                "Loaded Identity {} from {}",
                pretty_hex(identity.address_hash().as_slice()),
                path.display()
            );
            return Ok(Some(WorkingIdentity::Private(identity)));
        }

        if args.no_cache {
            return if allow_none {
                Ok(None)
            } else {
                err(R_NO_IDENTITY, "Could not resolve identity")
            };
        }

        if input.len() == AddressHash::new_empty().len() * 2 {
            if allow_none && !args.request {
                return Ok(None);
            }
            return err(
                R_NO_IDENTITY,
                format!(
                    "Could not recall Identity for {}.\nYou can query the network for unknown Identities with the -R option.",
                    pretty_hex(&decode_hex(input)?)
                ),
            );
        }
    }

    if let Some(input) = &args.import_pub {
        let bytes = decode_identity_input(input, PUBLIC_KEY_LENGTH * 2, true)?;
        let identity =
            Identity::new_from_slices(&bytes[..PUBLIC_KEY_LENGTH], &bytes[PUBLIC_KEY_LENGTH..])
                .map_err(|e| (R_INVALID_IDENTITY, format!("Could not create identity: {e}")))?;
        return Ok(Some(WorkingIdentity::Public(identity)));
    }

    if let Some(input) = &args.import_prv {
        let bytes = decode_identity_input(input, PUBLIC_KEY_LENGTH * 2, false)?;
        let identity = PrivateIdentity::new_from_hex_string(&hex_encode(&bytes)).map_err(|e| {
            (
                R_INVALID_IDENTITY,
                format!("Could not create Reticulum identity from specified data: {e:?}"),
            )
        })?;
        return Ok(Some(WorkingIdentity::Private(identity)));
    }

    Ok(None)
}

fn decode_identity_input(input: &str, size: usize, public: bool) -> Result<Vec<u8>, (i32, String)> {
    let path = expand_home(input);
    if path.is_file() {
        let bytes = fs::read(&path).map_err(|e| {
            (
                R_READ_ERROR,
                format!("Could not read {}: {e}", path.display()),
            )
        })?;
        if bytes.len() == size {
            println!("Reticulum Identity imported from {}", path.display());
            return Ok(bytes);
        }
    }

    if input.len() == size * 2 {
        if let Ok(bytes) = decode_hex(input) {
            if bytes.len() == size {
                println!("Reticulum Identity imported from hex input");
                return Ok(bytes);
            }
        }
    }

    if let Ok(bytes) = base32_decode(input) {
        if bytes.len() == size {
            println!("Reticulum Identity imported from base32 input");
            return Ok(bytes);
        }
    }

    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE.decode(input.as_bytes()) {
        if bytes.len() == size {
            println!("Reticulum Identity imported from base64 input");
            return Ok(bytes);
        }
    }

    if let Ok(bytes) = base256_decode(input) {
        if bytes.len() == size {
            println!("Reticulum Identity imported from base256 input");
            return Ok(bytes);
        }
    }

    let kind = if public { "public" } else { "private" };
    err(
        R_INVALID_IDENTITY,
        format!("Could not decode specified data to a valid {kind} Reticulum Identity"),
    )
}

fn sign_paths(
    args: &Args,
    identity: &WorkingIdentity,
    paths: &[String],
) -> Result<(), (i32, String)> {
    if paths.is_empty() {
        return err(R_INVALID_ARGS, "No file specified for signing");
    }
    let mut signed = 0usize;
    for path in paths {
        sign_path(args, identity, path)?;
        signed += 1;
    }
    if signed != paths.len() {
        return err(
            R_SEQUENCE_ERROR,
            "Sequence error on recursive signature creation",
        );
    }
    Ok(())
}

fn sign_path(args: &Args, identity: &WorkingIdentity, path: &str) -> Result<(), (i32, String)> {
    let private = identity.private().ok_or_else(|| {
        (
            R_NO_PRVKEY,
            format!("Cannot sign \"{path}\", the identity does not hold a private key"),
        )
    })?;
    let sign_path = expand_home(path);
    let rsg_path = PathBuf::from(format!("{}.{}", sign_path.display(), SIG_EXT));
    if !sign_path.is_file() {
        return err(
            R_NO_FILE,
            format!("The file \"{}\" does not exist", sign_path.display()),
        );
    }
    let output = output_encoding(args);
    if output == Encoding::Bin && rsg_path.exists() && !args.force {
        return err(
            R_FILE_EXISTS,
            format!(
                "The signature file \"{}\" already exists, not overwriting",
                rsg_path.display()
            ),
        );
    }

    if args.raw {
        let data = fs::read(&sign_path).map_err(|e| {
            (
                R_READ_ERROR,
                format!("Could not read {}: {e}", sign_path.display()),
            )
        })?;
        fs::write(&rsg_path, private.sign(&data).to_bytes()).map_err(|e| {
            (
                R_WRITE_ERROR,
                format!("Could not sign {}: {e}", sign_path.display()),
            )
        })?;
    } else {
        let data = fs::read(&sign_path).map_err(|e| {
            (
                R_READ_ERROR,
                format!("Could not read {}: {e}", sign_path.display()),
            )
        })?;
        let rsg = create_rsg(private, &data, false, None, output)?;
        if output == Encoding::Bin {
            fs::write(&rsg_path, rsg).map_err(|e| {
                (
                    R_WRITE_ERROR,
                    format!("Could not sign {}: {e}", sign_path.display()),
                )
            })?;
        } else {
            println!("\n{}\n", wrap_rsg(&rsg));
        }
    }

    println!("Signed file {} with {}", sign_path.display(), identity);
    Ok(())
}

fn sign_message(args: &Args, identity: &WorkingIdentity) -> Result<(), (i32, String)> {
    let private = identity.private().ok_or_else(|| {
        (
            R_NO_PRVKEY,
            "Cannot sign, the identity does not hold a private key".to_string(),
        )
    })?;
    let output = output_encoding(args);
    if output == Encoding::Bin && args.write.is_none() {
        return err(R_INVALID_ARGS, "No write path specified");
    }

    let mut message = match &args.sign_message {
        Some(Some(message)) => message.as_bytes().to_vec(),
        Some(None) => {
            if let Some(read_path) = &args.read {
                fs::read_to_string(expand_home(read_path))
                    .map_err(|e| (R_READ_ERROR, format!("Could not read {read_path}: {e}")))?
                    .into_bytes()
            } else {
                return err(R_INVALID_ARGS, "No message specified");
            }
        }
        None => return err(R_INVALID_ARGS, "No message specified"),
    };

    if let Some(read_path) = &args.read {
        if matches!(args.sign_message, Some(Some(_))) {
            return err(
                R_INVALID_ARGS,
                "Both an input file and command-line provided message was specified, aborting",
            );
        }
        message = fs::read_to_string(expand_home(read_path))
            .map_err(|e| (R_READ_ERROR, format!("Could not read {read_path}: {e}")))?
            .into_bytes();
    }
    if message.is_empty() {
        return err(R_INVALID_ARGS, "No message specified");
    }

    let meta = match &args.embed_meta {
        Some(path) => Some(load_simple_meta(path)?),
        None => None,
    };
    let rsg = create_rsg(private, &message, true, meta, output)?;
    if output == Encoding::Bin {
        let mut rsg_path = expand_home(args.write.as_ref().unwrap());
        if !rsg_path.to_string_lossy().ends_with(&format!(".{MSG_EXT}")) {
            rsg_path = PathBuf::from(format!("{}.{}", rsg_path.display(), MSG_EXT));
        }
        if rsg_path.exists() && !args.force {
            return err(
                R_FILE_EXISTS,
                format!(
                    "The signature file \"{}\" already exists, not overwriting",
                    rsg_path.display()
                ),
            );
        }
        fs::write(&rsg_path, rsg)
            .map_err(|e| (R_WRITE_ERROR, format!("Could not sign message: {e}")))?;
        println!(
            "Message signed with {} saved to {}",
            identity,
            rsg_path.display()
        );
    } else {
        println!("\n{}\n", wrap_rsg(&rsg));
        println!("Message signed with {}", identity);
    }
    Ok(())
}

fn create_rsg(
    signer: &PrivateIdentity,
    message: &[u8],
    embed: bool,
    meta: Option<Vec<(Value, Value)>>,
    output: Encoding,
) -> Result<Vec<u8>, (i32, String)> {
    let public_key = [
        signer.as_identity().public_key_bytes().as_slice(),
        signer.as_identity().verifying_key_bytes().as_slice(),
    ]
    .concat();
    let mut meta_map = vec![
        (
            Value::String("signer".into()),
            Value::Binary(signer.address_hash().as_slice().to_vec()),
        ),
        (Value::String("pubkey".into()), Value::Binary(public_key)),
    ];
    if let Some(extra) = meta {
        for (key, value) in extra {
            if !matches!(&key, Value::String(s) if s.as_str() == Some("signer") || s.as_str() == Some("pubkey"))
            {
                meta_map.push((key, value));
            }
        }
    }

    let mut signed_data = vec![
        (
            Value::String("hashtype".into()),
            Value::String("sha256".into()),
        ),
        (
            Value::String("hash".into()),
            Value::Binary(Sha256::digest(message).to_vec()),
        ),
        (Value::String("meta".into()), Value::Map(meta_map)),
    ];
    if embed {
        signed_data.push((
            Value::String("message".into()),
            Value::Binary(message.to_vec()),
        ));
    }

    let mut envelope = Vec::new();
    write_value(&mut envelope, &Value::Map(signed_data)).map_err(|e| {
        (
            R_UNKNOWN_ERROR,
            format!("Could not create signature envelope: {e}"),
        )
    })?;
    let signature = signer.sign(&envelope).to_bytes();
    let mut rsg = Vec::with_capacity(signature.len() + envelope.len());
    rsg.extend_from_slice(&signature);
    rsg.extend_from_slice(&envelope);

    Ok(match output {
        Encoding::Bin => rsg,
        Encoding::Hex => hex_encode(&rsg).into_bytes(),
        Encoding::Base32 => base32_encode(&rsg).into_bytes(),
        Encoding::Base64 => base64::engine::general_purpose::URL_SAFE
            .encode(rsg)
            .into_bytes(),
        Encoding::Base256 => base256_encode(&rsg).into_bytes(),
    })
}

fn validate_paths(
    args: &Args,
    identity: Option<&WorkingIdentity>,
    paths: &[String],
) -> Result<(), (i32, String)> {
    if paths.is_empty() {
        return err(R_INVALID_ARGS, "No file specified for validation");
    }
    for path in paths {
        validate_path(args, identity, path)?;
    }
    Ok(())
}

fn validate_path(
    args: &Args,
    identity: Option<&WorkingIdentity>,
    path: &str,
) -> Result<(), (i32, String)> {
    let validate_path = expand_home(path);
    let path_string = validate_path.to_string_lossy();
    if path_string.to_lowercase().ends_with(&format!(".{MSG_EXT}")) {
        return validate_message(args, identity, &validate_path);
    }
    let sig_suffix = format!(".{SIG_EXT}");
    let (signature_path, file_path) = if path_string.to_lowercase().ends_with(&sig_suffix) {
        (
            validate_path.clone(),
            PathBuf::from(&path_string[..path_string.len() - sig_suffix.len()]),
        )
    } else {
        (
            PathBuf::from(format!("{}.{}", validate_path.display(), SIG_EXT)),
            validate_path,
        )
    };

    if !file_path.is_file() {
        return err(
            R_NO_FILE,
            format!(
                "The validation target \"{}\" does not exist",
                file_path.display()
            ),
        );
    }
    if !signature_path.is_file() {
        return err(
            R_NO_FILE,
            format!("No signature file exists for \"{}\"", file_path.display()),
        );
    }
    let rsg = fs::read(&signature_path)
        .map_err(|e| (R_READ_ERROR, format!("Could not read rsg: {e}")))?;

    if rsg.len() == SIGNATURE_LENGTH {
        let id = identity.ok_or_else(|| {
            (
                R_NO_IDENTITY,
                "Cannot validate legacy rsg signatures without an explicit required identity"
                    .to_string(),
            )
        })?;
        let data = fs::read(&file_path).map_err(|e| {
            (
                R_READ_ERROR,
                format!("Could not read {}: {e}", file_path.display()),
            )
        })?;
        let sig = Signature::from_slice(&rsg)
            .map_err(|_| (R_INVALID_SIGNATURE, "Invalid signature".to_string()))?;
        id.identity().verify(&data, &sig).map_err(|_| {
            (
                R_INVALID_SIGNATURE,
                format!(
                    "Invalid signature {} for file {}\nThis file was NOT signed by {}",
                    signature_path.display(),
                    file_path.display(),
                    id
                ),
            )
        })?;
        println!(
            "Signature is valid, the file {} was signed by {}",
            file_path.display(),
            id
        );
        return Ok(());
    }

    let data = fs::read(&file_path).map_err(|e| {
        (
            R_READ_ERROR,
            format!("Could not read {}: {e}", file_path.display()),
        )
    })?;
    let (valid, signing_identity) = validate_rsg(&rsg, &data, identity)?;
    if !valid {
        let desc = identity
            .map(|i| format!("\nThis file was NOT signed by {i}"))
            .unwrap_or_default();
        return err(
            R_INVALID_SIGNATURE,
            format!(
                "Invalid signature {} for file {}{}",
                signature_path.display(),
                file_path.display(),
                desc
            ),
        );
    }
    println!(
        "Signature is valid, the file {} was signed by {}",
        file_path.display(),
        pretty_hex(signing_identity.address_hash.as_slice())
    );
    Ok(())
}

fn validate_message(
    args: &Args,
    identity: Option<&WorkingIdentity>,
    path: &Path,
) -> Result<(), (i32, String)> {
    if !path.is_file() {
        return err(
            R_NO_FILE,
            format!("The signature file \"{}\" does not exist", path.display()),
        );
    }
    let rsg = fs::read(path).map_err(|e| (R_READ_ERROR, format!("Could not read rsg: {e}")))?;
    let signed_data = parse_rsg_envelope(&rsg)?;
    let message = map_get(&signed_data, "message")
        .and_then(value_as_bytes)
        .ok_or_else(|| {
            (
                R_INVALID_SIGNATURE,
                format!("No embedded message in {}", path.display()),
            )
        })?;
    let (valid, signing_identity) = validate_rsg(&rsg, &message, identity)?;
    if !valid {
        let desc = identity
            .map(|i| format!("\nThe message was NOT signed by {i}"))
            .unwrap_or_default();
        return err(
            R_INVALID_SIGNATURE,
            format!("Invalid signature in {}{}", path.display(), desc),
        );
    }
    if args.meta {
        println!("RSM Metadata\n============\n");
        if let Some(Value::Map(meta)) = map_get(&signed_data, "meta") {
            for (key, value) in meta {
                print_meta_entry(key, value, 1);
            }
        }
        println!("\nValidation\n==========");
    }
    let c = if args.meta { "" } else { ":" };
    let following = if args.meta { "" } else { " following" };
    println!(
        "\nSignature is valid, the{following} message was signed by {}{c}\n",
        pretty_hex(signing_identity.address_hash.as_slice())
    );
    if args.meta {
        println!("Message\n=======\n");
    }
    println!("{}", String::from_utf8_lossy(&message));
    Ok(())
}

fn validate_rsg(
    rsg: &[u8],
    message: &[u8],
    required: Option<&WorkingIdentity>,
) -> Result<(bool, Identity), (i32, String)> {
    if rsg.len() < SIGNATURE_LENGTH + 1 {
        return err(R_INVALID_SIGNATURE, "Invalid signature");
    }
    let signature = Signature::from_slice(&rsg[..SIGNATURE_LENGTH])
        .map_err(|_| (R_INVALID_SIGNATURE, "Invalid signature".to_string()))?;
    let envelope = &rsg[SIGNATURE_LENGTH..];
    let signed_data = parse_rsg_envelope(rsg)?;
    let hashtype = map_get(&signed_data, "hashtype").and_then(|v| match v {
        Value::String(s) => s.as_str().map(ToOwned::to_owned),
        _ => None,
    });
    if hashtype.as_deref() != Some("sha256") {
        return err(R_INVALID_SIGNATURE, "Invalid signature");
    }
    let expected_hash = Sha256::digest(message).to_vec();
    if map_get(&signed_data, "hash").and_then(value_as_bytes) != Some(expected_hash) {
        let fallback = required.map(|i| *i.identity()).unwrap_or_default();
        return Ok((false, fallback));
    }
    let meta = match map_get(&signed_data, "meta") {
        Some(Value::Map(meta)) => meta,
        _ => return err(R_INVALID_SIGNATURE, "Invalid signature"),
    };
    let pubkey = meta_get(meta, "pubkey")
        .and_then(value_as_bytes)
        .ok_or_else(|| (R_INVALID_SIGNATURE, "Invalid signature".to_string()))?;
    if pubkey.len() != PUBLIC_KEY_LENGTH * 2 {
        return err(R_INVALID_SIGNATURE, "Invalid signature");
    }
    let signing_identity =
        Identity::new_from_slices(&pubkey[..PUBLIC_KEY_LENGTH], &pubkey[PUBLIC_KEY_LENGTH..])
            .map_err(|_| (R_INVALID_SIGNATURE, "Invalid signature".to_string()))?;

    if let Some(required) = required {
        if signing_identity.address_hash.as_slice() != required.identity_hash() {
            return Ok((false, signing_identity));
        }
    }
    if signing_identity.verify(envelope, &signature).is_err() {
        return Ok((false, signing_identity));
    }
    Ok((true, signing_identity))
}

fn parse_rsg_envelope(rsg: &[u8]) -> Result<Value, (i32, String)> {
    if rsg.len() <= SIGNATURE_LENGTH {
        return err(R_INVALID_SIGNATURE, "Invalid signature");
    }
    read_value(&mut &rsg[SIGNATURE_LENGTH..])
        .map_err(|_| (R_INVALID_SIGNATURE, "Invalid signature".to_string()))
}

fn encrypt_paths(
    args: &Args,
    identity: &WorkingIdentity,
    paths: &[String],
) -> Result<(), (i32, String)> {
    if paths.is_empty() {
        return err(R_INVALID_ARGS, "No file specified for encryption");
    }
    for path in paths {
        encrypt_path(args, identity, path)?;
    }
    Ok(())
}

fn encrypt_path(args: &Args, identity: &WorkingIdentity, path: &str) -> Result<(), (i32, String)> {
    let encrypt_path = expand_home(path);
    let rfe_path = args
        .write
        .as_ref()
        .map(|path| expand_home(path))
        .unwrap_or_else(|| PathBuf::from(format!("{}.{}", encrypt_path.display(), ENCRYPT_EXT)));
    if !encrypt_path.is_file() {
        return err(
            R_NO_FILE,
            format!("The file \"{}\" does not exist", encrypt_path.display()),
        );
    }
    if rfe_path.exists() && !args.force {
        return err(
            R_FILE_EXISTS,
            format!(
                "The encryption output file \"{}\" already exists, not overwriting",
                rfe_path.display()
            ),
        );
    }

    let mut input = File::open(&encrypt_path).map_err(|e| {
        (
            R_READ_ERROR,
            format!(
                "Error reading {} for encryption: {e}",
                encrypt_path.display()
            ),
        )
    })?;
    let mut output = create_file(&rfe_path, args.force)?;
    let mut buf = vec![0u8; ENC_CHUNK];
    let mut out_buf = vec![0u8; ENC_CHUNK + 256];
    let mut wrote = 0usize;
    let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();
    loop {
        let read = input.read(&mut buf).map_err(|e| {
            (
                R_READ_ERROR,
                format!(
                    "Error reading {} for encryption: {e}",
                    encrypt_path.display()
                ),
            )
        })?;
        if read == 0 {
            break;
        }
        let encrypted = identity
            .identity()
            .encrypt_packet(&mut rng, &buf[..read], None, &mut out_buf)
            .map_err(|e| {
                (
                    R_UNKNOWN_ERROR,
                    format!("Could not encrypt {}: {e:?}", encrypt_path.display()),
                )
            })?;
        output.write_all(encrypted).map_err(|e| {
            (
                R_WRITE_ERROR,
                format!(
                    "Error writing encrypted output to {}: {e}",
                    rfe_path.display()
                ),
            )
        })?;
        wrote += encrypted.len();
        print!(
            "\rWrote {} to {}   ",
            pretty_size(wrote),
            rfe_path.display()
        );
        let _ = io::stdout().flush();
    }
    println!(
        "\nFile {} encrypted for {} to {}",
        encrypt_path.display(),
        identity,
        rfe_path.display()
    );
    Ok(())
}

fn decrypt_paths(
    args: &Args,
    identity: &WorkingIdentity,
    paths: &[String],
) -> Result<(), (i32, String)> {
    if paths.is_empty() {
        return err(R_INVALID_ARGS, "No file specified for decryption");
    }
    for path in paths {
        decrypt_path(args, identity, path)?;
    }
    Ok(())
}

fn decrypt_path(args: &Args, identity: &WorkingIdentity, path: &str) -> Result<(), (i32, String)> {
    let private = identity.private().ok_or_else(|| {
        (
            R_NO_PRVKEY,
            format!("Cannot decrypt \"{path}\", the identity does not hold a private key"),
        )
    })?;
    let rfe_path = expand_home(path);
    let suffix = format!(".{ENCRYPT_EXT}");
    let rfe_str = rfe_path.to_string_lossy();
    if !rfe_str.ends_with(&suffix) {
        return err(
            R_INVALID_FILE,
            format!(
                "The file {} does not appear to be a Reticulum encrypted file",
                rfe_path.display()
            ),
        );
    }
    let decrypt_path = args
        .write
        .as_ref()
        .map(|path| expand_home(path))
        .unwrap_or_else(|| PathBuf::from(&rfe_str[..rfe_str.len() - suffix.len()]));
    if !rfe_path.is_file() {
        return err(
            R_NO_FILE,
            format!("The file \"{}\" does not exist", rfe_path.display()),
        );
    }
    if decrypt_path.exists() && !args.force {
        return err(
            R_FILE_EXISTS,
            format!(
                "The decryption output file \"{}\" already exists, not overwriting",
                decrypt_path.display()
            ),
        );
    }

    let mut input = File::open(&rfe_path).map_err(|e| {
        (
            R_READ_ERROR,
            format!("Error reading {} for decryption: {e}", rfe_path.display()),
        )
    })?;
    let mut output = create_file(&decrypt_path, args.force)?;
    let mut buf = vec![0u8; DEC_CHUNK];
    let mut out_buf = vec![0u8; DEC_CHUNK];
    let mut wrote = 0usize;
    let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();
    loop {
        let read = input.read(&mut buf).map_err(|e| {
            (
                R_READ_ERROR,
                format!("Error reading {} for decryption: {e}", rfe_path.display()),
            )
        })?;
        if read == 0 {
            break;
        }
        let decrypted = private
            .decrypt_packet(&mut rng, &buf[..read], None, &mut out_buf)
            .map_err(|_| {
                (
                    R_DECRYPT_FAILED,
                    "The provided identity could not decrypt the file".to_string(),
                )
            })?;
        output.write_all(decrypted).map_err(|e| {
            (
                R_WRITE_ERROR,
                format!(
                    "Error writing decrypted output to {}: {e}",
                    decrypt_path.display()
                ),
            )
        })?;
        wrote += decrypted.len();
        print!(
            "\rWrote {} to {}   ",
            pretty_size(wrote),
            decrypt_path.display()
        );
        let _ = io::stdout().flush();
    }
    println!(
        "\nFile {} decrypted to {}",
        rfe_path.display(),
        decrypt_path.display()
    );
    Ok(())
}

fn write_identity(args: &Args, identity: &WorkingIdentity) -> Result<(), (i32, String)> {
    let mut path = expand_home(args.write.as_ref().unwrap());
    if args.export_prv {
        let private = identity.private().ok_or_else(|| {
            (
                R_NO_PRVKEY,
                "Identity doesn't hold a private key, cannot export".to_string(),
            )
        })?;
        if path.exists() && !args.force {
            return err(
                R_FILE_EXISTS,
                format!("File {} already exists, not overwriting", path.display()),
            );
        }
        write_private_identity_file(&path, private)?;
        println!("Wrote private identity to {}", path.display());
        return Ok(());
    }

    if !path
        .to_string_lossy()
        .to_lowercase()
        .ends_with(&format!(".{PUB_EXT}"))
    {
        path = PathBuf::from(format!("{}.{}", path.display(), PUB_EXT));
    }
    if path.exists() && !args.force {
        return err(
            R_FILE_EXISTS,
            format!("File {} already exists, not overwriting", path.display()),
        );
    }
    fs::write(&path, identity.public_key_bytes()).map_err(|e| {
        (
            R_WRITE_ERROR,
            format!("Error while writing imported identity to file: {e}"),
        )
    })?;
    println!("Wrote public identity to {}", path.display());
    Ok(())
}

fn print_identity_information(args: &Args, identity: &WorkingIdentity) {
    println!("Identity Hash : {}", pretty_hex(identity.identity_hash()));
    println!(
        "Public Key    : {}",
        encode_key(args, &identity.public_key_bytes())
    );
    if let Some(private) = identity.private() {
        if args.print_private {
            println!(
                "Private Key   : {}",
                encode_key(args, &decode_hex(&private.to_hex_string()).unwrap())
            );
        } else {
            println!("Private Key   : Hidden");
        }
    }
}

fn print_hash_information(
    aspects: &str,
    identity: Option<&WorkingIdentity>,
    identity_arg: Option<&str>,
) -> Result<(), (i32, String)> {
    let identity_hash = if let Some(identity) = identity {
        identity.identity_hash().to_vec()
    } else if let Some(identity_arg) = identity_arg {
        if identity_arg.len() != AddressHash::new_empty().len() * 2 {
            return err(R_INVALID_IDENTITY, "Invalid identity hash length");
        }
        decode_hex(identity_arg)?
    } else {
        return err(R_INVALID_IDENTITY, "Invalid identity");
    };
    let (app, aspect_tail) = split_aspects(aspects)?;
    let name = DestinationName::new(app, &aspect_tail);
    let mut hash_input = Vec::with_capacity(PUBLIC_KEY_LENGTH);
    hash_input.extend_from_slice(name.as_name_hash_slice());
    hash_input.extend_from_slice(&identity_hash);
    let destination_hash = AddressHash::new_from_slice(&hash_input);
    println!(
        "The {aspects} destination for this Identity is {}",
        pretty_hex(destination_hash.as_slice())
    );
    if let Some(WorkingIdentity::Private(private)) = identity {
        let destination = SingleOutputDestination::new(*private.as_identity(), name);
        println!("The full destination specifier is {}", destination.desc);
    } else if let Some(WorkingIdentity::Public(public)) = identity {
        let destination = SingleOutputDestination::new(*public, name);
        println!("The full destination specifier is {}", destination.desc);
    }
    Ok(())
}

fn export_pub_identity(args: &Args, identity: &WorkingIdentity) -> Result<(), (i32, String)> {
    let key = identity.public_key_bytes();
    if key.is_empty() {
        return err(
            R_NO_PUBKEY,
            "Identity doesn't hold a public key, cannot export",
        );
    }
    println!("Public Identity Keys  : {}", encode_key(args, &key));
    Ok(())
}

fn export_prv_identity(args: &Args, identity: &WorkingIdentity) -> Result<(), (i32, String)> {
    let private = identity.private().ok_or_else(|| {
        (
            R_NO_PRVKEY,
            "Identity doesn't hold a private key, cannot export".to_string(),
        )
    })?;
    println!(
        "Private Identity Keys : {}",
        encode_key(args, &decode_hex(&private.to_hex_string()).unwrap())
    );
    Ok(())
}

fn output_encoding(args: &Args) -> Encoding {
    if args.base32 {
        Encoding::Base32
    } else if args.base64 {
        Encoding::Base64
    } else if args.base256 {
        Encoding::Base256
    } else if args.hex {
        Encoding::Hex
    } else {
        Encoding::Bin
    }
}

fn encode_key(args: &Args, bytes: &[u8]) -> String {
    if args.base64 {
        base64::engine::general_purpose::URL_SAFE.encode(bytes)
    } else if args.base32 {
        base32_encode(bytes)
    } else if args.base256 {
        base256_encode(bytes)
    } else {
        hex_encode(bytes)
    }
}

fn split_aspects(aspects: &str) -> Result<(&str, String), (i32, String)> {
    let mut parts = aspects.split('.');
    let app = parts.next().unwrap_or_default();
    if app.is_empty() {
        return err(R_INVALID_ASPECTS, "Invalid destination aspects specified");
    }
    Ok((app, parts.collect::<Vec<_>>().join(".")))
}

fn map_get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    match value {
        Value::Map(map) => meta_get(map, key),
        _ => None,
    }
}

fn meta_get<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    map.iter().find_map(|(k, v)| match k {
        Value::String(s) if s.as_str() == Some(key) => Some(v),
        _ => None,
    })
}

fn value_as_bytes(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::Binary(bytes) => Some(bytes.clone()),
        Value::String(s) => s.as_str().map(|s| s.as_bytes().to_vec()),
        _ => None,
    }
}

fn load_simple_meta(path: &str) -> Result<Vec<(Value, Value)>, (i32, String)> {
    let text = fs::read_to_string(expand_home(path)).map_err(|e| {
        (
            R_READ_ERROR,
            format!("Could not load metadata from {path}: {e}"),
        )
    })?;
    let mut map = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            map.push((
                Value::String(Utf8String::from(key.trim())),
                Value::String(Utf8String::from(value.trim())),
            ));
        }
    }
    Ok(map)
}

fn print_meta_entry(key: &Value, value: &Value, level: usize) {
    let key = match key {
        Value::String(s) => s.as_str().unwrap_or("<decode-error>"),
        _ => "<decode-error>",
    };
    let indent = "  ".repeat(level);
    match value {
        Value::Map(map) => {
            println!("d{indent}{key}:");
            for (k, v) in map {
                print_meta_entry(k, v, level + 1);
            }
        }
        Value::Binary(bytes) => println!("b{indent}{key}={}", hex_encode(bytes)),
        Value::String(s) => println!("s{indent}{key}={}", s.as_str().unwrap_or("<decode-error>")),
        Value::Integer(i) => println!("i{indent}{key}={i}"),
        Value::F32(v) => println!("f{indent}{key}={v}"),
        Value::F64(v) => println!("f{indent}{key}={v}"),
        Value::Nil => println!("N{indent}{key}=None"),
        Value::Array(_) => println!("l{indent}{key}={value}"),
        _ => println!("u{indent}{key}={value}"),
    }
}

fn read_private_identity_file(path: &Path) -> Result<PrivateIdentity, (i32, String)> {
    let data = fs::read(path).map_err(|e| {
        (
            R_INVALID_IDENTITY,
            format!("Could not load Identity from specified file: {e}"),
        )
    })?;
    let hex = if data.len() == PUBLIC_KEY_LENGTH * 2 {
        hex_encode(&data)
    } else {
        String::from_utf8_lossy(&data).trim().to_string()
    };
    PrivateIdentity::new_from_hex_string(&hex).map_err(|e| {
        (
            R_INVALID_IDENTITY,
            format!("Could not load Identity from specified file: {e:?}"),
        )
    })
}

fn write_private_identity_file(
    path: &Path,
    identity: &PrivateIdentity,
) -> Result<(), (i32, String)> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            (
                R_WRITE_ERROR,
                format!("An error ocurred while saving the generated Identity: {e}"),
            )
        })?;
    }
    fs::write(path, decode_hex(&identity.to_hex_string()).unwrap()).map_err(|e| {
        (
            R_WRITE_ERROR,
            format!("An error ocurred while saving the generated Identity: {e}"),
        )
    })
}

fn create_file(path: &Path, force: bool) -> Result<File, (i32, String)> {
    let mut options = OpenOptions::new();
    options.write(true).create(true);
    if force {
        options.truncate(true);
    } else {
        options.create_new(true);
    }
    options.open(path).map_err(|e| {
        (
            R_WRITE_ERROR,
            format!("Could not open {} for writing: {e}", path.display()),
        )
    })
}

fn expand_home(input: &str) -> PathBuf {
    if let Some(rest) = input.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(input)
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

fn decode_hex(input: &str) -> Result<Vec<u8>, (i32, String)> {
    let input = input.trim();
    if input.len() % 2 != 0 {
        return err(R_INVALID_IDENTITY, "Invalid hexadecimal input");
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    for i in (0..input.len()).step_by(2) {
        out.push(u8::from_str_radix(&input[i..i + 2], 16).map_err(|e| {
            (
                R_INVALID_IDENTITY,
                format!("Invalid hexadecimal input: {e}"),
            )
        })?);
    }
    Ok(out)
}

fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer = 0u16;
    let mut bits = 0u8;
    for byte in bytes {
        buffer = (buffer << 8) | *byte as u16;
        bits += 8;
        while bits >= 5 {
            let index = ((buffer >> (bits - 5)) & 0x1f) as usize;
            out.push(ALPHABET[index] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[index] as char);
    }
    while out.len() % 8 != 0 {
        out.push('=');
    }
    out
}

fn base32_decode(input: &str) -> Result<Vec<u8>, ()> {
    let mut buffer = 0u32;
    let mut bits = 0u8;
    let mut out = Vec::new();
    for byte in input.trim_end_matches('=').bytes() {
        let val = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return Err(()),
        } as u32;
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            out.push(((buffer >> (bits - 8)) & 0xff) as u8);
            bits -= 8;
        }
    }
    Ok(out)
}

fn base256_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| B256[*byte as usize]).collect()
}

fn base256_decode(input: &str) -> Result<Vec<u8>, ()> {
    input
        .chars()
        .map(|ch| {
            B256.iter()
                .position(|entry| *entry == ch.to_string())
                .map(|index| index as u8)
                .ok_or(())
        })
        .collect()
}

fn wrap_rsg(rsg: &[u8]) -> String {
    let header = format!(
        "{}{}",
        "#### Start of rsg data ",
        "#".repeat(RSG_ROW_WIDTH - "#### Start of rsg data ".len())
    );
    let footer_text = " End of rsg data ####";
    let footer = format!(
        "{}{}",
        "#".repeat(RSG_ROW_WIDTH - footer_text.len()),
        footer_text
    );
    let mut wrapped = String::new();
    wrapped.push_str(&header);
    wrapped.push('\n');
    let data = String::from_utf8_lossy(rsg);
    for chunk in data.as_bytes().chunks(RSG_ROW_WIDTH) {
        let mut line = String::from_utf8_lossy(chunk).to_string();
        while line.len() < RSG_ROW_WIDTH {
            line.push('=');
        }
        wrapped.push_str(&line);
        wrapped.push('\n');
    }
    wrapped.push_str(&footer);
    wrapped
}

fn pretty_size(bytes: usize) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    let mut unit = 0usize;
    while size >= 1024.0 && unit + 1 < UNITS.len() {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{size:.2} {}", UNITS[unit])
    }
}

fn print_help() {
    println!(
        "Reticulum Identity & Encryption Utility\n\n\
Usage: rnid [options]\n\n\
Identity Resolution:\n\
  --config <path>             path to alternative Reticulum config directory\n\
  -i, --identity <rid>        hexadecimal Reticulum identity or destination hash, or path to Identity file\n\
  -g, --generate <path>       generate a new Identity and save to path\n\
  -m, --import-pub <rid>      import public Reticulum identity in hex, base32 or base64 format, or from file\n\
  -M, --import-prv <rid>      import Reticulum identity in hex, base32 or base64 format, or from file\n\
  -x, --export-pub            export public identity to hex, base32 or base64 format\n\
  -X, --export-prv            export private identity to hex, base32 or base64 format, or to file\n\n\
Operations:\n\
  -a, --announce [aspects]    announce a destination based on this Identity\n\
  -H, --hash <aspects>        show destination hashes for other aspects for this Identity\n\
  -d, --decrypt [file ...]    decrypt file\n\
  -e, --encrypt [file ...]    encrypt file\n\
  -V, --validate [path ...]   validate signature\n\
  -s, --sign [path ...]       sign file\n\
  -S, --sign-message [text]   create embedded signed message\n\
  -E, --embed-meta [path]     embed metadata structure from file\n\
  --raw                       sign raw input data instead of hashing first\n\n\
I/O Control:\n\
  -w, --write <path>          output file path\n\
  -r, --read <path>           input file path for operations with optional file input\n\
  -f, --force                 write output even if it overwrites existing files\n\
  -R, --request               request unknown Identities from the network\n\
  -N, --no-cache              never use cached or network-sourced information\n\
  -p, --print-identity        print identity info and exit\n\
  -P, --print-private         allow displaying private keys\n\n\
Formatting Control:\n\
  -B, --base32                Use base32-encoded input and output\n\
  -b, --base64                Use base64-encoded input and output\n\
  -U, --base256               Use base256-encoded input and output\n\
  -F, --hex                   Use hex-encoded input and output\n\
  --meta                      Display RSM metadata if available"
    );
}

fn err<T, S: Into<String>>(code: i32, msg: S) -> Result<T, (i32, String)> {
    Err((code, msg.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_round_trip() {
        let data = b"reticulum identity";
        assert_eq!(base32_decode(&base32_encode(data)).unwrap(), data);
    }

    #[test]
    fn base256_round_trip() {
        let data = (0u8..=255).collect::<Vec<_>>();
        assert_eq!(base256_decode(&base256_encode(&data)).unwrap(), data);
    }

    #[test]
    fn destination_hash_uses_name_hash_and_identity_hash() {
        let identity_hash = [7u8; 16];
        let name = DestinationName::new("rns", "id");
        let mut input = Vec::new();
        input.extend_from_slice(name.as_name_hash_slice());
        input.extend_from_slice(&identity_hash);
        let expected = AddressHash::new_from_slice(&input);

        let mut calculated_input = Vec::new();
        calculated_input.extend_from_slice(name.as_name_hash_slice());
        calculated_input.extend_from_slice(&identity_hash);
        assert_eq!(AddressHash::new_from_slice(&calculated_input), expected);
    }

    #[test]
    fn rsg_validates_against_embedded_public_key() {
        let mut rng = StdRng::try_from_rng(&mut SysRng).unwrap();
        let identity = PrivateIdentity::new_from_rand(&mut rng);
        let message = b"hello";
        let rsg = create_rsg(&identity, message, true, None, Encoding::Bin).unwrap();
        let (valid, signer) = validate_rsg(&rsg, message, None).unwrap();
        assert!(valid);
        assert_eq!(
            signer.address_hash.as_slice(),
            identity.address_hash().as_slice()
        );
    }
}
