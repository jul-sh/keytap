mod encrypt;
mod help;
mod keychain;
mod nearby;
mod remember;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use keytap_core::{PrivateKeyFormat, PublicKeyFormat};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "keytap",
    version,
    about = "Derive keys and encrypt files from a passkey.",
    // The top-level help is our own generated single-screen overview (see
    // `main`); clap keeps its default `--help` on each subcommand.
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create the passkey (only needed once)
    Init,

    /// Output the public key
    Public {
        /// Key name for domain separation
        #[arg(default_value = "default")]
        name: String,

        /// Output format
        // `--as` is the documented flag; `--format` stays as a hidden alias so
        // existing scripts keep working. (`as` is a Rust keyword, hence the
        // field is still named `format`.)
        #[arg(long = "as", alias = "format", value_name = "FORMAT", default_value = "hex")]
        format: PublicFormat,
    },

    /// Reveal private key material
    #[command(after_help = help::REUSE)]
    Reveal {
        /// Key name for domain separation
        #[arg(default_value = "default")]
        name: String,

        /// Output format
        #[arg(long = "as", alias = "format", value_name = "FORMAT", default_value = "hex")]
        format: Format,
    },

    /// Encrypt with the derived age identity (stdin/stdout by default)
    Encrypt {
        /// Files to encrypt ('-' or omitted = stdin). Multiple files are each
        /// written to `<file>.age` (one authentication for the whole batch).
        file: Vec<String>,

        /// Write ciphertext here ('-' = stdout). Only valid with a single input.
        #[arg(short = 'o', long = "output")]
        output: Option<String>,

        /// Key name for domain separation
        #[arg(long, default_value = "default")]
        key: String,

        /// Additional age recipient (can be repeated)
        #[arg(long = "to")]
        recipients: Vec<String>,

        /// File containing age recipients (one per line)
        #[arg(short = 'R')]
        recipients_file: Vec<String>,

        /// Don't include self as a recipient when encrypting
        #[arg(long)]
        no_self: bool,
    },

    /// Decrypt an age file with the derived age identity (stdin/stdout by default)
    Decrypt {
        /// Files to decrypt ('-' or omitted = stdin). Multiple files each have
        /// their `.age` suffix stripped for output (one authentication).
        file: Vec<String>,

        /// Write plaintext here ('-' = stdout). Only valid with a single input.
        #[arg(short = 'o', long = "output")]
        output: Option<String>,

        /// Key name for domain separation
        #[arg(long, default_value = "default")]
        key: String,
    },

    /// Remember a derived key in the OS keychain (no more prompts for it)
    #[command(after_help = help::REMEMBER)]
    Remember {
        /// Key name for domain separation
        #[arg(default_value = "default")]
        name: String,

        /// Store in a plain file instead of the OS keychain, for machines
        /// without one (not encrypted at rest; see --help)
        #[arg(long)]
        file: bool,
    },

    /// Forget a remembered key
    Forget {
        /// Key name for domain separation
        #[arg(default_value = "default")]
        name: String,

        /// Forget every remembered key, including ones from previous passkeys
        #[arg(long, conflicts_with = "name")]
        all: bool,
    },

    /// List keys remembered on this machine (never prints key material)
    Remembered,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum Format {
    Hex,
    Base64,
    Age,
    Ssh,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum PublicFormat {
    Hex,
    Base64,
    Age,
    Ssh,
}

fn main() {
    // Intercept the top-level help ourselves (bare `keytap`, `keytap -h`,
    // `keytap --help`, `keytap help`) so it renders our single-screen overview.
    // Subcommand help (`keytap reveal --help`) still falls through to clap.
    if wants_top_level_help() {
        print!("{}", help::overview(&Cli::command()));
        return;
    }

    let cli = Cli::parse();

    match cli.command {
        Command::Init => {
            let credential_id = register();
            remember::after_init(&credential_id);
        }
        Command::Public { ref name, format } => {
            let raw_key = obtain_key(name);
            emit_public_key(&raw_key, format, name);
        }
        Command::Reveal { ref name, format } => {
            let raw_key = obtain_key(name);
            emit_private_key(&raw_key, format);
        }
        Command::Encrypt { ref file, ref output, ref key, ref recipients, ref recipients_file, no_self } => {
            // Validate flags BEFORE authenticating so a bad invocation fails fast
            // instead of after a Touch ID / phone approval.
            encrypt::validate_io(file, output.as_deref());
            let raw_key = obtain_key(key);
            encrypt::encrypt(&raw_key, file, output.as_deref(), recipients, recipients_file, !no_self);
        }
        Command::Decrypt { ref file, ref output, ref key } => {
            encrypt::validate_io(file, output.as_deref());
            let raw_key = obtain_key(key);
            encrypt::decrypt(&raw_key, file, output.as_deref());
        }
        Command::Remember { ref name, file } => {
            // Fail fast on names derivation would reject, and on machines
            // with nowhere to store, before any ceremony.
            if let Err(e) = keytap_core::prf_salt_for_name(name) {
                die(&e.to_string());
            }
            let mut target = remember::write_target(name, file);
            let assertion = authenticate(name);
            let raw_key = derive_key(&assertion.prf_output);
            remember::remember(&mut target, name, &assertion.credential_id, &raw_key);
        }
        Command::Forget { ref name, all } => {
            if all {
                remember::forget_all();
            } else {
                remember::forget(name);
            }
        }
        Command::Remembered => remember::remembered(),
    }
}

/// Resolve the raw key for `name`: a key remembered on this machine (under
/// the active passkey root) is used as-is; otherwise run the passkey ceremony
/// and derive on demand, storing nothing.
fn obtain_key(name: &str) -> Zeroizing<Vec<u8>> {
    if let Some(raw_key) = remember::lookup(name) {
        return raw_key;
    }
    derive_key(&authenticate(name).prf_output)
}

/// True when the invocation asks for top-level help: no subcommand at all, or
/// a help token (`-h`/`--help`/`help`) before any subcommand is named.
fn wants_top_level_help() -> bool {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => true,
        Some("-h" | "--help" | "help") => true,
        _ => false,
    }
}

/// A completed passkey ceremony: the PRF output plus the ID of the credential
/// that produced it (the latter identifies the root for remembered keys).
struct Assertion {
    prf_output: Zeroizing<Vec<u8>>,
    credential_id: Vec<u8>,
}

impl Assertion {
    fn new(prf_output: Vec<u8>, credential_id: Vec<u8>) -> Self {
        Assertion { prf_output: Zeroizing::new(prf_output), credential_id }
    }
}

/// Authenticate with a passkey ceremony.
#[cfg(feature = "native-passkey")]
fn authenticate(name: &str) -> Assertion {
    match keytap_macos::assert(name) {
        keytap_macos::AssertionOutcome::Success { prf_output, credential_id } => {
            Assertion::new(prf_output, credential_id)
        }
        keytap_macos::AssertionOutcome::Error(msg) if msg == "cancelled" => {
            die(&msg);
        }
        keytap_macos::AssertionOutcome::Error(msg) => {
            eprintln!("Couldn't open native passkey flow: {msg}");
            let (prf_output, credential_id) = nearby::authenticate_nearby(name);
            Assertion::new(prf_output, credential_id)
        }
    }
}

#[cfg(not(feature = "native-passkey"))]
fn authenticate(name: &str) -> Assertion {
    let (prf_output, credential_id) = nearby::authenticate_nearby(name);
    Assertion::new(prf_output, credential_id)
}

fn derive_key(prf_output: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(keytap_core::derive_raw_key(prf_output).unwrap_or_else(|e| {
        die(&format!("key derivation failed: {e}"));
    }))
}

/// Register a new passkey; returns its credential ID so init can rotate the
/// remembered-keys root.
#[cfg(feature = "native-passkey")]
fn register() -> Vec<u8> {
    match keytap_macos::register() {
        keytap_macos::RegistrationOutcome::Success { credential_id } => {
            eprintln!("Passkey registered successfully.");
            credential_id
        }
        keytap_macos::RegistrationOutcome::Error(msg) if msg == "cancelled" => {
            die(&msg);
        }
        keytap_macos::RegistrationOutcome::Error(msg) => {
            eprintln!("Couldn't open native passkey flow: {msg}");
            nearby::register_nearby()
        }
    }
}

#[cfg(not(feature = "native-passkey"))]
fn register() -> Vec<u8> {
    nearby::register_nearby()
}

fn emit_private_key(raw_key: &[u8], format: Format) {
    let priv_format = match format {
        Format::Hex => PrivateKeyFormat::Hex,
        Format::Base64 => PrivateKeyFormat::Base64,
        Format::Age => PrivateKeyFormat::AgeSecretKey,
        Format::Ssh => PrivateKeyFormat::SshPrivateKey,
    };
    match keytap_core::format_private_key(raw_key, priv_format) {
        Ok(bytes) => {
            // SSH PEM already ends in a newline; others are single-line values.
            if matches!(format, Format::Ssh) {
                print!("{}", String::from_utf8(bytes).unwrap());
            } else {
                println!("{}", String::from_utf8(bytes).unwrap());
            }
        }
        Err(e) => die(&format!("format error: {e}")),
    }
}

fn emit_public_key(raw_key: &[u8], format: PublicFormat, name: &str) {
    let pub_format = match format {
        PublicFormat::Hex => PublicKeyFormat::Hex,
        PublicFormat::Base64 => PublicKeyFormat::Base64,
        PublicFormat::Age => PublicKeyFormat::AgeRecipient,
        PublicFormat::Ssh => PublicKeyFormat::SshPublicKey,
    };
    // The name is only meaningful as the SSH key comment; other formats ignore it.
    let comment = matches!(format, PublicFormat::Ssh).then_some(name);
    match keytap_core::format_public_key(raw_key, pub_format, comment) {
        Ok(s) => println!("{s}"),
        Err(e) => die(&format!("format error: {e}")),
    }
}

pub(crate) fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}
