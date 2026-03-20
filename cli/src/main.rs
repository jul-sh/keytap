mod nearby;

use clap::{Parser, Subcommand, ValueEnum};
use std::io::Write;
use tapkey_core::{PrivateKeyFormat, PublicKeyFormat};

#[derive(Parser)]
#[command(name = "tapkey", version)]
struct Cli {
    /// Create the passkey (only needed once)
    #[arg(long)]
    init: bool,

    #[command(subcommand)]
    command: Option<Cmd>,

    /// Key name for domain separation
    #[arg(default_value = "default", conflicts_with = "init")]
    name: Option<String>,

    /// Output format
    #[arg(long, default_value = "hex", conflicts_with = "init")]
    format: Format,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show the public key for a derived key
    PublicKey {
        /// Key name for domain separation
        #[arg(default_value = "default")]
        name: String,
        /// Output format
        #[arg(long, default_value = "age")]
        format: Format,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum Format {
    Hex,
    Base64,
    Age,
    Raw,
    Ssh,
}

fn main() {
    let cli = Cli::parse();

    if cli.init {
        register();
    } else if let Some(Cmd::PublicKey { name, format }) = cli.command {
        if matches!(format, Format::Raw) {
            die("--format raw is not supported for public-key");
        }
        derive(&name, format, true);
    } else {
        let name = cli.name.as_deref().unwrap_or("default");
        derive(name, cli.format, false);
    }
}

#[cfg(feature = "native-passkey")]
fn register() {
    match tapkey_macos::register() {
        tapkey_macos::RegistrationOutcome::Success => {
            eprintln!("Passkey registered successfully.");
        }
        tapkey_macos::RegistrationOutcome::Error(msg) if msg == "cancelled" => {
            die(&msg);
        }
        tapkey_macos::RegistrationOutcome::Error(msg) => {
            eprintln!("Native passkey failed: {msg}");
            eprintln!("Falling back to QR code flow…");
            nearby::start_nearby_flow("register", "default", Format::Hex, false);
        }
    }
}

#[cfg(not(feature = "native-passkey"))]
fn register() {
    nearby::start_nearby_flow("register", "default", Format::Hex, false);
}

#[cfg(feature = "native-passkey")]
fn derive(name: &str, format: Format, is_public: bool) {
    match tapkey_macos::assert(name) {
        tapkey_macos::AssertionOutcome::Success { prf_output, .. } => {
            emit_key(&prf_output, format, is_public);
        }
        tapkey_macos::AssertionOutcome::Error(msg) if msg == "cancelled" => {
            die(&msg);
        }
        tapkey_macos::AssertionOutcome::Error(msg) => {
            eprintln!("Native passkey failed: {msg}");
            eprintln!("Falling back to QR code flow…");
            nearby::start_nearby_flow("assert", name, format, is_public);
        }
    }
}

#[cfg(not(feature = "native-passkey"))]
fn derive(name: &str, format: Format, is_public: bool) {
    nearby::start_nearby_flow("assert", name, format, is_public);
}

pub(crate) fn emit_key(prf_output: &[u8], format: Format, is_public: bool) {
    let raw_key = match tapkey_core::derive_raw_key(prf_output) {
        Ok(k) => k,
        Err(e) => die(&format!("key derivation failed: {e}")),
    };

    if is_public {
        let pub_format = match format {
            Format::Hex => PublicKeyFormat::Hex,
            Format::Base64 => PublicKeyFormat::Base64,
            Format::Age => PublicKeyFormat::AgeRecipient,
            Format::Ssh => PublicKeyFormat::SshPublicKey,
            Format::Raw => die("--format raw is not supported for public-key"),
        };
        match tapkey_core::format_public_key(&raw_key, pub_format) {
            Ok(s) => {
                println!("{s}");
            }
            Err(e) => die(&format!("format error: {e}")),
        }
    } else {
        let priv_format = match format {
            Format::Hex => PrivateKeyFormat::Hex,
            Format::Base64 => PrivateKeyFormat::Base64,
            Format::Age => PrivateKeyFormat::AgeSecretKey,
            Format::Raw => PrivateKeyFormat::Raw,
            Format::Ssh => PrivateKeyFormat::SshPrivateKey,
        };
        match tapkey_core::format_private_key(&raw_key, priv_format) {
            Ok(bytes) => {
                if matches!(format, Format::Raw) {
                    std::io::stdout().write_all(&bytes).unwrap();
                } else if matches!(format, Format::Ssh) {
                    print!("{}", String::from_utf8(bytes).unwrap());
                } else {
                    println!("{}", String::from_utf8(bytes).unwrap());
                }
            }
            Err(e) => die(&format!("format error: {e}")),
        }
    }
}

pub(crate) fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}
