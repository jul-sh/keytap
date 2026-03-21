mod encrypt;
mod nearby;

use clap::{Parser, Subcommand, ValueEnum};
use std::io::Write;
use keytap_core::{PrivateKeyFormat, PublicKeyFormat};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "keytap", version)]
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
        #[arg(long, default_value = "hex")]
        format: PublicFormat,
    },

    /// Reveal private key material
    Reveal {
        /// Key name for domain separation
        #[arg(default_value = "default")]
        name: String,

        /// Output format
        #[arg(long, default_value = "hex")]
        format: Format,
    },

    /// Encrypt a file with the derived age identity
    Encrypt {
        /// File to encrypt
        file: String,

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

    /// Decrypt an age-encrypted file with the derived age identity
    Decrypt {
        /// File to decrypt
        file: String,

        /// Key name for domain separation
        #[arg(long, default_value = "default")]
        key: String,
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

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum PublicFormat {
    Hex,
    Base64,
    Age,
    Ssh,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Init => register(),
        Command::Public { ref name, format } => {
            let prf_output = authenticate(name);
            let raw_key = derive_key(&prf_output);
            emit_public_key(&raw_key, format);
        }
        Command::Reveal { ref name, format } => {
            let prf_output = authenticate(name);
            let raw_key = derive_key(&prf_output);
            emit_private_key(&raw_key, format);
        }
        Command::Encrypt { ref file, ref key, ref recipients, ref recipients_file, no_self } => {
            let prf_output = authenticate(key);
            let raw_key = derive_key(&prf_output);
            encrypt::encrypt_file(&raw_key, file, recipients, recipients_file, !no_self);
        }
        Command::Decrypt { ref file, ref key } => {
            let prf_output = authenticate(key);
            let raw_key = derive_key(&prf_output);
            encrypt::decrypt_file(&raw_key, file);
        }
    }
}

/// Authenticate with passkey and return the PRF output.
#[cfg(feature = "native-passkey")]
fn authenticate(name: &str) -> Zeroizing<Vec<u8>> {
    for attempt in 1..=3 {
        match keytap_macos::assert(name) {
            keytap_macos::AssertionOutcome::Success { prf_output, .. } => {
                return Zeroizing::new(prf_output);
            }
            keytap_macos::AssertionOutcome::Error(msg) if msg == "cancelled" => {
                die(&msg);
            }
            keytap_macos::AssertionOutcome::Error(msg) => {
                if attempt < 3 {
                    eprintln!("Native passkey failed (attempt {attempt}/3): {msg}");
                } else {
                    eprintln!("Couldn't open native passkey flow.");
                    return Zeroizing::new(nearby::authenticate_nearby(name));
                }
            }
        }
    }
    unreachable!()
}

#[cfg(not(feature = "native-passkey"))]
fn authenticate(name: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(nearby::authenticate_nearby(name))
}

fn derive_key(prf_output: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(keytap_core::derive_raw_key(prf_output).unwrap_or_else(|e| {
        die(&format!("key derivation failed: {e}"));
    }))
}

#[cfg(feature = "native-passkey")]
fn register() {
    for attempt in 1..=3 {
        match keytap_macos::register() {
            keytap_macos::RegistrationOutcome::Success => {
                eprintln!("Passkey registered successfully.");
                return;
            }
            keytap_macos::RegistrationOutcome::Error(msg) if msg == "cancelled" => {
                die(&msg);
            }
            keytap_macos::RegistrationOutcome::Error(msg) => {
                if attempt < 3 {
                    eprintln!("Native passkey failed (attempt {attempt}/3): {msg}");
                } else {
                    eprintln!("Couldn't open native passkey flow.");
                    nearby::register_nearby();
                    return;
                }
            }
        }
    }
}

#[cfg(not(feature = "native-passkey"))]
fn register() {
    nearby::register_nearby();
}

fn emit_private_key(raw_key: &[u8], format: Format) {
    let priv_format = match format {
        Format::Hex => PrivateKeyFormat::Hex,
        Format::Base64 => PrivateKeyFormat::Base64,
        Format::Age => PrivateKeyFormat::AgeSecretKey,
        Format::Raw => PrivateKeyFormat::Raw,
        Format::Ssh => PrivateKeyFormat::SshPrivateKey,
    };
    match keytap_core::format_private_key(raw_key, priv_format) {
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

fn emit_public_key(raw_key: &[u8], format: PublicFormat) {
    let pub_format = match format {
        PublicFormat::Hex => PublicKeyFormat::Hex,
        PublicFormat::Base64 => PublicKeyFormat::Base64,
        PublicFormat::Age => PublicKeyFormat::AgeRecipient,
        PublicFormat::Ssh => PublicKeyFormat::SshPublicKey,
    };
    match keytap_core::format_public_key(raw_key, pub_format) {
        Ok(s) => println!("{s}"),
        Err(e) => die(&format!("format error: {e}")),
    }
}

pub(crate) fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}
