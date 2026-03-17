mod auth;

use clap::{Parser, Subcommand, ValueEnum};
use std::io::Write;
use tapkey_core::{PrivateKeyFormat, PublicKeyFormat};

#[derive(Parser)]
#[command(name = "tapkey", version)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the passkey root
    Register,
    /// Derive key material from your passkey
    Derive {
        /// Key name for domain separation
        #[arg(default_value = "default")]
        name: String,
        /// Output format
        #[arg(long, default_value = "hex")]
        format: Format,
    },
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
enum Format {
    Hex,
    Base64,
    Age,
    Raw,
    Ssh,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Cmd::Register => {
            auth::start_registration(Box::new(|outcome| match outcome {
                auth::RegistrationOutcome::Success { .. } => {
                    eprintln!("Passkey registered successfully.");
                    std::process::exit(0);
                }
                auth::RegistrationOutcome::Error(msg) => die(&msg),
            }));
        }
        Cmd::Derive { name, format } => {
            start_assertion(&name, format, false);
        }
        Cmd::PublicKey { name, format } => {
            if matches!(format, Format::Raw) {
                die("--format raw is not supported for public-key");
            }
            start_assertion(&name, format, true);
        }
    }
}

fn start_assertion(name: &str, format: Format, is_public: bool) {
    auth::start_assertion(
        name,
        Box::new(move |outcome| match outcome {
            auth::AssertionOutcome::Success { prf_output, .. } => {
                emit_key(&prf_output, format, is_public);
            }
            auth::AssertionOutcome::Error(msg) => die(&msg),
        }),
    );
}

fn emit_key(prf_output: &[u8], format: Format, is_public: bool) {
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
                std::process::exit(0);
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
                std::process::exit(0);
            }
            Err(e) => die(&format!("format error: {e}")),
        }
    }
}

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}
