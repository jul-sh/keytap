//! `keytap encrypt` / `keytap decrypt`: pure stdin→stdout filters over the
//! derived age identity. Payload never touches a path keytap chooses; where
//! bytes come from and go is the shell's job (`<`, `>`, pipes). The old
//! multi-file batch mode existed to amortize one ceremony across many files;
//! `keytap remember` made that redundant, so v6 removed it.

use age::x25519;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::str::FromStr;
use zeroize::Zeroizing;

/// Encrypt stdin to stdout with the derived age identity (plus optional
/// additional recipients). Streamed and chunked; no size ceiling.
pub fn encrypt(
    raw_key: &[u8],
    additional_recipients: &[String],
    recipients_files: &[String],
    include_self: bool,
) {
    let recipients = build_recipients(raw_key, additional_recipients, recipients_files, include_self);
    let mut reader = BufReader::new(io::stdin());
    let mut writer = BufWriter::new(io::stdout());
    encrypt_stream(&recipients, &mut reader, &mut writer);
    writer
        .flush()
        .unwrap_or_else(|e| crate::die(&format!("encryption failed flushing stdout: {e}")));
}

/// Decrypt age input from stdin to stdout using the derived age identity.
/// Streamed and chunked; no size ceiling.
pub fn decrypt(raw_key: &[u8]) {
    let identity = identity_from_raw_key(raw_key);
    let mut reader = BufReader::new(io::stdin());
    let mut writer = BufWriter::new(io::stdout());
    decrypt_stream(&identity, &mut reader, &mut writer);
    writer
        .flush()
        .unwrap_or_else(|e| crate::die(&format!("decryption failed flushing stdout: {e}")));
}

/// Stream the plaintext reader through the age encryptor into `writer`.
/// Chunked copy — no whole-file buffering, so there is no size ceiling.
fn encrypt_stream(
    recipients: &[Box<dyn age::Recipient + Send>],
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) {
    let encryptor = age::Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref() as &dyn age::Recipient))
        .unwrap_or_else(|e| crate::die(&format!("failed to create encryptor: {e}")));

    let mut age_writer = encryptor
        .wrap_output(writer)
        .unwrap_or_else(|e| crate::die(&format!("encryption failed: {e}")));

    io::copy(reader, &mut age_writer)
        .unwrap_or_else(|e| crate::die(&format!("encryption failed writing output: {e}")));
    age_writer
        .finish()
        .unwrap_or_else(|e| crate::die(&format!("encryption failed finalizing output: {e}")));
}

/// Stream the age reader through the decryptor into `writer`. Chunked — no ceiling.
fn decrypt_stream(identity: &x25519::Identity, reader: &mut dyn Read, writer: &mut dyn Write) {
    let decryptor = age::Decryptor::new(reader)
        .unwrap_or_else(|e| crate::die(&format!("failed to read age input: {e}")));

    let mut age_reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .unwrap_or_else(|e| crate::die(&format!("decryption failed: {e}")));

    io::copy(&mut age_reader, writer)
        .unwrap_or_else(|e| crate::die(&format!("decryption failed writing output: {e}")));
}

/// Collect the recipient set: self (derived identity) plus any `--to` / `-R`.
fn build_recipients(
    raw_key: &[u8],
    additional_recipients: &[String],
    recipients_files: &[String],
    include_self: bool,
) -> Vec<Box<dyn age::Recipient + Send>> {
    let mut recipients: Vec<Box<dyn age::Recipient + Send>> = Vec::new();

    if include_self {
        recipients.push(Box::new(identity_from_raw_key(raw_key).to_public()));
    }

    for r in additional_recipients {
        let recipient = x25519::Recipient::from_str(r)
            .unwrap_or_else(|e| crate::die(&format!("invalid recipient {r}: {e}")));
        recipients.push(Box::new(recipient));
    }

    for file in recipients_files {
        let contents = std::fs::read_to_string(file)
            .unwrap_or_else(|e| crate::die(&format!("failed to read recipients file {file}: {e}")));
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let recipient = x25519::Recipient::from_str(line)
                .unwrap_or_else(|e| crate::die(&format!("invalid recipient in {file}: {line}: {e}")));
            recipients.push(Box::new(recipient));
        }
    }

    if recipients.is_empty() {
        crate::die("no recipients specified (use --to, -R, or remove --no-self)");
    }
    recipients
}

fn identity_from_raw_key(raw_key: &[u8]) -> x25519::Identity {
    let secret_key_bytes = Zeroizing::new(
        keytap_core::format_private_key(raw_key, keytap_core::PrivateKeyFormat::AgeSecretKey)
            .unwrap_or_else(|e| crate::die(&format!("key format error: {e}"))),
    );
    let secret_key_str = Zeroizing::new(
        String::from_utf8(secret_key_bytes.to_vec())
            .unwrap_or_else(|e| crate::die(&format!("key format error: {e}"))),
    );
    x25519::Identity::from_str(&secret_key_str)
        .unwrap_or_else(|e| crate::die(&format!("invalid age identity: {e}")))
}
