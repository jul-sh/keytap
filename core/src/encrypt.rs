//! age encryption/decryption over the derived identity — the shared engine
//! behind `keytap encrypt` / `keytap decrypt` on every platform. Streams
//! `Read` → `Write` with no size ceiling; where the bytes come from and go
//! (stdin/stdout, a browser buffer) is the caller's job, as is reading
//! recipient files — they arrive here as (label, contents) pairs so error
//! messages can still name the file.

use crate::{KeytapError, PrivateKeyFormat};
use age::x25519;
use std::io::{Read, Write};
use std::str::FromStr;
use zeroize::Zeroizing;

fn crypto_err(message: String) -> KeytapError {
    KeytapError::Crypto { message }
}

/// The derived age identity for a raw key.
pub fn identity(raw_key: &[u8]) -> Result<x25519::Identity, KeytapError> {
    let secret_key_bytes = Zeroizing::new(
        crate::format_private_key(raw_key, PrivateKeyFormat::AgeSecretKey)
            .map_err(|e| crypto_err(format!("key format error: {e}")))?,
    );
    let secret_key_str = Zeroizing::new(
        String::from_utf8(secret_key_bytes.to_vec())
            .map_err(|e| crypto_err(format!("key format error: {e}")))?,
    );
    x25519::Identity::from_str(&secret_key_str)
        .map_err(|e| crypto_err(format!("invalid age identity: {e}")))
}

/// Collect the recipient set: self (the derived identity, when given), plus
/// parsed recipient strings, plus recipient files as (label, contents).
pub fn recipients(
    self_key: Option<&[u8]>,
    additional_recipients: &[String],
    recipients_files: &[(String, String)],
) -> Result<Vec<Box<dyn age::Recipient + Send>>, KeytapError> {
    let mut recipients: Vec<Box<dyn age::Recipient + Send>> = Vec::new();

    if let Some(raw_key) = self_key {
        recipients.push(Box::new(identity(raw_key)?.to_public()));
    }

    for r in additional_recipients {
        let recipient = x25519::Recipient::from_str(r)
            .map_err(|e| crypto_err(format!("invalid recipient {r}: {e}")))?;
        recipients.push(Box::new(recipient));
    }

    for (label, contents) in recipients_files {
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let recipient = x25519::Recipient::from_str(line)
                .map_err(|e| crypto_err(format!("invalid recipient in {label}: {line}: {e}")))?;
            recipients.push(Box::new(recipient));
        }
    }

    if recipients.is_empty() {
        return Err(crypto_err(
            "no recipients specified (use --to, -R, or remove --no-self)".into(),
        ));
    }
    Ok(recipients)
}

/// Stream the plaintext reader through the age encryptor into `writer`.
/// Chunked copy — no whole-input buffering, so there is no size ceiling.
pub fn encrypt_stream(
    recipients: &[Box<dyn age::Recipient + Send>],
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), KeytapError> {
    let encryptor =
        age::Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref() as &dyn age::Recipient))
            .map_err(|e| crypto_err(format!("failed to create encryptor: {e}")))?;

    let mut age_writer = encryptor
        .wrap_output(writer)
        .map_err(|e| crypto_err(format!("encryption failed: {e}")))?;

    std::io::copy(reader, &mut age_writer)
        .map_err(|e| crypto_err(format!("encryption failed writing output: {e}")))?;
    age_writer
        .finish()
        .map_err(|e| crypto_err(format!("encryption failed finalizing output: {e}")))?;
    Ok(())
}

/// Stream the age reader through the decryptor into `writer`. Chunked — no ceiling.
pub fn decrypt_stream(
    raw_key: &[u8],
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), KeytapError> {
    let identity = identity(raw_key)?;
    let decryptor = age::Decryptor::new(reader)
        .map_err(|e| crypto_err(format!("failed to read age input: {e}")))?;

    let mut age_reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| crypto_err(format!("decryption failed: {e}")))?;

    std::io::copy(&mut age_reader, writer)
        .map_err(|e| crypto_err(format!("decryption failed writing output: {e}")))?;
    Ok(())
}
