use base64::Engine;
use bech32::{Bech32, Hrp};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::fmt;

mod ed25519;
mod ssh;

#[derive(Debug)]
pub struct InvalidKeyName(&'static str);

impl fmt::Display for InvalidKeyName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid key name: {}", self.0)
    }
}

impl std::error::Error for InvalidKeyName {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateKeyFormat {
    Hex,
    Base64,
    AgeSecretKey,
    SshPrivateKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyFormat<'a> {
    Hex,
    Base64,
    AgeRecipient,
    Ssh { comment: Option<&'a str> },
}

const HKDF_INFO: &[u8] = b"keytap:key";

pub fn prf_salt_for_name(key_name: &str) -> Result<[u8; 32], InvalidKeyName> {
    validate_key_name(key_name)?;
    Ok(Sha256::digest(format!("keytap:prf:{key_name}")).into())
}

pub fn derive_raw_key(prf_output: &[u8; 32]) -> [u8; 32] {
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(None, prf_output)
        .expand(HKDF_INFO, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA-256 output length");
    okm
}

/// `format_private_key`, newline-terminated the way the CLI prints it: the
/// SSH PEM already ends in a newline; every other format gets one.
pub fn format_private_key_display(raw_key: &[u8; 32], format: PrivateKeyFormat) -> Vec<u8> {
    let mut bytes = format_private_key(raw_key, format);
    if format != PrivateKeyFormat::SshPrivateKey {
        bytes.push(b'\n');
    }
    bytes
}

/// `format_public_key`, newline-terminated.
pub fn format_public_key_display(raw_key: &[u8; 32], format: PublicKeyFormat<'_>) -> String {
    let mut s = format_public_key(raw_key, format);
    s.push('\n');
    s
}

pub fn format_private_key(raw_key: &[u8; 32], format: PrivateKeyFormat) -> Vec<u8> {
    match format {
        PrivateKeyFormat::Hex => hex::encode(raw_key).into_bytes(),
        PrivateKeyFormat::Base64 => base64::engine::general_purpose::STANDARD
            .encode(raw_key)
            .into_bytes(),
        PrivateKeyFormat::AgeSecretKey => {
            let mut encoded = bech32_encode("age-secret-key-", raw_key);
            encoded.make_ascii_uppercase();
            encoded.into_bytes()
        }
        PrivateKeyFormat::SshPrivateKey => ssh::private_key_pem(raw_key).into_bytes(),
    }
}

pub fn format_public_key(raw_key: &[u8; 32], format: PublicKeyFormat<'_>) -> String {
    match format {
        PublicKeyFormat::Hex => hex::encode(x25519_public(raw_key)),
        PublicKeyFormat::Base64 => {
            base64::engine::general_purpose::STANDARD.encode(x25519_public(raw_key))
        }
        PublicKeyFormat::AgeRecipient => bech32_encode("age", &x25519_public(raw_key)),
        PublicKeyFormat::Ssh { comment } => ssh::public_key_line(raw_key, comment),
    }
}

fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*secret)).as_bytes()
}

fn bech32_encode(hrp: &str, data: &[u8]) -> String {
    bech32::encode::<Bech32>(Hrp::parse(hrp).unwrap(), data).unwrap()
}

fn validate_key_name(name: &str) -> Result<(), InvalidKeyName> {
    if name.is_empty() {
        return Err(InvalidKeyName("key name must not be empty"));
    }
    if name.len() > 128 {
        return Err(InvalidKeyName("key name must not exceed 128 characters"));
    }
    if !name.is_ascii() {
        return Err(InvalidKeyName("key name must be ASCII-only"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
