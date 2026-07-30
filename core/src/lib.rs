use base64::Engine;
use bech32::{Bech32, Hrp};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use thiserror::Error;

mod ed25519;
pub mod encrypt;
mod ssh;

#[derive(Debug, Error)]
pub enum KeytapError {
    #[error("invalid key name: {reason}")]
    InvalidKeyName { reason: String },
    #[error("invalid PRF output length: got {actual}, expected 32")]
    InvalidPrfOutputLength { actual: usize },
    #[error("invalid key material: {reason}")]
    InvalidKeyMaterial { reason: String },
    #[error("internal error: {message}")]
    Internal { message: String },
    /// An age encryption/decryption failure; the message is complete and
    /// already names the failing stage.
    #[error("{message}")]
    Crypto { message: String },
}

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

#[derive(serde::Serialize)]
pub struct RegistrationConfig {
    pub rp_id: String,
    pub user_name: String,
    pub user_id: Vec<u8>,
    pub default_prf_salt: Vec<u8>,
}

#[derive(serde::Serialize)]
pub struct AssertionConfig {
    pub rp_id: String,
    pub key_name: String,
    pub prf_salt: Vec<u8>,
    pub preferred_credential_id: Option<Vec<u8>>,
}

const RP_ID: &str = "keytap.jul.sh";
const REG_NAME: &str = "keytap";
const REG_USER_ID: &[u8] = b"keytap-user";
const HKDF_INFO: &[u8] = b"keytap:key";

pub fn registration_config() -> RegistrationConfig {
    RegistrationConfig {
        rp_id: RP_ID.into(),
        user_name: REG_NAME.into(),
        user_id: REG_USER_ID.to_vec(),
        default_prf_salt: prf_salt_for_name("default").unwrap(),
    }
}

pub fn assertion_config(
    key_name: &str,
    preferred_credential_id: Option<Vec<u8>>,
) -> Result<AssertionConfig, KeytapError> {
    Ok(AssertionConfig {
        rp_id: RP_ID.into(),
        key_name: key_name.into(),
        prf_salt: prf_salt_for_name(key_name)?,
        preferred_credential_id,
    })
}

pub fn prf_salt_for_name(key_name: &str) -> Result<Vec<u8>, KeytapError> {
    validate_key_name(key_name)?;
    Ok(Sha256::digest(format!("keytap:prf:{key_name}")).to_vec())
}

pub fn derive_raw_key(prf_output: &[u8]) -> Result<Vec<u8>, KeytapError> {
    if prf_output.len() != 32 {
        return Err(KeytapError::InvalidPrfOutputLength {
            actual: prf_output.len(),
        });
    }
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(None, prf_output)
        .expand(HKDF_INFO, &mut okm)
        .map_err(|e| KeytapError::Internal {
            message: e.to_string(),
        })?;
    Ok(okm.to_vec())
}

/// Derive the Ed25519 public key for a 32-byte signing seed.
pub fn ed25519_public_key(seed: &[u8]) -> Result<[u8; 32], KeytapError> {
    let seed: &[u8; 32] = seed
        .try_into()
        .map_err(|_| KeytapError::InvalidPrfOutputLength { actual: seed.len() })?;
    Ok(ed25519::public_key(seed).to_bytes())
}

/// `format_private_key`, newline-terminated the way the CLI prints it: the
/// SSH PEM already ends in a newline, every other format is a single line
/// that gets one. Shared by the native binary and the web terminal so the
/// presentation rule exists once.
pub fn format_private_key_display(
    raw_key: &[u8],
    format: PrivateKeyFormat,
) -> Result<Vec<u8>, KeytapError> {
    let mut bytes = format_private_key(raw_key, format)?;
    if format != PrivateKeyFormat::SshPrivateKey {
        bytes.push(b'\n');
    }
    Ok(bytes)
}

/// `format_public_key`, newline-terminated.
pub fn format_public_key_display(
    raw_key: &[u8],
    format: PublicKeyFormat<'_>,
) -> Result<String, KeytapError> {
    let mut s = format_public_key(raw_key, format)?;
    s.push('\n');
    Ok(s)
}

pub fn format_private_key(
    raw_key: &[u8],
    format: PrivateKeyFormat,
) -> Result<Vec<u8>, KeytapError> {
    let key = to_32(raw_key)?;
    match format {
        PrivateKeyFormat::Hex => Ok(hex::encode(key).into_bytes()),
        PrivateKeyFormat::Base64 => Ok(base64::engine::general_purpose::STANDARD
            .encode(key)
            .into_bytes()),
        PrivateKeyFormat::AgeSecretKey => Ok(bech32_encode("age-secret-key-", key)
            .to_uppercase()
            .into_bytes()),
        PrivateKeyFormat::SshPrivateKey => Ok(ssh::private_key_pem(key).into_bytes()),
    }
}

/// Parse the age secret key encoding (`AGE-SECRET-KEY-1…`) back into the raw
/// 32 key bytes — the inverse of `format_private_key(_, AgeSecretKey)`. This
/// is the one encoding accepted from the environment (`$KEYTAP_KEY_<NAME>`):
/// bech32's checksum means a corrupted value fails here instead of silently
/// becoming a different key.
pub fn parse_age_secret_key(s: &str) -> Result<Vec<u8>, KeytapError> {
    let (hrp, data) = bech32::decode(s).map_err(|e| KeytapError::InvalidKeyMaterial {
        reason: e.to_string(),
    })?;
    if hrp.to_lowercase() != "age-secret-key-" {
        return Err(KeytapError::InvalidKeyMaterial {
            reason: format!(
                "prefix is '{}', expected 'age-secret-key-'",
                hrp.to_lowercase()
            ),
        });
    }
    if data.len() != 32 {
        return Err(KeytapError::InvalidKeyMaterial {
            reason: format!("holds {} key bytes, expected 32", data.len()),
        });
    }
    Ok(data)
}

pub fn format_public_key(
    raw_key: &[u8],
    format: PublicKeyFormat<'_>,
) -> Result<String, KeytapError> {
    let key = to_32(raw_key)?;
    match format {
        PublicKeyFormat::Hex => Ok(hex::encode(x25519_public(key))),
        PublicKeyFormat::Base64 => {
            Ok(base64::engine::general_purpose::STANDARD.encode(x25519_public(key)))
        }
        PublicKeyFormat::AgeRecipient => Ok(bech32_encode("age", &x25519_public(key))),
        PublicKeyFormat::Ssh { comment } => Ok(ssh::public_key_line(key, comment)),
    }
}

fn to_32(raw_key: &[u8]) -> Result<&[u8; 32], KeytapError> {
    raw_key.try_into().map_err(|_| KeytapError::Internal {
        message: format!("raw key must be 32 bytes, got {}", raw_key.len()),
    })
}

fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*secret)).as_bytes()
}

fn bech32_encode(hrp: &str, data: &[u8]) -> String {
    bech32::encode::<Bech32>(Hrp::parse(hrp).unwrap(), data).unwrap()
}

fn validate_key_name(name: &str) -> Result<(), KeytapError> {
    if name.is_empty() {
        return Err(KeytapError::InvalidKeyName {
            reason: "key name must not be empty".into(),
        });
    }
    if name.len() > 128 {
        return Err(KeytapError::InvalidKeyName {
            reason: "key name must not exceed 128 characters".into(),
        });
    }
    if !name.is_ascii() {
        return Err(KeytapError::InvalidKeyName {
            reason: "key name must be ASCII-only".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
