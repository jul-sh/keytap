use base64::Engine;
use bech32::{Bech32, Hrp};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use thiserror::Error;

mod ssh;

#[derive(Debug, Error)]
pub enum TapkeyError {
    #[error("invalid key name: {reason}")]
    InvalidKeyName { reason: String },
    #[error("invalid PRF output length: got {actual}, expected 32")]
    InvalidPrfOutputLength { actual: usize },
    #[error("unsupported format: {reason}")]
    UnsupportedFormat { reason: String },
    #[error("internal error: {message}")]
    Internal { message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateKeyFormat { Hex, Base64, AgeSecretKey, Raw, SshPrivateKey }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyFormat { Hex, Base64, AgeRecipient, SshPublicKey }

pub struct RegistrationConfig {
    pub rp_id: String,
    pub user_name: String,
    pub user_id: Vec<u8>,
    pub default_prf_salt: Vec<u8>,
}

pub struct AssertionConfig {
    pub rp_id: String,
    pub key_name: String,
    pub prf_salt: Vec<u8>,
    pub preferred_credential_id: Option<Vec<u8>>,
}

const RP_ID: &str = "tapkey.jul.sh";
const REG_NAME: &str = "tapkey";
const REG_USER_ID: &[u8] = b"tapkey-user";
const HKDF_INFO: &[u8] = b"tapkey:key";

pub fn registration_config() -> RegistrationConfig {
    RegistrationConfig {
        rp_id: RP_ID.into(),
        user_name: REG_NAME.into(),
        user_id: REG_USER_ID.to_vec(),
        default_prf_salt: prf_salt_for_name("default").unwrap(),
    }
}

pub fn assertion_config(key_name: &str, preferred_credential_id: Option<Vec<u8>>) -> Result<AssertionConfig, TapkeyError> {
    validate_key_name(key_name)?;
    Ok(AssertionConfig {
        rp_id: RP_ID.into(),
        key_name: key_name.into(),
        prf_salt: prf_salt_for_name(key_name)?,
        preferred_credential_id,
    })
}

pub fn prf_salt_for_name(key_name: &str) -> Result<Vec<u8>, TapkeyError> {
    validate_key_name(key_name)?;
    Ok(Sha256::digest(format!("tapkey:prf:{key_name}")).to_vec())
}

pub fn derive_raw_key(prf_output: &[u8]) -> Result<Vec<u8>, TapkeyError> {
    if prf_output.len() != 32 {
        return Err(TapkeyError::InvalidPrfOutputLength { actual: prf_output.len() });
    }
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(None, prf_output)
        .expand(HKDF_INFO, &mut okm)
        .map_err(|e| TapkeyError::Internal { message: e.to_string() })?;
    Ok(okm.to_vec())
}

pub fn format_private_key(raw_key: &[u8], format: PrivateKeyFormat) -> Result<Vec<u8>, TapkeyError> {
    let key = to_32(raw_key)?;
    match format {
        PrivateKeyFormat::Hex => Ok(hex::encode(key).into_bytes()),
        PrivateKeyFormat::Base64 => Ok(base64::engine::general_purpose::STANDARD.encode(key).into_bytes()),
        PrivateKeyFormat::AgeSecretKey => Ok(bech32_encode("age-secret-key-", key).to_uppercase().into_bytes()),
        PrivateKeyFormat::Raw => Ok(key.to_vec()),
        PrivateKeyFormat::SshPrivateKey => Ok(ssh::private_key_pem(key).into_bytes()),
    }
}

pub fn format_public_key(raw_key: &[u8], format: PublicKeyFormat) -> Result<String, TapkeyError> {
    let key = to_32(raw_key)?;
    match format {
        PublicKeyFormat::SshPublicKey => Ok(ssh::public_key_line(key)),
        _ => {
            let pub_bytes = x25519_public(key);
            match format {
                PublicKeyFormat::Hex => Ok(hex::encode(pub_bytes)),
                PublicKeyFormat::Base64 => Ok(base64::engine::general_purpose::STANDARD.encode(pub_bytes)),
                PublicKeyFormat::AgeRecipient => Ok(bech32_encode("age", &pub_bytes)),
                PublicKeyFormat::SshPublicKey => unreachable!(),
            }
        }
    }
}

fn to_32(raw_key: &[u8]) -> Result<&[u8; 32], TapkeyError> {
    raw_key.try_into().map_err(|_| TapkeyError::Internal {
        message: format!("raw key must be 32 bytes, got {}", raw_key.len()),
    })
}

fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*secret)).as_bytes()
}

fn bech32_encode(hrp: &str, data: &[u8]) -> String {
    bech32::encode::<Bech32>(Hrp::parse(hrp).unwrap(), data).unwrap()
}

fn validate_key_name(name: &str) -> Result<(), TapkeyError> {
    if name.is_empty() {
        return Err(TapkeyError::InvalidKeyName { reason: "key name must not be empty".into() });
    }
    if name.len() > 128 {
        return Err(TapkeyError::InvalidKeyName { reason: "key name must not exceed 128 characters".into() });
    }
    if !name.is_ascii() {
        return Err(TapkeyError::InvalidKeyName { reason: "key name must be ASCII-only".into() });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
