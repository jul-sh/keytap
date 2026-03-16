use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

fn config_dir() -> PathBuf {
    dirs::home_dir()
        .expect("could not determine home directory")
        .join(".config/tapkey")
}

pub fn credential_path() -> PathBuf {
    config_dir().join("credential.json")
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredCredential {
    #[serde(rename = "credentialID")]
    #[serde(serialize_with = "ser_base64", deserialize_with = "de_base64")]
    pub credential_id: Vec<u8>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

fn ser_base64<S: Serializer>(data: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(data))
}

fn de_base64<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(d)?;
    base64::engine::general_purpose::STANDARD
        .decode(&s)
        .map_err(serde::de::Error::custom)
}

impl StoredCredential {
    pub fn new(credential_id: Vec<u8>) -> Self {
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        Self {
            credential_id,
            created_at: now,
        }
    }
}

pub fn save(credential: &StoredCredential) -> Result<(), String> {
    let dir = config_dir();
    fs::create_dir_all(&dir).map_err(|e| format!("failed to create config dir: {e}"))?;
    let json =
        serde_json::to_string_pretty(credential).map_err(|e| format!("failed to serialize: {e}"))?;
    let path = credential_path();
    fs::write(&path, json).map_err(|e| format!("failed to write credential: {e}"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("failed to set permissions: {e}"))?;
    Ok(())
}

pub fn load() -> Result<StoredCredential, String> {
    let path = credential_path();
    let data = fs::read_to_string(&path).map_err(|e| format!("failed to read credential: {e}"))?;
    serde_json::from_str(&data).map_err(|e| format!("failed to parse credential: {e}"))
}

pub fn cache_if_needed(credential_id: &[u8]) -> Result<(), String> {
    if let Ok(stored) = load() {
        if stored.credential_id == credential_id {
            return Ok(());
        }
    }
    save(&StoredCredential::new(credential_id.to_vec()))
}
