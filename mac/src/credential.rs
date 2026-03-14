use base64::Engine;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StoredCredential {
    #[serde(
        serialize_with = "serialize_credential_id",
        deserialize_with = "deserialize_credential_id"
    )]
    pub credential_id: Vec<u8>,
    pub created_at: String,
}

fn serialize_credential_id<S: serde::Serializer>(data: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(data))
}

fn deserialize_credential_id<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(d)?;
    base64::engine::general_purpose::STANDARD
        .decode(&s)
        .map_err(serde::de::Error::custom)
}

fn config_dir() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME not set");
    PathBuf::from(home).join(".config/tapkey")
}

fn credential_path() -> PathBuf {
    config_dir().join("credential.json")
}

pub fn credential_path_display() -> String {
    credential_path().display().to_string()
}

pub fn save_credential(credential_id: &[u8]) -> io::Result<()> {
    let dir = config_dir();
    fs::create_dir_all(&dir)?;

    let now = time::OffsetDateTime::now_utc();
    let format = time::format_description::well_known::Iso8601::DEFAULT;
    let created_at = now.format(&format).unwrap();

    let cred = StoredCredential {
        credential_id: credential_id.to_vec(),
        created_at,
    };

    let json = serde_json::to_string_pretty(&cred).unwrap();
    let path = credential_path();
    fs::write(&path, json.as_bytes())?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub fn load_credential() -> Option<StoredCredential> {
    let data = fs::read(credential_path()).ok()?;
    serde_json::from_slice(&data).ok()
}

pub fn cache_credential_id_if_needed(credential_id: &[u8]) -> io::Result<()> {
    if let Some(stored) = load_credential() {
        if stored.credential_id == credential_id {
            return Ok(());
        }
    }
    save_credential(credential_id)
}
