//! Keys that can read a vault, and public keys that can be granted access.
//!
//! A recipient is an age public key. A local identity is the matching age
//! secret key: the one Keytap derives from your passkey, or one from an age
//! identity file.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use age::secrecy::ExposeSecret;
use age::x25519;
use zeroize::{Zeroize, Zeroizing};

use crate::store;
use crate::Passkey;

pub const IDENTITY_ENVIRONMENT: &str = "ENVTAP_IDENTITY";
const MAX_IDENTITY_FILE_SIZE: usize = 64 * 1024;
const REMEMBERED_FILE_NAME: &str = "identity-file";

/// A public key that a vault can be encrypted to.
#[derive(Clone)]
pub struct Recipient(x25519::Recipient);

impl Recipient {
    pub fn new(recipient: x25519::Recipient) -> Self {
        Self(recipient)
    }

    /// Parse `age1…`.
    pub fn parse(text: &str) -> Result<Self, String> {
        x25519::Recipient::from_str(text.trim())
            .map(Self)
            .map_err(|_| "expected an age public key (age1…)".to_owned())
    }

    /// The single spelling Envtap writes into a vault.
    pub fn canonical(&self) -> String {
        self.0.to_string()
    }

    pub fn as_dyn(&self) -> &dyn age::Recipient {
        &self.0
    }
}

impl PartialEq for Recipient {
    fn eq(&self, other: &Self) -> bool {
        self.canonical() == other.canonical()
    }
}

/// A secret key available on this machine.
pub struct LocalIdentity(x25519::Identity);

impl LocalIdentity {
    pub fn new(identity: x25519::Identity) -> Self {
        Self(identity)
    }

    pub fn as_dyn(&self) -> &dyn age::Identity {
        &self.0
    }

    /// The public key to grant.
    pub fn public_key(&self) -> Recipient {
        Recipient(self.0.to_public())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    Explicit(PathBuf),
    Environment,
    Passkey,
    RememberedFile(PathBuf),
}

impl Source {
    pub fn describe(&self) -> String {
        match self {
            Source::Explicit(path) => format!("from {}", path.display()),
            Source::Environment => format!("from ${IDENTITY_ENVIRONMENT}"),
            Source::Passkey => "from your passkey".to_owned(),
            Source::RememberedFile(path) => format!("from {}", path.display()),
        }
    }
}

pub struct Identities {
    pub list: Vec<LocalIdentity>,
    pub source: Source,
}

impl Identities {
    /// The first key's public half, for hints and for creating a vault.
    pub fn public_key(&self) -> Recipient {
        self.list[0].public_key()
    }
}

/// Resolve the identities for one command in priority order: an explicit
/// file, the identity environment variable, the key Keytap remembers for
/// the passkey login, then a remembered identity file.
pub fn resolve(explicit: Option<&Path>, passkey: &dyn Passkey) -> Result<Identities, String> {
    if let Some(path) = explicit {
        return Ok(Identities {
            list: parse_identity_file(path)?,
            source: Source::Explicit(path.to_path_buf()),
        });
    }
    if let Some(value) = std::env::var_os(IDENTITY_ENVIRONMENT) {
        let value = Zeroizing::new(
            value
                .into_string()
                .map_err(|_| format!("{IDENTITY_ENVIRONMENT} is not UTF-8"))?,
        );
        let identity = parse_age_secret(value.trim())
            .map_err(|_| format!("{IDENTITY_ENVIRONMENT} is not an age secret key"))?;
        return Ok(Identities {
            list: vec![LocalIdentity::new(identity)],
            source: Source::Environment,
        });
    }
    if let Some(identity) = passkey.remembered()? {
        return Ok(Identities {
            list: vec![LocalIdentity::new(identity)],
            source: Source::Passkey,
        });
    }
    if let Some(path) = remembered_identity_file()? {
        return Ok(Identities {
            list: parse_identity_file(&path)?,
            source: Source::RememberedFile(path),
        });
    }
    Err("not logged in on this machine; run `envtap login`".to_owned())
}

fn parse_age_secret(text: &str) -> Result<x25519::Identity, String> {
    x25519::Identity::from_str(text.trim()).map_err(|error| error.to_owned())
}

/// Parse an age identity file: one or more `AGE-SECRET-KEY-1…` lines, with
/// `#` comments.
pub fn parse_identity_file(path: &Path) -> Result<Vec<LocalIdentity>, String> {
    let mut raw = read_identity_file(path)?;
    let parsed = parse_identity_text(&raw, path);
    raw.zeroize();
    parsed
}

fn parse_identity_text(raw: &str, path: &Path) -> Result<Vec<LocalIdentity>, String> {
    let mut identities = Vec::new();
    for line in raw.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let identity = parse_age_secret(line)
            .map_err(|_| format!("{} must contain age secret keys", path.display()))?;
        identities.push(LocalIdentity::new(identity));
    }
    if identities.is_empty() {
        return Err(format!("{} contains no identity", path.display()));
    }
    Ok(identities)
}

fn read_identity_file(path: &Path) -> Result<String, String> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if metadata.len() > MAX_IDENTITY_FILE_SIZE as u64 {
        return Err(format!("{} exceeds 64 KiB", path.display()));
    }
    let mut raw = String::with_capacity(metadata.len() as usize);
    file.take(MAX_IDENTITY_FILE_SIZE as u64 + 1)
        .read_to_string(&mut raw)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if raw.len() > MAX_IDENTITY_FILE_SIZE {
        raw.zeroize();
        return Err(format!("{} exceeds 64 KiB", path.display()));
    }
    Ok(raw)
}

fn remembered_file_path() -> PathBuf {
    store::user_state_directory()
        .join("envtap")
        .join(REMEMBERED_FILE_NAME)
}

/// Remember an identity file for future commands. The file itself is never
/// copied; only its absolute path is recorded.
pub fn remember_identity_file(path: &Path) -> Result<PathBuf, String> {
    let absolute = fs::canonicalize(path)
        .map_err(|error| format!("cannot locate {}: {error}", path.display()))?;
    parse_identity_file(&absolute)?;
    let pointer = remembered_file_path();
    let directory = pointer
        .parent()
        .ok_or_else(|| "no state directory".to_owned())?;
    store::create_private_directories(directory)
        .map_err(|error| format!("cannot prepare {}: {error}", directory.display()))?;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&pointer)
        .map_err(|error| format!("cannot write {}: {error}", pointer.display()))?;
    use std::os::unix::ffi::OsStrExt;
    file.write_all(absolute.as_os_str().as_bytes())
        .map_err(|error| format!("cannot write {}: {error}", pointer.display()))?;
    Ok(absolute)
}

pub fn remembered_identity_file() -> Result<Option<PathBuf>, String> {
    let pointer = remembered_file_path();
    match fs::read(&pointer) {
        Ok(bytes) => {
            use std::os::unix::ffi::OsStrExt;
            let path = PathBuf::from(std::ffi::OsStr::from_bytes(&bytes));
            if path.as_os_str().is_empty() {
                return Ok(None);
            }
            Ok(Some(path))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("cannot read {}: {error}", pointer.display())),
    }
}

/// Forget a remembered identity file. Returns whether one was remembered.
pub fn forget_identity_file() -> Result<bool, String> {
    let pointer = remembered_file_path();
    match fs::remove_file(&pointer) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("cannot remove {}: {error}", pointer.display())),
    }
}

/// Encode an age identity for `ENVTAP_IDENTITY` and CI storage.
pub fn age_secret_string(identity: &x25519::Identity) -> Zeroizing<String> {
    Zeroizing::new(identity.to_string().expose_secret().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_age_recipients_canonically() {
        let identity = x25519::Identity::generate();
        let text = identity.to_public().to_string();
        let parsed = Recipient::parse(&format!("  {text}\n")).unwrap();
        assert_eq!(parsed.canonical(), text);
        assert!(Recipient::parse("ssh-ed25519 AAAA").is_err());
        assert!(Recipient::parse("hello").is_err());
    }

    #[test]
    fn identity_files_hold_age_keys_with_comments() {
        let first = x25519::Identity::generate();
        let second = x25519::Identity::generate();
        let text = format!(
            "# created\n{}\n\n{}\n",
            first.to_string().expose_secret(),
            second.to_string().expose_secret()
        );
        let identities = parse_identity_text(&text, Path::new("keys.txt")).unwrap();
        assert_eq!(identities.len(), 2);
        assert_eq!(
            identities[1].public_key().canonical(),
            second.to_public().to_string()
        );
        assert!(parse_identity_text("# nothing\n", Path::new("keys.txt")).is_err());
        assert!(parse_identity_text("garbage\n", Path::new("keys.txt")).is_err());
    }
}
