//! Keys that can read a vault, and public keys that can be granted access.
//!
//! A recipient is a native age public key or an SSH public key. A local
//! identity is the matching private half: the age key Keytap derives from
//! your passkey, an age identity file, or an SSH private key.

use std::fs;
use std::io::{self, BufReader, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use age::secrecy::{ExposeSecret, SecretString};
use age::x25519;
use base64::Engine as _;
use zeroize::{Zeroize, Zeroizing};

use crate::store;
use crate::Passkey;

pub const IDENTITY_ENVIRONMENT: &str = "ENVTAP_IDENTITY";
const MAX_IDENTITY_FILE_SIZE: usize = 64 * 1024;
const REMEMBERED_FILE_NAME: &str = "identity-file";

/// A public key that a vault can be encrypted to.
#[derive(Clone)]
pub enum Recipient {
    Age(x25519::Recipient),
    Ssh(age::ssh::Recipient),
}

impl Recipient {
    /// Parse `age1…` or `ssh-ed25519 AAAA…` (an SSH key comment is ignored).
    /// Only ed25519 SSH keys are accepted, so the RSA code that age compiles
    /// for its SSH support is never executed.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        if text.starts_with("age1") {
            return x25519::Recipient::from_str(text)
                .map(Recipient::Age)
                .map_err(|_| "not a valid age public key".to_owned());
        }
        if text.starts_with("ssh-") {
            let mut tokens = text.split_whitespace();
            let (Some(kind), Some(key)) = (tokens.next(), tokens.next()) else {
                return Err("an SSH public key needs a type and a key".to_owned());
            };
            let parsed = age::ssh::Recipient::from_str(&format!("{kind} {key}"))
                .map_err(|error| format!("unsupported SSH public key: {error:?}"))?;
            return match parsed {
                age::ssh::Recipient::SshEd25519(..) => Ok(Recipient::Ssh(parsed)),
                age::ssh::Recipient::SshRsa(..) => {
                    Err("ssh-rsa keys are not supported; use an ssh-ed25519 key".to_owned())
                }
            };
        }
        Err("expected an age public key (age1…) or an SSH public key (ssh-ed25519 …)".to_owned())
    }

    /// The single spelling Envtap writes into a vault.
    pub fn canonical(&self) -> String {
        match self {
            Recipient::Age(recipient) => recipient.to_string(),
            Recipient::Ssh(recipient) => recipient.to_string(),
        }
    }

    pub fn as_dyn(&self) -> &dyn age::Recipient {
        match self {
            Recipient::Age(recipient) => recipient,
            Recipient::Ssh(recipient) => recipient,
        }
    }
}

impl PartialEq for Recipient {
    fn eq(&self, other: &Self) -> bool {
        self.canonical() == other.canonical()
    }
}

/// A private key available on this machine.
pub enum LocalIdentity {
    Age(x25519::Identity),
    Ssh {
        identity: Box<dyn age::Identity>,
        public_key: Recipient,
    },
}

impl LocalIdentity {
    pub fn as_dyn(&self) -> &dyn age::Identity {
        match self {
            LocalIdentity::Age(identity) => identity,
            LocalIdentity::Ssh { identity, .. } => identity.as_ref(),
        }
    }

    /// The public key to grant.
    pub fn public_key(&self) -> Recipient {
        match self {
            LocalIdentity::Age(identity) => Recipient::Age(identity.to_public()),
            LocalIdentity::Ssh { public_key, .. } => public_key.clone(),
        }
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
            list: vec![LocalIdentity::Age(identity)],
            source: Source::Environment,
        });
    }
    if let Some(identity) = passkey.remembered()? {
        return Ok(Identities {
            list: vec![LocalIdentity::Age(identity)],
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

/// Parse an age identity file (one or more `AGE-SECRET-KEY-1…` lines) or an
/// OpenSSH private key.
pub fn parse_identity_file(path: &Path) -> Result<Vec<LocalIdentity>, String> {
    let mut raw = read_identity_file(path)?;
    let parsed = parse_identity_text(&raw, path);
    raw.zeroize();
    parsed
}

fn parse_identity_text(raw: &str, path: &Path) -> Result<Vec<LocalIdentity>, String> {
    if raw.contains("-----BEGIN OPENSSH PRIVATE KEY-----") {
        return parse_ssh_identity(raw, path).map(|identity| vec![identity]);
    }
    let mut identities = Vec::new();
    for line in raw.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let identity = parse_age_secret(line).map_err(|_| {
            format!(
                "{} must contain age secret keys or one OpenSSH private key",
                path.display()
            )
        })?;
        identities.push(LocalIdentity::Age(identity));
    }
    if identities.is_empty() {
        return Err(format!("{} contains no identity", path.display()));
    }
    Ok(identities)
}

fn parse_ssh_identity(raw: &str, path: &Path) -> Result<LocalIdentity, String> {
    let public_key = openssh_public_key(raw)
        .map_err(|error| format!("cannot use SSH key {}: {error}", path.display()))?;
    let parsed = age::ssh::Identity::from_buffer(
        BufReader::new(raw.as_bytes()),
        Some(path.display().to_string()),
    )
    .map_err(|error| format!("cannot parse SSH key {}: {error}", path.display()))?;
    let identity: Box<dyn age::Identity> = match parsed {
        age::ssh::Identity::Unencrypted(_) => Box::new(parsed),
        age::ssh::Identity::Encrypted(_) => Box::new(parsed.with_callbacks(PassphrasePrompt)),
        age::ssh::Identity::Unsupported(_) => {
            return Err(format!(
                "{} is an SSH key Envtap cannot use; use an ssh-ed25519 key",
                path.display()
            ))
        }
    };
    Ok(LocalIdentity::Ssh {
        identity,
        public_key,
    })
}

/// The public key embedded, unencrypted, in an OpenSSH private key file.
/// Only ed25519 keys are accepted; see [`Recipient::parse`].
fn openssh_public_key(raw: &str) -> Result<Recipient, String> {
    use base64::engine::general_purpose::STANDARD;

    let body: String = raw
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .map(str::trim)
        .collect();
    let bytes = STANDARD
        .decode(body)
        .map_err(|_| "not an OpenSSH private key".to_owned())?;
    let mut cursor = bytes
        .strip_prefix(b"openssh-key-v1\0")
        .ok_or_else(|| "not an OpenSSH private key".to_owned())?;
    for _ in 0..3 {
        read_ssh_string(&mut cursor)?;
    }
    if read_ssh_u32(&mut cursor)? != 1 {
        return Err("the file must contain exactly one key".to_owned());
    }
    let blob = read_ssh_string(&mut cursor)?;
    let mut inner = blob;
    let key_type = std::str::from_utf8(read_ssh_string(&mut inner)?)
        .map_err(|_| "invalid key type".to_owned())?;
    if key_type != "ssh-ed25519" {
        return Err(format!(
            "it is an {key_type} key, which Envtap does not support; use an ssh-ed25519 key"
        ));
    }
    Recipient::parse(&format!("ssh-ed25519 {}", STANDARD.encode(blob)))
}

fn read_ssh_u32(cursor: &mut &[u8]) -> Result<u32, String> {
    let (head, rest) = cursor
        .split_first_chunk::<4>()
        .ok_or_else(|| "truncated OpenSSH key".to_owned())?;
    *cursor = rest;
    Ok(u32::from_be_bytes(*head))
}

fn read_ssh_string<'a>(cursor: &mut &'a [u8]) -> Result<&'a [u8], String> {
    let length = read_ssh_u32(cursor)? as usize;
    if cursor.len() < length {
        return Err("truncated OpenSSH key".to_owned());
    }
    let (value, rest) = cursor.split_at(length);
    *cursor = rest;
    Ok(value)
}

#[derive(Clone)]
struct PassphrasePrompt;

impl age::Callbacks for PassphrasePrompt {
    fn display_message(&self, message: &str) {
        eprintln!("{message}");
    }

    fn confirm(&self, _message: &str, _yes: &str, _no: Option<&str>) -> Option<bool> {
        None
    }

    fn request_public_string(&self, _description: &str) -> Option<String> {
        None
    }

    fn request_passphrase(&self, description: &str) -> Option<SecretString> {
        if !io::stdin().is_terminal() {
            return None;
        }
        rpassword::prompt_password(format!("{description}: "))
            .ok()
            .map(SecretString::from)
    }
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
    fn parses_age_and_ssh_recipients_canonically() {
        let identity = x25519::Identity::generate();
        let text = identity.to_public().to_string();
        let parsed = Recipient::parse(&format!("  {text}\n")).unwrap();
        assert_eq!(parsed.canonical(), text);

        let ssh = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxK1UiU7rAoLh9Sh7yMOWFhDx4a8Yx7/1oVbrMTyA5F user@host";
        let parsed = Recipient::parse(ssh).unwrap();
        assert_eq!(
            parsed.canonical(),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxK1UiU7rAoLh9Sh7yMOWFhDx4a8Yx7/1oVbrMTyA5F"
        );
        assert!(Recipient::parse("ssh-dss AAAA").is_err());
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
