//! The `tap.env` model and its cryptographic boundary.
//!
//! The file is dotenv-shaped text. Directive lines start with `#:`. The first
//! line names the format and a random vault ID. Each grant line carries a
//! label, a public key, and the vault's data key wrapped to that public key
//! with age. Each variable line holds the value encrypted under the data key
//! with ChaCha20-Poly1305, with the vault ID and the variable name bound as
//! associated data.
//!
//! Comments and blank lines are preserved verbatim, and any line whose
//! content did not change is written back byte for byte, so Git diffs and
//! merges stay line-level. Anyone with write access to the repository can
//! delete lines or replace the whole file; nobody without the data key can
//! alter, move, or forge an individual value undetected.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use base64::Engine as _;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::identity::{LocalIdentity, Recipient};

pub const DEFAULT_FILE_NAME: &str = "tap.env";
pub const FORMAT_VERSION: &str = "v1";
pub const MAX_FILE_SIZE: usize = 16 * 1024 * 1024;
pub const MAX_VALUE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_LABEL_BYTES: usize = 64;
pub const RESERVED_VARIABLE: &str = "ENVTAP_IDENTITY";

const DIRECTIVE: &str = "#:";
const VALUE_PREFIX: &str = "envtap:v1:";
const KEY_WRAP_DOMAIN: &[u8] = b"envtap-key-v1\0";
const VALUE_DOMAIN: &[u8] = b"envtap-value-v1\0";
const KEY_BYTES: usize = 32;
const ID_BYTES: usize = 32;
const TAG_BYTES: usize = 16;
const WRAP_PAYLOAD_BYTES: usize = KEY_WRAP_DOMAIN.len() + KEY_BYTES + ID_BYTES;
const MAX_WRAP_BYTES: usize = 8 * 1024;

/// Failures at the vault boundary. No variant carries a secret value.
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("the file exceeds the 16 MiB size limit")]
    TooLarge,

    #[error("invalid envtap file: {0}")]
    InvalidFile(String),

    #[error("integrity check failed: {0}")]
    Tampered(String),

    #[error("none of your keys is granted access")]
    NotGranted,

    #[error(
        "invalid variable name `{0}`: use letters, digits, and `_`, and do not start with a digit"
    )]
    InvalidVariableName(String),

    #[error("{RESERVED_VARIABLE} is reserved and cannot be stored")]
    ReservedVariable,

    #[error("`{0}` is not set")]
    VariableNotFound(String),

    #[error("{0}")]
    InvalidVariableValue(String),

    #[error("invalid label `{0}`: use 1-64 ASCII letters, digits, `.`, `_`, or `-`, starting with a letter or digit")]
    InvalidLabel(String),

    #[error("`{0}` already names a different key")]
    LabelConflict(String),

    #[error("that key already has access as `{0}`")]
    RecipientAlreadyGranted(String),

    #[error("nobody is granted as `{0}`")]
    LabelNotFound(String),

    #[error("cannot revoke `{0}`: it is the key you are using")]
    CannotRevokeSelf(String),

    #[error("the file grants access to nobody")]
    NoGrants,

    #[error("cryptography failed: {0}")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, VaultError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetOutcome {
    Added,
    Replaced,
    Unchanged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantOutcome {
    Added,
    Unchanged,
}

/// One access grant: a label, a public key, and the data key wrapped to it.
pub struct Grant {
    pub label: String,
    pub recipient: Recipient,
    /// `None` when the data key changed and the wrap must be regenerated.
    wrap: Option<Vec<u8>>,
}

enum Stored {
    Encrypted(String),
    /// The value changed; the ciphertext is generated at render time.
    Pending,
}

enum Line {
    Header,
    Grant(Grant),
    Value { name: String, stored: Stored },
    Verbatim(String),
}

/// The committed form: public metadata and authenticated ciphertext, but no
/// plaintext secret.
pub struct LockedVault {
    id: [u8; ID_BYTES],
    lines: Vec<Line>,
}

struct Entry {
    value: Zeroizing<String>,
}

/// A decrypted and validated vault. Every value was authenticated against
/// its name and the vault ID when this was constructed.
pub struct UnlockedVault {
    id: [u8; ID_BYTES],
    lines: Vec<Line>,
    data_key: Zeroizing<[u8; KEY_BYTES]>,
    granted_as: String,
    entries: BTreeMap<String, Entry>,
}

impl std::fmt::Debug for LockedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockedVault")
            .field("id", &self.id())
            .field(
                "grants",
                &self.grants().map(|g| &g.label).collect::<Vec<_>>(),
            )
            .field("variables", &self.variables().collect::<Vec<_>>())
            .finish()
    }
}

impl std::fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("id", &self.id())
            .field("granted_as", &self.granted_as)
            .field(
                "grants",
                &self.grants().map(|g| &g.label).collect::<Vec<_>>(),
            )
            .field("variables", &self.variables().collect::<Vec<_>>())
            .field("values", &"<redacted>")
            .finish()
    }
}

impl LockedVault {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_FILE_SIZE {
            return Err(VaultError::TooLarge);
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| VaultError::InvalidFile("the file is not UTF-8".into()))?;
        let text = text.replace("\r\n", "\n");
        let mut raw_lines: Vec<&str> = text.split('\n').collect();
        if raw_lines.last() == Some(&"") {
            raw_lines.pop();
        }
        let mut raw_lines = raw_lines.into_iter().enumerate();
        let Some((_, first)) = raw_lines.next() else {
            return Err(VaultError::InvalidFile("the file is empty".into()));
        };
        let id = parse_header(first)?;

        let mut lines = vec![Line::Header];
        let mut names: BTreeSet<String> = BTreeSet::new();
        let mut labels: Vec<String> = Vec::new();
        let mut recipients: Vec<String> = Vec::new();
        for (index, raw) in raw_lines {
            let number = index + 1;
            let line = parse_line(raw, number)?;
            match &line {
                Line::Grant(grant) => {
                    if labels.contains(&grant.label) {
                        return Err(invalid(
                            number,
                            format!("label `{}` appears twice", grant.label),
                        ));
                    }
                    let canonical = grant.recipient.canonical();
                    if recipients.contains(&canonical) {
                        return Err(invalid(number, "the same key is granted twice"));
                    }
                    labels.push(grant.label.clone());
                    recipients.push(canonical);
                }
                Line::Value { name, .. } => {
                    if !names.insert(name.clone()) {
                        return Err(invalid(number, format!("`{name}` is set twice")));
                    }
                }
                Line::Header | Line::Verbatim(_) => {}
            }
            lines.push(line);
        }
        if labels.is_empty() {
            return Err(VaultError::NoGrants);
        }
        Ok(Self { id, lines })
    }

    pub fn id(&self) -> String {
        BASE64.encode(self.id)
    }

    pub fn grants(&self) -> impl Iterator<Item = &Grant> {
        grants_in(&self.lines)
    }

    pub fn variables(&self) -> impl Iterator<Item = &str> {
        variables_in(&self.lines)
    }

    /// Unwrap the data key with the first identity that is granted, then
    /// authenticate every value.
    pub fn unlock(self, identities: &[LocalIdentity]) -> Result<UnlockedVault> {
        let (granted_as, data_key) = self.unwrap_data_key(identities)?;
        let mut entries = BTreeMap::new();
        for line in &self.lines {
            if let Line::Value { name, stored } = line {
                let entry = match stored {
                    Stored::Encrypted(body) => Entry {
                        value: decrypt_value(&data_key, &self.id, name, body)?,
                    },
                    Stored::Pending => unreachable!("parsed vaults have no pending values"),
                };
                entries.insert(name.clone(), entry);
            }
        }
        Ok(UnlockedVault {
            id: self.id,
            lines: self.lines,
            data_key,
            granted_as,
            entries,
        })
    }

    fn unwrap_data_key(
        &self,
        identities: &[LocalIdentity],
    ) -> Result<(String, Zeroizing<[u8; KEY_BYTES]>)> {
        for grant in self.grants() {
            let wrap = grant
                .wrap
                .as_deref()
                .expect("parsed grants carry their wrap");
            let Some(payload) = unwrap_with(wrap, identities)? else {
                continue;
            };
            if payload.len() != WRAP_PAYLOAD_BYTES
                || !payload.starts_with(KEY_WRAP_DOMAIN)
                || !constant_time_eq(&payload[WRAP_PAYLOAD_BYTES - ID_BYTES..], &self.id)
            {
                return Err(VaultError::Tampered(format!(
                    "the key wrapped for `{}` belongs to a different file",
                    grant.label
                )));
            }
            let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
            key.copy_from_slice(&payload[KEY_WRAP_DOMAIN.len()..KEY_WRAP_DOMAIN.len() + KEY_BYTES]);
            return Ok((grant.label.clone(), key));
        }
        Err(VaultError::NotGranted)
    }
}

impl UnlockedVault {
    /// A new vault granting access to one key.
    pub fn create(owner_label: &str, owner: &Recipient) -> Result<Self> {
        validate_label(owner_label)?;
        let id = random_bytes::<ID_BYTES>()?;
        let data_key = Zeroizing::new(random_bytes::<KEY_BYTES>()?);
        let wrap = wrap_key(owner, &data_key, &id)?;
        Ok(Self {
            id,
            lines: vec![
                Line::Header,
                Line::Grant(Grant {
                    label: owner_label.to_owned(),
                    recipient: owner.clone(),
                    wrap: Some(wrap),
                }),
                Line::Verbatim(String::new()),
            ],
            data_key,
            granted_as: owner_label.to_owned(),
            entries: BTreeMap::new(),
        })
    }

    pub fn id(&self) -> String {
        BASE64.encode(self.id)
    }

    /// The label under which the unlocking key is granted.
    pub fn granted_as(&self) -> &str {
        &self.granted_as
    }

    pub fn grants(&self) -> impl Iterator<Item = &Grant> {
        grants_in(&self.lines)
    }

    pub fn variables(&self) -> impl Iterator<Item = &str> {
        variables_in(&self.lines)
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries.get(name).map(|entry| entry.value.as_str())
    }

    /// Every value, in file order.
    pub fn values(&self) -> impl Iterator<Item = (&str, &str)> {
        self.variables()
            .map(|name| (name, self.entries[name].value.as_str()))
    }

    pub fn set(&mut self, name: &str, value: &str) -> Result<SetOutcome> {
        validate_variable_name(name)?;
        validate_value(value)?;
        match self.entries.get_mut(name) {
            Some(entry) if entry.value.as_str() == value => Ok(SetOutcome::Unchanged),
            Some(entry) => {
                entry.value = Zeroizing::new(value.to_owned());
                for line in &mut self.lines {
                    if let Line::Value {
                        name: existing,
                        stored,
                    } = line
                    {
                        if existing == name {
                            *stored = Stored::Pending;
                        }
                    }
                }
                Ok(SetOutcome::Replaced)
            }
            None => {
                self.entries.insert(
                    name.to_owned(),
                    Entry {
                        value: Zeroizing::new(value.to_owned()),
                    },
                );
                let position = self.insertion_index(name);
                self.lines.insert(
                    position,
                    Line::Value {
                        name: name.to_owned(),
                        stored: Stored::Pending,
                    },
                );
                Ok(SetOutcome::Added)
            }
        }
    }

    /// Keep a sorted file sorted; otherwise append after the last value.
    fn insertion_index(&self, name: &str) -> usize {
        let mut last_value = None;
        for (index, line) in self.lines.iter().enumerate() {
            if let Line::Value { name: existing, .. } = line {
                if existing.as_str() > name {
                    return index;
                }
                last_value = Some(index);
            }
        }
        match last_value {
            Some(index) => index + 1,
            None => self.lines.len(),
        }
    }

    pub fn unset(&mut self, name: &str) -> Result<()> {
        validate_variable_name(name)?;
        self.entries
            .remove(name)
            .ok_or_else(|| VaultError::VariableNotFound(name.to_owned()))?;
        self.lines
            .retain(|line| !matches!(line, Line::Value { name: existing, .. } if existing == name));
        Ok(())
    }

    /// Wrap the current data key to another key. Values are untouched.
    pub fn grant(&mut self, label: &str, recipient: &Recipient) -> Result<GrantOutcome> {
        validate_label(label)?;
        if let Some(existing) = self.grants().find(|grant| grant.label == label) {
            return if existing.recipient == *recipient {
                Ok(GrantOutcome::Unchanged)
            } else {
                Err(VaultError::LabelConflict(label.to_owned()))
            };
        }
        if let Some(existing) = self.grants().find(|grant| grant.recipient == *recipient) {
            return Err(VaultError::RecipientAlreadyGranted(existing.label.clone()));
        }
        let wrap = wrap_key(recipient, &self.data_key, &self.id)?;
        let position = self
            .lines
            .iter()
            .rposition(|line| matches!(line, Line::Grant(_)))
            .map_or(1, |index| index + 1);
        self.lines.insert(
            position,
            Line::Grant(Grant {
                label: label.to_owned(),
                recipient: recipient.clone(),
                wrap: Some(wrap),
            }),
        );
        Ok(GrantOutcome::Added)
    }

    /// Remove a grant and move every value to a fresh data key, so the
    /// revoked key cannot read future revisions.
    pub fn revoke(&mut self, label: &str) -> Result<()> {
        self.remove_grant(label)?;
        self.rotate()
    }

    pub(crate) fn remove_grant(&mut self, label: &str) -> Result<()> {
        if label == self.granted_as {
            return Err(VaultError::CannotRevokeSelf(label.to_owned()));
        }
        let position = self
            .lines
            .iter()
            .position(|line| matches!(line, Line::Grant(grant) if grant.label == label))
            .ok_or_else(|| VaultError::LabelNotFound(label.to_owned()))?;
        self.lines.remove(position);
        Ok(())
    }

    /// Re-encrypt every value under a fresh data key and re-wrap it for
    /// every grant.
    pub fn rotate(&mut self) -> Result<()> {
        let key = random_bytes::<KEY_BYTES>()?;
        self.rekey(&key);
        Ok(())
    }

    pub(crate) fn rekey(&mut self, key: &[u8; KEY_BYTES]) {
        self.data_key.copy_from_slice(key);
        for line in &mut self.lines {
            match line {
                Line::Grant(grant) => grant.wrap = None,
                Line::Value { stored, .. } => *stored = Stored::Pending,
                Line::Header | Line::Verbatim(_) => {}
            }
        }
    }

    pub(crate) fn data_key(&self) -> &[u8; KEY_BYTES] {
        &self.data_key
    }

    /// Produce the complete file. Unchanged lines are reproduced exactly;
    /// changed values and stale wraps are regenerated and then kept, so a
    /// second render is byte-identical.
    pub fn render(&mut self) -> Result<Vec<u8>> {
        let Self {
            id,
            lines,
            data_key,
            entries,
            ..
        } = self;
        let mut out = String::new();
        for line in lines.iter_mut() {
            match line {
                Line::Header => {
                    out.push_str(DIRECTIVE);
                    out.push_str(" envtap ");
                    out.push_str(FORMAT_VERSION);
                    out.push(' ');
                    out.push_str(&BASE64.encode(*id));
                }
                Line::Grant(grant) => {
                    if grant.wrap.is_none() {
                        grant.wrap = Some(wrap_key(&grant.recipient, data_key, id)?);
                    }
                    out.push_str(DIRECTIVE);
                    out.push_str(" grant ");
                    out.push_str(&grant.label);
                    out.push(' ');
                    out.push_str(&grant.recipient.canonical());
                    out.push(' ');
                    out.push_str(&BASE64.encode(grant.wrap.as_deref().unwrap_or_default()));
                }
                Line::Value { name, stored } => {
                    if matches!(stored, Stored::Pending) {
                        let entry = &entries[name.as_str()];
                        *stored =
                            Stored::Encrypted(encrypt_value(data_key, id, name, &entry.value)?);
                    }
                    out.push_str(name);
                    out.push('=');
                    match stored {
                        Stored::Encrypted(body) => {
                            out.push_str(VALUE_PREFIX);
                            out.push_str(body);
                        }
                        Stored::Pending => unreachable!("pending values were rendered"),
                    }
                }
                Line::Verbatim(text) => out.push_str(text),
            }
            out.push('\n');
        }
        if out.len() > MAX_FILE_SIZE {
            return Err(VaultError::TooLarge);
        }
        Ok(out.into_bytes())
    }
}

fn grants_in(lines: &[Line]) -> impl Iterator<Item = &Grant> {
    lines.iter().filter_map(|line| match line {
        Line::Grant(grant) => Some(grant),
        _ => None,
    })
}

fn variables_in(lines: &[Line]) -> impl Iterator<Item = &str> {
    lines.iter().filter_map(|line| match line {
        Line::Value { name, .. } => Some(name.as_str()),
        _ => None,
    })
}

fn invalid(number: usize, message: impl Into<String>) -> VaultError {
    VaultError::InvalidFile(format!("line {number}: {}", message.into()))
}

fn parse_header(raw: &str) -> Result<[u8; ID_BYTES]> {
    let tokens: Vec<&str> = raw.split_whitespace().collect();
    let [directive, "envtap", version, id] = tokens[..] else {
        return Err(invalid(1, "expected `#: envtap v1 <id>` on the first line"));
    };
    if directive != DIRECTIVE {
        return Err(invalid(1, "expected `#: envtap v1 <id>` on the first line"));
    }
    if version != FORMAT_VERSION {
        return Err(invalid(
            1,
            format!("format `{version}` is not supported by this Envtap"),
        ));
    }
    decode_id(id).ok_or_else(|| invalid(1, "the vault ID is not 32 canonical base64url bytes"))
}

fn decode_id(text: &str) -> Option<[u8; ID_BYTES]> {
    let bytes = BASE64.decode(text).ok()?;
    let id: [u8; ID_BYTES] = bytes.try_into().ok()?;
    (BASE64.encode(id) == text).then_some(id)
}

fn parse_line(raw: &str, number: usize) -> Result<Line> {
    if raw.starts_with(DIRECTIVE) {
        return parse_directive(raw, number);
    }
    if raw.trim().is_empty() || raw.trim_start().starts_with('#') {
        return Ok(Line::Verbatim(raw.to_owned()));
    }
    let Some((name, rest)) = raw.split_once('=') else {
        return Err(invalid(number, "expected NAME=value"));
    };
    validate_variable_name(name).map_err(|error| invalid(number, error.to_string()))?;
    let Some(body) = rest.strip_prefix(VALUE_PREFIX) else {
        return Err(invalid(
            number,
            format!("`{name}` is not encrypted; every value is `{VALUE_PREFIX}…`"),
        ));
    };
    let decoded = BASE64
        .decode(body)
        .map_err(|_| invalid(number, format!("`{name}` is not valid base64url")))?;
    if decoded.len() < NONCE_LEN + TAG_BYTES {
        return Err(invalid(number, format!("`{name}` is truncated")));
    }
    let stored = Stored::Encrypted(body.to_owned());
    Ok(Line::Value {
        name: name.to_owned(),
        stored,
    })
}

fn parse_directive(raw: &str, number: usize) -> Result<Line> {
    let tokens: Vec<&str> = raw.split_whitespace().collect();
    match tokens.get(1).copied() {
        Some("grant") => {}
        Some("envtap") => return Err(invalid(number, "a second header line")),
        Some(other) => return Err(invalid(number, format!("unknown directive `{other}`"))),
        None => return Err(invalid(number, "empty directive")),
    }
    if tokens.len() < 5 {
        return Err(invalid(
            number,
            "expected `#: grant <label> <public key> <wrapped key>`",
        ));
    }
    let label = tokens[2];
    validate_label(label).map_err(|error| invalid(number, error.to_string()))?;
    let recipient_text = tokens[3..tokens.len() - 1].join(" ");
    let recipient = Recipient::parse(&recipient_text).map_err(|error| invalid(number, error))?;
    if recipient.canonical() != recipient_text {
        return Err(invalid(
            number,
            format!("the public key for `{label}` is not in canonical form"),
        ));
    }
    let wrap = BASE64.decode(tokens[tokens.len() - 1]).map_err(|_| {
        invalid(
            number,
            format!("the wrapped key for `{label}` is not base64url"),
        )
    })?;
    if wrap.is_empty() || wrap.len() > MAX_WRAP_BYTES {
        return Err(invalid(
            number,
            format!("the wrapped key for `{label}` has an invalid length"),
        ));
    }
    Ok(Line::Grant(Grant {
        label: label.to_owned(),
        recipient,
        wrap: Some(wrap),
    }))
}

pub fn validate_variable_name(name: &str) -> Result<()> {
    if name == RESERVED_VARIABLE {
        return Err(VaultError::ReservedVariable);
    }
    let mut bytes = name.bytes();
    let valid_first = bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic());
    if !valid_first || !bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric()) {
        return Err(VaultError::InvalidVariableName(name.to_owned()));
    }
    Ok(())
}

pub fn validate_label(label: &str) -> Result<()> {
    let mut bytes = label.bytes();
    let valid_first = bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric());
    if label.len() > MAX_LABEL_BYTES
        || !valid_first
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(VaultError::InvalidLabel(label.to_owned()));
    }
    Ok(())
}

fn validate_value(value: &str) -> Result<()> {
    if value.len() > MAX_VALUE_BYTES {
        return Err(VaultError::InvalidVariableValue(
            "values cannot exceed 4 MiB".into(),
        ));
    }
    if value.contains('\0') {
        return Err(VaultError::InvalidVariableValue(
            "values cannot contain NUL".into(),
        ));
    }
    Ok(())
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0_u8; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| VaultError::Crypto("the system random generator failed".into()))?;
    Ok(bytes)
}

fn value_aad(id: &[u8; ID_BYTES], name: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(VALUE_DOMAIN.len() + ID_BYTES + 1 + name.len());
    aad.extend_from_slice(VALUE_DOMAIN);
    aad.extend_from_slice(id);
    aad.push(0);
    aad.extend_from_slice(name.as_bytes());
    aad
}

fn aead_key(data_key: &[u8; KEY_BYTES]) -> Result<LessSafeKey> {
    UnboundKey::new(&CHACHA20_POLY1305, data_key)
        .map(LessSafeKey::new)
        .map_err(|_| VaultError::Crypto("the data key is invalid".into()))
}

fn encrypt_value(
    data_key: &[u8; KEY_BYTES],
    id: &[u8; ID_BYTES],
    name: &str,
    value: &str,
) -> Result<String> {
    let nonce = random_bytes::<NONCE_LEN>()?;
    let mut buffer = Zeroizing::new(value.as_bytes().to_vec());
    aead_key(data_key)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(value_aad(id, name)),
            &mut *buffer,
        )
        .map_err(|_| VaultError::Crypto(format!("could not encrypt `{name}`")))?;
    let mut out = Vec::with_capacity(NONCE_LEN + buffer.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buffer);
    Ok(BASE64.encode(out))
}

fn decrypt_value(
    data_key: &[u8; KEY_BYTES],
    id: &[u8; ID_BYTES],
    name: &str,
    body: &str,
) -> Result<Zeroizing<String>> {
    let bytes = BASE64
        .decode(body)
        .map_err(|_| VaultError::Tampered(format!("`{name}` is not valid base64url")))?;
    if bytes.len() < NONCE_LEN + TAG_BYTES {
        return Err(VaultError::Tampered(format!("`{name}` is truncated")));
    }
    let (nonce, ciphertext) = bytes.split_at(NONCE_LEN);
    let nonce = Nonce::try_assume_unique_for_key(nonce)
        .map_err(|_| VaultError::Tampered(format!("`{name}` has an invalid nonce")))?;
    let mut buffer = Zeroizing::new(ciphertext.to_vec());
    let plaintext = aead_key(data_key)?
        .open_in_place(nonce, Aad::from(value_aad(id, name)), &mut buffer)
        .map_err(|_| {
            VaultError::Tampered(format!(
                "`{name}` does not authenticate; it was altered or moved"
            ))
        })?;
    let text = std::str::from_utf8(plaintext)
        .map_err(|_| VaultError::Tampered(format!("`{name}` is not UTF-8")))?;
    Ok(Zeroizing::new(text.to_owned()))
}

fn wrap_key(
    recipient: &Recipient,
    data_key: &[u8; KEY_BYTES],
    id: &[u8; ID_BYTES],
) -> Result<Vec<u8>> {
    let mut payload = Zeroizing::new(Vec::with_capacity(WRAP_PAYLOAD_BYTES));
    payload.extend_from_slice(KEY_WRAP_DOMAIN);
    payload.extend_from_slice(data_key);
    payload.extend_from_slice(id);
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient.as_dyn()))
        .map_err(|error| VaultError::Crypto(error.to_string()))?;
    let mut out = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut out)
        .map_err(|error| VaultError::Crypto(error.to_string()))?;
    writer
        .write_all(&payload)
        .and_then(|_| writer.finish().map(drop))
        .map_err(|error| VaultError::Crypto(error.to_string()))?;
    Ok(out)
}

/// `Ok(None)` when no identity matches the wrap; `Err` when one does but
/// the wrap is corrupt or the identity itself cannot be used.
fn unwrap_with(wrap: &[u8], identities: &[LocalIdentity]) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let decryptor = age::Decryptor::new(wrap).map_err(|error| {
        VaultError::Tampered(format!("a wrapped key is not an age file: {error}"))
    })?;
    if decryptor.is_scrypt() {
        return Err(VaultError::Tampered(
            "a wrapped key uses a passphrase instead of a public key".into(),
        ));
    }
    let reader = match decryptor.decrypt(identities.iter().map(LocalIdentity::as_dyn)) {
        Ok(reader) => reader,
        Err(age::DecryptError::NoMatchingKeys) => return Ok(None),
        Err(age::DecryptError::KeyDecryptionFailed) => {
            return Err(VaultError::Crypto(
                "the SSH key could not be decrypted; run interactively to enter its passphrase or use an unencrypted key".into(),
            ))
        }
        Err(error) => {
            return Err(VaultError::Tampered(format!(
                "a wrapped key does not authenticate: {error}"
            )))
        }
    };
    let mut payload = Zeroizing::new(Vec::new());
    reader
        .take(MAX_WRAP_BYTES as u64)
        .read_to_end(&mut payload)
        .map_err(|error| VaultError::Tampered(format!("a wrapped key is corrupt: {error}")))?;
    Ok(Some(payload))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |acc, (l, r)| acc | (l ^ r))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::x25519;

    fn identity() -> (LocalIdentity, Recipient) {
        let identity = x25519::Identity::generate();
        let recipient = Recipient::Age(identity.to_public());
        (LocalIdentity::Age(identity), recipient)
    }

    fn text(bytes: &[u8]) -> String {
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[test]
    fn round_trips_and_preserves_unchanged_lines() {
        let (owner, owner_key) = identity();
        let mut vault = UnlockedVault::create("owner", &owner_key).unwrap();
        assert_eq!(vault.set("B_VALUE", "second").unwrap(), SetOutcome::Added);
        assert_eq!(vault.set("A_VALUE", "first").unwrap(), SetOutcome::Added);
        let first = vault.render().unwrap();
        let rendered = text(&first);
        let lines: Vec<&str> = rendered.lines().collect();
        assert!(lines[0].starts_with("#: envtap v1 "));
        assert!(lines[1].starts_with("#: grant owner age1"));
        assert_eq!(lines[2], "");
        assert!(lines[3].starts_with("A_VALUE=envtap:v1:"));
        assert!(lines[4].starts_with("B_VALUE=envtap:v1:"));
        assert_eq!(lines.len(), 5);
        assert!(!rendered.contains("first") && !rendered.contains("second"));

        let mut reopened = LockedVault::parse(&first)
            .unwrap()
            .unlock(std::slice::from_ref(&owner))
            .unwrap();
        assert_eq!(reopened.granted_as(), "owner");
        assert_eq!(reopened.get("A_VALUE"), Some("first"));
        assert_eq!(
            reopened.set("A_VALUE", "first").unwrap(),
            SetOutcome::Unchanged
        );
        assert_eq!(reopened.render().unwrap(), first);

        assert_eq!(
            reopened.set("B_VALUE", "changed").unwrap(),
            SetOutcome::Replaced
        );
        let second = text(&reopened.render().unwrap());
        let changed: Vec<(&str, &str)> = rendered
            .lines()
            .zip(second.lines())
            .filter(|(before, after)| before != after)
            .collect();
        assert_eq!(changed.len(), 1);
        assert!(changed[0].1.starts_with("B_VALUE="));
    }

    #[test]
    fn values_are_bound_to_their_name_and_file() {
        let (owner, owner_key) = identity();
        let mut vault = UnlockedVault::create("owner", &owner_key).unwrap();
        vault.set("ONE", "1").unwrap();
        vault.set("TWO", "2").unwrap();
        let rendered = text(&vault.render().unwrap());
        let one = rendered.lines().find(|l| l.starts_with("ONE=")).unwrap();
        let two = rendered.lines().find(|l| l.starts_with("TWO=")).unwrap();

        let swapped = rendered
            .replace(one, "ONE=SWAP")
            .replace(two, &format!("TWO={}", &one[4..]))
            .replace("ONE=SWAP", &format!("ONE={}", &two[4..]));
        let error = LockedVault::parse(swapped.as_bytes())
            .unwrap()
            .unlock(std::slice::from_ref(&owner))
            .unwrap_err();
        assert!(matches!(error, VaultError::Tampered(_)), "{error}");

        let mut other = UnlockedVault::create("owner", &owner_key).unwrap();
        other.set("ONE", "x").unwrap();
        let other_text = text(&other.render().unwrap());
        let grant = rendered.lines().nth(1).unwrap();
        let transplanted = other_text
            .lines()
            .enumerate()
            .map(|(i, l)| if i == 1 { grant } else { l })
            .collect::<Vec<_>>()
            .join("\n");
        let error = LockedVault::parse(transplanted.as_bytes())
            .unwrap()
            .unlock(std::slice::from_ref(&owner))
            .unwrap_err();
        assert!(matches!(error, VaultError::Tampered(_)), "{error}");
    }

    #[test]
    fn grant_revoke_and_rotate() {
        let (owner, owner_key) = identity();
        let (sam, sam_key) = identity();
        let (eve, eve_key) = identity();
        let mut vault = UnlockedVault::create("owner", &owner_key).unwrap();
        vault.set("TOKEN", "t").unwrap();
        assert_eq!(vault.grant("sam", &sam_key).unwrap(), GrantOutcome::Added);
        assert_eq!(
            vault.grant("sam", &sam_key).unwrap(),
            GrantOutcome::Unchanged
        );
        assert!(matches!(
            vault.grant("sam", &eve_key),
            Err(VaultError::LabelConflict(_))
        ));
        assert!(matches!(
            vault.grant("other", &sam_key),
            Err(VaultError::RecipientAlreadyGranted(_))
        ));
        let before = vault.render().unwrap();
        let sam_view = LockedVault::parse(&before)
            .unwrap()
            .unlock(std::slice::from_ref(&sam))
            .unwrap();
        assert_eq!(sam_view.granted_as(), "sam");
        assert_eq!(sam_view.get("TOKEN"), Some("t"));
        assert!(matches!(
            LockedVault::parse(&before)
                .unwrap()
                .unlock(std::slice::from_ref(&eve)),
            Err(VaultError::NotGranted)
        ));

        assert!(matches!(
            vault.revoke("owner"),
            Err(VaultError::CannotRevokeSelf(_))
        ));
        assert!(matches!(
            vault.revoke("nobody"),
            Err(VaultError::LabelNotFound(_))
        ));
        vault.revoke("sam").unwrap();
        let after = vault.render().unwrap();
        assert!(matches!(
            LockedVault::parse(&after)
                .unwrap()
                .unlock(std::slice::from_ref(&sam)),
            Err(VaultError::NotGranted)
        ));
        let token_before = text(&before)
            .lines()
            .find(|l| l.starts_with("TOKEN="))
            .unwrap()
            .to_owned();
        let token_after = text(&after)
            .lines()
            .find(|l| l.starts_with("TOKEN="))
            .unwrap()
            .to_owned();
        assert_ne!(token_before, token_after, "revoke must rotate");
        assert_eq!(
            LockedVault::parse(&after)
                .unwrap()
                .unlock(std::slice::from_ref(&owner))
                .unwrap()
                .get("TOKEN"),
            Some("t")
        );

        let key_before = *vault.data_key();
        vault.rotate().unwrap();
        assert_ne!(key_before, *vault.data_key());
        let rotated = vault.render().unwrap();
        assert_ne!(rotated, after);
        assert_eq!(
            LockedVault::parse(&rotated)
                .unwrap()
                .unlock(std::slice::from_ref(&owner))
                .unwrap()
                .get("TOKEN"),
            Some("t")
        );
    }

    #[test]
    fn rejects_malformed_files() {
        let (owner, owner_key) = identity();
        let mut vault = UnlockedVault::create("owner", &owner_key).unwrap();
        vault.set("A", "1").unwrap();
        let good = text(&vault.render().unwrap());
        let duplicate = good.lines().find(|l| l.starts_with("A=")).unwrap();
        let cases = [
            ("", "empty"),
            ("A=1\n", "first line"),
            ("#: envtap v2 abc\n", "not supported"),
            (&good.replace("#: grant", "#: give"), "unknown directive"),
            (&format!("{good}{duplicate}\n"), "set twice"),
            (&format!("{good}noequals\n"), "NAME=value"),
            (&format!("{good}ENVTAP_IDENTITY=x\n"), "reserved"),
            (
                &good.lines().skip(2).collect::<Vec<_>>().join("\n"),
                "first line",
            ),
        ];
        for (input, expected) in cases {
            let error = LockedVault::parse(input.as_bytes())
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "{input:?}: {error}");
        }
        let without_grants = good
            .lines()
            .filter(|l| !l.starts_with("#: grant"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(matches!(
            LockedVault::parse(without_grants.as_bytes()),
            Err(VaultError::NoGrants)
        ));
        let _ = owner;
    }

    #[test]
    fn crlf_and_comments_are_tolerated_but_plaintext_is_not() {
        let (owner, owner_key) = identity();
        let mut vault = UnlockedVault::create("owner", &owner_key).unwrap();
        vault.set("A", "1").unwrap();
        let rendered = text(&vault.render().unwrap());
        let edited = format!("{rendered}# a comment\n\n").replace('\n', "\r\n");
        let mut parsed = LockedVault::parse(edited.as_bytes())
            .unwrap()
            .unlock(std::slice::from_ref(&owner))
            .unwrap();
        assert_eq!(parsed.get("A"), Some("1"));
        let out = text(&parsed.render().unwrap());
        assert!(out.ends_with("# a comment\n\n"));
        assert!(!out.contains('\r'));

        let error = LockedVault::parse(format!("{rendered}B=plain\n").as_bytes()).unwrap_err();
        assert!(error.to_string().contains("not encrypted"), "{error}");
    }

    #[test]
    fn validates_names_and_labels() {
        for valid in ["A", "_A", "database_url", "A1_B2", "envtap_identity"] {
            assert!(validate_variable_name(valid).is_ok());
        }
        for invalid in ["", "1A", "A-B", "A.B", "A=B", "ENVTAP_IDENTITY"] {
            assert!(validate_variable_name(invalid).is_err());
        }
        for valid in ["owner", "github-actions", "ci.prod_1", "9"] {
            assert!(validate_label(valid).is_ok());
        }
        for invalid in ["", " leading", "a/b", "sam\u{202e}owner", &"x".repeat(65)] {
            assert!(validate_label(invalid).is_err());
        }
    }
}
