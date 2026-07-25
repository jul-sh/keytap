//! Human-paired identity for nearby passkey ceremonies.
//!
//! A nearby WebAuthn assertion asks the passkey PRF for two independent
//! outputs in one prompt: the named key output and a fixed identity seed. The
//! page derives an Ed25519 key from the latter and signs the exact nearby
//! result. A short authentication string authenticates the first channel
//! before this module pins the public identity and credential ID. A later
//! nearby flow must match both and carry a valid, fresh signature.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use crate::nearby_sas::ConfirmedComparison;

const FORMAT: &str = "keytap-nearby-identity-v2";
const PRF_SALT_CONTEXT: &[u8] = b"keytap:nearby-identity-prf:v1";
const PROOF_DOMAIN: &[u8] = b"keytap:nearby-identity-proof:v2\0";

enum PairingState {
    FirstUse,
    Credential {
        credential_id: Vec<u8>,
        expected: Vec<u8>,
    },
}

pub enum Anchor {
    Pairing(PairingAnchor),
    Pinned(PinnedAnchor),
}

pub struct PairingAnchor {
    path: PathBuf,
    state: PairingState,
}

pub struct PinnedAnchor {
    path: PathBuf,
    expected: Vec<u8>,
    credential_id: Vec<u8>,
    public_key: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Revision {
    Missing,
    Present(Vec<u8>),
}

/// An exact identity-file snapshot used to make the identity generation the
/// authority for remembered-key lookup.
pub struct RememberAuthority {
    path: PathBuf,
    expected: Vec<u8>,
    credential_id: Vec<u8>,
}

/// A snapshot taken before an init ceremony. Consuming it is the only way to
/// publish the new credential anchor, and publication fails if another
/// process changed the identity in the meantime.
pub struct PendingInit {
    path: PathBuf,
    expected: Revision,
}

#[derive(Clone, Copy)]
pub enum InitMode {
    Create,
    Replace,
}

/// Proof that the credential anchor was committed before init is acknowledged.
pub struct PersistedInit;

pub enum PairingConstraint<'a> {
    AnyPasskey,
    Credential { credential_id: &'a [u8] },
}

pub struct Proof {
    pub credential_id: Vec<u8>,
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

pub struct ProofContext<'a> {
    pub binding: ProofBinding<'a>,
    pub challenge: &'a [u8],
    pub prf_output: &'a [u8; 32],
    pub key_name: &'a str,
}

#[derive(Clone, Copy)]
pub enum ProofBinding<'a> {
    BootstrapSas {
        confirmation: &'a ConfirmedComparison,
    },
    PinnedSession {
        digest: &'a [u8; 32],
    },
}

#[derive(Debug)]
pub enum VerificationError {
    IdentityMismatch,
    InvalidProof,
    Store(String),
    DurabilityUnknown(String),
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IdentityMismatch => write!(
                f,
                "the nearby passkey does not match the identity first trusted on this machine"
            ),
            Self::InvalidProof => write!(f, "the phone returned an invalid passkey identity proof"),
            Self::Store(message) => {
                write!(f, "could not store the nearby passkey identity: {message}")
            }
            Self::DurabilityUnknown(message) => write!(
                f,
                "the nearby passkey identity was published, but its durability is unknown: {message}"
            ),
        }
    }
}

/// Failure to commit a newly registered credential anchor. Publication and
/// durable publication are deliberately separate states: only the latter may
/// be acknowledged as a successful init.
#[derive(Debug)]
pub enum InitCommitError {
    NotPublished(String),
    PublishedButNotDurable(String),
}

#[derive(Serialize, Deserialize)]
struct StoredFile {
    format: String,
    identity: StoredIdentity,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum StoredIdentity {
    Credential {
        #[serde(rename = "credentialId")]
        credential_id: String,
    },
    Ed25519 {
        #[serde(rename = "credentialId")]
        credential_id: String,
        #[serde(rename = "publicKey")]
        public_key: String,
    },
}

impl Anchor {
    pub fn load() -> Result<Self, String> {
        let path = default_path()?;
        Self::load_from(path)
    }

    fn load_from(path: PathBuf) -> Result<Self, String> {
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::Pairing(PairingAnchor {
                    path,
                    state: PairingState::FirstUse,
                }))
            }
            Err(error) => return Err(format!("reading {}: {error}", path.display())),
        };
        let stored = parse_stored_file(&path, &bytes)?;
        match stored.identity {
            StoredIdentity::Credential { credential_id } => {
                let credential_id = decode_bounded(&credential_id, "credential ID", 1, 1024)
                    .map_err(|error| format!("{}: {error}", path.display()))?;
                Ok(Self::Pairing(PairingAnchor {
                    path,
                    state: PairingState::Credential {
                        credential_id,
                        expected: bytes,
                    },
                }))
            }
            StoredIdentity::Ed25519 {
                credential_id,
                public_key,
            } => {
                let credential_id = decode_bounded(&credential_id, "credential ID", 1, 1024)
                    .map_err(|error| format!("{}: {error}", path.display()))?;
                let public_key = decode_fixed::<32>(&public_key, "public key")
                    .map_err(|error| format!("{}: {error}", path.display()))?;
                VerifyingKey::from_bytes(&public_key).map_err(|_| {
                    format!("{} contains an invalid Ed25519 public key", path.display())
                })?;
                Ok(Self::Pinned(PinnedAnchor {
                    path,
                    expected: bytes,
                    credential_id,
                    public_key,
                }))
            }
        }
    }
}

fn parse_stored_file(path: &Path, bytes: &[u8]) -> Result<StoredFile, String> {
    let stored: StoredFile = serde_json::from_slice(bytes)
        .map_err(|_| format!("{} is not a valid nearby identity file", path.display()))?;
    if stored.format != FORMAT {
        return Err(format!(
            "{} has an unknown nearby identity format",
            path.display()
        ));
    }
    Ok(stored)
}

impl PairingAnchor {
    pub fn constraint(&self) -> PairingConstraint<'_> {
        match &self.state {
            PairingState::FirstUse => PairingConstraint::AnyPasskey,
            PairingState::Credential { credential_id, .. } => {
                PairingConstraint::Credential { credential_id }
            }
        }
    }

    /// This method is intentionally available only on a pairing anchor. Its
    /// caller must first complete the local SAS comparison represented by the
    /// `BootstrapSas` proof binding.
    pub fn verify_and_pin_after_sas(
        &self,
        proof: &Proof,
        context: &ProofContext<'_>,
    ) -> Result<(), VerificationError> {
        if !matches!(context.binding, ProofBinding::BootstrapSas { .. }) {
            return Err(VerificationError::InvalidProof);
        }
        match &self.state {
            PairingState::Credential { credential_id, .. }
                if *credential_id != proof.credential_id =>
            {
                return Err(VerificationError::IdentityMismatch)
            }
            PairingState::FirstUse | PairingState::Credential { .. } => {}
        }
        verify_proof(proof, context)?;
        let bytes = verified_pin_bytes(proof).map_err(VerificationError::Store)?;
        let _lock = IdentityLock::acquire(&self.path).map_err(VerificationError::Store)?;
        let current = read_revision(&self.path).map_err(|error| {
            VerificationError::Store(format!("reading {}: {error}", self.path.display()))
        })?;
        match (&self.state, current) {
            (PairingState::FirstUse, Revision::Missing) => {
                match write_private_new(&self.path, &bytes).map_err(verification_publish_error)? {
                    NewFile::Created => Ok(()),
                    NewFile::AlreadyExists => Err(VerificationError::IdentityMismatch),
                }
            }
            (PairingState::Credential { expected, .. }, Revision::Present(current))
                if current == *expected =>
            {
                write_private_replace(&self.path, &bytes).map_err(verification_publish_error)?;
                Ok(())
            }
            (PairingState::FirstUse | PairingState::Credential { .. }, _) => {
                Err(VerificationError::IdentityMismatch)
            }
        }
    }
}

fn verification_publish_error(error: PublishError) -> VerificationError {
    match error {
        PublishError::BeforePublication(message) => VerificationError::Store(message),
        PublishError::PublishedButNotDurable(message) => {
            VerificationError::DurabilityUnknown(message)
        }
    }
}

impl PinnedAnchor {
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    pub fn verify(
        &self,
        proof: &Proof,
        context: &ProofContext<'_>,
    ) -> Result<(), VerificationError> {
        if !matches!(context.binding, ProofBinding::PinnedSession { .. }) {
            return Err(VerificationError::InvalidProof);
        }
        if self.credential_id != proof.credential_id || self.public_key != proof.public_key {
            return Err(VerificationError::IdentityMismatch);
        }
        verify_proof(proof, context)?;

        // Force-init and assertion may overlap. The proof authenticates the
        // snapshot sent in this ceremony, but only this final compare under
        // the writer lock makes that snapshot current at acceptance time.
        let _lock = IdentityLock::acquire(&self.path).map_err(VerificationError::Store)?;
        let current = read_revision(&self.path).map_err(|error| {
            VerificationError::Store(format!("reading {}: {error}", self.path.display()))
        })?;
        match current {
            Revision::Present(bytes) if bytes == self.expected => Ok(()),
            Revision::Missing | Revision::Present(_) => Err(VerificationError::IdentityMismatch),
        }
    }
}

fn verify_proof(proof: &Proof, context: &ProofContext<'_>) -> Result<(), VerificationError> {
    let key =
        VerifyingKey::from_bytes(&proof.public_key).map_err(|_| VerificationError::InvalidProof)?;
    let signature = Signature::from_bytes(&proof.signature);
    key.verify_strict(&proof_message(proof, context), &signature)
        .map_err(|_| VerificationError::InvalidProof)
}

fn verified_pin_bytes(proof: &Proof) -> Result<Vec<u8>, String> {
    let stored = StoredFile {
        format: FORMAT.to_string(),
        identity: StoredIdentity::Ed25519 {
            credential_id: URL_SAFE_NO_PAD.encode(&proof.credential_id),
            public_key: URL_SAFE_NO_PAD.encode(proof.public_key),
        },
    };
    serde_json::to_vec_pretty(&stored).map_err(|error| error.to_string())
}

pub fn proof_message(proof: &Proof, context: &ProofContext<'_>) -> Vec<u8> {
    let binding = match context.binding {
        ProofBinding::BootstrapSas { confirmation } => confirmation.binding_digest(),
        ProofBinding::PinnedSession { digest } => digest,
    };
    let mut message = Vec::with_capacity(
        PROOF_DOMAIN.len()
            + 1
            + binding.len()
            + context.challenge.len()
            + proof.credential_id.len()
            + context.prf_output.len()
            + context.key_name.len()
            + proof.public_key.len()
            + 24,
    );
    message.extend_from_slice(PROOF_DOMAIN);
    message.push(match context.binding {
        ProofBinding::BootstrapSas { .. } => 0,
        ProofBinding::PinnedSession { .. } => 1,
    });
    append_field(&mut message, binding);
    append_field(&mut message, context.challenge);
    append_field(&mut message, &proof.credential_id);
    append_field(&mut message, context.prf_output);
    append_field(&mut message, context.key_name.as_bytes());
    append_field(&mut message, &proof.public_key);
    message
}

fn append_field(message: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("nearby proof fields fit in u32");
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(value);
}

fn decode_bounded(
    value: &str,
    label: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>, String> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| format!("invalid {label} encoding"))?;
    if decoded.len() < minimum || decoded.len() > maximum {
        return Err(format!("invalid {label} length"));
    }
    Ok(decoded)
}

fn decode_fixed<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    decode_bounded(value, label, N, N)?
        .try_into()
        .map_err(|_| format!("invalid {label} length"))
}

fn default_path() -> Result<PathBuf, String> {
    let state_home = std::env::var_os("XDG_STATE_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(|home| PathBuf::from(home).join(".local/state"))
        })
        .ok_or_else(|| {
            "can't locate a state directory (neither $XDG_STATE_HOME nor $HOME is set)".to_string()
        })?;
    Ok(state_home.join("keytap").join("nearby-identity.json"))
}

/// The second PRF input used by nearby flows to derive a stable signing
/// identity from the same passkey approval as the requested named key.
pub fn prf_salt() -> [u8; 32] {
    Sha256::digest(PRF_SALT_CONTEXT).into()
}

/// Snapshot the identity generation that remembered-key lookup must obey.
/// Without an identity file, remembered entries are deliberately unavailable.
pub fn remember_authority() -> Result<RememberAuthority, String> {
    let path = default_path()?;
    remember_authority_at(path)
}

pub(crate) fn remember_authority_at(path: PathBuf) -> Result<RememberAuthority, String> {
    let expected = read_revision(&path)
        .map_err(|error| format!("reading nearby identity at {}: {error}", path.display()))?;
    let Revision::Present(bytes) = expected else {
        return Err(format!(
            "no nearby identity is stored at {}",
            path.display()
        ));
    };
    let stored = parse_stored_file(&path, &bytes)?;
    let encoded = match stored.identity {
        StoredIdentity::Credential { credential_id } => credential_id,
        StoredIdentity::Ed25519 {
            credential_id,
            public_key,
        } => {
            let public_key = decode_fixed::<32>(&public_key, "public key")
                .map_err(|error| format!("{}: {error}", path.display()))?;
            VerifyingKey::from_bytes(&public_key).map_err(|_| {
                format!("{} contains an invalid Ed25519 public key", path.display())
            })?;
            credential_id
        }
    };
    let credential_id = decode_bounded(&encoded, "credential ID", 1, 1024)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(RememberAuthority {
        path,
        expected: bytes,
        credential_id,
    })
}

impl RememberAuthority {
    /// The credential whose root namespace is authoritative.
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// Re-read the exact identity revision after a candidate lookup/store.
    /// A concurrent init therefore turns the operation into a fail-closed
    /// miss/rejection instead of serving or acknowledging the old root.
    pub fn revalidate(&self) -> Result<bool, String> {
        read_revision(&self.path)
            .map(|revision| matches!(revision, Revision::Present(bytes) if bytes == self.expected))
            .map_err(|error| format!("reading {}: {error}", self.path.display()))
    }
}

/// Snapshot the identity revision before starting WebAuthn. Even a forced init
/// may replace only this exact revision; a concurrent pairing or init wins
/// instead of being silently overwritten.
pub fn prepare_init(mode: InitMode) -> Result<PendingInit, String> {
    let path = default_path()?;
    prepare_init_at(path, mode)
}

pub(crate) fn prepare_init_at(path: PathBuf, mode: InitMode) -> Result<PendingInit, String> {
    let expected = read_revision(&path)
        .map_err(|error| format!("reading nearby identity at {}: {error}", path.display()))?;
    if matches!((&mode, &expected), (InitMode::Create, Revision::Present(_))) {
        return Err(format!(
            "a nearby passkey identity is already stored at {}; pass --force to replace it",
            path.display()
        ));
    }
    Ok(PendingInit { path, expected })
}

impl PendingInit {
    pub fn commit(self, credential_id: &[u8]) -> Result<PersistedInit, InitCommitError> {
        if credential_id.is_empty() || credential_id.len() > 1024 {
            return Err(InitCommitError::NotPublished(
                "the new passkey returned an invalid credential ID length".to_string(),
            ));
        }
        let bytes = init_credential_bytes(credential_id).map_err(InitCommitError::NotPublished)?;
        let _lock = IdentityLock::acquire(&self.path).map_err(InitCommitError::NotPublished)?;
        let current = read_revision(&self.path).map_err(|error| {
            InitCommitError::NotPublished(format!("reading {}: {error}", self.path.display()))
        })?;
        if current != self.expected {
            return Err(InitCommitError::NotPublished(format!(
                "{} changed while the passkey ceremony was in progress; refusing to overwrite it",
                self.path.display()
            )));
        }
        match self.expected {
            Revision::Missing => {
                match write_private_new(&self.path, &bytes).map_err(InitCommitError::from)? {
                    NewFile::Created => {}
                    NewFile::AlreadyExists => {
                        return Err(InitCommitError::NotPublished(format!(
                            "{} changed while the passkey ceremony was in progress; refusing to overwrite it",
                            self.path.display()
                        )))
                    }
                }
            }
            Revision::Present(_) => {
                write_private_replace(&self.path, &bytes).map_err(InitCommitError::from)?
            }
        }
        Ok(PersistedInit)
    }
}

impl From<PublishError> for InitCommitError {
    fn from(error: PublishError) -> Self {
        match error {
            PublishError::BeforePublication(message) => Self::NotPublished(message),
            PublishError::PublishedButNotDurable(message) => Self::PublishedButNotDurable(message),
        }
    }
}

fn init_credential_bytes(credential_id: &[u8]) -> Result<Vec<u8>, String> {
    let stored = StoredFile {
        format: FORMAT.to_string(),
        identity: StoredIdentity::Credential {
            credential_id: URL_SAFE_NO_PAD.encode(credential_id),
        },
    };
    serde_json::to_vec_pretty(&stored).map_err(|error| error.to_string())
}

fn read_revision(path: &Path) -> std::io::Result<Revision> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Revision::Present(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Revision::Missing),
        Err(error) => Err(error),
    }
}

enum NewFile {
    Created,
    AlreadyExists,
}

#[derive(Debug)]
enum PublishError {
    BeforePublication(String),
    PublishedButNotDurable(String),
}

struct IdentityLock {
    #[cfg(unix)]
    _file: std::fs::File,
    #[cfg(not(unix))]
    path: PathBuf,
}

impl IdentityLock {
    fn acquire(identity_path: &Path) -> Result<Self, String> {
        let path = identity_path.with_extension("json.lock");
        if let Some(parent) = path.parent() {
            make_private_dir(parent)
                .map_err(|error| format!("creating {}: {error}", parent.display()))?;
        }

        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::OpenOptionsExt;
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(&path)
                .map_err(|error| format!("opening identity lock {}: {error}", path.display()))?;
            // The file is permanent; the kernel releases this advisory lock
            // automatically if the process exits, so a crash cannot strand a
            // sentinel that blocks future pairings.
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result != 0 {
                let error = std::io::Error::last_os_error();
                return Err(if error.kind() == std::io::ErrorKind::WouldBlock {
                    format!(
                        "another nearby identity update is in progress at {}",
                        path.display()
                    )
                } else {
                    format!("locking {}: {error}", identity_path.display())
                });
            }
            Ok(Self { _file: file })
        }

        #[cfg(not(unix))]
        {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            options.open(&path).map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    format!(
                        "another nearby identity update is in progress at {}",
                        path.display()
                    )
                } else {
                    format!("locking {}: {error}", identity_path.display())
                }
            })?;
            Ok(Self { path })
        }
    }
}

#[cfg(not(unix))]
impl Drop for IdentityLock {
    fn drop(&mut self) {
        std::fs::remove_file(&self.path).ok();
    }
}

/// Publish a fully-written file without ever replacing an identity another
/// concurrent first-use flow already won. A hard link is the atomic
/// create-if-absent operation; the temporary link is removed afterward.
fn write_private_new(path: &Path, bytes: &[u8]) -> Result<NewFile, PublishError> {
    write_private_new_with_sync(path, bytes, sync_parent)
}

fn write_private_new_with_sync(
    path: &Path,
    bytes: &[u8],
    sync: impl FnOnce(&Path) -> std::io::Result<()>,
) -> Result<NewFile, PublishError> {
    if let Some(parent) = path.parent() {
        make_private_dir(parent).map_err(|error| {
            PublishError::BeforePublication(format!("creating {}: {error}", parent.display()))
        })?;
    }
    let temporary = temporary_path(path).map_err(PublishError::BeforePublication)?;
    if let Err(error) = write_private_file(&temporary, bytes) {
        std::fs::remove_file(&temporary).ok();
        return Err(PublishError::BeforePublication(format!(
            "writing {}: {error}",
            temporary.display()
        )));
    }
    let published = match std::fs::hard_link(&temporary, path) {
        Ok(()) => Ok(NewFile::Created),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Ok(NewFile::AlreadyExists)
        }
        Err(error) => Err(PublishError::BeforePublication(format!(
            "creating {}: {error}",
            path.display()
        ))),
    };
    // Once the hard link succeeds, cleanup failure must not turn a committed
    // pin into a reported failure. A later run may remove an orphaned temp.
    std::fs::remove_file(&temporary).ok();
    if matches!(&published, Ok(NewFile::Created)) {
        require_durable_publication(path, sync(path))?;
    }
    published
}

fn write_private_replace(path: &Path, bytes: &[u8]) -> Result<(), PublishError> {
    write_private_replace_with_sync(path, bytes, sync_parent)
}

fn write_private_replace_with_sync(
    path: &Path,
    bytes: &[u8],
    sync: impl FnOnce(&Path) -> std::io::Result<()>,
) -> Result<(), PublishError> {
    if let Some(parent) = path.parent() {
        make_private_dir(parent).map_err(|error| {
            PublishError::BeforePublication(format!("creating {}: {error}", parent.display()))
        })?;
    }
    let temporary = temporary_path(path).map_err(PublishError::BeforePublication)?;
    if let Err(error) = write_private_file(&temporary, bytes) {
        std::fs::remove_file(&temporary).ok();
        return Err(PublishError::BeforePublication(format!(
            "writing {}: {error}",
            temporary.display()
        )));
    }
    if let Err(error) = std::fs::rename(&temporary, path) {
        std::fs::remove_file(&temporary).ok();
        return Err(PublishError::BeforePublication(format!(
            "replacing {}: {error}",
            path.display()
        )));
    }
    require_durable_publication(path, sync(path))?;
    Ok(())
}

fn require_durable_publication(
    path: &Path,
    sync_result: std::io::Result<()>,
) -> Result<(), PublishError> {
    sync_result.map_err(|error| {
        PublishError::PublishedButNotDurable(format!(
            "syncing identity directory at {}: {error}",
            path.display()
        ))
    })
}

fn temporary_path(path: &Path) -> Result<PathBuf, String> {
    let mut suffix = [0u8; 8];
    getrandom::getrandom(&mut suffix)
        .map_err(|error| format!("generating a temporary identity filename: {error}"))?;
    Ok(path.with_extension(format!("json.{}.tmp", hex::encode(suffix))))
}

#[cfg(unix)]
fn make_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if path.is_dir() {
        return Ok(());
    }
    if let Some(parent) = path.parent().filter(|parent| *parent != path) {
        make_private_dir(parent)?;
    }
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => sync_parent(path),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(not(unix))]
fn make_private_dir(path: &Path) -> std::io::Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    if let Some(parent) = path.parent().filter(|parent| *parent != path) {
        make_private_dir(parent)?;
    }
    match std::fs::create_dir(path) {
        Ok(()) => sync_parent(path),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[derive(Clone, Copy)]
    enum TestBinding {
        Bootstrap,
        Pinned,
    }

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!(
                "keytap-nearby-identity-{}-{tag}",
                std::process::id()
            ))
            .join("nearby-identity.json")
    }

    fn bootstrap_fields_for<'a>(
        proof: &'a Proof,
        confirmation: &'a ConfirmedComparison,
        challenge: &'a [u8; 32],
        prf: &'a [u8; 32],
    ) -> ProofContext<'a> {
        let _ = proof;
        ProofContext {
            binding: ProofBinding::BootstrapSas { confirmation },
            challenge,
            prf_output: prf,
            key_name: "deploy",
        }
    }

    fn pinned_fields_for<'a>(
        proof: &'a Proof,
        digest: &'a [u8; 32],
        challenge: &'a [u8; 32],
        prf: &'a [u8; 32],
    ) -> ProofContext<'a> {
        let _ = proof;
        ProofContext {
            binding: ProofBinding::PinnedSession { digest },
            challenge,
            prf_output: prf,
            key_name: "deploy",
        }
    }

    fn signed_proof(seed: [u8; 32], credential_id: &[u8], binding: TestBinding) -> Proof {
        let signing = SigningKey::from_bytes(&seed);
        let public_key = signing.verifying_key().to_bytes();
        let mut proof = Proof {
            credential_id: credential_id.to_vec(),
            public_key,
            signature: [0; 64],
        };
        let digest = [0x42; 32];
        let challenge = [0x24; 32];
        let prf = [0x11; 32];
        let message = match binding {
            TestBinding::Bootstrap => {
                let confirmation = ConfirmedComparison::from_digest_for_test(digest);
                proof_message(
                    &proof,
                    &bootstrap_fields_for(&proof, &confirmation, &challenge, &prf),
                )
            }
            TestBinding::Pinned => proof_message(
                &proof,
                &pinned_fields_for(&proof, &digest, &challenge, &prf),
            ),
        };
        proof.signature = signing.sign(&message).to_bytes();
        proof
    }

    fn pairing(anchor: Anchor) -> PairingAnchor {
        match anchor {
            Anchor::Pairing(anchor) => anchor,
            Anchor::Pinned(_) => panic!("expected an identity that still requires pairing"),
        }
    }

    fn pinned(anchor: Anchor) -> PinnedAnchor {
        match anchor {
            Anchor::Pinned(anchor) => anchor,
            Anchor::Pairing(_) => panic!("expected a fully pinned identity"),
        }
    }

    fn pending_init_at(path: PathBuf) -> PendingInit {
        PendingInit {
            expected: read_revision(&path).unwrap(),
            path,
        }
    }

    #[test]
    fn identity_prf_salt_is_stable_and_separate_from_named_keys() {
        assert_eq!(
            hex::encode(prf_salt()),
            "0e77b3886c1dfd2ce68782dc0fa4b6872e75a18dfe28799aab9414b5fd8e249e"
        );
        assert_ne!(
            prf_salt().as_slice(),
            keytap_core::prf_salt_for_name("nearby-identity-prf:v1").unwrap()
        );
    }

    #[test]
    fn missing_identity_cannot_authorize_remembered_keys() {
        let path = temp_path("missing-remember-authority");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        assert!(remember_authority_at(path).is_err());
    }

    #[test]
    fn init_commit_is_a_revision_compare_and_swap() {
        let path = temp_path("init-cas");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let first = pending_init_at(path.clone());
        let racing = pending_init_at(path.clone());

        first.commit(b"credential-one").unwrap();
        assert!(racing.commit(b"credential-two").is_err());
        assert!(matches!(
            pairing(Anchor::load_from(path.clone()).unwrap()).constraint(),
            PairingConstraint::Credential { credential_id } if credential_id == b"credential-one"
        ));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn new_publication_sync_failure_is_typed_as_durability_unknown() {
        let path = temp_path("new-durability-unknown");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let result = write_private_new_with_sync(&path, b"new identity", |_| {
            Err(std::io::Error::other("injected directory sync failure"))
        });
        assert!(matches!(
            result,
            Err(PublishError::PublishedButNotDurable(_))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"new identity");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn replacement_sync_failure_is_typed_as_durability_unknown() {
        let path = temp_path("replace-durability-unknown");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        write_private_new(&path, b"old identity").unwrap();
        let result = write_private_replace_with_sync(&path, b"new identity", |_| {
            Err(std::io::Error::other("injected directory sync failure"))
        });
        assert!(matches!(
            result,
            Err(PublishError::PublishedButNotDurable(_))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"new identity");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn create_mode_cannot_authorize_replacing_an_existing_identity() {
        let path = temp_path("init-create-mode");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        pending_init_at(path.clone())
            .commit(b"credential-one")
            .unwrap();

        assert!(prepare_init_at(path.clone(), InitMode::Create).is_err());
        assert!(prepare_init_at(path.clone(), InitMode::Replace).is_ok());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn init_cannot_overwrite_a_pairing_that_won_during_the_ceremony() {
        let path = temp_path("init-versus-pairing");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let pending = pending_init_at(path.clone());
        let anchor = pairing(Anchor::load_from(path.clone()).unwrap());
        let proof = signed_proof([7; 32], b"paired-credential", TestBinding::Bootstrap);
        let digest = [0x42; 32];
        let confirmation = ConfirmedComparison::from_digest_for_test(digest);
        let challenge = [0x24; 32];
        let prf = [0x11; 32];
        anchor
            .verify_and_pin_after_sas(
                &proof,
                &bootstrap_fields_for(&proof, &confirmation, &challenge, &prf),
            )
            .unwrap();

        assert!(pending.commit(b"init-credential").is_err());
        assert_eq!(
            pinned(Anchor::load_from(path.clone()).unwrap()).credential_id(),
            b"paired-credential"
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn a_preexisting_lock_file_is_not_a_stale_sentinel() {
        let path = temp_path("permanent-lock");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        make_private_dir(path.parent().unwrap()).unwrap();
        std::fs::write(
            path.with_extension("json.lock"),
            b"left by an earlier process",
        )
        .unwrap();

        pending_init_at(path.clone())
            .commit(b"credential-one")
            .unwrap();
        assert!(path.is_file());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn confirmed_first_pairing_pins_and_later_requires_the_identity() {
        let path = temp_path("pair");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let anchor = pairing(Anchor::load_from(path.clone()).unwrap());
        assert!(matches!(anchor.constraint(), PairingConstraint::AnyPasskey));

        let proof = signed_proof([7; 32], b"credential-one", TestBinding::Bootstrap);
        let digest = [0x42; 32];
        let confirmation = ConfirmedComparison::from_digest_for_test(digest);
        let challenge = [0x24; 32];
        let prf = [0x11; 32];
        anchor
            .verify_and_pin_after_sas(
                &proof,
                &bootstrap_fields_for(&proof, &confirmation, &challenge, &prf),
            )
            .unwrap();

        let anchor = pinned(Anchor::load_from(path.clone()).unwrap());
        assert_eq!(anchor.credential_id(), b"credential-one");
        let proof = signed_proof([7; 32], b"credential-one", TestBinding::Pinned);
        anchor
            .verify(
                &proof,
                &pinned_fields_for(&proof, &digest, &challenge, &prf),
            )
            .unwrap();
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn force_init_wins_before_a_stale_pinned_result_is_accepted() {
        let path = temp_path("force-init-versus-pinned-result");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let first = pairing(Anchor::load_from(path.clone()).unwrap());
        let digest = [0x42; 32];
        let confirmation = ConfirmedComparison::from_digest_for_test(digest);
        let challenge = [0x24; 32];
        let prf = [0x11; 32];
        let bootstrap = signed_proof([7; 32], b"credential-one", TestBinding::Bootstrap);
        first
            .verify_and_pin_after_sas(
                &bootstrap,
                &bootstrap_fields_for(&bootstrap, &confirmation, &challenge, &prf),
            )
            .unwrap();

        // The assertion captured generation one, then a force-init committed
        // generation two before the assertion result reached final acceptance.
        let stale = pinned(Anchor::load_from(path.clone()).unwrap());
        let replacement = prepare_init_at(path.clone(), InitMode::Replace).unwrap();
        replacement.commit(b"credential-two").unwrap();
        let old_proof = signed_proof([7; 32], b"credential-one", TestBinding::Pinned);
        assert!(matches!(
            stale.verify(
                &old_proof,
                &pinned_fields_for(&old_proof, &digest, &challenge, &prf),
            ),
            Err(VerificationError::IdentityMismatch)
        ));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_different_identity_is_rejected_after_pairing() {
        let path = temp_path("mismatch");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let first = pairing(Anchor::load_from(path.clone()).unwrap());
        let digest = [0x42; 32];
        let confirmation = ConfirmedComparison::from_digest_for_test(digest);
        let challenge = [0x24; 32];
        let prf = [0x11; 32];
        let proof = signed_proof([7; 32], b"credential-one", TestBinding::Bootstrap);
        first
            .verify_and_pin_after_sas(
                &proof,
                &bootstrap_fields_for(&proof, &confirmation, &challenge, &prf),
            )
            .unwrap();

        let anchor = pinned(Anchor::load_from(path.clone()).unwrap());
        let other = signed_proof([9; 32], b"credential-two", TestBinding::Pinned);
        assert!(matches!(
            anchor.verify(
                &other,
                &pinned_fields_for(&other, &digest, &challenge, &prf),
            ),
            Err(VerificationError::IdentityMismatch)
        ));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn credential_only_init_anchor_still_requires_sas() {
        let path = temp_path("credential-pairing");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let stored = StoredFile {
            format: FORMAT.to_string(),
            identity: StoredIdentity::Credential {
                credential_id: URL_SAFE_NO_PAD.encode(b"credential-one"),
            },
        };
        write_private_replace(&path, &serde_json::to_vec(&stored).unwrap()).unwrap();
        let anchor = pairing(Anchor::load_from(path.clone()).unwrap());
        assert!(matches!(
            anchor.constraint(),
            PairingConstraint::Credential { credential_id } if credential_id == b"credential-one"
        ));

        let digest = [0x42; 32];
        let confirmation = ConfirmedComparison::from_digest_for_test(digest);
        let challenge = [0x24; 32];
        let prf = [0x11; 32];
        let wrong = signed_proof([9; 32], b"credential-two", TestBinding::Bootstrap);
        assert!(matches!(
            anchor.verify_and_pin_after_sas(
                &wrong,
                &bootstrap_fields_for(&wrong, &confirmation, &challenge, &prf),
            ),
            Err(VerificationError::IdentityMismatch)
        ));

        let matching = signed_proof([7; 32], b"credential-one", TestBinding::Bootstrap);
        anchor
            .verify_and_pin_after_sas(
                &matching,
                &bootstrap_fields_for(&matching, &confirmation, &challenge, &prf),
            )
            .unwrap();
        assert!(matches!(
            Anchor::load_from(path.clone()).unwrap(),
            Anchor::Pinned(_)
        ));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn concurrent_pairing_never_replaces_the_winner() {
        let path = temp_path("race");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let first = pairing(Anchor::load_from(path.clone()).unwrap());
        let racing = pairing(Anchor::load_from(path.clone()).unwrap());
        let winner = signed_proof([7; 32], b"credential-one", TestBinding::Bootstrap);
        let loser = signed_proof([9; 32], b"credential-two", TestBinding::Bootstrap);
        let digest = [0x42; 32];
        let confirmation = ConfirmedComparison::from_digest_for_test(digest);
        let challenge = [0x24; 32];
        let prf = [0x11; 32];

        first
            .verify_and_pin_after_sas(
                &winner,
                &bootstrap_fields_for(&winner, &confirmation, &challenge, &prf),
            )
            .unwrap();
        assert!(matches!(
            racing.verify_and_pin_after_sas(
                &loser,
                &bootstrap_fields_for(&loser, &confirmation, &challenge, &prf),
            ),
            Err(VerificationError::IdentityMismatch)
        ));
        assert_eq!(
            pinned(Anchor::load_from(path.clone()).unwrap()).credential_id(),
            b"credential-one"
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn proof_mode_and_full_digest_are_bound() {
        let path = temp_path("binding");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let anchor = pairing(Anchor::load_from(path.clone()).unwrap());
        let proof = signed_proof([7; 32], b"credential-one", TestBinding::Bootstrap);
        let wrong_digest = [0x43; 32];
        let wrong_confirmation = ConfirmedComparison::from_digest_for_test(wrong_digest);
        let challenge = [0x24; 32];
        let prf = [0x11; 32];
        assert!(matches!(
            anchor.verify_and_pin_after_sas(
                &proof,
                &bootstrap_fields_for(&proof, &wrong_confirmation, &challenge, &prf),
            ),
            Err(VerificationError::InvalidProof)
        ));
        assert!(!path.exists(), "an invalid proof must never create a pin");

        let correct_digest = [0x42; 32];
        assert!(matches!(
            anchor.verify_and_pin_after_sas(
                &proof,
                &pinned_fields_for(&proof, &correct_digest, &challenge, &prf),
            ),
            Err(VerificationError::InvalidProof)
        ));
    }

    #[test]
    fn proof_bytes_are_deterministic_for_browser_interop() {
        let proof = signed_proof([7; 32], b"credential-one", TestBinding::Bootstrap);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(proof.public_key),
            "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw"
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(proof.signature),
            "NVy39fNzZCAiPt1NmmwKtykd-vRk9SPzvlxnHd_Lp8smT5qNZZJ5OVvlObjz3hrsPoCVNDtZU4onn_bgPqyFDQ"
        );
    }
}
