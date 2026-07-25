//! Trust-on-first-use identity for nearby passkey ceremonies.
//!
//! A nearby WebAuthn assertion asks the passkey PRF for two independent
//! outputs in one prompt: the named key output and a fixed identity seed. The
//! page derives an Ed25519 key from the latter and signs the exact nearby
//! result. This module pins only the public identity and credential ID. A
//! later nearby flow must match both and carry a valid, fresh signature.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const FORMAT: &str = "keytap-nearby-identity-v1";
const PROOF_DOMAIN: &[u8] = b"keytap:nearby-identity-proof:v1\0";
const FINGERPRINT_DOMAIN: &[u8] = b"keytap:nearby-identity-fingerprint:v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Expectation {
    FirstUse,
    Pinned { credential_id: Vec<u8> },
}

#[derive(Debug)]
enum TrustState {
    FirstUse,
    Credential(PinnedCredential),
    Pinned(PinnedIdentity),
}

enum PinWrite {
    Created,
    Existing(PinnedIdentity),
}

#[derive(Debug)]
struct PinnedIdentity {
    credential_id: Vec<u8>,
    public_key: [u8; 32],
}

#[derive(Debug)]
struct PinnedCredential {
    credential_id: Vec<u8>,
}

pub struct Anchor {
    path: PathBuf,
    state: TrustState,
}

pub struct Proof {
    pub credential_id: Vec<u8>,
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

pub struct ProofFields<'a> {
    pub session_binding: &'a [u8; 32],
    pub challenge: &'a [u8],
    pub credential_id: &'a [u8],
    pub prf_output: &'a [u8; 32],
    pub key_name: &'a str,
    pub public_key: &'a [u8; 32],
}

#[derive(Debug, Eq, PartialEq)]
pub enum Verification {
    TofuPinned { fingerprint: String },
    InitPinCompleted { fingerprint: String },
    MatchedPin,
}

#[derive(Debug)]
pub enum VerificationError {
    IdentityMismatch,
    InvalidProof,
    Store(String),
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IdentityMismatch => write!(
                f,
                "the nearby passkey does not match the identity first trusted on this machine"
            ),
            Self::InvalidProof => write!(f, "the phone returned an invalid passkey identity proof"),
            Self::Store(message) => write!(f, "could not store the nearby passkey identity: {message}"),
        }
    }
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
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self { path, state: TrustState::FirstUse })
            }
            Err(error) => return Err(format!("reading {}: {error}", path.display())),
        };
        let stored: StoredFile = serde_json::from_str(&text)
            .map_err(|_| format!("{} is not a valid nearby identity file", path.display()))?;
        if stored.format != FORMAT {
            return Err(format!("{} has an unknown nearby identity format", path.display()));
        }
        let state = match stored.identity {
            StoredIdentity::Credential { credential_id } => {
                let credential_id = decode_bounded(&credential_id, "credential ID", 1, 1024)
                    .map_err(|error| format!("{}: {error}", path.display()))?;
                TrustState::Credential(PinnedCredential { credential_id })
            }
            StoredIdentity::Ed25519 { credential_id, public_key } => {
                let credential_id = decode_bounded(&credential_id, "credential ID", 1, 1024)
                    .map_err(|error| format!("{}: {error}", path.display()))?;
                let public_key = decode_fixed::<32>(&public_key, "public key")
                    .map_err(|error| format!("{}: {error}", path.display()))?;
                VerifyingKey::from_bytes(&public_key).map_err(|_| {
                    format!("{} contains an invalid Ed25519 public key", path.display())
                })?;
                TrustState::Pinned(PinnedIdentity { credential_id, public_key })
            }
        };
        Ok(Self { path, state })
    }

    pub fn expectation(&self) -> Expectation {
        match &self.state {
            TrustState::FirstUse => Expectation::FirstUse,
            TrustState::Credential(identity) => Expectation::Pinned {
                credential_id: identity.credential_id.clone(),
            },
            TrustState::Pinned(identity) => Expectation::Pinned {
                credential_id: identity.credential_id.clone(),
            },
        }
    }

    pub fn verify_and_pin(
        &self,
        proof: &Proof,
        fields: &ProofFields<'_>,
    ) -> Result<Verification, VerificationError> {
        if proof.credential_id != fields.credential_id || proof.public_key != *fields.public_key {
            return Err(VerificationError::InvalidProof);
        }

        match &self.state {
            TrustState::Credential(pinned) if pinned.credential_id != proof.credential_id => {
                return Err(VerificationError::IdentityMismatch)
            }
            TrustState::Pinned(pinned)
                if pinned.credential_id != proof.credential_id
                    || pinned.public_key != proof.public_key =>
            {
                return Err(VerificationError::IdentityMismatch)
            }
            TrustState::FirstUse | TrustState::Credential(_) | TrustState::Pinned(_) => {}
        }

        let key = VerifyingKey::from_bytes(&proof.public_key)
            .map_err(|_| VerificationError::InvalidProof)?;
        let signature = Signature::from_bytes(&proof.signature);
        key.verify_strict(&proof_message(fields), &signature)
            .map_err(|_| VerificationError::InvalidProof)?;

        match &self.state {
            TrustState::Pinned(_) => Ok(Verification::MatchedPin),
            TrustState::Credential(_) => {
                self.replace_with_verified_pin(proof)?;
                Ok(Verification::InitPinCompleted {
                    fingerprint: fingerprint(&proof.public_key),
                })
            }
            TrustState::FirstUse => {
                match self.write_pin(proof)? {
                    PinWrite::Created => Ok(Verification::TofuPinned {
                        fingerprint: fingerprint(&proof.public_key),
                    }),
                    PinWrite::Existing(existing)
                        if existing.credential_id == proof.credential_id
                            && existing.public_key == proof.public_key =>
                    {
                        Ok(Verification::MatchedPin)
                    }
                    PinWrite::Existing(_) => Err(VerificationError::IdentityMismatch),
                }
            }
        }
    }

    fn write_pin(&self, proof: &Proof) -> Result<PinWrite, VerificationError> {
        let bytes = verified_pin_bytes(proof).map_err(VerificationError::Store)?;
        match write_private_new(&self.path, &bytes).map_err(VerificationError::Store)? {
            NewFile::Created => Ok(PinWrite::Created),
            NewFile::AlreadyExists => {
                let existing = Self::load_from(self.path.clone())
                    .map_err(VerificationError::Store)?;
                match existing.state {
                    TrustState::Pinned(identity) => Ok(PinWrite::Existing(identity)),
                    TrustState::FirstUse | TrustState::Credential(_) => Err(VerificationError::Store(
                        "identity file disappeared during first-use pinning".to_string(),
                    )),
                }
            }
        }
    }

    fn replace_with_verified_pin(&self, proof: &Proof) -> Result<(), VerificationError> {
        let bytes = verified_pin_bytes(proof).map_err(VerificationError::Store)?;
        write_private_replace(&self.path, &bytes).map_err(VerificationError::Store)
    }
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

pub fn proof_message(fields: &ProofFields<'_>) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        PROOF_DOMAIN.len()
            + fields.session_binding.len()
            + fields.challenge.len()
            + fields.credential_id.len()
            + fields.prf_output.len()
            + fields.key_name.len()
            + fields.public_key.len()
            + 24,
    );
    message.extend_from_slice(PROOF_DOMAIN);
    append_field(&mut message, fields.session_binding);
    append_field(&mut message, fields.challenge);
    append_field(&mut message, fields.credential_id);
    append_field(&mut message, fields.prf_output);
    append_field(&mut message, fields.key_name.as_bytes());
    append_field(&mut message, fields.public_key);
    message
}

fn append_field(message: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("nearby proof fields fit in u32");
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(value);
}

fn fingerprint(public_key: &[u8; 32]) -> String {
    let digest = Sha256::new_with_prefix(FINGERPRINT_DOMAIN)
        .chain_update(public_key)
        .finalize();
    URL_SAFE_NO_PAD.encode(&digest[..9])
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

pub fn previously_pinned() -> bool {
    default_path().is_ok_and(|path| path.is_file())
}

/// A successful init replaces the root. The registration does not expose the
/// stable PRF-derived public identity yet, but its credential ID is already a
/// trusted anchor. The next nearby assertion must use that exact credential
/// and then completes the full identity pin without another init ceremony.
pub fn after_init(credential_id: &[u8]) {
    let Ok(path) = default_path() else { return };
    let stored = StoredFile {
        format: FORMAT.to_string(),
        identity: StoredIdentity::Credential {
            credential_id: URL_SAFE_NO_PAD.encode(credential_id),
        },
    };
    let result = serde_json::to_vec_pretty(&stored)
        .map_err(|error| error.to_string())
        .and_then(|bytes| write_private_replace(&path, &bytes));
    if let Err(error) = result {
        eprintln!(
            "warning: couldn't record the new nearby credential identity at {}: {error}",
            path.display()
        );
    }
}

enum NewFile {
    Created,
    AlreadyExists,
}

/// Publish a fully-written file without ever replacing an identity another
/// concurrent first-use flow already won. A hard link is the atomic
/// create-if-absent operation; the temporary link is removed afterward.
fn write_private_new(path: &Path, bytes: &[u8]) -> Result<NewFile, String> {
    if let Some(parent) = path.parent() {
        make_private_dir(parent)
            .map_err(|error| format!("creating {}: {error}", parent.display()))?;
    }
    let temporary = temporary_path(path)?;
    write_private_file(&temporary, bytes)
        .map_err(|error| format!("writing {}: {error}", temporary.display()))?;
    let published = match std::fs::hard_link(&temporary, path) {
        Ok(()) => Ok(NewFile::Created),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Ok(NewFile::AlreadyExists)
        }
        Err(error) => Err(format!("creating {}: {error}", path.display())),
    };
    if let Err(error) = std::fs::remove_file(&temporary) {
        if published.is_ok() {
            return Err(format!("removing temporary {}: {error}", temporary.display()));
        }
    }
    published
}

fn write_private_replace(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        make_private_dir(parent)
            .map_err(|error| format!("creating {}: {error}", parent.display()))?;
    }
    let temporary = temporary_path(path)?;
    write_private_file(&temporary, bytes)
        .map_err(|error| format!("writing {}: {error}", temporary.display()))?;
    std::fs::rename(&temporary, path)
        .map_err(|error| format!("replacing {}: {error}", path.display()))
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
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(path)
}

#[cfg(not(unix))]
fn make_private_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)
}

#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!("keytap-nearby-identity-{}-{tag}", std::process::id()))
            .join("nearby-identity.json")
    }

    fn signed_proof(seed: [u8; 32], credential_id: &[u8]) -> Proof {
        let signing = SigningKey::from_bytes(&seed);
        let public_key = signing.verifying_key().to_bytes();
        let session_binding = [0x42; 32];
        let challenge = [0x24; 32];
        let prf_output = [0x11; 32];
        let fields = ProofFields {
            session_binding: &session_binding,
            challenge: &challenge,
            credential_id,
            prf_output: &prf_output,
            key_name: "deploy",
            public_key: &public_key,
        };
        let signature = signing.sign(&proof_message(&fields)).to_bytes();
        Proof { credential_id: credential_id.to_vec(), public_key, signature }
    }

    fn fields_for<'a>(
        proof: &'a Proof,
        session_binding: &'a [u8; 32],
        challenge: &'a [u8; 32],
        prf: &'a [u8; 32],
    ) -> ProofFields<'a> {
        ProofFields {
            session_binding,
            challenge,
            credential_id: &proof.credential_id,
            prf_output: prf,
            key_name: "deploy",
            public_key: &proof.public_key,
        }
    }

    #[test]
    fn first_valid_proof_is_pinned_and_then_required() {
        let path = temp_path("pin");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let anchor = Anchor::load_from(path.clone()).unwrap();
        assert_eq!(anchor.expectation(), Expectation::FirstUse);

        let proof = signed_proof([7; 32], b"credential-one");
        let session_binding = [0x42; 32];
        let challenge = [0x24; 32];
        let prf = [0x11; 32];
        let result = anchor
            .verify_and_pin(&proof, &fields_for(&proof, &session_binding, &challenge, &prf))
            .unwrap();
        assert!(matches!(result, Verification::TofuPinned { .. }));

        let reloaded = Anchor::load_from(path.clone()).unwrap();
        assert_eq!(
            reloaded.expectation(),
            Expectation::Pinned { credential_id: b"credential-one".to_vec() }
        );
        assert_eq!(
            reloaded
                .verify_and_pin(&proof, &fields_for(&proof, &session_binding, &challenge, &prf))
                .unwrap(),
            Verification::MatchedPin
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_different_identity_is_rejected_after_first_use() {
        let path = temp_path("mismatch");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let anchor = Anchor::load_from(path.clone()).unwrap();
        let first = signed_proof([7; 32], b"credential-one");
        let session_binding = [0x42; 32];
        let challenge = [0x24; 32];
        let prf = [0x11; 32];
        anchor
            .verify_and_pin(&first, &fields_for(&first, &session_binding, &challenge, &prf))
            .unwrap();

        let reloaded = Anchor::load_from(path.clone()).unwrap();
        let other = signed_proof([9; 32], b"credential-two");
        assert!(matches!(
            reloaded.verify_and_pin(&other, &fields_for(&other, &session_binding, &challenge, &prf)),
            Err(VerificationError::IdentityMismatch)
        ));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn init_credential_anchor_is_enforced_and_completed() {
        let path = temp_path("init-anchor");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let stored = StoredFile {
            format: FORMAT.to_string(),
            identity: StoredIdentity::Credential {
                credential_id: URL_SAFE_NO_PAD.encode(b"credential-one"),
            },
        };
        write_private_replace(&path, &serde_json::to_vec(&stored).unwrap()).unwrap();
        let anchor = Anchor::load_from(path.clone()).unwrap();
        assert_eq!(
            anchor.expectation(),
            Expectation::Pinned { credential_id: b"credential-one".to_vec() }
        );

        let session_binding = [0x42; 32];
        let challenge = [0x24; 32];
        let prf = [0x11; 32];
        let wrong = signed_proof([9; 32], b"credential-two");
        assert!(matches!(
            anchor.verify_and_pin(
                &wrong,
                &fields_for(&wrong, &session_binding, &challenge, &prf)
            ),
            Err(VerificationError::IdentityMismatch)
        ));

        let matching = signed_proof([7; 32], b"credential-one");
        assert!(matches!(
            anchor
                .verify_and_pin(
                    &matching,
                    &fields_for(&matching, &session_binding, &challenge, &prf)
                )
                .unwrap(),
            Verification::InitPinCompleted { .. }
        ));
        assert!(matches!(
            Anchor::load_from(path.clone()).unwrap().state,
            TrustState::Pinned(_)
        ));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn concurrent_first_use_never_replaces_the_winner() {
        let path = temp_path("race");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let first_flow = Anchor::load_from(path.clone()).unwrap();
        let racing_flow = Anchor::load_from(path.clone()).unwrap();
        let winner = signed_proof([7; 32], b"credential-one");
        let loser = signed_proof([9; 32], b"credential-two");
        let session_binding = [0x42; 32];
        let challenge = [0x24; 32];
        let prf = [0x11; 32];

        first_flow
            .verify_and_pin(
                &winner,
                &fields_for(&winner, &session_binding, &challenge, &prf),
            )
            .unwrap();
        assert!(matches!(
            racing_flow.verify_and_pin(
                &loser,
                &fields_for(&loser, &session_binding, &challenge, &prf)
            ),
            Err(VerificationError::IdentityMismatch)
        ));
        assert_eq!(
            Anchor::load_from(path.clone()).unwrap().expectation(),
            Expectation::Pinned { credential_id: b"credential-one".to_vec() }
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn proof_is_bound_to_the_fresh_session() {
        let path = temp_path("binding");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        let anchor = Anchor::load_from(path.clone()).unwrap();
        let proof = signed_proof([7; 32], b"credential-one");
        let wrong_session_binding = [0x43; 32];
        let challenge = [0x24; 32];
        let prf = [0x11; 32];
        assert!(matches!(
            anchor.verify_and_pin(
                &proof,
                &fields_for(&proof, &wrong_session_binding, &challenge, &prf)
            ),
            Err(VerificationError::InvalidProof)
        ));
        assert!(!path.exists(), "an invalid first proof must never create a pin");
    }

    #[test]
    fn proof_bytes_match_the_browser_vector() {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let public_key = signing.verifying_key().to_bytes();
        let session_binding: [u8; 32] = URL_SAFE_NO_PAD
            .decode("OCbUzlIS3pmQOcOtyIfbACBko5QZou4dTY4-dsa34Pc")
            .unwrap()
            .try_into()
            .unwrap();
        let challenge = [0x24; 32];
        let prf_output = [0x11; 32];
        let fields = ProofFields {
            session_binding: &session_binding,
            challenge: &challenge,
            credential_id: b"credential-one",
            prf_output: &prf_output,
            key_name: "deploy",
            public_key: &public_key,
        };
        assert_eq!(
            URL_SAFE_NO_PAD.encode(signing.sign(&proof_message(&fields)).to_bytes()),
            "2UnoDFl5z93sC3gNM7-S3lYG6ckXzu3rIwedCYQvWDU2v-YvpuXlKtOnnLIscb0TSghY6_gUB6zcnTkPZHutAA"
        );
    }
}
