//! Approve a passkey ceremony in a nearby browser through an opaque relay.
//!
//! The CLI connects before showing a one-use public key. The browser and CLI
//! use that key for ephemeral P-256 agreement, then exchange only sequenced,
//! end-to-end encrypted messages. Two words establish the first local pairing;
//! a passkey-derived identity then pins the exact credential and signs later
//! assertion results for the one-use channel and request.

use crate::nearby_identity::{
    Anchor as IdentityAnchor, AssertionDisposition, InitCommitError as IdentityInitCommitError,
    PairingAnchor as IdentityPairingAnchor, PairingConstraint as IdentityPairingConstraint,
    PendingInit as PendingIdentityInit, PersistedInit as PersistedIdentityInit,
    PinnedAnchor as IdentityPinnedAnchor, PreparedPairingPin as PreparedIdentityPairingPin,
    PreparedPinnedAssertion as PreparedPinnedIdentityAssertion, Proof as NearbyIdentityProof,
    ProofBinding as NearbyIdentityProofBinding, ProofContext as NearbyIdentityProofContext,
    RegistrationProofContext as NearbyRegistrationProofContext,
    VerificationError as IdentityVerificationError,
};
use crate::nearby_protocol::{CliHandshake, SecureChannel};
use crate::nearby_sas::{
    ConfirmedComparison as SasConfirmation, Context as SasContext,
    InitiatorCommitment as SasCommitment,
};
use crate::note;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::net::{Shutdown, TcpStream};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use tungstenite::client::connect_with_config;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};
use zeroize::Zeroizing;

const RELAY_WEBSOCKET_BASE_URL: &str = "wss://keytap-relay.julsh.workers.dev";
const PAGE_URL: &str = "https://keytap.jul.sh/nearby";
const RELAY_SETUP_TIMEOUT: Duration = Duration::from_secs(15);
const ROOM_TIMEOUT: Duration = Duration::from_secs(300);
const CEREMONY_TIMEOUT: Duration = Duration::from_secs(150);
const SEND_TIMEOUT: Duration = Duration::from_secs(2);
const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(100);
const RELAY_FRAME_LIMIT: usize = 16 * 1024;
const ENCRYPTED_OVERHEAD: usize = 1 + 8 + 16;
const PLAINTEXT_LIMIT: usize = RELAY_FRAME_LIMIT - ENCRYPTED_OVERHEAD;
const SUPERSEDED_ERROR: &str = "nearby approval was completed on this Mac instead";

/// The only transport state shared with the native approval coordinator.
/// An active clone of the underlying TCP stream exists solely so a native
/// winner can interrupt a blocking relay read.
#[derive(Clone)]
pub(crate) struct NearbyCancellation {
    inner: Arc<Mutex<NearbyCancellationState>>,
}

enum NearbyCancellationState {
    Preparing,
    Active(TcpStream),
    Superseded,
    Finished,
}

impl NearbyCancellation {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(NearbyCancellationState::Preparing)),
        }
    }

    fn register(&self, stream: TcpStream) -> Result<(), String> {
        let mut state = self
            .inner
            .lock()
            .expect("nearby cancellation lock poisoned");
        match std::mem::replace(&mut *state, NearbyCancellationState::Finished) {
            NearbyCancellationState::Preparing => {
                *state = NearbyCancellationState::Active(stream);
                Ok(())
            }
            NearbyCancellationState::Superseded => {
                stream.shutdown(Shutdown::Both).ok();
                *state = NearbyCancellationState::Superseded;
                Err(SUPERSEDED_ERROR.to_string())
            }
            invalid @ (NearbyCancellationState::Active(_) | NearbyCancellationState::Finished) => {
                *state = invalid;
                Err("nearby cancellation entered an invalid connection state".to_string())
            }
        }
    }

    fn ensure_active(&self) -> Result<(), String> {
        match &*self
            .inner
            .lock()
            .expect("nearby cancellation lock poisoned")
        {
            NearbyCancellationState::Preparing | NearbyCancellationState::Active(_) => Ok(()),
            NearbyCancellationState::Superseded => Err(SUPERSEDED_ERROR.to_string()),
            NearbyCancellationState::Finished => {
                Err("nearby approval session already finished".to_string())
            }
        }
    }

    /// Serialize presentation with native supersession so a dead invitation
    /// cannot begin printing after local approval has won.
    fn present_invitation(
        &self,
        present: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        let state = self
            .inner
            .lock()
            .expect("nearby cancellation lock poisoned");
        match &*state {
            NearbyCancellationState::Active(_) => present(),
            NearbyCancellationState::Superseded => Err(SUPERSEDED_ERROR.to_string()),
            NearbyCancellationState::Preparing => {
                Err("nearby approval connection was not ready".to_string())
            }
            NearbyCancellationState::Finished => {
                Err("nearby approval session already finished".to_string())
            }
        }
    }

    #[cfg(any(target_os = "macos", test))]
    pub(crate) fn supersede(&self) {
        let mut state = self
            .inner
            .lock()
            .expect("nearby cancellation lock poisoned");
        match std::mem::replace(&mut *state, NearbyCancellationState::Superseded) {
            NearbyCancellationState::Active(stream) => {
                stream.shutdown(Shutdown::Both).ok();
            }
            NearbyCancellationState::Preparing
            | NearbyCancellationState::Superseded
            | NearbyCancellationState::Finished => {}
        }
    }

    pub(crate) fn finish(&self) {
        let mut state = self
            .inner
            .lock()
            .expect("nearby cancellation lock poisoned");
        match std::mem::replace(&mut *state, NearbyCancellationState::Finished) {
            NearbyCancellationState::Superseded => {
                *state = NearbyCancellationState::Superseded;
            }
            NearbyCancellationState::Preparing
            | NearbyCancellationState::Active(_)
            | NearbyCancellationState::Finished => {}
        }
    }
}

/// A completed nearby assertion ceremony.
pub struct NearbyAssertion {
    pub prf_output: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub storage: StorageOutcome,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StoragePolicy {
    Choose,
    Remember,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageOutcome {
    Once,
    Stored,
    Unavailable,
}

#[cfg(not(target_os = "macos"))]
pub fn authenticate_nearby(name: &str, storage_policy: StoragePolicy) -> NearbyAssertion {
    let cancellation = NearbyCancellation::new();
    let prepared = prepare_nearby_assertion_with_presentation(
        name,
        storage_policy,
        cancellation.clone(),
        InvitationPresentation::StandaloneNearby,
    )
    .unwrap_or_else(|error| crate::die(&error));
    cancellation.finish();
    prepared.commit().unwrap_or_else(|error| crate::die(&error))
}

#[cfg(target_os = "macos")]
pub(crate) fn prepare_nearby_assertion(
    name: &str,
    storage_policy: StoragePolicy,
    cancellation: NearbyCancellation,
) -> Result<PreparedNearbyAssertion, String> {
    prepare_nearby_assertion_with_presentation(
        name,
        storage_policy,
        cancellation,
        InvitationPresentation::ConcurrentNativeAndNearby,
    )
}

pub fn register_nearby(pending_init: PendingIdentityInit) -> PersistedIdentityInit {
    let result = run_nearby_registration(pending_init).unwrap_or_else(|error| crate::die(&error));
    eprintln!("Passkey registered successfully via nearby device.");
    result
}

enum Operation<'a> {
    Register {
        pending_init: PendingIdentityInit,
    },
    Assert {
        name: &'a str,
        storage_policy: StoragePolicy,
    },
}

enum FlowPlan {
    Registration {
        request: CeremonyRequest,
        challenge: [u8; 32],
        pending_init: PendingIdentityInit,
    },
    Assertion {
        assertion: AssertionPlan,
        route: AssertionRoute,
    },
}

enum AssertionRoute {
    FirstPair(IdentityPairingAnchor),
    PinnedIdentity(IdentityPinnedAnchor),
}

impl AssertionRoute {
    fn identity_request(&self) -> IdentityRequest {
        match self {
            Self::FirstPair(anchor) => match anchor.constraint() {
                IdentityPairingConstraint::AnyPasskey => IdentityRequest::PairingAny,
                IdentityPairingConstraint::Credential { credential_id } => {
                    IdentityRequest::PairingCredential {
                        credential_id: URL_SAFE_NO_PAD.encode(credential_id),
                    }
                }
            },
            Self::PinnedIdentity(anchor) => IdentityRequest::Pinned {
                credential_id: URL_SAFE_NO_PAD.encode(anchor.credential_id()),
            },
        }
    }
}

struct AssertionPlan {
    key_name: String,
    prf_salt: Vec<u8>,
    identity_salt: [u8; 32],
    challenge: [u8; 32],
    storage: StoragePolicy,
}

impl AssertionPlan {
    fn request(&self, route: &AssertionRoute) -> CeremonyRequest {
        CeremonyRequest::Assert {
            key_name: self.key_name.clone(),
            prf_salt: URL_SAFE_NO_PAD.encode(&self.prf_salt),
            identity_salt: URL_SAFE_NO_PAD.encode(self.identity_salt),
            challenge: URL_SAFE_NO_PAD.encode(self.challenge),
            identity: route.identity_request(),
            storage: self.storage,
        }
    }
}

struct ConnectedNearby {
    session: RelaySession,
    session_binding: [u8; 32],
    plan: FlowPlan,
}

#[derive(Clone, Copy)]
enum InvitationPresentation {
    StandaloneNearby,
    #[cfg(any(target_os = "macos", test))]
    ConcurrentNativeAndNearby,
}

fn build_plan(operation: Operation<'_>) -> Result<FlowPlan, String> {
    let mut challenge = [0u8; 32];
    getrandom::getrandom(&mut challenge)
        .map_err(|error| format!("failed to generate WebAuthn challenge: {error}"))?;
    match operation {
        Operation::Register { pending_init } => Ok(FlowPlan::Registration {
            request: CeremonyRequest::Register {
                challenge: URL_SAFE_NO_PAD.encode(challenge),
                identity_salt: URL_SAFE_NO_PAD.encode(crate::nearby_identity::prf_salt()),
                user_id: URL_SAFE_NO_PAD.encode(b"keytap-user"),
                user_name: "keytap".to_string(),
            },
            challenge,
            pending_init,
        }),
        Operation::Assert {
            name,
            storage_policy,
        } => {
            let prf_salt = keytap_core::prf_salt_for_name(name)
                .map_err(|error| format!("invalid key name: {error}"))?;
            let anchor = IdentityAnchor::load()
                .map_err(|error| format!("could not load the nearby passkey identity: {error}"))?;
            let route = match anchor {
                IdentityAnchor::Pairing(anchor) => AssertionRoute::FirstPair(anchor),
                IdentityAnchor::Pinned(anchor) => AssertionRoute::PinnedIdentity(anchor),
            };
            Ok(FlowPlan::Assertion {
                assertion: AssertionPlan {
                    key_name: name.to_string(),
                    prf_salt,
                    identity_salt: crate::nearby_identity::prf_salt(),
                    challenge,
                    storage: storage_policy,
                },
                route,
            })
        }
    }
}

fn connect_nearby(
    operation: Operation<'_>,
    cancellation: Option<&NearbyCancellation>,
    presentation: InvitationPresentation,
) -> Result<ConnectedNearby, String> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let plan = build_plan(operation)?;
    let handshake = CliHandshake::generate()?;
    let ws_url = format!(
        "{RELAY_WEBSOCKET_BASE_URL}/room/{}?role=cli",
        handshake.room_id()
    );
    let mut socket = connect_relay(&ws_url)?;
    if let Some(cancellation) = cancellation {
        cancellation.register(interrupt_stream(&socket)?)?;
    }

    let url = format!("{PAGE_URL}#key={}", handshake.fragment_value());
    let present = || {
        print_invitation(&url, presentation)?;
        Ok(())
    };
    if let Some(cancellation) = cancellation {
        cancellation.present_invitation(present)?;
    } else {
        present()?;
    }
    if let Some(cancellation) = cancellation {
        cancellation.ensure_active()?;
    }

    let hello = receive_browser_hello(&mut socket, Instant::now() + ROOM_TIMEOUT, cancellation)?;
    let channel = handshake.accept(&hello)?;
    let session_binding = *channel.session_binding();
    Ok(ConnectedNearby {
        session: RelaySession { socket, channel },
        session_binding,
        plan,
    })
}

fn prepare_nearby_assertion_with_presentation(
    name: &str,
    storage_policy: StoragePolicy,
    cancellation: NearbyCancellation,
    presentation: InvitationPresentation,
) -> Result<PreparedNearbyAssertion, String> {
    let result = (|| {
        let ConnectedNearby {
            mut session,
            session_binding,
            plan,
        } = connect_nearby(
            Operation::Assert {
                name,
                storage_policy,
            },
            Some(&cancellation),
            presentation,
        )?;
        let FlowPlan::Assertion { assertion, route } = plan else {
            return Err("nearby protocol prepared registration for an assertion".to_string());
        };
        let request = assertion.request(&route);
        let authorization = match route {
            AssertionRoute::FirstPair(anchor) => AssertionAuthorization::FirstPair {
                anchor,
                confirmation: run_sas(
                    &mut session,
                    &request,
                    &session_binding,
                    Some(&cancellation),
                )?,
            },
            AssertionRoute::PinnedIdentity(anchor) => AssertionAuthorization::PinnedIdentity {
                anchor,
                binding: DirectProofBinding {
                    session_binding,
                    request: session.send(&CliMessage::Request { request })?,
                },
            },
        };
        let result = match (
            &authorization,
            session.receive(CEREMONY_TIMEOUT, Some(&cancellation))?,
        ) {
            (
                AssertionAuthorization::FirstPair { .. },
                ApproverMessage::PairedAssertionResult {
                    credential_id,
                    prf_first,
                    disposition,
                    identity,
                },
            )
            | (
                AssertionAuthorization::PinnedIdentity { .. },
                ApproverMessage::AssertionResult {
                    credential_id,
                    prf_first,
                    disposition,
                    identity,
                },
            ) => AssertionResult {
                credential_id,
                prf_first,
                disposition,
                identity,
            },
            (_, ApproverMessage::Done {}) => {
                return Err("the nearby approval was cancelled; no key was accepted".to_string())
            }
            _ => return reject_unexpected(&mut session, Some(&cancellation)),
        };
        prepare_assertion(
            session,
            assertion,
            authorization,
            result,
            Some(&cancellation),
        )
    })();
    if result.is_err() {
        let cancellation_error = cancellation.ensure_active().err();
        cancellation.finish();
        if let Some(error) = cancellation_error {
            return Err(error);
        }
    }
    result
}

fn run_nearby_registration(
    pending_init: PendingIdentityInit,
) -> Result<PersistedIdentityInit, String> {
    let ConnectedNearby {
        mut session,
        session_binding,
        plan,
    } = connect_nearby(
        Operation::Register { pending_init },
        None,
        InvitationPresentation::StandaloneNearby,
    )?;
    let FlowPlan::Registration {
        request,
        challenge,
        pending_init,
    } = plan
    else {
        return Err("nearby protocol prepared assertion for registration".to_string());
    };
    let confirmation = run_sas(&mut session, &request, &session_binding, None)?;
    let (credential_id, identity) = match session.receive(CEREMONY_TIMEOUT, None)? {
        ApproverMessage::PairedRegistrationResult {
            credential_id,
            identity,
        } => (decode_credential_id(&credential_id)?, identity),
        ApproverMessage::Done {} => {
            return Err("passkey registration was cancelled on the nearby device".to_string())
        }
        _ => return reject_unexpected(&mut session, None),
    };
    let proof = decode_identity_proof(&credential_id, identity)?;
    let prepared = match pending_init.prepare_registration_pin(
        &proof,
        &NearbyRegistrationProofContext {
            confirmation: &confirmation,
            challenge: &challenge,
        },
    ) {
        Ok(prepared) => prepared,
        Err(error) => {
            report_identity_failure(&mut session, &error);
            return Err(format!("{error}; refusing to trust the registered passkey"));
        }
    };
    let registration = match prepared.commit() {
        Ok(registration) => registration,
        Err(IdentityInitCommitError::NotPublished(error)) => {
            session
                .send_final(&CliMessage::InitialRejected {
                    reason: InitialRejectedReason::IdentityStoreUnavailable,
                })
                .ok();
            return Err(format!(
                "passkey was created, but its local identity record could not be stored: {error}"
            ));
        }
        Err(IdentityInitCommitError::PublishedButNotDurable(error)) => {
            crate::remember::after_init();
            session
                .send_final(&CliMessage::InitialIndeterminate {
                    reason: InitialIndeterminateReason::IdentityDurabilityUnknown,
                })
                .ok();
            return Err(format!(
                "passkey was created and its local identity record is visible, but durable storage could not be confirmed: {error}. No success was acknowledged; rerun `keytap init --force` before relying on it"
            ));
        }
    };
    if let Err(error) = session.send_final(&CliMessage::InitialAccepted) {
        note(&format!(
            "Passkey was registered, but the nearby-device acknowledgement could not be delivered: {error}"
        ));
    }
    Ok(registration)
}

fn run_sas(
    session: &mut RelaySession,
    request: &CeremonyRequest,
    session_binding: &[u8; 32],
    cancellation: Option<&NearbyCancellation>,
) -> Result<SasConfirmation, String> {
    let request_bytes = session.send(&CliMessage::Request {
        request: request.clone(),
    })?;
    let pending = SasCommitment::generate(SasContext::bind(session_binding, &request_bytes))?;
    session.send(&CliMessage::SasCliCommit {
        commitment: URL_SAFE_NO_PAD.encode(pending.commitment()),
    })?;
    let approver_commitment = match session.receive(CEREMONY_TIMEOUT, cancellation)? {
        ApproverMessage::SasApproverCommit { commitment } => {
            decode_fixed_base64url::<32>(&commitment, "approver comparison commitment")?
        }
        ApproverMessage::SasApproverRejected {} | ApproverMessage::Done {} => {
            return Err(
                "comparison was cancelled on the nearby device; WebAuthn was not started"
                    .to_string(),
            )
        }
        _ => return reject_unexpected(session, cancellation),
    };
    let awaiting_reveal = pending.accept_approver_commitment(approver_commitment);
    session.send(&CliMessage::SasCliReveal {
        nonce: URL_SAFE_NO_PAD.encode(awaiting_reveal.cli_nonce()),
    })?;
    let approver_nonce = match session.receive(CEREMONY_TIMEOUT, cancellation)? {
        ApproverMessage::SasApproverReveal { nonce } => {
            decode_fixed_base64url::<32>(&nonce, "approver comparison nonce")?
        }
        ApproverMessage::SasApproverRejected {} | ApproverMessage::Done {} => {
            return Err(
                "comparison was cancelled on the nearby device; WebAuthn was not started"
                    .to_string(),
            )
        }
        _ => return reject_unexpected(session, cancellation),
    };
    let comparison = awaiting_reveal.accept_approver_nonce(approver_nonce)?;
    eprintln!();
    eprintln!("Compare these words with the nearby device:");
    eprintln!();
    eprintln!("    {}", comparison.phrase());
    eprintln!();
    match session.receive(CEREMONY_TIMEOUT, cancellation)? {
        ApproverMessage::SasApproverConfirmed {} => {}
        ApproverMessage::SasApproverRejected {} | ApproverMessage::Done {} => {
            return Err(
                "comparison was not confirmed on the nearby device; WebAuthn was not started"
                    .to_string(),
            )
        }
        _ => return reject_unexpected(session, cancellation),
    }
    let confirmed = match cancellation {
        Some(cancellation) => comparison.confirm_with_tty_while(|| cancellation.ensure_active()),
        None => comparison.confirm_with_tty(),
    };
    let confirmed = match confirmed {
        Ok(confirmed) => confirmed,
        Err(error) => {
            if let Some(cancellation) = cancellation {
                cancellation.ensure_active()?;
            }
            session.send_final(&CliMessage::SasCliRejected).ok();
            return Err(error);
        }
    };
    session.send(&CliMessage::SasCliConfirmed)?;
    Ok(confirmed)
}

enum PreparedIdentityAcceptance {
    Pairing(PreparedIdentityPairingPin),
    Pinned(PreparedPinnedIdentityAssertion),
}

struct DirectProofBinding {
    session_binding: [u8; 32],
    request: Vec<u8>,
}

enum AssertionAuthorization {
    FirstPair {
        anchor: IdentityPairingAnchor,
        confirmation: SasConfirmation,
    },
    PinnedIdentity {
        anchor: IdentityPinnedAnchor,
        binding: DirectProofBinding,
    },
}

enum PreparedAssertionStorage {
    Once,
    Remember { raw_key: Zeroizing<Vec<u8>> },
}

struct AssertionResult {
    credential_id: String,
    prf_first: String,
    disposition: AssertionDisposition,
    identity: IdentityProofDto,
}

struct AssertionPayload {
    credential_id: Vec<u8>,
    prf_output: Zeroizing<[u8; 32]>,
}

/// A verified result with no local side effects. Only the approval-race
/// winner may consume it through `commit`.
pub(crate) struct PreparedNearbyAssertion {
    session: RelaySession,
    key_name: String,
    identity: PreparedIdentityAcceptance,
    payload: AssertionPayload,
    storage: PreparedAssertionStorage,
}

fn prepare_assertion(
    mut session: RelaySession,
    assertion: AssertionPlan,
    authorization: AssertionAuthorization,
    result: AssertionResult,
    cancellation: Option<&NearbyCancellation>,
) -> Result<PreparedNearbyAssertion, String> {
    let disposition = authorize_disposition(assertion.storage, result.disposition)?;
    let payload = decode_assertion_fields(&result.credential_id, &result.prf_first)?;
    let proof = decode_identity_proof(&payload.credential_id, result.identity)?;
    let fields = |binding| NearbyIdentityProofContext {
        binding,
        challenge: &assertion.challenge,
        prf_output: &payload.prf_output,
        key_name: &assertion.key_name,
        disposition,
    };
    let identity = match authorization {
        AssertionAuthorization::FirstPair {
            anchor,
            confirmation,
        } => anchor
            .prepare_pin(
                &proof,
                &fields(NearbyIdentityProofBinding::FirstPairSas {
                    confirmation: &confirmation,
                }),
            )
            .map(PreparedIdentityAcceptance::Pairing),
        AssertionAuthorization::PinnedIdentity { anchor, binding } => anchor
            .prepare(
                &proof,
                &fields(NearbyIdentityProofBinding::PinnedIdentity {
                    session_binding: &binding.session_binding,
                    request: &binding.request,
                }),
            )
            .map(PreparedIdentityAcceptance::Pinned),
    };
    let identity = match identity {
        Ok(identity) => identity,
        Err(error) => {
            if let Some(cancellation) = cancellation {
                cancellation.ensure_active()?;
            }
            report_identity_failure(&mut session, &error);
            return Err(identity_error_message(error));
        }
    };
    let storage = match disposition {
        AssertionDisposition::Once => PreparedAssertionStorage::Once,
        AssertionDisposition::Remember => {
            let raw_key = Zeroizing::new(
                keytap_core::derive_raw_key(payload.prf_output.as_ref())
                    .map_err(|error| format!("key derivation failed: {error}"))?,
            );
            PreparedAssertionStorage::Remember { raw_key }
        }
    };
    Ok(PreparedNearbyAssertion {
        session,
        key_name: assertion.key_name,
        identity,
        payload,
        storage,
    })
}

impl PreparedNearbyAssertion {
    pub(crate) fn commit(self) -> Result<NearbyAssertion, String> {
        let Self {
            mut session,
            key_name,
            identity,
            payload,
            storage,
        } = self;
        match identity {
            PreparedIdentityAcceptance::Pairing(identity) => {
                commit_identity_acceptance(&mut session, identity.commit())?;
                note("Pinned this passkey identity for future nearby requests.");
            }
            PreparedIdentityAcceptance::Pinned(identity) => {
                commit_identity_acceptance(&mut session, identity.commit())?;
            }
        }
        let storage = match storage {
            PreparedAssertionStorage::Once => StorageOutcome::Once,
            PreparedAssertionStorage::Remember { raw_key } => {
                match crate::remember::remember_requested_nearby(
                    &key_name,
                    &payload.credential_id,
                    &raw_key,
                ) {
                    crate::remember::NearbyRememberOutcome::Stored => StorageOutcome::Stored,
                    crate::remember::NearbyRememberOutcome::Unavailable => {
                        StorageOutcome::Unavailable
                    }
                }
            }
        };
        if let Err(error) = session.send_final(&CliMessage::AssertionAccepted { storage }) {
            note(&format!(
                "Passkey result was accepted, but the nearby-device acknowledgement could not be delivered: {error}"
            ));
        }
        Ok(NearbyAssertion {
            credential_id: payload.credential_id,
            prf_output: payload.prf_output.to_vec(),
            storage,
        })
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn supersede(mut self) {
        self.session
            .send_final(&CliMessage::CompletedElsewhere)
            .ok();
    }
}

fn authorize_disposition(
    policy: StoragePolicy,
    disposition: AssertionDisposition,
) -> Result<AssertionDisposition, String> {
    match (policy, disposition) {
        (StoragePolicy::Choose, AssertionDisposition::Once) => Ok(AssertionDisposition::Once),
        (StoragePolicy::Choose | StoragePolicy::Remember, AssertionDisposition::Remember) => {
            Ok(AssertionDisposition::Remember)
        }
        (StoragePolicy::Remember, AssertionDisposition::Once) => {
            Err("nearby device declined local storage required by this command".to_string())
        }
    }
}

struct RelaySession {
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
    channel: SecureChannel,
}

impl RelaySession {
    fn send(&mut self, message: &CliMessage) -> Result<Vec<u8>, String> {
        let plaintext = serde_json::to_vec(message)
            .map_err(|error| format!("failed to encode nearby message: {error}"))?;
        if plaintext.len() > PLAINTEXT_LIMIT {
            return Err("nearby message exceeded the encrypted frame limit".to_string());
        }
        let frame = self.channel.seal(&plaintext)?;
        set_write_timeout(&self.socket, Some(SEND_TIMEOUT));
        self.socket
            .send(Message::Binary(frame))
            .map_err(|error| format!("approval relay connection error: {error}"))?;
        Ok(plaintext)
    }

    fn send_final(&mut self, message: &CliMessage) -> Result<(), String> {
        self.send(message)?;
        self.socket
            .flush()
            .map_err(|error| format!("approval relay connection error: {error}"))
    }

    fn send_protocol_error(&mut self, code: ProtocolErrorCode) {
        self.send_final(&CliMessage::ProtocolError { code }).ok();
    }

    fn receive(
        &mut self,
        timeout: Duration,
        cancellation: Option<&NearbyCancellation>,
    ) -> Result<ApproverMessage, String> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(cancellation) = cancellation {
                cancellation.ensure_active()?;
            }
            let message = read_relay_message(&mut self.socket, deadline, cancellation)?;
            match message {
                Message::Binary(frame) => {
                    let plaintext = match self.channel.open(&frame) {
                        Ok(plaintext) => plaintext,
                        Err(error) => {
                            self.send_protocol_error(ProtocolErrorCode::InvalidMessage);
                            return Err(error);
                        }
                    };
                    return serde_json::from_slice(&plaintext).map_err(|error| {
                        self.send_protocol_error(ProtocolErrorCode::InvalidMessage);
                        format!("invalid nearby protocol message: {error}")
                    });
                }
                Message::Ping(data) => {
                    set_write_timeout(&self.socket, Some(SEND_TIMEOUT));
                    self.socket
                        .send(Message::Pong(data))
                        .map_err(|error| format!("approval relay connection error: {error}"))?;
                }
                Message::Close(_) => {
                    return Err("the nearby device closed the approval request".to_string())
                }
                Message::Text(_) | Message::Pong(_) | Message::Frame(_) => {
                    self.send_protocol_error(ProtocolErrorCode::InvalidMessage);
                    return Err("nearby device sent a non-binary protocol frame".to_string());
                }
            }
        }
    }
}

impl Drop for RelaySession {
    fn drop(&mut self) {
        set_write_timeout(&self.socket, Some(SEND_TIMEOUT));
        self.socket.close(None).ok();
    }
}

fn connect_relay(url: &str) -> Result<WebSocket<MaybeTlsStream<TcpStream>>, String> {
    let url = url.to_string();
    run_relay_setup(RELAY_SETUP_TIMEOUT, move || {
        connect_with_config(
            url,
            Some(WebSocketConfig {
                max_message_size: Some(RELAY_FRAME_LIMIT),
                max_frame_size: Some(RELAY_FRAME_LIMIT),
                ..Default::default()
            }),
            0,
        )
        .map(|(socket, _)| socket)
        .map_err(|error| format!("could not connect to the approval relay: {error}"))
    })
}

fn run_relay_setup<T: Send + 'static>(
    timeout: Duration,
    setup: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = std::thread::Builder::new()
        .name("keytap-relay-connect".to_string())
        .spawn(move || {
            sender.send(setup()).ok();
        })
        .map_err(|error| format!("could not start approval relay setup: {error}"))?;

    match receiver.recv_timeout(timeout) {
        Ok(result) => {
            worker
                .join()
                .map_err(|_| "approval relay setup panicked".to_string())?;
            result
        }
        Err(mpsc::RecvTimeoutError::Timeout) => Err(format!(
            "timed out connecting to the approval relay after {} seconds",
            timeout.as_secs()
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            worker.join().ok();
            Err("approval relay setup stopped unexpectedly".to_string())
        }
    }
}

fn receive_browser_hello(
    socket: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    deadline: Instant,
    cancellation: Option<&NearbyCancellation>,
) -> Result<Vec<u8>, String> {
    loop {
        match read_relay_message(socket, deadline, cancellation)? {
            Message::Binary(hello) => return Ok(hello),
            Message::Ping(data) => {
                set_write_timeout(socket, Some(SEND_TIMEOUT));
                socket
                    .send(Message::Pong(data))
                    .map_err(|error| format!("approval relay connection error: {error}"))?;
            }
            Message::Close(_) => {
                return Err("the approval relay closed before the nearby device joined".to_string())
            }
            Message::Text(_) | Message::Pong(_) | Message::Frame(_) => {
                return Err("approval relay returned an invalid handshake frame".to_string())
            }
        }
    }
}

fn read_relay_message(
    socket: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    deadline: Instant,
    cancellation: Option<&NearbyCancellation>,
) -> Result<Message, String> {
    loop {
        if let Some(cancellation) = cancellation {
            cancellation.ensure_active()?;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("timed out waiting for the nearby device; run the command again for a fresh approval request".to_string());
        }
        let wait = if cancellation.is_some() {
            remaining.min(CANCELLATION_POLL_INTERVAL)
        } else {
            remaining
        };
        set_read_timeout(socket, Some(wait));
        match socket.read() {
            Ok(message) => return Ok(message),
            Err(tungstenite::Error::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => {
                if let Some(cancellation) = cancellation {
                    cancellation.ensure_active()?;
                }
                return Err(format!("approval relay connection error: {error}"));
            }
        }
    }
}

fn interrupt_stream(socket: &WebSocket<MaybeTlsStream<TcpStream>>) -> Result<TcpStream, String> {
    match socket.get_ref() {
        MaybeTlsStream::Plain(stream) => stream.try_clone(),
        MaybeTlsStream::Rustls(stream) => stream.get_ref().try_clone(),
        _ => return Err("approval relay used an unsupported TLS transport".to_string()),
    }
    .map_err(|error| format!("could not prepare nearby cancellation: {error}"))
}

fn set_read_timeout(socket: &WebSocket<MaybeTlsStream<TcpStream>>, timeout: Option<Duration>) {
    let timeout = timeout.map(|value| value.max(Duration::from_millis(1)));
    match socket.get_ref() {
        MaybeTlsStream::Plain(stream) => stream.set_read_timeout(timeout).ok(),
        MaybeTlsStream::Rustls(stream) => stream.get_ref().set_read_timeout(timeout).ok(),
        _ => None,
    };
}

fn set_write_timeout(socket: &WebSocket<MaybeTlsStream<TcpStream>>, timeout: Option<Duration>) {
    let timeout = timeout.map(|value| value.max(Duration::from_millis(1)));
    match socket.get_ref() {
        MaybeTlsStream::Plain(stream) => stream.set_write_timeout(timeout).ok(),
        MaybeTlsStream::Rustls(stream) => stream.get_ref().set_write_timeout(timeout).ok(),
        _ => None,
    };
}

fn print_invitation(url: &str, presentation: InvitationPresentation) -> Result<(), String> {
    use std::io::Write;

    let qr = qr2term::generate_qr_string(url)
        .map_err(|error| format!("failed to render QR code: {error}"))?;
    eprint!("{}", invitation_text(url, &qr, presentation));
    std::io::stderr()
        .flush()
        .map_err(|error| format!("could not show nearby approval invitation: {error}"))
}

fn invitation_text(url: &str, qr: &str, presentation: InvitationPresentation) -> String {
    match presentation {
        InvitationPresentation::StandaloneNearby => format!(
            "\nScan to approve with a passkey on a nearby device (end-to-end encrypted):\n\n\
             {qr}\nOr open: {url}\n\n\
             Waiting for the nearby device (timeout: 5 minutes)…\n"
        ),
        #[cfg(any(target_os = "macos", test))]
        InvitationPresentation::ConcurrentNativeAndNearby => format!(
            "\nApprove on this Mac, or scan to approve with a passkey on a nearby device \
             (end-to-end encrypted):\n\n\
             {qr}\nOr forward this end-to-end encrypted URL:\n\
             keytap-nearby-approval-url: {url}\n\
             The first accepted approval wins. Press Ctrl-C to cancel both.\n\n"
        ),
    }
}

#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum CeremonyRequest {
    Register {
        challenge: String,
        #[serde(rename = "identitySalt")]
        identity_salt: String,
        #[serde(rename = "userId")]
        user_id: String,
        #[serde(rename = "userName")]
        user_name: String,
    },
    Assert {
        #[serde(rename = "keyName")]
        key_name: String,
        #[serde(rename = "prfSalt")]
        prf_salt: String,
        #[serde(rename = "identitySalt")]
        identity_salt: String,
        challenge: String,
        identity: IdentityRequest,
        storage: StoragePolicy,
    },
}

#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum IdentityRequest {
    PairingAny,
    PairingCredential {
        #[serde(rename = "credentialId")]
        credential_id: String,
    },
    Pinned {
        #[serde(rename = "credentialId")]
        credential_id: String,
    },
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum CliMessage {
    Request { request: CeremonyRequest },
    SasCliCommit { commitment: String },
    SasCliReveal { nonce: String },
    SasCliConfirmed,
    SasCliRejected,
    InitialAccepted,
    InitialRejected { reason: InitialRejectedReason },
    InitialIndeterminate { reason: InitialIndeterminateReason },
    AssertionAccepted { storage: StorageOutcome },
    CompletedElsewhere,
    ProtocolError { code: ProtocolErrorCode },
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum ApproverMessage {
    SasApproverCommit {
        commitment: String,
    },
    SasApproverReveal {
        nonce: String,
    },
    SasApproverConfirmed {},
    SasApproverRejected {},
    PairedRegistrationResult {
        #[serde(rename = "credentialId")]
        credential_id: String,
        identity: IdentityProofDto,
    },
    PairedAssertionResult {
        #[serde(rename = "credentialId")]
        credential_id: String,
        #[serde(rename = "prfFirst")]
        prf_first: String,
        disposition: AssertionDisposition,
        identity: IdentityProofDto,
    },
    AssertionResult {
        #[serde(rename = "credentialId")]
        credential_id: String,
        #[serde(rename = "prfFirst")]
        prf_first: String,
        disposition: AssertionDisposition,
        identity: IdentityProofDto,
    },
    Done {},
}

#[derive(Deserialize)]
#[serde(tag = "algorithm", rename_all = "lowercase", deny_unknown_fields)]
enum IdentityProofDto {
    Ed25519 {
        #[serde(rename = "publicKey")]
        public_key: String,
        signature: String,
    },
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ProtocolErrorCode {
    InvalidMessage,
    UnexpectedMessage,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum InitialRejectedReason {
    IdentityMismatch,
    InvalidIdentityProof,
    IdentityStoreUnavailable,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum InitialIndeterminateReason {
    IdentityDurabilityUnknown,
}

fn reject_unexpected<T>(
    session: &mut RelaySession,
    cancellation: Option<&NearbyCancellation>,
) -> Result<T, String> {
    if let Some(cancellation) = cancellation {
        cancellation.ensure_active()?;
    }
    session.send_protocol_error(ProtocolErrorCode::UnexpectedMessage);
    Err("nearby device returned an unexpected protocol message".to_string())
}

fn decode_credential_id(value: &str) -> Result<Vec<u8>, String> {
    let decoded = decode_canonical(value, "credential ID")?;
    match decoded.len() {
        0 => Err("nearby device returned an empty credential ID".to_string()),
        1..=1024 => Ok(decoded),
        length => Err(format!(
            "nearby device returned a credential ID of {length} bytes; maximum is 1024"
        )),
    }
}

fn decode_assertion_fields(
    credential_id: &str,
    prf_first: &str,
) -> Result<AssertionPayload, String> {
    let credential_id = decode_credential_id(credential_id)?;
    let bytes = decode_canonical(prf_first, "PRF output")?;
    let prf_output: [u8; 32] = bytes.try_into().map_err(|value: Vec<u8>| {
        format!(
            "passkey provider returned {} bytes of PRF output; expected 32",
            value.len()
        )
    })?;
    Ok(AssertionPayload {
        credential_id,
        prf_output: Zeroizing::new(prf_output),
    })
}

fn decode_identity_proof(
    credential_id: &[u8],
    proof: IdentityProofDto,
) -> Result<NearbyIdentityProof, String> {
    let IdentityProofDto::Ed25519 {
        public_key,
        signature,
    } = proof;
    Ok(NearbyIdentityProof {
        credential_id: credential_id.to_vec(),
        public_key: decode_fixed_base64url::<32>(&public_key, "identity public key")?,
        signature: decode_fixed_base64url::<64>(&signature, "identity signature")?,
    })
}

fn decode_fixed_base64url<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    decode_canonical(value, label)?
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("invalid {label} length {}; expected {N}", bytes.len()))
}

fn decode_canonical(value: &str, label: &str) -> Result<Vec<u8>, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| format!("invalid {label} encoding"))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(format!("non-canonical {label} encoding"));
    }
    Ok(bytes)
}

fn commit_identity_acceptance(
    session: &mut RelaySession,
    result: Result<(), IdentityVerificationError>,
) -> Result<(), String> {
    match result {
        Ok(()) => Ok(()),
        Err(error) => {
            report_identity_failure(session, &error);
            Err(identity_error_message(error))
        }
    }
}

fn report_identity_failure(session: &mut RelaySession, error: &IdentityVerificationError) {
    let message = match error {
        IdentityVerificationError::IdentityMismatch => CliMessage::InitialRejected {
            reason: InitialRejectedReason::IdentityMismatch,
        },
        IdentityVerificationError::InvalidProof => CliMessage::InitialRejected {
            reason: InitialRejectedReason::InvalidIdentityProof,
        },
        IdentityVerificationError::Store(_) => CliMessage::InitialRejected {
            reason: InitialRejectedReason::IdentityStoreUnavailable,
        },
        IdentityVerificationError::DurabilityUnknown(_) => CliMessage::InitialIndeterminate {
            reason: InitialIndeterminateReason::IdentityDurabilityUnknown,
        },
    };
    session.send_final(&message).ok();
}

fn identity_error_message(error: IdentityVerificationError) -> String {
    match error {
        IdentityVerificationError::IdentityMismatch => format!(
            "{error}; refusing the returned key. If you intentionally replaced the keytap passkey, run `keytap init --force` first"
        ),
        IdentityVerificationError::InvalidProof | IdentityVerificationError::Store(_) => {
            format!("{error}; refusing the returned key")
        }
        IdentityVerificationError::DurabilityUnknown(_) => format!(
            "{error}; no success was acknowledged and the returned key was refused. Retry with a fresh approval request before relying on the pairing"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standalone_invitation_shows_qr_and_openable_url() {
        let url = "https://keytap.example/nearby#key=invitation";

        assert_eq!(
            invitation_text(url, "<QR>\n", InvitationPresentation::StandaloneNearby,),
            "\nScan to approve with a passkey on a nearby device (end-to-end encrypted):\n\n\
             <QR>\n\n\
             Or open: https://keytap.example/nearby#key=invitation\n\n\
             Waiting for the nearby device (timeout: 5 minutes)…\n"
        );
    }

    #[test]
    fn concurrent_native_invitation_shows_qr_and_forwardable_url() {
        let url = "https://keytap.example/nearby#key=invitation";

        assert_eq!(
            invitation_text(
                url,
                "<QR>\n",
                InvitationPresentation::ConcurrentNativeAndNearby,
            ),
            "\nApprove on this Mac, or scan to approve with a passkey on a nearby device \
             (end-to-end encrypted):\n\n\
             <QR>\n\n\
             Or forward this end-to-end encrypted URL:\n\
             keytap-nearby-approval-url: https://keytap.example/nearby#key=invitation\n\
             The first accepted approval wins. Press Ctrl-C to cancel both.\n\n"
        );
    }

    #[test]
    fn superseding_during_relay_setup_is_sticky() {
        let cancellation = NearbyCancellation::new();

        cancellation.supersede();
        assert_eq!(cancellation.ensure_active().unwrap_err(), SUPERSEDED_ERROR);

        let mut presented = false;
        assert_eq!(
            cancellation
                .present_invitation(|| {
                    presented = true;
                    Ok(())
                })
                .unwrap_err(),
            SUPERSEDED_ERROR
        );
        assert!(!presented);

        cancellation.finish();
        assert_eq!(cancellation.ensure_active().unwrap_err(), SUPERSEDED_ERROR);
    }

    #[test]
    fn relay_setup_returns_a_result_before_deadline() {
        assert_eq!(
            run_relay_setup(Duration::from_secs(1), || Ok(7)).unwrap(),
            7
        );
    }

    #[test]
    fn relay_setup_timeout_drops_a_late_connection() {
        struct DropNotice(mpsc::SyncSender<()>);

        impl Drop for DropNotice {
            fn drop(&mut self) {
                self.0.send(()).ok();
            }
        }

        let (dropped_tx, dropped_rx) = mpsc::sync_channel(1);
        let error = run_relay_setup(Duration::from_millis(10), move || {
            std::thread::sleep(Duration::from_millis(30));
            Ok(DropNotice(dropped_tx))
        })
        .err()
        .expect("setup should time out");

        assert!(error.contains("timed out"));
        dropped_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("late setup result should be dropped");
    }

    #[test]
    fn request_shapes_are_discriminated_and_exact() {
        let registration = CeremonyRequest::Register {
            challenge: "challenge".to_string(),
            identity_salt: "identity".to_string(),
            user_id: "user".to_string(),
            user_name: "keytap".to_string(),
        };
        assert_eq!(
            serde_json::to_value(CliMessage::Request {
                request: registration
            })
            .unwrap(),
            serde_json::json!({
                "type": "request",
                "request": {
                    "kind": "register",
                    "challenge": "challenge",
                    "identitySalt": "identity",
                    "userId": "user",
                    "userName": "keytap"
                }
            })
        );

        let request = CeremonyRequest::Assert {
            key_name: "deploy".to_string(),
            prf_salt: "salt".to_string(),
            identity_salt: "identity".to_string(),
            challenge: "challenge".to_string(),
            identity: IdentityRequest::Pinned {
                credential_id: "credential".to_string(),
            },
            storage: StoragePolicy::Choose,
        };
        assert_eq!(
            serde_json::to_value(CliMessage::Request { request }).unwrap(),
            serde_json::json!({
                "type": "request",
                "request": {
                    "kind": "assert",
                    "keyName": "deploy",
                    "prfSalt": "salt",
                    "identitySalt": "identity",
                    "challenge": "challenge",
                    "identity": {"kind": "pinned", "credentialId": "credential"},
                    "storage": "choose"
                }
            })
        );
    }

    #[test]
    fn approver_messages_reject_unknown_fields_and_states() {
        assert!(matches!(
            serde_json::from_str::<ApproverMessage>(r#"{"type":"sas-approver-confirmed"}"#)
                .unwrap(),
            ApproverMessage::SasApproverConfirmed {}
        ));
        assert!(serde_json::from_str::<ApproverMessage>(
            r#"{"type":"sas-approver-confirmed","extra":true}"#
        )
        .is_err());
        assert!(serde_json::from_str::<ApproverMessage>(r#"{"type":"unknown"}"#).is_err());
    }

    #[test]
    fn storage_policy_cannot_be_weakened() {
        assert!(matches!(
            authorize_disposition(StoragePolicy::Choose, AssertionDisposition::Once),
            Ok(AssertionDisposition::Once)
        ));
        assert!(matches!(
            authorize_disposition(StoragePolicy::Choose, AssertionDisposition::Remember),
            Ok(AssertionDisposition::Remember)
        ));
        assert!(
            authorize_disposition(StoragePolicy::Remember, AssertionDisposition::Once).is_err()
        );
    }

    #[test]
    fn result_fields_are_canonical_and_bounded() {
        let credential = URL_SAFE_NO_PAD.encode(b"credential");
        let prf = URL_SAFE_NO_PAD.encode([7; 32]);
        assert!(decode_assertion_fields(&credential, &prf).is_ok());
        assert!(decode_assertion_fields("", &prf).is_err());
        assert!(decode_assertion_fields(&format!("{credential}="), &prf).is_err());
        assert!(decode_assertion_fields(&credential, &URL_SAFE_NO_PAD.encode([7; 31])).is_err());
    }
}
