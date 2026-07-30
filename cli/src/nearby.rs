//! Authenticate with a passkey on a nearby browser over WebRTC.
//!
//! The approval-link fragment contains a one-time 32-byte CLI public key. The Worker sees
//! only a hash-derived rendezvous id. The CLI signs the full, non-trickle
//! WebRTC offer (including its DTLS fingerprint), so the approver authenticates
//! the data-channel peer before it sends any WebAuthn result.

use crate::nearby_identity::{
    Anchor as IdentityAnchor, AssertionDisposition, InitCommitError as IdentityInitCommitError,
    PairingAnchor as IdentityPairingAnchor, PairingConstraint as IdentityPairingConstraint,
    PendingInit as PendingIdentityInit, PersistedInit as PersistedIdentityInit,
    PinnedAnchor as PinnedIdentityAnchor, PreparedPairingPin as PreparedIdentityPairingPin,
    PreparedPinnedAssertion as PreparedPinnedIdentityAssertion, Proof as NearbyIdentityProof,
    ProofBinding as NearbyIdentityProofBinding, ProofContext as NearbyIdentityProofContext,
    VerificationError as IdentityVerificationError,
};
use crate::nearby_protocol::{ApproverAnswer, CliSessionKey, SignalAttempt};
use crate::nearby_sas::{
    ConfirmedComparison as SasConfirmation, Context as SasContext,
    InitiatorCommitment as SasCommitment,
};
use crate::note;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::net::TcpStream;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use tungstenite::client::connect_with_config;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
#[cfg(test)]
use webrtc::api::setting_engine::SettingEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;
use zeroize::Zeroizing;

const SIGNAL_WEBSOCKET_BASE_URL: &str = "wss://keytap-signal.julsh.workers.dev";
const SIGNAL_HTTP_BASE_URL: &str = "https://keytap-signal.julsh.workers.dev";
const PAGE_URL: &str = "https://keytap.jul.sh/nearby";
const DATA_CHANNEL_LABEL: &str = "keytap/nearby";
const DATA_CHANNEL_PROTOCOL: &str = "keytap.nearby.v1";

const PEER_JOIN_TIMEOUT: Duration = Duration::from_secs(300);
const CONNECTION_SETUP_TIMEOUT: Duration = Duration::from_secs(120);
const CEREMONY_RESPONSE_TIMEOUT: Duration = Duration::from_secs(150);
// TURN consent can precede a full 120-second WebAuthn prompt and an HTTP
// authorization round trip. Keep this independently bounded below the
// signaling room's 20-minute lifetime.
const TURN_AUTHORIZATION_TIMEOUT: Duration = Duration::from_secs(600);
const ICE_GATHER_TIMEOUT: Duration = Duration::from_secs(45);
const DATA_CHANNEL_OPEN_TIMEOUT: Duration = Duration::from_secs(60);
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const COMPLETION_TIMEOUT: Duration = Duration::from_secs(2);
const DATA_SEND_TIMEOUT: Duration = Duration::from_secs(1);
const DATA_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const DATA_DRAIN_POLL_INTERVAL: Duration = Duration::from_millis(10);
const RTC_CLOSE_TIMEOUT: Duration = Duration::from_millis(500);
const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(50);
const SIGNAL_FRAME_LIMIT: usize = 128 * 1024;
const DATA_FRAME_LIMIT: usize = 16 * 1024;
const SUPERSEDED_ERROR: &str = "nearby approval was completed on this Mac instead";
const COMPLETED_ELSEWHERE_SIGNAL: &str = r#"{"type":"completed-elsewhere"}"#;

// webrtc-rs 0.17.x currently implements TURN allocation over UDP only. Keep
// the accepted endpoints explicit so neither the signaling Worker nor a
// modified credential response can redirect the native client elsewhere.
const CLOUDFLARE_STUN_URL: &str = "stun:stun.cloudflare.com:3478";
const CLOUDFLARE_TURN_UDP_URL: &str = "turn:turn.cloudflare.com:3478?transport=udp";

/// A cancellation handle owned by the native-vs-nearby coordinator. The
/// transport valid in each phase lives inside that phase, so cancellation can
/// interrupt a blocking signaling read or an established WebRTC session
/// without parallel nullable handles.
#[derive(Clone)]
pub(crate) struct NearbyCancellation {
    inner: Arc<Mutex<NearbyCancellationState>>,
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
enum NearbyCancellationState {
    Preparing,
    Active {
        room: NearbyRoom,
        transport: NearbyTransport,
    },
    SupersededBeforeRoom,
    Superseded {
        room: NearbyRoom,
    },
    SupersededRetired,
    Finished,
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
enum NearbyTransport {
    Connecting,
    Signaling,
    PrivateChannel(RtcCancellation),
}

#[derive(Clone)]
struct NearbyRoom {
    completion_url: String,
    completion_body: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletionResponse {
    kind: CompletionOutcome,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum CompletionOutcome {
    CompletedElsewhere,
}

struct RtcCancellation {
    runtime: Arc<tokio::runtime::Runtime>,
    peer_connection: Arc<RTCPeerConnection>,
    data_channel: Arc<RTCDataChannel>,
}

impl NearbyCancellation {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(NearbyCancellationState::Preparing)),
        }
    }

    fn ensure_active(&self) -> Result<(), String> {
        match &*self
            .inner
            .lock()
            .expect("nearby cancellation lock poisoned")
        {
            NearbyCancellationState::Preparing | NearbyCancellationState::Active { .. } => Ok(()),
            NearbyCancellationState::SupersededBeforeRoom
            | NearbyCancellationState::Superseded { .. }
            | NearbyCancellationState::SupersededRetired => Err(SUPERSEDED_ERROR.to_string()),
            NearbyCancellationState::Finished => {
                Err("nearby approval session already finished".to_string())
            }
        }
    }

    fn register_room(&self, completion_url: String, completion_body: String) -> Result<(), String> {
        let room = NearbyRoom {
            completion_url,
            completion_body,
        };
        let mut state = self
            .inner
            .lock()
            .expect("nearby cancellation lock poisoned");
        match std::mem::replace(&mut *state, NearbyCancellationState::Finished) {
            NearbyCancellationState::Preparing => {
                *state = NearbyCancellationState::Active {
                    room,
                    transport: NearbyTransport::Connecting,
                };
                Ok(())
            }
            NearbyCancellationState::SupersededBeforeRoom => {
                *state = NearbyCancellationState::Superseded { room };
                Err(SUPERSEDED_ERROR.to_string())
            }
            invalid @ (NearbyCancellationState::Active { .. }
            | NearbyCancellationState::Superseded { .. }
            | NearbyCancellationState::SupersededRetired
            | NearbyCancellationState::Finished) => {
                *state = invalid;
                Err("nearby cancellation entered an invalid room state".to_string())
            }
        }
    }

    fn register_signaling(&self) -> Result<(), String> {
        let mut state = self
            .inner
            .lock()
            .expect("nearby cancellation lock poisoned");
        match std::mem::replace(&mut *state, NearbyCancellationState::Finished) {
            NearbyCancellationState::Active {
                room,
                transport: NearbyTransport::Connecting,
            } => {
                *state = NearbyCancellationState::Active {
                    room,
                    transport: NearbyTransport::Signaling,
                };
                Ok(())
            }
            superseded @ (NearbyCancellationState::SupersededBeforeRoom
            | NearbyCancellationState::Superseded { .. }
            | NearbyCancellationState::SupersededRetired) => {
                *state = superseded;
                Err(SUPERSEDED_ERROR.to_string())
            }
            invalid @ (NearbyCancellationState::Preparing
            | NearbyCancellationState::Active { .. }
            | NearbyCancellationState::Finished) => {
                *state = invalid;
                Err("nearby cancellation entered an invalid signaling state".to_string())
            }
        }
    }

    fn register_private_channel(&self, session: &RtcSession) -> Result<(), String> {
        let private = RtcCancellation {
            runtime: Arc::clone(&session.runtime),
            peer_connection: Arc::clone(&session.peer_connection),
            data_channel: Arc::clone(&session.data_channel),
        };
        enum Registration {
            Registered,
            Superseded(RtcCancellation),
            Invalid,
        }
        let registration = {
            let mut state = self
                .inner
                .lock()
                .expect("nearby cancellation lock poisoned");
            match std::mem::replace(&mut *state, NearbyCancellationState::Finished) {
                NearbyCancellationState::Active {
                    room,
                    transport: NearbyTransport::Signaling,
                } => {
                    *state = NearbyCancellationState::Active {
                        room,
                        transport: NearbyTransport::PrivateChannel(private),
                    };
                    Registration::Registered
                }
                superseded @ (NearbyCancellationState::SupersededBeforeRoom
                | NearbyCancellationState::Superseded { .. }
                | NearbyCancellationState::SupersededRetired) => {
                    *state = superseded;
                    Registration::Superseded(private)
                }
                invalid @ (NearbyCancellationState::Preparing
                | NearbyCancellationState::Active { .. }
                | NearbyCancellationState::Finished) => {
                    *state = invalid;
                    Registration::Invalid
                }
            }
        };
        match registration {
            Registration::Registered => Ok(()),
            Registration::Superseded(private) => {
                private.supersede();
                Err(SUPERSEDED_ERROR.to_string())
            }
            Registration::Invalid => {
                Err("nearby cancellation entered an invalid private-channel state".to_string())
            }
        }
    }

    /// Native approval won. Notify an already-connected approver when possible,
    /// then close whichever nearby transport is currently blocking.
    #[cfg(target_os = "macos")]
    pub(crate) fn supersede(&self) {
        let transport = {
            let mut state = self
                .inner
                .lock()
                .expect("nearby cancellation lock poisoned");
            match std::mem::replace(&mut *state, NearbyCancellationState::Finished) {
                NearbyCancellationState::Preparing => {
                    *state = NearbyCancellationState::SupersededBeforeRoom;
                    None
                }
                NearbyCancellationState::Active { room, transport } => {
                    *state = NearbyCancellationState::Superseded { room };
                    Some(transport)
                }
                superseded @ (NearbyCancellationState::SupersededBeforeRoom
                | NearbyCancellationState::Superseded { .. }
                | NearbyCancellationState::SupersededRetired) => {
                    *state = superseded;
                    None
                }
                NearbyCancellationState::Finished => None,
            }
        };
        let Some(transport) = transport else {
            return;
        };
        match transport {
            NearbyTransport::PrivateChannel(private) => private.supersede(),
            NearbyTransport::Connecting | NearbyTransport::Signaling => {}
        }
        self.retire_superseded_url();
    }

    /// Publish the idempotent terminal transition. The native coordinator and
    /// the unwinding worker may both try; only a confirmed HTTP success marks
    /// the room retired, so one transient failure cannot suppress the other.
    pub(crate) fn retire_superseded_url(&self) {
        let cleanup_room = {
            let state = self
                .inner
                .lock()
                .expect("nearby cancellation lock poisoned");
            match &*state {
                NearbyCancellationState::Superseded { room } => Some(room.clone()),
                NearbyCancellationState::Preparing
                | NearbyCancellationState::Active { .. }
                | NearbyCancellationState::SupersededBeforeRoom
                | NearbyCancellationState::SupersededRetired
                | NearbyCancellationState::Finished => None,
            }
        };
        let Some(cleanup_room) = cleanup_room else {
            return;
        };
        if cleanup_room.tombstone() {
            self.mark_superseded_url_retired();
        }
    }

    fn mark_superseded_url_retired(&self) {
        let mut state = self
            .inner
            .lock()
            .expect("nearby cancellation lock poisoned");
        match &*state {
            NearbyCancellationState::Superseded { .. } => {
                *state = NearbyCancellationState::SupersededRetired;
            }
            NearbyCancellationState::Preparing
            | NearbyCancellationState::Active { .. }
            | NearbyCancellationState::SupersededBeforeRoom
            | NearbyCancellationState::SupersededRetired
            | NearbyCancellationState::Finished => {}
        }
    }

    pub(crate) fn finish(&self) {
        let mut state = self
            .inner
            .lock()
            .expect("nearby cancellation lock poisoned");
        match std::mem::replace(&mut *state, NearbyCancellationState::Finished) {
            NearbyCancellationState::Preparing | NearbyCancellationState::Active { .. } => {}
            NearbyCancellationState::SupersededBeforeRoom => {
                *state = NearbyCancellationState::SupersededBeforeRoom;
            }
            NearbyCancellationState::Superseded { room } => {
                *state = NearbyCancellationState::Superseded { room };
            }
            NearbyCancellationState::SupersededRetired => {
                *state = NearbyCancellationState::SupersededRetired;
            }
            NearbyCancellationState::Finished => {
                *state = NearbyCancellationState::Finished;
            }
        }
    }
}

impl NearbyRoom {
    fn tombstone(self) -> bool {
        let deadline = Instant::now() + COMPLETION_TIMEOUT;
        let mut last_error = None;
        for retry_delay in [0, 25, 75, 150] {
            if retry_delay != 0 {
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    break;
                };
                std::thread::sleep(Duration::from_millis(retry_delay).min(remaining));
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            match self.try_tombstone(remaining.min(Duration::from_millis(500))) {
                Ok(()) => return true,
                Err(error) => last_error = Some(error),
            }
        }
        if let Some(error) = last_error {
            note(&format!(
                "warning: could not mark the nearby approval URL complete ({error})"
            ));
        }
        false
    }

    fn try_tombstone(&self, timeout: Duration) -> Result<(), String> {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(timeout.max(Duration::from_millis(1))))
            .http_status_as_error(false)
            .max_redirects(0)
            .build()
            .into();
        let mut response = agent
            .post(&self.completion_url)
            .header("Content-Type", "application/json")
            .send(self.completion_body.as_bytes())
            .map_err(|error| format!("failed to retire nearby approval URL: {error}"))?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(format!(
                "nearby service rejected URL retirement (HTTP {status})"
            ));
        }
        let body = response
            .body_mut()
            .with_config()
            .limit(1024)
            .read_to_string()
            .map_err(|error| format!("could not read nearby URL retirement response: {error}"))?;
        let CompletionResponse {
            kind: CompletionOutcome::CompletedElsewhere,
        } = serde_json::from_str(&body).map_err(|_| {
            "nearby service returned an invalid URL retirement response".to_string()
        })?;
        Ok(())
    }
}

fn send_data_text_bounded(
    runtime: &tokio::runtime::Runtime,
    data_channel: &RTCDataChannel,
    text: String,
) -> Result<(), String> {
    runtime.block_on(async {
        tokio::time::timeout(DATA_SEND_TIMEOUT, data_channel.send_text(text))
            .await
            .map_err(|_| "timed out queueing a nearby message".to_string())?
            .map(|_| ())
            .map_err(|error| format!("failed to send nearby message: {error}"))
    })
}

fn send_data_text_and_drain_bounded(
    runtime: &tokio::runtime::Runtime,
    data_channel: &RTCDataChannel,
    text: String,
) -> Result<(), String> {
    runtime.block_on(async {
        tokio::time::timeout(DATA_SEND_TIMEOUT, data_channel.send_text(text))
            .await
            .map_err(|_| "timed out queueing a nearby terminal message".to_string())?
            .map_err(|error| format!("failed to send nearby terminal message: {error}"))?;
        tokio::time::timeout(DATA_DRAIN_TIMEOUT, async {
            while data_channel.buffered_amount().await != 0 {
                tokio::time::sleep(DATA_DRAIN_POLL_INTERVAL).await;
            }
        })
        .await
        .map_err(|_| "timed out delivering a nearby terminal message".to_string())
    })
}

fn close_rtc_bounded(
    runtime: &tokio::runtime::Runtime,
    peer_connection: &RTCPeerConnection,
    data_channel: &RTCDataChannel,
) {
    runtime.block_on(async {
        tokio::time::timeout(RTC_CLOSE_TIMEOUT, async {
            data_channel.close().await.ok();
            peer_connection.close().await.ok();
        })
        .await
        .ok();
    });
}

fn block_on_cancellable<F>(
    runtime: &tokio::runtime::Runtime,
    future: F,
    cancellation: Option<&NearbyCancellation>,
) -> Result<F::Output, String>
where
    F: Future,
{
    if let Some(cancellation) = cancellation {
        cancellation.ensure_active()?;
    }
    runtime.block_on(async {
        tokio::pin!(future);
        loop {
            tokio::select! {
                biased;
                output = &mut future => return Ok(output),
                _ = tokio::time::sleep(CANCELLATION_POLL_INTERVAL), if cancellation.is_some() => {
                    cancellation.expect("guarded cancellation branch").ensure_active()?;
                }
            }
        }
    })
}

impl RtcCancellation {
    fn supersede(self) {
        let Self {
            runtime,
            peer_connection,
            data_channel,
        } = self;
        if let Ok(message) = serde_json::to_string(&CliMessage::CompletedElsewhere) {
            send_data_text_and_drain_bounded(&runtime, &data_channel, message).ok();
        }
        close_rtc_bounded(&runtime, &peer_connection, &data_channel);
    }
}

/// A completed nearby assertion ceremony.
pub struct NearbyAssertion {
    pub prf_output: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub storage: StorageOutcome,
}

/// Authenticate via a nearby device. `storage_policy` controls whether the
/// approver may request local storage before performing its single assertion.
#[cfg(not(target_os = "macos"))]
pub fn authenticate_nearby(name: &str, storage_policy: StoragePolicy) -> NearbyAssertion {
    authenticate_nearby_with_presentation(name, storage_policy, InvitationPresentation::QrAndUrl)
}

#[cfg(not(target_os = "macos"))]
fn authenticate_nearby_with_presentation(
    name: &str,
    storage_policy: StoragePolicy,
    presentation: InvitationPresentation,
) -> NearbyAssertion {
    let cancellation = NearbyCancellation::new();
    let prepared = prepare_nearby_assertion_with_presentation(
        name,
        storage_policy,
        cancellation.clone(),
        presentation,
        || {},
    )
    .unwrap_or_else(|error| crate::die(&error));
    cancellation.finish();
    prepared.commit().unwrap_or_else(|error| crate::die(&error))
}

/// Prepare a nearby assertion for arbitration against the native macOS
/// prompt. The URL is deliberately printed before any network wait so an
/// unattended agent can forward it immediately.
#[cfg(target_os = "macos")]
pub(crate) fn prepare_nearby_assertion(
    name: &str,
    storage_policy: StoragePolicy,
    cancellation: NearbyCancellation,
    invitation_ready: impl FnOnce(),
) -> Result<PreparedNearbyAssertion, String> {
    prepare_nearby_assertion_with_presentation(
        name,
        storage_policy,
        cancellation,
        InvitationPresentation::ForwardableUrl,
        invitation_ready,
    )
}

/// Register a passkey via a nearby device.
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

/// Everything valid only for one ceremony kind lives in that variant.
enum FlowPlan {
    Registration {
        request: PairingCeremonyRequest,
        pending_init: PendingIdentityInit,
    },
    PairingAssertion {
        assertion: AssertionPlan,
        anchor: IdentityPairingAnchor,
    },
    PinnedAssertion {
        assertion: AssertionPlan,
        anchor: PinnedIdentityAnchor,
    },
}

/// Canonical local assertion data. Wire requests are derived from this value at
/// the send boundary, so encoded request fields cannot disagree with the data
/// later used to verify the returned identity proof.
struct AssertionPlan {
    key_name: String,
    prf_salt: Vec<u8>,
    identity_salt: [u8; 32],
    challenge: [u8; 32],
    storage: StoragePolicy,
}

impl AssertionPlan {
    fn pairing_request(&self, constraint: IdentityPairingConstraint<'_>) -> PairingCeremonyRequest {
        let identity = match constraint {
            IdentityPairingConstraint::AnyPasskey => PairingIdentityRequest::Any,
            IdentityPairingConstraint::Credential { credential_id } => {
                PairingIdentityRequest::Credential {
                    credential_id: URL_SAFE_NO_PAD.encode(credential_id),
                }
            }
        };
        PairingCeremonyRequest::Assert {
            key_name: self.key_name.clone(),
            prf_salt: URL_SAFE_NO_PAD.encode(&self.prf_salt),
            identity_salt: URL_SAFE_NO_PAD.encode(self.identity_salt),
            challenge: URL_SAFE_NO_PAD.encode(self.challenge),
            identity,
            storage: self.storage,
        }
    }

    fn pinned_request(&self, credential_id: &[u8]) -> PinnedCeremonyRequest {
        PinnedCeremonyRequest::Assert {
            key_name: self.key_name.clone(),
            prf_salt: URL_SAFE_NO_PAD.encode(&self.prf_salt),
            identity_salt: URL_SAFE_NO_PAD.encode(self.identity_salt),
            challenge: URL_SAFE_NO_PAD.encode(self.challenge),
            identity: PinnedIdentityRequest::Pinned {
                credential_id: URL_SAFE_NO_PAD.encode(credential_id),
            },
            storage: self.storage,
        }
    }
}

enum AuthenticatedIdentity {
    Pairing {
        anchor: IdentityPairingAnchor,
        confirmation: SasConfirmation,
    },
    Pinned {
        anchor: PinnedIdentityAnchor,
        session_digest: [u8; 32],
    },
}

enum BufferedPairingResult {
    Registration {
        credential_id: String,
    },
    Assertion {
        credential_id: String,
        prf_first: String,
        disposition: AssertionDisposition,
        proof: IdentityProofDto,
    },
}

enum PairingAuthorization {
    Registration {
        credential_id: String,
    },
    Assertion {
        confirmation: SasConfirmation,
        credential_id: String,
        prf_first: String,
        disposition: AssertionDisposition,
        proof: IdentityProofDto,
    },
}

struct AssertionCompletion {
    key_name: String,
    challenge: [u8; 32],
    storage: StoragePolicy,
    identity: AuthenticatedIdentity,
    credential_id: String,
    prf_first: String,
    disposition: AssertionDisposition,
    proof: IdentityProofDto,
}

enum PreparedIdentityAcceptance {
    Pairing(PreparedIdentityPairingPin),
    Pinned(PreparedPinnedIdentityAssertion),
}

enum PreparedAssertionStorage {
    Once,
    Remember { raw_key: Zeroizing<Vec<u8>> },
}

/// A fully parsed and cryptographically verified approver result. It owns the
/// live session needed for the final acknowledgement, but has not pinned an
/// identity, stored a key, or acknowledged success. Only the approval-race
/// winner may consume it through `commit`.
pub(crate) struct PreparedNearbyAssertion {
    session: RtcSession,
    key_name: String,
    identity: PreparedIdentityAcceptance,
    payload: AssertionPayload,
    storage: PreparedAssertionStorage,
}

struct ConnectedNearby {
    session: RtcSession,
    identity_binding: [u8; 32],
    plan: FlowPlan,
}

#[derive(Clone, Copy)]
enum InvitationPresentation {
    QrAndUrl,
    #[cfg(target_os = "macos")]
    ForwardableUrl,
}

#[derive(Clone, Copy)]
enum AuthorizedDisposition {
    Once,
    Remember,
}

enum IceCandidateScope {
    NetworkInterfaces,
    #[cfg(test)]
    IncludeLoopback,
}

enum DataChannelEstablishmentFailure {
    Failed(String),
    TimedOut,
}

#[derive(Debug)]
enum IceGatheringFailure {
    Setup(String),
    TimedOut,
}

/// Only failures reached while gathering ICE or opening the data channel
/// inhabit this type. Signaling, authentication, SDP parsing, and peer
/// construction errors stay ordinary errors and never trigger a second offer.
enum ConnectivityFailure {
    IceGatheringTimedOut,
    DataChannel(DataChannelEstablishmentFailure),
}

struct ConnectedAttempt {
    peer_connection: Arc<RTCPeerConnection>,
    data_channel: Arc<RTCDataChannel>,
    incoming: mpsc::Receiver<DataChannelEvent>,
    offer_sdp: String,
    answer_sdp: String,
}

struct PreparedAttempt {
    peer_connection: Arc<RTCPeerConnection>,
    data_channel: Arc<RTCDataChannel>,
    open_rx: mpsc::Receiver<EstablishmentEvent>,
    incoming: mpsc::Receiver<DataChannelEvent>,
    offer_sdp: String,
}

enum PreparedAttemptOutcome {
    Prepared(PreparedAttempt),
    ConnectivityFailed(ConnectivityFailure),
}

enum ConnectionAttemptOutcome {
    Connected(ConnectedAttempt),
    ConnectivityFailed(ConnectivityFailure),
}

enum DirectConnectionAttemptOutcome {
    Connected(ConnectedAttempt),
    CliConnectivityFailed(ConnectivityFailure),
    ApproverDirectConnectivityFailed {
        authorization: TurnAuthorizationOutcome,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum TurnUnavailableReason {
    NotAllowlisted,
    Cancelled,
    PasskeyUnavailable,
    ProviderUnavailable,
}

enum TurnAuthorizationOutcome {
    Authorized { capability: TurnCapability },
    Unavailable(TurnUnavailableReason),
}

/// A room-bound bearer capability issued only after the Worker verifies the
/// approver's Ed25519 passkey-identity proof. Construction is restricted to the
/// strict signaling parse boundary below.
#[derive(Clone)]
struct TurnCapability([u8; 64]);

impl TurnCapability {
    fn parse(encoded: &str) -> Result<Self, &'static str> {
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| "TURN capability is not canonical base64url")?;
        if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
            return Err("TURN capability is not canonical base64url");
        }
        let signature = decoded
            .try_into()
            .map_err(|_| "TURN capability must contain exactly 64 bytes")?;
        Ok(Self(signature))
    }

    fn bearer_header_value(&self) -> String {
        format!("Bearer {}", URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl<'de> Deserialize<'de> for TurnCapability {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        Self::parse(&encoded).map_err(serde::de::Error::custom)
    }
}

/// A direct attempt can fail on either WebRTC endpoint. When it fails on the
/// approver before an answer exists, the approver may finish TURN authorization
/// while the CLI is still waiting for that answer.
enum DirectAttemptRetry {
    CliConnectivityFailure(ConnectivityFailure),
    ApproverConnectivityFailure {
        authorization: TurnAuthorizationOutcome,
    },
}

enum DirectAnswerWaitOutcome {
    Answer(String),
    ApproverDirectConnectivityFailed {
        authorization: TurnAuthorizationOutcome,
    },
}

impl ConnectivityFailure {
    fn final_error(self) -> String {
        match self {
            Self::IceGatheringTimedOut => {
                "timed out gathering ICE candidates for the WebRTC offer".to_string()
            }
            Self::DataChannel(DataChannelEstablishmentFailure::Failed(error)) => error,
            Self::DataChannel(DataChannelEstablishmentFailure::TimedOut) => {
                "timed out establishing the encrypted WebRTC data channel".to_string()
            }
        }
    }
}

fn turn_unavailable_error(direct: String, reason: TurnUnavailableReason) -> String {
    match reason {
        TurnUnavailableReason::NotAllowlisted => format!(
            "{direct}; the direct peer-to-peer connection failed, and this passkey identity is not on the TURN allowlist. TURN is limited to approved passkeys because it consumes shared Cloudflare quota"
        ),
        TurnUnavailableReason::Cancelled => format!(
            "{direct}; the direct peer-to-peer connection failed, and TURN authorization was cancelled on the nearby device"
        ),
        TurnUnavailableReason::PasskeyUnavailable => format!(
            "{direct}; the direct peer-to-peer connection failed, and the passkey on the nearby device could not produce the identity proof required for TURN"
        ),
        TurnUnavailableReason::ProviderUnavailable => format!(
            "{direct}; the direct peer-to-peer connection failed, and TURN relay is temporarily unavailable"
        ),
    }
}

fn prepare_nearby_assertion_with_presentation(
    name: &str,
    storage_policy: StoragePolicy,
    cancellation: NearbyCancellation,
    presentation: InvitationPresentation,
    invitation_ready: impl FnOnce(),
) -> Result<PreparedNearbyAssertion, String> {
    let result = (|| {
        let ConnectedNearby {
            session,
            identity_binding,
            plan,
        } = connect_nearby(
            Operation::Assert {
                name,
                storage_policy,
            },
            Some(&cancellation),
            presentation,
            invitation_ready,
        )?;
        match plan {
            FlowPlan::PairingAssertion { assertion, anchor } => {
                let request = assertion.pairing_request(anchor.constraint());
                let (confirmation, credential_id, prf_first, disposition, proof) =
                    match run_pairing(&session, request, &identity_binding, Some(&cancellation))? {
                        PairingAuthorization::Assertion {
                            confirmation,
                            credential_id,
                            prf_first,
                            disposition,
                            proof,
                        } => (confirmation, credential_id, prf_first, disposition, proof),
                        PairingAuthorization::Registration { .. } => {
                            return reject_unexpected_pairing(&session, Some(&cancellation))
                        }
                    };
                prepare_assertion(
                    session,
                    AssertionCompletion {
                        key_name: assertion.key_name,
                        challenge: assertion.challenge,
                        storage: assertion.storage,
                        identity: AuthenticatedIdentity::Pairing {
                            anchor,
                            confirmation,
                        },
                        credential_id,
                        prf_first,
                        disposition,
                        proof,
                    },
                    Some(&cancellation),
                )
            }
            FlowPlan::PinnedAssertion { assertion, anchor } => {
                let request = assertion.pinned_request(anchor.credential_id());
                cancellation.ensure_active()?;
                session.send(&CliMessage::Request { request })?;
                match session.receive(CEREMONY_RESPONSE_TIMEOUT, Some(&cancellation))? {
                    ApproverMessage::AssertionResult {
                        credential_id,
                        prf_first,
                        disposition,
                        identity: proof,
                    } => prepare_assertion(
                        session,
                        AssertionCompletion {
                            key_name: assertion.key_name,
                            challenge: assertion.challenge,
                            storage: assertion.storage,
                            identity: AuthenticatedIdentity::Pinned {
                                anchor,
                                session_digest: identity_binding,
                            },
                            credential_id,
                            prf_first,
                            disposition,
                            proof,
                        },
                        Some(&cancellation),
                    ),
                    ApproverMessage::Done => {
                        Err("the page on the nearby device was closed before approving".into())
                    }
                    _ => {
                        cancellation.ensure_active()?;
                        session.send_protocol_error(ProtocolErrorCode::UnexpectedMessage);
                        Err("nearby device returned an unexpected protocol message".into())
                    }
                }
            }
            FlowPlan::Registration { .. } => {
                Err("nearby protocol prepared a registration for an assertion request".into())
            }
        }
    })();
    if result.is_err() {
        let cancellation_error = cancellation.ensure_active().err();
        if cancellation_error.as_deref() == Some(SUPERSEDED_ERROR) {
            cancellation.retire_superseded_url();
        }
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
        session,
        identity_binding,
        plan,
    } = connect_nearby(
        Operation::Register { pending_init },
        None,
        InvitationPresentation::QrAndUrl,
        || {},
    )?;
    let FlowPlan::Registration {
        request,
        pending_init,
    } = plan
    else {
        return Err("nearby protocol prepared an assertion for a registration request".into());
    };
    let credential_id = match run_pairing(&session, request, &identity_binding, None)? {
        PairingAuthorization::Registration { credential_id } => credential_id,
        PairingAuthorization::Assertion { .. } => return reject_unexpected_pairing(&session, None),
    };
    let credential_id = decode_credential_id(&credential_id)?;
    let registration = match pending_init.commit(&credential_id) {
        Ok(registration) => registration,
        Err(IdentityInitCommitError::NotPublished(error)) => {
            session
                .send_final(&CliMessage::InitialRejected {
                    reason: InitialRejectedReason::IdentityStoreUnavailable,
                })
                .ok();
            return Err(format!(
                "passkey was created, but its paired identity could not be stored: {error}"
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
                "passkey was created and its paired identity is visible, but durable storage could not be confirmed: {error}. No success was acknowledged; rerun `keytap init --force` before relying on it"
            ));
        }
    };
    if let Err(error) = session.send_final(&CliMessage::InitialAccepted) {
        note(&format!(
            "Passkey identity was stored, but the nearby-device acknowledgement could not be delivered: {error}"
        ));
    }
    Ok(registration)
}

fn connect_nearby(
    operation: Operation<'_>,
    cancellation: Option<&NearbyCancellation>,
    presentation: InvitationPresentation,
    invitation_ready: impl FnOnce(),
) -> Result<ConnectedNearby, String> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    // Validate all local inputs before showing the approval request or asking
    // the user to touch another device.
    let plan = build_plan(operation)?;

    let cli_session_key = CliSessionKey::generate();
    let rendezvous_id = cli_session_key.rendezvous_id();
    let ws_url = format!("{SIGNAL_WEBSOCKET_BASE_URL}/signal/{rendezvous_id}?role=cli");
    if let Some(cancellation) = cancellation {
        let completion_url = format!("{SIGNAL_HTTP_BASE_URL}/signal/{rendezvous_id}/complete");
        let completion_body = serde_json::to_string(&cli_session_key.sign_completion())
            .map_err(|error| format!("failed to encode nearby URL retirement proof: {error}"))?;
        cancellation.register_room(completion_url, completion_body)?;
    }

    let url = format!("{PAGE_URL}#key={}", cli_session_key.fragment_value());
    match presentation {
        InvitationPresentation::QrAndUrl => print_qr(&url)?,
        #[cfg(target_os = "macos")]
        InvitationPresentation::ForwardableUrl => print_forwardable_url(&url)?,
    }
    invitation_ready();
    if let Some(cancellation) = cancellation {
        cancellation.ensure_active()?;
    }

    let mut signaling = connect_signaling(&ws_url)?;
    if let Some(cancellation) = cancellation {
        if let Err(error) = cancellation.register_signaling() {
            set_ws_write_timeout(&signaling, Some(DATA_SEND_TIMEOUT));
            signaling
                .send(Message::Text(COMPLETED_ELSEWHERE_SIGNAL.to_string()))
                .ok();
            signaling.close(None).ok();
            return Err(error);
        }
    }

    let peer_join_deadline = Instant::now() + PEER_JOIN_TIMEOUT;
    let peer = wait_for_peer(&mut signaling, peer_join_deadline, cancellation);
    if let Some(cancellation) = cancellation {
        cancellation.ensure_active()?;
    }
    peer?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("keytap-webrtc")
        .build()
        .map_err(|error| format!("failed to start WebRTC runtime: {error}"))?;

    let connected_result = match run_direct_connection_attempt(
        &runtime,
        &mut signaling,
        &cli_session_key,
        stun_only_ice_servers(),
        Instant::now() + CONNECTION_SETUP_TIMEOUT,
        cancellation,
    )? {
        DirectConnectionAttemptOutcome::Connected(connected) => connected,
        DirectConnectionAttemptOutcome::CliConnectivityFailed(failure) => run_turn_retry(
            &runtime,
            &mut signaling,
            &cli_session_key,
            &rendezvous_id,
            DirectAttemptRetry::CliConnectivityFailure(failure),
            cancellation,
        )?,
        DirectConnectionAttemptOutcome::ApproverDirectConnectivityFailed { authorization } => {
            run_turn_retry(
                &runtime,
                &mut signaling,
                &cli_session_key,
                &rendezvous_id,
                DirectAttemptRetry::ApproverConnectivityFailure { authorization },
                cancellation,
            )?
        }
    };
    if let Some(cancellation) = cancellation {
        cancellation.ensure_active()?;
    }
    let connected = connected_result;

    let identity_binding = cli_session_key.identity_session_binding(
        connected.offer_sdp.as_bytes(),
        connected.answer_sdp.as_bytes(),
    );
    signaling.close(None).ok();
    drop(signaling);

    let session = RtcSession {
        runtime: Arc::new(runtime),
        peer_connection: connected.peer_connection,
        data_channel: connected.data_channel,
        incoming: connected.incoming,
    };
    if let Some(cancellation) = cancellation {
        cancellation.register_private_channel(&session)?;
    }
    Ok(ConnectedNearby {
        session,
        identity_binding,
        plan,
    })
}

fn run_turn_retry(
    runtime: &tokio::runtime::Runtime,
    signaling: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    cli_session_key: &CliSessionKey,
    rendezvous_id: &str,
    direct_retry: DirectAttemptRetry,
    cancellation: Option<&NearbyCancellation>,
) -> Result<ConnectedAttempt, String> {
    let (direct_failure, authorization) = match direct_retry {
        DirectAttemptRetry::CliConnectivityFailure(failure) => {
            send_signal(signaling, &CliSignalMessage::TurnRequired, cancellation)?;
            (
                failure.final_error(),
                wait_for_turn_authorization(
                    signaling,
                    Instant::now() + TURN_AUTHORIZATION_TIMEOUT,
                    cancellation,
                )?,
            )
        }
        DirectAttemptRetry::ApproverConnectivityFailure { authorization } => (
            "the nearby device could not establish the direct peer-to-peer WebRTC connection"
                .to_string(),
            authorization,
        ),
    };
    let capability = match authorization {
        TurnAuthorizationOutcome::Unavailable(reason) => {
            return Err(turn_unavailable_error(direct_failure, reason))
        }
        TurnAuthorizationOutcome::Authorized { capability } => capability,
    };

    let turn_url = format!("{SIGNAL_HTTP_BASE_URL}/signal/{rendezvous_id}/turn");
    let turn_ice_servers = match fetch_turn_ice_servers_cancellable(
        &turn_url,
        &capability,
        Instant::now() + CONNECTION_SETUP_TIMEOUT,
        cancellation,
    )? {
        Ok(ice_servers) => ice_servers,
        Err(TurnCredentialFetchError::AuthorizationRejected) => {
            return Err(turn_unavailable_error(
                direct_failure,
                TurnUnavailableReason::NotAllowlisted,
            ))
        }
        Err(TurnCredentialFetchError::Unavailable(error)) => {
            note(&format!("warning: TURN relay is unavailable ({error})"));
            return Err(turn_unavailable_error(
                direct_failure,
                TurnUnavailableReason::ProviderUnavailable,
            ));
        }
    };

    note("Direct peer-to-peer connection failed; retrying with TURN relay.");
    match run_turn_connection_attempt(
        runtime,
        signaling,
        cli_session_key,
        turn_ice_servers,
        Instant::now() + CONNECTION_SETUP_TIMEOUT,
        cancellation,
    )? {
        ConnectionAttemptOutcome::Connected(connected) => Ok(connected),
        ConnectionAttemptOutcome::ConnectivityFailed(failure) => Err(failure.final_error()),
    }
}

fn prepare_assertion(
    session: RtcSession,
    completion: AssertionCompletion,
    cancellation: Option<&NearbyCancellation>,
) -> Result<PreparedNearbyAssertion, String> {
    let AssertionCompletion {
        key_name,
        challenge,
        storage,
        identity,
        credential_id,
        prf_first,
        disposition,
        proof,
    } = completion;
    let disposition = match authorize_disposition(storage, disposition) {
        Ok(disposition) => disposition,
        Err(error) => {
            if let Some(cancellation) = cancellation {
                cancellation.ensure_active()?;
            }
            session.send_protocol_error(ProtocolErrorCode::UnexpectedMessage);
            return Err(error);
        }
    };
    let payload = decode_assertion_fields(&credential_id, &prf_first)?;
    let proof = decode_identity_proof(&payload.credential_id, proof)?;
    let identity = match identity {
        AuthenticatedIdentity::Pairing {
            anchor,
            confirmation,
        } => {
            let context = NearbyIdentityProofContext {
                binding: NearbyIdentityProofBinding::BootstrapSas {
                    confirmation: &confirmation,
                },
                challenge: &challenge,
                prf_output: &payload.prf_output,
                key_name: &key_name,
                disposition: disposition.proof_value(),
            };
            anchor
                .prepare_pin_after_sas(&proof, &context)
                .map(PreparedIdentityAcceptance::Pairing)
        }
        AuthenticatedIdentity::Pinned {
            anchor,
            session_digest,
        } => {
            let context = NearbyIdentityProofContext {
                binding: NearbyIdentityProofBinding::PinnedSession {
                    digest: &session_digest,
                },
                challenge: &challenge,
                prf_output: &payload.prf_output,
                key_name: &key_name,
                disposition: disposition.proof_value(),
            };
            anchor
                .prepare(&proof, &context)
                .map(PreparedIdentityAcceptance::Pinned)
        }
    };
    let identity = match identity {
        Ok(identity) => identity,
        Err(error) => {
            if let Some(cancellation) = cancellation {
                cancellation.ensure_active()?;
            }
            report_identity_failure(&session, &error);
            return Err(identity_error_message(error));
        }
    };
    let storage = match disposition {
        AuthorizedDisposition::Once => PreparedAssertionStorage::Once,
        AuthorizedDisposition::Remember => {
            let raw_key = Zeroizing::new(
                keytap_core::derive_raw_key(payload.prf_output.as_ref())
                    .map_err(|error| format!("key derivation failed: {error}"))?,
            );
            PreparedAssertionStorage::Remember { raw_key }
        }
    };

    Ok(PreparedNearbyAssertion {
        session,
        key_name,
        identity,
        payload,
        storage,
    })
}

impl PreparedNearbyAssertion {
    /// Cross the side-effect boundary after this route has atomically won.
    /// A failure here is terminal: the coordinator must never promote the
    /// already-superseded native candidate.
    pub(crate) fn commit(self) -> Result<NearbyAssertion, String> {
        let Self {
            session,
            key_name,
            identity,
            payload,
            storage,
        } = self;
        match identity {
            PreparedIdentityAcceptance::Pairing(identity) => {
                commit_identity_acceptance(&session, identity.commit())?;
                note("Pairing confirmed; pinned this passkey identity for future nearby requests.");
            }
            PreparedIdentityAcceptance::Pinned(identity) => {
                commit_identity_acceptance(&session, identity.commit())?;
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
                "Passkey result was verified, but the nearby-device acknowledgement could not be delivered: {error}"
            ));
        }

        Ok(NearbyAssertion {
            credential_id: payload.credential_id,
            prf_output: payload.prf_output.to_vec(),
            storage,
        })
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn supersede(self) {
        self.session
            .send_final(&CliMessage::CompletedElsewhere)
            .ok();
    }
}

impl AuthorizedDisposition {
    fn proof_value(self) -> AssertionDisposition {
        match self {
            Self::Once => AssertionDisposition::Once,
            Self::Remember => AssertionDisposition::Remember,
        }
    }
}

fn authorize_disposition(
    policy: StoragePolicy,
    disposition: AssertionDisposition,
) -> Result<AuthorizedDisposition, String> {
    match (policy, disposition) {
        (StoragePolicy::Choose, AssertionDisposition::Once) => Ok(AuthorizedDisposition::Once),
        (StoragePolicy::Choose | StoragePolicy::Remember, AssertionDisposition::Remember) => {
            Ok(AuthorizedDisposition::Remember)
        }
        (StoragePolicy::Remember, AssertionDisposition::Once) => {
            Err("nearby device declined local storage required by this command".into())
        }
    }
}

fn run_pairing(
    session: &RtcSession,
    request: PairingCeremonyRequest,
    session_binding: &[u8; 32],
    cancellation: Option<&NearbyCancellation>,
) -> Result<PairingAuthorization, String> {
    enum ExpectedPairingResult {
        Registration,
        Assertion,
    }

    let canonical_request = request.sas_bytes()?;
    let expected_result = match &request {
        PairingCeremonyRequest::Register { .. } => ExpectedPairingResult::Registration,
        PairingCeremonyRequest::Assert { .. } => ExpectedPairingResult::Assertion,
    };
    let pending = SasCommitment::generate(SasContext::bind(session_binding, &canonical_request))?;
    session.send(&CliMessage::PairingRequest {
        request,
        cli_commitment: URL_SAFE_NO_PAD.encode(pending.commitment()),
    })?;

    let approver_commitment = match session.receive(CEREMONY_RESPONSE_TIMEOUT, cancellation)? {
        ApproverMessage::SasApproverCommit { commitment, .. } => {
            decode_fixed_base64url::<32>(&commitment, "approver pairing commitment")?
        }
        ApproverMessage::SasApproverRejected | ApproverMessage::Done => {
            return Err("pairing was cancelled on the nearby device; no key was accepted".into())
        }
        _ => return reject_unexpected_pairing(session, cancellation),
    };
    let awaiting_reveal = pending.accept_approver_commitment(approver_commitment);
    session.send(&CliMessage::SasCliReveal {
        nonce: URL_SAFE_NO_PAD.encode(awaiting_reveal.cli_nonce()),
    })?;

    let approver_nonce = match session.receive(CEREMONY_RESPONSE_TIMEOUT, cancellation)? {
        ApproverMessage::SasApproverReveal { nonce, .. } => {
            decode_fixed_base64url::<32>(&nonce, "approver pairing nonce")?
        }
        ApproverMessage::SasApproverRejected | ApproverMessage::Done => {
            return Err("pairing was cancelled on the nearby device; no key was accepted".into())
        }
        _ => return reject_unexpected_pairing(session, cancellation),
    };
    let comparison = awaiting_reveal.accept_approver_nonce(approver_nonce)?;

    eprintln!();
    eprintln!("Pairing words — compare these with your nearby device:");
    eprintln!();
    eprintln!("    {}", comparison.phrase());
    eprintln!();
    eprintln!("Finish the passkey prompt on your nearby device. The CLI will buffer its result until you confirm these words here.");

    let buffered = match (
        expected_result,
        session.receive(CEREMONY_RESPONSE_TIMEOUT, cancellation)?,
    ) {
        (
            ExpectedPairingResult::Registration,
            ApproverMessage::PairedRegistrationResult { credential_id },
        ) => BufferedPairingResult::Registration { credential_id },
        (
            ExpectedPairingResult::Assertion,
            ApproverMessage::PairedAssertionResult {
                credential_id,
                prf_first,
                disposition,
                identity: proof,
            },
        ) => BufferedPairingResult::Assertion {
            credential_id,
            prf_first,
            disposition,
            proof,
        },
        (_, ApproverMessage::SasApproverRejected | ApproverMessage::Done) => {
            return Err(
                "pairing was rejected or cancelled on the nearby device; no key was accepted"
                    .into(),
            )
        }
        _ => return reject_unexpected_pairing(session, cancellation),
    };

    let buffered_comparison = comparison.result_buffered();
    let confirmation = match cancellation {
        Some(cancellation) => {
            buffered_comparison.confirm_with_tty_while(|| cancellation.ensure_active())
        }
        None => buffered_comparison.confirm_with_tty(),
    };
    let confirmed = match confirmation {
        Ok(confirmed) => confirmed,
        Err(error) => {
            if let Some(cancellation) = cancellation {
                cancellation.ensure_active()?;
            }
            session.send_final(&CliMessage::SasCliRejected).ok();
            return Err(error);
        }
    };
    Ok(match buffered {
        BufferedPairingResult::Registration { credential_id } => {
            PairingAuthorization::Registration { credential_id }
        }
        BufferedPairingResult::Assertion {
            credential_id,
            prf_first,
            disposition,
            proof,
        } => PairingAuthorization::Assertion {
            confirmation: confirmed,
            credential_id,
            prf_first,
            disposition,
            proof,
        },
    })
}

fn reject_unexpected_pairing<T>(
    session: &RtcSession,
    cancellation: Option<&NearbyCancellation>,
) -> Result<T, String> {
    if let Some(cancellation) = cancellation {
        cancellation.ensure_active()?;
    }
    session.send_protocol_error(ProtocolErrorCode::UnexpectedMessage);
    Err("nearby device returned an unexpected pairing protocol message; run the command again for a fresh approval request".into())
}

fn connect_signaling(url: &str) -> Result<WebSocket<MaybeTlsStream<TcpStream>>, String> {
    connect_with_config(
        url,
        Some(WebSocketConfig {
            max_message_size: Some(SIGNAL_FRAME_LIMIT),
            max_frame_size: Some(SIGNAL_FRAME_LIMIT),
            ..Default::default()
        }),
        // Signaling rooms are one-origin capabilities. Do not let an endpoint
        // silently move a fresh rendezvous URL to another service.
        0,
    )
    .map(|(socket, _)| socket)
    .map_err(|error| format!("failed to connect to signaling service: {error}"))
}

fn print_qr(url: &str) -> Result<(), String> {
    eprintln!();
    eprintln!("Scan to authenticate with a passkey on a nearby device (encrypted with WebRTC):");
    eprintln!();
    let qr_string = qr2term::generate_qr_string(url)
        .map_err(|error| format!("failed to render QR code: {error}"))?;
    eprint!("{qr_string}");
    eprintln!();
    eprintln!("Or open: {url}");
    eprintln!();
    eprintln!("Waiting for the nearby device (timeout: 5 minutes)…");
    Ok(())
}

#[cfg(target_os = "macos")]
fn print_forwardable_url(url: &str) -> Result<(), String> {
    use std::io::Write;

    eprintln!();
    eprintln!("Approve on this Mac, or forward this URL to the passkey holder:");
    eprintln!("keytap-nearby-approval-url: {url}");
    eprintln!("The first accepted approval wins. Press Ctrl-C to cancel both.");
    eprintln!();
    std::io::stderr()
        .flush()
        .map_err(|error| format!("could not show nearby approval URL: {error}"))
}

fn wait_for_peer(
    signaling: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    deadline: Instant,
    cancellation: Option<&NearbyCancellation>,
) -> Result<(), String> {
    loop {
        let message = read_signal(signaling, deadline, cancellation)?;
        match message {
            Message::Text(text) => {
                let control: Result<SignalControl, _> = serde_json::from_str(text.as_str());
                if matches!(control, Ok(SignalControl::PeerReady)) {
                    return Ok(());
                }
            }
            Message::Ping(data) => {
                send_ws_message(signaling, Message::Pong(data), cancellation)?;
            }
            Message::Close(_) => {
                return Err("signaling connection closed before the approver joined".into())
            }
            _ => {}
        }
    }
}

fn wait_for_answer_message(
    signaling: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    deadline: Instant,
    cancellation: Option<&NearbyCancellation>,
) -> Result<String, String> {
    loop {
        let message = read_signal(signaling, deadline, cancellation)?;
        match message {
            Message::Text(text) => return Ok(text.to_string()),
            Message::Ping(data) => {
                send_ws_message(signaling, Message::Pong(data), cancellation)?;
            }
            Message::Close(_) => {
                return Err("signaling connection closed before the approver answer arrived".into())
            }
            Message::Pong(_) => {}
            _ => return Err("approver sent an invalid WebRTC answer message".into()),
        }
    }
}

fn wait_for_direct_answer(
    signaling: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    deadline: Instant,
    cancellation: Option<&NearbyCancellation>,
) -> Result<DirectAnswerWaitOutcome, String> {
    let text = wait_for_answer_message(signaling, deadline, cancellation)?;
    decode_direct_answer_signal(&text)
}

fn wait_for_turn_retry_answer(
    signaling: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    deadline: Instant,
    cancellation: Option<&NearbyCancellation>,
) -> Result<String, String> {
    let text = wait_for_answer_message(signaling, deadline, cancellation)?;
    decode_approver_answer_signal(&text, SignalAttempt::TurnRetry)
}

fn decode_approver_answer_signal(text: &str, attempt: SignalAttempt) -> Result<String, String> {
    let body = ApproverAnswer::decode(text, attempt)
        .map_err(|error| format!("approver sent an invalid WebRTC answer: {error}"))?;
    String::from_utf8(body).map_err(|_| "approver WebRTC answer was not UTF-8".to_string())
}

fn decode_direct_answer_signal(text: &str) -> Result<DirectAnswerWaitOutcome, String> {
    match decode_approver_answer_signal(text, SignalAttempt::Direct) {
        Ok(answer) => Ok(DirectAnswerWaitOutcome::Answer(answer)),
        Err(answer_error) => {
            let control: TurnAuthorizationMessage =
                serde_json::from_str(text).map_err(|_| answer_error)?;
            let authorization = match control {
                TurnAuthorizationMessage::TurnAuthorized { capability } => {
                    TurnAuthorizationOutcome::Authorized { capability }
                }
                TurnAuthorizationMessage::TurnUnavailable { reason } => {
                    TurnAuthorizationOutcome::Unavailable(reason)
                }
            };
            Ok(DirectAnswerWaitOutcome::ApproverDirectConnectivityFailed { authorization })
        }
    }
}

fn wait_for_turn_authorization(
    signaling: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    deadline: Instant,
    cancellation: Option<&NearbyCancellation>,
) -> Result<TurnAuthorizationOutcome, String> {
    loop {
        let message = read_signal(signaling, deadline, cancellation)?;
        match message {
            Message::Text(text) => {
                let control: TurnAuthorizationMessage = serde_json::from_str(text.as_str())
                    .map_err(|_| {
                        "approver sent an invalid TURN authorization message".to_string()
                    })?;
                return Ok(match control {
                    TurnAuthorizationMessage::TurnAuthorized { capability } => {
                        TurnAuthorizationOutcome::Authorized { capability }
                    }
                    TurnAuthorizationMessage::TurnUnavailable { reason } => {
                        TurnAuthorizationOutcome::Unavailable(reason)
                    }
                });
            }
            Message::Ping(data) => {
                send_ws_message(signaling, Message::Pong(data), cancellation)?;
            }
            Message::Close(_) => {
                return Err("signaling connection closed during TURN authorization".into())
            }
            Message::Pong(_) => {}
            _ => return Err("approver sent an invalid TURN authorization message".into()),
        }
    }
}

fn send_signal(
    signaling: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    envelope: &impl Serialize,
    cancellation: Option<&NearbyCancellation>,
) -> Result<(), String> {
    let json = serde_json::to_string(envelope)
        .map_err(|error| format!("failed to encode signaling message: {error}"))?;
    send_ws_message(signaling, Message::Text(json), cancellation)
}

fn send_ws_message(
    signaling: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    message: Message,
    cancellation: Option<&NearbyCancellation>,
) -> Result<(), String> {
    if let Some(cancellation) = cancellation {
        cancellation.ensure_active()?;
    }
    set_ws_write_timeout(signaling, Some(DATA_SEND_TIMEOUT));
    signaling
        .send(message)
        .map_err(|error| format!("signaling connection error: {error}"))
}

fn read_signal(
    signaling: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    deadline: Instant,
    cancellation: Option<&NearbyCancellation>,
) -> Result<Message, String> {
    loop {
        if let Some(cancellation) = cancellation {
            cancellation.ensure_active()?;
        }
        let remaining = remaining_until(deadline)?;
        let read_timeout = if cancellation.is_some() {
            remaining.min(CANCELLATION_POLL_INTERVAL)
        } else {
            remaining
        };
        set_ws_read_timeout(signaling, Some(read_timeout));
        match signaling.read() {
            Ok(message) => return Ok(message),
            Err(tungstenite::Error::Io(io))
                if matches!(
                    io.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if Instant::now() >= deadline {
                    return Err("timed out waiting for the nearby device; run the command again for a fresh approval request".to_string());
                }
            }
            Err(error) => return Err(format!("signaling connection error: {error}")),
        }
    }
}

fn set_ws_read_timeout(ws: &WebSocket<MaybeTlsStream<TcpStream>>, timeout: Option<Duration>) {
    let timeout = timeout.map(|timeout| timeout.max(Duration::from_millis(1)));
    match ws.get_ref() {
        MaybeTlsStream::Plain(stream) => {
            stream.set_read_timeout(timeout).ok();
        }
        MaybeTlsStream::Rustls(stream) => {
            stream.get_ref().set_read_timeout(timeout).ok();
        }
        _ => {}
    }
}

fn set_ws_write_timeout(ws: &WebSocket<MaybeTlsStream<TcpStream>>, timeout: Option<Duration>) {
    let timeout = timeout.map(|timeout| timeout.max(Duration::from_millis(1)));
    match ws.get_ref() {
        MaybeTlsStream::Plain(stream) => {
            stream.set_write_timeout(timeout).ok();
        }
        MaybeTlsStream::Rustls(stream) => {
            stream.get_ref().set_write_timeout(timeout).ok();
        }
        _ => {}
    }
}

fn remaining_until(deadline: Instant) -> Result<Duration, String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(
            "timed out waiting for the nearby device; run the command again for a fresh approval request"
                .into(),
        )
    } else {
        Ok(remaining)
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum SignalControl {
    PeerReady,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum CliSignalMessage {
    TurnRequired,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum TurnAuthorizationMessage {
    TurnAuthorized { capability: TurnCapability },
    TurnUnavailable { reason: TurnUnavailableReason },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TurnCredentialResponse {
    ice_servers: Vec<TurnServerDto>,
}

/// External Cloudflare DTO. Conditional credential fields stay at this parse
/// boundary and are converted immediately into a strict credential type.
#[derive(Deserialize)]
struct TurnServerDto {
    urls: TurnUrls,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    credential: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum TurnUrls {
    One(String),
    Many(Vec<String>),
}

impl TurnUrls {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(url) => url == expected,
            Self::Many(urls) => urls.iter().any(|url| url == expected),
        }
    }
}

struct CloudflareTurnCredential {
    username: String,
    credential: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TurnPolicyErrorResponse {
    kind: TurnPolicyErrorKind,
}

#[derive(Deserialize)]
enum TurnPolicyErrorKind {
    #[serde(rename = "turn-not-allowlisted")]
    AuthorizationRejected,
}

enum TurnCredentialFetchError {
    AuthorizationRejected,
    Unavailable(String),
}

fn fetch_turn_ice_servers(
    url: &str,
    capability: &TurnCapability,
    deadline: Instant,
) -> Result<Vec<RTCIceServer>, TurnCredentialFetchError> {
    let mut response = turn_http_agent(deadline)
        .map_err(TurnCredentialFetchError::Unavailable)?
        .get(url)
        .header("Authorization", capability.bearer_header_value())
        .call()
        .map_err(turn_fetch_error)?;
    let status = response.status().as_u16();
    let body = response
        .body_mut()
        .with_config()
        .limit(64 * 1024)
        .read_to_string()
        .map_err(|error| {
            TurnCredentialFetchError::Unavailable(format!(
                "failed to read TURN credential response: {error}"
            ))
        })?;
    if !(200..=299).contains(&status) {
        return Err(turn_response_error(status, &body));
    }
    let parsed: TurnCredentialResponse = serde_json::from_str(&body).map_err(|error| {
        TurnCredentialFetchError::Unavailable(format!(
            "TURN service returned invalid JSON: {error}"
        ))
    })?;
    ice_servers_from_turn_response(parsed).map_err(TurnCredentialFetchError::Unavailable)
}

fn fetch_turn_ice_servers_cancellable(
    url: &str,
    capability: &TurnCapability,
    deadline: Instant,
    cancellation: Option<&NearbyCancellation>,
) -> Result<Result<Vec<RTCIceServer>, TurnCredentialFetchError>, String> {
    let Some(cancellation) = cancellation else {
        return Ok(fetch_turn_ice_servers(url, capability, deadline));
    };
    cancellation.ensure_active()?;

    let url = url.to_string();
    let capability = capability.clone();
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("keytap-turn-credentials".to_string())
        .spawn(move || {
            let result = fetch_turn_ice_servers(&url, &capability, deadline);
            result_tx.send(result).ok();
        })
        .map_err(|error| format!("failed to start TURN credential request: {error}"))?;

    loop {
        cancellation.ensure_active()?;
        match result_rx.recv_timeout(CANCELLATION_POLL_INTERVAL) {
            Ok(result) => return Ok(result),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err("TURN credential request stopped unexpectedly".to_string())
            }
        }
    }
}

fn turn_http_agent(deadline: Instant) -> Result<ureq::Agent, String> {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(remaining_until(deadline)?.min(HTTP_TIMEOUT)))
        .http_status_as_error(false)
        .max_redirects(0)
        .build();
    Ok(config.into())
}

fn turn_fetch_error(error: ureq::Error) -> TurnCredentialFetchError {
    TurnCredentialFetchError::Unavailable(format!("failed to fetch TURN credentials: {error}"))
}

fn turn_response_error(status: u16, body: &str) -> TurnCredentialFetchError {
    if status == 403
        && matches!(
            serde_json::from_str(body),
            Ok(TurnPolicyErrorResponse {
                kind: TurnPolicyErrorKind::AuthorizationRejected
            })
        )
    {
        TurnCredentialFetchError::AuthorizationRejected
    } else if status == 503 {
        TurnCredentialFetchError::Unavailable(
            "nearby service has not been configured with Cloudflare TURN credentials".into(),
        )
    } else {
        TurnCredentialFetchError::Unavailable(format!(
            "TURN credential service rejected the request (HTTP {status})"
        ))
    }
}

fn ice_servers_from_turn_response(
    response: TurnCredentialResponse,
) -> Result<Vec<RTCIceServer>, String> {
    let credential = response
        .ice_servers
        .into_iter()
        .filter(|server| server.urls.contains(CLOUDFLARE_TURN_UDP_URL))
        .find_map(|server| match (server.username, server.credential) {
            (Some(username), Some(credential))
                if !username.is_empty() && !credential.is_empty() =>
            {
                Some(CloudflareTurnCredential {
                    username,
                    credential,
                })
            }
            _ => None,
        })
        .ok_or_else(|| {
            "TURN response did not contain credentials for Cloudflare UDP port 3478".to_string()
        })?;

    let mut servers = stun_only_ice_servers();
    servers.push(RTCIceServer {
        urls: vec![CLOUDFLARE_TURN_UDP_URL.to_string()],
        username: credential.username,
        credential: credential.credential,
    });
    Ok(servers)
}

fn stun_only_ice_servers() -> Vec<RTCIceServer> {
    vec![RTCIceServer {
        urls: vec![CLOUDFLARE_STUN_URL.to_string()],
        ..Default::default()
    }]
}

fn run_direct_connection_attempt(
    runtime: &tokio::runtime::Runtime,
    signaling: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    cli_session_key: &CliSessionKey,
    ice_servers: Vec<RTCIceServer>,
    deadline: Instant,
    cancellation: Option<&NearbyCancellation>,
) -> Result<DirectConnectionAttemptOutcome, String> {
    let prepared = match prepare_connection_attempt(
        runtime,
        signaling,
        cli_session_key,
        SignalAttempt::Direct,
        ice_servers,
        deadline,
        cancellation,
    )? {
        PreparedAttemptOutcome::Prepared(prepared) => prepared,
        PreparedAttemptOutcome::ConnectivityFailed(failure) => {
            return Ok(DirectConnectionAttemptOutcome::CliConnectivityFailed(
                failure,
            ))
        }
    };

    // An approver that cannot gather its direct answer first spends up to the ICE
    // timeout discovering that fact, then completes the bounded passkey
    // authorization ceremony before it can report a TURN outcome. Keep that
    // valid path independent from the CLI's original direct setup deadline.
    let answer_deadline = Instant::now() + ICE_GATHER_TIMEOUT + TURN_AUTHORIZATION_TIMEOUT;
    let answer_sdp = match wait_for_direct_answer(signaling, answer_deadline, cancellation) {
        Ok(DirectAnswerWaitOutcome::Answer(answer_sdp)) => answer_sdp,
        Ok(DirectAnswerWaitOutcome::ApproverDirectConnectivityFailed { authorization }) => {
            close_connection_attempt(runtime, &prepared.peer_connection, &prepared.data_channel);
            return Ok(
                DirectConnectionAttemptOutcome::ApproverDirectConnectivityFailed { authorization },
            );
        }
        Err(error) => {
            close_connection_attempt(runtime, &prepared.peer_connection, &prepared.data_channel);
            return Err(error);
        }
    };

    Ok(
        match complete_connection_attempt(runtime, prepared, answer_sdp, cancellation)? {
            ConnectionAttemptOutcome::Connected(connected) => {
                DirectConnectionAttemptOutcome::Connected(connected)
            }
            ConnectionAttemptOutcome::ConnectivityFailed(failure) => {
                DirectConnectionAttemptOutcome::CliConnectivityFailed(failure)
            }
        },
    )
}

fn run_turn_connection_attempt(
    runtime: &tokio::runtime::Runtime,
    signaling: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    cli_session_key: &CliSessionKey,
    ice_servers: Vec<RTCIceServer>,
    deadline: Instant,
    cancellation: Option<&NearbyCancellation>,
) -> Result<ConnectionAttemptOutcome, String> {
    let prepared = match prepare_connection_attempt(
        runtime,
        signaling,
        cli_session_key,
        SignalAttempt::TurnRetry,
        ice_servers,
        deadline,
        cancellation,
    )? {
        PreparedAttemptOutcome::Prepared(prepared) => prepared,
        PreparedAttemptOutcome::ConnectivityFailed(failure) => {
            return Ok(ConnectionAttemptOutcome::ConnectivityFailed(failure))
        }
    };
    let answer_sdp = match wait_for_turn_retry_answer(signaling, deadline, cancellation) {
        Ok(answer_sdp) => answer_sdp,
        Err(error) => {
            close_connection_attempt(runtime, &prepared.peer_connection, &prepared.data_channel);
            return Err(error);
        }
    };
    complete_connection_attempt(runtime, prepared, answer_sdp, cancellation)
}

fn prepare_connection_attempt(
    runtime: &tokio::runtime::Runtime,
    signaling: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    cli_session_key: &CliSessionKey,
    attempt: SignalAttempt,
    ice_servers: Vec<RTCIceServer>,
    deadline: Instant,
    cancellation: Option<&NearbyCancellation>,
) -> Result<PreparedAttemptOutcome, String> {
    let (peer_connection, data_channel, open_rx, incoming) = block_on_cancellable(
        runtime,
        create_offer_peer(ice_servers, IceCandidateScope::NetworkInterfaces),
        cancellation,
    )?
    .map_err(|error| format!("failed to create WebRTC connection: {error}"))?;

    let gathering_timeout = match remaining_until(deadline) {
        Ok(remaining) => remaining.min(ICE_GATHER_TIMEOUT),
        Err(_) => {
            close_connection_attempt(runtime, &peer_connection, &data_channel);
            return Err("the WebRTC setup deadline expired before ICE gathering began".to_string());
        }
    };
    let gathered_offer = match block_on_cancellable(
        runtime,
        gather_offer(&peer_connection, gathering_timeout),
        cancellation,
    ) {
        Ok(result) => result,
        Err(error) => {
            close_connection_attempt(runtime, &peer_connection, &data_channel);
            return Err(error);
        }
    };
    let offer_sdp = match gathered_offer {
        Ok(offer_sdp) => offer_sdp,
        Err(IceGatheringFailure::TimedOut) => {
            close_connection_attempt(runtime, &peer_connection, &data_channel);
            return Ok(PreparedAttemptOutcome::ConnectivityFailed(
                ConnectivityFailure::IceGatheringTimedOut,
            ));
        }
        Err(IceGatheringFailure::Setup(error)) => {
            close_connection_attempt(runtime, &peer_connection, &data_channel);
            return Err(format!("failed to gather WebRTC offer: {error}"));
        }
    };
    let offer = cli_session_key.sign_offer(attempt, offer_sdp.as_bytes());
    if let Err(error) = send_signal(signaling, &offer, cancellation) {
        close_connection_attempt(runtime, &peer_connection, &data_channel);
        return Err(error);
    }

    Ok(PreparedAttemptOutcome::Prepared(PreparedAttempt {
        peer_connection,
        data_channel,
        open_rx,
        incoming,
        offer_sdp,
    }))
}

fn complete_connection_attempt(
    runtime: &tokio::runtime::Runtime,
    prepared: PreparedAttempt,
    answer_sdp: String,
    cancellation: Option<&NearbyCancellation>,
) -> Result<ConnectionAttemptOutcome, String> {
    let PreparedAttempt {
        peer_connection,
        data_channel,
        open_rx,
        incoming,
        offer_sdp,
    } = prepared;
    let answer = match RTCSessionDescription::answer(answer_sdp.clone()) {
        Ok(answer) => answer,
        Err(error) => {
            close_connection_attempt(runtime, &peer_connection, &data_channel);
            return Err(format!("approver sent an invalid WebRTC answer: {error}"));
        }
    };
    let remote_description = block_on_cancellable(
        runtime,
        peer_connection.set_remote_description(answer),
        cancellation,
    );
    let remote_description = match remote_description {
        Ok(result) => result,
        Err(error) => {
            close_connection_attempt(runtime, &peer_connection, &data_channel);
            return Err(error);
        }
    };
    if let Err(error) = remote_description {
        close_connection_attempt(runtime, &peer_connection, &data_channel);
        return Err(format!("failed to apply WebRTC answer: {error}"));
    }

    // Once a valid answer is applied, observe a full bounded data-channel
    // establishment interval. Expiration before entering this phase is not
    // fabricated into a connectivity failure, and a real timeout here is.
    let open_deadline = Instant::now() + DATA_CHANNEL_OPEN_TIMEOUT;
    let failure = loop {
        if let Some(cancellation) = cancellation {
            if let Err(error) = cancellation.ensure_active() {
                close_connection_attempt(runtime, &peer_connection, &data_channel);
                return Err(error);
            }
        }
        let remaining = open_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break DataChannelEstablishmentFailure::TimedOut;
        }
        let wait = if cancellation.is_some() {
            remaining.min(CANCELLATION_POLL_INTERVAL)
        } else {
            remaining
        };
        match open_rx.recv_timeout(wait) {
            Ok(EstablishmentEvent::Open) => {
                return Ok(ConnectionAttemptOutcome::Connected(ConnectedAttempt {
                    peer_connection,
                    data_channel,
                    incoming,
                    offer_sdp,
                    answer_sdp,
                }))
            }
            Ok(EstablishmentEvent::Failed(error)) => {
                break DataChannelEstablishmentFailure::Failed(error)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break DataChannelEstablishmentFailure::Failed(
                    "WebRTC data channel stopped unexpectedly during setup".into(),
                )
            }
        }
    };
    close_connection_attempt(runtime, &peer_connection, &data_channel);
    Ok(ConnectionAttemptOutcome::ConnectivityFailed(
        ConnectivityFailure::DataChannel(failure),
    ))
}

fn close_connection_attempt(
    runtime: &tokio::runtime::Runtime,
    peer_connection: &RTCPeerConnection,
    data_channel: &RTCDataChannel,
) {
    close_rtc_bounded(runtime, peer_connection, data_channel);
}

async fn create_offer_peer(
    ice_servers: Vec<RTCIceServer>,
    candidate_scope: IceCandidateScope,
) -> Result<
    (
        Arc<RTCPeerConnection>,
        Arc<RTCDataChannel>,
        mpsc::Receiver<EstablishmentEvent>,
        mpsc::Receiver<DataChannelEvent>,
    ),
    webrtc::Error,
> {
    let configuration = RTCConfiguration {
        ice_servers,
        ..Default::default()
    };
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
    let api_builder = APIBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry);
    let api = match candidate_scope {
        IceCandidateScope::NetworkInterfaces => api_builder,
        #[cfg(test)]
        IceCandidateScope::IncludeLoopback => {
            let mut setting_engine = SettingEngine::default();
            setting_engine.set_include_loopback_candidate(true);
            api_builder.with_setting_engine(setting_engine)
        }
    }
    .build();

    let peer_connection = Arc::new(api.new_peer_connection(configuration).await?);
    let data_channel = match peer_connection
        .create_data_channel(
            DATA_CHANNEL_LABEL,
            Some(RTCDataChannelInit {
                ordered: Some(true),
                protocol: Some(DATA_CHANNEL_PROTOCOL.to_string()),
                ..Default::default()
            }),
        )
        .await
    {
        Ok(data_channel) => data_channel,
        Err(error) => {
            peer_connection.close().await.ok();
            return Err(error);
        }
    };

    let (open_tx, open_rx) = mpsc::channel();
    let open_handler_tx = open_tx.clone();
    data_channel.on_open(Box::new(move || {
        let open_tx = open_handler_tx.clone();
        Box::pin(async move {
            let _ = open_tx.send(EstablishmentEvent::Open);
        })
    }));

    let (event_tx, event_rx) = mpsc::channel();
    let message_tx = event_tx.clone();
    data_channel.on_message(Box::new(move |message: DataChannelMessage| {
        let message_tx = message_tx.clone();
        Box::pin(async move {
            let event = if !message.is_string {
                DataChannelEvent::Invalid("approver sent a binary data-channel message".into())
            } else if message.data.len() > DATA_FRAME_LIMIT {
                DataChannelEvent::Invalid("approver data-channel message was too large".into())
            } else {
                match String::from_utf8(message.data.to_vec()) {
                    Ok(text) => DataChannelEvent::Text(text),
                    Err(_) => DataChannelEvent::Invalid(
                        "approver data-channel message was not valid UTF-8".into(),
                    ),
                }
            };
            let _ = message_tx.send(event);
        })
    }));
    let close_event_tx = event_tx.clone();
    let close_open_tx = open_tx.clone();
    data_channel.on_close(Box::new(move || {
        let event_tx = close_event_tx.clone();
        let open_tx = close_open_tx.clone();
        Box::pin(async move {
            let _ = event_tx.send(DataChannelEvent::Closed);
            let _ = open_tx.send(EstablishmentEvent::Failed(
                "approver closed the WebRTC data channel during setup".into(),
            ));
        })
    }));

    let error_event_tx = event_tx.clone();
    let error_open_tx = open_tx.clone();
    data_channel.on_error(Box::new(move |error| {
        let event_tx = error_event_tx.clone();
        let open_tx = error_open_tx.clone();
        Box::pin(async move {
            let error = format!("WebRTC data channel failed: {error}");
            let _ = event_tx.send(DataChannelEvent::TransportFailed(error.clone()));
            let _ = open_tx.send(EstablishmentEvent::Failed(error));
        })
    }));

    let connection_event_tx = event_tx;
    let connection_open_tx = open_tx;
    peer_connection.on_peer_connection_state_change(Box::new(move |state| {
        let event_tx = connection_event_tx.clone();
        let open_tx = connection_open_tx.clone();
        Box::pin(async move {
            match state {
                RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed => {
                    let error = format!("WebRTC peer connection entered {state} state");
                    let _ = event_tx.send(DataChannelEvent::TransportFailed(error.clone()));
                    let _ = open_tx.send(EstablishmentEvent::Failed(error));
                }
                _ => {}
            }
        })
    }));

    Ok((peer_connection, data_channel, open_rx, event_rx))
}

async fn gather_offer(
    peer_connection: &RTCPeerConnection,
    timeout: Duration,
) -> Result<String, IceGatheringFailure> {
    let offer = peer_connection
        .create_offer(None)
        .await
        .map_err(|error| IceGatheringFailure::Setup(error.to_string()))?;
    let mut gathering_complete = peer_connection.gathering_complete_promise().await;
    peer_connection
        .set_local_description(offer)
        .await
        .map_err(|error| IceGatheringFailure::Setup(error.to_string()))?;
    tokio::time::timeout(timeout, gathering_complete.recv())
        .await
        .map_err(|_| IceGatheringFailure::TimedOut)?;
    peer_connection
        .local_description()
        .await
        .map(|description| description.sdp)
        .ok_or_else(|| IceGatheringFailure::Setup("missing local WebRTC description".to_string()))
}

enum EstablishmentEvent {
    Open,
    Failed(String),
}

enum DataChannelEvent {
    Text(String),
    Closed,
    Invalid(String),
    TransportFailed(String),
}

struct RtcSession {
    runtime: Arc<tokio::runtime::Runtime>,
    peer_connection: Arc<RTCPeerConnection>,
    data_channel: Arc<RTCDataChannel>,
    incoming: mpsc::Receiver<DataChannelEvent>,
}

impl RtcSession {
    fn send(&self, message: &CliMessage) -> Result<(), String> {
        let text = serde_json::to_string(message)
            .map_err(|error| format!("failed to encode nearby message: {error}"))?;
        send_data_text_bounded(&self.runtime, &self.data_channel, text)
    }

    fn send_final(&self, message: &CliMessage) -> Result<(), String> {
        let text = serde_json::to_string(message)
            .map_err(|error| format!("failed to encode nearby terminal message: {error}"))?;
        send_data_text_and_drain_bounded(&self.runtime, &self.data_channel, text)
    }

    fn send_protocol_error(&self, code: ProtocolErrorCode) {
        self.send_final(&CliMessage::ProtocolError { code }).ok();
    }

    fn receive(
        &self,
        timeout: Duration,
        cancellation: Option<&NearbyCancellation>,
    ) -> Result<ApproverMessage, String> {
        let deadline = Instant::now() + timeout;
        let event = loop {
            if let Some(cancellation) = cancellation {
                cancellation.ensure_active()?;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("timed out waiting for the nearby device".into());
            }
            let wait = if cancellation.is_some() {
                remaining.min(CANCELLATION_POLL_INTERVAL)
            } else {
                remaining
            };
            match self.incoming.recv_timeout(wait) {
                Ok(event) => break event,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err("WebRTC data channel stopped unexpectedly".into())
                }
            }
        };
        if let Some(cancellation) = cancellation {
            cancellation.ensure_active()?;
        }
        match event {
            DataChannelEvent::Text(text) => match decode_approver_message(&text) {
                Ok(message) => Ok(message),
                Err(error) => {
                    if let Some(cancellation) = cancellation {
                        cancellation.ensure_active()?;
                    }
                    self.send_protocol_error(ProtocolErrorCode::InvalidMessage);
                    Err(error)
                }
            },
            DataChannelEvent::Invalid(error) => {
                if let Some(cancellation) = cancellation {
                    cancellation.ensure_active()?;
                }
                self.send_protocol_error(ProtocolErrorCode::InvalidMessage);
                Err(error)
            }
            DataChannelEvent::Closed => Err("approver closed the WebRTC data channel".into()),
            DataChannelEvent::TransportFailed(error) => Err(error),
        }
    }
}

impl Drop for RtcSession {
    fn drop(&mut self) {
        close_rtc_bounded(&self.runtime, &self.peer_connection, &self.data_channel);
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum CliMessage {
    Request {
        request: PinnedCeremonyRequest,
    },
    PairingRequest {
        request: PairingCeremonyRequest,
        #[serde(rename = "cliCommitment")]
        cli_commitment: String,
    },
    SasCliReveal {
        nonce: String,
    },
    SasCliRejected,
    InitialAccepted,
    InitialRejected {
        reason: InitialRejectedReason,
    },
    InitialIndeterminate {
        reason: InitialIndeterminateReason,
    },
    AssertionAccepted {
        storage: StorageOutcome,
    },
    CompletedElsewhere,
    ProtocolError {
        code: ProtocolErrorCode,
    },
}

#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum PairingCeremonyRequest {
    Register {
        challenge: String,
        #[serde(rename = "prfSalt")]
        prf_salt: String,
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
        identity: PairingIdentityRequest,
        storage: StoragePolicy,
    },
}

#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum PinnedCeremonyRequest {
    Assert {
        #[serde(rename = "keyName")]
        key_name: String,
        #[serde(rename = "prfSalt")]
        prf_salt: String,
        #[serde(rename = "identitySalt")]
        identity_salt: String,
        challenge: String,
        identity: PinnedIdentityRequest,
        storage: StoragePolicy,
    },
}

impl PairingCeremonyRequest {
    fn sas_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        match self {
            Self::Register {
                challenge,
                prf_salt,
                user_id,
                user_name,
            } => {
                bytes.push(0);
                append_sas_field(&mut bytes, &decode_sas_field(challenge, "challenge")?);
                append_sas_field(&mut bytes, &decode_sas_field(prf_salt, "PRF salt")?);
                append_sas_field(&mut bytes, &decode_sas_field(user_id, "user ID")?);
                append_sas_field(&mut bytes, user_name.as_bytes());
            }
            Self::Assert {
                key_name,
                prf_salt,
                identity_salt,
                challenge,
                identity,
                storage,
            } => {
                bytes.push(1);
                append_sas_field(&mut bytes, &decode_sas_field(challenge, "challenge")?);
                append_sas_field(&mut bytes, &decode_sas_field(prf_salt, "PRF salt")?);
                append_sas_field(
                    &mut bytes,
                    &decode_sas_field(identity_salt, "identity PRF salt")?,
                );
                append_sas_field(&mut bytes, key_name.as_bytes());
                match identity {
                    PairingIdentityRequest::Any => bytes.push(0),
                    PairingIdentityRequest::Credential { credential_id } => {
                        bytes.push(1);
                        append_sas_field(
                            &mut bytes,
                            &decode_sas_field(credential_id, "credential ID")?,
                        );
                    }
                }
                match storage {
                    StoragePolicy::Choose => bytes.push(0),
                    StoragePolicy::Remember => bytes.push(1),
                }
            }
        }
        Ok(bytes)
    }
}

fn decode_sas_field(value: &str, label: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| format!("could not bind invalid {label} into pairing"))
}

fn append_sas_field(target: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("bounded nearby request fields fit in u32");
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
}

#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum PairingIdentityRequest {
    #[serde(rename = "pairing-any")]
    Any,
    #[serde(rename = "pairing-credential")]
    Credential {
        #[serde(rename = "credentialId")]
        credential_id: String,
    },
}

#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum PinnedIdentityRequest {
    Pinned {
        #[serde(rename = "credentialId")]
        credential_id: String,
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

fn build_plan(operation: Operation<'_>) -> Result<FlowPlan, String> {
    let mut challenge_bytes = [0u8; 32];
    getrandom::getrandom(&mut challenge_bytes)
        .map_err(|error| format!("failed to generate WebAuthn challenge: {error}"))?;

    match operation {
        Operation::Register { pending_init } => {
            let prf_salt = keytap_core::prf_salt_for_name("default")
                .map_err(|error| format!("failed to derive registration PRF salt: {error}"))?;
            Ok(FlowPlan::Registration {
                request: PairingCeremonyRequest::Register {
                    challenge: URL_SAFE_NO_PAD.encode(challenge_bytes),
                    prf_salt: URL_SAFE_NO_PAD.encode(prf_salt),
                    user_id: URL_SAFE_NO_PAD.encode(b"keytap-user"),
                    user_name: "keytap".to_string(),
                },
                pending_init,
            })
        }
        Operation::Assert {
            name,
            storage_policy,
        } => {
            let prf_salt = keytap_core::prf_salt_for_name(name)
                .map_err(|error| format!("invalid key name: {error}"))?;
            let identity_salt = crate::nearby_identity::prf_salt();
            let anchor = IdentityAnchor::load()
                .map_err(|error| format!("could not load the nearby passkey identity: {error}"))?;
            let assertion = AssertionPlan {
                key_name: name.to_string(),
                prf_salt,
                identity_salt,
                challenge: challenge_bytes,
                storage: storage_policy,
            };
            match anchor {
                IdentityAnchor::Pairing(anchor) => {
                    Ok(FlowPlan::PairingAssertion { assertion, anchor })
                }
                IdentityAnchor::Pinned(anchor) => {
                    Ok(FlowPlan::PinnedAssertion { assertion, anchor })
                }
            }
        }
    }
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
    SasApproverRejected,
    PairedRegistrationResult {
        #[serde(rename = "credentialId")]
        credential_id: String,
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
    Done,
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

fn decode_approver_message(text: &str) -> Result<ApproverMessage, String> {
    serde_json::from_str(text).map_err(|error| format!("invalid nearby protocol message: {error}"))
}

struct AssertionPayload {
    credential_id: Vec<u8>,
    prf_output: Zeroizing<[u8; 32]>,
}

fn decode_credential_id(value: &str) -> Result<Vec<u8>, String> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| format!("invalid credentialId: {error}"))?;
    match decoded.len() {
        0 => Err("nearby device returned an empty credentialId".into()),
        1..=1024 => Ok(decoded),
        length => Err(format!(
            "nearby device returned a credentialId of {length} bytes; maximum is 1024"
        )),
    }
}

fn decode_assertion_fields(
    credential_id: &str,
    prf_first: &str,
) -> Result<AssertionPayload, String> {
    let credential_id = decode_credential_id(credential_id)?;
    let prf_output: [u8; 32] = URL_SAFE_NO_PAD
        .decode(prf_first)
        .map_err(|error| format!("invalid prfFirst: {error}"))?
        .try_into()
        .map_err(|value: Vec<u8>| {
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
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| format!("invalid {label}: {error}"))?
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("invalid {label} length {}; expected {N}", bytes.len()))
}

fn commit_identity_acceptance(
    session: &RtcSession,
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

fn report_identity_failure(session: &RtcSession, error: &IdentityVerificationError) {
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
            "{error}; no success was acknowledged and the returned key was refused. The local passkey record may be visible but is not confirmed durable; retry this command with a fresh approval request before relying on the pairing"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assertion_request_has_no_conditionally_optional_fields() {
        let request = PinnedCeremonyRequest::Assert {
            key_name: "deploy".into(),
            prf_salt: "salt".into(),
            identity_salt: "identity-salt".into(),
            challenge: "challenge".into(),
            identity: PinnedIdentityRequest::Pinned {
                credential_id: "credential".into(),
            },
            storage: StoragePolicy::Choose,
        };
        let json = serde_json::to_value(CliMessage::Request { request }).unwrap();
        assert_eq!(json["type"], "request");
        assert_eq!(json["request"]["kind"], "assert");
        assert_eq!(json["request"]["storage"], "choose");
        assert_eq!(json["request"]["identity"]["kind"], "pinned");
        assert_eq!(json["request"]["identity"]["credentialId"], "credential");
        assert_eq!(json["request"]["identitySalt"], "identity-salt");
        assert!(json["request"].get("userId").is_none());
        assert_eq!(
            serde_json::to_value(StoragePolicy::Remember).unwrap(),
            serde_json::json!("remember")
        );
    }

    #[test]
    fn pairing_request_and_context_match_the_browser_vector() {
        let request = PairingCeremonyRequest::Assert {
            key_name: "deploy".into(),
            prf_salt: URL_SAFE_NO_PAD.encode([2u8; 32]),
            identity_salt: URL_SAFE_NO_PAD.encode([3u8; 32]),
            challenge: URL_SAFE_NO_PAD.encode([1u8; 32]),
            identity: PairingIdentityRequest::Credential {
                credential_id: URL_SAFE_NO_PAD.encode(b"cred"),
            },
            storage: StoragePolicy::Choose,
        };
        let canonical = request.sas_bytes().unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(&canonical),
            "AQAAACABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQAAACACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgAAACADAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwAAAAZkZXBsb3kBAAAABGNyZWQA"
        );
        let context = SasContext::bind(&[4; 32], &canonical);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(context.as_bytes()),
            "-ttmWQ8-kdx7xyaCzmPOpk7KNSnoYJkNBd_OwlhIxQs"
        );

        let mut required = request.clone();
        let PairingCeremonyRequest::Assert { storage, .. } = &mut required else {
            unreachable!()
        };
        *storage = StoragePolicy::Remember;
        let required = required.sas_bytes().unwrap();
        assert_eq!(
            &required[..required.len() - 1],
            &canonical[..canonical.len() - 1]
        );
        assert_eq!(canonical.last(), Some(&0));
        assert_eq!(required.last(), Some(&1));
        assert_ne!(
            SasContext::bind(&[4; 32], &canonical).as_bytes(),
            SasContext::bind(&[4; 32], &required).as_bytes()
        );

        let json = serde_json::to_value(CliMessage::PairingRequest {
            request,
            cli_commitment: URL_SAFE_NO_PAD.encode([9; 32]),
        })
        .unwrap();
        assert_eq!(json["type"], "pairing-request");
        assert_eq!(json["request"]["identity"]["kind"], "pairing-credential");
    }

    #[test]
    fn registration_request_carries_every_required_webauthn_value() {
        let request = PairingCeremonyRequest::Register {
            challenge: "challenge".into(),
            prf_salt: "salt".into(),
            user_id: "user-id".into(),
            user_name: "keytap".into(),
        };
        let json = serde_json::to_value(CliMessage::PairingRequest {
            request,
            cli_commitment: URL_SAFE_NO_PAD.encode([9; 32]),
        })
        .unwrap();
        assert_eq!(json["type"], "pairing-request");
        assert_eq!(json["cliCommitment"], URL_SAFE_NO_PAD.encode([9; 32]));
        assert_eq!(json["request"]["kind"], "register");
        assert_eq!(json["request"]["challenge"], "challenge");
        assert_eq!(json["request"]["prfSalt"], "salt");
        assert_eq!(json["request"]["userId"], "user-id");
        assert_eq!(json["request"]["userName"], "keytap");
        assert!(json["request"].get("storage").is_none());
    }

    #[test]
    fn error_and_rejection_messages_have_allowlisted_payloads() {
        assert_eq!(
            serde_json::to_string(&CliMessage::CompletedElsewhere).unwrap(),
            COMPLETED_ELSEWHERE_SIGNAL
        );

        let error = serde_json::to_value(CliMessage::ProtocolError {
            code: ProtocolErrorCode::UnexpectedMessage,
        })
        .unwrap();
        assert_eq!(
            error,
            serde_json::json!({
                "type": "protocol-error",
                "code": "unexpected-message"
            })
        );

        for (storage, expected) in [
            (StorageOutcome::Once, "once"),
            (StorageOutcome::Stored, "stored"),
            (StorageOutcome::Unavailable, "unavailable"),
        ] {
            assert_eq!(
                serde_json::to_value(CliMessage::AssertionAccepted { storage }).unwrap(),
                serde_json::json!({
                    "type": "assertion-accepted",
                    "storage": expected
                })
            );
        }

        let identity_rejected = serde_json::to_value(CliMessage::InitialRejected {
            reason: InitialRejectedReason::IdentityMismatch,
        })
        .unwrap();
        assert_eq!(
            identity_rejected,
            serde_json::json!({
                "type": "initial-rejected",
                "reason": "identity-mismatch"
            })
        );

        let identity_indeterminate = serde_json::to_value(CliMessage::InitialIndeterminate {
            reason: InitialIndeterminateReason::IdentityDurabilityUnknown,
        })
        .unwrap();
        assert_eq!(
            identity_indeterminate,
            serde_json::json!({
                "type": "initial-indeterminate",
                "reason": "identity-durability-unknown"
            })
        );

        assert_eq!(
            serde_json::to_value(CliMessage::SasCliRejected).unwrap(),
            serde_json::json!({ "type": "sas-cli-rejected" })
        );
    }

    #[test]
    fn completion_acknowledgement_is_exact() {
        assert!(
            serde_json::from_str::<CompletionResponse>(r#"{"kind":"completed-elsewhere"}"#).is_ok()
        );
        for invalid in [
            r#"{"kind":"completed-elsewhere","extra":true}"#,
            r#"{"kind":"completed"}"#,
            r#"{}"#,
        ] {
            assert!(serde_json::from_str::<CompletionResponse>(invalid).is_err());
        }
    }

    #[test]
    fn supersession_interrupts_an_in_progress_async_setup_wait() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let cancellation = NearbyCancellation::new();
        let competing_winner = cancellation.clone();
        let winner = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            *competing_winner
                .inner
                .lock()
                .expect("nearby cancellation lock poisoned") =
                NearbyCancellationState::SupersededBeforeRoom;
        });

        let started = Instant::now();
        let result = block_on_cancellable(
            &runtime,
            async {
                tokio::time::sleep(Duration::from_secs(5)).await;
            },
            Some(&cancellation),
        );
        winner.join().unwrap();

        assert_eq!(result.unwrap_err(), SUPERSEDED_ERROR);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn approver_messages_are_strictly_typed() {
        assert!(matches!(
            decode_approver_message(
                r#"{"type":"paired-registration-result","credentialId":"Y3JlZA"}"#
            )
            .unwrap(),
            ApproverMessage::PairedRegistrationResult { .. }
        ));
        assert!(decode_approver_message(
            r#"{"type":"paired-registration-result","credentialId":"Y3JlZA","extra":true}"#
        )
        .is_err());
        assert!(decode_approver_message(r#"{"type":"unknown"}"#).is_err());
        let complete = r#"{"type":"assertion-result","credentialId":"YQ","prfFirst":"cHJm","disposition":"remember","identity":{"algorithm":"ed25519","publicKey":"cHVi","signature":"c2ln"}}"#;
        assert!(matches!(
            decode_approver_message(complete).unwrap(),
            ApproverMessage::AssertionResult {
                disposition: AssertionDisposition::Remember,
                ..
            }
        ));
        let missing = r#"{"type":"assertion-result","credentialId":"YQ","prfFirst":"cHJm","identity":{"algorithm":"ed25519","publicKey":"cHVi","signature":"c2ln"}}"#;
        assert!(decode_approver_message(missing).is_err());
        let paired_missing = r#"{"type":"paired-assertion-result","credentialId":"YQ","prfFirst":"cHJm","identity":{"algorithm":"ed25519","publicKey":"cHVi","signature":"c2ln"}}"#;
        assert!(decode_approver_message(paired_missing).is_err());
        let unknown = r#"{"type":"assertion-result","credentialId":"YQ","prfFirst":"cHJm","disposition":"later","identity":{"algorithm":"ed25519","publicKey":"cHVi","signature":"c2ln"}}"#;
        assert!(decode_approver_message(unknown).is_err());
        let extra = r#"{"type":"assertion-result","credentialId":"YQ","prfFirst":"cHJm","disposition":"once","identity":{"algorithm":"ed25519","publicKey":"cHVi","signature":"c2ln"},"extra":true}"#;
        assert!(decode_approver_message(extra).is_err());
    }

    #[test]
    fn response_disposition_must_be_authorized_by_request_policy() {
        assert!(matches!(
            authorize_disposition(StoragePolicy::Choose, AssertionDisposition::Once),
            Ok(AuthorizedDisposition::Once)
        ));
        assert!(matches!(
            authorize_disposition(StoragePolicy::Choose, AssertionDisposition::Remember),
            Ok(AuthorizedDisposition::Remember)
        ));
        assert!(
            authorize_disposition(StoragePolicy::Remember, AssertionDisposition::Once).is_err()
        );
        assert!(matches!(
            authorize_disposition(StoragePolicy::Remember, AssertionDisposition::Remember),
            Ok(AuthorizedDisposition::Remember)
        ));
    }

    #[test]
    fn assertion_fields_require_exact_prf_size() {
        let prf = URL_SAFE_NO_PAD.encode([7u8; 32]);
        let payload = decode_assertion_fields("Y3JlZA", &prf).unwrap();
        assert_eq!(payload.credential_id, b"cred");
        assert_eq!(payload.prf_output.as_ref(), &[7u8; 32]);
        assert!(decode_assertion_fields("Y3JlZA", "c2hvcnQ").is_err());
        assert!(decode_credential_id(&URL_SAFE_NO_PAD.encode(vec![0; 1025])).is_err());
    }

    #[test]
    fn turn_retry_control_messages_are_exact_and_strict() {
        assert_eq!(
            serde_json::to_value(CliSignalMessage::TurnRequired).unwrap(),
            serde_json::json!({ "type": "turn-required" })
        );

        let encoded_capability = URL_SAFE_NO_PAD.encode([0x42; 64]);
        let authorized =
            format!(r#"{{"type":"turn-authorized","capability":"{encoded_capability}"}}"#);
        match serde_json::from_str::<TurnAuthorizationMessage>(&authorized).unwrap() {
            TurnAuthorizationMessage::TurnAuthorized { capability } => assert_eq!(
                capability.bearer_header_value(),
                format!("Bearer {encoded_capability}")
            ),
            TurnAuthorizationMessage::TurnUnavailable { .. } => {
                panic!("authorized control decoded as unavailable")
            }
        }
        for (encoded, expected) in [
            (
                r#"{"type":"turn-unavailable","reason":"not-allowlisted"}"#,
                TurnUnavailableReason::NotAllowlisted,
            ),
            (
                r#"{"type":"turn-unavailable","reason":"cancelled"}"#,
                TurnUnavailableReason::Cancelled,
            ),
            (
                r#"{"type":"turn-unavailable","reason":"passkey-unavailable"}"#,
                TurnUnavailableReason::PasskeyUnavailable,
            ),
            (
                r#"{"type":"turn-unavailable","reason":"provider-unavailable"}"#,
                TurnUnavailableReason::ProviderUnavailable,
            ),
        ] {
            assert!(matches!(
                serde_json::from_str::<TurnAuthorizationMessage>(encoded).unwrap(),
                TurnAuthorizationMessage::TurnUnavailable { reason } if reason == expected
            ));
        }
        let padded_capability = format!("{encoded_capability}=");
        let wrong_length_capability = URL_SAFE_NO_PAD.encode([0x42; 63]);
        let invalid = [
            r#"{"type":"turn-authorized"}"#.to_string(),
            format!(
                r#"{{"type":"turn-authorized","capability":"{encoded_capability}","extra":true}}"#
            ),
            format!(r#"{{"type":"turn-authorized","capability":"{padded_capability}"}}"#),
            format!(r#"{{"type":"turn-authorized","capability":"{wrong_length_capability}"}}"#),
            r#"{"type":"turn-authorized","capability":"not+base64url"}"#.to_string(),
            r#"{"type":"turn-unavailable"}"#.to_string(),
            r#"{"type":"turn-unavailable","reason":"unknown"}"#.to_string(),
            r#"{"type":"turn-required"}"#.to_string(),
        ];
        for invalid in invalid {
            assert!(serde_json::from_str::<TurnAuthorizationMessage>(&invalid).is_err());
        }
    }

    #[test]
    fn direct_answer_wait_accepts_exact_early_turn_outcomes_only() {
        let encoded_capability = URL_SAFE_NO_PAD.encode([0x24; 64]);
        let authorized =
            format!(r#"{{"type":"turn-authorized","capability":"{encoded_capability}"}}"#);
        assert!(matches!(
            decode_direct_answer_signal(&authorized),
            Ok(DirectAnswerWaitOutcome::ApproverDirectConnectivityFailed {
                authorization: TurnAuthorizationOutcome::Authorized { .. },
            })
        ));
        for (encoded, expected) in [
            (
                r#"{"type":"turn-unavailable","reason":"not-allowlisted"}"#,
                TurnUnavailableReason::NotAllowlisted,
            ),
            (
                r#"{"type":"turn-unavailable","reason":"cancelled"}"#,
                TurnUnavailableReason::Cancelled,
            ),
            (
                r#"{"type":"turn-unavailable","reason":"passkey-unavailable"}"#,
                TurnUnavailableReason::PasskeyUnavailable,
            ),
            (
                r#"{"type":"turn-unavailable","reason":"provider-unavailable"}"#,
                TurnUnavailableReason::ProviderUnavailable,
            ),
        ] {
            assert!(matches!(
                decode_direct_answer_signal(encoded),
                Ok(DirectAnswerWaitOutcome::ApproverDirectConnectivityFailed {
                    authorization: TurnAuthorizationOutcome::Unavailable(reason),
                }) if reason == expected
            ));
            assert!(decode_approver_answer_signal(encoded, SignalAttempt::TurnRetry).is_err());
        }

        for invalid in [
            r#"{"type":"turn-authorized"}"#,
            r#"{"type":"turn-authorized","capability":"bad","extra":true}"#,
            r#"{"type":"turn-unavailable","reason":"not-allowlisted","extra":true}"#,
            r#"{"type":"turn-required"}"#,
        ] {
            assert!(decode_direct_answer_signal(invalid).is_err());
        }
        assert!(decode_approver_answer_signal(&authorized, SignalAttempt::TurnRetry,).is_err());
    }

    #[test]
    fn only_not_allowlisted_failure_mentions_shared_quota() {
        let not_allowlisted = turn_unavailable_error(
            ConnectivityFailure::DataChannel(DataChannelEstablishmentFailure::TimedOut)
                .final_error(),
            TurnUnavailableReason::NotAllowlisted,
        );
        assert!(not_allowlisted.contains("passkey identity is not on the TURN allowlist"));
        assert!(not_allowlisted.contains("shared Cloudflare quota"));

        let cancelled = turn_unavailable_error(
            ConnectivityFailure::DataChannel(DataChannelEstablishmentFailure::Failed(
                "direct failed".into(),
            ))
            .final_error(),
            TurnUnavailableReason::Cancelled,
        );
        assert_eq!(
            cancelled,
            "direct failed; the direct peer-to-peer connection failed, and TURN authorization was cancelled on the nearby device"
        );
        assert!(!cancelled.contains("allowlist"));
        assert!(!cancelled.contains("quota"));

        let passkey = turn_unavailable_error(
            ConnectivityFailure::DataChannel(DataChannelEstablishmentFailure::Failed(
                "direct failed".into(),
            ))
            .final_error(),
            TurnUnavailableReason::PasskeyUnavailable,
        );
        assert_eq!(
            passkey,
            "direct failed; the direct peer-to-peer connection failed, and the passkey on the nearby device could not produce the identity proof required for TURN"
        );
        assert!(!passkey.contains("allowlist"));
        assert!(!passkey.contains("quota"));
        assert!(!passkey.contains("temporarily unavailable"));

        let provider = turn_unavailable_error(
            ConnectivityFailure::IceGatheringTimedOut.final_error(),
            TurnUnavailableReason::ProviderUnavailable,
        );
        assert_eq!(
            provider,
            "timed out gathering ICE candidates for the WebRTC offer; the direct peer-to-peer connection failed, and TURN relay is temporarily unavailable"
        );
        assert!(!provider.contains("allowlist"));
        assert!(!provider.contains("quota"));
    }

    #[test]
    fn only_exact_turn_policy_denial_is_classified_as_not_allowlisted() {
        assert!(matches!(
            turn_response_error(403, r#"{"kind":"turn-not-allowlisted"}"#),
            TurnCredentialFetchError::AuthorizationRejected
        ));
        for body in [
            "Forbidden",
            r#"{"kind":"turn-configuration-error"}"#,
            r#"{"kind":"turn-not-allowlisted","extra":true}"#,
            r#"{"kind":"turn-not-allowlisted"} trailing"#,
        ] {
            assert!(matches!(
                turn_response_error(403, body),
                TurnCredentialFetchError::Unavailable(_)
            ));
        }
        assert!(matches!(
            turn_response_error(503, r#"{"kind":"turn-configuration-error"}"#),
            TurnCredentialFetchError::Unavailable(_)
        ));
    }

    #[test]
    fn turn_fetch_sends_room_capability_only_in_authorization_header() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let count = stream.read(&mut buffer).unwrap();
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..count]);
                assert!(
                    request.len() <= 8192,
                    "request headers were unexpectedly large"
                );
            }

            let body = format!(
                r#"{{"iceServers":[{{"urls":"{CLOUDFLARE_TURN_UDP_URL}","username":"turn-user","credential":"turn-password"}}]}}"#
            );
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
            String::from_utf8(request).unwrap()
        });

        let encoded_capability = URL_SAFE_NO_PAD.encode([0x5a; 64]);
        let capability = TurnCapability::parse(&encoded_capability).unwrap();
        let url = format!("http://{address}/turn");
        let servers = match fetch_turn_ice_servers(
            &url,
            &capability,
            Instant::now() + Duration::from_secs(5),
        ) {
            Ok(servers) => servers,
            Err(_) => panic!("TURN credential fetch failed"),
        };
        assert_eq!(servers.len(), 2);

        let request = server.join().unwrap();
        let mut lines = request.lines();
        assert_eq!(lines.next(), Some("GET /turn HTTP/1.1"));
        let authorization = lines.find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("authorization")
                .then(|| value.trim())
        });
        assert_eq!(
            authorization,
            Some(format!("Bearer {encoded_capability}").as_str())
        );
    }

    #[test]
    fn turn_response_cannot_redirect_native_client() {
        let response: TurnCredentialResponse = serde_json::from_value(serde_json::json!({
            "iceServers": [
                {
                    "urls": ["turn:attacker.example:3478?transport=udp"],
                    "username": "bad-user",
                    "credential": "bad-password"
                },
                {
                    "urls": [
                        "turn:turn.cloudflare.com:53?transport=udp",
                        CLOUDFLARE_TURN_UDP_URL,
                        "turns:turn.cloudflare.com:443?transport=tcp"
                    ],
                    "username": "good-user",
                    "credential": "good-password"
                }
            ]
        }))
        .unwrap();
        let servers = ice_servers_from_turn_response(response).unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].urls, [CLOUDFLARE_STUN_URL]);
        assert_eq!(servers[1].urls, [CLOUDFLARE_TURN_UDP_URL]);
        assert_eq!(servers[1].username, "good-user");
        assert_eq!(servers[1].credential, "good-password");
    }

    #[test]
    fn turn_response_without_exact_cloudflare_udp_url_is_rejected() {
        let response: TurnCredentialResponse = serde_json::from_value(serde_json::json!({
            "iceServers": [{
                "urls": ["turn:turn.cloudflare.com:53?transport=udp"],
                "username": "user",
                "credential": "password"
            }]
        }))
        .unwrap();
        assert!(ice_servers_from_turn_response(response).is_err());
    }

    #[test]
    fn native_data_channel_connects_over_a_non_trickle_loopback_offer() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .unwrap();

        let (offer_pc, offer_dc, open_rx, _offer_events) = runtime
            .block_on(create_offer_peer(
                Vec::new(),
                IceCandidateScope::IncludeLoopback,
            ))
            .unwrap();
        let (message_tx, message_rx) = mpsc::channel();

        let answer_pc = runtime
            .block_on(async {
                let mut media_engine = MediaEngine::default();
                media_engine.register_default_codecs()?;
                let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
                let mut setting_engine = SettingEngine::default();
                setting_engine.set_include_loopback_candidate(true);
                let api = APIBuilder::new()
                    .with_media_engine(media_engine)
                    .with_interceptor_registry(registry)
                    .with_setting_engine(setting_engine)
                    .build();
                let peer = Arc::new(api.new_peer_connection(RTCConfiguration::default()).await?);
                peer.on_data_channel(Box::new(move |channel| {
                    let message_tx = message_tx.clone();
                    Box::pin(async move {
                        assert_eq!(channel.label(), DATA_CHANNEL_LABEL);
                        assert_eq!(channel.protocol(), DATA_CHANNEL_PROTOCOL);
                        channel.on_message(Box::new(move |message| {
                            let message_tx = message_tx.clone();
                            Box::pin(async move {
                                let _ = message_tx.send(message.data.to_vec());
                            })
                        }));
                    })
                }));
                Ok::<_, webrtc::Error>(peer)
            })
            .unwrap();

        let offer_sdp = runtime
            .block_on(gather_offer(&offer_pc, Duration::from_secs(10)))
            .unwrap();
        runtime
            .block_on(
                answer_pc.set_remote_description(RTCSessionDescription::offer(offer_sdp).unwrap()),
            )
            .unwrap();
        let answer_sdp = runtime
            .block_on(async {
                let answer = answer_pc.create_answer(None).await?;
                let mut gathering_complete = answer_pc.gathering_complete_promise().await;
                answer_pc.set_local_description(answer).await?;
                tokio::time::timeout(Duration::from_secs(10), gathering_complete.recv())
                    .await
                    .map_err(|_| webrtc::Error::new("answer ICE gathering timed out".into()))?;
                answer_pc
                    .local_description()
                    .await
                    .map(|description| description.sdp)
                    .ok_or_else(|| webrtc::Error::new("missing answer description".into()))
            })
            .unwrap();
        runtime
            .block_on(
                offer_pc.set_remote_description(RTCSessionDescription::answer(answer_sdp).unwrap()),
            )
            .unwrap();

        assert!(matches!(
            open_rx.recv_timeout(Duration::from_secs(10)).unwrap(),
            EstablishmentEvent::Open
        ));
        send_data_text_and_drain_bounded(&runtime, &offer_dc, "hello".into()).unwrap();
        close_rtc_bounded(&runtime, &offer_pc, &offer_dc);
        assert_eq!(
            message_rx.recv_timeout(Duration::from_secs(10)).unwrap(),
            b"hello"
        );

        runtime
            .block_on(async { tokio::time::timeout(RTC_CLOSE_TIMEOUT, answer_pc.close()).await })
            .ok();
    }
}
