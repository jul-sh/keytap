//! Authenticate with a passkey on a nearby browser over WebRTC.
//!
//! The QR fragment contains a one-time 32-byte CLI public key. The Worker sees
//! only a hash-derived rendezvous id. The CLI signs the full, non-trickle
//! WebRTC offer (including its DTLS fingerprint), so the phone authenticates
//! the data-channel peer before it releases any WebAuthn result.

use crate::nearby_identity::{
    Anchor as IdentityAnchor, PairingAnchor as IdentityPairingAnchor,
    InitCommitError as IdentityInitCommitError, PairingConstraint as IdentityPairingConstraint,
    PendingInit as PendingIdentityInit, PersistedInit as PersistedIdentityInit,
    PinnedAnchor as PinnedIdentityAnchor,
    Proof as NearbyIdentityProof, ProofBinding as NearbyIdentityProofBinding,
    ProofFields as NearbyIdentityProofFields, Verification as IdentityVerification,
    VerificationError as IdentityVerificationError,
};
use crate::nearby_protocol::{CliSessionKey, PhoneAnswer};
use crate::nearby_sas::{
    ConfirmedComparison as SasConfirmation, Context as SasContext,
    InitiatorCommitment as SasCommitment,
};
use crate::note;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::net::TcpStream;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};
use tungstenite::client::connect_with_config;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
#[cfg(test)]
use webrtc::peer_connection::policy::ice_transport_policy::RTCIceTransportPolicy;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;
use zeroize::Zeroizing;

const DEFAULT_SIGNAL_URL: &str = "wss://keytap-relay.julsh.workers.dev";
const PAGE_URL: &str = "https://keytap.jul.sh/nearby";
const DATA_CHANNEL_LABEL: &str = "keytap/3";
const DATA_CHANNEL_PROTOCOL: &str = "keytap.v3";
const PROTOCOL_VERSION: u8 = 3;

const PEER_JOIN_TIMEOUT: Duration = Duration::from_secs(300);
const CONNECTION_SETUP_TIMEOUT: Duration = Duration::from_secs(120);
const CEREMONY_RESPONSE_TIMEOUT: Duration = Duration::from_secs(150);
const ICE_GATHER_TIMEOUT: Duration = Duration::from_secs(45);
const DATA_CHANNEL_OPEN_TIMEOUT: Duration = Duration::from_secs(60);
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const SIGNAL_FRAME_LIMIT: usize = 128 * 1024;
const DATA_FRAME_LIMIT: usize = 16 * 1024;

// webrtc-rs 0.17.x currently implements TURN allocation over UDP only. Keep
// the accepted endpoints explicit so neither the signaling Worker nor a
// modified credential response can redirect the native client elsewhere.
const CLOUDFLARE_STUN_URL: &str = "stun:stun.cloudflare.com:3478";
const CLOUDFLARE_TURN_UDP_URL: &str = "turn:turn.cloudflare.com:3478?transport=udp";

const DEFAULT_REMEMBER_WINDOW_SECS: u64 = 60;
const REMEMBER_PENDING_EXTENSION_SECS: u64 = 150;
const MAX_LINGER_SECS: u64 = 600;

/// How long the CLI offers the phone's post-auth remember action.
fn remember_window_secs() -> u64 {
    match std::env::var("KEYTAP_REMEMBER_WINDOW") {
        Ok(value) => value
            .trim()
            .parse::<u64>()
            .map(|secs| secs.min(MAX_LINGER_SECS))
            .unwrap_or(DEFAULT_REMEMBER_WINDOW_SECS),
        Err(_) => DEFAULT_REMEMBER_WINDOW_SECS,
    }
}

/// A completed nearby assertion ceremony.
pub struct NearbyAssertion {
    pub prf_output: Vec<u8>,
    pub credential_id: Vec<u8>,
    /// Retained for the caller's established API. Protocol v3 performs remember
    /// only as an acknowledged follow-up, so this is always false.
    pub remember_requested: bool,
    pub followup: Option<RememberWindow>,
}

/// Authenticate via a nearby device. `offer_remember` controls whether the
/// phone may perform the acknowledged second ceremony used for local storage.
pub fn authenticate_nearby(name: &str, offer_remember: bool) -> NearbyAssertion {
    let result = run_nearby_flow(Operation::Assert {
        name,
        offer_remember,
    })
    .unwrap_or_else(|error| crate::die(&error));

    match result {
        FlowResult::Assertion {
            credential_id,
            prf_output,
            followup,
        } => NearbyAssertion {
            credential_id,
            prf_output,
            remember_requested: false,
            followup: followup.map(|window| *window),
        },
        FlowResult::Registration { .. } => {
            crate::die("nearby protocol returned a registration for an assertion request")
        }
    }
}

/// Register a passkey via a nearby device.
pub fn register_nearby(pending_init: PendingIdentityInit) -> PersistedIdentityInit {
    let result = run_nearby_flow(Operation::Register { pending_init })
        .unwrap_or_else(|error| crate::die(&error));
    match result {
        FlowResult::Registration { registration } => {
            eprintln!("Passkey registered successfully via nearby device.");
            registration
        }
        FlowResult::Assertion { .. } => {
            crate::die("nearby protocol returned an assertion for a registration request")
        }
    }
}

enum Operation<'a> {
    Register { pending_init: PendingIdentityInit },
    Assert { name: &'a str, offer_remember: bool },
}

/// Everything valid only for one ceremony kind lives in that variant.
enum FlowPlan {
    Registration {
        request: PairingCeremonyRequest,
        pending_init: PendingIdentityInit,
    },
    PairingAssertion {
        request: PairingCeremonyRequest,
        key_name: String,
        challenge: [u8; 32],
        remember: RememberOffer,
        anchor: IdentityPairingAnchor,
    },
    PinnedAssertion {
        request: PinnedCeremonyRequest,
        key_name: String,
        challenge: [u8; 32],
        remember: RememberOffer,
        anchor: PinnedIdentityAnchor,
    },
}

enum AuthenticatedPlan {
    Registration {
        authorization: PairingAuthorization,
        pending_init: PendingIdentityInit,
    },
    Assertion {
        key_name: String,
        challenge: [u8; 32],
        remember: RememberOffer,
        identity: AuthenticatedIdentity,
    },
}

enum AuthenticatedIdentity {
    Pairing {
        anchor: IdentityPairingAnchor,
        authorization: PairingAuthorization,
    },
    Pinned {
        anchor: PinnedIdentityAnchor,
        session_digest: [u8; 32],
    },
}

struct PairingAuthorization {
    confirmation: SasConfirmation,
    release_signature: [u8; 64],
}

struct AssertionCompletion {
    key_name: String,
    challenge: [u8; 32],
    remember: RememberOffer,
    identity: AuthenticatedIdentity,
    credential_id: String,
    prf_first: String,
    proof: IdentityProofDto,
}

enum FlowResult {
    Registration {
        registration: PersistedIdentityInit,
    },
    Assertion {
        credential_id: Vec<u8>,
        prf_output: Vec<u8>,
        followup: Option<Box<RememberWindow>>,
    },
}

/// The open post-auth opt-in window. Keeping the peer connection and runtime
/// here lets `main.rs` emit the key before waiting for the optional gesture.
pub struct RememberWindow {
    session: RtcSession,
    name: String,
    window_secs: u64,
    credential_id: Vec<u8>,
    prf_output: Zeroizing<Vec<u8>>,
}

enum RememberState {
    AwaitingChoice { deadline: Instant },
    AwaitingResult { deadline: Instant },
}

impl RememberWindow {
    pub fn settle(mut self, raw_key: &[u8]) {
        note(&format!(
            "Key delivered. Waiting up to {}s in case you choose \u{201c}remember\u{201d} on \
             your phone (finishing or closing the page there ends the wait; Ctrl-C skips).",
            self.window_secs
        ));
        exit_zero_on_sigint();
        self.run_window(raw_key);
        self.session.close();
    }

    fn run_window(&mut self, raw_key: &[u8]) {
        let start = Instant::now();
        let hard_stop = start + Duration::from_secs(MAX_LINGER_SECS);
        let mut state = RememberState::AwaitingChoice {
            deadline: start + Duration::from_secs(self.window_secs),
        };
        let mut announced_pending = false;
        let mut warned_mismatch = false;

        loop {
            let deadline = match state {
                RememberState::AwaitingChoice { deadline }
                | RememberState::AwaitingResult { deadline } => deadline.min(hard_stop),
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return;
            }

            let message = match self.session.receive(remaining) {
                Ok(message) => message,
                Err(_) => return,
            };

            state = match (state, message) {
                (_, PhoneMessage::Done { .. }) => return,
                (RememberState::AwaitingChoice { .. }, PhoneMessage::RememberBegin { .. }) => {
                    if !announced_pending {
                        announced_pending = true;
                        note("Remember chosen on the phone; waiting for the passkey approval…");
                    }
                    if self
                        .session
                        .send(&CliMessage::RememberReady {
                            version: PROTOCOL_VERSION,
                        })
                        .is_err()
                    {
                        return;
                    }
                    RememberState::AwaitingResult {
                        deadline: Instant::now()
                            + Duration::from_secs(REMEMBER_PENDING_EXTENSION_SECS),
                    }
                }
                (
                    RememberState::AwaitingResult { deadline },
                    PhoneMessage::RememberBegin { .. },
                ) => {
                    // Idempotent retry if the phone did not observe the first ACK.
                    if self
                        .session
                        .send(&CliMessage::RememberReady {
                            version: PROTOCOL_VERSION,
                        })
                        .is_err()
                    {
                        return;
                    }
                    RememberState::AwaitingResult { deadline }
                }
                (
                    RememberState::AwaitingResult { deadline },
                    PhoneMessage::RememberResult {
                        credential_id,
                        prf_first,
                        ..
                    },
                ) => match decode_assertion_fields(&credential_id, &prf_first) {
                    Err(error) => {
                        self.session
                            .send_protocol_error(ProtocolErrorCode::InvalidMessage);
                        note(&format!(
                            "warning: ignored invalid remember approval: {error}"
                        ));
                        RememberState::AwaitingResult { deadline }
                    }
                    Ok(payload) if self.matches_first_ceremony(&payload) => {
                        match crate::remember::remember_requested_nearby(
                            &self.name,
                            &self.credential_id,
                            raw_key,
                        ) {
                            crate::remember::NearbyRememberOutcome::Stored => {
                                self.session
                                    .send(&CliMessage::RememberAccepted {
                                        version: PROTOCOL_VERSION,
                                    })
                                    .ok();
                            }
                            crate::remember::NearbyRememberOutcome::Unavailable => {
                                self.session
                                    .send(&CliMessage::RememberRejected {
                                        version: PROTOCOL_VERSION,
                                        reason: RememberRejectedReason::Unavailable,
                                    })
                                    .ok();
                            }
                        }
                        return;
                    }
                    Ok(_) => {
                        self.session
                            .send(&CliMessage::RememberRejected {
                                version: PROTOCOL_VERSION,
                                reason: RememberRejectedReason::Mismatch,
                            })
                            .ok();
                        if !warned_mismatch {
                            warned_mismatch = true;
                            note(&format!(
                                "warning: the \u{201c}remember\u{201d} approval on your phone \
                                     used a different passkey than the one that derived this key; \
                                     nothing was stored. You can retry on the phone, or run \
                                     `keytap remember {}` on this machine to store it \
                                     deliberately.",
                                self.name
                            ));
                        }
                        RememberState::AwaitingChoice { deadline }
                    }
                },
                (
                    state @ RememberState::AwaitingChoice { .. },
                    PhoneMessage::RememberResult { .. },
                ) => {
                    self.session
                        .send_protocol_error(ProtocolErrorCode::UnexpectedMessage);
                    state
                }
                (state, PhoneMessage::SasPhoneCommit { .. })
                | (state, PhoneMessage::SasPhoneReveal { .. })
                | (state, PhoneMessage::SasPhoneComplete { .. })
                | (state, PhoneMessage::SasPhoneRejected { .. })
                | (state, PhoneMessage::PairedRegistrationResult { .. })
                | (state, PhoneMessage::PairedAssertionResult { .. })
                | (state, PhoneMessage::AssertionResult { .. }) => {
                    self.session
                        .send_protocol_error(ProtocolErrorCode::UnexpectedMessage);
                    state
                }
            };
        }
    }

    fn matches_first_ceremony(&self, payload: &AssertionPayload) -> bool {
        use subtle::ConstantTimeEq;
        let prf_matches: bool = payload.prf_output.ct_eq(&self.prf_output).into();
        payload.credential_id == self.credential_id && prf_matches
    }
}

/// From here to exit, Ctrl-C means "stop waiting, all is well" because the
/// command already emitted its result.
fn exit_zero_on_sigint() {
    extern "C" fn exit_ok(_: libc::c_int) {
        unsafe { libc::_exit(0) }
    }
    unsafe {
        libc::signal(libc::SIGINT, exit_ok as extern "C" fn(libc::c_int) as usize);
    }
}

fn run_nearby_flow(operation: Operation<'_>) -> Result<FlowResult, String> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    // Validate all local inputs before displaying a QR code or asking the
    // user to touch another device.
    let plan = build_plan(operation)?;

    let signal_base = signal_base_url();
    let cli_session_key = CliSessionKey::generate();
    let rendezvous_id = cli_session_key.rendezvous_id();
    let ws_url = format!("{signal_base}/v2/signal/{rendezvous_id}?role=cli");
    let mut signaling = connect_signaling(&ws_url)?;

    let url = format!("{PAGE_URL}#k={}", cli_session_key.fragment_value());
    print_qr(&url)?;

    let peer_join_deadline = Instant::now() + PEER_JOIN_TIMEOUT;
    wait_for_peer(&mut signaling, peer_join_deadline)?;
    let setup_deadline = Instant::now() + CONNECTION_SETUP_TIMEOUT;

    let turn_url = format!(
        "{}/v2/signal/{rendezvous_id}/turn/cli",
        http_base_url(&signal_base)?
    );
    let ice_servers = match fetch_turn_ice_servers(&turn_url, setup_deadline) {
        Ok(servers) => servers,
        Err(error) => {
            note(&format!(
                "warning: Cloudflare TURN is unavailable ({error}); trying a direct connection"
            ));
            stun_only_ice_servers()
        }
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("keytap-webrtc")
        .build()
        .map_err(|error| format!("failed to start WebRTC runtime: {error}"))?;

    let (peer_connection, data_channel, open_rx, incoming) = runtime
        .block_on(create_offer_peer(ice_servers))
        .map_err(|error| format!("failed to create WebRTC connection: {error}"))?;

    let offer_sdp = runtime
        .block_on(gather_offer(
            &peer_connection,
            remaining_until(setup_deadline)?.min(ICE_GATHER_TIMEOUT),
        ))
        .map_err(|error| format!("failed to gather WebRTC offer: {error}"))?;
    let offer = cli_session_key.sign_offer(offer_sdp.as_bytes());
    send_signal(&mut signaling, &offer)?;

    let answer_sdp = wait_for_answer(&mut signaling, setup_deadline)?;
    let identity_binding =
        cli_session_key.identity_session_binding(offer_sdp.as_bytes(), answer_sdp.as_bytes());
    let answer = RTCSessionDescription::answer(answer_sdp)
        .map_err(|error| format!("phone sent an invalid WebRTC answer: {error}"))?;
    runtime
        .block_on(peer_connection.set_remote_description(answer))
        .map_err(|error| format!("failed to apply WebRTC answer: {error}"))?;

    let open_timeout = remaining_until(setup_deadline)?.min(DATA_CHANNEL_OPEN_TIMEOUT);
    match open_rx.recv_timeout(open_timeout) {
        Ok(EstablishmentEvent::Open) => {}
        Ok(EstablishmentEvent::Failed(error)) => return Err(error),
        Err(_) => {
            return Err("timed out establishing the encrypted WebRTC data channel".to_string())
        }
    }

    let mut session = RtcSession {
        runtime,
        peer_connection,
        data_channel,
        incoming,
        signaling,
        closed: false,
    };

    let plan = authenticate_plan(plan, &session, identity_binding, &cli_session_key)?;
    let first = session.receive(CEREMONY_RESPONSE_TIMEOUT)?;
    let result = match (plan, first) {
        (
            AuthenticatedPlan::Registration {
                authorization,
                pending_init,
            },
            PhoneMessage::PairedRegistrationResult {
                credential_id,
                release_signature,
                ..
            },
        ) => {
            verify_release_echo(&release_signature, &authorization.release_signature)?;
            let credential_id = decode_credential_id(&credential_id)?;
            let registration = match pending_init.commit(&credential_id) {
                Ok(registration) => registration,
                Err(IdentityInitCommitError::NotPublished(error)) => {
                    session
                        .send(&CliMessage::InitialRejected {
                            version: PROTOCOL_VERSION,
                            reason: InitialRejectedReason::IdentityStoreUnavailable,
                        })
                        .ok();
                    session.close();
                    return Err(format!(
                        "passkey was created, but its paired identity could not be stored: {error}"
                    ));
                }
                Err(IdentityInitCommitError::PublishedButNotDurable(error)) => {
                    // This cannot make the identity publication durable, but
                    // rotating every reachable remembered root further
                    // reduces the chance of stale-key resurrection. It is
                    // still indeterminate and must never receive a success ACK.
                    crate::remember::after_init(&credential_id);
                    session
                        .send(&CliMessage::InitialIndeterminate {
                            version: PROTOCOL_VERSION,
                            reason: InitialIndeterminateReason::IdentityDurabilityUnknown,
                        })
                        .ok();
                    session.close();
                    return Err(format!(
                        "passkey was created and its paired identity is visible, but durable storage could not be confirmed: {error}. No success was acknowledged; rerun `keytap init --force` before relying on it"
                    ));
                }
            };
            if let Err(error) = session.send(&CliMessage::InitialAccepted {
                version: PROTOCOL_VERSION,
            }) {
                note(&format!(
                    "Passkey identity was stored, but the phone acknowledgement could not be delivered: {error}"
                ));
            }
            session.close();
            FlowResult::Registration { registration }
        }
        (
            AuthenticatedPlan::Assertion {
                key_name,
                challenge,
                remember,
                identity:
                    AuthenticatedIdentity::Pairing {
                        anchor,
                        authorization,
                    },
            },
            PhoneMessage::PairedAssertionResult {
                credential_id,
                prf_first,
                identity: proof,
                release_signature,
                ..
            },
        ) => {
            verify_release_echo(&release_signature, &authorization.release_signature)?;
            complete_assertion(
                session,
                AssertionCompletion {
                    key_name,
                    challenge,
                    remember,
                    identity: AuthenticatedIdentity::Pairing {
                        anchor,
                        authorization,
                    },
                    credential_id,
                    prf_first,
                    proof,
                },
            )?
        }
        (
            AuthenticatedPlan::Assertion {
                key_name,
                challenge,
                remember,
                identity:
                    AuthenticatedIdentity::Pinned {
                        anchor,
                        session_digest,
                    },
            },
            PhoneMessage::AssertionResult {
                credential_id,
                prf_first,
                identity: proof,
                ..
            },
        ) => complete_assertion(
            session,
            AssertionCompletion {
                key_name,
                challenge,
                remember,
                identity: AuthenticatedIdentity::Pinned {
                    anchor,
                    session_digest,
                },
                credential_id,
                prf_first,
                proof,
            },
        )?,
        (_, PhoneMessage::Done { .. }) => {
            session.close();
            return Err("the page on your phone was closed before approving".into());
        }
        _ => {
            session.send_protocol_error(ProtocolErrorCode::UnexpectedMessage);
            session.close();
            return Err("phone returned an unexpected nearby protocol message".into());
        }
    };

    Ok(result)
}

fn complete_assertion(
    mut session: RtcSession,
    completion: AssertionCompletion,
) -> Result<FlowResult, String> {
    let AssertionCompletion {
        key_name,
        challenge,
        remember,
        identity,
        credential_id,
        prf_first,
        proof,
    } = completion;
    let payload = decode_assertion_fields(&credential_id, &prf_first)?;
    let proof = decode_identity_proof(&payload.credential_id, proof)?;
    let verification = match identity {
        AuthenticatedIdentity::Pairing {
            anchor,
            authorization,
        } => {
            let fields = NearbyIdentityProofFields {
                binding: NearbyIdentityProofBinding::BootstrapSas {
                    confirmation: &authorization.confirmation,
                },
                challenge: &challenge,
                credential_id: &payload.credential_id,
                prf_output: &payload.prf_output,
                key_name: &key_name,
                public_key: &proof.public_key,
            };
            anchor.verify_and_pin_after_sas(&proof, &fields)
        }
        AuthenticatedIdentity::Pinned {
            anchor,
            session_digest,
        } => {
            let fields = NearbyIdentityProofFields {
                binding: NearbyIdentityProofBinding::PinnedSession {
                    digest: &session_digest,
                },
                challenge: &challenge,
                credential_id: &payload.credential_id,
                prf_output: &payload.prf_output,
                key_name: &key_name,
                public_key: &proof.public_key,
            };
            anchor
                .verify(&proof, &fields)
                .map(|()| IdentityVerification::MatchedPin)
        }
    };
    match verification {
        Ok(IdentityVerification::ConcurrentPairingMatched) => {}
        Ok(IdentityVerification::MatchedPin) => {}
        Ok(IdentityVerification::Paired { fingerprint }) => note(&format!(
            "Pairing confirmed; pinned this passkey identity for future nearby requests ({fingerprint})."
        )),
        Ok(IdentityVerification::InitPinCompleted { fingerprint }) => note(&format!(
            "Pairing confirmed; completed the passkey identity pin created by init ({fingerprint})."
        )),
        Err(error @ IdentityVerificationError::DurabilityUnknown(_)) => {
            session
                .send(&CliMessage::InitialIndeterminate {
                    version: PROTOCOL_VERSION,
                    reason: InitialIndeterminateReason::IdentityDurabilityUnknown,
                })
                .ok();
            session.close();
            return Err(identity_error_message(error));
        }
        Err(error) => {
            session
                .send(&CliMessage::InitialRejected {
                    version: PROTOCOL_VERSION,
                    reason: initial_rejection_reason(&error),
                })
                .ok();
            session.close();
            return Err(identity_error_message(error));
        }
    }
    let acknowledgement_delivered = match session.send(&CliMessage::InitialAccepted {
        version: PROTOCOL_VERSION,
    }) {
        Ok(()) => true,
        Err(error) => {
            note(&format!(
                "Passkey result was verified, but the phone acknowledgement could not be delivered: {error}"
            ));
            false
        }
    };

    let followup = match (remember, acknowledgement_delivered) {
        (RememberOffer::Disabled, _) | (_, false) => {
            session.close();
            None
        }
        (RememberOffer::Available { window_secs }, true) => Some(Box::new(RememberWindow {
            session,
            name: key_name,
            window_secs,
            credential_id: payload.credential_id.clone(),
            prf_output: Zeroizing::new(payload.prf_output.to_vec()),
        })),
    };

    Ok(FlowResult::Assertion {
        credential_id: payload.credential_id,
        prf_output: payload.prf_output.to_vec(),
        followup,
    })
}

fn verify_release_echo(encoded: &str, expected: &[u8; 64]) -> Result<(), String> {
    use subtle::ConstantTimeEq;
    let actual = decode_fixed_base64url::<64>(encoded, "pairing release signature")?;
    if bool::from(actual.ct_eq(expected)) {
        Ok(())
    } else {
        Err("phone returned a result from before CLI pairing confirmation".to_string())
    }
}

fn authenticate_plan(
    plan: FlowPlan,
    session: &RtcSession,
    session_binding: [u8; 32],
    cli_session_key: &CliSessionKey,
) -> Result<AuthenticatedPlan, String> {
    match plan {
        FlowPlan::Registration {
            request,
            pending_init,
        } => {
            let authorization = run_pairing(session, request, &session_binding, cli_session_key)?;
            Ok(AuthenticatedPlan::Registration {
                authorization,
                pending_init,
            })
        }
        FlowPlan::PairingAssertion {
            request,
            key_name,
            challenge,
            remember,
            anchor,
        } => {
            let authorization = run_pairing(session, request, &session_binding, cli_session_key)?;
            Ok(AuthenticatedPlan::Assertion {
                key_name,
                challenge,
                remember,
                identity: AuthenticatedIdentity::Pairing {
                    anchor,
                    authorization,
                },
            })
        }
        FlowPlan::PinnedAssertion {
            request,
            key_name,
            challenge,
            remember,
            anchor,
        } => {
            session.send(&CliMessage::Request {
                version: PROTOCOL_VERSION,
                request,
            })?;
            Ok(AuthenticatedPlan::Assertion {
                key_name,
                challenge,
                remember,
                identity: AuthenticatedIdentity::Pinned {
                    anchor,
                    session_digest: session_binding,
                },
            })
        }
    }
}

fn run_pairing(
    session: &RtcSession,
    request: PairingCeremonyRequest,
    session_binding: &[u8; 32],
    cli_session_key: &CliSessionKey,
) -> Result<PairingAuthorization, String> {
    let canonical_request = request.sas_bytes()?;
    let pending = SasCommitment::generate(SasContext::bind(session_binding, &canonical_request))?;
    session.send(&CliMessage::PairingRequest {
        version: PROTOCOL_VERSION,
        request,
        cli_commitment: URL_SAFE_NO_PAD.encode(pending.commitment()),
    })?;

    let phone_commitment = match session.receive(CEREMONY_RESPONSE_TIMEOUT)? {
        PhoneMessage::SasPhoneCommit { commitment, .. } => {
            decode_fixed_base64url::<32>(&commitment, "phone pairing commitment")?
        }
        PhoneMessage::SasPhoneRejected { .. } | PhoneMessage::Done { .. } => {
            return Err("pairing was cancelled on the phone; no key was accepted".into())
        }
        _ => return reject_unexpected_pairing(session),
    };
    let awaiting_reveal = pending.accept_phone_commitment(phone_commitment);
    session.send(&CliMessage::SasCliReveal {
        version: PROTOCOL_VERSION,
        nonce: URL_SAFE_NO_PAD.encode(awaiting_reveal.cli_nonce()),
    })?;

    let phone_nonce = match session.receive(CEREMONY_RESPONSE_TIMEOUT)? {
        PhoneMessage::SasPhoneReveal { nonce, .. } => {
            decode_fixed_base64url::<32>(&nonce, "phone pairing nonce")?
        }
        PhoneMessage::SasPhoneRejected { .. } | PhoneMessage::Done { .. } => {
            return Err("pairing was cancelled on the phone; no key was accepted".into())
        }
        _ => return reject_unexpected_pairing(session),
    };
    let comparison = awaiting_reveal.accept_phone_nonce(phone_nonce)?;

    eprintln!();
    eprintln!("Pairing words — compare these with your phone:");
    eprintln!();
    eprintln!("    {}", comparison.phrase());
    eprintln!();
    eprintln!("Finish the passkey prompt on your phone. The result stays there until you confirm these words here.");

    let release_nonce = match session.receive(CEREMONY_RESPONSE_TIMEOUT)? {
        PhoneMessage::SasPhoneComplete { release_nonce, .. } => {
            decode_fixed_base64url::<32>(&release_nonce, "phone release nonce")?
        }
        PhoneMessage::SasPhoneRejected { .. } | PhoneMessage::Done { .. } => {
            return Err(
                "pairing was rejected or cancelled on the phone; no key was accepted".into(),
            )
        }
        _ => return reject_unexpected_pairing(session),
    };

    let confirmed = match comparison.phone_result_held().confirm_with_tty() {
        Ok(confirmed) => confirmed,
        Err(error) => {
            session
                .send(&CliMessage::SasCliRejected {
                    version: PROTOCOL_VERSION,
                    release_nonce: URL_SAFE_NO_PAD.encode(release_nonce),
                })
                .ok();
            return Err(error);
        }
    };
    let release_signature = cli_session_key.sign_pairing_release(
        session_binding,
        confirmed.binding_digest(),
        &canonical_request,
        &release_nonce,
    );
    session.send(&CliMessage::SasCliAccepted {
        version: PROTOCOL_VERSION,
        release_nonce: URL_SAFE_NO_PAD.encode(release_nonce),
        signature: URL_SAFE_NO_PAD.encode(release_signature),
    })?;
    Ok(PairingAuthorization {
        confirmation: confirmed,
        release_signature,
    })
}

fn reject_unexpected_pairing<T>(session: &RtcSession) -> Result<T, String> {
    session.send_protocol_error(ProtocolErrorCode::UnexpectedMessage);
    Err("phone returned an unexpected pairing protocol message; run the command again for a fresh QR code".into())
}

fn signal_base_url() -> String {
    std::env::var("KEYTAP_SIGNAL_URL")
        .or_else(|_| std::env::var("KEYTAP_RELAY_URL"))
        .unwrap_or_else(|_| DEFAULT_SIGNAL_URL.to_string())
        .trim_end_matches('/')
        .to_string()
}

fn connect_signaling(url: &str) -> Result<WebSocket<MaybeTlsStream<TcpStream>>, String> {
    connect_with_config(
        url,
        Some(WebSocketConfig {
            max_message_size: Some(SIGNAL_FRAME_LIMIT),
            max_frame_size: Some(SIGNAL_FRAME_LIMIT),
            ..Default::default()
        }),
        3,
    )
    .map(|(socket, _)| socket)
    .map_err(|error| format!("failed to connect to signaling service: {error}"))
}

fn http_base_url(signal_base: &str) -> Result<String, String> {
    if let Some(rest) = signal_base.strip_prefix("wss://") {
        Ok(format!("https://{rest}"))
    } else if let Some(rest) = signal_base.strip_prefix("ws://") {
        Ok(format!("http://{rest}"))
    } else {
        Err("signaling URL must begin with wss:// or ws://".into())
    }
}

fn print_qr(url: &str) -> Result<(), String> {
    eprintln!();
    eprintln!("Scan to authenticate with a passkey on your phone (encrypted with WebRTC):");
    eprintln!();
    let qr_string = qr2term::generate_qr_string(url)
        .map_err(|error| format!("failed to render QR code: {error}"))?;
    eprint!("{qr_string}");
    eprintln!();
    eprintln!("Or open: {url}");
    eprintln!();
    eprintln!("Waiting for your phone (timeout: 5 minutes)…");
    Ok(())
}

fn wait_for_peer(
    signaling: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    deadline: Instant,
) -> Result<(), String> {
    loop {
        let message = read_signal(signaling, deadline)?;
        match message {
            Message::Text(text) => {
                if text.len() > SIGNAL_FRAME_LIMIT {
                    continue;
                }
                let control: Result<SignalControl, _> = serde_json::from_str(text.as_str());
                if matches!(control, Ok(SignalControl::PeerReady)) {
                    return Ok(());
                }
            }
            Message::Ping(data) => {
                signaling
                    .send(Message::Pong(data))
                    .map_err(|error| format!("signaling connection error: {error}"))?;
            }
            Message::Close(_) => {
                return Err("signaling connection closed before the phone joined".into())
            }
            _ => {}
        }
    }
}

fn wait_for_answer(
    signaling: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    deadline: Instant,
) -> Result<String, String> {
    loop {
        let message = read_signal(signaling, deadline)?;
        match message {
            Message::Text(text) => {
                if text.len() > SIGNAL_FRAME_LIMIT {
                    continue;
                }
                let body = match PhoneAnswer::decode(text.as_str()) {
                    Ok(body) => body,
                    Err(_) => continue,
                };
                return String::from_utf8(body)
                    .map_err(|_| "phone WebRTC answer was not UTF-8".to_string());
            }
            Message::Ping(data) => {
                signaling
                    .send(Message::Pong(data))
                    .map_err(|error| format!("signaling connection error: {error}"))?;
            }
            Message::Close(_) => {
                return Err("signaling connection closed before the phone answer arrived".into())
            }
            _ => {}
        }
    }
}

fn send_signal(
    signaling: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    envelope: &impl Serialize,
) -> Result<(), String> {
    let json = serde_json::to_string(envelope)
        .map_err(|error| format!("failed to encode WebRTC offer: {error}"))?;
    signaling
        .send(Message::Text(json))
        .map_err(|error| format!("failed to send WebRTC offer: {error}"))
}

fn read_signal(
    signaling: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    deadline: Instant,
) -> Result<Message, String> {
    let remaining = remaining_until(deadline)?;
    set_ws_timeout(signaling, remaining);
    signaling.read().map_err(|error| {
        if let tungstenite::Error::Io(io) = &error {
            if matches!(
                io.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) {
                return "timed out waiting for the phone; run the command again for a fresh QR code"
                    .to_string();
            }
        }
        format!("signaling connection error: {error}")
    })
}

fn set_ws_timeout(ws: &WebSocket<MaybeTlsStream<TcpStream>>, timeout: Duration) {
    let timeout = Some(timeout.max(Duration::from_millis(1)));
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

fn remaining_until(deadline: Instant) -> Result<Duration, String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err("timed out waiting for the phone; run the command again for a fresh QR code".into())
    } else {
        Ok(remaining)
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum SignalControl {
    PeerReady,
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

fn fetch_turn_ice_servers(url: &str, deadline: Instant) -> Result<Vec<RTCIceServer>, String> {
    let agent = turn_http_agent(deadline)?;
    let mut response = match agent.get(url).call() {
        Ok(response) => response,
        Err(ureq::Error::StatusCode(409)) => {
            // `peer-ready` and the DO's joined-state write can cross by one
            // event-loop turn. One bounded retry avoids exposing that race.
            let remaining = remaining_until(deadline)?;
            if remaining <= Duration::from_millis(150) {
                return Err("timed out fetching TURN credentials".into());
            }
            std::thread::sleep(Duration::from_millis(150));
            turn_http_agent(deadline)?
                .get(url)
                .call()
                .map_err(turn_fetch_error)?
        }
        Err(error) => return Err(turn_fetch_error(error)),
    };
    let body = response
        .body_mut()
        .with_config()
        .limit(64 * 1024)
        .read_to_string()
        .map_err(|error| format!("failed to read TURN credential response: {error}"))?;
    let parsed: TurnCredentialResponse = serde_json::from_str(&body)
        .map_err(|error| format!("TURN service returned invalid JSON: {error}"))?;
    ice_servers_from_turn_response(parsed)
}

fn turn_http_agent(deadline: Instant) -> Result<ureq::Agent, String> {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(remaining_until(deadline)?.min(HTTP_TIMEOUT)))
        .build();
    Ok(config.into())
}

fn turn_fetch_error(error: ureq::Error) -> String {
    match error {
        ureq::Error::StatusCode(409) => {
            "TURN credential was requested before both peers joined the session".into()
        }
        ureq::Error::StatusCode(503) => {
            "nearby service has not been configured with Cloudflare TURN credentials".into()
        }
        ureq::Error::StatusCode(code) => {
            format!("TURN credential service rejected the request (HTTP {code})")
        }
        error => format!("failed to fetch TURN credentials: {error}"),
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

async fn create_offer_peer(
    ice_servers: Vec<RTCIceServer>,
) -> Result<
    (
        Arc<RTCPeerConnection>,
        Arc<RTCDataChannel>,
        mpsc::Receiver<EstablishmentEvent>,
        mpsc::Receiver<DataChannelEvent>,
    ),
    webrtc::Error,
> {
    create_offer_peer_with_configuration(RTCConfiguration {
        ice_servers,
        ..Default::default()
    })
    .await
}

async fn create_offer_peer_with_configuration(
    configuration: RTCConfiguration,
) -> Result<
    (
        Arc<RTCPeerConnection>,
        Arc<RTCDataChannel>,
        mpsc::Receiver<EstablishmentEvent>,
        mpsc::Receiver<DataChannelEvent>,
    ),
    webrtc::Error,
> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
    let api = APIBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build();

    let peer_connection = Arc::new(api.new_peer_connection(configuration).await?);
    let data_channel = peer_connection
        .create_data_channel(
            DATA_CHANNEL_LABEL,
            Some(RTCDataChannelInit {
                ordered: Some(true),
                protocol: Some(DATA_CHANNEL_PROTOCOL.to_string()),
                ..Default::default()
            }),
        )
        .await?;

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
                DataChannelEvent::Invalid("phone sent a binary data-channel message".into())
            } else if message.data.len() > DATA_FRAME_LIMIT {
                DataChannelEvent::Invalid("phone data-channel message was too large".into())
            } else {
                match String::from_utf8(message.data.to_vec()) {
                    Ok(text) => DataChannelEvent::Text(text),
                    Err(_) => DataChannelEvent::Invalid(
                        "phone data-channel message was not valid UTF-8".into(),
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
                "phone closed the WebRTC data channel during setup".into(),
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
) -> Result<String, webrtc::Error> {
    let offer = peer_connection.create_offer(None).await?;
    let mut gathering_complete = peer_connection.gathering_complete_promise().await;
    peer_connection.set_local_description(offer).await?;
    tokio::time::timeout(timeout, gathering_complete.recv())
        .await
        .map_err(|_| webrtc::Error::new("ICE gathering timed out".to_string()))?;
    peer_connection
        .local_description()
        .await
        .map(|description| description.sdp)
        .ok_or_else(|| webrtc::Error::new("missing local WebRTC description".to_string()))
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
    runtime: tokio::runtime::Runtime,
    peer_connection: Arc<RTCPeerConnection>,
    data_channel: Arc<RTCDataChannel>,
    incoming: mpsc::Receiver<DataChannelEvent>,
    signaling: WebSocket<MaybeTlsStream<TcpStream>>,
    closed: bool,
}

impl RtcSession {
    fn send(&self, message: &CliMessage) -> Result<(), String> {
        let text = serde_json::to_string(message)
            .map_err(|error| format!("failed to encode nearby message: {error}"))?;
        self.runtime
            .block_on(self.data_channel.send_text(text))
            .map(|_| ())
            .map_err(|error| format!("failed to send nearby message: {error}"))
    }

    fn send_protocol_error(&self, code: ProtocolErrorCode) {
        self.send(&CliMessage::ProtocolError {
            version: PROTOCOL_VERSION,
            code,
        })
        .ok();
    }

    fn receive(&self, timeout: Duration) -> Result<PhoneMessage, String> {
        match self.incoming.recv_timeout(timeout) {
            Ok(DataChannelEvent::Text(text)) => match decode_phone_message(&text) {
                Ok(message) => Ok(message),
                Err(error) => {
                    self.send_protocol_error(ProtocolErrorCode::InvalidMessage);
                    Err(error)
                }
            },
            Ok(DataChannelEvent::Invalid(error)) => {
                self.send_protocol_error(ProtocolErrorCode::InvalidMessage);
                Err(error)
            }
            Ok(DataChannelEvent::Closed) => Err("phone closed the WebRTC data channel".into()),
            Ok(DataChannelEvent::TransportFailed(error)) => Err(error),
            Err(mpsc::RecvTimeoutError::Timeout) => Err("timed out waiting for the phone".into()),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err("WebRTC data channel stopped unexpectedly".into())
            }
        }
    }

    fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.runtime.block_on(self.data_channel.close()).ok();
        self.runtime.block_on(self.peer_connection.close()).ok();
        self.signaling.close(None).ok();
        self.signaling.flush().ok();
    }
}

impl Drop for RtcSession {
    fn drop(&mut self) {
        self.close();
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum CliMessage {
    Request {
        #[serde(rename = "v")]
        version: u8,
        request: PinnedCeremonyRequest,
    },
    PairingRequest {
        #[serde(rename = "v")]
        version: u8,
        request: PairingCeremonyRequest,
        #[serde(rename = "cliCommitment")]
        cli_commitment: String,
    },
    SasCliReveal {
        #[serde(rename = "v")]
        version: u8,
        nonce: String,
    },
    SasCliAccepted {
        #[serde(rename = "v")]
        version: u8,
        #[serde(rename = "releaseNonce")]
        release_nonce: String,
        signature: String,
    },
    SasCliRejected {
        #[serde(rename = "v")]
        version: u8,
        #[serde(rename = "releaseNonce")]
        release_nonce: String,
    },
    InitialAccepted {
        #[serde(rename = "v")]
        version: u8,
    },
    InitialRejected {
        #[serde(rename = "v")]
        version: u8,
        reason: InitialRejectedReason,
    },
    InitialIndeterminate {
        #[serde(rename = "v")]
        version: u8,
        reason: InitialIndeterminateReason,
    },
    RememberReady {
        #[serde(rename = "v")]
        version: u8,
    },
    RememberAccepted {
        #[serde(rename = "v")]
        version: u8,
    },
    RememberRejected {
        #[serde(rename = "v")]
        version: u8,
        reason: RememberRejectedReason,
    },
    ProtocolError {
        #[serde(rename = "v")]
        version: u8,
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
        remember: RememberOffer,
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
        remember: RememberOffer,
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
                remember,
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
                match remember {
                    RememberOffer::Disabled => bytes.push(0),
                    RememberOffer::Available { window_secs } => {
                        bytes.push(1);
                        bytes.extend_from_slice(&window_secs.to_be_bytes());
                    }
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
#[serde(tag = "kind", rename_all = "lowercase")]
enum RememberOffer {
    Disabled,
    Available {
        #[serde(rename = "windowSecs")]
        window_secs: u64,
    },
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ProtocolErrorCode {
    InvalidMessage,
    UnexpectedMessage,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
enum RememberRejectedReason {
    Mismatch,
    Unavailable,
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
    let challenge = URL_SAFE_NO_PAD.encode(challenge_bytes);

    match operation {
        Operation::Register { pending_init } => {
            let prf_salt = keytap_core::prf_salt_for_name("default")
                .map_err(|error| format!("failed to derive registration PRF salt: {error}"))?;
            Ok(FlowPlan::Registration {
                request: PairingCeremonyRequest::Register {
                    challenge,
                    prf_salt: URL_SAFE_NO_PAD.encode(prf_salt),
                    user_id: URL_SAFE_NO_PAD.encode(b"keytap-user"),
                    user_name: "keytap".to_string(),
                },
                pending_init,
            })
        }
        Operation::Assert {
            name,
            offer_remember,
        } => {
            let prf_salt = keytap_core::prf_salt_for_name(name)
                .map_err(|error| format!("invalid key name: {error}"))?;
            let identity_salt = keytap_core::nearby_identity_prf_salt();
            let anchor = IdentityAnchor::load()
                .map_err(|error| format!("could not load the nearby passkey identity: {error}"))?;
            let remember = match (offer_remember, remember_window_secs()) {
                (true, window_secs) if window_secs > 0 => RememberOffer::Available { window_secs },
                _ => RememberOffer::Disabled,
            };
            let key_name = name.to_string();
            let prf_salt = URL_SAFE_NO_PAD.encode(prf_salt);
            let identity_salt = URL_SAFE_NO_PAD.encode(identity_salt);
            match anchor {
                IdentityAnchor::Pairing(anchor) => {
                    let identity = match anchor.constraint() {
                        IdentityPairingConstraint::AnyPasskey => PairingIdentityRequest::Any,
                        IdentityPairingConstraint::Credential { credential_id } => {
                            PairingIdentityRequest::Credential {
                                credential_id: URL_SAFE_NO_PAD.encode(credential_id),
                            }
                        }
                    };
                    Ok(FlowPlan::PairingAssertion {
                        request: PairingCeremonyRequest::Assert {
                            key_name: key_name.clone(),
                            prf_salt,
                            identity_salt,
                            challenge,
                            identity,
                            remember,
                        },
                        key_name,
                        challenge: challenge_bytes,
                        anchor,
                        remember,
                    })
                }
                IdentityAnchor::Pinned(anchor) => Ok(FlowPlan::PinnedAssertion {
                    request: PinnedCeremonyRequest::Assert {
                        key_name: key_name.clone(),
                        prf_salt,
                        identity_salt,
                        challenge,
                        identity: PinnedIdentityRequest::Pinned {
                            credential_id: URL_SAFE_NO_PAD.encode(anchor.credential_id()),
                        },
                        remember,
                    },
                    key_name,
                    challenge: challenge_bytes,
                    anchor,
                    remember,
                }),
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum PhoneMessage {
    SasPhoneCommit {
        #[serde(rename = "v")]
        version: u8,
        commitment: String,
    },
    SasPhoneReveal {
        #[serde(rename = "v")]
        version: u8,
        nonce: String,
    },
    SasPhoneComplete {
        #[serde(rename = "v")]
        version: u8,
        #[serde(rename = "releaseNonce")]
        release_nonce: String,
    },
    SasPhoneRejected {
        #[serde(rename = "v")]
        version: u8,
    },
    PairedRegistrationResult {
        #[serde(rename = "v")]
        version: u8,
        #[serde(rename = "credentialId")]
        credential_id: String,
        #[serde(rename = "releaseSignature")]
        release_signature: String,
    },
    PairedAssertionResult {
        #[serde(rename = "v")]
        version: u8,
        #[serde(rename = "credentialId")]
        credential_id: String,
        #[serde(rename = "prfFirst")]
        prf_first: String,
        identity: IdentityProofDto,
        #[serde(rename = "releaseSignature")]
        release_signature: String,
    },
    AssertionResult {
        #[serde(rename = "v")]
        version: u8,
        #[serde(rename = "credentialId")]
        credential_id: String,
        #[serde(rename = "prfFirst")]
        prf_first: String,
        identity: IdentityProofDto,
    },
    RememberBegin {
        #[serde(rename = "v")]
        version: u8,
    },
    RememberResult {
        #[serde(rename = "v")]
        version: u8,
        #[serde(rename = "credentialId")]
        credential_id: String,
        #[serde(rename = "prfFirst")]
        prf_first: String,
    },
    Done {
        #[serde(rename = "v")]
        version: u8,
    },
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

fn decode_phone_message(text: &str) -> Result<PhoneMessage, String> {
    let message: PhoneMessage = serde_json::from_str(text)
        .map_err(|error| format!("invalid nearby protocol message: {error}"))?;
    let version = match &message {
        PhoneMessage::SasPhoneCommit { version, .. }
        | PhoneMessage::SasPhoneReveal { version, .. }
        | PhoneMessage::SasPhoneComplete { version, .. }
        | PhoneMessage::SasPhoneRejected { version }
        | PhoneMessage::PairedRegistrationResult { version, .. }
        | PhoneMessage::PairedAssertionResult { version, .. }
        | PhoneMessage::AssertionResult { version, .. }
        | PhoneMessage::RememberBegin { version }
        | PhoneMessage::RememberResult { version, .. }
        | PhoneMessage::Done { version } => *version,
    };
    if version != PROTOCOL_VERSION {
        return Err(format!("unsupported nearby protocol version {version}"));
    }
    Ok(message)
}

struct AssertionPayload {
    credential_id: Vec<u8>,
    prf_output: [u8; 32],
}

fn decode_credential_id(value: &str) -> Result<Vec<u8>, String> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| format!("invalid credentialId: {error}"))?;
    match decoded.len() {
        0 => Err("phone returned an empty credentialId".into()),
        1..=1024 => Ok(decoded),
        length => Err(format!(
            "phone returned a credentialId of {length} bytes; maximum is 1024"
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
        prf_output,
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

fn initial_rejection_reason(error: &IdentityVerificationError) -> InitialRejectedReason {
    match error {
        IdentityVerificationError::IdentityMismatch => InitialRejectedReason::IdentityMismatch,
        IdentityVerificationError::InvalidProof => InitialRejectedReason::InvalidIdentityProof,
        IdentityVerificationError::Store(_) => InitialRejectedReason::IdentityStoreUnavailable,
        IdentityVerificationError::DurabilityUnknown(_) => {
            unreachable!("durability-unknown uses initial-indeterminate")
        }
    }
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
            "{error}; no success was acknowledged and the returned key was refused. The local identity may be visible but is not confirmed durable; retry this command with a fresh QR code before relying on the pairing"
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
            remember: RememberOffer::Available { window_secs: 60 },
        };
        let json = serde_json::to_value(CliMessage::Request {
            version: PROTOCOL_VERSION,
            request,
        })
        .unwrap();
        assert_eq!(json["v"], 3);
        assert_eq!(json["type"], "request");
        assert_eq!(json["request"]["kind"], "assert");
        assert_eq!(json["request"]["remember"]["kind"], "available");
        assert_eq!(json["request"]["remember"]["windowSecs"], 60);
        assert_eq!(json["request"]["identity"]["kind"], "pinned");
        assert_eq!(json["request"]["identity"]["credentialId"], "credential");
        assert_eq!(json["request"]["identitySalt"], "identity-salt");
        assert!(json["request"].get("userId").is_none());
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
            remember: RememberOffer::Available { window_secs: 60 },
        };
        let canonical = request.sas_bytes().unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(&canonical),
            "AQAAACABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQAAACACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgAAACADAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwAAAAZkZXBsb3kBAAAABGNyZWQBAAAAAAAAADw"
        );
        let context = SasContext::bind(&[4; 32], &canonical);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(context.as_bytes()),
            "ov2kOyVpend0ognXvoqine2hW54dYUqDikvCzmw4xqE"
        );

        let json = serde_json::to_value(CliMessage::PairingRequest {
            version: PROTOCOL_VERSION,
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
            version: PROTOCOL_VERSION,
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
        assert!(json["request"].get("remember").is_none());
    }

    #[test]
    fn error_and_rejection_messages_have_allowlisted_payloads() {
        let error = serde_json::to_value(CliMessage::ProtocolError {
            version: PROTOCOL_VERSION,
            code: ProtocolErrorCode::UnexpectedMessage,
        })
        .unwrap();
        assert_eq!(
            error,
            serde_json::json!({
                "type": "protocol-error",
                "v": 3,
                "code": "unexpected-message"
            })
        );

        let rejected = serde_json::to_value(CliMessage::RememberRejected {
            version: PROTOCOL_VERSION,
            reason: RememberRejectedReason::Mismatch,
        })
        .unwrap();
        assert_eq!(
            rejected,
            serde_json::json!({
                "type": "remember-rejected",
                "v": 3,
                "reason": "mismatch"
            })
        );

        let unavailable = serde_json::to_value(CliMessage::RememberRejected {
            version: PROTOCOL_VERSION,
            reason: RememberRejectedReason::Unavailable,
        })
        .unwrap();
        assert_eq!(
            unavailable,
            serde_json::json!({
                "type": "remember-rejected",
                "v": 3,
                "reason": "unavailable"
            })
        );

        let identity_rejected = serde_json::to_value(CliMessage::InitialRejected {
            version: PROTOCOL_VERSION,
            reason: InitialRejectedReason::IdentityMismatch,
        })
        .unwrap();
        assert_eq!(
            identity_rejected,
            serde_json::json!({
                "type": "initial-rejected",
                "v": 3,
                "reason": "identity-mismatch"
            })
        );

        let identity_indeterminate = serde_json::to_value(CliMessage::InitialIndeterminate {
            version: PROTOCOL_VERSION,
            reason: InitialIndeterminateReason::IdentityDurabilityUnknown,
        })
        .unwrap();
        assert_eq!(
            identity_indeterminate,
            serde_json::json!({
                "type": "initial-indeterminate",
                "v": 3,
                "reason": "identity-durability-unknown"
            })
        );
    }

    #[test]
    fn phone_messages_are_versioned_and_typed() {
        assert!(matches!(
            decode_phone_message(r#"{"v":3,"type":"remember-begin"}"#).unwrap(),
            PhoneMessage::RememberBegin { .. }
        ));
        assert!(decode_phone_message(r#"{"v":1,"type":"done"}"#).is_err());
        assert!(
            decode_phone_message(r#"{"v":3,"type":"assertion-result","credentialId":"YQ"}"#)
                .is_err()
        );
    }

    #[test]
    fn assertion_fields_require_exact_prf_size() {
        let prf = URL_SAFE_NO_PAD.encode([7u8; 32]);
        let payload = decode_assertion_fields("Y3JlZA", &prf).unwrap();
        assert_eq!(payload.credential_id, b"cred");
        assert_eq!(payload.prf_output, [7u8; 32]);
        assert!(decode_assertion_fields("Y3JlZA", "c2hvcnQ").is_err());
        assert!(decode_credential_id(&URL_SAFE_NO_PAD.encode(vec![0; 1025])).is_err());
    }

    #[test]
    fn paired_results_must_echo_the_exact_post_confirmation_release() {
        let expected = [7u8; 64];
        assert!(verify_release_echo(&URL_SAFE_NO_PAD.encode(expected), &expected).is_ok());
        assert!(verify_release_echo(&URL_SAFE_NO_PAD.encode([8u8; 64]), &expected).is_err());
        assert!(verify_release_echo("not-base64url!", &expected).is_err());
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

        let (offer_pc, offer_dc, open_rx, _offer_events) =
            runtime.block_on(create_offer_peer(Vec::new())).unwrap();
        let (message_tx, message_rx) = mpsc::channel();

        let answer_pc = runtime
            .block_on(async {
                let mut media_engine = MediaEngine::default();
                media_engine.register_default_codecs()?;
                let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
                let api = APIBuilder::new()
                    .with_media_engine(media_engine)
                    .with_interceptor_registry(registry)
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
        runtime.block_on(offer_dc.send_text("hello")).unwrap();
        assert_eq!(
            message_rx.recv_timeout(Duration::from_secs(10)).unwrap(),
            b"hello"
        );

        runtime.block_on(offer_dc.close()).ok();
        runtime.block_on(offer_pc.close()).ok();
        runtime.block_on(answer_pc.close()).ok();
    }

    /// End-to-end smoke test for the deployed signaling Durable Object and
    /// Cloudflare's UDP TURN service. It is ignored by default because it
    /// consumes live network service and intentionally forbids direct ICE.
    #[test]
    #[ignore = "requires the deployed keytap Worker and Cloudflare TURN"]
    fn production_forced_turn_signaling_and_data_channel() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let cli_session_key = CliSessionKey::generate();
        let rendezvous_id = cli_session_key.rendezvous_id();
        let signal_base = DEFAULT_SIGNAL_URL;
        let mut cli_signaling =
            connect_signaling(&format!("{signal_base}/v2/signal/{rendezvous_id}?role=cli"))
                .unwrap();
        let mut phone_signaling = connect_signaling(&format!(
            "{signal_base}/v2/signal/{rendezvous_id}?role=phone"
        ))
        .unwrap();
        let live_deadline = Instant::now() + Duration::from_secs(120);
        wait_for_peer(&mut cli_signaling, live_deadline).unwrap();
        wait_for_peer(&mut phone_signaling, live_deadline).unwrap();

        let http_base = http_base_url(signal_base).unwrap();
        let cli_ice = fetch_turn_ice_servers(
            &format!("{http_base}/v2/signal/{rendezvous_id}/turn/cli"),
            live_deadline,
        )
        .unwrap();
        let phone_ice = fetch_turn_ice_servers(
            &format!("{http_base}/v2/signal/{rendezvous_id}/turn/phone"),
            live_deadline,
        )
        .unwrap();

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .unwrap();
        let (offer_pc, offer_dc, open_rx, _offer_events) = runtime
            .block_on(create_offer_peer_with_configuration(RTCConfiguration {
                ice_servers: cli_ice,
                ice_transport_policy: RTCIceTransportPolicy::Relay,
                ..Default::default()
            }))
            .unwrap();

        let (message_tx, message_rx) = mpsc::channel();
        let answer_pc = runtime
            .block_on(async {
                let mut media_engine = MediaEngine::default();
                media_engine.register_default_codecs()?;
                let registry = register_default_interceptors(Registry::new(), &mut media_engine)?;
                let api = APIBuilder::new()
                    .with_media_engine(media_engine)
                    .with_interceptor_registry(registry)
                    .build();
                let peer = Arc::new(
                    api.new_peer_connection(RTCConfiguration {
                        ice_servers: phone_ice,
                        ice_transport_policy: RTCIceTransportPolicy::Relay,
                        ..Default::default()
                    })
                    .await?,
                );
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
            .block_on(gather_offer(&offer_pc, ICE_GATHER_TIMEOUT))
            .unwrap();
        assert!(
            offer_sdp.contains(" typ relay "),
            "relay-only offer contained no TURN candidate:\n{offer_sdp}"
        );
        let signed_offer = cli_session_key.sign_offer(offer_sdp.as_bytes());
        send_signal(&mut cli_signaling, &signed_offer).unwrap();
        let received_offer = loop {
            let Message::Text(text) = read_signal(&mut phone_signaling, live_deadline).unwrap()
            else {
                continue;
            };
            let Ok(envelope) = serde_json::from_str(text.as_str()) else {
                continue;
            };
            if let Ok(body) = cli_session_key.verify_offer(&envelope) {
                break String::from_utf8(body).unwrap();
            }
        };
        runtime
            .block_on(
                answer_pc
                    .set_remote_description(RTCSessionDescription::offer(received_offer).unwrap()),
            )
            .unwrap();

        let answer_sdp = runtime
            .block_on(async {
                let answer = answer_pc.create_answer(None).await?;
                let mut gathering_complete = answer_pc.gathering_complete_promise().await;
                answer_pc.set_local_description(answer).await?;
                tokio::time::timeout(ICE_GATHER_TIMEOUT, gathering_complete.recv())
                    .await
                    .map_err(|_| webrtc::Error::new("answer ICE gathering timed out".into()))?;
                answer_pc
                    .local_description()
                    .await
                    .map(|description| description.sdp)
                    .ok_or_else(|| webrtc::Error::new("missing answer description".into()))
            })
            .unwrap();
        assert!(
            answer_sdp.contains(" typ relay "),
            "relay-only answer contained no TURN candidate:\n{answer_sdp}"
        );
        let answer = PhoneAnswer::new(answer_sdp.as_bytes());
        send_signal(&mut phone_signaling, &answer).unwrap();
        let received_answer = wait_for_answer(&mut cli_signaling, live_deadline).unwrap();
        runtime
            .block_on(
                offer_pc.set_remote_description(
                    RTCSessionDescription::answer(received_answer).unwrap(),
                ),
            )
            .unwrap();

        assert!(matches!(
            open_rx.recv_timeout(Duration::from_secs(30)).unwrap(),
            EstablishmentEvent::Open
        ));
        runtime
            .block_on(offer_dc.send_text("cloudflare-turn-ok"))
            .unwrap();
        assert_eq!(
            message_rx.recv_timeout(Duration::from_secs(30)).unwrap(),
            b"cloudflare-turn-ok"
        );

        runtime.block_on(offer_dc.close()).ok();
        runtime.block_on(offer_pc.close()).ok();
        runtime.block_on(answer_pc.close()).ok();
        cli_signaling.close(None).ok();
        phone_signaling.close(None).ok();
    }
}
