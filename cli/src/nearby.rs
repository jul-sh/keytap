//! Authenticate with a passkey on a nearby browser over WebRTC.
//!
//! The QR fragment contains a one-time 32-byte CLI public key. The Worker sees
//! only a hash-derived rendezvous id. The CLI signs the full, non-trickle
//! WebRTC offer (including its DTLS fingerprint), so the phone authenticates
//! the data-channel peer before it sends any WebAuthn result.

use crate::nearby_identity::{
    Anchor as IdentityAnchor, AssertionDisposition, InitCommitError as IdentityInitCommitError,
    PairingAnchor as IdentityPairingAnchor, PairingConstraint as IdentityPairingConstraint,
    PendingInit as PendingIdentityInit, PersistedInit as PersistedIdentityInit,
    PinnedAnchor as PinnedIdentityAnchor, Proof as NearbyIdentityProof,
    ProofBinding as NearbyIdentityProofBinding, ProofContext as NearbyIdentityProofContext,
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
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;
use zeroize::Zeroizing;

const DEFAULT_SIGNAL_URL: &str = "wss://keytap-relay.julsh.workers.dev";
const PAGE_URL: &str = "https://keytap.jul.sh/nearby";
const DATA_CHANNEL_LABEL: &str = "keytap/4";
const DATA_CHANNEL_PROTOCOL: &str = "keytap.v4";

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

/// A completed nearby assertion ceremony.
pub struct NearbyAssertion {
    pub prf_output: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub storage: StorageOutcome,
}

/// Authenticate via a nearby device. `storage_policy` controls whether the
/// phone may request local storage before performing its single assertion.
pub fn authenticate_nearby(name: &str, storage_policy: StoragePolicy) -> NearbyAssertion {
    let result = run_nearby_flow(Operation::Assert {
        name,
        storage_policy,
    })
    .unwrap_or_else(|error| crate::die(&error));

    match result {
        FlowResult::Assertion {
            credential_id,
            prf_output,
            storage,
        } => NearbyAssertion {
            credential_id,
            prf_output,
            storage,
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
        request: PairingCeremonyRequest,
        key_name: String,
        challenge: [u8; 32],
        storage: StoragePolicy,
        anchor: IdentityPairingAnchor,
    },
    PinnedAssertion {
        request: PinnedCeremonyRequest,
        key_name: String,
        challenge: [u8; 32],
        storage: StoragePolicy,
        anchor: PinnedIdentityAnchor,
    },
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

enum FlowResult {
    Registration {
        registration: PersistedIdentityInit,
    },
    Assertion {
        credential_id: Vec<u8>,
        prf_output: Vec<u8>,
        storage: StorageOutcome,
    },
}

#[derive(Clone, Copy)]
enum AuthorizedDisposition {
    Once,
    Remember,
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
        "{}/v2/signal/{rendezvous_id}/turn",
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
    signaling.close(None).ok();
    drop(signaling);

    let session = RtcSession {
        runtime,
        peer_connection,
        data_channel,
        incoming,
    };

    let result = match plan {
        FlowPlan::Registration {
            request,
            pending_init,
        } => {
            let credential_id = match run_pairing(&session, request, &identity_binding)? {
                PairingAuthorization::Registration { credential_id } => credential_id,
                PairingAuthorization::Assertion { .. } => {
                    return reject_unexpected_pairing(&session)
                }
            };
            let credential_id = decode_credential_id(&credential_id)?;
            let registration = match pending_init.commit(&credential_id) {
                Ok(registration) => registration,
                Err(IdentityInitCommitError::NotPublished(error)) => {
                    session
                        .send(&CliMessage::InitialRejected {
                            reason: InitialRejectedReason::IdentityStoreUnavailable,
                        })
                        .ok();
                    return Err(format!(
                        "passkey was created, but its paired identity could not be stored: {error}"
                    ));
                }
                Err(IdentityInitCommitError::PublishedButNotDurable(error)) => {
                    // This cannot make the identity publication durable, but
                    // rotating every reachable remembered root further
                    // reduces the chance of stale-key resurrection. It is
                    // still indeterminate and must never receive a success ACK.
                    crate::remember::after_init();
                    session
                        .send(&CliMessage::InitialIndeterminate {
                            reason: InitialIndeterminateReason::IdentityDurabilityUnknown,
                        })
                        .ok();
                    return Err(format!(
                        "passkey was created and its paired identity is visible, but durable storage could not be confirmed: {error}. No success was acknowledged; rerun `keytap init --force` before relying on it"
                    ));
                }
            };
            if let Err(error) = session.send(&CliMessage::InitialAccepted) {
                note(&format!(
                    "Passkey identity was stored, but the phone acknowledgement could not be delivered: {error}"
                ));
            }
            FlowResult::Registration { registration }
        }
        FlowPlan::PairingAssertion {
            request,
            key_name,
            challenge,
            storage,
            anchor,
        } => {
            let (confirmation, credential_id, prf_first, disposition, proof) =
                match run_pairing(&session, request, &identity_binding)? {
                    PairingAuthorization::Assertion {
                        confirmation,
                        credential_id,
                        prf_first,
                        disposition,
                        proof,
                    } => (confirmation, credential_id, prf_first, disposition, proof),
                    PairingAuthorization::Registration { .. } => {
                        return reject_unexpected_pairing(&session)
                    }
                };
            complete_assertion(
                session,
                AssertionCompletion {
                    key_name,
                    challenge,
                    storage,
                    identity: AuthenticatedIdentity::Pairing {
                        anchor,
                        confirmation,
                    },
                    credential_id,
                    prf_first,
                    disposition,
                    proof,
                },
            )?
        }
        FlowPlan::PinnedAssertion {
            request,
            key_name,
            challenge,
            storage,
            anchor,
        } => {
            session.send(&CliMessage::Request { request })?;
            match session.receive(CEREMONY_RESPONSE_TIMEOUT)? {
                PhoneMessage::AssertionResult {
                    credential_id,
                    prf_first,
                    disposition,
                    identity: proof,
                } => complete_assertion(
                    session,
                    AssertionCompletion {
                        key_name,
                        challenge,
                        storage,
                        identity: AuthenticatedIdentity::Pinned {
                            anchor,
                            session_digest: identity_binding,
                        },
                        credential_id,
                        prf_first,
                        disposition,
                        proof,
                    },
                )?,
                PhoneMessage::Done => {
                    return Err("the page on your phone was closed before approving".into())
                }
                _ => {
                    session.send_protocol_error(ProtocolErrorCode::UnexpectedMessage);
                    return Err("phone returned an unexpected nearby protocol message".into());
                }
            }
        }
    };

    Ok(result)
}

fn complete_assertion(
    session: RtcSession,
    completion: AssertionCompletion,
) -> Result<FlowResult, String> {
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
            session.send_protocol_error(ProtocolErrorCode::UnexpectedMessage);
            return Err(error);
        }
    };
    let payload = decode_assertion_fields(&credential_id, &prf_first)?;
    let proof = decode_identity_proof(&payload.credential_id, proof)?;
    let verification = match identity {
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
            anchor.verify_and_pin_after_sas(&proof, &context).map(|()| {
                note("Pairing confirmed; pinned this passkey identity for future nearby requests.")
            })
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
            anchor.verify(&proof, &context)
        }
    };
    match verification {
        Ok(()) => {}
        Err(error @ IdentityVerificationError::DurabilityUnknown(_)) => {
            session
                .send(&CliMessage::InitialIndeterminate {
                    reason: InitialIndeterminateReason::IdentityDurabilityUnknown,
                })
                .ok();
            return Err(identity_error_message(error));
        }
        Err(error) => {
            session
                .send(&CliMessage::InitialRejected {
                    reason: initial_rejection_reason(&error),
                })
                .ok();
            return Err(identity_error_message(error));
        }
    }
    let storage = match disposition {
        AuthorizedDisposition::Once => StorageOutcome::Once,
        AuthorizedDisposition::Remember => {
            let raw_key = Zeroizing::new(
                keytap_core::derive_raw_key(&payload.prf_output)
                    .map_err(|error| format!("key derivation failed: {error}"))?,
            );
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

    if let Err(error) = session.send(&CliMessage::AssertionAccepted { storage }) {
        note(&format!(
            "Passkey result was verified, but the phone acknowledgement could not be delivered: {error}"
        ));
    }

    Ok(FlowResult::Assertion {
        credential_id: payload.credential_id,
        prf_output: payload.prf_output.to_vec(),
        storage,
    })
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
            Err("phone declined local storage required by this command".into())
        }
    }
}

fn run_pairing(
    session: &RtcSession,
    request: PairingCeremonyRequest,
    session_binding: &[u8; 32],
) -> Result<PairingAuthorization, String> {
    let canonical_request = request.sas_bytes()?;
    let expects_registration = matches!(&request, PairingCeremonyRequest::Register { .. });
    let pending = SasCommitment::generate(SasContext::bind(session_binding, &canonical_request))?;
    session.send(&CliMessage::PairingRequest {
        request,
        cli_commitment: URL_SAFE_NO_PAD.encode(pending.commitment()),
    })?;

    let phone_commitment = match session.receive(CEREMONY_RESPONSE_TIMEOUT)? {
        PhoneMessage::SasPhoneCommit { commitment, .. } => {
            decode_fixed_base64url::<32>(&commitment, "phone pairing commitment")?
        }
        PhoneMessage::SasPhoneRejected | PhoneMessage::Done => {
            return Err("pairing was cancelled on the phone; no key was accepted".into())
        }
        _ => return reject_unexpected_pairing(session),
    };
    let awaiting_reveal = pending.accept_phone_commitment(phone_commitment);
    session.send(&CliMessage::SasCliReveal {
        nonce: URL_SAFE_NO_PAD.encode(awaiting_reveal.cli_nonce()),
    })?;

    let phone_nonce = match session.receive(CEREMONY_RESPONSE_TIMEOUT)? {
        PhoneMessage::SasPhoneReveal { nonce, .. } => {
            decode_fixed_base64url::<32>(&nonce, "phone pairing nonce")?
        }
        PhoneMessage::SasPhoneRejected | PhoneMessage::Done => {
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
    eprintln!("Finish the passkey prompt on your phone. The CLI will buffer its result until you confirm these words here.");

    let buffered = match (
        expects_registration,
        session.receive(CEREMONY_RESPONSE_TIMEOUT)?,
    ) {
        (true, PhoneMessage::PairedRegistrationResult { credential_id }) => {
            BufferedPairingResult::Registration { credential_id }
        }
        (
            false,
            PhoneMessage::PairedAssertionResult {
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
        (_, PhoneMessage::SasPhoneRejected | PhoneMessage::Done) => {
            return Err(
                "pairing was rejected or cancelled on the phone; no key was accepted".into(),
            )
        }
        _ => return reject_unexpected_pairing(session),
    };

    let confirmed = match comparison.result_buffered().confirm_with_tty() {
        Ok(confirmed) => confirmed,
        Err(error) => {
            session.send(&CliMessage::SasCliRejected).ok();
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

fn reject_unexpected_pairing<T>(session: &RtcSession) -> Result<T, String> {
    session.send_protocol_error(ProtocolErrorCode::UnexpectedMessage);
    Err("phone returned an unexpected pairing protocol message; run the command again for a fresh QR code".into())
}

fn signal_base_url() -> String {
    std::env::var("KEYTAP_SIGNAL_URL")
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
    let mut response = turn_http_agent(deadline)?
        .get(url)
        .call()
        .map_err(turn_fetch_error)?;
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
    let configuration = RTCConfiguration {
        ice_servers,
        ..Default::default()
    };
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
        self.send(&CliMessage::ProtocolError { code }).ok();
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
}

impl Drop for RtcSession {
    fn drop(&mut self) {
        self.runtime.block_on(self.data_channel.close()).ok();
        self.runtime.block_on(self.peer_connection.close()).ok();
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
            storage_policy,
        } => {
            let prf_salt = keytap_core::prf_salt_for_name(name)
                .map_err(|error| format!("invalid key name: {error}"))?;
            let identity_salt = crate::nearby_identity::prf_salt();
            let anchor = IdentityAnchor::load()
                .map_err(|error| format!("could not load the nearby passkey identity: {error}"))?;
            let storage = storage_policy;
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
                            storage,
                        },
                        key_name,
                        challenge: challenge_bytes,
                        anchor,
                        storage,
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
                        storage,
                    },
                    key_name,
                    challenge: challenge_bytes,
                    anchor,
                    storage,
                }),
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum PhoneMessage {
    SasPhoneCommit {
        commitment: String,
    },
    SasPhoneReveal {
        nonce: String,
    },
    SasPhoneRejected,
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

fn decode_phone_message(text: &str) -> Result<PhoneMessage, String> {
    serde_json::from_str(text).map_err(|error| format!("invalid nearby protocol message: {error}"))
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
    fn phone_messages_are_strictly_typed() {
        assert!(decode_phone_message(r#"{"type":"remember-begin"}"#).is_err());
        assert!(matches!(
            decode_phone_message(
                r#"{"type":"paired-registration-result","credentialId":"Y3JlZA"}"#
            )
            .unwrap(),
            PhoneMessage::PairedRegistrationResult { .. }
        ));
        assert!(decode_phone_message(
            r#"{"type":"paired-registration-result","credentialId":"Y3JlZA","releaseSignature":"legacy"}"#
        )
        .is_err());
        assert!(decode_phone_message(r#"{"type":"unknown"}"#).is_err());
        let complete = r#"{"type":"assertion-result","credentialId":"YQ","prfFirst":"cHJm","disposition":"remember","identity":{"algorithm":"ed25519","publicKey":"cHVi","signature":"c2ln"}}"#;
        assert!(matches!(
            decode_phone_message(complete).unwrap(),
            PhoneMessage::AssertionResult {
                disposition: AssertionDisposition::Remember,
                ..
            }
        ));
        let missing = r#"{"type":"assertion-result","credentialId":"YQ","prfFirst":"cHJm","identity":{"algorithm":"ed25519","publicKey":"cHVi","signature":"c2ln"}}"#;
        assert!(decode_phone_message(missing).is_err());
        let paired_missing = r#"{"type":"paired-assertion-result","credentialId":"YQ","prfFirst":"cHJm","identity":{"algorithm":"ed25519","publicKey":"cHVi","signature":"c2ln"}}"#;
        assert!(decode_phone_message(paired_missing).is_err());
        let unknown = r#"{"type":"assertion-result","credentialId":"YQ","prfFirst":"cHJm","disposition":"later","identity":{"algorithm":"ed25519","publicKey":"cHVi","signature":"c2ln"}}"#;
        assert!(decode_phone_message(unknown).is_err());
        let extra = r#"{"type":"assertion-result","credentialId":"YQ","prfFirst":"cHJm","disposition":"once","identity":{"algorithm":"ed25519","publicKey":"cHVi","signature":"c2ln"},"remember":true}"#;
        assert!(decode_phone_message(extra).is_err());
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
        assert_eq!(payload.prf_output, [7u8; 32]);
        assert!(decode_assertion_fields("Y3JlZA", "c2hvcnQ").is_err());
        assert!(decode_credential_id(&URL_SAFE_NO_PAD.encode(vec![0; 1025])).is_err());
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
}
