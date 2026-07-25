//! Authenticate with a passkey on a nearby browser over WebRTC.
//!
//! The QR fragment contains a one-time 32-byte capability. The Worker sees
//! only a hash-derived rendezvous id. That capability authenticates the full,
//! non-trickle WebRTC offer and answer (including ICE candidates and DTLS
//! fingerprints), while WebRTC DTLS protects all application data.

use crate::nearby_identity::{
    Anchor as IdentityAnchor, Expectation as IdentityExpectation,
    Proof as NearbyIdentityProof, ProofFields as NearbyIdentityProofFields,
    Verification as IdentityVerification, VerificationError as IdentityVerificationError,
};
use crate::nearby_protocol::{Capability, SignalEnvelope, SignalKind, SignalRole};
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
const DATA_CHANNEL_LABEL: &str = "keytap/2";
const DATA_CHANNEL_PROTOCOL: &str = "keytap.v2";
const PROTOCOL_VERSION: u8 = 2;

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
    /// Retained for the caller's established API. Version 2 performs remember
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

/// Register a passkey via a nearby device; returns the credential ID.
pub fn register_nearby() -> Vec<u8> {
    let result = run_nearby_flow(Operation::Register).unwrap_or_else(|error| crate::die(&error));
    match result {
        FlowResult::Registration { credential_id } => {
            eprintln!("Passkey registered successfully via nearby device.");
            credential_id
        }
        FlowResult::Assertion { .. } => {
            crate::die("nearby protocol returned an assertion for a registration request")
        }
    }
}

enum Operation<'a> {
    Register,
    Assert { name: &'a str, offer_remember: bool },
}

/// Everything valid only for one ceremony kind lives in that variant. The
/// assertion branch owns the TOFU anchor and exact bytes its proof must bind.
enum FlowPlan {
    Registration {
        request: CeremonyRequest,
    },
    Assertion {
        request: CeremonyRequest,
        key_name: String,
        challenge: [u8; 32],
        remember: RememberOffer,
        identity: IdentityAnchor,
    },
}

impl FlowPlan {
    fn request(&self) -> &CeremonyRequest {
        match self {
            Self::Registration { request } | Self::Assertion { request, .. } => request,
        }
    }
}

enum FlowResult {
    Registration {
        credential_id: Vec<u8>,
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
    pub fn settle(mut self) -> bool {
        note(&format!(
            "Key delivered. Waiting up to {}s in case you choose \u{201c}remember\u{201d} on \
             your phone (finishing or closing the page there ends the wait; Ctrl-C skips).",
            self.window_secs
        ));
        exit_zero_on_sigint();
        let opted_in = self.run_window();
        self.session.close();
        opted_in
    }

    fn run_window(&mut self) -> bool {
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
                return false;
            }

            let message = match self.session.receive(remaining) {
                Ok(message) => message,
                Err(_) => return false,
            };

            state = match (state, message) {
                (_, PhoneMessage::Done { .. }) => return false,
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
                        return false;
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
                        return false;
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
                        if self
                            .session
                            .send(&CliMessage::RememberAccepted {
                                version: PROTOCOL_VERSION,
                            })
                            .is_err()
                        {
                            return false;
                        }
                        return true;
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
                (state, PhoneMessage::RegistrationResult { .. })
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
    let plan = build_plan(&operation)?;

    let signal_base = signal_base_url();
    let capability = Capability::generate();
    let rendezvous_id = capability.rendezvous_id();
    let ws_url = format!("{signal_base}/v2/signal/{rendezvous_id}?role=cli");
    let mut signaling = connect_signaling(&ws_url)?;

    let url = format!("{PAGE_URL}#q={}", capability.fragment_value());
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
    let offer = capability.sign(SignalRole::Cli, 0, SignalKind::Offer, offer_sdp.as_bytes());
    send_signal(&mut signaling, &offer)?;

    let answer_sdp = wait_for_answer(&mut signaling, &capability, setup_deadline)?;
    let identity_binding =
        capability.identity_session_binding(offer_sdp.as_bytes(), answer_sdp.as_bytes());
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

    session.send(&CliMessage::Request {
        version: PROTOCOL_VERSION,
        request: plan.request().clone(),
    })?;

    let first = session.receive(CEREMONY_RESPONSE_TIMEOUT)?;
    let result = match (plan, first) {
        (FlowPlan::Registration { .. }, PhoneMessage::RegistrationResult { credential_id, .. }) => {
            let credential_id = decode_credential_id(&credential_id)?;
            session.send(&CliMessage::InitialAccepted {
                version: PROTOCOL_VERSION,
            })?;
            session.close();
            FlowResult::Registration { credential_id }
        }
        (
            FlowPlan::Assertion {
                key_name,
                challenge,
                remember,
                identity,
                ..
            },
            PhoneMessage::AssertionResult {
                credential_id,
                prf_first,
                identity: proof,
                ..
            },
        ) => {
            let payload = decode_assertion_fields(&credential_id, &prf_first)?;
            let proof = decode_identity_proof(&payload.credential_id, proof)?;
            let proof_fields = NearbyIdentityProofFields {
                session_binding: &identity_binding,
                challenge: &challenge,
                credential_id: &payload.credential_id,
                prf_output: &payload.prf_output,
                key_name: &key_name,
                public_key: &proof.public_key,
            };
            match identity.verify_and_pin(&proof, &proof_fields) {
                Ok(IdentityVerification::MatchedPin) => {}
                Ok(IdentityVerification::TofuPinned { fingerprint }) => note(&format!(
                    "Trusted this passkey for future nearby requests on this machine (TOFU identity {fingerprint})."
                )),
                Ok(IdentityVerification::InitPinCompleted { fingerprint }) => note(&format!(
                    "Verified the passkey selected by init and pinned its nearby identity ({fingerprint})."
                )),
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
            session.send(&CliMessage::InitialAccepted {
                version: PROTOCOL_VERSION,
            })?;

            let followup = match remember {
                RememberOffer::Disabled => {
                    session.close();
                    None
                }
                RememberOffer::Available { window_secs } => Some(Box::new(RememberWindow {
                    session,
                    name: key_name,
                    window_secs,
                    credential_id: payload.credential_id.clone(),
                    prf_output: Zeroizing::new(payload.prf_output.to_vec()),
                })),
            };

            FlowResult::Assertion {
                credential_id: payload.credential_id,
                prf_output: payload.prf_output.to_vec(),
                followup,
            }
        }
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
    capability: &Capability,
    deadline: Instant,
) -> Result<String, String> {
    wait_for_authenticated_sdp(
        signaling,
        capability,
        SignalRole::Phone,
        SignalKind::Answer,
        deadline,
    )
}

fn wait_for_authenticated_sdp(
    signaling: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    capability: &Capability,
    expected_role: SignalRole,
    expected_kind: SignalKind,
    deadline: Instant,
) -> Result<String, String> {
    loop {
        let message = read_signal(signaling, deadline)?;
        match message {
            Message::Text(text) => {
                if text.len() > SIGNAL_FRAME_LIMIT {
                    continue;
                }
                let envelope: SignalEnvelope = match serde_json::from_str(text.as_str()) {
                    Ok(envelope) => envelope,
                    Err(_) => continue,
                };
                let body = match capability.verify(&envelope, expected_role, 0, expected_kind) {
                    Ok(body) => body,
                    Err(_) => continue,
                };
                return String::from_utf8(body)
                    .map_err(|_| "authenticated WebRTC SDP was not UTF-8".to_string());
            }
            Message::Ping(data) => {
                signaling
                    .send(Message::Pong(data))
                    .map_err(|error| format!("signaling connection error: {error}"))?;
            }
            Message::Close(_) => {
                return Err("signaling connection closed before authenticated SDP arrived".into())
            }
            _ => {}
        }
    }
}

fn send_signal(
    signaling: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    envelope: &SignalEnvelope,
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
        request: CeremonyRequest,
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
enum CeremonyRequest {
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
        identity: NearbyIdentityRequest,
        remember: RememberOffer,
    },
}

#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum NearbyIdentityRequest {
    Tofu,
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
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum InitialRejectedReason {
    IdentityMismatch,
    InvalidIdentityProof,
    IdentityStoreUnavailable,
}

fn build_plan(operation: &Operation<'_>) -> Result<FlowPlan, String> {
    let mut challenge_bytes = [0u8; 32];
    getrandom::getrandom(&mut challenge_bytes)
        .map_err(|error| format!("failed to generate WebAuthn challenge: {error}"))?;
    let challenge = URL_SAFE_NO_PAD.encode(challenge_bytes);

    match operation {
        Operation::Register => {
            let prf_salt = keytap_core::prf_salt_for_name("default")
                .map_err(|error| format!("failed to derive registration PRF salt: {error}"))?;
            Ok(FlowPlan::Registration {
                request: CeremonyRequest::Register {
                    challenge,
                    prf_salt: URL_SAFE_NO_PAD.encode(prf_salt),
                    user_id: URL_SAFE_NO_PAD.encode(b"keytap-user"),
                    user_name: "keytap".to_string(),
                },
            })
        }
        Operation::Assert {
            name,
            offer_remember,
        } => {
            let prf_salt = keytap_core::prf_salt_for_name(name)
                .map_err(|error| format!("invalid key name: {error}"))?;
            let identity_salt = keytap_core::nearby_identity_prf_salt();
            let identity = IdentityAnchor::load()
                .map_err(|error| format!("could not load the nearby passkey identity: {error}"))?;
            let identity_request = match identity.expectation() {
                IdentityExpectation::FirstUse => NearbyIdentityRequest::Tofu,
                IdentityExpectation::Pinned { credential_id } => NearbyIdentityRequest::Pinned {
                    credential_id: URL_SAFE_NO_PAD.encode(credential_id),
                },
            };
            let remember = match (*offer_remember, remember_window_secs()) {
                (true, window_secs) if window_secs > 0 => RememberOffer::Available { window_secs },
                _ => RememberOffer::Disabled,
            };
            Ok(FlowPlan::Assertion {
                request: CeremonyRequest::Assert {
                    key_name: (*name).to_string(),
                    prf_salt: URL_SAFE_NO_PAD.encode(prf_salt),
                    identity_salt: URL_SAFE_NO_PAD.encode(identity_salt),
                    challenge,
                    identity: identity_request,
                    remember,
                },
                key_name: (*name).to_string(),
                challenge: challenge_bytes,
                identity,
                remember,
            })
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum PhoneMessage {
    RegistrationResult {
        #[serde(rename = "v")]
        version: u8,
        #[serde(rename = "credentialId")]
        credential_id: String,
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
#[serde(tag = "algorithm", rename_all = "lowercase")]
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
        PhoneMessage::RegistrationResult { version, .. }
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
    if decoded.is_empty() {
        Err("phone returned an empty credentialId".into())
    } else {
        Ok(decoded)
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
    let IdentityProofDto::Ed25519 { public_key, signature } = proof;
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assertion_request_has_no_conditionally_optional_fields() {
        let request = CeremonyRequest::Assert {
            key_name: "deploy".into(),
            prf_salt: "salt".into(),
            identity_salt: "identity-salt".into(),
            challenge: "challenge".into(),
            identity: NearbyIdentityRequest::Pinned {
                credential_id: "credential".into(),
            },
            remember: RememberOffer::Available { window_secs: 60 },
        };
        let json = serde_json::to_value(CliMessage::Request {
            version: PROTOCOL_VERSION,
            request,
        })
        .unwrap();
        assert_eq!(json["v"], 2);
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
    fn registration_request_carries_every_required_webauthn_value() {
        let request = CeremonyRequest::Register {
            challenge: "challenge".into(),
            prf_salt: "salt".into(),
            user_id: "user-id".into(),
            user_name: "keytap".into(),
        };
        let json = serde_json::to_value(CliMessage::Request {
            version: PROTOCOL_VERSION,
            request,
        })
        .unwrap();
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
                "v": 2,
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
                "v": 2,
                "reason": "mismatch"
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
                "v": 2,
                "reason": "identity-mismatch"
            })
        );
    }

    #[test]
    fn phone_messages_are_versioned_and_typed() {
        assert!(matches!(
            decode_phone_message(r#"{"v":2,"type":"remember-begin"}"#).unwrap(),
            PhoneMessage::RememberBegin { .. }
        ));
        assert!(decode_phone_message(r#"{"v":1,"type":"done"}"#).is_err());
        assert!(
            decode_phone_message(r#"{"v":2,"type":"assertion-result","credentialId":"YQ"}"#)
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
        let capability = Capability::generate();
        let rendezvous_id = capability.rendezvous_id();
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
        let signed_offer =
            capability.sign(SignalRole::Cli, 0, SignalKind::Offer, offer_sdp.as_bytes());
        send_signal(&mut cli_signaling, &signed_offer).unwrap();
        let received_offer = wait_for_authenticated_sdp(
            &mut phone_signaling,
            &capability,
            SignalRole::Cli,
            SignalKind::Offer,
            live_deadline,
        )
        .unwrap();
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
        let signed_answer = capability.sign(
            SignalRole::Phone,
            0,
            SignalKind::Answer,
            answer_sdp.as_bytes(),
        );
        send_signal(&mut phone_signaling, &signed_answer).unwrap();
        let received_answer =
            wait_for_answer(&mut cli_signaling, &capability, live_deadline).unwrap();
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
