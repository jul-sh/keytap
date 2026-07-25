use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hkdf::Hkdf;
use sha2::Sha256;
use std::net::TcpStream;
use std::time::{Duration, Instant};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{connect, Message, WebSocket};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const DEFAULT_RELAY_URL: &str = "wss://keytap-relay.julsh.workers.dev";
const PAGE_URL: &str = "https://keytap.jul.sh/n";
const WS_TIMEOUT_SECS: u64 = 300; // 5 minutes

/// How long the CLI stays reachable for the phone page's post-auth
/// "remember this key" opt-in, by default. The page releases the CLI the
/// moment the user finishes (an explicit tap, or closing the page fires a
/// beacon); the window is only the backstop when that signal is lost.
/// Advertised to the page in the session config (`w`) so it can show the
/// offer as expired instead of letting a ceremony run into a dead session.
const DEFAULT_REMEMBER_WINDOW_SECS: u64 = 60;

/// The remember window, honoring `KEYTAP_REMEMBER_WINDOW` (seconds).
/// `0` disables the opt-in entirely; users who need more time to act on
/// the phone (WCAG 2.2.1) can raise it, up to an hour.
fn remember_window_secs() -> u64 {
    match std::env::var("KEYTAP_REMEMBER_WINDOW") {
        Ok(value) => value
            .trim()
            .parse::<u64>()
            .map(|secs| secs.min(3600))
            .unwrap_or(DEFAULT_REMEMBER_WINDOW_SECS),
        Err(_) => DEFAULT_REMEMBER_WINDOW_SECS,
    }
}

/// Extra time granted when the page reports the remember button was tapped
/// (`remember-pending`): the second passkey ceremony is now in flight (the
/// page's WebAuthn timeout is 120s), and it must not race the window that
/// was ticking while the user decided.
const REMEMBER_PENDING_EXTENSION_SECS: u64 = 150;

/// Hard ceiling on the whole opt-in window, extensions included, so a page
/// re-sending `remember-pending` can never pin the CLI open indefinitely.
const MAX_LINGER_SECS: u64 = 600;

/// A completed nearby assertion ceremony.
pub struct NearbyAssertion {
    pub prf_output: Vec<u8>,
    /// Credential ID of the passkey that produced the PRF output.
    pub credential_id: Vec<u8>,
    /// The user asked to remember this key on this machine (legacy pages
    /// send it with the assertion itself; current pages use [`RememberWindow`]).
    pub remember_requested: bool,
    /// Open channel for the page's post-auth remember opt-in, present when
    /// this CLI offered one and the first payload didn't already request it.
    /// The caller settles it AFTER emitting its output, so the key is never
    /// delayed by the opt-in window.
    pub followup: Option<RememberWindow>,
}

/// Authenticate via nearby device. `offer_remember` controls whether the
/// phone page offers its post-auth "remember this key on this machine" step;
/// `keytap remember` suppresses it because that command already stores.
pub fn authenticate_nearby(name: &str, offer_remember: bool) -> NearbyAssertion {
    let (payload, session) = run_nearby_flow("assert", name, offer_remember);
    let prf_output = payload.prf_first.unwrap_or_else(|| {
        crate::die("passkey provider did not return PRF output — it may not support the PRF extension");
    });
    // A request the CLI never offered is not honored, whatever the page sent.
    let remember_requested = offer_remember && payload.remember_requested;
    let window_secs = remember_window_secs();
    // The opt-in window opens only when there is something to wait for:
    // the request didn't already arrive with the assertion (legacy checkbox
    // pages), the page declared it can follow up (`follow` — old cached
    // pages never send `done`, so waiting on them is a guaranteed stall),
    // and the window wasn't disabled.
    let followup = match session {
        Some(session) if !remember_requested && payload.follow && window_secs > 0 => {
            Some(RememberWindow {
                session,
                name: name.to_string(),
                window_secs,
                credential_id: payload.credential_id.clone(),
                prf_output: Zeroizing::new(prf_output.clone()),
            })
        }
        _ => None,
    };
    NearbyAssertion {
        prf_output,
        credential_id: payload.credential_id,
        remember_requested,
        followup,
    }
}

/// Register a passkey via nearby device; returns the new credential ID.
pub fn register_nearby() -> Vec<u8> {
    let (payload, _) = run_nearby_flow("register", "default", false);
    eprintln!("Passkey registered successfully via nearby device.");
    payload.credential_id
}

/// The live relay connection plus everything needed to decrypt further
/// messages on it.
struct WsSession {
    ws: WebSocket<MaybeTlsStream<TcpStream>>,
    secret: StaticSecret,
    session_id: String,
}

/// The open opt-in window after a nearby assertion: the page may still send
/// a remember request backed by a second passkey ceremony.
pub struct RememberWindow {
    session: WsSession,
    /// Key name, for the mismatch warning's suggested command.
    name: String,
    /// Window length actually advertised to the page.
    window_secs: u64,
    /// The credential that produced the key the user would be remembering.
    credential_id: Vec<u8>,
    /// Its PRF output; a valid opt-in re-presents it. Key material, so it
    /// is wiped when the window closes.
    prf_output: Zeroizing<Vec<u8>>,
}

use crate::note;

impl RememberWindow {
    /// Wait (bounded) for the page's remember opt-in. `true` means the user
    /// completed a second ceremony with the same passkey and the key should
    /// be remembered. Every failure mode — timeout, page gone, relay gone,
    /// malformed traffic — is `false`: the command's real work already
    /// happened, so nothing here is worth failing over. Ctrl-C here is the
    /// user saying "I have my key": it ends the wait as a success, never as
    /// a failure a `set -e` script would trip on.
    pub fn settle(mut self) -> bool {
        note(&format!(
            "Key delivered. Waiting up to {}s in case you choose \u{201c}remember\u{201d} on \
             your phone (finishing or closing the page there ends the wait; Ctrl-C skips).",
            self.window_secs
        ));
        exit_zero_on_sigint();
        let opted_in = self.run_window();
        // A closed socket makes the page's later POSTs honest 410s ("that
        // machine finished") instead of deliveries into the void.
        self.session.ws.close(None).ok();
        self.session.ws.flush().ok();
        opted_in
    }

    fn run_window(&mut self) -> bool {
        let start = Instant::now();
        let hard_stop = start + Duration::from_secs(MAX_LINGER_SECS);
        let mut deadline = start + Duration::from_secs(self.window_secs);
        // Each advisory line prints at most once: a flood of junk or
        // mismatched approvals (anyone who fetched the config before the
        // first delivery wiped it can post) must not amplify into stderr
        // spam. Later occurrences still act, just silently.
        let mut announced_pending = false;
        let mut warned_mismatch = false;
        loop {
            let remaining = deadline.min(hard_stop).saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            set_ws_timeout(&self.session.ws, remaining);
            let msg = match self.session.ws.read() {
                Ok(msg) => msg,
                // Timeout, relay gone, page gone: the window just closes.
                Err(_) => return false,
            };
            match msg {
                Message::Text(text) => match decode_phone_message(&self.session, &text) {
                    Ok(PhoneMessage::Done) => return false,
                    // The remember button was tapped; the second ceremony is
                    // in flight and gets its own time.
                    Ok(PhoneMessage::RememberPending) => {
                        if !announced_pending {
                            announced_pending = true;
                            note("Remember chosen on the phone; waiting for the passkey approval…");
                        }
                        deadline = Instant::now()
                            + Duration::from_secs(REMEMBER_PENDING_EXTENSION_SECS);
                    }
                    Ok(PhoneMessage::Assertion(payload)) if payload.remember_requested => {
                        if self.matches_first_ceremony(&payload) {
                            return true;
                        }
                        // Keep the window open: the page that holds the real
                        // session may still act (another tab could have sent
                        // this one).
                        if !warned_mismatch {
                            warned_mismatch = true;
                            note(&format!(
                                "warning: the \u{201c}remember\u{201d} approval on your phone \
                                 used a different passkey than the one that derived this key; \
                                 nothing was stored. Run `keytap remember {}` on this machine \
                                 to store it deliberately.",
                                self.name
                            ));
                        }
                    }
                    // An assertion without a remember request, or noise:
                    // not what the window is for; keep waiting.
                    Ok(PhoneMessage::Assertion(_)) | Err(_) => {}
                },
                Message::Close(_) => return false,
                Message::Ping(data) => {
                    self.session.ws.send(Message::Pong(data)).ok();
                }
                _ => {}
            }
        }
    }

    /// Whether a remember follow-up re-presents the ceremony that derived
    /// the key: same credential, same PRF output. The PRF comparison is the
    /// gate that matters (credential IDs are public), so it is constant-time.
    /// Defense-in-depth against page bugs and tab mixups — the page relays
    /// no authenticator signature, so this is not cryptographic proof of a
    /// second gesture.
    fn matches_first_ceremony(&self, payload: &NearbyPayload) -> bool {
        use subtle::ConstantTimeEq;
        let prf_matches: bool = match payload.prf_first.as_deref() {
            Some(prf) => prf.ct_eq(&self.prf_output).into(),
            None => false,
        };
        payload.credential_id == self.credential_id && prf_matches
    }
}

/// From here to exit, Ctrl-C means "stop waiting, all is well": the key has
/// already been emitted and stdout flushed, so interrupting the opt-in
/// window must read as success to shells and `set -e` scripts.
fn exit_zero_on_sigint() {
    extern "C" fn exit_ok(_: libc::c_int) {
        // Async-signal-safe, and the flush already happened.
        unsafe { libc::_exit(0) }
    }
    unsafe {
        libc::signal(libc::SIGINT, exit_ok as extern "C" fn(libc::c_int) as usize);
    }
}

fn run_nearby_flow(
    operation: &str,
    name: &str,
    offer_remember: bool,
) -> (NearbyPayload, Option<WsSession>) {
    // Install rustls crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok(); // ok if already installed

    let relay_url =
        std::env::var("KEYTAP_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY_URL.to_string());

    // X25519 keypair for this session. Static (reusable) rather than
    // ephemeral-consumed: the page sends each message under a fresh keypair
    // of its own, and the CLI must be able to decrypt more than one
    // (the assertion, then a possible remember opt-in).
    let cli_secret = StaticSecret::random_from_rng(OsRng);
    let cli_public = PublicKey::from(&cli_secret);

    // Generate random session ID (8 base64url chars = 6 bytes)
    let mut session_bytes = [0u8; 6];
    getrandom::getrandom(&mut session_bytes).expect("failed to generate random session ID");
    let session_id = URL_SAFE_NO_PAD.encode(session_bytes);

    // Build QR config
    let prf_salt = keytap_core::prf_salt_for_name(name).unwrap_or_else(|e| {
        crate::die(&format!("invalid key name: {e}"));
    });

    let mut challenge_bytes = [0u8; 32];
    getrandom::getrandom(&mut challenge_bytes).expect("failed to generate challenge");

    let config = build_qr_config(
        operation,
        &session_id,
        &cli_public,
        name,
        &prf_salt,
        &challenge_bytes,
        offer_remember,
    );

    // Upload config to relay
    let config_url = format!(
        "{}/relay/{}",
        relay_url.replace("wss://", "https://").replace("ws://", "http://"),
        session_id
    );
    let resp = ureq::put(&config_url)
        .content_type("application/json")
        .send(config.as_bytes())
        .unwrap_or_else(|e| {
            crate::die(&format!("failed to upload config to relay: {e}"));
        });
    if resp.status() != 200 {
        crate::die(&format!("relay rejected config: {}", resp.status()));
    }

    let url = format!("{PAGE_URL}/{session_id}");
    // GitHub Pages 404.html redirects /n/{id} → /nearby#s={id}

    // Connect WebSocket to relay
    let ws_url = format!("{relay_url}/relay/{session_id}");
    let (ws, _) = connect(&ws_url).unwrap_or_else(|e| {
        crate::die(&format!("failed to connect to relay: {e}"));
    });

    // Print QR code to stderr (keep stdout clean for key output)
    eprintln!();
    eprintln!("Scan to authenticate with a passkey on your phone (end-to-end encrypted):");
    eprintln!();
    let qr_string = qr2term::generate_qr_string(&url).unwrap_or_else(|e| {
        crate::die(&format!("failed to render QR code: {e}"));
    });
    eprint!("{qr_string}");
    eprintln!();
    eprintln!("Or open: {url}");
    eprintln!();
    eprintln!("One-time host public key (compare with phone):");
    eprintln!("{}", URL_SAFE_NO_PAD.encode(cli_public.as_bytes()));
    eprintln!();
    eprintln!("Waiting for response (timeout: 5 minutes)…");

    let mut session = WsSession { ws, secret: cli_secret, session_id };

    // Wait for the assertion (or registration) payload
    let payload = wait_for_first_payload(&mut session);

    let session = offer_remember.then_some(session);
    (payload, session)
}

fn build_qr_config(
    operation: &str,
    session_id: &str,
    cli_public: &PublicKey,
    name: &str,
    prf_salt: &[u8],
    challenge: &[u8],
    offer_remember: bool,
) -> String {
    let op = match operation {
        "register" => "r",
        _ => "a",
    };

    let mut config = serde_json::json!({
        "o": op,
        "s": session_id,
        "k": URL_SAFE_NO_PAD.encode(cli_public.as_bytes()),
        "n": name,
        "p": URL_SAFE_NO_PAD.encode(prf_salt),
        "c": URL_SAFE_NO_PAD.encode(challenge),
    });

    if operation == "register" {
        config["u"] = serde_json::json!(URL_SAFE_NO_PAD.encode(b"keytap-user"));
        config["un"] = serde_json::json!("keytap");
    }

    // Remember capability, twice over for version skew:
    // `w` (window seconds) is what current pages key on — it means "this CLI
    // lingers after the assertion for a post-auth remember opt-in", and tells
    // the page when the offer expires. `m` is kept for old cached pages,
    // whose pre-auth checkbox rides in with the first payload; that legacy
    // request is still honored. Pages ignore flags they don't know, and a
    // page must never offer remembering to a CLI that would drop it.
    if offer_remember {
        config["m"] = serde_json::json!(true);
        let window_secs = remember_window_secs();
        if window_secs > 0 {
            config["w"] = serde_json::json!(window_secs);
        }
    }

    config.to_string()
}

fn set_ws_timeout(ws: &WebSocket<MaybeTlsStream<TcpStream>>, timeout: Duration) {
    // Zero would mean "block forever"; the callers' deadlines never ask for it.
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

/// The encrypted envelope every phone message travels in.
struct Envelope {
    phone_pk: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// Block until the phone sends its first real payload; die only on what is
/// truly unrecoverable (relay gone, timeout, a page that was closed before
/// approving). Undecryptable or malformed frames are noise — anyone who
/// learns the session id can push bytes through the relay, and AES-GCM
/// already rejects forgeries — so they are reported and skipped, never fatal.
fn wait_for_first_payload(session: &mut WsSession) -> NearbyPayload {
    let timed_out = || -> ! {
        crate::die(
            "timed out after 5 minutes waiting for the phone. \
             Run the command again for a fresh QR code.",
        );
    };
    // A wall-clock deadline, not a per-read timeout: junk frames must not
    // be able to keep pushing the five minutes out.
    let deadline = Instant::now() + Duration::from_secs(WS_TIMEOUT_SECS);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            timed_out();
        }
        set_ws_timeout(&session.ws, remaining);
        let msg = session.ws.read().unwrap_or_else(|e| {
            if let tungstenite::Error::Io(io) = &e {
                if matches!(
                    io.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) {
                    timed_out();
                }
            }
            crate::die(&format!("relay connection error: {e}"));
        });

        match msg {
            Message::Text(text) => match decode_phone_message(session, &text) {
                Ok(PhoneMessage::Assertion(payload)) => return payload,
                Ok(PhoneMessage::Done) => {
                    crate::die("the page on your phone was closed before approving");
                }
                Ok(PhoneMessage::RememberPending) => {}
                Err(_) => {
                    eprintln!(
                        "note: ignored an unreadable message from the relay; if the phone page \
                         says the code was already used, press Ctrl-C and run the command again"
                    );
                }
            },
            Message::Close(_) => {
                crate::die("relay connection closed before receiving response");
            }
            Message::Ping(data) => {
                session.ws.send(Message::Pong(data)).ok();
            }
            _ => {}
        }
    }
}

/// Parse and decrypt one relay text frame into a phone message.
fn decode_phone_message(session: &WsSession, text: &str) -> Result<PhoneMessage, String> {
    let envelope = parse_envelope(text)?;
    let plaintext = decrypt_envelope(&session.secret, &envelope, &session.session_id)?;
    parse_message(&plaintext)
}

fn parse_envelope(text: &str) -> Result<Envelope, String> {
    let parsed: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("invalid relay response: {e}"))?;

    let field = |key: &str| -> Result<Vec<u8>, String> {
        let value = parsed[key]
            .as_str()
            .ok_or_else(|| format!("missing {key} in relay response"))?;
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|e| format!("invalid {key}: {e}"))
    };

    Ok(Envelope {
        phone_pk: field("pk")?,
        nonce: field("nonce")?,
        ciphertext: field("ciphertext")?,
    })
}

fn decrypt_envelope(
    secret: &StaticSecret,
    envelope: &Envelope,
    session_id: &str,
) -> Result<Vec<u8>, String> {
    let phone_pk_bytes: [u8; 32] = envelope.phone_pk[..]
        .try_into()
        .map_err(|_| "phone public key must be 32 bytes".to_string())?;
    let phone_pk = PublicKey::from(phone_pk_bytes);

    // ECDH shared secret
    let shared_secret = secret.diffie_hellman(&phone_pk);

    // HKDF-SHA256(ikm=shared, salt=session_id, info="keytap:e2e:v1") → 32-byte AES key
    let hk = Hkdf::<Sha256>::new(Some(session_id.as_bytes()), shared_secret.as_bytes());
    let mut aes_key = [0u8; 32];
    hk.expand(b"keytap:e2e:v1", &mut aes_key)
        .map_err(|e| format!("HKDF expansion failed: {e}"))?;

    // AES-256-GCM decrypt
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .map_err(|e| format!("AES key init failed: {e}"))?;

    let nonce = Nonce::from_slice(&envelope.nonce);
    cipher
        .decrypt(nonce, envelope.ciphertext.as_ref())
        .map_err(|e| format!("decryption failed: {e}"))
}

/// A decrypted message from the phone page.
enum PhoneMessage {
    /// A passkey ceremony result (assertion or registration).
    Assertion(NearbyPayload),
    /// The user is finished on the page; nothing more is coming.
    Done,
    /// The remember button was tapped; a second ceremony is in flight.
    RememberPending,
}

/// The decrypted ceremony payload, decoded but not yet validated against the
/// operation (registrations carry no PRF output; assertions must).
struct NearbyPayload {
    credential_id: Vec<u8>,
    prf_first: Option<Vec<u8>>,
    remember_requested: bool,
    /// The page can send follow-up messages (done, remember). Old cached
    /// pages never set it, and never get lingered on.
    follow: bool,
}

/// Decode a decrypted phone payload into its protocol message.
fn parse_message(plaintext: &[u8]) -> Result<PhoneMessage, String> {
    let payload: serde_json::Value = serde_json::from_slice(plaintext)
        .map_err(|e| format!("invalid decrypted payload: {e}"))?;

    match payload["type"].as_str() {
        Some("done") => return Ok(PhoneMessage::Done),
        Some("remember-pending") => return Ok(PhoneMessage::RememberPending),
        _ => {}
    }

    let cred_id_b64 = payload["credentialId"]
        .as_str()
        .ok_or_else(|| "missing credentialId in decrypted payload".to_string())?;
    let credential_id = URL_SAFE_NO_PAD
        .decode(cred_id_b64)
        .map_err(|e| format!("invalid credentialId: {e}"))?;

    // Registration responses carry no PRF output; assertions must. The caller
    // enforces presence so this stays a pure protocol decoder.
    let prf_first = match payload["prfFirst"].as_str() {
        Some(prf_b64) => {
            let decoded = URL_SAFE_NO_PAD
                .decode(prf_b64)
                .map_err(|e| format!("invalid prfFirst: {e}"))?;
            if decoded.is_empty() {
                return Err(
                    "passkey provider returned empty PRF output — it may not support the PRF extension"
                        .to_string(),
                );
            }
            Some(decoded)
        }
        None => None,
    };

    Ok(PhoneMessage::Assertion(NearbyPayload {
        credential_id,
        prf_first,
        // Absent on registrations and on pages that predate the opt-in.
        remember_requested: payload["remember"].as_bool().unwrap_or(false),
        follow: payload["follow"].as_bool().unwrap_or(false),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_assertion(plaintext: &[u8]) -> NearbyPayload {
        match parse_message(plaintext).unwrap() {
            PhoneMessage::Assertion(payload) => payload,
            _ => panic!("expected an assertion"),
        }
    }

    #[test]
    fn payload_without_remember_field_requests_nothing() {
        let payload = parse_assertion(br#"{"credentialId":"Y3JlZA","prfFirst":"cHJm"}"#);
        assert!(!payload.remember_requested);
        assert_eq!(payload.credential_id, b"cred");
        assert_eq!(payload.prf_first.as_deref(), Some(b"prf".as_slice()));
    }

    #[test]
    fn payload_with_remember_true_requests_remembering() {
        let payload =
            parse_assertion(br#"{"credentialId":"Y3JlZA","prfFirst":"cHJm","remember":true}"#);
        assert!(payload.remember_requested);
    }

    #[test]
    fn done_message_parses_as_done() {
        assert!(matches!(
            parse_message(br#"{"type":"done"}"#).unwrap(),
            PhoneMessage::Done
        ));
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        assert!(parse_message(b"not json").is_err());
        assert!(parse_message(br#"{"type":"assert-success"}"#).is_err());
    }

    #[test]
    fn qr_config_offers_remember_only_when_asked() {
        let cli_secret = StaticSecret::random_from_rng(OsRng);
        let cli_public = PublicKey::from(&cli_secret);
        let config = |offer| -> serde_json::Value {
            let json = build_qr_config("assert", "session", &cli_public, "deploy", &[0; 32], &[0; 32], offer);
            serde_json::from_str(&json).unwrap()
        };
        assert_eq!(config(true)["m"], serde_json::json!(true));
        assert!(config(false).get("m").is_none());
    }
}
