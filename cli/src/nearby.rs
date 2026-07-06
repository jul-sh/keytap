use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hkdf::Hkdf;
use sha2::Sha256;
use std::net::TcpStream;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{connect, Message, WebSocket};
use x25519_dalek::{EphemeralSecret, PublicKey};

const DEFAULT_RELAY_URL: &str = "wss://keytap-relay.julsh.workers.dev";
const PAGE_URL: &str = "https://keytap.jul.sh/n";
const WS_TIMEOUT_SECS: u64 = 300; // 5 minutes

/// A completed nearby assertion ceremony.
pub struct NearbyAssertion {
    pub prf_output: Vec<u8>,
    /// Credential ID of the passkey that produced the PRF output.
    pub credential_id: Vec<u8>,
    /// The user ticked "remember this key on this machine" on the phone page.
    pub remember_requested: bool,
}

/// Authenticate via nearby device. `offer_remember` controls whether the
/// phone page shows its "remember this key on this machine" checkbox;
/// `keytap remember` suppresses it because that command already stores.
pub fn authenticate_nearby(name: &str, offer_remember: bool) -> NearbyAssertion {
    let payload = run_nearby_flow("assert", name, offer_remember);
    let prf_output = payload.prf_first.unwrap_or_else(|| {
        crate::die("passkey provider did not return PRF output — it may not support the PRF extension");
    });
    NearbyAssertion {
        prf_output,
        credential_id: payload.credential_id,
        // A request the CLI never offered is not honored, whatever the page sent.
        remember_requested: offer_remember && payload.remember_requested,
    }
}

/// Register a passkey via nearby device; returns the new credential ID.
pub fn register_nearby() -> Vec<u8> {
    let payload = run_nearby_flow("register", "default", false);
    eprintln!("Passkey registered successfully via nearby device.");
    payload.credential_id
}

fn run_nearby_flow(operation: &str, name: &str, offer_remember: bool) -> NearbyPayload {
    // Install rustls crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok(); // ok if already installed

    let relay_url =
        std::env::var("KEYTAP_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY_URL.to_string());

    // Generate X25519 keypair
    let cli_secret = EphemeralSecret::random_from_rng(OsRng);
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
    let (mut ws, _) = connect(&ws_url).unwrap_or_else(|e| {
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
    eprintln!("Waiting for response (timeout: 5 minutes)…");

    // Set read timeout
    set_ws_timeout(&ws, WS_TIMEOUT_SECS);

    // Wait for response
    let response = wait_for_response(&mut ws);

    // Decrypt
    decrypt_response(cli_secret, &response, &session_id)
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

    // "may remember": the page only offers its remember checkbox when this
    // CLI is new enough to honor the request (older CLIs ignore the payload
    // flag, which would turn the checkbox into a silent no-op).
    if offer_remember {
        config["m"] = serde_json::json!(true);
    }

    config.to_string()
}

fn set_ws_timeout(ws: &WebSocket<MaybeTlsStream<TcpStream>>, secs: u64) {
    let timeout = Some(std::time::Duration::from_secs(secs));
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

struct RelayResponse {
    phone_pk: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn wait_for_response(ws: &mut WebSocket<MaybeTlsStream<TcpStream>>) -> RelayResponse {
    loop {
        let msg = ws.read().unwrap_or_else(|e| {
            crate::die(&format!("relay connection error: {e}"));
        });

        match msg {
            Message::Text(text) => {
                let parsed: serde_json::Value =
                    serde_json::from_str(&text).unwrap_or_else(|e| {
                        crate::die(&format!("invalid relay response: {e}"));
                    });

                let pk = parsed["pk"]
                    .as_str()
                    .unwrap_or_else(|| crate::die("missing pk in relay response"));
                let nonce = parsed["nonce"]
                    .as_str()
                    .unwrap_or_else(|| crate::die("missing nonce in relay response"));
                let ct = parsed["ciphertext"]
                    .as_str()
                    .unwrap_or_else(|| crate::die("missing ciphertext in relay response"));

                return RelayResponse {
                    phone_pk: URL_SAFE_NO_PAD
                        .decode(pk)
                        .unwrap_or_else(|e| crate::die(&format!("invalid pk: {e}"))),
                    nonce: URL_SAFE_NO_PAD
                        .decode(nonce)
                        .unwrap_or_else(|e| crate::die(&format!("invalid nonce: {e}"))),
                    ciphertext: URL_SAFE_NO_PAD
                        .decode(ct)
                        .unwrap_or_else(|e| crate::die(&format!("invalid ciphertext: {e}"))),
                };
            }
            Message::Close(_) => {
                crate::die("relay connection closed before receiving response");
            }
            Message::Ping(data) => {
                ws.send(Message::Pong(data)).ok();
            }
            _ => {}
        }
    }
}

/// The decrypted phone payload, decoded but not yet validated against the
/// operation (registrations carry no PRF output; assertions must).
struct NearbyPayload {
    credential_id: Vec<u8>,
    prf_first: Option<Vec<u8>>,
    remember_requested: bool,
}

fn decrypt_response(
    cli_secret: EphemeralSecret,
    response: &RelayResponse,
    session_id: &str,
) -> NearbyPayload {
    let phone_pk_bytes: [u8; 32] = response.phone_pk[..].try_into().unwrap_or_else(|_| {
        crate::die("phone public key must be 32 bytes");
    });
    let phone_pk = PublicKey::from(phone_pk_bytes);

    // ECDH shared secret
    let shared_secret = cli_secret.diffie_hellman(&phone_pk);

    // HKDF-SHA256(ikm=shared, salt=session_id, info="keytap:e2e:v1") → 32-byte AES key
    let hk = Hkdf::<Sha256>::new(Some(session_id.as_bytes()), shared_secret.as_bytes());
    let mut aes_key = [0u8; 32];
    hk.expand(b"keytap:e2e:v1", &mut aes_key)
        .unwrap_or_else(|e| crate::die(&format!("HKDF expansion failed: {e}")));

    // AES-256-GCM decrypt
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .unwrap_or_else(|e| crate::die(&format!("AES key init failed: {e}")));

    let nonce = Nonce::from_slice(&response.nonce);
    let plaintext = cipher
        .decrypt(nonce, response.ciphertext.as_ref())
        .unwrap_or_else(|e| crate::die(&format!("decryption failed: {e}")));

    parse_payload(&plaintext)
}

/// Decode a decrypted phone payload into its protocol fields.
fn parse_payload(plaintext: &[u8]) -> NearbyPayload {
    let payload: serde_json::Value = serde_json::from_slice(plaintext)
        .unwrap_or_else(|e| crate::die(&format!("invalid decrypted payload: {e}")));

    let cred_id_b64 = payload["credentialId"]
        .as_str()
        .unwrap_or_else(|| crate::die("missing credentialId in decrypted payload"));
    let credential_id = URL_SAFE_NO_PAD
        .decode(cred_id_b64)
        .unwrap_or_else(|e| crate::die(&format!("invalid credentialId: {e}")));

    // Registration responses carry no PRF output; assertions must. The caller
    // enforces presence so this stays a pure protocol decoder.
    let prf_first = payload["prfFirst"].as_str().map(|prf_b64| {
        let decoded = URL_SAFE_NO_PAD
            .decode(prf_b64)
            .unwrap_or_else(|e| crate::die(&format!("invalid prfFirst: {e}")));
        if decoded.is_empty() {
            crate::die("passkey provider returned empty PRF output — it may not support the PRF extension");
        }
        decoded
    });

    NearbyPayload {
        credential_id,
        prf_first,
        // Absent on registrations and on pages that predate the checkbox.
        remember_requested: payload["remember"].as_bool().unwrap_or(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_without_remember_field_requests_nothing() {
        let payload = parse_payload(
            br#"{"credentialId":"Y3JlZA","prfFirst":"cHJm"}"#,
        );
        assert!(!payload.remember_requested);
        assert_eq!(payload.credential_id, b"cred");
        assert_eq!(payload.prf_first.as_deref(), Some(b"prf".as_slice()));
    }

    #[test]
    fn payload_with_remember_true_requests_remembering() {
        let payload = parse_payload(
            br#"{"credentialId":"Y3JlZA","prfFirst":"cHJm","remember":true}"#,
        );
        assert!(payload.remember_requested);
    }

    #[test]
    fn qr_config_offers_remember_only_when_asked() {
        let cli_secret = EphemeralSecret::random_from_rng(OsRng);
        let cli_public = PublicKey::from(&cli_secret);
        let config = |offer| -> serde_json::Value {
            let json = build_qr_config("assert", "session", &cli_public, "deploy", &[0; 32], &[0; 32], offer);
            serde_json::from_str(&json).unwrap()
        };
        assert_eq!(config(true)["m"], serde_json::json!(true));
        assert!(config(false).get("m").is_none());
    }
}
