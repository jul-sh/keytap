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

use crate::Format;

const DEFAULT_RELAY_URL: &str = "wss://tapkey-relay.julsh.workers.dev";
const PAGE_URL: &str = "https://tapkey.jul.sh/nearby";
const WS_TIMEOUT_SECS: u64 = 300; // 5 minutes

pub fn start_nearby_flow(operation: &str, name: &str, format: Format, is_public: bool) {
    // Install rustls crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok(); // ok if already installed

    let relay_url =
        std::env::var("TAPKEY_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY_URL.to_string());

    // Generate X25519 keypair
    let cli_secret = EphemeralSecret::random_from_rng(OsRng);
    let cli_public = PublicKey::from(&cli_secret);

    // Generate random session ID (22 base64url chars = 16 bytes)
    let mut session_bytes = [0u8; 16];
    getrandom::getrandom(&mut session_bytes).expect("failed to generate random session ID");
    let session_id = URL_SAFE_NO_PAD.encode(session_bytes);

    // Build QR config
    let prf_salt = tapkey_core::prf_salt_for_name(name).unwrap_or_else(|e| {
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
    );

    let cfg_b64 = URL_SAFE_NO_PAD.encode(config.as_bytes());
    let url = format!("{PAGE_URL}#cfg={cfg_b64}");

    // Connect WebSocket to relay
    let ws_url = format!("{relay_url}/relay/{session_id}");
    let (mut ws, _) = connect(&ws_url).unwrap_or_else(|e| {
        crate::die(&format!("failed to connect to relay: {e}"));
    });

    // Print QR code to stderr (keep stdout clean for key output)
    eprintln!();
    eprintln!("Scan this QR code with your phone:");
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
    let (_credential_id, prf_first) = decrypt_response(cli_secret, &response, &session_id);

    if operation == "register" {
        eprintln!("Passkey registered successfully via nearby device.");
        std::process::exit(0);
    }

    // For derive/public-key: emit the key
    crate::emit_key(&prf_first, format, is_public);
}

fn build_qr_config(
    operation: &str,
    session_id: &str,
    cli_public: &PublicKey,
    name: &str,
    prf_salt: &[u8],
    challenge: &[u8],
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
        config["u"] = serde_json::json!(URL_SAFE_NO_PAD.encode(b"tapkey-user"));
        config["un"] = serde_json::json!("tapkey");
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

fn decrypt_response(
    cli_secret: EphemeralSecret,
    response: &RelayResponse,
    session_id: &str,
) -> (Vec<u8>, Vec<u8>) {
    let phone_pk_bytes: [u8; 32] = response.phone_pk[..].try_into().unwrap_or_else(|_| {
        crate::die("phone public key must be 32 bytes");
    });
    let phone_pk = PublicKey::from(phone_pk_bytes);

    // ECDH shared secret
    let shared_secret = cli_secret.diffie_hellman(&phone_pk);

    // HKDF-SHA256(ikm=shared, salt=session_id, info="tapkey:e2e:v1") → 32-byte AES key
    let hk = Hkdf::<Sha256>::new(Some(session_id.as_bytes()), shared_secret.as_bytes());
    let mut aes_key = [0u8; 32];
    hk.expand(b"tapkey:e2e:v1", &mut aes_key)
        .unwrap_or_else(|e| crate::die(&format!("HKDF expansion failed: {e}")));

    // AES-256-GCM decrypt
    let cipher = Aes256Gcm::new_from_slice(&aes_key)
        .unwrap_or_else(|e| crate::die(&format!("AES key init failed: {e}")));

    let nonce = Nonce::from_slice(&response.nonce);
    let plaintext = cipher
        .decrypt(nonce, response.ciphertext.as_ref())
        .unwrap_or_else(|e| crate::die(&format!("decryption failed: {e}")));

    let payload: serde_json::Value = serde_json::from_slice(&plaintext)
        .unwrap_or_else(|e| crate::die(&format!("invalid decrypted payload: {e}")));

    let cred_id_b64 = payload["credentialId"]
        .as_str()
        .unwrap_or_else(|| crate::die("missing credentialId in decrypted payload"));
    let credential_id = URL_SAFE_NO_PAD
        .decode(cred_id_b64)
        .unwrap_or_else(|e| crate::die(&format!("invalid credentialId: {e}")));

    let prf_first = if let Some(prf_b64) = payload["prfFirst"].as_str() {
        URL_SAFE_NO_PAD
            .decode(prf_b64)
            .unwrap_or_else(|e| crate::die(&format!("invalid prfFirst: {e}")))
    } else {
        Vec::new()
    };

    (credential_id, prf_first)
}
