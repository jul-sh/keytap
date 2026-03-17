/// End-to-end test for the nearby relay crypto protocol.
/// Simulates both the CLI and phone sides to verify:
/// - X25519 ECDH produces the same shared secret on both sides
/// - HKDF-SHA256 derives the same AES key
/// - AES-256-GCM encryption/decryption round-trips correctly
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

#[test]
fn test_ecdh_shared_secret_matches() {
    // CLI side
    let cli_secret = EphemeralSecret::random_from_rng(OsRng);
    let cli_public = PublicKey::from(&cli_secret);

    // Phone side
    let phone_secret = EphemeralSecret::random_from_rng(OsRng);
    let phone_public = PublicKey::from(&phone_secret);

    // Both sides compute ECDH
    let cli_shared = cli_secret.diffie_hellman(&phone_public);
    let phone_shared = phone_secret.diffie_hellman(&cli_public);

    assert_eq!(cli_shared.as_bytes(), phone_shared.as_bytes());
}

#[test]
fn test_full_e2e_encrypt_decrypt() {
    let session_id = "test-session-id-12345";

    // CLI generates keypair
    let cli_secret = EphemeralSecret::random_from_rng(OsRng);
    let cli_public = PublicKey::from(&cli_secret);

    // Phone generates keypair
    let phone_secret = EphemeralSecret::random_from_rng(OsRng);
    let phone_public = PublicKey::from(&phone_secret);

    // --- Phone side encryption (simulates Web Crypto) ---

    // Phone does ECDH with CLI's public key
    let phone_shared = phone_secret.diffie_hellman(&cli_public);

    // HKDF
    let phone_hk = Hkdf::<Sha256>::new(Some(session_id.as_bytes()), phone_shared.as_bytes());
    let mut phone_aes_key = [0u8; 32];
    phone_hk
        .expand(b"tapkey:e2e:v1", &mut phone_aes_key)
        .unwrap();

    // Encrypt payload
    let payload = serde_json::json!({
        "credentialId": "dGVzdC1jcmVkLWlk",
        "prfFirst": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    });
    let plaintext = serde_json::to_vec(&payload).unwrap();

    let phone_cipher = Aes256Gcm::new_from_slice(&phone_aes_key).unwrap();
    let nonce_bytes: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]; // deterministic for test
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = phone_cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

    // --- CLI side decryption ---

    // CLI does ECDH with phone's public key
    let cli_shared = cli_secret.diffie_hellman(&phone_public);

    // HKDF
    let cli_hk = Hkdf::<Sha256>::new(Some(session_id.as_bytes()), cli_shared.as_bytes());
    let mut cli_aes_key = [0u8; 32];
    cli_hk
        .expand(b"tapkey:e2e:v1", &mut cli_aes_key)
        .unwrap();

    // Keys must match
    assert_eq!(phone_aes_key, cli_aes_key);

    // Decrypt
    let cli_cipher = Aes256Gcm::new_from_slice(&cli_aes_key).unwrap();
    let decrypted = cli_cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();

    let decrypted_payload: serde_json::Value = serde_json::from_slice(&decrypted).unwrap();
    assert_eq!(decrypted_payload, payload);
}

#[test]
fn test_base64url_roundtrip() {
    let original = [0u8, 1, 2, 255, 254, 253, 128, 64, 32];
    let encoded = URL_SAFE_NO_PAD.encode(&original);
    let decoded = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
    assert_eq!(original.to_vec(), decoded);
}

#[test]
fn test_qr_config_compact_format() {
    // Verify the compact QR config format is valid JSON with expected fields
    let session_id = URL_SAFE_NO_PAD.encode([0u8; 16]);
    let cli_public_b64 = URL_SAFE_NO_PAD.encode([0u8; 32]);
    let prf_salt_b64 = URL_SAFE_NO_PAD.encode([0u8; 32]);
    let challenge_b64 = URL_SAFE_NO_PAD.encode([0u8; 32]);

    let config = serde_json::json!({
        "o": "a",
        "s": session_id,
        "k": cli_public_b64,
        "n": "default",
        "p": prf_salt_b64,
        "c": challenge_b64,
    });

    let config_str = config.to_string();
    let config_b64 = URL_SAFE_NO_PAD.encode(config_str.as_bytes());
    let url = format!("https://tapkey.jul.sh/nearby#cfg={}", config_b64);

    // Verify URL is reasonably short for QR
    assert!(
        url.len() < 400,
        "URL too long for QR: {} chars",
        url.len()
    );

    // Verify we can decode it back
    let decoded_bytes = URL_SAFE_NO_PAD.decode(&config_b64).unwrap();
    let decoded_str = String::from_utf8(decoded_bytes).unwrap();
    let decoded: serde_json::Value = serde_json::from_str(&decoded_str).unwrap();
    assert_eq!(decoded["o"], "a");
    assert_eq!(decoded["n"], "default");
    assert_eq!(decoded["s"], session_id);
}

#[test]
fn test_derive_key_from_prf_output() {
    // Verify that the key derivation path matches tapkey-core
    let fake_prf = [42u8; 32]; // simulated PRF output
    let raw_key = tapkey_core::derive_raw_key(&fake_prf).unwrap();
    assert_eq!(raw_key.len(), 32);

    // Determinism: same PRF input → same key
    let raw_key2 = tapkey_core::derive_raw_key(&fake_prf).unwrap();
    assert_eq!(raw_key, raw_key2);
}
