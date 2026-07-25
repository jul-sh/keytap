//! Protocol-level tests for the nearby WebRTC security boundary.
//!
//! WebRTC DTLS protects data-channel payloads. These tests independently
//! exercise the compact QR public key and the Ed25519 signature that binds the
//! complete CLI SDP offer (including its DTLS certificate fingerprint).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey};
use sha2::{Digest, Sha256};

const RID_DOMAIN: &[u8] = b"keytap:rendezvous:v3\0";
const OFFER_SIGNATURE_DOMAIN: &[u8] = b"keytap:signal-offer:v3\0";

fn rendezvous_id(public_key: &[u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(RID_DOMAIN);
    digest.update(public_key);
    digest.finalize().into()
}

fn offer_message(body: &[u8]) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(OFFER_SIGNATURE_DOMAIN);
    message.push(3);
    message.extend_from_slice(b"cli\0");
    message.extend_from_slice(&0u64.to_be_bytes());
    message.extend_from_slice(b"offer\0");
    message.extend_from_slice(&(body.len() as u64).to_be_bytes());
    message.extend_from_slice(body);
    message
}

#[test]
fn qr_is_a_compact_fragment_only_public_key() {
    let signing = SigningKey::from_bytes(&[7; 32]);
    let public_key = signing.verifying_key().to_bytes();
    let encoded = URL_SAFE_NO_PAD.encode(public_key);
    let url = format!("https://keytap.jul.sh/nearby#k={encoded}");

    assert_eq!(encoded.len(), 43);
    assert_eq!(url.len(), 74);
    assert!(!url.contains('?'));
    assert_eq!(URL_SAFE_NO_PAD.decode(encoded).unwrap(), public_key);
    assert_ne!(public_key, [7; 32], "the QR must not contain the signing seed");
}

#[test]
fn signaling_matches_the_cross_language_fixed_vector() {
    let signing = SigningKey::from_bytes(&[7; 32]);
    let public_key = signing.verifying_key().to_bytes();
    let body = br#"{"type":"offer"}"#;
    let signature = signing.sign(&offer_message(body)).to_bytes();

    assert_eq!(
        URL_SAFE_NO_PAD.encode(public_key),
        "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw"
    );
    assert_eq!(
        URL_SAFE_NO_PAD.encode(rendezvous_id(&public_key)),
        "MFHH-4Il-dVD-AwsB7c-4kdD25EFZ_aGEczf569GW8U"
    );
    assert_eq!(
        URL_SAFE_NO_PAD.encode(signature),
        "U2k9m3s7XkIf9QF0ShT4TNY-FzYYAfoF4RX9zLBWoo5TYwS5-oblqKqQdK7mQVxO92UWDTidykN6Nm3vXeWPDg"
    );
}

#[test]
fn changing_the_sdp_fingerprint_invalidates_the_signature() {
    let signing = SigningKey::from_bytes(&[7; 32]);
    let authentic = b"v=0\r\na=fingerprint:sha-256 AA:BB:CC\r\n";
    let substituted = b"v=0\r\na=fingerprint:sha-256 DD:EE:FF\r\n";
    let signature = signing.sign(&offer_message(authentic));

    signing
        .verifying_key()
        .verify_strict(&offer_message(authentic), &signature)
        .unwrap();
    assert!(signing
        .verifying_key()
        .verify_strict(
            &offer_message(substituted),
            &Signature::from_bytes(&signature.to_bytes()),
        )
        .is_err());
}

#[test]
fn test_derive_key_from_prf_output() {
    let fake_prf = [42u8; 32];
    let raw_key = keytap_core::derive_raw_key(&fake_prf).unwrap();
    assert_eq!(raw_key.len(), 32);
    assert_eq!(raw_key, keytap_core::derive_raw_key(&fake_prf).unwrap());
}
