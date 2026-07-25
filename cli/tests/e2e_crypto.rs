//! Protocol-level tests for the nearby WebRTC security boundary.
//!
//! WebRTC DTLS protects data-channel payloads. These tests independently
//! exercise the compact QR capability and the HMAC transcript that binds the
//! complete SDP (including its DTLS certificate fingerprint) to that
//! capability.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const RID_DOMAIN: &[u8] = b"keytap:rendezvous:v2\0";
const MAC_DOMAIN: &[u8] = b"keytap:signal:v2\0";

fn rendezvous_id(capability: &[u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(RID_DOMAIN);
    digest.update(capability);
    digest.finalize().into()
}

fn cli_signal_key(capability: &[u8; 32], rid: &[u8; 32]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(Some(rid), capability);
    let mut key = [0u8; 32];
    hkdf.expand(b"keytap:signal-key:v2:cli", &mut key).unwrap();
    key
}

fn cli_offer_mac(capability: &[u8; 32], body: &[u8]) -> [u8; 32] {
    let rid = rendezvous_id(capability);
    let key = cli_signal_key(capability, &rid);
    let mut mac = HmacSha256::new_from_slice(&key).unwrap();
    mac.update(MAC_DOMAIN);
    mac.update(b"cli\0");
    mac.update(&0u64.to_be_bytes());
    mac.update(b"offer\0");
    mac.update(&(body.len() as u64).to_be_bytes());
    mac.update(body);
    mac.finalize().into_bytes().into()
}

#[test]
fn qr_is_a_compact_fragment_only_capability() {
    let capability = [0x42u8; 32];
    let encoded = URL_SAFE_NO_PAD.encode(capability);
    let url = format!("https://keytap.jul.sh/nearby#q={encoded}");

    assert_eq!(encoded.len(), 43);
    assert_eq!(url.len(), 74);
    assert!(!url.contains('?'));
    assert_eq!(URL_SAFE_NO_PAD.decode(encoded).unwrap(), capability);
}

#[test]
fn signaling_matches_the_cross_language_fixed_vector() {
    let capability = [0x42u8; 32];
    let rid = rendezvous_id(&capability);
    let body = br#"{"type":"offer"}"#;
    let mac = cli_offer_mac(&capability, body);

    assert_eq!(
        URL_SAFE_NO_PAD.encode(rid),
        "6_2qUdwr2cvl5omCEB61Ys263Y1nu0TIjppVQPePcUA"
    );
    assert_eq!(
        URL_SAFE_NO_PAD.encode(cli_signal_key(&capability, &rid)),
        "3WRsRm1tbJnFAp8FuyV6TUTOY5ouwjbG_Q26FHhnHTk"
    );
    assert_eq!(
        URL_SAFE_NO_PAD.encode(mac),
        "FoqM9kpeEx726l8vB0Whib5XjyzePgjWQwBiOFQtZ1E"
    );
}

#[test]
fn changing_the_sdp_fingerprint_invalidates_the_signal() {
    let capability = [0x42u8; 32];
    let authentic = b"v=0\r\na=fingerprint:sha-256 AA:BB:CC\r\n";
    let substituted = b"v=0\r\na=fingerprint:sha-256 DD:EE:FF\r\n";
    let expected = cli_offer_mac(&capability, authentic);
    let actual = cli_offer_mac(&capability, substituted);

    assert_ne!(expected, actual);
    let rid = rendezvous_id(&capability);
    let key = cli_signal_key(&capability, &rid);
    let mut verifier = HmacSha256::new_from_slice(&key).unwrap();
    verifier.update(MAC_DOMAIN);
    verifier.update(b"cli\0");
    verifier.update(&0u64.to_be_bytes());
    verifier.update(b"offer\0");
    verifier.update(&(substituted.len() as u64).to_be_bytes());
    verifier.update(substituted);
    assert!(verifier.verify_slice(&expected).is_err());
}

#[test]
fn test_derive_key_from_prf_output() {
    let fake_prf = [42u8; 32];
    let raw_key = keytap_core::derive_raw_key(&fake_prf).unwrap();
    assert_eq!(raw_key.len(), 32);
    assert_eq!(raw_key, keytap_core::derive_raw_key(&fake_prf).unwrap());
}
