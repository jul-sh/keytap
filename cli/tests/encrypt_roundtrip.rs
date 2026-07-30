//! Round-trip tests for the streaming encrypt/decrypt path.
//!
//! These exercise the same age operations `encrypt.rs` performs (derive an age
//! identity from a fixed 32-byte key, stream through the encryptor, stream back
//! through the decryptor) without needing a passkey. They verify the streaming
//! contract: what encrypt writes, decrypt must recover.

use std::io::Read;
use std::str::FromStr;

fn identity_from_raw(raw: &[u8]) -> age::x25519::Identity {
    let sk =
        keytap_core::format_private_key(raw, keytap_core::PrivateKeyFormat::AgeSecretKey).unwrap();
    let sk = String::from_utf8(sk).unwrap();
    age::x25519::Identity::from_str(&sk).unwrap()
}

/// Encrypt bytes the way `encrypt_stream` does (chunked, no buffering ceiling).
fn stream_encrypt(recipient: &age::x25519::Recipient, plaintext: &[u8]) -> Vec<u8> {
    let enc =
        age::Encryptor::with_recipients(std::iter::once(recipient as &dyn age::Recipient)).unwrap();
    let mut ct = Vec::new();
    let mut w = enc.wrap_output(&mut ct).unwrap();
    std::io::copy(&mut &plaintext[..], &mut w).unwrap();
    w.finish().unwrap();
    ct
}

/// Decrypt the way `decrypt_stream` does.
fn stream_decrypt(identity: &age::x25519::Identity, ciphertext: &[u8]) -> Vec<u8> {
    let dec = age::Decryptor::new(ciphertext).unwrap();
    let mut r = dec
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .unwrap();
    let mut out = Vec::new();
    r.read_to_end(&mut out).unwrap();
    out
}

#[test]
fn round_trips_small_payload() {
    let raw = [7u8; 32];
    let id = identity_from_raw(&raw);
    let plaintext = b"hello keytap streaming round trip";

    let ct = stream_encrypt(&id.to_public(), plaintext);
    assert_ne!(
        &ct[..],
        &plaintext[..],
        "ciphertext must differ from plaintext"
    );
    let pt = stream_decrypt(&id, &ct);
    assert_eq!(&pt[..], &plaintext[..]);
}

#[test]
fn round_trips_large_payload_streaming() {
    // 8 MiB comfortably exercises chunked streaming across many writes.
    let raw = [42u8; 32];
    let id = identity_from_raw(&raw);
    let plaintext: Vec<u8> = (0..8 * 1024 * 1024).map(|i| (i % 251) as u8).collect();

    let ct = stream_encrypt(&id.to_public(), &plaintext);
    let pt = stream_decrypt(&id, &ct);
    assert_eq!(pt.len(), plaintext.len());
    assert_eq!(pt, plaintext);
}

#[test]
fn wrong_identity_fails_to_decrypt() {
    let id_a = identity_from_raw(&[1u8; 32]);
    let id_b = identity_from_raw(&[2u8; 32]);
    let ct = stream_encrypt(&id_a.to_public(), b"secret");

    let dec = age::Decryptor::new(&ct[..]).unwrap();
    let result = dec.decrypt(std::iter::once(&id_b as &dyn age::Identity));
    assert!(
        result.is_err(),
        "decrypting with the wrong identity must fail"
    );
}

#[test]
fn empty_input_round_trips() {
    let id = identity_from_raw(&[9u8; 32]);
    let ct = stream_encrypt(&id.to_public(), b"");
    let pt = stream_decrypt(&id, &ct);
    assert!(pt.is_empty());
}
