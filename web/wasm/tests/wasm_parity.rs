//! Run the shared crates' crypto under wasm (via `wasm-pack test`) to prove
//! the browser build derives and formats exactly like the native one.

use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn prf_salt_deterministic() {
    let salt1 = keytap_core::prf_salt_for_name("default").unwrap();
    let salt2 = keytap_core::prf_salt_for_name("default").unwrap();
    assert_eq!(salt1, salt2);
    assert_eq!(salt1.len(), 32);
}

#[wasm_bindgen_test]
fn invalid_name_rejected() {
    assert!(keytap_core::prf_salt_for_name("").is_err());
}

#[wasm_bindgen_test]
fn derive_raw_key_works() {
    let prf = vec![0x42u8; 32];
    let key = keytap_core::derive_raw_key(&prf).unwrap();
    assert_eq!(key.len(), 32);
    assert!(keytap_core::derive_raw_key(&[0u8; 16]).is_err());
}

#[wasm_bindgen_test]
fn formats_render() {
    let raw = vec![0xab; 32];
    let hex = keytap_core::format_private_key(&raw, keytap_core::PrivateKeyFormat::Hex).unwrap();
    assert_eq!(String::from_utf8(hex).unwrap(), "ab".repeat(32));

    let age = keytap_core::format_private_key(&raw, keytap_core::PrivateKeyFormat::AgeSecretKey).unwrap();
    assert!(String::from_utf8(age).unwrap().starts_with("AGE-SECRET-KEY-1"));

    let ssh =
        keytap_core::format_private_key_display(&raw, keytap_core::PrivateKeyFormat::SshPrivateKey)
            .unwrap();
    let ssh = String::from_utf8(ssh).unwrap();
    assert!(ssh.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
    assert!(ssh.ends_with("-----END OPENSSH PRIVATE KEY-----\n"));

    let public =
        keytap_core::format_public_key_display(&raw, keytap_core::PublicKeyFormat::SshPublicKey, "demo")
            .unwrap();
    assert!(public.starts_with("ssh-ed25519 "));
    assert!(public.ends_with(" keytap:demo\n"));
}

#[wasm_bindgen_test]
fn age_roundtrip() {
    let raw = vec![7u8; 32];
    let recipients = keytap_core::encrypt::recipients(Some(&raw), &[], &[]).unwrap();
    let mut ciphertext = Vec::new();
    keytap_core::encrypt::encrypt_stream(&recipients, &mut &b"wasm parity"[..], &mut ciphertext)
        .unwrap();
    let mut plaintext = Vec::new();
    keytap_core::encrypt::decrypt_stream(&raw, &mut &ciphertext[..], &mut plaintext).unwrap();
    assert_eq!(plaintext, b"wasm parity");
}

#[wasm_bindgen_test]
fn spec_parses_formats_by_clap_name() {
    use std::str::FromStr;
    let format = keytap_cli_spec::Format::from_str("ssh").unwrap();
    assert_eq!(format.as_str(), "ssh");
    assert!(keytap_cli_spec::Format::from_str("yaml").is_err());
}
