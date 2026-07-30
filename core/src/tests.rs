use super::*;
use base64::Engine;

#[test]
fn test_validate_key_name_empty() {
    assert!(matches!(
        prf_salt_for_name(""),
        Err(KeytapError::InvalidKeyName { .. })
    ));
}

#[test]
fn test_validate_key_name_non_ascii() {
    assert!(matches!(
        prf_salt_for_name("kéy"),
        Err(KeytapError::InvalidKeyName { .. })
    ));
}

#[test]
fn test_validate_key_name_too_long() {
    let long_name = "a".repeat(129);
    assert!(matches!(
        prf_salt_for_name(&long_name),
        Err(KeytapError::InvalidKeyName { .. })
    ));
}

#[test]
fn test_validate_key_name_max_length_ok() {
    let name = "a".repeat(128);
    assert!(prf_salt_for_name(&name).is_ok());
}

#[test]
fn test_prf_salt_deterministic() {
    let salt1 = prf_salt_for_name("default").unwrap();
    let salt2 = prf_salt_for_name("default").unwrap();
    assert_eq!(salt1, salt2);
    assert_eq!(salt1.len(), 32);
}

#[test]
fn test_prf_salt_known_value() {
    // SHA256("keytap:prf:default")
    let salt = prf_salt_for_name("default").unwrap();
    // This is the canonical test vector - SHA256 of "keytap:prf:default"
    let computed = sha2::Sha256::digest(b"keytap:prf:default");
    assert_eq!(salt, computed.to_vec());
    // Salt should be exactly 32 bytes
    assert_eq!(salt.len(), 32);
}

#[test]
fn test_prf_salt_different_names() {
    let salt_default = prf_salt_for_name("default").unwrap();
    let salt_other = prf_salt_for_name("other").unwrap();
    assert_ne!(salt_default, salt_other);
}

#[test]
fn test_derive_raw_key_wrong_length() {
    assert!(matches!(
        derive_raw_key(&[0u8; 16]),
        Err(KeytapError::InvalidPrfOutputLength { actual: 16 })
    ));
}

#[test]
fn test_ed25519_public_key_from_identity_seed() {
    let public_key = ed25519_public_key(&[7; 32]).unwrap();
    assert_eq!(
        hex::encode(public_key),
        "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
    );
    assert!(matches!(
        ed25519_public_key(&[7; 31]),
        Err(KeytapError::InvalidPrfOutputLength { actual: 31 })
    ));
}

#[test]
fn test_derive_raw_key_deterministic() {
    let prf = [0x42u8; 32];
    let key1 = derive_raw_key(&prf).unwrap();
    let key2 = derive_raw_key(&prf).unwrap();
    assert_eq!(key1, key2);
    assert_eq!(key1.len(), 32);
}

#[test]
fn test_format_private_key_hex() {
    let raw = [0xab; 32];
    let result = format_private_key(&raw, PrivateKeyFormat::Hex).unwrap();
    let expected = "ab".repeat(32);
    assert_eq!(String::from_utf8(result).unwrap(), expected);
}

#[test]
fn test_format_private_key_base64() {
    let raw = [0u8; 32];
    let result = format_private_key(&raw, PrivateKeyFormat::Base64).unwrap();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(String::from_utf8(result).unwrap())
        .unwrap();
    assert_eq!(decoded, vec![0u8; 32]);
}

#[test]
fn test_format_private_key_age() {
    let raw = [0u8; 32];
    let result = format_private_key(&raw, PrivateKeyFormat::AgeSecretKey).unwrap();
    let s = String::from_utf8(result).unwrap();
    assert!(s.starts_with("AGE-SECRET-KEY-1"));
}

#[test]
fn test_format_private_key_ssh() {
    let raw = [0u8; 32];
    let result = format_private_key(&raw, PrivateKeyFormat::SshPrivateKey).unwrap();
    let s = String::from_utf8(result).unwrap();
    assert!(s.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
    assert!(s.ends_with("-----END OPENSSH PRIVATE KEY-----\n"));
}

#[test]
fn test_format_public_key_ssh() {
    let raw = [0u8; 32];
    let result = format_public_key(&raw, PublicKeyFormat::Ssh { comment: None }).unwrap();
    assert!(result.starts_with("ssh-ed25519 "));
    assert!(result.ends_with(" keytap"));
}

#[test]
fn test_format_public_key_ssh_with_name() {
    let raw = [0u8; 32];
    let result = format_public_key(
        &raw,
        PublicKeyFormat::Ssh {
            comment: Some("foo"),
        },
    )
    .unwrap();
    assert!(result.starts_with("ssh-ed25519 "));
    assert!(result.ends_with(" keytap:foo"));
    // The key body must be unaffected by the comment.
    let unnamed = format_public_key(&raw, PublicKeyFormat::Ssh { comment: None }).unwrap();
    assert_eq!(
        result.rsplit_once(' ').unwrap().0,
        unnamed.rsplit_once(' ').unwrap().0,
    );
}

#[test]
fn test_format_public_key_age() {
    let raw = [0u8; 32];
    let result = format_public_key(&raw, PublicKeyFormat::AgeRecipient).unwrap();
    assert!(result.starts_with("age1"));
}

#[test]
fn test_registration_config() {
    let config = registration_config();
    assert_eq!(config.rp_id, "keytap.jul.sh");
    assert_eq!(config.user_name, "keytap");
    assert_eq!(config.user_id, b"keytap-user");
    assert_eq!(config.default_prf_salt.len(), 32);
}

#[test]
fn test_assertion_config() {
    let config = assertion_config("mykey", None).unwrap();
    assert_eq!(config.rp_id, "keytap.jul.sh");
    assert_eq!(config.key_name, "mykey");
    assert_eq!(config.prf_salt.len(), 32);
    assert!(config.preferred_credential_id.is_none());
}

#[test]
fn test_assertion_config_with_credential() {
    let cred_id = vec![1, 2, 3, 4];
    let config = assertion_config("mykey", Some(cred_id.clone())).unwrap();
    assert_eq!(config.preferred_credential_id, Some(cred_id));
}

// Golden vector tests using fixture data
#[test]
fn test_golden_vectors() {
    let fixture_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/fixtures/derivation-vectors.json"
    );
    let data = std::fs::read_to_string(fixture_path).expect("fixture file must exist");
    let vectors: serde_json::Value = serde_json::from_str(&data).unwrap();

    for vector in vectors.as_array().unwrap() {
        let key_name = vector["key_name"].as_str().unwrap();
        let prf_output_hex = vector["prf_output_hex"].as_str().unwrap();
        let prf_output = hex::decode(prf_output_hex).unwrap();

        // Verify PRF salt
        let expected_salt_hex = vector["prf_salt_hex"].as_str().unwrap();
        let actual_salt = prf_salt_for_name(key_name).unwrap();
        assert_eq!(
            hex::encode(&actual_salt),
            expected_salt_hex,
            "PRF salt mismatch for key_name={}",
            key_name
        );

        // Verify raw key derivation
        let expected_raw_hex = vector["raw_key_hex"].as_str().unwrap();
        let raw_key = derive_raw_key(&prf_output).unwrap();
        assert_eq!(
            hex::encode(&raw_key),
            expected_raw_hex,
            "raw key mismatch for key_name={}",
            key_name
        );

        // Verify private key formats
        let private_formats = vector["private"].as_object().unwrap();

        let hex_result = format_private_key(&raw_key, PrivateKeyFormat::Hex).unwrap();
        assert_eq!(
            String::from_utf8(hex_result).unwrap(),
            private_formats["hex"].as_str().unwrap(),
            "hex private key mismatch"
        );

        let b64_result = format_private_key(&raw_key, PrivateKeyFormat::Base64).unwrap();
        assert_eq!(
            String::from_utf8(b64_result).unwrap(),
            private_formats["base64"].as_str().unwrap(),
            "base64 private key mismatch"
        );

        let age_result = format_private_key(&raw_key, PrivateKeyFormat::AgeSecretKey).unwrap();
        assert_eq!(
            String::from_utf8(age_result).unwrap(),
            private_formats["age"].as_str().unwrap(),
            "age private key mismatch"
        );

        let ssh_result = format_private_key(&raw_key, PrivateKeyFormat::SshPrivateKey).unwrap();
        assert_eq!(
            String::from_utf8(ssh_result).unwrap(),
            private_formats["ssh"].as_str().unwrap(),
            "ssh private key mismatch"
        );

        // Verify public key formats
        let public_formats = vector["public"].as_object().unwrap();

        let hex_pub = format_public_key(&raw_key, PublicKeyFormat::Hex).unwrap();
        assert_eq!(
            hex_pub,
            public_formats["hex"].as_str().unwrap(),
            "hex public key mismatch"
        );

        let b64_pub = format_public_key(&raw_key, PublicKeyFormat::Base64).unwrap();
        assert_eq!(
            b64_pub,
            public_formats["base64"].as_str().unwrap(),
            "base64 public key mismatch"
        );

        let age_pub = format_public_key(&raw_key, PublicKeyFormat::AgeRecipient).unwrap();
        assert_eq!(
            age_pub,
            public_formats["age"].as_str().unwrap(),
            "age public key mismatch"
        );

        let ssh_pub = format_public_key(&raw_key, PublicKeyFormat::Ssh { comment: None }).unwrap();
        assert_eq!(
            ssh_pub,
            public_formats["ssh"].as_str().unwrap(),
            "ssh public key mismatch"
        );
    }
}

#[test]
fn test_parse_age_secret_key_round_trips() {
    for raw in [[0u8; 32], [7u8; 32], [0xFF; 32]] {
        let encoded =
            String::from_utf8(format_private_key(&raw, PrivateKeyFormat::AgeSecretKey).unwrap())
                .unwrap();
        assert_eq!(parse_age_secret_key(&encoded).unwrap(), raw.to_vec());
        // bech32 permits either case as long as it's uniform; keytap emits
        // uppercase, but a lowercased copy must parse to the same key.
        assert_eq!(
            parse_age_secret_key(&encoded.to_lowercase()).unwrap(),
            raw.to_vec()
        );
    }
}

#[test]
fn test_parse_age_secret_key_rejects_bad_input() {
    let valid =
        String::from_utf8(format_private_key(&[7u8; 32], PrivateKeyFormat::AgeSecretKey).unwrap())
            .unwrap();

    // Not bech32 at all.
    assert!(matches!(
        parse_age_secret_key("not-a-key"),
        Err(KeytapError::InvalidKeyMaterial { .. })
    ));
    // Other lossless encodings of the same key are deliberately refused:
    // the env contract is one format, not autodetection.
    let hex =
        String::from_utf8(format_private_key(&[7u8; 32], PrivateKeyFormat::Hex).unwrap()).unwrap();
    assert!(parse_age_secret_key(&hex).is_err());
    // Wrong prefix, valid bech32.
    let wrong_hrp = bech32_encode("age", &[7u8; 32]);
    assert!(matches!(
        parse_age_secret_key(&wrong_hrp),
        Err(KeytapError::InvalidKeyMaterial { .. })
    ));
    // Right prefix, wrong payload length.
    let short = bech32_encode("age-secret-key-", &[7u8; 16]);
    assert!(matches!(
        parse_age_secret_key(&short),
        Err(KeytapError::InvalidKeyMaterial { .. })
    ));
    // A corrupted character trips the checksum instead of yielding a key.
    let mut corrupted = valid.clone();
    let last = corrupted.pop().unwrap();
    corrupted.push(if last == 'Q' { 'P' } else { 'Q' });
    assert!(parse_age_secret_key(&corrupted).is_err());
    // Mixed case is invalid bech32.
    let mixed = format!("age-SECRET-key-{}", &valid["AGE-SECRET-KEY-".len()..]);
    assert!(parse_age_secret_key(&mixed).is_err());
}
