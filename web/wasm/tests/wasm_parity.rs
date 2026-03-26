use wasm_bindgen_test::*;

#[wasm_bindgen_test]
fn test_prf_salt_deterministic() {
    let salt1 = keytap_web::prf_salt_for_name("default").unwrap();
    let salt2 = keytap_web::prf_salt_for_name("default").unwrap();
    assert_eq!(salt1, salt2);
    assert_eq!(salt1.len(), 32);
}

#[wasm_bindgen_test]
fn test_prf_salt_invalid_name() {
    assert!(keytap_web::prf_salt_for_name("").is_err());
}

#[wasm_bindgen_test]
fn test_derive_raw_key() {
    let prf = vec![0x42u8; 32];
    let key = keytap_web::derive_raw_key(&prf).unwrap();
    assert_eq!(key.len(), 32);
}

#[wasm_bindgen_test]
fn test_derive_raw_key_wrong_length() {
    assert!(keytap_web::derive_raw_key(&[0u8; 16]).is_err());
}

#[wasm_bindgen_test]
fn test_format_private_key_hex() {
    let raw = vec![0xab; 32];
    let result = keytap_web::format_private_key(&raw, "hex").unwrap();
    let expected = "ab".repeat(32);
    assert_eq!(String::from_utf8(result).unwrap(), expected);
}

#[wasm_bindgen_test]
fn test_format_private_key_age() {
    let raw = vec![0u8; 32];
    let result = keytap_web::format_private_key(&raw, "age").unwrap();
    let s = String::from_utf8(result).unwrap();
    assert!(s.starts_with("AGE-SECRET-KEY-1"));
}

#[wasm_bindgen_test]
fn test_format_private_key_ssh() {
    let raw = vec![0u8; 32];
    let result = keytap_web::format_private_key(&raw, "ssh").unwrap();
    let s = String::from_utf8(result).unwrap();
    assert!(s.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
}

#[wasm_bindgen_test]
fn test_format_public_key_ssh() {
    let raw = vec![0u8; 32];
    let result = keytap_web::format_public_key(&raw, "ssh").unwrap();
    assert!(result.starts_with("ssh-ed25519 "));
    assert!(result.ends_with(" keytap"));
}

#[wasm_bindgen_test]
fn test_format_public_key_age() {
    let raw = vec![0u8; 32];
    let result = keytap_web::format_public_key(&raw, "age").unwrap();
    assert!(result.starts_with("age1"));
}

#[wasm_bindgen_test]
fn test_format_invalid_format() {
    let raw = vec![0u8; 32];
    assert!(keytap_web::format_private_key(&raw, "invalid").is_err());
    assert!(keytap_web::format_public_key(&raw, "invalid").is_err());
}

#[wasm_bindgen_test]
fn test_golden_parity() {
    // Test the exact same vectors as the core golden tests
    let vectors: Vec<TestVector> = serde_json::from_str(include_str!(
        "../../../tests/fixtures/derivation-vectors.json"
    ))
    .unwrap();

    for v in &vectors {
        let prf_output = hex_decode(&v.prf_output_hex);
        let raw_key = keytap_web::derive_raw_key(&prf_output).unwrap();
        assert_eq!(hex_encode(&raw_key), v.raw_key_hex);

        let salt = keytap_web::prf_salt_for_name(&v.key_name).unwrap();
        assert_eq!(hex_encode(&salt), v.prf_salt_hex);

        let hex_priv = keytap_web::format_private_key(&raw_key, "hex").unwrap();
        assert_eq!(String::from_utf8(hex_priv).unwrap(), v.private.hex);

        let b64_priv = keytap_web::format_private_key(&raw_key, "base64").unwrap();
        assert_eq!(String::from_utf8(b64_priv).unwrap(), v.private.base64);

        let age_priv = keytap_web::format_private_key(&raw_key, "age").unwrap();
        assert_eq!(String::from_utf8(age_priv).unwrap(), v.private.age);

        let ssh_priv = keytap_web::format_private_key(&raw_key, "ssh").unwrap();
        assert_eq!(String::from_utf8(ssh_priv).unwrap(), v.private.ssh);

        let hex_pub = keytap_web::format_public_key(&raw_key, "hex").unwrap();
        assert_eq!(hex_pub, v.public.hex);

        let b64_pub = keytap_web::format_public_key(&raw_key, "base64").unwrap();
        assert_eq!(b64_pub, v.public.base64);

        let age_pub = keytap_web::format_public_key(&raw_key, "age").unwrap();
        assert_eq!(age_pub, v.public.age);

        let ssh_pub = keytap_web::format_public_key(&raw_key, "ssh").unwrap();
        assert_eq!(ssh_pub, v.public.ssh);
    }
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[derive(serde::Deserialize)]
struct TestVector {
    key_name: String,
    prf_output_hex: String,
    prf_salt_hex: String,
    raw_key_hex: String,
    private: FormatOutputs,
    public: FormatOutputs,
}

#[derive(serde::Deserialize)]
struct FormatOutputs {
    hex: String,
    base64: String,
    age: String,
    ssh: String,
}
