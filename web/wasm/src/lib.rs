use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = registrationConfig)]
pub fn registration_config() -> Result<JsValue, JsError> {
    let config = keytap_core::registration_config();
    Ok(serde_wasm_bindgen::to_value(&RegistrationConfigJs {
        rp_id: config.rp_id,
        user_name: config.user_name,
        user_id: config.user_id,
        default_prf_salt: config.default_prf_salt,
    })?)
}

#[wasm_bindgen(js_name = assertionConfig)]
pub fn assertion_config(
    key_name: &str,
    preferred_credential_id: Option<Vec<u8>>,
) -> Result<JsValue, JsError> {
    let config = keytap_core::assertion_config(key_name, preferred_credential_id)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(serde_wasm_bindgen::to_value(&AssertionConfigJs {
        rp_id: config.rp_id,
        key_name: config.key_name,
        prf_salt: config.prf_salt,
        preferred_credential_id: config.preferred_credential_id,
    })?)
}

#[wasm_bindgen(js_name = prfSaltForName)]
pub fn prf_salt_for_name(key_name: &str) -> Result<Vec<u8>, JsError> {
    keytap_core::prf_salt_for_name(key_name).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen(js_name = deriveRawKey)]
pub fn derive_raw_key(prf_output: &[u8]) -> Result<Vec<u8>, JsError> {
    keytap_core::derive_raw_key(prf_output).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen(js_name = formatPrivateKey)]
pub fn format_private_key(raw_key: &[u8], format: &str) -> Result<Vec<u8>, JsError> {
    let fmt = parse_private_format(format)?;
    keytap_core::format_private_key(raw_key, fmt).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen(js_name = formatPublicKey)]
pub fn format_public_key(raw_key: &[u8], format: &str) -> Result<String, JsError> {
    let fmt = parse_public_format(format)?;
    keytap_core::format_public_key(raw_key, fmt).map_err(|e| JsError::new(&e.to_string()))
}

fn parse_private_format(s: &str) -> Result<keytap_core::PrivateKeyFormat, JsError> {
    match s {
        "hex" => Ok(keytap_core::PrivateKeyFormat::Hex),
        "base64" => Ok(keytap_core::PrivateKeyFormat::Base64),
        "age" => Ok(keytap_core::PrivateKeyFormat::AgeSecretKey),
        "raw" => Ok(keytap_core::PrivateKeyFormat::Raw),
        "ssh" => Ok(keytap_core::PrivateKeyFormat::SshPrivateKey),
        _ => Err(JsError::new(&format!("unknown private key format: {}", s))),
    }
}

fn parse_public_format(s: &str) -> Result<keytap_core::PublicKeyFormat, JsError> {
    match s {
        "hex" => Ok(keytap_core::PublicKeyFormat::Hex),
        "base64" => Ok(keytap_core::PublicKeyFormat::Base64),
        "age" => Ok(keytap_core::PublicKeyFormat::AgeRecipient),
        "ssh" => Ok(keytap_core::PublicKeyFormat::SshPublicKey),
        _ => Err(JsError::new(&format!("unknown public key format: {}", s))),
    }
}

#[derive(serde::Serialize)]
struct RegistrationConfigJs {
    rp_id: String,
    user_name: String,
    user_id: Vec<u8>,
    default_prf_salt: Vec<u8>,
}

#[derive(serde::Serialize)]
struct AssertionConfigJs {
    rp_id: String,
    key_name: String,
    prf_salt: Vec<u8>,
    preferred_credential_id: Option<Vec<u8>>,
}

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[test]
    fn test_parse_private_formats() {
        assert!(parse_private_format("hex").is_ok());
        assert!(parse_private_format("base64").is_ok());
        assert!(parse_private_format("age").is_ok());
        assert!(parse_private_format("raw").is_ok());
        assert!(parse_private_format("ssh").is_ok());
        assert!(parse_private_format("invalid").is_err());
    }

    #[test]
    fn test_parse_public_formats() {
        assert!(parse_public_format("hex").is_ok());
        assert!(parse_public_format("base64").is_ok());
        assert!(parse_public_format("age").is_ok());
        assert!(parse_public_format("ssh").is_ok());
        assert!(parse_public_format("invalid").is_err());
    }
}
