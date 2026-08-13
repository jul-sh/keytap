use ed25519_dalek::SigningKey;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

/// Derive the public half of a nearby Ed25519 identity. Taking ownership lets
/// us wipe wasm-bindgen's private seed copy before returning to JavaScript.
#[wasm_bindgen(js_name = ed25519PublicKey)]
pub fn ed25519_public_key(mut seed: Vec<u8>) -> Result<Vec<u8>, JsError> {
    let Ok(mut seed_copy) = <[u8; 32]>::try_from(seed.as_slice()) else {
        seed.zeroize();
        return Err(JsError::new("Ed25519 seed must be 32 bytes"));
    };
    let signing_key = SigningKey::from_bytes(&seed_copy);
    let public_key = signing_key.verifying_key().to_bytes().to_vec();
    seed_copy.zeroize();
    seed.zeroize();
    Ok(public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_the_nearby_identity_vector() {
        assert_eq!(
            ed25519_public_key(vec![7; 32]).unwrap(),
            [
                0xea, 0x4a, 0x6c, 0x63, 0xe2, 0x9c, 0x52, 0x0a, 0xbe, 0xf5, 0x50, 0x7b, 0x13, 0x2e,
                0xc5, 0xf9, 0x95, 0x47, 0x76, 0xae, 0xbe, 0xbe, 0x7b, 0x92, 0x42, 0x1e, 0xea, 0x69,
                0x14, 0x46, 0xd2, 0x2c,
            ]
        );
    }
}
