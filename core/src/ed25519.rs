pub(crate) fn public_key(seed: &[u8; 32]) -> ed25519_dalek::VerifyingKey {
    ed25519_dalek::SigningKey::from_bytes(seed).verifying_key()
}
