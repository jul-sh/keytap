use base64::Engine;
use sha2::{Digest, Sha256};
const CHECK_INT_LABEL: &[u8] = b"tapkey:ssh-checkint";

fn ed25519_public_key(seed: &[u8; 32]) -> ed25519_dalek::VerifyingKey {
    ed25519_dalek::SigningKey::from_bytes(seed).verifying_key()
}

pub fn public_key_line(seed: &[u8]) -> String {
    let seed: &[u8; 32] = seed.try_into().unwrap();
    let vk = ed25519_public_key(seed);
    let key = ssh_key::PublicKey::from(ssh_key::public::Ed25519PublicKey::from(vk));
    let openssh = key.to_openssh().unwrap();
    format!("{} tapkey", openssh)
}

/// OpenSSH private key PEM with deterministic check-int.
///
/// Standard ssh-key crates use random check-ints. Tapkey needs determinism
/// (same seed → same PEM), so we build the private key blob manually.
pub fn private_key_pem(seed: &[u8]) -> String {
    let seed: &[u8; 32] = seed.try_into().unwrap();
    let pub_key = ed25519_public_key(seed).to_bytes();

    // Check-int: first 4 bytes of SHA256("tapkey:ssh-checkint" || seed)
    let check_int = {
        let hash = Sha256::digest([CHECK_INT_LABEL, seed].concat());
        u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
    };

    let mut blob = Vec::new();
    blob.extend(b"openssh-key-v1\0");
    push_str(&mut blob, "none"); // cipher
    push_str(&mut blob, "none"); // kdf
    push_str(&mut blob, "");     // kdf options
    push_u32(&mut blob, 1);      // number of keys

    // Public section
    let pub_blob = [str_bytes("ssh-ed25519"), len_bytes(&pub_key)].concat();
    push_bytes(&mut blob, &pub_blob);

    // Private section
    let mut priv_payload = Vec::new();
    push_u32(&mut priv_payload, check_int);
    push_u32(&mut priv_payload, check_int);
    priv_payload.extend(str_bytes("ssh-ed25519"));
    push_bytes(&mut priv_payload, &pub_key);
    push_bytes(&mut priv_payload, &[seed.as_slice(), &pub_key].concat());
    push_str(&mut priv_payload, ""); // comment
    let mut pad: u8 = 1;
    while priv_payload.len() % 8 != 0 {
        priv_payload.push(pad);
        pad += 1;
    }
    push_bytes(&mut blob, &priv_payload);

    let b64 = base64::engine::general_purpose::STANDARD.encode(&blob);
    let wrapped: Vec<&str> = b64.as_bytes().chunks(76).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n", wrapped.join("\n"))
}

fn push_u32(buf: &mut Vec<u8>, v: u32) { buf.extend(v.to_be_bytes()); }
fn push_str(buf: &mut Vec<u8>, s: &str) { push_bytes(buf, s.as_bytes()); }
fn push_bytes(buf: &mut Vec<u8>, d: &[u8]) { push_u32(buf, d.len() as u32); buf.extend(d); }
fn str_bytes(s: &str) -> Vec<u8> { let mut v = Vec::new(); push_str(&mut v, s); v }
fn len_bytes(d: &[u8]) -> Vec<u8> { let mut v = Vec::new(); push_bytes(&mut v, d); v }
