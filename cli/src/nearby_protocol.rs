//! Authentication for the nearby WebRTC signaling transcript.
//!
//! The QR fragment contains a fresh Ed25519 public key. The CLI signs its
//! complete WebRTC offer, including the DTLS fingerprint, so a phone that
//! scanned the QR can authenticate the peer before it runs WebAuthn. The
//! signaling service receives only a hash-derived rendezvous identifier.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
#[cfg(test)]
use ed25519_dalek::Signature;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const RID_DOMAIN: &[u8] = b"keytap:rendezvous:v3\0";
const OFFER_SIGNATURE_DOMAIN: &[u8] = b"keytap:signal-offer:v3\0";
const SAS_RELEASE_DOMAIN: &[u8] = b"keytap:nearby-sas-release:v1\0";
const IDENTITY_SESSION_DOMAIN: &[u8] = b"keytap:nearby-identity-session:v2\0";
const SIGNAL_VERSION: u8 = 3;

/// The one-time CLI authentication key whose public half is carried by QR.
pub struct CliSessionKey {
    seed: Zeroizing<[u8; 32]>,
    public_key: [u8; 32],
    rendezvous: [u8; 32],
}

impl CliSessionKey {
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(seed.as_mut()).expect("failed to generate nearby CLI identity");
        Self::from_seed(seed)
    }

    fn from_seed(seed: Zeroizing<[u8; 32]>) -> Self {
        let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let rendezvous = rendezvous_for(&public_key);
        Self {
            seed,
            public_key,
            rendezvous,
        }
    }

    /// The QR value is public, fixed-width, and remains 43 base64url chars.
    pub fn fragment_value(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.public_key)
    }

    pub fn rendezvous_id(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.rendezvous)
    }

    pub fn sign_offer(&self, body: &[u8]) -> SignedCliOffer {
        let signature = SigningKey::from_bytes(&self.seed)
            .sign(&offer_signature_message(0, body))
            .to_bytes();
        SignedCliOffer {
            version: SIGNAL_VERSION,
            from: CliRole::Cli,
            seq: 0,
            kind: OfferKind::Offer,
            body: URL_SAFE_NO_PAD.encode(body),
            signature: URL_SAFE_NO_PAD.encode(signature),
        }
    }

    /// Authorize release of a held WebAuthn result only after the local CLI
    /// comparison. The phone nonce is generated after WebAuthn completes, so
    /// a valid authorization cannot have been queued before the result existed.
    pub fn sign_pairing_release(
        &self,
        session_binding: &[u8; 32],
        sas_digest: &[u8; 32],
        canonical_request: &[u8],
        release_nonce: &[u8; 32],
    ) -> [u8; 64] {
        SigningKey::from_bytes(&self.seed)
            .sign(&pairing_release_message(
                &self.public_key,
                session_binding,
                sas_digest,
                canonical_request,
                release_nonce,
            ))
            .to_bytes()
    }

    /// Bind identity proofs and SAS to the QR key plus both complete SDPs.
    pub fn identity_session_binding(&self, offer: &[u8], answer: &[u8]) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(IDENTITY_SESSION_DOMAIN);
        digest.update(self.public_key);
        digest.update((offer.len() as u64).to_be_bytes());
        digest.update(offer);
        digest.update((answer.len() as u64).to_be_bytes());
        digest.update(answer);
        digest.finalize().into()
    }
}

fn rendezvous_for(public_key: &[u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(RID_DOMAIN);
    digest.update(public_key);
    digest.finalize().into()
}

fn offer_signature_message(seq: u64, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(OFFER_SIGNATURE_DOMAIN.len() + body.len() + 25);
    message.extend_from_slice(OFFER_SIGNATURE_DOMAIN);
    message.push(SIGNAL_VERSION);
    message.extend_from_slice(b"cli\0");
    message.extend_from_slice(&seq.to_be_bytes());
    message.extend_from_slice(b"offer\0");
    message.extend_from_slice(&(body.len() as u64).to_be_bytes());
    message.extend_from_slice(body);
    message
}

fn pairing_release_message(
    cli_public_key: &[u8; 32],
    session_binding: &[u8; 32],
    sas_digest: &[u8; 32],
    canonical_request: &[u8],
    release_nonce: &[u8; 32],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        SAS_RELEASE_DOMAIN.len()
            + cli_public_key.len()
            + session_binding.len()
            + sas_digest.len()
            + canonical_request.len()
            + release_nonce.len()
            + 9,
    );
    message.extend_from_slice(SAS_RELEASE_DOMAIN);
    message.push(3);
    message.extend_from_slice(cli_public_key);
    message.extend_from_slice(session_binding);
    message.extend_from_slice(sas_digest);
    message.extend_from_slice(&(canonical_request.len() as u64).to_be_bytes());
    message.extend_from_slice(canonical_request);
    message.extend_from_slice(release_nonce);
    message
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum CliRole {
    Cli,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum PhoneRole {
    Phone,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum OfferKind {
    Offer,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum AnswerKind {
    Answer,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCliOffer {
    #[serde(rename = "v")]
    version: u8,
    from: CliRole,
    seq: u64,
    kind: OfferKind,
    body: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhoneAnswer {
    #[serde(rename = "v")]
    version: u8,
    from: PhoneRole,
    seq: u64,
    kind: AnswerKind,
    body: String,
}

impl PhoneAnswer {
    pub fn decode(text: &str) -> Result<Vec<u8>, String> {
        let Self {
            version,
            from: PhoneRole::Phone,
            seq,
            kind: AnswerKind::Answer,
            body,
        } = serde_json::from_str(text)
            .map_err(|_| "invalid phone signaling envelope".to_string())?;
        if version != SIGNAL_VERSION || seq != 0 {
            return Err("unexpected signaling state".into());
        }
        decode_canonical(&body, "signaling body")
    }
}

fn decode_canonical(value: &str, label: &str) -> Result<Vec<u8>, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| format!("invalid {label} encoding"))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(format!("non-canonical {label} encoding"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_key() -> CliSessionKey {
        CliSessionKey::from_seed(Zeroizing::new([7; 32]))
    }

    #[test]
    fn qr_contains_only_the_public_key() {
        let key = fixed_key();
        assert_eq!(
            key.fragment_value(),
            "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw"
        );
        assert_ne!(key.fragment_value(), URL_SAFE_NO_PAD.encode([7; 32]));
        assert_eq!(key.fragment_value().len(), 43);
        assert_eq!(
            key.rendezvous_id(),
            "MFHH-4Il-dVD-AwsB7c-4kdD25EFZ_aGEczf569GW8U"
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(key.identity_session_binding(b"offer", b"answer")),
            "4onRCvmREapRgbR1UvtUZ_AJ0aCKjDR0Q1fWTksrzJY"
        );
    }

    #[test]
    fn signed_offer_matches_the_browser_vector() {
        let key = fixed_key();
        let offer = key.sign_offer(br#"{"type":"offer"}"#);
        assert_eq!(
            offer.signature,
            "U2k9m3s7XkIf9QF0ShT4TNY-FzYYAfoF4RX9zLBWoo5TYwS5-oblqKqQdK7mQVxO92UWDTidykN6Nm3vXeWPDg"
        );
        assert_eq!(offer.body, URL_SAFE_NO_PAD.encode(br#"{"type":"offer"}"#));
    }

    #[test]
    fn release_signature_is_bound_to_post_ceremony_nonce_and_full_pairing() {
        let key = fixed_key();
        let signature = key.sign_pairing_release(&[1; 32], &[2; 32], b"request", &[3; 32]);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(signature),
            "Iyw_IiGnfBf7isag5c_waK22c6C0vdyERCWS9R5JZZA1GTYmasb6nG5S39sJKA7AR1szG6vp4HaIcNo5mq86Dw"
        );
        let verifying_key = SigningKey::from_bytes(&[7; 32]).verifying_key();
        let message = pairing_release_message(
            &verifying_key.to_bytes(),
            &[1; 32],
            &[2; 32],
            b"request",
            &[3; 32],
        );
        verifying_key
            .verify_strict(&message, &Signature::from_bytes(&signature))
            .unwrap();
    }

    #[test]
    fn release_signature_matches_the_browser_canonical_request_vector() {
        let key = fixed_key();
        let canonical_request = URL_SAFE_NO_PAD.decode(
            "AQAAACABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQAAACACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgAAACADAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwAAAAZkZXBsb3kBAAAABGNyZWQBAAAAAAAAADw",
        ).unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(key.sign_pairing_release(
                &[4; 32],
                &[5; 32],
                &canonical_request,
                &[6; 32],
            )),
            "Z1ZC9SnoBK3gYjh2AYlxTRx9HAfKUsOmRm7sAQhM63Yj3VXjZGHVsQIhFkmsQMJC-_Z0ZZ61zJny3_4EgbsgDQ"
        );
    }

    #[test]
    fn phone_answer_is_strict_and_canonical() {
        assert_eq!(
            PhoneAnswer::decode(
                r#"{"v":3,"from":"phone","seq":0,"kind":"answer","body":"YW5zd2Vy"}"#
            )
            .unwrap(),
            b"answer"
        );
        assert!(PhoneAnswer::decode(
            r#"{"v":2,"from":"phone","seq":0,"kind":"answer","body":"YW5zd2Vy"}"#
        )
        .is_err());
        assert!(PhoneAnswer::decode(
            r#"{"v":3,"from":"phone","seq":0,"kind":"answer","body":"YW5zd2Vy="}"#
        )
        .is_err());
    }

    #[test]
    fn session_binding_changes_with_each_authenticated_input() {
        let key = fixed_key();
        let baseline = key.identity_session_binding(b"offer", b"answer");
        assert_ne!(
            baseline,
            key.identity_session_binding(b"changed", b"answer")
        );
        assert_ne!(baseline, key.identity_session_binding(b"offer", b"changed"));
        assert_ne!(
            baseline,
            CliSessionKey::from_seed(Zeroizing::new([8; 32]))
                .identity_session_binding(b"offer", b"answer")
        );
    }
}
