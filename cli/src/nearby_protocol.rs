//! Authentication for the nearby WebRTC signaling transcript.
//!
//! The QR fragment contains a fresh Ed25519 public key. The CLI signs its
//! complete WebRTC offer, including the DTLS fingerprint, so an approver that
//! scanned the QR can authenticate the peer before it runs WebAuthn. The
//! signaling service receives only a hash-derived rendezvous identifier.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const RID_DOMAIN: &[u8] = b"keytap:rendezvous:v1\0";
const OFFER_SIGNATURE_DOMAIN: &[u8] = b"keytap:signal-offer:v1\0";
const COMPLETION_SIGNATURE_DOMAIN: &[u8] = b"keytap:signal-completion:v1\0";
const IDENTITY_SESSION_DOMAIN: &[u8] = b"keytap:nearby-identity-session:v1\0";
const SIGNAL_VERSION: u8 = 1;

/// The signaling transcript has at most two offers. Keeping the wire sequence
/// behind this enum prevents callers from accepting an arbitrary or stale
/// answer when a direct connection is retried with TURN.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalAttempt {
    Direct,
    TurnRetry,
}

impl SignalAttempt {
    fn sequence(self) -> u64 {
        match self {
            Self::Direct => 0,
            Self::TurnRetry => 1,
        }
    }
}

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

    /// The QR value is public, fixed-width, and 43 base64url characters long.
    pub fn fragment_value(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.public_key)
    }

    pub fn rendezvous_id(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.rendezvous)
    }

    pub fn sign_offer(&self, attempt: SignalAttempt, body: &[u8]) -> SignedCliOffer {
        let sequence = attempt.sequence();
        let signature = SigningKey::from_bytes(&self.seed)
            .sign(&offer_signature_message(attempt, body))
            .to_bytes();
        SignedCliOffer {
            version: SIGNAL_VERSION,
            from: CliRole::Cli,
            seq: sequence,
            kind: OfferKind::Offer,
            body: URL_SAFE_NO_PAD.encode(body),
            signature: URL_SAFE_NO_PAD.encode(signature),
        }
    }

    /// Authenticate the terminal transition independently of the live
    /// signaling socket. This lets the native winner retire a room while the
    /// worker thread is blocked in ICE setup, without exposing a cancellation
    /// capability in the forwarded URL.
    pub fn sign_completion(&self) -> SignedCliCompletion {
        let rendezvous_id = self.rendezvous_id();
        let signature = SigningKey::from_bytes(&self.seed)
            .sign(&completion_signature_message(&rendezvous_id))
            .to_bytes();
        SignedCliCompletion {
            version: SIGNAL_VERSION,
            from: CliRole::Cli,
            kind: CompletionKind::CompletedElsewhere,
            public_key: URL_SAFE_NO_PAD.encode(self.public_key),
            signature: URL_SAFE_NO_PAD.encode(signature),
        }
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

fn offer_signature_message(attempt: SignalAttempt, body: &[u8]) -> Vec<u8> {
    let sequence = attempt.sequence();
    let mut message = Vec::with_capacity(OFFER_SIGNATURE_DOMAIN.len() + body.len() + 25);
    message.extend_from_slice(OFFER_SIGNATURE_DOMAIN);
    message.push(SIGNAL_VERSION);
    message.extend_from_slice(b"cli\0");
    message.extend_from_slice(&sequence.to_be_bytes());
    message.extend_from_slice(b"offer\0");
    message.extend_from_slice(&(body.len() as u64).to_be_bytes());
    message.extend_from_slice(body);
    message
}

fn completion_signature_message(rendezvous_id: &str) -> Vec<u8> {
    let rendezvous_id = rendezvous_id.as_bytes();
    let mut message = Vec::with_capacity(
        COMPLETION_SIGNATURE_DOMAIN.len() + std::mem::size_of::<u32>() + rendezvous_id.len(),
    );
    message.extend_from_slice(COMPLETION_SIGNATURE_DOMAIN);
    message.extend_from_slice(&(rendezvous_id.len() as u32).to_be_bytes());
    message.extend_from_slice(rendezvous_id);
    message
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum CliRole {
    Cli,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum ApproverRole {
    Approver,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum OfferKind {
    Offer,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
enum CompletionKind {
    CompletedElsewhere,
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

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCliCompletion {
    #[serde(rename = "v")]
    version: u8,
    from: CliRole,
    kind: CompletionKind,
    #[serde(rename = "publicKey")]
    public_key: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproverAnswer {
    #[serde(rename = "v")]
    version: u8,
    from: ApproverRole,
    seq: u64,
    kind: AnswerKind,
    body: String,
}

impl ApproverAnswer {
    pub fn decode(text: &str, expected_attempt: SignalAttempt) -> Result<Vec<u8>, String> {
        let Self {
            version,
            from: ApproverRole::Approver,
            seq,
            kind: AnswerKind::Answer,
            body,
        } = serde_json::from_str(text)
            .map_err(|_| "invalid approver signaling envelope".to_string())?;
        if version != SIGNAL_VERSION || seq != expected_attempt.sequence() {
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
            "kEJcshyj36SyT3e3fov2QqlBFMMRquKV0hgfhlqLIeI"
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(key.identity_session_binding(b"offer", b"answer")),
            "MiMn0rHSnUJlFMpIE5sBrbshnEo2rHruqNEWOYp_9pk"
        );
    }

    #[test]
    fn signed_offer_matches_the_browser_vector() {
        let key = fixed_key();
        let offer = key.sign_offer(SignalAttempt::Direct, br#"{"type":"offer"}"#);
        assert_eq!(
            offer.signature,
            "VqMHWBIykqAxKHsKgukMdrF99Jq18DxWgwCvaTCMRYN_nuqUYAuk94tKYrxD_tBaOGRUrl71OeRxlnCCoM8qBw"
        );
        assert_eq!(offer.body, URL_SAFE_NO_PAD.encode(br#"{"type":"offer"}"#));
    }

    #[test]
    fn turn_retry_uses_a_distinct_authenticated_sequence() {
        let key = fixed_key();
        let body = br#"{"type":"offer"}"#;
        let direct = key.sign_offer(SignalAttempt::Direct, body);
        let retry = key.sign_offer(SignalAttempt::TurnRetry, body);

        assert_eq!(direct.seq, 0);
        assert_eq!(retry.seq, 1);
        assert_ne!(direct.signature, retry.signature);
        assert_eq!(
            retry.signature,
            "TgDrSC1EhIxT5cQKGF7JyM4UZpOc7i0TLgYkpYWHbaVFoJXKlvsZaeJoHvAVFyI_8ZAl1EcMragWSbbeHkaGCw"
        );
    }

    #[test]
    fn signed_completion_is_bound_to_the_private_qr_key_and_room() {
        let key = fixed_key();
        assert_eq!(
            serde_json::to_value(key.sign_completion()).unwrap(),
            serde_json::json!({
                "v": 1,
                "from": "cli",
                "kind": "completed-elsewhere",
                "publicKey": "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw",
                "signature": "rAs3D7SL7tb5W4vSv_p8S0sMavfnGvFzCAahbjZ2cOz0Qo31MlsELG2Y0H00_HVh8iA-APlKKMHv9otvGLmiDQ"
            })
        );
    }

    #[test]
    fn approver_answer_is_strict_and_canonical() {
        assert_eq!(
            ApproverAnswer::decode(
                r#"{"v":1,"from":"approver","seq":0,"kind":"answer","body":"YW5zd2Vy"}"#,
                SignalAttempt::Direct,
            )
            .unwrap(),
            b"answer"
        );
        assert!(ApproverAnswer::decode(
            r#"{"v":0,"from":"approver","seq":0,"kind":"answer","body":"YW5zd2Vy"}"#,
            SignalAttempt::Direct,
        )
        .is_err());
        assert!(ApproverAnswer::decode(
            r#"{"v":1,"from":"approver","seq":0,"kind":"answer","body":"YW5zd2Vy="}"#,
            SignalAttempt::Direct,
        )
        .is_err());
        assert!(ApproverAnswer::decode(
            r#"{"v":1,"from":"approver","seq":0,"kind":"answer","body":"YW5zd2Vy"}"#,
            SignalAttempt::TurnRetry,
        )
        .is_err());
        assert_eq!(
            ApproverAnswer::decode(
                r#"{"v":1,"from":"approver","seq":1,"kind":"answer","body":"YW5zd2Vy"}"#,
                SignalAttempt::TurnRetry,
            )
            .unwrap(),
            b"answer"
        );
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
