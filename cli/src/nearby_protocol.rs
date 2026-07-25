//! Authentication for the nearby WebRTC signaling transcript.
//!
//! WebRTC's DTLS data channel protects the key material. This module protects
//! the offer/answer exchange that tells each peer which DTLS certificate it is
//! connecting to. The 32-byte capability is carried only in the QR fragment;
//! the signaling service receives only its SHA-256 rendezvous identifier.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const RID_DOMAIN: &[u8] = b"keytap:rendezvous:v2\0";
const MAC_DOMAIN: &[u8] = b"keytap:signal:v2\0";
const KEY_INFO_PREFIX: &[u8] = b"keytap:signal-key:v2:";
const IDENTITY_BINDING_DOMAIN: &[u8] = b"keytap:nearby-identity-binding:v1\0";
const IDENTITY_SESSION_DOMAIN: &[u8] = b"keytap:nearby-identity-session:v1\0";

type HmacSha256 = Hmac<Sha256>;

/// A one-time capability shared by the CLI and the page through the QR code.
pub struct Capability {
    secret: Zeroizing<[u8; 32]>,
    rendezvous: [u8; 32],
}

impl Capability {
    pub fn generate() -> Self {
        let mut secret = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(secret.as_mut()).expect("failed to generate nearby capability");
        Self::from_secret(secret)
    }

    fn from_secret(secret: Zeroizing<[u8; 32]>) -> Self {
        let mut digest = Sha256::new();
        digest.update(RID_DOMAIN);
        digest.update(secret.as_ref());
        let rendezvous: [u8; 32] = digest.finalize().into();
        Self { secret, rendezvous }
    }

    pub fn fragment_value(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.secret.as_ref())
    }

    pub fn rendezvous_id(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.rendezvous)
    }

    /// Bind passkey identity proofs to this exact one-time QR capability.
    /// The bytes remain local to the two endpoints and are never sent to the
    /// signaling service.
    fn identity_capability_binding(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(IDENTITY_BINDING_DOMAIN);
        digest.update(self.secret.as_ref());
        digest.finalize().into()
    }

    /// Bind a nearby identity proof to the QR capability and both complete
    /// authenticated SDPs, including the DTLS fingerprints and ICE candidates.
    pub fn identity_session_binding(&self, offer: &[u8], answer: &[u8]) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(IDENTITY_SESSION_DOMAIN);
        digest.update(self.identity_capability_binding());
        digest.update((offer.len() as u64).to_be_bytes());
        digest.update(offer);
        digest.update((answer.len() as u64).to_be_bytes());
        digest.update(answer);
        digest.finalize().into()
    }

    fn key_for(&self, role: SignalRole) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(&self.rendezvous), self.secret.as_ref());
        let mut info = KEY_INFO_PREFIX.to_vec();
        info.extend_from_slice(role.as_str().as_bytes());
        let mut key = [0u8; 32];
        hk.expand(&info, &mut key)
            .expect("32-byte HKDF output is valid");
        key
    }

    pub fn sign(
        &self,
        role: SignalRole,
        seq: u64,
        kind: SignalKind,
        body: &[u8],
    ) -> SignalEnvelope {
        let key = Zeroizing::new(self.key_for(role));
        let mut mac = HmacSha256::new_from_slice(key.as_ref()).expect("HMAC accepts 32-byte keys");
        update_mac(&mut mac, role, seq, kind, body);
        SignalEnvelope {
            version: 2,
            from: role,
            seq,
            kind,
            body: URL_SAFE_NO_PAD.encode(body),
            mac: URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()),
        }
    }

    pub fn verify(
        &self,
        envelope: &SignalEnvelope,
        expected_role: SignalRole,
        expected_seq: u64,
        expected_kind: SignalKind,
    ) -> Result<Vec<u8>, String> {
        if envelope.version != 2 {
            return Err("unsupported signaling version".into());
        }
        if envelope.from != expected_role
            || envelope.seq != expected_seq
            || envelope.kind != expected_kind
        {
            return Err("unexpected signaling state".into());
        }
        let body = URL_SAFE_NO_PAD
            .decode(&envelope.body)
            .map_err(|_| "invalid signaling body encoding".to_string())?;
        let tag = URL_SAFE_NO_PAD
            .decode(&envelope.mac)
            .map_err(|_| "invalid signaling MAC encoding".to_string())?;
        let key = Zeroizing::new(self.key_for(expected_role));
        let mut mac = HmacSha256::new_from_slice(key.as_ref()).expect("HMAC accepts 32-byte keys");
        update_mac(&mut mac, expected_role, expected_seq, expected_kind, &body);
        mac.verify_slice(&tag)
            .map_err(|_| "signaling authentication failed".to_string())?;
        Ok(body)
    }
}

fn update_mac(mac: &mut HmacSha256, role: SignalRole, seq: u64, kind: SignalKind, body: &[u8]) {
    mac.update(MAC_DOMAIN);
    mac.update(role.as_str().as_bytes());
    mac.update(&[0]);
    mac.update(&seq.to_be_bytes());
    mac.update(kind.as_str().as_bytes());
    mac.update(&[0]);
    mac.update(&(body.len() as u64).to_be_bytes());
    mac.update(body);
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SignalRole {
    Cli,
    Phone,
}

impl SignalRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Phone => "phone",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SignalKind {
    Offer,
    Answer,
}

impl SignalKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Offer => "offer",
            Self::Answer => "answer",
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SignalEnvelope {
    #[serde(rename = "v")]
    pub version: u8,
    pub from: SignalRole,
    pub seq: u64,
    pub kind: SignalKind,
    pub body: String,
    pub mac: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_capability() -> Capability {
        Capability::from_secret(Zeroizing::new([0x42; 32]))
    }

    #[test]
    fn rendezvous_is_stable_and_does_not_reveal_capability() {
        let capability = fixed_capability();
        assert_eq!(
            capability.fragment_value(),
            "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI"
        );
        assert_eq!(
            capability.rendezvous_id(),
            "6_2qUdwr2cvl5omCEB61Ys263Y1nu0TIjppVQPePcUA"
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(capability.identity_session_binding(b"offer", b"answer")),
            "OCbUzlIS3pmQOcOtyIfbACBko5QZou4dTY4-dsa34Pc"
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(capability.key_for(SignalRole::Cli)),
            "3WRsRm1tbJnFAp8FuyV6TUTOY5ouwjbG_Q26FHhnHTk"
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(capability.key_for(SignalRole::Phone)),
            "m1an7BpTty_CiWJmoO1dgD00qyLh45eSg_uvUJXdLk8"
        );
    }

    #[test]
    fn signal_round_trip_is_role_and_state_bound() {
        let capability = fixed_capability();
        let offer = capability.sign(
            SignalRole::Cli,
            0,
            SignalKind::Offer,
            br#"{"type":"offer"}"#,
        );
        assert_eq!(offer.mac, "FoqM9kpeEx726l8vB0Whib5XjyzePgjWQwBiOFQtZ1E");
        assert_eq!(
            capability
                .verify(&offer, SignalRole::Cli, 0, SignalKind::Offer)
                .unwrap(),
            br#"{"type":"offer"}"#
        );
        assert!(capability
            .verify(&offer, SignalRole::Phone, 0, SignalKind::Offer)
            .is_err());
        assert!(capability
            .verify(&offer, SignalRole::Cli, 1, SignalKind::Offer)
            .is_err());
        assert!(capability
            .verify(&offer, SignalRole::Cli, 0, SignalKind::Answer)
            .is_err());
    }

    #[test]
    fn tampering_fails_authentication() {
        let capability = fixed_capability();
        let mut answer = capability.sign(SignalRole::Phone, 0, SignalKind::Answer, b"answer");
        answer.body = URL_SAFE_NO_PAD.encode(b"different");
        assert!(capability
            .verify(&answer, SignalRole::Phone, 0, SignalKind::Answer)
            .is_err());
    }
}
