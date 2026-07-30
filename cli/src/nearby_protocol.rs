//! One-use authenticated channel for nearby approval.
//!
//! The invitation carries a fresh P-256 public key in its URL fragment. The
//! matching private key never leaves the CLI. A nearby browser contributes an
//! ephemeral key, then both sides derive directional AES-GCM keys. The relay
//! sees only public handshake material and ciphertext.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::{aead, agreement, hkdf, rand};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const ROOM_DOMAIN: &[u8] = b"keytap:relay-room:v1\0";
const SESSION_DOMAIN: &[u8] = b"keytap:relay-session:v1\0";
const KEY_DOMAIN: &[u8] = b"keytap:relay-key:v1\0";
const BOX_DOMAIN: &[u8] = b"keytap:relay-box:v1\0";
const CLI_KEY_INFO: &[u8] = b"keytap:relay-key:v1\0cli-to-approver";
const APPROVER_KEY_INFO: &[u8] = b"keytap:relay-key:v1\0approver-to-cli";
const CLI_DIRECTION: [u8; 4] = *b"CLI\0";
const APPROVER_DIRECTION: [u8; 4] = *b"APP\0";
const HELLO_TYPE: u8 = 1;
const BOX_TYPE: u8 = 2;
const P256_PUBLIC_KEY_LEN: usize = 65;
const HELLO_LEN: usize = 1 + P256_PUBLIC_KEY_LEN;
const BOX_HEADER_LEN: usize = 1 + 8;
const TAG_LEN: usize = 16;

/// A fresh CLI key whose public half is the complete invitation capability.
pub struct CliHandshake {
    private_key: agreement::EphemeralPrivateKey,
    public_key: [u8; P256_PUBLIC_KEY_LEN],
}

impl CliHandshake {
    pub fn generate() -> Result<Self, String> {
        let rng = rand::SystemRandom::new();
        let private_key = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
            .map_err(|_| "could not generate the nearby invitation key".to_string())?;
        let public_key: [u8; P256_PUBLIC_KEY_LEN] = private_key
            .compute_public_key()
            .map_err(|_| "could not derive the nearby invitation key".to_string())?
            .as_ref()
            .try_into()
            .map_err(|_| "nearby invitation key had an invalid length".to_string())?;
        Ok(Self {
            private_key,
            public_key,
        })
    }

    pub fn fragment_value(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.public_key)
    }

    pub fn room_id(&self) -> String {
        URL_SAFE_NO_PAD.encode(room_id(&self.public_key))
    }

    /// Consume the one-use private key and authenticate the browser's exact
    /// binary hello before constructing the encrypted channel.
    pub fn accept(self, hello: &[u8]) -> Result<SecureChannel, String> {
        let approver_public = parse_approver_hello(hello)?;
        let session_binding = session_binding(&self.public_key, &approver_public);
        let peer = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, approver_public);
        agreement::agree_ephemeral(self.private_key, &peer, |shared| {
            SecureChannel::from_shared(shared, session_binding, ChannelRole::Cli)
        })
        .map_err(|_| "nearby device sent an invalid P-256 public key".to_string())
    }

    #[cfg(test)]
    fn public_key(&self) -> [u8; P256_PUBLIC_KEY_LEN] {
        self.public_key
    }
}

/// Directional authenticated encryption plus exact receive sequencing.
pub struct SecureChannel {
    sending_key: aead::LessSafeKey,
    receiving_key: aead::LessSafeKey,
    send_direction: [u8; 4],
    receive_direction: [u8; 4],
    send_sequence: u64,
    receive_sequence: u64,
    session_binding: [u8; 32],
}

#[derive(Clone, Copy)]
enum ChannelRole {
    Cli,
    #[cfg(test)]
    Approver,
}

impl SecureChannel {
    fn from_shared(shared: &[u8], session_binding: [u8; 32], role: ChannelRole) -> Self {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &session_binding);
        let secret = salt.extract(shared);
        let cli_key = expand_key(&secret, CLI_KEY_INFO);
        let approver_key = expand_key(&secret, APPROVER_KEY_INFO);
        let (sending_key, receiving_key, send_direction, receive_direction) = match role {
            ChannelRole::Cli => (
                aead_key(cli_key),
                aead_key(approver_key),
                CLI_DIRECTION,
                APPROVER_DIRECTION,
            ),
            #[cfg(test)]
            ChannelRole::Approver => (
                aead_key(approver_key),
                aead_key(cli_key),
                APPROVER_DIRECTION,
                CLI_DIRECTION,
            ),
        };
        Self {
            sending_key,
            receiving_key,
            send_direction,
            receive_direction,
            send_sequence: 0,
            receive_sequence: 0,
            session_binding,
        }
    }

    pub fn session_binding(&self) -> &[u8; 32] {
        &self.session_binding
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let sequence = self.send_sequence;
        let mut ciphertext = plaintext.to_vec();
        self.sending_key
            .seal_in_place_append_tag(
                nonce(self.send_direction, sequence),
                aead::Aad::from(aad(&self.session_binding, self.send_direction, sequence)),
                &mut ciphertext,
            )
            .map_err(|_| "could not encrypt the nearby message".to_string())?;
        self.send_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| "nearby send sequence exhausted".to_string())?;

        let mut frame = Vec::with_capacity(BOX_HEADER_LEN + ciphertext.len());
        frame.push(BOX_TYPE);
        frame.extend_from_slice(&sequence.to_be_bytes());
        frame.extend_from_slice(&ciphertext);
        Ok(frame)
    }

    pub fn open(&mut self, frame: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        if frame.len() < BOX_HEADER_LEN + TAG_LEN || frame.first() != Some(&BOX_TYPE) {
            return Err("nearby device sent an invalid encrypted frame".to_string());
        }
        let sequence = u64::from_be_bytes(
            frame[1..BOX_HEADER_LEN]
                .try_into()
                .expect("box sequence has a fixed width"),
        );
        if sequence != self.receive_sequence {
            return Err("nearby device sent an out-of-sequence frame".to_string());
        }

        let mut plaintext = Zeroizing::new(frame[BOX_HEADER_LEN..].to_vec());
        let opened_len = self
            .receiving_key
            .open_in_place(
                nonce(self.receive_direction, sequence),
                aead::Aad::from(aad(&self.session_binding, self.receive_direction, sequence)),
                plaintext.as_mut(),
            )
            .map_err(|_| "nearby message authentication failed".to_string())?
            .len();
        plaintext.truncate(opened_len);
        self.receive_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| "nearby receive sequence exhausted".to_string())?;
        Ok(plaintext)
    }
}

fn parse_approver_hello(hello: &[u8]) -> Result<[u8; P256_PUBLIC_KEY_LEN], String> {
    if hello.len() != HELLO_LEN || hello.first() != Some(&HELLO_TYPE) {
        return Err("nearby device sent an invalid channel hello".to_string());
    }
    hello[1..]
        .try_into()
        .map_err(|_| "nearby device sent an invalid channel hello".to_string())
}

fn room_id(public_key: &[u8; P256_PUBLIC_KEY_LEN]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(ROOM_DOMAIN);
    digest.update(public_key);
    digest.finalize().into()
}

fn session_binding(
    cli_public: &[u8; P256_PUBLIC_KEY_LEN],
    approver_public: &[u8; P256_PUBLIC_KEY_LEN],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(SESSION_DOMAIN);
    digest.update(cli_public);
    digest.update(approver_public);
    digest.finalize().into()
}

fn expand_key(secret: &hkdf::Prk, info: &'static [u8]) -> [u8; 32] {
    debug_assert!(info.starts_with(KEY_DOMAIN));
    let info = [info];
    let output = secret
        .expand(&info, hkdf::HKDF_SHA256)
        .expect("SHA-256 HKDF accepts a 32-byte output");
    let mut key = [0u8; 32];
    output
        .fill(&mut key)
        .expect("SHA-256 HKDF fills its declared output");
    key
}

fn aead_key(key: [u8; 32]) -> aead::LessSafeKey {
    let key = Zeroizing::new(key);
    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, key.as_ref())
        .expect("AES-256-GCM accepts a 32-byte key");
    aead::LessSafeKey::new(unbound)
}

fn nonce(direction: [u8; 4], sequence: u64) -> aead::Nonce {
    let mut value = [0u8; 12];
    value[..4].copy_from_slice(&direction);
    value[4..].copy_from_slice(&sequence.to_be_bytes());
    aead::Nonce::assume_unique_for_key(value)
}

fn aad(session: &[u8; 32], direction: [u8; 4], sequence: u64) -> Vec<u8> {
    let mut value = Vec::with_capacity(BOX_DOMAIN.len() + 32 + 4 + 8);
    value.extend_from_slice(BOX_DOMAIN);
    value.extend_from_slice(session);
    value.extend_from_slice(&direction);
    value.extend_from_slice(&sequence.to_be_bytes());
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(deprecated)]
    fn fixed_private(byte: u8) -> agreement::EphemeralPrivateKey {
        let rng = ring::test::rand::FixedByteRandom { byte };
        agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap()
    }

    fn channel_pair() -> (SecureChannel, SecureChannel) {
        let cli = CliHandshake::generate().unwrap();
        let cli_public = cli.public_key();
        let rng = rand::SystemRandom::new();
        let approver_private =
            agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
        let approver_public: [u8; P256_PUBLIC_KEY_LEN] = approver_private
            .compute_public_key()
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap();
        let mut hello = vec![HELLO_TYPE];
        hello.extend_from_slice(&approver_public);
        let cli_channel = cli.accept(&hello).unwrap();
        let binding = session_binding(&cli_public, &approver_public);
        let peer = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, cli_public);
        let approver_channel = agreement::agree_ephemeral(approver_private, &peer, |shared| {
            SecureChannel::from_shared(shared, binding, ChannelRole::Approver)
        })
        .unwrap();
        (cli_channel, approver_channel)
    }

    #[test]
    fn invitation_is_one_canonical_p256_key() {
        let invitation = CliHandshake::generate().unwrap();
        assert_eq!(invitation.fragment_value().len(), 87);
        assert_eq!(invitation.room_id().len(), 43);
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(invitation.fragment_value())
                .unwrap()
                .len(),
            65
        );
    }

    #[test]
    fn directional_channels_round_trip() {
        let (mut cli, mut approver) = channel_pair();
        assert_eq!(cli.session_binding(), approver.session_binding());
        let request = cli.seal(br#"{"type":"request"}"#).unwrap();
        assert_eq!(
            approver.open(&request).unwrap().as_slice(),
            br#"{"type":"request"}"#
        );
        let result = approver.seal(br#"{"type":"done"}"#).unwrap();
        assert_eq!(cli.open(&result).unwrap().as_slice(), br#"{"type":"done"}"#);
    }

    #[test]
    fn tamper_replay_and_reflection_fail_closed() {
        let (mut cli, mut approver) = channel_pair();
        let frame = cli.seal(b"secret").unwrap();

        let mut tampered = frame.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(approver.open(&tampered).is_err());
        assert_eq!(approver.open(&frame).unwrap().as_slice(), b"secret");
        assert!(approver.open(&frame).is_err());

        let reflected = cli.seal(b"reflection").unwrap();
        assert!(cli.open(&reflected).is_err());
    }

    #[test]
    fn malformed_hello_and_box_are_rejected() {
        let invitation = CliHandshake::generate().unwrap();
        assert!(invitation.accept(&[HELLO_TYPE; HELLO_LEN]).is_err());

        let (mut cli, _) = channel_pair();
        assert!(cli.open(&[]).is_err());
        assert!(cli.open(&[BOX_TYPE; BOX_HEADER_LEN + TAG_LEN - 1]).is_err());
    }

    #[test]
    fn matches_the_browser_interoperability_vector() {
        let cli_private = fixed_private(7);
        let cli_public: [u8; P256_PUBLIC_KEY_LEN] = cli_private
            .compute_public_key()
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(cli_public),
            "BB4YUy_UdUwC8wQdnHXOszuD_9gax85P6ILMscmLxYlupGwxHE4v9A3ZajZT5uRURdMt_khuztdcepDGoYiBwKM"
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(room_id(&cli_public)),
            "SpUsZq6Fzt8RE_36Ef2mVzI4Y6gT4XRyOJj0W0S43_M"
        );

        let approver_private = fixed_private(9);
        let approver_public: [u8; P256_PUBLIC_KEY_LEN] = approver_private
            .compute_public_key()
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(approver_public),
            "BHE1-k_ZOgnc6Yu_aBtL_PUOfA1jVOYq-wv_KjQpYXhl7UwfAt25Aj7lalV-UV1qncZsEfIglg3llDNN9Yh3ZyQ"
        );
        let binding = session_binding(&cli_public, &approver_public);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(binding),
            "mPxIFAKQTkV1mFPcdhqB-qELkQBiePe_-SGpFTx1-xo"
        );

        let approver_peer =
            agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, approver_public);
        let mut cli = agreement::agree_ephemeral(cli_private, &approver_peer, |shared| {
            SecureChannel::from_shared(shared, binding, ChannelRole::Cli)
        })
        .unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(cli.seal(br#"{"type":"request"}"#).unwrap()),
            "AgAAAAAAAAAAi10Zvu3ekrWgXmty1zwZ_DhOTOvzwmXUK2Eb01LQhY5jHw"
        );

        let cli_peer = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, cli_public);
        let mut approver = agreement::agree_ephemeral(approver_private, &cli_peer, |shared| {
            SecureChannel::from_shared(shared, binding, ChannelRole::Approver)
        })
        .unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(
                approver
                    .seal(br#"{"type":"sas-approver-confirmed"}"#)
                    .unwrap()
            ),
            "AgAAAAAAAAAARQQEm6770h33ni16cUYW5G6LIrHmD8P1B66BkEPqxiZeALa2Rpwd9X7hXiuaKOfNPQ"
        );
    }
}
