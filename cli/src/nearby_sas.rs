//! Human-verifiable binding for a first nearby connection.
//!
//! The CLI commits to fresh randomness before the approver contributes its own.
//! Only then does the CLI reveal its nonce. This ordering prevents a peer that
//! controls two different WebRTC sessions from grinding either transcript
//! until the short authentication strings collide.

use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{BufRead, Write};
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;
use zeroize::Zeroizing;

const COMMIT_DOMAIN: &[u8] = b"keytap:nearby-sas-commit:v1\0";
const DIGEST_DOMAIN: &[u8] = b"keytap:nearby-sas-digest:v1\0";
const CONTEXT_DOMAIN: &[u8] = b"keytap:nearby-sas-context:v1\0";
const CLI_ROLE: &[u8] = b"cli\0";
const APPROVER_ROLE: &[u8] = b"approver\0";
const WORDS: &str = include_str!("../../web/nearby-sas-words.txt");
const WORD_COUNT: usize = 2048;
const TERMINAL_CONFIRM_TIMEOUT: Duration = Duration::from_secs(120);
#[cfg(unix)]
const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone, Copy)]
pub struct Context([u8; 32]);

/// The first, committed state of the CLI side of the SAS exchange.
pub struct InitiatorCommitment {
    context: [u8; 32],
    cli_nonce: Zeroizing<[u8; 32]>,
    commitment: [u8; 32],
}

/// The state reached only after both peers have fixed their nonce commitments.
pub struct AwaitingApproverReveal {
    context: [u8; 32],
    cli_nonce: Zeroizing<[u8; 32]>,
    cli_commitment: [u8; 32],
    approver_commitment: [u8; 32],
}

/// The state reached only after the approver's commitment has been opened.
pub struct Comparison {
    digest: [u8; 32],
    phrase: Phrase,
}

/// The CLI has received the WebAuthn result but has not accepted it.
/// Only the terminal can turn this state into a confirmed comparison.
pub struct BufferedResultComparison(Comparison);

/// This state can only be produced by an affirmative terminal answer.
pub struct ConfirmedComparison {
    digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Phrase {
    first: u16,
    second: u16,
}

impl InitiatorCommitment {
    pub fn generate(context: Context) -> Result<Self, String> {
        let mut cli_nonce = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(cli_nonce.as_mut())
            .map_err(|error| format!("failed to generate pairing randomness: {error}"))?;
        Ok(Self::from_nonce(context.0, cli_nonce))
    }

    fn from_nonce(context: [u8; 32], cli_nonce: Zeroizing<[u8; 32]>) -> Self {
        let commitment = commitment_digest(CLI_ROLE, &context, &cli_nonce);
        Self {
            context,
            cli_nonce,
            commitment,
        }
    }

    pub fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }

    pub fn accept_approver_commitment(
        self,
        approver_commitment: [u8; 32],
    ) -> AwaitingApproverReveal {
        AwaitingApproverReveal {
            context: self.context,
            cli_nonce: self.cli_nonce,
            cli_commitment: self.commitment,
            approver_commitment,
        }
    }
}

impl Context {
    /// Freeze both the WebRTC transcript and the exact request that the approver
    /// will execute before the CLI buffers its result for terminal confirmation.
    pub fn bind(session_binding: &[u8; 32], canonical_request: &[u8]) -> Self {
        let mut digest = Sha256::new();
        digest.update(CONTEXT_DOMAIN);
        digest.update(session_binding);
        digest.update((canonical_request.len() as u64).to_be_bytes());
        digest.update(canonical_request);
        Self(digest.finalize().into())
    }

    #[cfg(test)]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AwaitingApproverReveal {
    pub fn cli_nonce(&self) -> &[u8; 32] {
        &self.cli_nonce
    }

    pub fn accept_approver_nonce(self, approver_nonce: [u8; 32]) -> Result<Comparison, String> {
        let opened = commitment_digest(APPROVER_ROLE, &self.context, &approver_nonce);
        if !constant_time_equal(&opened, &self.approver_commitment) {
            return Err("the nearby device did not open its pairing commitment".to_string());
        }
        let digest = sas_digest(
            &self.context,
            &self.cli_commitment,
            &self.approver_commitment,
            &self.cli_nonce,
            &approver_nonce,
        );
        Ok(Comparison {
            digest,
            phrase: phrase_from_digest(&digest),
        })
    }
}

impl Comparison {
    pub fn phrase(&self) -> Phrase {
        self.phrase
    }

    pub fn result_buffered(self) -> BufferedResultComparison {
        BufferedResultComparison(self)
    }
}

impl BufferedResultComparison {
    pub fn confirm_with_tty(self) -> Result<ConfirmedComparison, String> {
        self.confirm_with_tty_while(|| Ok(()))
    }

    /// Wait for local SAS confirmation while allowing a competing approval
    /// route to supersede this ceremony. The callback is polled even when the
    /// terminal has no input, so cancellation never waits for the full prompt
    /// timeout.
    pub fn confirm_with_tty_while(
        self,
        mut ensure_active: impl FnMut() -> Result<(), String>,
    ) -> Result<ConfirmedComparison, String> {
        #[cfg(unix)]
        {
            ensure_active()?;
            let mut terminal = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/tty")
                .map_err(|_| {
                    "pairing requires an interactive terminal; no key was accepted".to_string()
                })?;
            let reader_handle = terminal
                .try_clone()
                .map_err(|error| format!("could not read pairing confirmation: {error}"))?;
            discard_pending_terminal_input(&reader_handle)?;
            self.write_prompt(&mut terminal)?;
            wait_for_terminal_input_while(
                &reader_handle,
                TERMINAL_CONFIRM_TIMEOUT,
                &mut ensure_active,
            )?;
            ensure_active()?;
            let mut reader = std::io::BufReader::new(reader_handle);
            self.read_confirmation(&mut reader)
        }
        #[cfg(not(unix))]
        {
            let _ = &mut ensure_active;
            Err("pairing confirmation is not supported on this platform".to_string())
        }
    }

    #[cfg(test)]
    fn confirm_with_io(
        self,
        reader: &mut impl BufRead,
        writer: &mut impl Write,
    ) -> Result<ConfirmedComparison, String> {
        self.write_prompt(writer)?;
        self.read_confirmation(reader)
    }

    fn write_prompt(&self, writer: &mut impl Write) -> Result<(), String> {
        write!(
            writer,
            "\nResult received but not accepted. Did your nearby device show exactly \"{}\"? [y/N, 2 minute timeout] ",
            self.0.phrase
        )
        .map_err(|error| format!("could not write pairing confirmation: {error}"))?;
        writer
            .flush()
            .map_err(|error| format!("could not show pairing confirmation: {error}"))
    }

    fn read_confirmation(self, reader: &mut impl BufRead) -> Result<ConfirmedComparison, String> {
        let mut answer = String::new();
        reader
            .read_line(&mut answer)
            .map_err(|error| format!("could not read pairing confirmation: {error}"))?;
        match answer.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => Ok(ConfirmedComparison {
                digest: self.0.digest,
            }),
            _ => Err("pairing words were not confirmed; no key was accepted".to_string()),
        }
    }
}

#[cfg(unix)]
fn discard_pending_terminal_input(file: &std::fs::File) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    loop {
        let result = unsafe { libc::tcflush(file.as_raw_fd(), libc::TCIFLUSH) };
        if result == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(format!(
                "could not prepare pairing confirmation: {error}; no key was accepted"
            ));
        }
    }
}

#[cfg(unix)]
fn wait_for_terminal_input_while(
    file: &std::fs::File,
    timeout: Duration,
    ensure_active: &mut impl FnMut() -> Result<(), String>,
) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    let mut descriptor = libc::pollfd {
        fd: file.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let deadline = Instant::now() + timeout;
    loop {
        ensure_active()?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| "pairing confirmation timed out; no key was accepted".to_string())?;
        let interval = remaining.min(CANCELLATION_POLL_INTERVAL);
        let timeout_ms = i32::try_from(interval.as_millis().max(1)).unwrap_or(i32::MAX);
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if result > 0 {
            return Ok(());
        }
        if result == 0 {
            continue;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(format!("could not wait for pairing confirmation: {error}"));
        }
    }
}

impl ConfirmedComparison {
    /// The full digest, rather than its 22-bit display, is bound into the
    /// passkey-derived identity signature after the user confirms the phrase.
    pub fn binding_digest(&self) -> &[u8; 32] {
        &self.digest
    }

    #[cfg(test)]
    pub(crate) fn from_digest_for_test(digest: [u8; 32]) -> Self {
        Self { digest }
    }
}

impl fmt::Display for Phrase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {}",
            word_at(usize::from(self.first)),
            word_at(usize::from(self.second))
        )
    }
}

fn commitment_digest(role: &[u8], context: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(COMMIT_DOMAIN);
    digest.update(role);
    digest.update(context);
    digest.update(nonce);
    digest.finalize().into()
}

fn sas_digest(
    context: &[u8; 32],
    cli_commitment: &[u8; 32],
    approver_commitment: &[u8; 32],
    cli_nonce: &[u8; 32],
    approver_nonce: &[u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(DIGEST_DOMAIN);
    digest.update(context);
    digest.update(cli_commitment);
    digest.update(approver_commitment);
    digest.update(cli_nonce);
    digest.update(approver_nonce);
    digest.finalize().into()
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(left.ct_eq(right))
}

fn phrase_from_digest(digest: &[u8; 32]) -> Phrase {
    // BIP-39 has exactly 2^11 words. Take the first 22 digest bits without
    // modulo reduction, so every two-word phrase is equally likely.
    let first = (u16::from(digest[0]) << 3) | u16::from(digest[1] >> 5);
    let second = (u16::from(digest[1] & 0x1f) << 6) | u16::from(digest[2] >> 2);
    Phrase { first, second }
}

fn word_at(index: usize) -> &'static str {
    debug_assert!(index < WORD_COUNT);
    WORDS
        .split_ascii_whitespace()
        .nth(index)
        .expect("the embedded nearby SAS word list has 2,048 entries")
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use std::collections::HashSet;

    #[cfg(unix)]
    fn pseudo_terminal() -> (std::fs::File, std::fs::File) {
        use std::os::fd::FromRawFd;

        let mut master_fd = -1;
        let mut slave_fd = -1;
        let result = unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(
            result,
            0,
            "openpty failed: {}",
            std::io::Error::last_os_error()
        );
        assert!(master_fd >= 0);
        assert!(slave_fd >= 0);
        unsafe {
            (
                std::fs::File::from_raw_fd(master_fd),
                std::fs::File::from_raw_fd(slave_fd),
            )
        }
    }

    #[test]
    fn word_list_has_the_bip39_shape() {
        let words: Vec<_> = WORDS.split_ascii_whitespace().collect();
        assert_eq!(words.len(), WORD_COUNT);
        assert_eq!(
            words.iter().copied().collect::<HashSet<_>>().len(),
            WORD_COUNT
        );
        assert!(words.iter().all(|word| {
            !word.is_empty()
                && word.len() <= 8
                && word.bytes().all(|byte| byte.is_ascii_lowercase())
        }));
        assert_eq!(words.first(), Some(&"abandon"));
        assert_eq!(words.last(), Some(&"zoo"));
        assert_eq!(
            hex::encode(Sha256::digest(WORDS.as_bytes())),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
    }

    #[test]
    fn fixed_commit_reveal_vector() {
        let pending = InitiatorCommitment::from_nonce([0x42; 32], Zeroizing::new([0x11; 32]));
        assert_eq!(
            URL_SAFE_NO_PAD.encode(pending.commitment()),
            "cvH8dRwfyO39Y_o_PCBXIQPtJ2CgNAF2dCLBJs4YldA"
        );
        let approver_commitment = commitment_digest(APPROVER_ROLE, &[0x42; 32], &[0x22; 32]);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(approver_commitment),
            "uGxkhyyB5CuiWLzkx3yVbtuDET2YFspXyFU24H71YLg"
        );
        let reveal = pending.accept_approver_commitment(approver_commitment);
        assert_eq!(reveal.cli_nonce(), &[0x11; 32]);
        let comparison = reveal.accept_approver_nonce([0x22; 32]).unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(comparison.digest),
            "IAUUgyGRkm-JJ34IUOnGhGCkfqDHlzCZxNtMQFsVQ8w"
        );
        assert_eq!(comparison.phrase().to_string(), "cactus chunk");
    }

    #[test]
    fn the_session_and_both_nonces_change_the_phrase_binding() {
        let baseline = sas_digest(&[1; 32], &[2; 32], &[3; 32], &[4; 32], &[5; 32]);
        assert_ne!(
            baseline,
            sas_digest(&[9; 32], &[2; 32], &[3; 32], &[4; 32], &[5; 32])
        );
        assert_ne!(
            baseline,
            sas_digest(&[1; 32], &[9; 32], &[3; 32], &[4; 32], &[5; 32])
        );
        assert_ne!(
            baseline,
            sas_digest(&[1; 32], &[2; 32], &[9; 32], &[4; 32], &[5; 32])
        );
        assert_ne!(
            baseline,
            sas_digest(&[1; 32], &[2; 32], &[3; 32], &[9; 32], &[5; 32])
        );
        assert_ne!(
            baseline,
            sas_digest(&[1; 32], &[2; 32], &[3; 32], &[4; 32], &[9; 32])
        );
    }

    #[test]
    fn a_false_approver_opening_is_rejected() {
        let pending = InitiatorCommitment::from_nonce([1; 32], Zeroizing::new([2; 32]));
        let reveal = pending.accept_approver_commitment([3; 32]);
        assert!(reveal.accept_approver_nonce([4; 32]).is_err());
    }

    #[test]
    fn local_confirmation_fails_closed() {
        let comparison = Comparison {
            digest: [7; 32],
            phrase: Phrase {
                first: 0,
                second: 1,
            },
        }
        .result_buffered();
        let mut output = Vec::new();
        assert!(comparison
            .confirm_with_io(&mut "no\n".as_bytes(), &mut output)
            .is_err());
        assert!(String::from_utf8(output)
            .unwrap()
            .contains("abandon ability"));
    }

    #[test]
    fn affirmative_local_confirmation_releases_the_full_binding() {
        let comparison = Comparison {
            digest: [7; 32],
            phrase: Phrase {
                first: 0,
                second: 1,
            },
        }
        .result_buffered();
        let confirmed = comparison
            .confirm_with_io(&mut "yes\n".as_bytes(), &mut Vec::new())
            .unwrap();
        assert_eq!(confirmed.binding_digest(), &[7; 32]);
    }

    #[cfg(unix)]
    #[test]
    fn pending_terminal_input_is_discarded_before_confirmation() {
        use std::io::Write as _;
        use std::os::fd::AsRawFd;

        let (mut master, slave) = pseudo_terminal();
        master.write_all(b"yes\n").unwrap();
        wait_for_terminal_input_while(&slave, Duration::from_secs(1), &mut || Ok(())).unwrap();

        discard_pending_terminal_input(&slave).unwrap();

        let mut descriptor = libc::pollfd {
            fd: slave.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
        assert_eq!(result, 0, "discarded confirmation remained readable");
    }

    #[cfg(unix)]
    #[test]
    fn terminal_wait_observes_competing_approval_cancellation() {
        let (_master, slave) = pseudo_terminal();
        let started = Instant::now();
        let mut checks = 0;
        let error = wait_for_terminal_input_while(&slave, Duration::from_secs(5), &mut || {
            checks += 1;
            match checks {
                1 => Ok(()),
                _ => Err("nearby approval was superseded".to_string()),
            }
        })
        .unwrap_err();
        assert_eq!(error, "nearby approval was superseded");
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[cfg(unix)]
    #[test]
    fn terminal_flush_failure_is_rejected() {
        let not_a_terminal = std::fs::File::open("/dev/null").unwrap();
        let error = discard_pending_terminal_input(&not_a_terminal).unwrap_err();
        assert!(error.contains("no key was accepted"));
    }
}
