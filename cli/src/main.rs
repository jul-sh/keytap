#[cfg(any(target_os = "macos", test))]
mod approval;
mod cli;
mod nearby;
mod nearby_identity;
mod nearby_protocol;
mod nearby_sas;

use cli::{Command, Invocation};
#[cfg(any(target_os = "macos", test))]
use std::sync::mpsc;
#[cfg(target_os = "macos")]
use std::sync::Arc;
use zeroize::Zeroizing;

fn main() {
    let command = match cli::invoke(std::env::args_os()) {
        Invocation::Overview(text) => {
            print!("{text}");
            return;
        }
        Invocation::Command(command) => command,
        Invocation::Clap(error) => error.exit(),
    };

    match command {
        Command::Init { force } => {
            let init_mode = if force {
                nearby_identity::InitMode::Replace
            } else {
                nearby_identity::InitMode::Create
            };
            let pending_init = nearby_identity::prepare_init(init_mode).unwrap_or_else(|error| {
                die(&format!(
                    "could not prepare the local credential record update: {error}"
                ))
            });
            register(pending_init);
        }
        Command::Public { ref name, format } => {
            with_derived_key(name, |raw_key| emit_public_key(raw_key, format, name));
        }
        Command::Reveal { ref name, format } => {
            with_derived_key(name, |raw_key| emit_private_key(raw_key, format));
        }
    }
}

/// Run a passkey ceremony, derive the named key, and hand it to the output
/// formatter. Keytap never stores the derived key.
fn with_derived_key(name: &str, use_key: impl FnOnce(&[u8; 32]) -> Result<(), String>) {
    if let Err(error) = keytap_core::prf_salt_for_name(name) {
        die(&error.to_string());
    }
    let prf_output = authenticate(name);
    let raw_key = derive_key(&prf_output);
    let result = use_key(&raw_key);
    drop(raw_key);
    drop(prf_output);
    if let Err(error) = result {
        die(&error);
    }
}

#[cfg(any(target_os = "macos", test))]
struct NativeAssertion {
    prf_output: Zeroizing<[u8; 32]>,
    credential_id: Vec<u8>,
}

#[cfg(any(target_os = "macos", test))]
impl NativeAssertion {
    fn native(prf_output: Vec<u8>, credential_id: Vec<u8>) -> Result<Self, String> {
        let prf_output = Zeroizing::new(prf_output);
        let actual = prf_output.len();
        if actual != 32 {
            return Err(format!(
                "native passkey provider returned {actual} bytes of PRF output; expected 32"
            ));
        }
        if credential_id.is_empty() || credential_id.len() > 1024 {
            return Err(format!(
                "native passkey provider returned a credential ID of {} bytes; expected 1 to 1024",
                credential_id.len()
            ));
        }
        let mut fixed_prf_output = Zeroizing::new([0u8; 32]);
        fixed_prf_output.copy_from_slice(&prf_output);
        Ok(Self {
            prf_output: fixed_prf_output,
            credential_id,
        })
    }
}

#[cfg(test)]
mod assertion_candidate_tests {
    use super::NativeAssertion;

    #[test]
    fn native_candidate_is_bounded_before_it_can_claim_the_race() {
        assert!(NativeAssertion::native(vec![7; 32], vec![9; 20]).is_ok());
        assert!(NativeAssertion::native(vec![7; 31], vec![9; 20]).is_err());
        assert!(NativeAssertion::native(vec![7; 32], Vec::new()).is_err());
        assert!(NativeAssertion::native(vec![7; 32], vec![9; 1025]).is_err());
    }
}

/// Start nearby approval in the background, then enter the native operation
/// immediately on the calling thread. Native passkey UI must run on the macOS
/// main thread and must never wait for network setup.
#[cfg(any(target_os = "macos", test))]
fn run_native_while_nearby_starts<T: Send + 'static, N>(
    nearby: impl FnOnce() -> T + Send + 'static,
    native: impl FnOnce() -> N,
) -> Result<(N, mpsc::Receiver<T>), String> {
    let (nearby_tx, nearby_rx) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("keytap-nearby-approval".into())
        .spawn(move || {
            nearby_tx.send(nearby()).ok();
        })
        .map_err(|error| format!("could not start nearby approval: {error}"))?;
    Ok((native(), nearby_rx))
}

#[cfg(test)]
mod approval_startup_tests {
    use super::run_native_while_nearby_starts;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn native_starts_while_nearby_setup_is_pending() {
        let (nearby_started_tx, nearby_started_rx) = mpsc::channel();
        let (release_nearby_tx, release_nearby_rx) = mpsc::channel();

        let (native, nearby_rx) = run_native_while_nearby_starts(
            move || {
                nearby_started_tx.send(()).unwrap();
                release_nearby_rx
                    .recv_timeout(Duration::from_secs(5))
                    .is_ok()
            },
            move || {
                nearby_started_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("nearby setup should start in the background");
                7
            },
        )
        .unwrap();

        assert_eq!(native, 7);
        release_nearby_tx
            .send(())
            .expect("native operation should return before nearby setup finishes");
        assert!(nearby_rx.recv_timeout(Duration::from_secs(5)).unwrap());
    }
}

/// Authenticate with a passkey ceremony.
#[cfg(target_os = "macos")]
fn authenticate(name: &str) -> Zeroizing<[u8; 32]> {
    use approval::{ApprovalRace, ApprovalRoute, ClaimOutcome};

    enum NearbyWorkerOutcome {
        Committed(Zeroizing<[u8; 32]>),
        CommitFailed(String),
        Failed(String),
        SupersededByNative,
    }

    let native_authority = nearby_identity::native_assertion_authority()
        .unwrap_or_else(|error| die(&format!("could not load the local passkey record: {error}")));
    let race = Arc::new(ApprovalRace::pending());
    let nearby_cancellation = nearby::NearbyCancellation::new();
    let native_credential = match &native_authority {
        nearby_identity::NativeAssertionAuthority::New(_) => {
            keytap_macos::AssertionCredential::Discoverable
        }
        nearby_identity::NativeAssertionAuthority::Existing(authority) => {
            keytap_macos::AssertionCredential::Constrained {
                credential_id: authority.credential_id().to_vec(),
            }
        }
    };
    let native_prf_salt = keytap_core::prf_salt_for_name(name)
        .expect("authenticate is called only after validating the key name");
    let native_operation =
        keytap_macos::AssertionOperation::new(native_prf_salt, native_credential);
    let native_cancellation = native_operation.cancellation_handle();
    let nearby_name = name.to_string();
    let nearby_race = Arc::clone(&race);
    let worker_cancellation = nearby_cancellation.clone();
    let (native_outcome, nearby_rx) = run_native_while_nearby_starts(
        move || {
            let prepared =
                nearby::prepare_nearby_assertion(&nearby_name, worker_cancellation.clone());
            match prepared {
                Ok(prepared) => match nearby_race.claim(ApprovalRoute::Nearby) {
                    ClaimOutcome::Claimed => {
                        worker_cancellation.finish();
                        native_cancellation.cancel();
                        match prepared.commit() {
                            Ok(assertion) => NearbyWorkerOutcome::Committed(assertion),
                            Err(error) => NearbyWorkerOutcome::CommitFailed(error),
                        }
                    }
                    ClaimOutcome::Lost => {
                        prepared.supersede();
                        NearbyWorkerOutcome::SupersededByNative
                    }
                },
                Err(error) => NearbyWorkerOutcome::Failed(error),
            }
        },
        || native_operation.run(),
    )
    .unwrap_or_else(|error| die(&error));
    let native_failure = match native_outcome {
        keytap_macos::AssertionOutcome::Success {
            prf_output,
            credential_id,
        } => match NativeAssertion::native(prf_output, credential_id) {
            Ok(assertion) => match native_authority.prepare(&assertion.credential_id) {
                Ok(prepared) => match race.claim(ApprovalRoute::Native) {
                    ClaimOutcome::Claimed => {
                        nearby_cancellation.supersede();
                        if let Err(error) = prepared.commit() {
                            drop(assertion);
                            die(&format!(
                                "native approval won, but its local passkey record could not be committed: {error}"
                            ));
                        }
                        note("Approved on this Mac; cancelled nearby approval.");
                        return assertion.prf_output;
                    }
                    ClaimOutcome::Lost => {
                        "native approval finished after nearby approval had already won".to_string()
                    }
                },
                Err(error) => error,
            },
            Err(error) => error,
        },
        keytap_macos::AssertionOutcome::Cancelled => {
            note("Native approval closed; waiting for nearby approval.");
            "native approval was cancelled".to_string()
        }
        keytap_macos::AssertionOutcome::Error(error) => {
            note(&format!(
                "Native approval ended ({error}); waiting for nearby approval."
            ));
            format!("native approval failed: {error}")
        }
    };

    let nearby_outcome = nearby_rx.recv().unwrap_or_else(|_| {
        NearbyWorkerOutcome::Failed("nearby approval stopped unexpectedly".into())
    });
    match nearby_outcome {
        NearbyWorkerOutcome::Committed(prf_output) => {
            note("Approved on the nearby device; closed the native approval prompt.");
            prf_output
        }
        NearbyWorkerOutcome::CommitFailed(error) => die(&format!(
            "nearby approval won but could not be committed: {error}"
        )),
        NearbyWorkerOutcome::Failed(error) => die(&format!(
            "{native_failure}; nearby approval failed: {error}"
        )),
        NearbyWorkerOutcome::SupersededByNative => die(&format!(
            "{native_failure}; nearby approval was superseded without an accepted native result"
        )),
    }
}

#[cfg(not(target_os = "macos"))]
fn authenticate(name: &str) -> Zeroizing<[u8; 32]> {
    nearby::authenticate_nearby(name)
}

fn derive_key(prf_output: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(keytap_core::derive_raw_key(prf_output))
}

#[cfg(target_os = "macos")]
fn register(pending_init: nearby_identity::PendingInit) -> nearby_identity::PersistedInit {
    match keytap_macos::register() {
        keytap_macos::RegistrationOutcome::Success { credential_id } => {
            match pending_init.commit(&credential_id) {
                Ok(registration) => {
                    eprintln!("Passkey registered successfully.");
                    registration
                }
                Err(nearby_identity::InitCommitError::NotPublished(error)) => die(&format!(
                    "passkey was created, but its local credential record could not be stored: {error}"
                )),
                Err(nearby_identity::InitCommitError::PublishedButNotDurable(error)) => {
                    die(&format!(
                        "passkey was created and its local credential record is visible, but durable storage could not be confirmed: {error}. Rerun `keytap init --force` before relying on it"
                    ))
                }
            }
        }
        keytap_macos::RegistrationOutcome::Cancelled => die("cancelled"),
        keytap_macos::RegistrationOutcome::FallbackToNearby { message } => {
            note(&format!(
                "Native passkey registration failed ({message}); continuing with a nearby device."
            ));
            nearby::register_nearby(pending_init)
        }
        keytap_macos::RegistrationOutcome::Indeterminate { message } => die(&format!(
            "native passkey registration ended in an indeterminate state: {message}. A credential may already have been created, so Keytap will not create another one on a nearby device"
        )),
    }
}

#[cfg(not(target_os = "macos"))]
fn register(pending_init: nearby_identity::PendingInit) -> nearby_identity::PersistedInit {
    nearby::register_nearby(pending_init)
}

fn emit_private_key(raw_key: &[u8; 32], format: cli::Format) -> Result<(), String> {
    use std::io::Write;

    let bytes = Zeroizing::new(keytap_core::format_private_key_display(
        raw_key,
        format.into(),
    ));
    let result = std::io::stdout()
        .lock()
        .write_all(&bytes)
        .map_err(|error| format!("could not write private key: {error}"));
    drop(bytes);
    result
}

fn emit_public_key(raw_key: &[u8; 32], format: cli::Format, name: &str) -> Result<(), String> {
    use std::io::Write;

    let output = keytap_core::format_public_key_display(raw_key, format.public_key_format(name));
    std::io::stdout()
        .lock()
        .write_all(output.as_bytes())
        .map_err(|error| format!("could not write public key: {error}"))
}

pub(crate) fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

/// A stderr line that must never take the process down. Once a command's
/// output is on stdout, even a closed stderr may not turn success into a
/// panic — everything printed after that point goes through here.
pub(crate) fn note(line: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "{line}");
}
