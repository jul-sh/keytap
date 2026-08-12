#[cfg(any(target_os = "macos", test))]
mod approval;
mod encrypt;
mod env_keys;
mod keychain;
mod nearby;
mod nearby_identity;
mod nearby_protocol;
mod nearby_sas;
mod remember;

use keytap_cli_spec::{Command, Invocation};
#[cfg(any(target_os = "macos", test))]
use std::sync::mpsc;
#[cfg(target_os = "macos")]
use std::sync::Arc;
use zeroize::Zeroizing;

fn main() {
    // The whole CLI surface — clap definitions, the single-screen overview,
    // the bare-`remember` special case — lives in keytap-cli-spec, shared
    // with the web terminal's wasm build. This binary only executes.
    let cli = match keytap_cli_spec::invoke(std::env::args_os()) {
        Invocation::Overview(text) => {
            print!("{text}");
            return;
        }
        Invocation::Misuse(msg) => die(&msg),
        Invocation::Parsed(Err(e)) => e.exit(),
        Invocation::Parsed(Ok(cli)) => cli,
    };

    match cli.command {
        Command::Init { force } => {
            guard_ceremony("init", cli.prompt);
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
            remember::after_init();
        }
        Command::Public { ref name, format } => {
            with_derived_key(name, cli.prompt, |raw_key| {
                emit_public_key(raw_key, format, name)
            });
        }
        Command::Reveal { ref name, format } => {
            with_derived_key(name, cli.prompt, |raw_key| {
                emit_private_key(raw_key, format)
            });
        }
        Command::Encrypt {
            ref name,
            ref recipients,
            ref recipients_file,
            no_self,
        } => {
            with_derived_key(name, cli.prompt, |raw_key| {
                encrypt::encrypt(raw_key, recipients, recipients_file, !no_self)
            });
        }
        Command::Decrypt { ref name } => {
            with_derived_key(name, cli.prompt, encrypt::decrypt);
        }
        Command::Remember { ref name } => {
            // Fail fast on invalid names or unavailable local storage before
            // asking either device to perform a ceremony.
            if let Err(e) = keytap_core::prf_salt_for_name(name) {
                die(&e.to_string());
            }
            guard_ceremony("remember", cli.prompt);
            let mut target = remember::write_target();
            let assertion = authenticate(name, nearby::StoragePolicy::Remember);
            match assertion.into_remember_disposition() {
                RememberDisposition::StoreLocally(assertion) => {
                    let raw_key = derive_key(&assertion.prf_output);
                    remember::remember(&mut target, name, &assertion.credential_id, &raw_key);
                }
                RememberDisposition::AlreadyStored => {}
                RememberDisposition::Unavailable => {
                    die("the nearby assertion succeeded, but this key could not be remembered")
                }
            }
        }
        Command::Forget { ref name, all } => {
            if all {
                remember::forget_all();
            } else {
                remember::forget(name);
            }
        }
        Command::Remembered => remember::remembered(),
    }
}

/// Resolve the raw key for `name` and hand it to `use_key`: first the
/// environment (`$KEYTAP_KEY_<NAME>`, the CI path), then a key remembered on
/// this machine, then a fresh ceremony. Under `$CI`, a fresh ceremony is
/// refused unless `--prompt` asks for it.
///
/// The named derived key is retained only when the user explicitly chooses to
/// remember it. First approval may still establish the local credential record
/// used to constrain later passkey ceremonies.
fn with_derived_key(name: &str, allow_prompt: bool, use_key: impl FnOnce(&[u8])) {
    if let Err(error) = keytap_core::prf_salt_for_name(name) {
        die(&error.to_string());
    }
    if let Some(raw_key) = env_keys::resolve(name) {
        return use_key(&raw_key);
    }
    if let Some(raw_key) = remember::lookup(name) {
        return use_key(&raw_key);
    }
    if in_ci() && !allow_prompt {
        die(&format!(
            "$CI is set and there is no key for '{name}': refusing to start a passkey ceremony \
             (it would hang this job). Set ${var} to the output of \
             `keytap reveal {name} --as age`, or pass --prompt to run the ceremony anyway \
             (the QR code and approval URL land in the job log).",
            var = env_keys::var_name(name)
        ));
    }
    let assertion = authenticate(name, nearby::StoragePolicy::Choose);
    let assertion = match assertion {
        Assertion::Native(assertion) | Assertion::Nearby { assertion, .. } => assertion,
    };
    let raw_key = derive_key(&assertion.prf_output);
    use_key(&raw_key);
}

/// `init` and `remember` exist to run a ceremony; under `$CI` that still
/// needs the same explicit opt-in as the derivation commands.
fn guard_ceremony(command: &str, allow_prompt: bool) {
    if in_ci() && !allow_prompt {
        die(&format!(
            "$CI is set: refusing to start the passkey ceremony `keytap {command}` needs \
             (it would hang this job). Pass --prompt to run it anyway."
        ));
    }
}

/// Whether this is a CI environment: `$CI` set to anything but the explicit
/// opt-outs — the convention every major CI platform follows.
fn in_ci() -> bool {
    std::env::var("CI").is_ok_and(|v| !v.is_empty() && v != "false" && v != "0")
}

/// The data shared by every completed passkey assertion. The credential ID
/// identifies the root for remembered keys.
struct AssertionData {
    prf_output: Zeroizing<Vec<u8>>,
    credential_id: Vec<u8>,
}

impl AssertionData {
    #[cfg(any(target_os = "macos", test))]
    fn native(prf_output: Vec<u8>, credential_id: Vec<u8>) -> Result<Self, String> {
        let prf_output = Zeroizing::new(prf_output);
        if prf_output.len() != 32 {
            return Err(format!(
                "native passkey provider returned {} bytes of PRF output; expected 32",
                prf_output.len()
            ));
        }
        if credential_id.is_empty() || credential_id.len() > 1024 {
            return Err(format!(
                "native passkey provider returned a credential ID of {} bytes; expected 1 to 1024",
                credential_id.len()
            ));
        }
        Ok(Self {
            prf_output,
            credential_id,
        })
    }
}

/// A completed passkey ceremony. Only nearby assertions carry a storage
/// outcome because native assertions never perform storage during approval.
enum Assertion {
    Native(AssertionData),
    Nearby {
        assertion: AssertionData,
        storage: nearby::StorageOutcome,
    },
}

impl Assertion {
    fn nearby(assertion: nearby::NearbyAssertion) -> Self {
        Self::Nearby {
            assertion: AssertionData {
                prf_output: Zeroizing::new(assertion.prf_output),
                credential_id: assertion.credential_id,
            },
            storage: assertion.storage,
        }
    }

    fn into_remember_disposition(self) -> RememberDisposition {
        match self {
            Self::Native(assertion)
            | Self::Nearby {
                assertion,
                storage: nearby::StorageOutcome::Once,
            } => RememberDisposition::StoreLocally(assertion),
            Self::Nearby {
                storage: nearby::StorageOutcome::Stored,
                ..
            } => RememberDisposition::AlreadyStored,
            Self::Nearby {
                storage: nearby::StorageOutcome::Unavailable,
                ..
            } => RememberDisposition::Unavailable,
        }
    }
}

enum RememberDisposition {
    StoreLocally(AssertionData),
    AlreadyStored,
    Unavailable,
}

#[cfg(test)]
mod assertion_candidate_tests {
    use super::{nearby, Assertion, AssertionData, RememberDisposition};

    #[test]
    fn native_candidate_is_bounded_before_it_can_claim_the_race() {
        assert!(AssertionData::native(vec![7; 32], vec![9; 20]).is_ok());
        assert!(AssertionData::native(vec![7; 31], vec![9; 20]).is_err());
        assert!(AssertionData::native(vec![7; 32], Vec::new()).is_err());
        assert!(AssertionData::native(vec![7; 32], vec![9; 1025]).is_err());
    }

    fn nearby_assertion(storage: nearby::StorageOutcome) -> Assertion {
        Assertion::nearby(nearby::NearbyAssertion {
            prf_output: vec![7; 32],
            credential_id: vec![9; 20],
            storage,
        })
    }

    #[test]
    fn native_and_one_time_nearby_assertions_are_stored_locally() {
        let native = Assertion::Native(
            AssertionData::native(vec![7; 32], vec![9; 20]).expect("valid native assertion"),
        );
        for assertion in [native, nearby_assertion(nearby::StorageOutcome::Once)] {
            match assertion.into_remember_disposition() {
                RememberDisposition::StoreLocally(assertion) => {
                    assert_eq!(assertion.prf_output.as_slice(), &[7; 32]);
                    assert_eq!(assertion.credential_id, vec![9; 20]);
                }
                RememberDisposition::AlreadyStored | RememberDisposition::Unavailable => {
                    panic!("assertion should be stored locally")
                }
            }
        }
    }

    #[test]
    fn nearby_storage_disposition_prevents_duplicate_or_impossible_local_write() {
        assert!(matches!(
            nearby_assertion(nearby::StorageOutcome::Stored).into_remember_disposition(),
            RememberDisposition::AlreadyStored
        ));
        assert!(matches!(
            nearby_assertion(nearby::StorageOutcome::Unavailable).into_remember_disposition(),
            RememberDisposition::Unavailable
        ));
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
fn authenticate(name: &str, storage_policy: nearby::StoragePolicy) -> Assertion {
    use approval::{ApprovalRace, ApprovalRoute, ClaimOutcome};

    enum NearbyWorkerOutcome {
        Committed(nearby::NearbyAssertion),
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
        .expect("authenticate is called only after validating the key name")
        .try_into()
        .expect("keytap PRF salts are always 32 bytes");
    let native_operation =
        keytap_macos::AssertionOperation::new(native_prf_salt, native_credential);
    let native_cancellation = native_operation.cancellation_handle();
    let nearby_name = name.to_string();
    let nearby_race = Arc::clone(&race);
    let worker_cancellation = nearby_cancellation.clone();
    let (native_outcome, nearby_rx) = run_native_while_nearby_starts(
        move || {
            let prepared = nearby::prepare_nearby_assertion(
                &nearby_name,
                storage_policy,
                worker_cancellation.clone(),
            );
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
        } => match AssertionData::native(prf_output, credential_id) {
            Ok(assertion) => match native_authority.prepare(&assertion.credential_id) {
                Ok(prepared) => match race.claim(ApprovalRoute::Native) {
                    ClaimOutcome::Claimed => {
                        nearby_cancellation.supersede();
                        if let Err(error) = prepared.commit() {
                            die(&format!(
                                "native approval won, but its local passkey record could not be committed: {error}"
                            ));
                        }
                        note("Approved on this Mac; cancelled nearby approval.");
                        return Assertion::Native(assertion);
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
        NearbyWorkerOutcome::Committed(assertion) => {
            note("Approved on the nearby device; closed the native approval prompt.");
            Assertion::nearby(assertion)
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
fn authenticate(name: &str, storage_policy: nearby::StoragePolicy) -> Assertion {
    Assertion::nearby(nearby::authenticate_nearby(name, storage_policy))
}

fn derive_key(prf_output: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(keytap_core::derive_raw_key(prf_output).unwrap_or_else(|e| {
        die(&format!("key derivation failed: {e}"));
    }))
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
                    remember::after_init();
                    die(&format!(
                        "passkey was created and its local credential record is visible, but durable storage could not be confirmed: {error}. Rerun `keytap init --force` before relying on it"
                    ))
                }
            }
        }
        keytap_macos::RegistrationOutcome::Cancelled => die("cancelled"),
        keytap_macos::RegistrationOutcome::Unavailable { message } => {
            note(&format!(
                "Native passkey registration is unavailable ({message}); continuing with a nearby device."
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

fn emit_private_key(raw_key: &[u8], format: keytap_cli_spec::Format) {
    match keytap_core::format_private_key_display(raw_key, format.into()) {
        Ok(bytes) => print!("{}", String::from_utf8(bytes).unwrap()),
        Err(e) => die(&format!("format error: {e}")),
    }
}

fn emit_public_key(raw_key: &[u8], format: keytap_cli_spec::Format, name: &str) {
    match keytap_core::format_public_key_display(raw_key, format.public_key_format(name)) {
        Ok(s) => print!("{s}"),
        Err(e) => die(&format!("format error: {e}")),
    }
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
