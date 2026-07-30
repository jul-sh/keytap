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
#[cfg(target_os = "macos")]
use std::sync::{mpsc, Arc};
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
        Command::Init { force, nearby } => {
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
            let route = registration_route(nearby);
            register(pending_init, route);
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
            match assertion.storage {
                nearby::StorageOutcome::Once => {
                    let raw_key = derive_key(&assertion.prf_output);
                    remember::remember(&mut target, name, &assertion.credential_id, &raw_key);
                }
                nearby::StorageOutcome::Stored => {}
                nearby::StorageOutcome::Unavailable => {
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

/// Resolve the raw key for `name` and hand it to `use_key`, in order: a key
/// from the environment (`$KEYTAP_KEY_<NAME>`, the CI path), a key remembered
/// on this machine (under the active passkey root), and finally a passkey
/// ceremony, deriving on demand. Under `$CI` the ceremony rung is refused
/// unless `--prompt` asks for it.
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
             (the approval URL lands in the job log).",
            var = env_keys::var_name(name)
        ));
    }
    let assertion = authenticate(name, nearby::StoragePolicy::Choose);
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

/// Registration is deliberately single-route. Creating two credentials in
/// parallel cannot be rolled back safely if both authenticators finish.
#[derive(Clone, Copy)]
enum RegistrationRoute {
    #[cfg(target_os = "macos")]
    Native,
    Nearby,
}

fn registration_route(nearby_requested: bool) -> RegistrationRoute {
    if nearby_requested {
        RegistrationRoute::Nearby
    } else {
        default_registration_route()
    }
}

#[cfg(target_os = "macos")]
fn default_registration_route() -> RegistrationRoute {
    RegistrationRoute::Native
}

#[cfg(not(target_os = "macos"))]
fn default_registration_route() -> RegistrationRoute {
    RegistrationRoute::Nearby
}

/// A completed passkey ceremony: the PRF output plus the ID of the credential
/// that produced it (the latter identifies the root for remembered keys).
struct Assertion {
    prf_output: Zeroizing<Vec<u8>>,
    credential_id: Vec<u8>,
    storage: nearby::StorageOutcome,
}

impl Assertion {
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
        Ok(Assertion {
            prf_output,
            credential_id,
            storage: nearby::StorageOutcome::Once,
        })
    }

    fn nearby(assertion: nearby::NearbyAssertion) -> Self {
        Assertion {
            prf_output: Zeroizing::new(assertion.prf_output),
            credential_id: assertion.credential_id,
            storage: assertion.storage,
        }
    }
}

#[cfg(test)]
mod assertion_candidate_tests {
    use super::Assertion;

    #[test]
    fn native_candidate_is_bounded_before_it_can_claim_the_race() {
        assert!(Assertion::native(vec![7; 32], vec![9; 20]).is_ok());
        assert!(Assertion::native(vec![7; 31], vec![9; 20]).is_err());
        assert!(Assertion::native(vec![7; 32], Vec::new()).is_err());
        assert!(Assertion::native(vec![7; 32], vec![9; 1025]).is_err());
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

    enum NearbyWorkerEvent {
        InvitationShown,
        Finished(NearbyWorkerOutcome),
    }

    enum NearbyStartup {
        InvitationShown,
        Finished(NearbyWorkerOutcome),
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
    let (nearby_tx, nearby_rx) = mpsc::sync_channel(1);
    let nearby_name = name.to_string();
    let nearby_race = Arc::clone(&race);
    let worker_cancellation = nearby_cancellation.clone();
    std::thread::Builder::new()
        .name("keytap-nearby-approval".into())
        .spawn(move || {
            let invitation_tx = nearby_tx.clone();
            let prepared = nearby::prepare_nearby_assertion(
                &nearby_name,
                storage_policy,
                worker_cancellation.clone(),
                move || {
                    invitation_tx.send(NearbyWorkerEvent::InvitationShown).ok();
                },
            );
            let outcome = match prepared {
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
                        worker_cancellation.retire_superseded_url();
                        NearbyWorkerOutcome::SupersededByNative
                    }
                },
                Err(error) => NearbyWorkerOutcome::Failed(error),
            };
            nearby_tx.send(NearbyWorkerEvent::Finished(outcome)).ok();
        })
        .unwrap_or_else(|error| die(&format!("could not start nearby approval: {error}")));

    // Do not open the native sheet until stderr contains the complete URL an
    // unattended agent can forward. Local setup failures are retained while
    // the still-usable native route proceeds.
    let nearby_startup = match nearby_rx.recv() {
        Ok(NearbyWorkerEvent::InvitationShown) => NearbyStartup::InvitationShown,
        Ok(NearbyWorkerEvent::Finished(outcome)) => NearbyStartup::Finished(outcome),
        Err(_) => NearbyStartup::Finished(NearbyWorkerOutcome::Failed(
            "nearby approval stopped before showing its URL".into(),
        )),
    };
    let native_outcome = native_operation.run();
    let native_failure = match native_outcome {
        keytap_macos::AssertionOutcome::Success {
            prf_output,
            credential_id,
        } => match Assertion::native(prf_output, credential_id) {
            Ok(assertion) => match native_authority.prepare(&assertion.credential_id) {
                Ok(prepared) => match race.claim(ApprovalRoute::Native) {
                    ClaimOutcome::Claimed => {
                        if let Err(error) = prepared.commit() {
                            nearby_cancellation.supersede();
                            die(&format!(
                                "native approval won, but its local passkey record could not be committed: {error}"
                            ));
                        }
                        nearby_cancellation.supersede();
                        match &nearby_startup {
                            NearbyStartup::Finished(NearbyWorkerOutcome::Failed(error)) => {
                                note(&format!("Nearby approval was unavailable ({error})."));
                                note("Approved on this Mac.");
                            }
                            NearbyStartup::InvitationShown
                            | NearbyStartup::Finished(
                                NearbyWorkerOutcome::Committed(_)
                                | NearbyWorkerOutcome::CommitFailed(_)
                                | NearbyWorkerOutcome::SupersededByNative,
                            ) => {
                                note("Approved on this Mac; closed the nearby approval request.");
                            }
                        }
                        return assertion;
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
                "Native approval ended ({error}); nearby approval is still available."
            ));
            format!("native approval failed: {error}")
        }
    };

    let nearby_outcome = match nearby_startup {
        NearbyStartup::Finished(outcome) => outcome,
        NearbyStartup::InvitationShown => loop {
            match nearby_rx.recv() {
                Ok(NearbyWorkerEvent::InvitationShown) => continue,
                Ok(NearbyWorkerEvent::Finished(outcome)) => break outcome,
                Err(_) => {
                    break NearbyWorkerOutcome::Failed(
                        "nearby approval stopped unexpectedly".into(),
                    )
                }
            }
        },
    };
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
fn register(
    pending_init: nearby_identity::PendingInit,
    route: RegistrationRoute,
) -> nearby_identity::PersistedInit {
    if let RegistrationRoute::Nearby = route {
        return nearby::register_nearby(pending_init);
    }
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
        keytap_macos::RegistrationOutcome::Error(msg) => die(&format!(
            "native passkey registration failed: {msg}. Registration will not switch authenticators automatically because the native provider may already have created a credential; retry explicitly with `keytap init --nearby` if no credential was created"
        )),
    }
}

#[cfg(not(target_os = "macos"))]
fn register(
    pending_init: nearby_identity::PendingInit,
    route: RegistrationRoute,
) -> nearby_identity::PersistedInit {
    match route {
        RegistrationRoute::Nearby => nearby::register_nearby(pending_init),
    }
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

#[cfg(test)]
mod registration_route_tests {
    use super::{registration_route, RegistrationRoute};

    #[test]
    fn explicit_nearby_registration_always_selects_nearby() {
        assert!(matches!(
            registration_route(true),
            RegistrationRoute::Nearby
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_build_defaults_registration_to_native() {
        assert!(matches!(
            registration_route(false),
            RegistrationRoute::Native
        ));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn nearby_only_build_has_only_the_nearby_registration_route() {
        assert!(matches!(
            registration_route(false),
            RegistrationRoute::Nearby
        ));
    }
}
