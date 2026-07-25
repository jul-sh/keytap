mod encrypt;
mod env_keys;
mod keychain;
mod nearby;
mod nearby_identity;
mod nearby_protocol;
mod nearby_sas;
mod remember;

use keytap_cli_spec::{Command, Invocation};
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
            if !force
                && (remember::previously_initialized() || nearby_identity::previously_pinned())
            {
                die(
                    "a keytap passkey is already set up on this machine. Running init again \
                     creates a new one: keys derived from the current passkey can no longer be \
                     re-derived (files encrypted to them stay locked), and remembered keys are \
                     cleared. Pass --force to replace the passkey.",
                );
            }
            let init_mode = if force {
                nearby_identity::InitMode::Replace
            } else {
                nearby_identity::InitMode::Create
            };
            let pending_init = nearby_identity::prepare_init(init_mode).unwrap_or_else(|error| {
                die(&format!(
                    "could not prepare the nearby identity update: {error}"
                ))
            });
            let registration = register(pending_init);
            remember::after_init(registration.credential_id());
        }
        Command::Public { ref name, format } => {
            with_derived_key(name, cli.prompt, |raw_key| emit_public_key(raw_key, format, name));
        }
        Command::Reveal { ref name, format } => {
            with_derived_key(name, cli.prompt, |raw_key| emit_private_key(raw_key, format));
        }
        Command::Encrypt { ref name, ref recipients, ref recipients_file, no_self } => {
            with_derived_key(name, cli.prompt, |raw_key| {
                encrypt::encrypt(raw_key, recipients, recipients_file, !no_self)
            });
        }
        Command::Decrypt { ref name } => {
            with_derived_key(name, cli.prompt, |raw_key| encrypt::decrypt(raw_key));
        }
        Command::Remember { ref name } => {
            // Fail fast on names derivation would reject, and on machines
            // with nowhere to store, before any ceremony.
            if let Err(e) = keytap_core::prf_salt_for_name(name) {
                die(&e.to_string());
            }
            guard_ceremony("remember", cli.prompt);
            let mut target = remember::write_target();
            let assertion = authenticate(name, SUPPRESS_REMEMBER);
            let raw_key = derive_key(&assertion.prf_output);
            remember::remember(&mut target, name, &assertion.credential_id, &raw_key);
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
/// Nothing is stored unless the user opts in on the nearby page. The opt-in
/// arrives either with the assertion itself (legacy pages) or afterwards,
/// backed by a second ceremony; the latter settles only after `use_key` has
/// emitted its output, so the command's result is never delayed by it.
fn with_derived_key(name: &str, allow_prompt: bool, use_key: impl FnOnce(&[u8])) {
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
             (the QR code lands in the job log).",
            var = env_keys::var_name(name)
        ));
    }
    let assertion = authenticate(name, OFFER_REMEMBER);
    let raw_key = derive_key(&assertion.prf_output);
    if assertion.remember_requested {
        let _ = remember::remember_requested_nearby(name, &assertion.credential_id, &raw_key);
    }
    use_key(&raw_key);
    if let Some(window) = assertion.followup {
        // The output must be out of the process before the opt-in window:
        // the window may end via Ctrl-C (_exit skips buffered-IO flushing),
        // and a piped consumer deserves the key now, not after the wait.
        use std::io::Write;
        std::io::stdout().flush().ok();
        window.settle(&raw_key);
    }
}

/// `init` and `remember` exist to run a ceremony; under `$CI` that still
/// needs the same explicit opt-in as the derivation commands.
fn guard_ceremony(command: &str, allow_prompt: bool) {
    if in_ci() && !allow_prompt {
        die(&format!(
            "$CI is set: refusing to start the passkey ceremony `keytap {command}` needs \
             (it would hang this job). Pass --prompt to run it anyway \
             (the QR code lands in the job log)."
        ));
    }
}

/// Whether this is a CI environment: `$CI` set to anything but the explicit
/// opt-outs — the convention every major CI platform follows.
fn in_ci() -> bool {
    std::env::var("CI").is_ok_and(|v| !v.is_empty() && v != "false" && v != "0")
}

/// Values for `authenticate`'s `offer_remember`, named so call sites read as
/// policy: derivation commands offer the nearby page's remember checkbox;
/// `keytap remember` suppresses it (that command already stores the key).
const OFFER_REMEMBER: bool = true;
const SUPPRESS_REMEMBER: bool = false;

/// A completed passkey ceremony: the PRF output plus the ID of the credential
/// that produced it (the latter identifies the root for remembered keys).
struct Assertion {
    prf_output: Zeroizing<Vec<u8>>,
    credential_id: Vec<u8>,
    /// The user asked, with the assertion itself, to remember this key on
    /// this machine. Never set by the native flow, which has no such control.
    remember_requested: bool,
    /// Still-open window for the nearby page's post-auth remember opt-in;
    /// settled after the command's output. Never present for the native flow.
    followup: Option<nearby::RememberWindow>,
}

impl Assertion {
    #[cfg(feature = "native-passkey")]
    fn native(prf_output: Vec<u8>, credential_id: Vec<u8>) -> Self {
        Assertion {
            prf_output: Zeroizing::new(prf_output),
            credential_id,
            remember_requested: false,
            followup: None,
        }
    }

    fn nearby(assertion: nearby::NearbyAssertion) -> Self {
        Assertion {
            prf_output: Zeroizing::new(assertion.prf_output),
            credential_id: assertion.credential_id,
            remember_requested: assertion.remember_requested,
            followup: assertion.followup,
        }
    }
}

/// Authenticate with a passkey ceremony.
#[cfg(feature = "native-passkey")]
fn authenticate(name: &str, offer_remember: bool) -> Assertion {
    match keytap_macos::assert(name) {
        keytap_macos::AssertionOutcome::Success { prf_output, credential_id } => {
            Assertion::native(prf_output, credential_id)
        }
        keytap_macos::AssertionOutcome::Error(msg) if msg == "cancelled" => {
            die(&msg);
        }
        keytap_macos::AssertionOutcome::Error(msg) => {
            eprintln!("Couldn't open native passkey flow: {msg}");
            Assertion::nearby(nearby::authenticate_nearby(name, offer_remember))
        }
    }
}

#[cfg(not(feature = "native-passkey"))]
fn authenticate(name: &str, offer_remember: bool) -> Assertion {
    Assertion::nearby(nearby::authenticate_nearby(name, offer_remember))
}

fn derive_key(prf_output: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(keytap_core::derive_raw_key(prf_output).unwrap_or_else(|e| {
        die(&format!("key derivation failed: {e}"));
    }))
}

#[cfg(feature = "native-passkey")]
fn register(pending_init: nearby_identity::PendingInit) -> nearby_identity::PersistedInit {
    match keytap_macos::register() {
        keytap_macos::RegistrationOutcome::Success { credential_id } => {
            match pending_init.commit(&credential_id) {
                Ok(registration) => {
                    eprintln!("Passkey registered successfully.");
                    registration
                }
                Err(nearby_identity::InitCommitError::NotPublished(error)) => die(&format!(
                    "passkey was created, but its nearby identity anchor could not be stored: {error}"
                )),
                Err(nearby_identity::InitCommitError::PublishedButNotDurable(error)) => {
                    remember::after_init(&credential_id);
                    die(&format!(
                        "passkey was created and its nearby identity anchor is visible, but durable storage could not be confirmed: {error}. Init is indeterminate; rerun `keytap init --force` before relying on it"
                    ))
                }
            }
        }
        keytap_macos::RegistrationOutcome::Error(msg) if msg == "cancelled" => {
            die(&msg);
        }
        keytap_macos::RegistrationOutcome::Error(msg) => {
            eprintln!("Couldn't open native passkey flow: {msg}");
            nearby::register_nearby(pending_init)
        }
    }
}

#[cfg(not(feature = "native-passkey"))]
fn register(pending_init: nearby_identity::PendingInit) -> nearby_identity::PersistedInit {
    nearby::register_nearby(pending_init)
}

fn emit_private_key(raw_key: &[u8], format: keytap_cli_spec::Format) {
    match keytap_core::format_private_key_display(raw_key, format.into()) {
        Ok(bytes) => print!("{}", String::from_utf8(bytes).unwrap()),
        Err(e) => die(&format!("format error: {e}")),
    }
}

fn emit_public_key(raw_key: &[u8], format: keytap_cli_spec::PublicFormat, name: &str) {
    match keytap_core::format_public_key_display(raw_key, format.into(), name) {
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
