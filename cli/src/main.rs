mod encrypt;
mod env_keys;
mod keychain;
mod nearby;
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
        Command::Init => {
            guard_ceremony("init", cli.prompt);
            let credential_id = register();
            remember::after_init(&credential_id);
        }
        Command::Public { ref name, format } => {
            let raw_key = obtain_key(name, cli.prompt);
            emit_public_key(&raw_key, format, name);
        }
        Command::Reveal { ref name, format } => {
            let raw_key = obtain_key(name, cli.prompt);
            emit_private_key(&raw_key, format);
        }
        Command::Encrypt { ref name, ref recipients, ref recipients_file, no_self } => {
            let raw_key = obtain_key(name, cli.prompt);
            encrypt::encrypt(&raw_key, recipients, recipients_file, !no_self);
        }
        Command::Decrypt { ref name } => {
            let raw_key = obtain_key(name, cli.prompt);
            encrypt::decrypt(&raw_key);
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

/// Resolve the raw key for `name`, in order: a key handed in via the
/// environment (`$KEYTAP_KEY_<NAME>`, the CI path), a key remembered on this
/// machine (under the active passkey root), and finally a passkey ceremony,
/// deriving on demand. Under `$CI` the ceremony rung is refused unless
/// `--prompt` asks for it. Nothing is stored unless the user opted in on the
/// nearby page ("remember this key on this machine"); that request arrives
/// with the assertion and is honored here, best-effort.
fn obtain_key(name: &str, allow_prompt: bool) -> Zeroizing<Vec<u8>> {
    if let Some(raw_key) = env_keys::resolve(name) {
        return raw_key;
    }
    if let Some(raw_key) = remember::lookup(name) {
        return raw_key;
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
        remember::remember_requested_nearby(name, &assertion.credential_id, &raw_key);
    }
    raw_key
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
    /// The user ticked "remember this key on this machine" on the nearby
    /// page. Never set by the native flow, which has no such control.
    remember_requested: bool,
}

impl Assertion {
    #[cfg(feature = "native-passkey")]
    fn native(prf_output: Vec<u8>, credential_id: Vec<u8>) -> Self {
        Assertion {
            prf_output: Zeroizing::new(prf_output),
            credential_id,
            remember_requested: false,
        }
    }

    fn nearby(assertion: nearby::NearbyAssertion) -> Self {
        Assertion {
            prf_output: Zeroizing::new(assertion.prf_output),
            credential_id: assertion.credential_id,
            remember_requested: assertion.remember_requested,
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

/// Register a new passkey; returns its credential ID so init can rotate the
/// remembered-keys root.
#[cfg(feature = "native-passkey")]
fn register() -> Vec<u8> {
    match keytap_macos::register() {
        keytap_macos::RegistrationOutcome::Success { credential_id } => {
            eprintln!("Passkey registered successfully.");
            credential_id
        }
        keytap_macos::RegistrationOutcome::Error(msg) if msg == "cancelled" => {
            die(&msg);
        }
        keytap_macos::RegistrationOutcome::Error(msg) => {
            eprintln!("Couldn't open native passkey flow: {msg}");
            nearby::register_nearby()
        }
    }
}

#[cfg(not(feature = "native-passkey"))]
fn register() -> Vec<u8> {
    nearby::register_nearby()
}

fn emit_private_key(raw_key: &[u8], format: keytap_cli_spec::Format) {
    match keytap_core::format_private_key(raw_key, format.into()) {
        Ok(bytes) => {
            // SSH PEM already ends in a newline; others are single-line values.
            if matches!(format, keytap_cli_spec::Format::Ssh) {
                print!("{}", String::from_utf8(bytes).unwrap());
            } else {
                println!("{}", String::from_utf8(bytes).unwrap());
            }
        }
        Err(e) => die(&format!("format error: {e}")),
    }
}

fn emit_public_key(raw_key: &[u8], format: keytap_cli_spec::PublicFormat, name: &str) {
    // The name is only meaningful as the SSH key comment; other formats ignore it.
    let comment = matches!(format, keytap_cli_spec::PublicFormat::Ssh).then_some(name);
    match keytap_core::format_public_key(raw_key, format.into(), comment) {
        Ok(s) => println!("{s}"),
        Err(e) => die(&format!("format error: {e}")),
    }
}

pub(crate) fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}
