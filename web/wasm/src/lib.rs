use keytap_cli_spec::{Command, Invocation};
use wasm_bindgen::prelude::*;

// ─── The CLI front-end, compiled to wasm ───
//
// The web terminal at keytap.jul.sh funnels every `keytap …` line through
// `cliInvoke`, which parses with the same keytap-cli-spec crate the native
// binary uses. Help text, defaults, and usage errors are the CLI's own
// rendering; JavaScript only executes the parsed command.

/// What an argv amounts to: text to print as-is, or a command to execute.
#[derive(serde::Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum CliOutcome {
    /// Text keytap would print without running anything: help screens,
    /// `--version`, usage errors. Mirrors the native process exactly.
    Output { stdout: String, stderr: String, exit: i32 },
    /// A parsed command for the host terminal to execute.
    Run { prompt: bool, command: CommandDto },
}

#[derive(serde::Serialize)]
#[serde(tag = "cmd", rename_all = "camelCase")]
enum CommandDto {
    Init,
    Public { name: String, format: String },
    Reveal { name: String, format: String },
    #[serde(rename_all = "camelCase")]
    Encrypt { name: String, recipients: Vec<String>, recipients_file: Vec<String>, no_self: bool },
    Decrypt { name: String },
    Remember { name: String },
    Forget { name: String, all: bool },
    Remembered,
}

impl From<Command> for CommandDto {
    fn from(cmd: Command) -> Self {
        match cmd {
            Command::Init => CommandDto::Init,
            Command::Public { name, format } => {
                CommandDto::Public { name, format: format.as_str() }
            }
            Command::Reveal { name, format } => {
                CommandDto::Reveal { name, format: format.as_str() }
            }
            Command::Encrypt { name, recipients, recipients_file, no_self } => {
                CommandDto::Encrypt { name, recipients, recipients_file, no_self }
            }
            Command::Decrypt { name } => CommandDto::Decrypt { name },
            Command::Remember { name } => CommandDto::Remember { name },
            Command::Forget { name, all } => CommandDto::Forget { name, all },
            Command::Remembered => CommandDto::Remembered,
        }
    }
}

/// Resolve an argv (including argv[0], i.e. `keytap`) the way the native
/// binary's `main` does. Kept free of wasm types so it's testable natively.
fn resolve(argv: Vec<String>) -> CliOutcome {
    match keytap_cli_spec::invoke(argv) {
        Invocation::Overview(text) => {
            CliOutcome::Output { stdout: text, stderr: String::new(), exit: 0 }
        }
        // Native keytap answers misuse via `die`: `error: …` on stderr, exit 1.
        Invocation::Misuse(msg) => CliOutcome::Output {
            stdout: String::new(),
            stderr: format!("error: {msg}\n"),
            exit: 1,
        },
        Invocation::Parsed(Err(e)) => {
            let text = e.render().to_string();
            if e.use_stderr() {
                CliOutcome::Output { stdout: String::new(), stderr: text, exit: e.exit_code() }
            } else {
                CliOutcome::Output { stdout: text, stderr: String::new(), exit: 0 }
            }
        }
        Invocation::Parsed(Ok(cli)) => {
            CliOutcome::Run { prompt: cli.prompt, command: cli.command.into() }
        }
    }
}

#[wasm_bindgen(js_name = cliInvoke)]
pub fn cli_invoke(argv: Vec<String>) -> Result<JsValue, JsError> {
    Ok(serde_wasm_bindgen::to_value(&resolve(argv))?)
}

#[wasm_bindgen(js_name = cliVersion)]
pub fn cli_version() -> String {
    keytap_cli_spec::version().to_string()
}

/// Subcommand names with their visible flags, for tab completion — walked
/// from the same clap metadata as the help, so completion can't drift.
#[wasm_bindgen(js_name = cliCompletions)]
pub fn cli_completions() -> Result<JsValue, JsError> {
    Ok(serde_wasm_bindgen::to_value(&keytap_cli_spec::completions())?)
}

// ─── age encryption, shared with the native `keytap encrypt`/`decrypt` ───

/// Encrypt plaintext for the derived identity (when `self_key` is given)
/// and/or explicit recipients. Recipient files arrive as parallel
/// label/contents arrays — reading them is the caller's job.
#[wasm_bindgen(js_name = encryptAge)]
pub fn encrypt_age(
    self_key: Option<Vec<u8>>,
    recipients: Vec<String>,
    recipients_file_labels: Vec<String>,
    recipients_file_contents: Vec<String>,
    plaintext: &[u8],
) -> Result<Vec<u8>, JsError> {
    if recipients_file_labels.len() != recipients_file_contents.len() {
        return Err(JsError::new("recipients file labels and contents differ in length"));
    }
    let files: Vec<(String, String)> =
        recipients_file_labels.into_iter().zip(recipients_file_contents).collect();
    let recipients = keytap_core::encrypt::recipients(self_key.as_deref(), &recipients, &files)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let mut reader: &[u8] = plaintext;
    let mut out = Vec::new();
    keytap_core::encrypt::encrypt_stream(&recipients, &mut reader, &mut out)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(out)
}

/// Decrypt age ciphertext with the derived identity.
#[wasm_bindgen(js_name = decryptAge)]
pub fn decrypt_age(raw_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
    let mut reader: &[u8] = ciphertext;
    let mut out = Vec::new();
    keytap_core::encrypt::decrypt_stream(raw_key, &mut reader, &mut out)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(out)
}

#[wasm_bindgen(js_name = registrationConfig)]
pub fn registration_config() -> Result<JsValue, JsError> {
    let config = keytap_core::registration_config();
    Ok(serde_wasm_bindgen::to_value(&RegistrationConfigJs {
        rp_id: config.rp_id,
        user_name: config.user_name,
        user_id: config.user_id,
        default_prf_salt: config.default_prf_salt,
    })?)
}

#[wasm_bindgen(js_name = assertionConfig)]
pub fn assertion_config(
    key_name: &str,
    preferred_credential_id: Option<Vec<u8>>,
) -> Result<JsValue, JsError> {
    let config = keytap_core::assertion_config(key_name, preferred_credential_id)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(serde_wasm_bindgen::to_value(&AssertionConfigJs {
        rp_id: config.rp_id,
        key_name: config.key_name,
        prf_salt: config.prf_salt,
        preferred_credential_id: config.preferred_credential_id,
    })?)
}

#[wasm_bindgen(js_name = prfSaltForName)]
pub fn prf_salt_for_name(key_name: &str) -> Result<Vec<u8>, JsError> {
    keytap_core::prf_salt_for_name(key_name).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen(js_name = deriveRawKey)]
pub fn derive_raw_key(prf_output: &[u8]) -> Result<Vec<u8>, JsError> {
    keytap_core::derive_raw_key(prf_output).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen(js_name = formatPrivateKey)]
pub fn format_private_key(raw_key: &[u8], format: &str) -> Result<Vec<u8>, JsError> {
    let fmt = parse_private_format(format)?;
    keytap_core::format_private_key(raw_key, fmt).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen(js_name = formatPublicKey)]
pub fn format_public_key(raw_key: &[u8], format: &str, name: Option<String>) -> Result<String, JsError> {
    let fmt = parse_public_format(format)?;
    keytap_core::format_public_key(raw_key, fmt, name.as_deref())
        .map_err(|e| JsError::new(&e.to_string()))
}

fn parse_private_format(s: &str) -> Result<keytap_core::PrivateKeyFormat, JsError> {
    match s {
        "hex" => Ok(keytap_core::PrivateKeyFormat::Hex),
        "base64" => Ok(keytap_core::PrivateKeyFormat::Base64),
        "age" => Ok(keytap_core::PrivateKeyFormat::AgeSecretKey),
        "raw" => Ok(keytap_core::PrivateKeyFormat::Raw),
        "ssh" => Ok(keytap_core::PrivateKeyFormat::SshPrivateKey),
        _ => Err(JsError::new(&format!("unknown private key format: {}", s))),
    }
}

fn parse_public_format(s: &str) -> Result<keytap_core::PublicKeyFormat, JsError> {
    match s {
        "hex" => Ok(keytap_core::PublicKeyFormat::Hex),
        "base64" => Ok(keytap_core::PublicKeyFormat::Base64),
        "age" => Ok(keytap_core::PublicKeyFormat::AgeRecipient),
        "ssh" => Ok(keytap_core::PublicKeyFormat::SshPublicKey),
        _ => Err(JsError::new(&format!("unknown public key format: {}", s))),
    }
}

#[derive(serde::Serialize)]
struct RegistrationConfigJs {
    rp_id: String,
    user_name: String,
    user_id: Vec<u8>,
    default_prf_salt: Vec<u8>,
}

#[derive(serde::Serialize)]
struct AssertionConfigJs {
    rp_id: String,
    key_name: String,
    prf_salt: Vec<u8>,
    preferred_credential_id: Option<Vec<u8>>,
}

#[cfg(test)]
mod cli_front_end_tests {
    use super::*;

    fn argv(line: &str) -> Vec<String> {
        std::iter::once("keytap").chain(line.split_whitespace()).map(String::from).collect()
    }

    #[test]
    fn overview_goes_to_stdout_with_exit_zero() {
        match resolve(argv("")) {
            CliOutcome::Output { stdout, stderr, exit } => {
                assert!(stdout.contains("Usage: keytap <COMMAND>"));
                assert!(stderr.is_empty());
                assert_eq!(exit, 0);
            }
            _ => panic!("expected output"),
        }
    }

    #[test]
    fn usage_error_goes_to_stderr_with_exit_two() {
        match resolve(argv("frobnicate")) {
            CliOutcome::Output { stdout, stderr, exit } => {
                assert!(stdout.is_empty());
                assert!(stderr.contains("frobnicate"));
                assert_eq!(exit, 2);
            }
            _ => panic!("expected output"),
        }
    }

    #[test]
    fn bare_remember_matches_native_die() {
        match resolve(argv("remember")) {
            CliOutcome::Output { stderr, exit, .. } => {
                assert!(stderr.starts_with("error: `keytap remember` needs a key name."));
                assert_eq!(exit, 1);
            }
            _ => panic!("expected output"),
        }
    }

    #[test]
    fn reveal_parses_to_run() {
        match resolve(argv("reveal github --as ssh")) {
            CliOutcome::Run { command: CommandDto::Reveal { name, format }, prompt } => {
                assert_eq!(name, "github");
                assert_eq!(format, "ssh");
                assert!(!prompt);
            }
            _ => panic!("expected run"),
        }
    }

    #[test]
    fn age_roundtrip_through_core() {
        let raw = vec![7u8; 32];
        let recipients = keytap_core::encrypt::recipients(Some(&raw), &[], &[]).unwrap();
        let mut ciphertext = Vec::new();
        keytap_core::encrypt::encrypt_stream(&recipients, &mut &b"hello keytap"[..], &mut ciphertext)
            .unwrap();
        let mut plaintext = Vec::new();
        keytap_core::encrypt::decrypt_stream(&raw, &mut &ciphertext[..], &mut plaintext).unwrap();
        assert_eq!(plaintext, b"hello keytap");
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[test]
    fn test_parse_private_formats() {
        assert!(parse_private_format("hex").is_ok());
        assert!(parse_private_format("base64").is_ok());
        assert!(parse_private_format("age").is_ok());
        assert!(parse_private_format("raw").is_ok());
        assert!(parse_private_format("ssh").is_ok());
        assert!(parse_private_format("invalid").is_err());
    }

    #[test]
    fn test_parse_public_formats() {
        assert!(parse_public_format("hex").is_ok());
        assert!(parse_public_format("base64").is_ok());
        assert!(parse_public_format("age").is_ok());
        assert!(parse_public_format("ssh").is_ok());
        assert!(parse_public_format("invalid").is_err());
    }
}
