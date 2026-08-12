use js_sys::Uint8Array;
use keytap_cli_spec::{Cli, Command, Invocation};
use wasm_bindgen::prelude::*;

// ─── The CLI, compiled to wasm ───
//
// The web terminal funnels every `keytap …` line through `cliRun`, which parses
// with the same keytap-cli-spec crate the native binary uses and derives keys
// with keytap-core. JavaScript supplies the browser platform: passkey
// ceremonies, the shell's in-memory files, and a stderr sink. Machine storage,
// nearby approval, and CI environment keys remain installed-CLI features. A
// new subcommand fails this crate's build instead of silently missing a case.

/// What the browser provides. Ceremony UX (the busy line, cancellation)
/// lives inside these callbacks.
#[wasm_bindgen]
extern "C" {
    pub type Host;

    /// Create the keytap passkey; resolves when registered.
    #[wasm_bindgen(method, catch)]
    async fn register(this: &Host) -> Result<JsValue, JsValue>;

    /// Run an assertion ceremony for a key name; resolves with PRF output.
    #[wasm_bindgen(method, catch)]
    async fn prf(this: &Host, name: &str) -> Result<JsValue, JsValue>;

    /// Whether this browser has recorded a credential ID from an earlier
    /// ceremony. This drives a conservative init guard; `false` does not mean
    /// an existing synced or security-key passkey is unavailable.
    #[wasm_bindgen(method, js_name = hasCredentialId)]
    fn has_credential_id(this: &Host) -> bool;

    /// Read a file from the shell's filesystem; undefined when missing.
    #[wasm_bindgen(method, js_name = readFile)]
    fn read_file(this: &Host, name: &str) -> JsValue;

    /// A line of stderr, printed as it happens.
    #[wasm_bindgen(method)]
    fn stderr(this: &Host, text: &str);
}

/// The browser shell has no machine key store. It may retain a credential ID
/// for passkey selection, but never implements the installed CLI's named-key
/// storage commands.
const STATELESS: &str = "the web demo does not provide machine key storage; \
     remember, forget, and remembered require the installed keytap CLI: \
     https://github.com/jul-sh/keytap";

/// What an argv amounts to before any ceremony: text the CLI would print
/// without running anything, or a command to execute. Pure, so the front-end
/// decisions stay natively testable.
enum Plan {
    Output {
        stdout: String,
        stderr: String,
        exit: i32,
    },
    Run(Cli),
}

fn plan(argv: Vec<String>) -> Plan {
    match keytap_cli_spec::invoke(argv) {
        Invocation::Overview(text) => Plan::Output {
            stdout: text,
            stderr: String::new(),
            exit: 0,
        },
        // Native keytap answers misuse via `die`: `error: …` on stderr, exit 1.
        Invocation::Misuse(msg) => Plan::Output {
            stdout: String::new(),
            stderr: format!("error: {msg}"),
            exit: 1,
        },
        Invocation::Parsed(Err(e)) => {
            let text = e.render().to_string();
            if e.use_stderr() {
                Plan::Output {
                    stdout: String::new(),
                    stderr: text,
                    exit: e.exit_code(),
                }
            } else {
                Plan::Output {
                    stdout: text,
                    stderr: String::new(),
                    exit: 0,
                }
            }
        }
        Invocation::Parsed(Ok(cli)) => Plan::Run(cli),
    }
}

/// Run one keytap invocation. Resolves with `{ stdout, exit, ran }` where
/// `ran` is the executed command as data (for the terminal's follow-up
/// hints); rejects with an Error whose message matches what the native CLI
/// would `die` with (ceremony cancellations included).
#[wasm_bindgen(js_name = cliRun)]
pub async fn cli_run(argv: Vec<String>, stdin: &[u8], host: Host) -> Result<JsValue, JsValue> {
    let cli = match plan(argv) {
        Plan::Output {
            stdout,
            exit,
            stderr,
        } => {
            if !stderr.is_empty() {
                host.stderr(stderr.trim_end_matches('\n'));
            }
            return done(stdout.into_bytes(), exit, None);
        }
        Plan::Run(cli) => cli,
    };

    let command = cli.command;
    let stdout: Vec<u8> = match &command {
        Command::Init { force } => {
            if !force && host.has_credential_id() {
                return Err(fail(
                    "this browser has a saved keytap credential ID. Running init creates a \
                     different passkey and makes this demo select it, so existing named keys \
                     would derive differently. Pass --force only if you intend to switch.",
                ));
            }
            if !force {
                host.stderr(
                    "No credential ID is saved in this browser, but an existing keytap \
                     passkey may still be available through sync or a security key. Init \
                     creates a new passkey; cancel if you already use keytap and run the \
                     command you need instead.",
                );
            }
            host.register().await?;
            host.stderr("Passkey registered successfully.");
            Vec::new()
        }

        Command::Public { name, format } => {
            let raw_key = obtain_key(&host, name).await?;
            keytap_core::format_public_key_display(&raw_key, format.public_key_format(name))
                .map_err(|e| fail(&format!("format error: {e}")))?
                .into_bytes()
        }

        Command::Reveal { name, format } => {
            let raw_key = obtain_key(&host, name).await?;
            keytap_core::format_private_key_display(&raw_key, (*format).into())
                .map_err(|e| fail(&format!("format error: {e}")))?
        }

        Command::Encrypt {
            name,
            recipients,
            recipients_file,
            no_self,
        } => {
            let mut files = Vec::new();
            for file in recipients_file {
                let data = host.read_file(file);
                if data.is_undefined() || data.is_null() {
                    return Err(fail(&format!(
                        "failed to read recipients file {file}: no such file"
                    )));
                }
                let bytes = Uint8Array::new(&data).to_vec();
                files.push((file.clone(), String::from_utf8_lossy(&bytes).into_owned()));
            }
            let raw_key = obtain_key(&host, name).await?;
            let self_key = (!no_self).then_some(&raw_key[..]);
            let recipients = keytap_core::encrypt::recipients(self_key, recipients, &files)
                .map_err(|e| fail(&e.to_string()))?;
            let mut reader: &[u8] = stdin;
            let mut out = Vec::new();
            keytap_core::encrypt::encrypt_stream(&recipients, &mut reader, &mut out)
                .map_err(|e| fail(&e.to_string()))?;
            out
        }

        Command::Decrypt { name } => {
            let raw_key = obtain_key(&host, name).await?;
            let mut reader: &[u8] = stdin;
            let mut out = Vec::new();
            keytap_core::encrypt::decrypt_stream(&raw_key, &mut reader, &mut out)
                .map_err(|e| fail(&e.to_string()))?;
            out
        }

        Command::Remember { name: _ }
        | Command::Forget { name: _, all: _ }
        | Command::Remembered => {
            host.stderr(&format!("error: {STATELESS}"));
            return done(Vec::new(), 1, None);
        }
    };

    done(stdout, 0, Some(&command))
}

/// PRF ceremony via the host, then the same HKDF step the native CLI runs.
async fn obtain_key(host: &Host, name: &str) -> Result<Vec<u8>, JsValue> {
    let prf = Uint8Array::new(&host.prf(name).await?).to_vec();
    keytap_core::derive_raw_key(&prf).map_err(|e| fail(&format!("key derivation failed: {e}")))
}

fn fail(message: &str) -> JsValue {
    js_sys::Error::new(message).into()
}

fn done(stdout: Vec<u8>, exit: i32, ran: Option<&Command>) -> Result<JsValue, JsValue> {
    let out = js_sys::Object::new();
    js_sys::Reflect::set(&out, &"stdout".into(), &Uint8Array::from(&stdout[..]))?;
    js_sys::Reflect::set(&out, &"exit".into(), &JsValue::from(exit))?;
    let ran = match ran {
        Some(command) => serde_wasm_bindgen::to_value(command).map_err(JsValue::from)?,
        None => JsValue::NULL,
    };
    js_sys::Reflect::set(&out, &"ran".into(), &ran)?;
    Ok(out.into())
}

// ─── Ceremony configuration, straight from keytap-core ───

#[wasm_bindgen(js_name = registrationConfig)]
pub fn registration_config() -> Result<JsValue, JsError> {
    Ok(serde_wasm_bindgen::to_value(
        &keytap_core::registration_config(),
    )?)
}

#[wasm_bindgen(js_name = assertionConfig)]
pub fn assertion_config(
    key_name: &str,
    preferred_credential_id: Option<Vec<u8>>,
) -> Result<JsValue, JsError> {
    let config = keytap_core::assertion_config(key_name, preferred_credential_id)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(serde_wasm_bindgen::to_value(&config)?)
}

/// Derive only the public half of the stable nearby Ed25519 identity. Taking
/// ownership lets us wipe wasm-bindgen's private seed copy before returning.
#[wasm_bindgen(js_name = ed25519PublicKey)]
pub fn ed25519_public_key(mut seed: Vec<u8>) -> Result<Vec<u8>, JsError> {
    let public_key = keytap_core::ed25519_public_key(&seed)
        .map(|public_key| public_key.to_vec())
        .map_err(|error| JsError::new(&error.to_string()));
    seed.fill(0);
    public_key
}

// ─── Terminal chrome inputs ───

/// Subcommand names with their visible flags, for tab completion; walked
/// from the same clap metadata as the help, so completion can't drift.
#[wasm_bindgen(js_name = cliCompletions)]
pub fn cli_completions() -> Result<JsValue, JsError> {
    Ok(serde_wasm_bindgen::to_value(
        &keytap_cli_spec::completions(),
    )?)
}

#[cfg(test)]
mod plan_tests {
    use super::*;

    fn argv(line: &str) -> Vec<String> {
        std::iter::once("keytap")
            .chain(line.split_whitespace())
            .map(String::from)
            .collect()
    }

    #[test]
    fn overview_goes_to_stdout_with_exit_zero() {
        match plan(argv("")) {
            Plan::Output {
                stdout,
                stderr,
                exit,
            } => {
                assert!(stdout.contains("Usage: keytap <COMMAND>"));
                assert!(stderr.is_empty());
                assert_eq!(exit, 0);
            }
            _ => panic!("expected output"),
        }
    }

    #[test]
    fn usage_error_goes_to_stderr_with_exit_two() {
        match plan(argv("frobnicate")) {
            Plan::Output {
                stdout,
                stderr,
                exit,
            } => {
                assert!(stdout.is_empty());
                assert!(stderr.contains("frobnicate"));
                assert_eq!(exit, 2);
            }
            _ => panic!("expected output"),
        }
    }

    #[test]
    fn bare_remember_matches_native_die() {
        match plan(argv("remember")) {
            Plan::Output { stderr, exit, .. } => {
                assert!(stderr.starts_with("error: `keytap remember` needs a key name."));
                assert_eq!(exit, 1);
            }
            _ => panic!("expected output"),
        }
    }

    #[test]
    fn reveal_parses_to_run() {
        match plan(argv("reveal github --as ssh")) {
            Plan::Run(cli) => {
                assert_eq!(
                    serde_json::to_value(&cli.command).unwrap(),
                    serde_json::json!({
                        "cmd": "reveal",
                        "name": "github",
                        "format": "ssh",
                    })
                );
                match cli.command {
                    Command::Reveal { name, format } => {
                        assert_eq!(name, "github");
                        assert!(matches!(format, keytap_cli_spec::Format::Ssh));
                    }
                    _ => panic!("wrong command"),
                }
            }
            _ => panic!("expected run"),
        }
    }

    #[test]
    fn init_parses_its_force_switch() {
        match plan(argv("init --force")) {
            Plan::Run(cli) => {
                assert!(matches!(cli.command, Command::Init { force: true }))
            }
            _ => panic!("expected run"),
        }
    }

    #[test]
    fn removed_switches_are_rejected_by_every_command() {
        for removed in ["--nearby", "--prompt"] {
            for line in [
                format!("init {removed}"),
                format!("public {removed}"),
                format!("reveal {removed}"),
                format!("encrypt {removed}"),
                format!("decrypt {removed}"),
                format!("remember deploy {removed}"),
                format!("forget {removed}"),
                format!("remembered {removed}"),
            ] {
                match plan(argv(&line)) {
                    Plan::Output { stderr, exit, .. } => {
                        assert!(stderr.contains(&format!("unexpected argument '{removed}'")));
                        assert_eq!(exit, 2);
                    }
                    _ => panic!("expected {line:?} to reject {removed}"),
                }
            }
        }
    }

    /// The JSON the terminal sees is derived from the clap types themselves;
    /// this pins the shape the chrome's follow-up hints key off.
    #[test]
    fn command_serializes_from_the_clap_idents() {
        let cli = match plan(argv("encrypt backup --to age1x -R friends.txt --no-self")) {
            Plan::Run(cli) => cli,
            _ => panic!("expected run"),
        };
        let json = serde_json::to_value(&cli.command).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "cmd": "encrypt",
                "name": "backup",
                "recipients": ["age1x"],
                "recipientsFile": ["friends.txt"],
                "noSelf": true,
            })
        );
    }

    #[test]
    fn age_roundtrip_through_core() {
        let raw = vec![7u8; 32];
        let recipients = keytap_core::encrypt::recipients(Some(&raw), &[], &[]).unwrap();
        let mut ciphertext = Vec::new();
        keytap_core::encrypt::encrypt_stream(
            &recipients,
            &mut &b"hello keytap"[..],
            &mut ciphertext,
        )
        .unwrap();
        let mut plaintext = Vec::new();
        keytap_core::encrypt::decrypt_stream(&raw, &mut &ciphertext[..], &mut plaintext).unwrap();
        assert_eq!(plaintext, b"hello keytap");
    }

    #[test]
    fn nearby_identity_public_key_matches_the_browser_vector() {
        assert_eq!(
            hex::encode(ed25519_public_key(vec![7; 32]).unwrap()),
            "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
        );
    }
}
