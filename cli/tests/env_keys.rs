//! End-to-end tests of the CI path: keys supplied via `$KEYTAP_KEY_<NAME>`,
//! exercised against the real binary. Every invocation runs with `CI=true`
//! and a cleared environment, so these double as proof that the CI ceremony
//! guard never blocks env-resolved keys — and that no passkey, keychain, or
//! network is touched on the env rung.

use std::io::Write;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_keytap");

/// A fixed raw key and its age encoding, produced by the same core code
/// `reveal --as age` uses — so these tests exercise the parse side against
/// the real format side.
const RAW: [u8; 32] = [7u8; 32];

fn age_encoding(raw: &[u8; 32]) -> String {
    let bytes =
        keytap_core::format_private_key(raw, keytap_core::PrivateKeyFormat::AgeSecretKey).unwrap();
    String::from_utf8(bytes).unwrap()
}

/// Run the binary with ONLY the given env vars (plus CI=true), feeding stdin
/// and collecting output. A hang means a ceremony started where none should:
/// kill and fail rather than wedge the suite.
fn keytap(envs: &[(&str, &str)], args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(BIN)
        .args(args)
        .env_clear()
        .env("CI", "true")
        .envs(envs.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    wait_or_kill(child)
}

fn wait_or_kill(mut child: Child) -> Output {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("keytap hung — a ceremony started where none should");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn stdout(out: &Output) -> String {
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn env_key_round_trips_every_output_format() {
    let key = age_encoding(&RAW);
    let envs: &[(&str, &str)] = &[("KEYTAP_KEY_CI", &key)];

    let hex = keytap(envs, &["reveal", "ci", "--as", "hex"], b"");
    assert_eq!(stdout(&hex).trim(), hex::encode(RAW));
    // The note names the variable, so job logs show the passkey wasn't used.
    assert!(stderr(&hex).contains("$KEYTAP_KEY_CI"), "stderr: {}", stderr(&hex));

    let age = keytap(envs, &["reveal", "ci", "--as", "age"], b"");
    assert_eq!(stdout(&age).trim(), key, "env → reveal --as age must echo the key");

    let expected_public =
        keytap_core::format_public_key(&RAW, keytap_core::PublicKeyFormat::AgeRecipient, None)
            .unwrap();
    let public = keytap(envs, &["public", "ci", "--as", "age"], b"");
    assert_eq!(stdout(&public).trim(), expected_public);
}

#[test]
fn env_key_accepts_lowercase_encoding() {
    let key = age_encoding(&RAW).to_lowercase();
    let out = keytap(&[("KEYTAP_KEY_CI", &key)], &["reveal", "ci", "--as", "hex"], b"");
    assert_eq!(stdout(&out).trim(), hex::encode(RAW));
}

#[test]
fn env_key_encrypt_decrypt_round_trip() {
    let key = age_encoding(&RAW);
    let envs: &[(&str, &str)] = &[("KEYTAP_KEY_BACKUP", &key)];
    let plaintext = b"the CI path never prompts".as_slice();

    let encrypted = keytap(envs, &["encrypt", "backup"], plaintext);
    let ciphertext = {
        assert!(encrypted.status.success(), "stderr: {}", stderr(&encrypted));
        encrypted.stdout
    };
    assert_ne!(ciphertext, plaintext);

    let decrypted = keytap(envs, &["decrypt", "backup"], &ciphertext);
    assert!(decrypted.status.success(), "stderr: {}", stderr(&decrypted));
    assert_eq!(decrypted.stdout, plaintext);
}

#[test]
fn env_var_name_flattens_punctuation() {
    let key = age_encoding(&RAW);
    let out =
        keytap(&[("KEYTAP_KEY_MY_APP_PROD", &key)], &["reveal", "my-app.prod", "--as", "hex"], b"");
    assert_eq!(stdout(&out).trim(), hex::encode(RAW));
}

#[test]
fn empty_value_is_an_error_not_a_fall_through() {
    let out = keytap(&[("KEYTAP_KEY_CI", "")], &["reveal", "ci"], b"");
    assert!(!out.status.success());
    assert!(stderr(&out).contains("empty"), "stderr: {}", stderr(&out));
}

#[test]
fn malformed_value_dies_with_the_expected_format() {
    let out = keytap(&[("KEYTAP_KEY_CI", "not-a-key")], &["reveal", "ci"], b"");
    assert!(!out.status.success());
    assert!(stderr(&out).contains("age secret key"), "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("keytap reveal ci --as age"), "stderr: {}", stderr(&out));
}

#[test]
fn other_encodings_of_the_key_are_refused() {
    // The env contract is ONE format; hex is valid `reveal` output but not
    // valid env input, and the error says what to use instead.
    let hex_key = hex::encode(RAW);
    let out = keytap(&[("KEYTAP_KEY_CI", &hex_key)], &["reveal", "ci"], b"");
    assert!(!out.status.success());
    assert!(stderr(&out).contains("--as age"), "stderr: {}", stderr(&out));
}

#[test]
fn bare_keytap_key_gets_guidance() {
    let key = age_encoding(&RAW);
    let out = keytap(&[("KEYTAP_KEY", &key)], &["reveal", "ci"], b"");
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("$KEYTAP_KEY_CI"),
        "the error must name the per-name variable; stderr: {}",
        stderr(&out)
    );
}

/// The refusal rung: under $CI with no env key (and nothing remembered),
/// keytap must fail fast instead of starting a ceremony. Linux-only: on
/// macOS the remembered-key lookup would touch the developer's real
/// keychain; in CI (ubuntu, cleared env, no D-Bus) the lookup is inert.
#[cfg(target_os = "linux")]
#[test]
fn ci_refuses_the_ceremony_and_names_the_fix() {
    let out = keytap(&[], &["reveal", "deploy"], b"");
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("$KEYTAP_KEY_DEPLOY"), "stderr: {err}");
    assert!(err.contains("--prompt"), "stderr: {err}");
}

/// Same guard for the commands whose whole purpose is a ceremony.
#[cfg(target_os = "linux")]
#[test]
fn ci_refuses_init_and_remember_without_prompt() {
    for args in [vec!["init"], vec!["remember", "deploy"]] {
        let out = keytap(&[], &args, b"");
        assert!(!out.status.success(), "{args:?} must refuse under $CI");
        assert!(stderr(&out).contains("--prompt"), "stderr: {}", stderr(&out));
    }
}
