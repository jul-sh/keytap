//! End-to-end tests of init's refusal to silently replace a passkey. A
//! machine shows it was initialized through the active-root marker its
//! stores carry; rerunning `keytap init` there must die with instructions
//! before any ceremony, unless --force says the replacement is deliberate.

use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_keytap");

/// Run the binary with ONLY the given env vars (plus CI=true, so a bug that
/// reaches a ceremony fails fast instead of prompting). A hang means a
/// ceremony started where none should: kill and fail rather than wedge the
/// suite.
fn keytap(envs: &[(&str, &str)], args: &[&str]) -> Output {
    let child = Command::new(BIN)
        .args(args)
        .env_clear()
        .env("CI", "true")
        .envs(envs.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
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

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// A state directory whose file store carries an active-root marker: the
/// exact trace a previous `keytap init` (or `remember`) leaves behind.
#[cfg(target_os = "linux")]
fn initialized_state_dir(tag: &str) -> std::path::PathBuf {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    let dir = std::env::temp_dir().join(format!("keytap-init-guard-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("keytap")).unwrap();
    let marker = BASE64.encode(b"keytap-root-v1:00112233445566778899aabbccddeeff");
    std::fs::write(
        dir.join("keytap/remembered.json"),
        format!(r#"{{"format":"keytap-file-store-v1","entries":{{"active-root":"{marker}"}}}}"#),
    )
    .unwrap();
    dir
}

/// The guard itself. Linux-only for the same reason as env_keys' store
/// tests: on macOS the root check would also consult the developer's real
/// keychain; here (cleared env, no D-Bus) only the file store answers.
#[cfg(target_os = "linux")]
#[test]
fn reinit_is_refused_without_force() {
    let dir = initialized_state_dir("refuse");
    let state = dir.to_str().unwrap();

    // --prompt gets past the CI ceremony guard, so what dies is the reinit
    // guard: before any ceremony, naming the flag that overrides it.
    let out = keytap(&[("XDG_STATE_HOME", state)], &["init", "--prompt"]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("already set up"), "stderr: {err}");
    assert!(err.contains("--force"), "stderr: {err}");

    // The refusal must leave the store exactly as it found it.
    let store = std::fs::read_to_string(dir.join("keytap/remembered.json")).unwrap();
    assert!(store.contains("active-root"), "store was modified: {store}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// --force overrides the reinit guard, never the CI one: headless jobs still
/// refuse the ceremony itself unless --prompt asks for it.
#[test]
fn force_does_not_bypass_the_ci_guard() {
    let out = keytap(&[], &["init", "--force"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("--prompt"), "stderr: {}", stderr(&out));
}
