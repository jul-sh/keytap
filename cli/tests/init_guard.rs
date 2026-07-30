//! End-to-end tests of init's refusal to silently replace a passkey. A stored
//! nearby identity proves this machine was initialized; rerunning `keytap
//! init` there must die before any ceremony unless --force is deliberate.

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

/// A state directory containing the credential anchor written by init.
fn initialized_state_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("keytap-init-guard-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("keytap")).unwrap();
    std::fs::write(
        dir.join("keytap/nearby-identity.json"),
        r#"{"format":"keytap-nearby-identity-v3","identity":{"kind":"credential","credentialId":"ABEiM0RVZneImaq7zN3u_w"}}"#,
    )
    .unwrap();
    dir
}

/// The identity check is file-only and must run before any platform ceremony.
#[test]
fn reinit_is_refused_without_force() {
    let dir = initialized_state_dir("refuse");
    let state = dir.to_str().unwrap();

    // --prompt gets past the CI ceremony guard, so what dies is the reinit
    // guard: before any ceremony, naming the flag that overrides it.
    let out = keytap(&[("XDG_STATE_HOME", state)], &["init", "--prompt"]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("already stored"), "stderr: {err}");
    assert!(err.contains("--force"), "stderr: {err}");

    // The refusal must leave the identity exactly as it found it.
    let identity = std::fs::read_to_string(dir.join("keytap/nearby-identity.json")).unwrap();
    assert!(identity.contains("ABEiM0RVZneImaq7zN3u_w"));

    let _ = std::fs::remove_dir_all(&dir);
}

/// --force overrides the reinit guard, never the CI one: headless jobs still
/// refuse the ceremony itself unless --prompt asks for it.
#[test]
fn force_does_not_bypass_the_ci_guard() {
    let out = keytap(&[], &["init", "--force"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("--prompt"),
        "stderr: {}",
        stderr(&out)
    );
}
