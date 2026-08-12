//! End-to-end contracts for read-only remembered-key inventory. A machine
//! without a v8 identity has no authoritative root, even if an older client
//! left key-store metadata behind.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_keytap");

fn state_dir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("keytap-remembered-{}-{tag}", std::process::id()))
}

fn keytap_remembered(state: &std::path::Path) -> std::process::Output {
    Command::new(BIN)
        .arg("remembered")
        .env_clear()
        .env("XDG_STATE_HOME", state)
        .output()
        .unwrap()
}

#[test]
fn missing_identity_is_empty_even_when_orphaned_entries_exist() {
    let dir = state_dir("uninitialized");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("keytap")).unwrap();
    std::fs::write(
        dir.join("keytap/remembered.json"),
        r#"{
  "format": "keytap-file-store-v1",
  "warning": "Raw keytap keys, NOT encrypted at rest. Remove entries with `keytap forget` or delete this file.",
  "entries": {
    "active-root": "a2V5dGFwLXJvb3QtdjE6b2xk",
    "remember:0123456789abcdef0123456789abcdef:orphaned": "b2xkLWZvcm1hdA=="
  }
}"#,
    )
    .unwrap();

    let output = keytap_remembered(&dir);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "No local passkey identity yet; no remembered keys are available. Run `keytap remember NAME` to remember one.\n"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn malformed_present_identity_remains_an_error() {
    let dir = state_dir("malformed");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("keytap")).unwrap();
    std::fs::write(dir.join("keytap/nearby-identity.json"), "not json").unwrap();

    let output = keytap_remembered(&dir);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("is not a valid passkey record"));

    let _ = std::fs::remove_dir_all(&dir);
}
