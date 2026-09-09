//! One executable, two entrypoints: invoked as `envtap`, the binary runs
//! the env-file CLI on Keytap's passkey.

use std::path::PathBuf;
use std::process::Command;

const KEYTAP: &str = env!("CARGO_BIN_EXE_keytap");

fn state_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("keytap-envtap-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(program: &std::path::Path, args: &[&str], state: &std::path::Path) -> std::process::Output {
    Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", state)
        .env("XDG_STATE_HOME", state)
        .current_dir(state)
        .output()
        .unwrap()
}

#[test]
fn the_envtap_name_selects_the_env_file_cli() {
    let state = state_dir("name");
    // The state directory must stay free for `$XDG_STATE_HOME/envtap/`.
    let bin = state.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let envtap = bin.join("envtap");
    std::os::unix::fs::symlink(KEYTAP, &envtap).unwrap();

    let version = run(&envtap, &["--version"], &state);
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("envtap "));

    let help = run(&envtap, &["login", "--help"], &state);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("keytap remember envtap"));

    // No passkey on this machine: the identity resolves to "not logged in"
    // without starting a ceremony.
    let status = run(&envtap, &["status"], &state);
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    assert!(String::from_utf8_lossy(&status.stdout).contains("not logged in on this machine"));

    let keytap = run(std::path::Path::new(KEYTAP), &["--version"], &state);
    assert!(String::from_utf8_lossy(&keytap.stdout).starts_with("keytap "));
    let _ = std::fs::remove_dir_all(&state);
}
