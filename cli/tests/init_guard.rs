//! Non-interactive coverage for init's destructive replacement guard.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_keytap");
const STORED_IDENTITY: &[u8] = br#"{"format":"keytap-nearby-identity-v3","identity":{"kind":"credential","credentialId":"ABEiM0RVZneImaq7zN3u_w"}}"#;

static NEXT_TEMP_DIR: AtomicUsize = AtomicUsize::new(0);

struct TempStateDir(PathBuf);

impl TempStateDir {
    fn initialized() -> Self {
        let sequence = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "keytap-init-guard-{}-{sequence}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(path.join("keytap")).unwrap();
        std::fs::write(path.join("keytap/nearby-identity.json"), STORED_IDENTITY).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn identity_path(&self) -> PathBuf {
        self.0.join("keytap/nearby-identity.json")
    }
}

impl Drop for TempStateDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn init_with_state(state: &Path) -> Output {
    let child = Command::new(BIN)
        .arg("init")
        .env_clear()
        .env("XDG_STATE_HOME", state)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_or_kill(child)
}

fn wait_or_kill(mut child: Child) -> Output {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("keytap init did not honor the stored-record guard");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn existing_record_refuses_plain_init_before_any_ceremony() {
    let state = TempStateDir::initialized();

    // The stored record itself must stop init before an interactive passkey
    // request can begin.
    let output = init_with_state(state.path());

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.starts_with("error: "), "stderr: {stderr}");
    assert!(stderr.contains("already stored"), "stderr: {stderr}");
    assert!(stderr.contains("--force"), "stderr: {stderr}");
    assert_eq!(
        std::fs::read(state.identity_path()).unwrap(),
        STORED_IDENTITY
    );
}
