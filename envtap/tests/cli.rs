#![cfg(unix)]

use age::secrecy::ExposeSecret;
use age::x25519;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

const ENVTAP: &str = env!("CARGO_BIN_EXE_envtap-fake");
const ENV_PROGRAM: &str = "/usr/bin/env";
const FILE: &str = "tap.env";

struct TestIdentity {
    secret: String,
    recipient: String,
    path: PathBuf,
}

impl TestIdentity {
    fn generate(directory: &Path, name: &str) -> Self {
        let identity = x25519::Identity::generate();
        let secret = identity.to_string().expose_secret().to_owned();
        let recipient = identity.to_public().to_string();
        let path = directory.join(format!("{name}.key"));
        fs::write(&path, format!("# test identity\n{secret}\n")).unwrap();
        Self {
            secret,
            recipient,
            path,
        }
    }
}

struct Project {
    _temporary: TempDir,
    root: PathBuf,
    state: PathBuf,
    owner: TestIdentity,
    /// The identity the fake passkey derives as its `envtap` key.
    passkey: TestIdentity,
    fake_passkey_dir: PathBuf,
}

impl Project {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("repo");
        fs::create_dir_all(root.join(".git")).unwrap();
        let state = temporary.path().join("state");
        fs::create_dir_all(&state).unwrap();
        let owner = TestIdentity::generate(temporary.path(), "owner");
        let passkey = TestIdentity::generate(temporary.path(), "passkey");
        let fake_passkey_dir = temporary.path().join("fake-passkey");
        fs::create_dir_all(&fake_passkey_dir).unwrap();
        fs::write(
            fake_passkey_dir.join("secret"),
            format!("{}\n", passkey.secret),
        )
        .unwrap();
        Self {
            _temporary: temporary,
            root,
            state,
            owner,
            passkey,
            fake_passkey_dir,
        }
    }

    fn passkey_calls(&self) -> String {
        fs::read_to_string(self.fake_passkey_dir.join("calls")).unwrap_or_default()
    }

    /// A command with no passkey login, no identity environment, and a
    /// deterministic user name.
    fn cli(&self) -> Command {
        self.cli_in(&self.root)
    }

    fn cli_in(&self, directory: &Path) -> Command {
        let mut command = Command::new(ENVTAP);
        command
            .current_dir(directory)
            .env_remove("ENVTAP_IDENTITY")
            .env_remove("CI")
            .env("HOME", self.state.join("home"))
            .env("XDG_STATE_HOME", &self.state)
            .env("USER", "tester")
            .env("ENVTAP_FAKE_PASSKEY_DIR", &self.fake_passkey_dir);
        command
    }

    /// A command running as the owner through an explicit identity file.
    fn owner(&self) -> Command {
        self.as_identity(&self.owner)
    }

    fn as_identity(&self, identity: &TestIdentity) -> Command {
        let mut command = self.cli();
        command.arg("-i").arg(&identity.path);
        command
    }

    fn file(&self) -> PathBuf {
        self.root.join(FILE)
    }

    /// The path as Envtap prints it (the temporary root may be a symlink).
    fn shown_file(&self) -> PathBuf {
        fs::canonicalize(self.file()).unwrap()
    }

    fn text(&self) -> String {
        fs::read_to_string(self.file()).unwrap()
    }

    fn set(&self, identity: &TestIdentity, name: &str, value: &str) -> Output {
        let mut command = self.as_identity(identity);
        command.args(["set", name]);
        let result = with_input(&mut command, &format!("{value}\n"));
        assert_success(&result);
        result
    }

    fn environment(&self, identity: &TestIdentity) -> BTreeMap<String, String> {
        let mut command = self.as_identity(identity);
        command.args(["run", "--", ENV_PROGRAM]);
        let result = output(&mut command);
        assert_success(&result);
        environment_from(&result)
    }
}

fn with_input(command: &mut Command, input: &str) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn output(command: &mut Command) -> Output {
    command.stdin(Stdio::null()).output().unwrap()
}

fn stdout(result: &Output) -> String {
    String::from_utf8_lossy(&result.stdout).into_owned()
}

fn stderr(result: &Output) -> String {
    String::from_utf8_lossy(&result.stderr).into_owned()
}

fn assert_success(result: &Output) {
    assert!(
        result.status.success(),
        "command failed with {}\nstdout:\n{}\nstderr:\n{}",
        result.status,
        stdout(result),
        stderr(result)
    );
}

fn assert_failure(result: &Output, expected: &str) {
    assert!(!result.status.success(), "command unexpectedly succeeded");
    assert!(
        stderr(result).contains(expected),
        "stderr did not contain {expected:?}:\n{}",
        stderr(result)
    );
}

fn write_executable(path: &Path, source: &str) {
    fs::write(path, source).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).unwrap();
}

fn environment_from(result: &Output) -> BTreeMap<String, String> {
    stdout(result)
        .lines()
        .filter_map(|line| {
            let (name, value) = line.split_once('=')?;
            Some((name.to_owned(), value.to_owned()))
        })
        .collect()
}

fn value_line<'a>(text: &'a str, name: &str) -> &'a str {
    text.lines()
        .find(|line| line.starts_with(&format!("{name}=")))
        .unwrap_or_else(|| panic!("{name} is not in the file:\n{text}"))
}

fn wait_for_path(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn set_creates_a_dotenv_shaped_file_and_round_trips() {
    let project = Project::new();
    let secret = "postgres://user:plaintext-password@localhost/app";

    let result = project.set(&project.owner, "DATABASE_URL", secret);
    let messages = stderr(&result);
    assert!(messages.contains(&format!("Created {}", project.shown_file().display())));
    assert!(messages.contains("granted your key as tester"));
    assert!(messages.contains("Added DATABASE_URL"));

    let text = project.text();
    let lines: Vec<&str> = text.lines().collect();
    assert!(lines[0].starts_with("#: envtap v1 "));
    assert!(lines[1].starts_with(&format!("#: grant tester {} ", project.owner.recipient)));
    assert!(value_line(&text, "DATABASE_URL").starts_with("DATABASE_URL=envtap:v1:"));
    assert!(!text.contains("plaintext-password"));
    assert!(!text.contains(&project.owner.secret));

    let mut command = project.owner();
    command.args(["get", "DATABASE_URL"]);
    let result = output(&mut command);
    assert_success(&result);
    assert_eq!(stdout(&result), format!("{secret}\n"));
    assert_eq!(
        project
            .environment(&project.owner)
            .get("DATABASE_URL")
            .map(String::as_str),
        Some(secret)
    );

    let before = project.text();
    let result = project.set(&project.owner, "DATABASE_URL", secret);
    assert!(stderr(&result).contains("DATABASE_URL is unchanged"));
    assert_eq!(
        project.text(),
        before,
        "an unchanged value must not rewrite the file"
    );

    project.set(&project.owner, "API_TOKEN", "token-value");
    let result = project.set(&project.owner, "DATABASE_URL", "replacement");
    assert!(stderr(&result).contains("Replaced DATABASE_URL"));
    let after = project.text();
    let changed: Vec<&str> = before
        .lines()
        .zip(after.lines().filter(|line| !line.starts_with("API_TOKEN=")))
        .filter(|(b, a)| b != a)
        .map(|(_, a)| a)
        .collect();
    assert_eq!(changed.len(), 1);
    assert!(changed[0].starts_with("DATABASE_URL="));
    assert!(after.find("API_TOKEN=").unwrap() < after.find("DATABASE_URL=").unwrap());
}

#[test]
fn status_reports_the_file_key_access_and_grants() {
    let project = Project::new();
    project.set(&project.owner, "SECRET", "hidden");
    project.set(&project.owner, "PORT", "3000");

    let mut command = project.owner();
    command.arg("status");
    let result = output(&mut command);
    assert_success(&result);
    let report = stdout(&result);
    assert!(report.contains(&format!("File     {}", project.shown_file().display())));
    assert!(report.contains(&format!("Key      {} (from", project.owner.recipient)));
    assert!(report.contains("Access   granted as tester"));
    assert!(report.contains("Values   2\n  PORT\n  SECRET\n"));
    assert!(report.contains(&format!("tester  {}", project.owner.recipient)));
    assert!(!project.text().contains("3000"), "every value is encrypted");
}

#[test]
fn files_are_discovered_upward_and_selected_by_env_or_path() {
    let project = Project::new();
    project.set(&project.owner, "ROOT_VALUE", "from-root");
    let nested = project.root.join("one/two");
    fs::create_dir_all(&nested).unwrap();

    let mut command = project.cli_in(&nested);
    command
        .arg("-i")
        .arg(&project.owner.path)
        .args(["set", "NESTED"]);
    assert_success(&with_input(&mut command, "from-nested\n"));
    assert!(!nested.join(FILE).exists());
    assert!(project.text().contains("NESTED="));

    let mut command = project.cli_in(&nested);
    command
        .arg("-i")
        .arg(&project.owner.path)
        .args(["-e", "production", "set", "PROD_ONLY"]);
    let result = with_input(&mut command, "prod\n");
    assert_success(&result);
    assert!(nested.join("tap.production.env").is_file());
    assert!(!project.text().contains("PROD_ONLY="));

    let mut command = project.cli_in(&nested);
    command
        .arg("-i")
        .arg(&project.owner.path)
        .args(["-e", "production", "run", "--", ENV_PROGRAM]);
    let result = output(&mut command);
    assert_success(&result);
    let environment = environment_from(&result);
    assert_eq!(
        environment.get("PROD_ONLY").map(String::as_str),
        Some("prod")
    );
    assert!(!environment.contains_key("ROOT_VALUE"));

    let explicit = project.root.join("elsewhere.env");
    let mut command = project.owner();
    command.arg("-f").arg(&explicit).args(["set", "EXPLICIT"]);
    assert_success(&with_input(&mut command, "x\n"));
    assert!(explicit.is_file());

    let outside = project._temporary.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    let mut command = project.cli_in(&outside);
    command
        .arg("-i")
        .arg(&project.owner.path)
        .args(["get", "ROOT_VALUE"]);
    assert_failure(&output(&mut command), "no tap.env found");
}

#[test]
fn grant_lets_a_second_key_read_and_is_idempotent() {
    let project = Project::new();
    let sam = TestIdentity::generate(&project.root, "sam");
    let eve = TestIdentity::generate(&project.root, "eve");
    project.set(&project.owner, "SHARED", "for-sam");

    let mut command = project.as_identity(&eve);
    command.args(["run", "--", ENV_PROGRAM]);
    let result = output(&mut command);
    assert_failure(&result, "is not granted access");
    assert!(stderr(&result).contains(&format!("envtap grant tester {}", eve.recipient)));

    let mut command = project.owner();
    command.args(["grant", "sam", &sam.recipient]);
    let result = output(&mut command);
    assert_success(&result);
    assert_eq!(stderr(&result), "Granted sam access\n");
    assert_eq!(
        project.environment(&sam).get("SHARED").map(String::as_str),
        Some("for-sam")
    );

    let before = project.text();
    let mut command = project.owner();
    command.args(["grant", "sam", &sam.recipient]);
    let result = output(&mut command);
    assert_success(&result);
    assert_eq!(stderr(&result), "sam already has access\n");
    assert_eq!(project.text(), before);

    let mut command = project.owner();
    command.args(["grant", "someone-else", &sam.recipient]);
    assert_failure(&output(&mut command), "already has access as `sam`");
    let mut command = project.owner();
    command.args(["grant", "sam", &eve.recipient]);
    assert_failure(&output(&mut command), "already names a different key");
    assert_eq!(project.text(), before);

    let mut command = project.as_identity(&sam);
    command.arg("status");
    let result = output(&mut command);
    assert_success(&result);
    assert!(stdout(&result).contains("Access   granted as sam"));
}

#[test]
fn revoke_rotates_the_key_and_rotate_keeps_values() {
    let project = Project::new();
    let sam = TestIdentity::generate(&project.root, "sam");
    project.set(&project.owner, "TOKEN", "t");
    let mut command = project.owner();
    command.args(["grant", "sam", &sam.recipient]);
    assert_success(&output(&mut command));
    let before = project.text();

    let mut command = project.owner();
    command.args(["revoke", "tester"]);
    assert_failure(&output(&mut command), "it is the key you are using");
    let mut command = project.owner();
    command.args(["revoke", "nobody"]);
    assert_failure(&output(&mut command), "nobody is granted as `nobody`");

    let mut command = project.owner();
    command.args(["revoke", "sam"]);
    let result = output(&mut command);
    assert_success(&result);
    assert!(stderr(&result).contains("Git history"));
    let after = project.text();
    assert!(!after.contains("#: grant sam"));
    assert_ne!(value_line(&before, "TOKEN"), value_line(&after, "TOKEN"));
    let mut command = project.as_identity(&sam);
    command.args(["get", "TOKEN"]);
    assert_failure(&output(&mut command), "is not granted access");
    assert_eq!(
        project
            .environment(&project.owner)
            .get("TOKEN")
            .map(String::as_str),
        Some("t")
    );

    let mut command = project.owner();
    command.arg("rotate");
    assert_success(&output(&mut command));
    let rotated = project.text();
    assert_ne!(value_line(&after, "TOKEN"), value_line(&rotated, "TOKEN"));
    assert_ne!(after.lines().nth(1), rotated.lines().nth(1));
    assert_eq!(
        project
            .environment(&project.owner)
            .get("TOKEN")
            .map(String::as_str),
        Some("t")
    );
}

#[test]
fn unset_removes_the_line_and_leaves_inherited_values_alone() {
    let project = Project::new();
    project.set(&project.owner, "REMOVE_ME", "vault-value");
    project.set(&project.owner, "KEEP_ME", "kept");

    let mut command = project.owner();
    command.args(["unset", "REMOVE_ME"]);
    let result = output(&mut command);
    assert_success(&result);
    assert_eq!(stderr(&result), "Removed REMOVE_ME\n");
    assert!(!project.text().contains("REMOVE_ME"));

    let mut command = project.owner();
    command
        .args(["run", "--", ENV_PROGRAM])
        .env("REMOVE_ME", "inherited");
    let result = output(&mut command);
    assert_success(&result);
    let environment = environment_from(&result);
    assert_eq!(
        environment.get("REMOVE_ME").map(String::as_str),
        Some("inherited")
    );
    assert_eq!(environment.get("KEEP_ME").map(String::as_str), Some("kept"));

    let before = project.text();
    let mut command = project.owner();
    command.args(["unset", "MISSING"]);
    assert_failure(&output(&mut command), "`MISSING` is not set");
    assert_eq!(project.text(), before);
}

#[test]
fn import_and_export_round_trip_through_every_format() {
    let project = Project::new();
    let dotenv = project.root.join(".env");
    fs::write(
        &dotenv,
        "# local settings\nexport DATABASE_URL=postgres://localhost/app\nMULTI=\"first\nsecond\"\nQUOTED='keep # this'\nEMPTY=\n",
    )
    .unwrap();

    let mut command = project.owner();
    command.arg("import").arg(&dotenv);
    let result = output(&mut command);
    assert_success(&result);
    assert!(stderr(&result).contains("Imported 4 variables"));
    assert!(stderr(&result).contains("4 added"));
    let text = project.text();
    assert!(!text.contains("postgres://localhost/app"));
    assert!(!text.contains("keep # this"));

    let mut command = project.owner();
    command.arg("export");
    let result = output(&mut command);
    assert_success(&result);
    assert_eq!(
        stdout(&result),
        "DATABASE_URL=postgres://localhost/app\nEMPTY=\"\"\nMULTI=\"first\\nsecond\"\nQUOTED=\"keep # this\"\n"
    );

    let mut command = project.owner();
    command.args(["export", "--format", "shell"]);
    let result = output(&mut command);
    assert_success(&result);
    let script = format!("{}\nprintf '%s|%s' \"$MULTI\" \"$QUOTED\"", stdout(&result));
    let shell = Command::new("sh").arg("-c").arg(&script).output().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&shell.stdout),
        "first\nsecond|keep # this"
    );

    fs::write(&dotenv, "DATABASE_URL=changed\nNEW=1\n").unwrap();
    let mut command = project.owner();
    command.arg("import").arg(&dotenv);
    let result = output(&mut command);
    assert_success(&result);
    assert!(stderr(&result).contains("1 added, 1 replaced"));

    fs::write(&dotenv, "BAD-NAME=1\n").unwrap();
    let mut command = project.owner();
    command.arg("import").arg(&dotenv);
    assert_failure(&output(&mut command), "line 1");
}

#[test]
fn run_overrides_matching_values_and_scrubs_the_identity_environment() {
    let project = Project::new();
    project.set(&project.owner, "OVERRIDE_ME", "from-vault");

    let mut command = project.cli();
    command
        .args(["run", "--", ENV_PROGRAM])
        .env("ENVTAP_IDENTITY", &project.owner.secret)
        .env("OVERRIDE_ME", "from-parent")
        .env("PRESERVE_ME", "still-here");
    let result = output(&mut command);
    assert_success(&result);
    let environment = environment_from(&result);
    assert_eq!(
        environment.get("OVERRIDE_ME").map(String::as_str),
        Some("from-vault")
    );
    assert_eq!(
        environment.get("PRESERVE_ME").map(String::as_str),
        Some("still-here")
    );
    assert!(!environment.contains_key("ENVTAP_IDENTITY"));
}

#[test]
fn the_identity_environment_cannot_create_a_file() {
    let project = Project::new();
    let mut command = project.cli();
    command
        .args(["set", "X"])
        .env("ENVTAP_IDENTITY", &project.owner.secret);
    assert_failure(
        &with_input(&mut command, "v\n"),
        "ENVTAP_IDENTITY cannot create a file",
    );
    assert!(!project.file().exists());

    let mut command = project.cli();
    command.args(["get", "X"]);
    assert_failure(&output(&mut command), "no tap.env found");
}

#[test]
fn grant_ci_stores_a_working_key_and_commits_only_after_storage_succeeds() {
    let project = Project::new();
    project.set(&project.owner, "CI_VALUE", "visible-in-ci");

    let store = project.root.join("store-credential");
    write_executable(
        &store,
        r#"#!/bin/sh
set -eu
if [ "${ENVTAP_IDENTITY+x}" = x ]; then
    echo "identity environment reached storage command" >&2
    exit 90
fi
IFS= read -r credential
printf '%s\n' "$credential" > "$1"
"#,
    );
    let stored = project.root.join("stored-ci-identity");
    let mut command = project.owner();
    command
        .args([
            OsStr::new("grant-ci"),
            OsStr::new("github-actions"),
            OsStr::new("--"),
        ])
        .arg(&store)
        .arg(&stored)
        .env("ENVTAP_IDENTITY", "must-not-reach-storage");
    let result = output(&mut command);
    assert_success(&result);
    assert_eq!(
        stderr(&result),
        "Granted github-actions access with a new key\n"
    );

    let credential = fs::read_to_string(&stored).unwrap();
    let ci_identity = x25519::Identity::from_str(credential.trim()).unwrap();
    let text = project.text();
    assert!(text.contains(&format!(
        "#: grant github-actions {} ",
        ci_identity.to_public()
    )));
    assert!(!text.contains(credential.trim()));

    let mut command = project.cli();
    command
        .args(["run", "--", ENV_PROGRAM])
        .env("ENVTAP_IDENTITY", credential.trim());
    let result = output(&mut command);
    assert_success(&result);
    assert_eq!(
        environment_from(&result)
            .get("CI_VALUE")
            .map(String::as_str),
        Some("visible-in-ci")
    );

    let failing = project.root.join("failing-store");
    write_executable(&failing, "#!/bin/sh\nIFS= read -r credential\nexit 23\n");
    let before = project.text();
    let mut command = project.owner();
    command
        .args([
            OsStr::new("grant-ci"),
            OsStr::new("broken"),
            OsStr::new("--"),
        ])
        .arg(&failing);
    let result = output(&mut command);
    assert_failure(&result, "failed with exit status: 23");
    assert!(stderr(&result).contains("was not changed"));
    assert_eq!(project.text(), before);

    let mut command = project.owner();
    command.args(["grant-ci", "printed", "--", "cat"]);
    let result = output(&mut command);
    assert_success(&result);
    assert!(stdout(&result).starts_with("AGE-SECRET-KEY-1"));
}

#[test]
fn concurrent_grant_ci_with_the_same_label_stores_only_the_committed_key() {
    let project = Project::new();
    project.set(&project.owner, "CI_VALUE", "visible-in-ci");
    let store = project.root.join("delayed-store");
    write_executable(
        &store,
        r#"#!/bin/sh
set -eu
touch "$2"
sleep "$3"
IFS= read -r credential
printf '%s\n' "$credential" > "$1"
"#,
    );
    let stored = project.root.join("stored-racing-identity");
    let first_marker = project.root.join("first-started");
    let second_marker = project.root.join("second-started");

    let mut first = project.owner();
    first
        .args([
            OsStr::new("grant-ci"),
            OsStr::new("same-label"),
            OsStr::new("--"),
        ])
        .arg(&store)
        .arg(&stored)
        .arg(&first_marker)
        .arg("0.5")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let first = first.spawn().unwrap();
    wait_for_path(&first_marker);

    let mut second = project.owner();
    second
        .args([
            OsStr::new("grant-ci"),
            OsStr::new("same-label"),
            OsStr::new("--"),
        ])
        .arg(&store)
        .arg(&stored)
        .arg(&second_marker)
        .arg("0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let second = second.spawn().unwrap();

    let first = first.wait_with_output().unwrap();
    let second = second.wait_with_output().unwrap();
    assert_success(&first);
    assert_failure(&second, "already names a different key");
    assert!(
        !second_marker.exists(),
        "the losing storage command was started"
    );

    let credential = fs::read_to_string(&stored).unwrap();
    let mut command = project.cli();
    command
        .args(["run", "--", ENV_PROGRAM])
        .env("ENVTAP_IDENTITY", credential.trim());
    let result = output(&mut command);
    assert_success(&result);
    assert_eq!(
        environment_from(&result)
            .get("CI_VALUE")
            .map(String::as_str),
        Some("visible-in-ci")
    );
}

#[test]
fn tampered_values_are_rejected() {
    let project = Project::new();
    project.set(&project.owner, "ONE", "1");
    project.set(&project.owner, "TWO", "2");
    let text = project.text();
    let one = value_line(&text, "ONE").to_owned();
    let two = value_line(&text, "TWO").to_owned();

    let swapped = text
        .replace(&one, &format!("ONE={}", &two[4..]))
        .replace(&two, &format!("TWO={}", &one[4..]));
    fs::write(project.file(), swapped).unwrap();
    let mut command = project.owner();
    command.args(["get", "ONE"]);
    assert_failure(&output(&mut command), "integrity check failed");

    let mut edited = text.clone();
    let index = edited.find("ONE=envtap:v1:").unwrap() + "ONE=envtap:v1:".len() + 20;
    let original = edited.as_bytes()[index];
    let replacement = if original == b'A' { b'B' } else { b'A' };
    edited.replace_range(
        index..index + 1,
        std::str::from_utf8(&[replacement]).unwrap(),
    );
    fs::write(project.file(), edited).unwrap();
    let mut command = project.owner();
    command.args(["get", "TWO"]);
    assert_failure(&output(&mut command), "`ONE` does not authenticate");
}

#[test]
fn the_merge_driver_merges_independent_changes_and_names_conflicts() {
    let project = Project::new();
    project.set(&project.owner, "SHARED", "base");
    project.set(&project.owner, "OURS_ONLY", "base");
    let base = project.root.join("base.env");
    fs::copy(project.file(), &base).unwrap();

    let ours = project.root.join("ours.env");
    fs::copy(&base, &ours).unwrap();
    let mut command = project.owner();
    command.arg("-f").arg(&ours).args(["set", "OURS_ONLY"]);
    assert_success(&with_input(&mut command, "ours\n"));

    let theirs = project.root.join("theirs.env");
    fs::copy(&base, &theirs).unwrap();
    let mut command = project.owner();
    command.arg("-f").arg(&theirs).args(["set", "THEIRS_NEW"]);
    assert_success(&with_input(&mut command, "theirs\n"));

    let mut command = project.owner();
    command.arg("merge").arg(&base).arg(&ours).arg(&theirs);
    let result = output(&mut command);
    assert_success(&result);
    let mut command = project.owner();
    command.arg("-f").arg(&ours).args(["export"]);
    let result = output(&mut command);
    assert_success(&result);
    assert_eq!(
        stdout(&result),
        "OURS_ONLY=ours\nSHARED=base\nTHEIRS_NEW=theirs\n"
    );

    let mut command = project.owner();
    command.arg("-f").arg(&theirs).args(["set", "OURS_ONLY"]);
    assert_success(&with_input(&mut command, "conflict\n"));
    let mut command = project.owner();
    command.arg("merge").arg(&base).arg(&ours).arg(&theirs);
    let result = output(&mut command);
    assert_eq!(result.status.code(), Some(1));
    assert!(stderr(&result).contains("both branches changed OURS_ONLY"));
}

/// A PATH on which `envtap` names this crate's test binary, so git's merge
/// driver and textconv find it the way they find an installed one.
fn path_with_envtap(bin: &Path) -> String {
    fs::create_dir_all(bin).unwrap();
    let link = bin.join("envtap");
    if !link.exists() {
        std::os::unix::fs::symlink(ENVTAP, &link).unwrap();
    }
    format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    )
}

fn git(directory: &Path, path: &str, args: &[&str]) -> Output {
    let result = Command::new("git")
        .current_dir(directory)
        .args(args)
        .env("PATH", path)
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.com")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.com")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", directory)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "git {} failed:\n{}",
        args.join(" "),
        stderr(&result)
    );
    result
}

#[test]
fn setup_git_makes_real_git_merges_and_diffs_work() {
    let temporary = tempfile::tempdir().unwrap();
    let repo = temporary.path().join("repo");
    fs::create_dir_all(&repo).unwrap();
    let path = path_with_envtap(&temporary.path().join("bin"));
    git(&repo, &path, &["init", "-q", "-b", "main"]);
    let owner = TestIdentity::generate(temporary.path(), "owner");
    let mut project = Project::new();
    project.root = repo.clone();
    project.owner = owner;

    project.set(&project.owner, "SHARED", "base");
    let mut command = project.owner();
    command.arg("setup-git");
    let result = output(&mut command);
    assert_success(&result);
    let attributes = fs::read_to_string(repo.join(".gitattributes")).unwrap();
    assert!(attributes.contains("tap.env merge=envtap diff=envtap"));
    assert!(attributes.contains("tap.*.env merge=envtap diff=envtap"));
    let driver = git(&repo, &path, &["config", "--get", "merge.envtap.driver"]);
    assert_eq!(stdout(&driver).trim(), "envtap merge %O %A %B");
    let mut command = project.owner();
    command.arg("setup-git");
    assert_success(&output(&mut command));
    assert_eq!(
        fs::read_to_string(repo.join(".gitattributes")).unwrap(),
        attributes
    );

    git(&repo, &path, &["add", "."]);
    git(&repo, &path, &["commit", "-q", "-m", "base"]);
    git(&repo, &path, &["checkout", "-q", "-b", "feature"]);
    project.set(&project.owner, "FEATURE", "on-feature");
    git(&repo, &path, &["commit", "-q", "-am", "feature"]);
    git(&repo, &path, &["checkout", "-q", "main"]);
    project.set(&project.owner, "SHARED", "on-main");
    git(&repo, &path, &["commit", "-q", "-am", "main"]);

    let secret = project.owner.secret.clone();
    let merge = Command::new("git")
        .current_dir(&repo)
        .args(["merge", "-q", "--no-edit", "feature"])
        .env("PATH", &path)
        .env("ENVTAP_IDENTITY", &secret)
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.com")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.com")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        merge.status.success(),
        "git merge failed:\n{}",
        stderr(&merge)
    );
    let mut command = project.owner();
    command.arg("export");
    let result = output(&mut command);
    assert_success(&result);
    assert_eq!(stdout(&result), "FEATURE=on-feature\nSHARED=on-main\n");

    let diff = Command::new("git")
        .current_dir(&repo)
        .args(["diff", "HEAD~2", "HEAD", "--", FILE])
        .env("PATH", &path)
        .env("ENVTAP_IDENTITY", &secret)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(diff.status.success(), "git diff failed:\n{}", stderr(&diff));
    let shown = stdout(&diff);
    assert!(shown.contains("+SHARED=on-main"), "{shown}");
    assert!(shown.contains("-SHARED=base"), "{shown}");
}

#[test]
fn login_with_an_identity_file_is_remembered_until_logout() {
    let project = Project::new();
    project.set(&project.owner, "VALUE", "v");

    let mut command = project.cli();
    command.arg("login").arg("-i").arg(&project.owner.path);
    let result = output(&mut command);
    assert_success(&result);
    assert!(stderr(&result).contains(&format!("Your public key: {}", project.owner.recipient)));

    let mut command = project.cli();
    command.arg("public-key");
    let result = output(&mut command);
    assert_success(&result);
    assert_eq!(stdout(&result), format!("{}\n", project.owner.recipient));
    let mut command = project.cli();
    command.args(["get", "VALUE"]);
    let result = output(&mut command);
    assert_success(&result);
    assert_eq!(stdout(&result), "v\n");

    let mut command = project.cli();
    command.arg("logout");
    let result = output(&mut command);
    assert_success(&result);
    assert!(stderr(&result).contains("Forgot the remembered key file"));
    let mut command = project.cli();
    command.arg("public-key");
    assert_failure(
        &output(&mut command),
        "not logged in on this machine; run `envtap login`",
    );
}

#[test]
fn login_and_logout_use_the_passkey() {
    let project = Project::new();
    project.set(&project.owner, "SHARED", "for-the-passkey");
    let mut command = project.owner();
    command.args(["grant", "me", &project.passkey.recipient]);
    assert_success(&output(&mut command));

    let mut command = project.cli();
    command.arg("login");
    assert_failure(&output(&mut command), "no passkey on this machine");

    let mut command = project.cli();
    command.args(["login", "--new"]);
    let result = output(&mut command);
    assert_success(&result);
    assert!(stderr(&result).contains(&format!("Your public key: {}", project.passkey.recipient)));
    assert_eq!(
        project.passkey_calls(),
        "remembered\nremember\ninit\nremember\nremembered\n"
    );

    let mut command = project.cli();
    command.arg("public-key");
    let result = output(&mut command);
    assert_success(&result);
    assert_eq!(stdout(&result), format!("{}\n", project.passkey.recipient));

    let mut command = project.cli();
    command.args(["get", "SHARED"]);
    let result = output(&mut command);
    assert_success(&result);
    assert_eq!(stdout(&result), "for-the-passkey\n");

    let mut command = project.cli();
    command.arg("status");
    let result = output(&mut command);
    assert_success(&result);
    assert!(stdout(&result).contains("from your passkey"));
    assert!(stdout(&result).contains("Access   granted as me"));

    let mut command = project.cli();
    command.arg("login");
    let result = output(&mut command);
    assert_success(&result);
    assert!(stderr(&result).contains("Already logged in with your passkey"));

    let mut command = project.cli();
    command.arg("logout");
    let result = output(&mut command);
    assert_success(&result);
    assert!(stderr(&result).contains("forgot the `envtap` key"));
    let mut command = project.cli();
    command.arg("public-key");
    assert_failure(
        &output(&mut command),
        "not logged in on this machine; run `envtap login`",
    );
}

#[test]
fn run_passes_arguments_literally_and_preserves_exit_status_and_signals() {
    let project = Project::new();
    project.set(&project.owner, "A_VALUE", "irrelevant");

    let recorder = project.root.join("record-arguments");
    write_executable(
        &recorder,
        "#!/bin/sh\nfor argument do\n    printf '<%s>\\n' \"$argument\"\ndone\n",
    );
    let unexpected = project.root.join("shell-expanded-this");
    let literal = [
        "two words".to_owned(),
        "*".to_owned(),
        "$HOME".to_owned(),
        format!("$(touch {})", unexpected.display()),
        ">redirected".to_owned(),
    ];
    let mut command = project.owner();
    command.arg("run").arg("--").arg(&recorder).args(&literal);
    let result = output(&mut command);
    assert_success(&result);
    let expected: String = literal.iter().map(|a| format!("<{a}>\n")).collect();
    assert_eq!(stdout(&result), expected);
    assert!(!unexpected.exists());

    let exit_37 = project.root.join("exit-37");
    write_executable(&exit_37, "#!/bin/sh\nexit 37\n");
    let mut command = project.owner();
    command.arg("run").arg("--").arg(&exit_37);
    assert_eq!(output(&mut command).status.code(), Some(37));

    let signal_self = project.root.join("signal-self");
    write_executable(
        &signal_self,
        "#!/bin/sh\nprintf '%s\\n' \"$$\"\nkill -TERM \"$$\"\nexit 99\n",
    );
    let mut command = project.owner();
    command.arg("run").arg("--").arg(&signal_self);
    let child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let envtap_pid = child.id();
    let result = child.wait_with_output().unwrap();
    assert_eq!(
        stdout(&result).trim(),
        envtap_pid.to_string(),
        "the command must keep the envtap PID"
    );
    assert_eq!(result.status.signal(), Some(libc::SIGTERM));
}

#[test]
fn a_symlink_cannot_be_used_as_the_lock_file() {
    let project = Project::new();
    project.set(&project.owner, "UNCHANGED", "original");
    project.set(&project.owner, "LOCK_CREATED", "original");
    let locks = project.root.join(".git/envtap/locks");
    let lock = fs::read_dir(&locks)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension() == Some(OsStr::new("lock")))
        .expect("mutation did not create its lock file");
    fs::remove_file(&lock).unwrap();
    let target = project.root.join("lock-symlink-target");
    fs::write(&target, "must remain unchanged").unwrap();
    std::os::unix::fs::symlink(&target, lock).unwrap();

    let before = project.text();
    let mut command = project.owner();
    command.args(["set", "ATTACKED"]);
    assert_failure(&with_input(&mut command, "new\n"), "not a regular file");
    assert_eq!(project.text(), before);
    assert_eq!(fs::read_to_string(target).unwrap(), "must remain unchanged");
}

#[test]
fn help_lists_the_workflow_and_hides_git_plumbing() {
    let project = Project::new();
    let mut command = project.cli();
    command.arg("--help");
    let result = output(&mut command);
    assert_success(&result);
    let help = stdout(&result);
    for visible in [
        "login",
        "logout",
        "status",
        "set",
        "get",
        "unset",
        "run",
        "export",
        "import",
        "public-key",
        "grant",
        "revoke",
        "rotate",
        "grant-ci",
        "setup-git",
    ] {
        assert!(
            help.lines()
                .any(|line| line.trim_start().starts_with(visible)),
            "help omitted {visible}:\n{help}"
        );
    }
    for hidden in ["merge", "textconv"] {
        assert!(
            !help
                .lines()
                .any(|line| line.trim_start().starts_with(hidden)),
            "help lists {hidden}"
        );
    }
    assert!(help.contains("-f, --file"));
    assert!(help.contains("-e, --env"));
    assert!(help.contains("-i, --identity"));

    let mut command = project.cli();
    command.args(["login", "--help"]);
    let result = output(&mut command);
    assert_success(&result);
    let help = stdout(&result);
    assert!(help.contains("keytap remember envtap"));
    assert!(help.contains("--new"));
    assert!(help.contains("QR code"));

    let mut command = project.cli();
    command.arg("status");
    let result = output(&mut command);
    assert_success(&result);
    let report = stdout(&result);
    assert!(report.contains("File     none"));
    assert!(report.contains("not logged in"));
}
