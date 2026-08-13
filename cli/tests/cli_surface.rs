//! Process-level checks for keytap's intentionally tiny command surface.
//!
//! Every invocation here exits during argument parsing, help rendering, or
//! version rendering. None can reach a passkey ceremony.

use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_keytap");

fn keytap(args: &[&str]) -> Output {
    let child = Command::new(BIN)
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_or_kill(child, args)
}

fn wait_or_kill(mut child: Child, args: &[&str]) -> Output {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("keytap {args:?} reached execution instead of exiting during parsing");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

fn listed_commands(help: &str) -> Vec<String> {
    let mut in_commands = false;
    let mut commands = Vec::new();

    for line in help.lines() {
        let trimmed = line.trim();
        if !in_commands {
            if matches!(trimmed, "Commands" | "Commands:") {
                in_commands = true;
            }
            continue;
        }

        if trimmed.is_empty() {
            if !commands.is_empty() {
                break;
            }
            continue;
        }

        let Some(command_line) = line.strip_prefix("  ") else {
            break;
        };
        if command_line.starts_with(' ') || command_line.starts_with('\t') {
            continue;
        }
        if let Some(command) = command_line.split_whitespace().next() {
            commands.push(command.to_string());
        }
    }

    commands
}

#[test]
fn top_level_help_lists_exactly_the_three_public_commands() {
    let output = keytap(&["--help"]);
    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr(&output));
    assert!(output.stderr.is_empty(), "stderr: {}", stderr(&output));

    let help = stdout(&output);
    assert_eq!(
        listed_commands(&help),
        ["init", "public", "reveal"].map(str::to_string)
    );
}

#[test]
fn version_uses_the_keytap_binary_and_package_version() {
    let output = keytap(&["--version"]);
    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr(&output));
    assert!(output.stderr.is_empty(), "stderr: {}", stderr(&output));
    assert_eq!(
        stdout(&output),
        format!("keytap {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn unknown_commands_are_parser_errors() {
    let output = keytap(&["unknown"]);
    assert_eq!(output.status.code(), Some(2), "stderr: {}", stderr(&output));
    assert!(output.stdout.is_empty(), "stdout: {}", stdout(&output));
    let error = stderr(&output);
    assert!(error.contains("unrecognized subcommand"), "stderr: {error}");
    assert!(error.contains("unknown"), "stderr: {error}");
}

#[test]
fn subcommand_help_documents_the_complete_parser_surface() {
    let init = keytap(&["init", "--help"]);
    assert_eq!(init.status.code(), Some(0), "stderr: {}", stderr(&init));
    assert!(init.stderr.is_empty(), "stderr: {}", stderr(&init));
    let init_help = stdout(&init);
    assert!(
        init_help.contains("Usage: keytap init"),
        "help: {init_help}"
    );
    assert!(init_help.contains("--force"), "help: {init_help}");

    for command in ["public", "reveal"] {
        let output = keytap(&[command, "--help"]);
        assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr(&output));
        assert!(output.stderr.is_empty(), "stderr: {}", stderr(&output));
        let help = stdout(&output);
        assert!(
            help.contains(&format!("Usage: keytap {command}")),
            "help for {command}: {help}"
        );
        assert!(help.contains("[NAME]"), "help for {command}: {help}");
        assert!(help.contains("--as <FORMAT>"), "help for {command}: {help}");
        assert!(
            help.contains("default: default"),
            "help for {command}: {help}"
        );
        assert!(help.contains("default: hex"), "help for {command}: {help}");
        for format in ["hex", "base64", "age", "ssh"] {
            assert!(
                help.contains(format),
                "{format:?} missing from {command} help: {help}"
            );
        }
    }
}

#[test]
fn unsupported_output_formats_fail_during_parsing() {
    for command in ["public", "reveal"] {
        let output = keytap(&[command, "--as", "raw"]);
        assert_eq!(output.status.code(), Some(2), "stderr: {}", stderr(&output));
        assert!(output.stdout.is_empty(), "stdout: {}", stdout(&output));
        let error = stderr(&output);
        assert!(error.contains("invalid value 'raw'"), "stderr: {error}");
        for format in ["hex", "base64", "age", "ssh"] {
            assert!(
                error.contains(format),
                "{format:?} missing from stderr: {error}"
            );
        }
    }
}
