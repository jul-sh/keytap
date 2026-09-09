//! `envtap` with a file-backed passkey, for this crate's tests only.
//!
//! State lives in `$ENVTAP_FAKE_PASSKEY_DIR`: `secret` holds the age secret
//! key the passkey derives, `passkey` marks that a passkey exists,
//! `remembered` marks that the key is remembered, and `calls` records every
//! method call.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;

use age::x25519;
use envtap::{Forgotten, Passkey};

struct FakePasskey {
    /// `$ENVTAP_FAKE_PASSKEY_DIR`; absent when a test only uses key files.
    directory: Option<PathBuf>,
}

impl FakePasskey {
    fn directory(&self) -> Result<&PathBuf, String> {
        self.directory
            .as_ref()
            .ok_or_else(|| "ENVTAP_FAKE_PASSKEY_DIR is not set".to_owned())
    }

    fn record(&self, call: &str) {
        let Some(directory) = &self.directory else {
            return;
        };
        fs::create_dir_all(directory).ok();
        let mut calls = fs::read_to_string(directory.join("calls")).unwrap_or_default();
        calls.push_str(call);
        calls.push('\n');
        fs::write(directory.join("calls"), calls).ok();
    }

    fn marked(&self, marker: &str) -> bool {
        self.directory
            .as_ref()
            .is_some_and(|directory| directory.join(marker).exists())
    }
}

impl Passkey for FakePasskey {
    fn remembered(&self) -> Result<Option<x25519::Identity>, String> {
        self.record("remembered");
        if !self.marked("remembered") {
            return Ok(None);
        }
        let secret = fs::read_to_string(self.directory()?.join("secret"))
            .map_err(|error| format!("fake passkey has no secret: {error}"))?;
        x25519::Identity::from_str(secret.trim())
            .map(Some)
            .map_err(|_| "fake passkey secret is not an age key".to_owned())
    }

    fn has_passkey(&self) -> Result<bool, String> {
        self.record("has_passkey");
        Ok(self.marked("passkey"))
    }

    fn init(&self) -> Result<(), String> {
        self.record("init");
        fs::write(self.directory()?.join("passkey"), b"").map_err(|error| error.to_string())
    }

    fn remember(&self) -> Result<(), String> {
        self.record("remember");
        if !self.marked("passkey") {
            return Err("no passkey on this machine".to_owned());
        }
        fs::write(self.directory()?.join("remembered"), b"").map_err(|error| error.to_string())
    }

    fn forget(&self) -> Result<Forgotten, String> {
        self.record("forget");
        if self.marked("remembered") {
            fs::remove_file(self.directory()?.join("remembered"))
                .map_err(|error| error.to_string())?;
            Ok(Forgotten::Yes)
        } else {
            Ok(Forgotten::Nothing)
        }
    }
}

fn main() -> ExitCode {
    let directory = std::env::var_os("ENVTAP_FAKE_PASSKEY_DIR").map(PathBuf::from);
    envtap::run(std::env::args_os(), &FakePasskey { directory })
}
