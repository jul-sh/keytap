//! Encrypted `.env` files with per-person access.
//!
//! This crate is the whole of the `envtap` command except its passkey. The
//! `keytap` executable, invoked as `envtap`, calls [`run`] with a [`Passkey`]
//! backed by Keytap's own identity code; that is the one binary users
//! install. The `envtap-fake` binary runs the same CLI against a file-backed
//! [`Passkey`] for this crate's tests.

mod cli;
mod dotenv;
mod identity;
mod merge;
mod store;
mod vault;

use std::ffi::OsString;
use std::process::ExitCode;

use age::x25519;

/// The named key `envtap` on this machine's passkey, as the host provides
/// it. Every method may prompt except [`Passkey::remembered`], which must
/// never start a ceremony.
pub trait Passkey {
    /// The key remembered for `envtap`. `None` when nothing is remembered.
    fn remembered(&self) -> Result<Option<x25519::Identity>, String>;
    /// Whether this machine already has a passkey record, so `login` can
    /// skip asking whether to create one.
    fn has_passkey(&self) -> Result<bool, String>;
    /// Create the passkey.
    fn init(&self) -> Result<(), String>;
    /// Approve with the passkey and remember the `envtap` key on this
    /// machine.
    fn remember(&self) -> Result<(), String>;
    /// Forget the remembered `envtap` key.
    fn forget(&self) -> Result<Forgotten, String>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Forgotten {
    Yes,
    /// Nothing was remembered, or there is no passkey on this machine.
    Nothing,
}

/// Run the `envtap` command line. `args` includes the program name.
pub fn run(args: impl IntoIterator<Item = OsString>, passkey: &dyn Passkey) -> ExitCode {
    cli::run(args, passkey)
}
