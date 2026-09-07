//! Envtap's passkey is Keytap's: the named key `envtap`.
//!
//! When this executable is invoked as `envtap`, the env-file CLI in the
//! `envtap` crate runs against this implementation, which uses the same
//! remembered-key store and passkey ceremonies as `keytap remember envtap`,
//! `keytap reveal envtap --as age`, and `keytap forget envtap`.

use age::x25519;
use envtap::{Forgotten, Passkey};

use crate::{nearby_identity, remember};

/// The Keytap key name Envtap derives its identity from. Part of every
/// grant ever written; changing it changes every user's key.
pub const KEY_NAME: &str = "envtap";

pub struct KeytapPasskey;

impl Passkey for KeytapPasskey {
    fn remembered(&self) -> Result<Option<x25519::Identity>, String> {
        keytap_core::prf_salt_for_name(KEY_NAME).map_err(|error| error.to_string())?;
        let Some(raw_key) = remember::lookup(KEY_NAME) else {
            return Ok(None);
        };
        keytap_core::encrypt::identity(&raw_key)
            .map(Some)
            .map_err(|error| error.to_string())
    }

    fn has_passkey(&self) -> Result<bool, String> {
        match nearby_identity::remembered_scope()? {
            nearby_identity::RememberedScope::Uninitialized(_) => Ok(false),
            nearby_identity::RememberedScope::Current(_) => Ok(true),
        }
    }

    fn init(&self) -> Result<(), String> {
        crate::init(false);
        Ok(())
    }

    fn remember(&self) -> Result<(), String> {
        crate::remember_key(KEY_NAME);
        Ok(())
    }

    fn forget(&self) -> Result<Forgotten, String> {
        match remember::try_forget(KEY_NAME) {
            Ok(true) => Ok(Forgotten::Yes),
            Ok(false) => Ok(Forgotten::Nothing),
            Err(error) if error.contains("could not determine the current passkey identity") => {
                Ok(Forgotten::Nothing)
            }
            Err(error) => Err(error),
        }
    }
}

/// Whether this executable was invoked as `envtap`: the same binary is
/// installed under both names, and the name is the only switch.
pub fn invoked_as_envtap() -> bool {
    std::env::args_os()
        .next()
        .map(std::path::PathBuf::from)
        .and_then(|program| program.file_stem().map(|stem| stem == "envtap"))
        .unwrap_or(false)
}
