//! Thin, uniform access to the OS keychain for remembered keys.
//!
//! Everything keytap stores lives under one keychain service (`keytap`) so
//! entries stay recognizable and auditable next to the user-managed entries
//! the README recommends. The trait exists so `remember.rs` holds all policy
//! (naming, formats, root rotation) as plain testable logic, while this module
//! stays a dumb byte store per platform: the macOS Keychain via the Security
//! framework, the freedesktop Secret Service (GNOME Keyring, KWallet, …) via
//! D-Bus on Linux.

use zeroize::Zeroizing;

/// Keychain service under which every keytap-managed entry is stored.
pub const SERVICE: &str = "keytap";

#[derive(Debug)]
pub enum KeychainError {
    /// No keychain backend exists for this platform (yet). Only constructed
    /// by the fallback platform module, but matched everywhere.
    #[allow(dead_code)]
    Unsupported,
    /// The platform keychain refused the operation (locked, ACL denied,
    /// no Secret Service on the bus, …).
    Backend(String),
}

impl std::fmt::Display for KeychainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeychainError::Unsupported => {
                write!(f, "remembered keys are not supported on this platform (no OS keychain backend)")
            }
            KeychainError::Backend(msg) => write!(f, "keychain error: {msg}"),
        }
    }
}

/// A byte store keyed by keychain account name, scoped to [`SERVICE`].
pub trait Keychain {
    /// Read an entry's value. `Ok(None)` when the account doesn't exist.
    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError>;

    /// Create or overwrite an entry.
    fn set(&mut self, account: &str, value: &[u8]) -> Result<(), KeychainError>;

    /// Delete an entry. Returns whether it existed.
    fn delete(&mut self, account: &str) -> Result<bool, KeychainError>;

    /// Every account name stored under [`SERVICE`], keytap-managed or not.
    /// Callers filter by their own prefixes.
    fn accounts(&self) -> Result<Vec<String>, KeychainError>;
}

/// Open the platform keychain, or learn that this platform has none.
pub fn open() -> Result<impl Keychain, KeychainError> {
    platform::open()
}

#[cfg(target_os = "macos")]
mod platform {
    use super::{Keychain, KeychainError, SERVICE};
    use security_framework::item::{ItemClass, ItemSearchOptions, Limit, SearchResult};
    use security_framework::passwords;
    use zeroize::Zeroizing;

    /// `errSecItemNotFound`: the only Security framework error that is an
    /// answer ("no such entry") rather than a failure.
    const ITEM_NOT_FOUND: i32 = -25300;

    pub struct MacosKeychain;

    pub fn open() -> Result<MacosKeychain, KeychainError> {
        Ok(MacosKeychain)
    }

    fn backend_err(e: security_framework::base::Error) -> KeychainError {
        KeychainError::Backend(e.to_string())
    }

    impl Keychain for MacosKeychain {
        fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
            match passwords::get_generic_password(SERVICE, account) {
                Ok(value) => Ok(Some(Zeroizing::new(value))),
                Err(e) if e.code() == ITEM_NOT_FOUND => Ok(None),
                Err(e) => Err(backend_err(e)),
            }
        }

        fn set(&mut self, account: &str, value: &[u8]) -> Result<(), KeychainError> {
            // set_generic_password updates in place when the item exists.
            passwords::set_generic_password(SERVICE, account, value).map_err(backend_err)
        }

        fn delete(&mut self, account: &str) -> Result<bool, KeychainError> {
            match passwords::delete_generic_password(SERVICE, account) {
                Ok(()) => Ok(true),
                Err(e) if e.code() == ITEM_NOT_FOUND => Ok(false),
                Err(e) => Err(backend_err(e)),
            }
        }

        fn accounts(&self) -> Result<Vec<String>, KeychainError> {
            let results = match ItemSearchOptions::new()
                .class(ItemClass::generic_password())
                .service(SERVICE)
                .load_attributes(true)
                .limit(Limit::All)
                .search()
            {
                Ok(results) => results,
                // An empty result set surfaces as "item not found".
                Err(e) if e.code() == ITEM_NOT_FOUND => return Ok(Vec::new()),
                Err(e) => return Err(backend_err(e)),
            };

            Ok(results
                .iter()
                .filter_map(SearchResult::simplify_dict)
                .filter_map(|attrs| attrs.get("acct").cloned())
                .collect())
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{Keychain, KeychainError, SERVICE};
    use dbus_secret_service::{Collection, EncryptionType, Item, SecretService};
    use std::collections::HashMap;
    use zeroize::Zeroizing;

    pub struct LinuxKeychain {
        service: SecretService,
    }

    pub fn open() -> Result<LinuxKeychain, KeychainError> {
        // DH-encrypt secrets in transit over the session bus.
        let service = SecretService::connect(EncryptionType::Dh).map_err(|e| {
            KeychainError::Backend(format!(
                "couldn't reach the Secret Service (GNOME Keyring / KWallet) on the session bus: {e}"
            ))
        })?;
        Ok(LinuxKeychain { service })
    }

    fn backend_err(e: dbus_secret_service::Error) -> KeychainError {
        KeychainError::Backend(e.to_string())
    }

    impl LinuxKeychain {
        /// The default collection, unlocked. Items searched out of it borrow
        /// it, so each operation opens the collection and finishes with it in
        /// the same scope.
        fn collection(&self) -> Result<Collection<'_>, KeychainError> {
            let collection = self.service.get_default_collection().map_err(backend_err)?;
            collection.ensure_unlocked().map_err(backend_err)?;
            Ok(collection)
        }
    }

    /// Items in `collection` carrying our service attribute, optionally
    /// narrowed to one account.
    fn find<'c>(
        collection: &'c Collection<'_>,
        account: Option<&str>,
    ) -> Result<Vec<Item<'c>>, KeychainError> {
        let mut attributes = HashMap::from([("service", SERVICE)]);
        if let Some(account) = account {
            attributes.insert("account", account);
        }
        collection.search_items(attributes).map_err(backend_err)
    }

    impl Keychain for LinuxKeychain {
        fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
            let collection = self.collection()?;
            match find(&collection, Some(account))?.first() {
                Some(item) => {
                    item.ensure_unlocked().map_err(backend_err)?;
                    Ok(Some(Zeroizing::new(item.get_secret().map_err(backend_err)?)))
                }
                None => Ok(None),
            }
        }

        fn set(&mut self, account: &str, value: &[u8]) -> Result<(), KeychainError> {
            let attributes = HashMap::from([("service", SERVICE), ("account", account)]);
            self.collection()?
                .create_item(
                    &format!("{SERVICE}: {account}"),
                    attributes,
                    value,
                    true, // replace an existing entry with the same attributes
                    "text/plain",
                )
                .map_err(backend_err)?;
            Ok(())
        }

        fn delete(&mut self, account: &str) -> Result<bool, KeychainError> {
            let collection = self.collection()?;
            let items = find(&collection, Some(account))?;
            let existed = !items.is_empty();
            for item in items {
                item.delete().map_err(backend_err)?;
            }
            Ok(existed)
        }

        fn accounts(&self) -> Result<Vec<String>, KeychainError> {
            // User-managed entries under the same service (e.g. the README's
            // secret-tool recipe) may lack an `account` attribute; skip them.
            let collection = self.collection()?;
            Ok(find(&collection, None)?
                .iter()
                .filter_map(|item| item.get_attributes().ok())
                .filter_map(|attrs| attrs.get("account").cloned())
                .collect())
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod platform {
    use super::{Keychain, KeychainError};
    use zeroize::Zeroizing;

    /// Platforms without a keychain backend. Every operation reports
    /// [`KeychainError::Unsupported`]; callers decide whether that is fatal
    /// (`remember`) or a silent no-op (key lookup).
    pub struct UnsupportedKeychain;

    pub fn open() -> Result<UnsupportedKeychain, KeychainError> {
        Err(KeychainError::Unsupported)
    }

    impl Keychain for UnsupportedKeychain {
        fn get(&self, _account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
            Err(KeychainError::Unsupported)
        }

        fn set(&mut self, _account: &str, _value: &[u8]) -> Result<(), KeychainError> {
            Err(KeychainError::Unsupported)
        }

        fn delete(&mut self, _account: &str) -> Result<bool, KeychainError> {
            Err(KeychainError::Unsupported)
        }

        fn accounts(&self) -> Result<Vec<String>, KeychainError> {
            Err(KeychainError::Unsupported)
        }
    }
}

/// In-memory store for exercising `remember.rs` logic without a real keychain.
#[cfg(test)]
pub mod memory {
    use super::{Keychain, KeychainError};
    use std::collections::BTreeMap;
    use zeroize::Zeroizing;

    #[derive(Default)]
    pub struct MemoryKeychain {
        entries: BTreeMap<String, Vec<u8>>,
    }

    impl Keychain for MemoryKeychain {
        fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
            Ok(self.entries.get(account).cloned().map(Zeroizing::new))
        }

        fn set(&mut self, account: &str, value: &[u8]) -> Result<(), KeychainError> {
            self.entries.insert(account.to_string(), value.to_vec());
            Ok(())
        }

        fn delete(&mut self, account: &str) -> Result<bool, KeychainError> {
            Ok(self.entries.remove(account).is_some())
        }

        fn accounts(&self) -> Result<Vec<String>, KeychainError> {
            Ok(self.entries.keys().cloned().collect())
        }
    }
}
