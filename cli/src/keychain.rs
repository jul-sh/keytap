//! Thin, uniform access to the OS keychain for remembered keys.
//!
//! Everything keytap stores lives under one keychain service (`keytap`) so
//! entries stay recognizable and auditable next to the user-managed entries
//! the README recommends. The trait exists so `remember.rs` holds all policy
//! (naming, formats, root rotation) as plain testable logic, while this module
//! stays a dumb byte store per platform: the macOS Keychain via the Security
//! framework, the freedesktop Secret Service (GNOME Keyring, KWallet, …) via
//! D-Bus on Linux, plus an opt-in plain-file store (see [`file`]) for
//! machines with neither.

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
        /// The default collection, possibly locked. Attribute searches work
        /// on a locked collection (lookup attributes are not encrypted), so
        /// opening never prompts; operations that need secret values or
        /// writes unlock explicitly, and only once they know there is
        /// something to unlock for. A locked keyring must never pop an
        /// unlock dialog just so keytap can discover it has nothing stored.
        fn collection(&self) -> Result<Collection<'_>, KeychainError> {
            self.service.get_default_collection().map_err(backend_err)
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
                    // Unlock only now that a matching entry is known to
                    // exist: the dialog a locked keyring pops here is for a
                    // key that is about to be used.
                    item.ensure_unlocked().map_err(backend_err)?;
                    Ok(Some(Zeroizing::new(item.get_secret().map_err(backend_err)?)))
                }
                None => Ok(None),
            }
        }

        fn set(&mut self, account: &str, value: &[u8]) -> Result<(), KeychainError> {
            let attributes = HashMap::from([("service", SERVICE), ("account", account)]);
            let collection = self.collection()?;
            // Writes need an unlocked collection; the prompt is justified
            // because the user explicitly asked to store something.
            collection.ensure_unlocked().map_err(backend_err)?;
            collection
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
                item.ensure_unlocked().map_err(backend_err)?;
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

/// Plain-file store: the baseline home for remembered keys. Machines with an
/// OS keychain upgrade past it automatically; everywhere else (headless
/// Linux, servers, containers) `keytap remember` stores here. Same
/// [`Keychain`] contract as the platform backends, but the values sit in a
/// JSON file protected only by file permissions: NOT encrypted at rest,
/// usable by anyone who can read the user's files, and documented as such.
/// Read paths consult it only once it exists.
pub mod file {
    use super::{Keychain, KeychainError};
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use serde_json::{Map, Value};
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use zeroize::Zeroizing;

    const FORMAT: &str = "keytap-file-store-v1";
    const WARNING: &str =
        "Raw keytap keys, NOT encrypted at rest. Remove entries with `keytap forget` or delete this file.";

    /// `$XDG_STATE_HOME/keytap/remembered.json`, defaulting to
    /// `~/.local/state/keytap/remembered.json`. `None` when neither variable
    /// resolves (then there is nowhere sensible to put the store).
    pub fn default_path() -> Option<PathBuf> {
        let state_home = std::env::var_os("XDG_STATE_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .filter(|v| !v.is_empty())
                    .map(|home| PathBuf::from(home).join(".local/state"))
            })?;
        Some(state_home.join("keytap").join("remembered.json"))
    }

    /// The store at the default path, but only if some earlier
    /// `keytap remember` created it. Read paths use this so machines that
    /// never stored a file never touch the filesystem.
    pub fn open_existing() -> Option<FileStore> {
        let path = default_path()?;
        path.is_file().then(|| FileStore { path })
    }

    /// The store at the default path for writing; the parent directory is
    /// created on first use. For `keytap remember` on keychain-less machines.
    pub fn open_default() -> Result<FileStore, KeychainError> {
        match default_path() {
            Some(path) => Ok(FileStore { path }),
            None => Err(KeychainError::Backend(
                "can't locate a state directory for the file store (neither $XDG_STATE_HOME nor $HOME is set)"
                    .to_string(),
            )),
        }
    }

    pub struct FileStore {
        path: PathBuf,
    }

    impl FileStore {
        /// A store at an explicit path, for tests.
        #[cfg(test)]
        pub fn at(path: PathBuf) -> FileStore {
            FileStore { path }
        }

        pub fn path(&self) -> &Path {
            &self.path
        }

        fn corrupt(&self, why: &str) -> KeychainError {
            KeychainError::Backend(format!(
                "{} is not a keytap file store ({why}); move it aside to start fresh",
                self.path.display()
            ))
        }

        /// Every entry in the store; an absent file is an empty store.
        fn read(&self) -> Result<BTreeMap<String, Vec<u8>>, KeychainError> {
            let text = match std::fs::read_to_string(&self.path) {
                Ok(text) => Zeroizing::new(text),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
                Err(e) => {
                    return Err(KeychainError::Backend(format!(
                        "reading {}: {e}",
                        self.path.display()
                    )))
                }
            };
            let root: Value =
                serde_json::from_str(&text).map_err(|_| self.corrupt("invalid JSON"))?;
            if root.get("format").and_then(Value::as_str) != Some(FORMAT) {
                return Err(self.corrupt("unknown format"));
            }
            let Some(raw_entries) = root.get("entries").and_then(Value::as_object) else {
                return Err(self.corrupt("no entries object"));
            };
            let mut entries = BTreeMap::new();
            for (account, value) in raw_entries {
                let encoded = value.as_str().ok_or_else(|| self.corrupt("non-string entry"))?;
                let bytes = BASE64
                    .decode(encoded)
                    .map_err(|_| self.corrupt("entry is not valid base64"))?;
                entries.insert(account.clone(), bytes);
            }
            Ok(entries)
        }

        /// Replace the store contents atomically (temp file + rename) with
        /// owner-only permissions, creating the parent directory on first use.
        fn write(&self, entries: &BTreeMap<String, Vec<u8>>) -> Result<(), KeychainError> {
            let io_err = |what: &str, e: std::io::Error| {
                KeychainError::Backend(format!("{what} {}: {e}", self.path.display()))
            };

            if let Some(dir) = self.path.parent() {
                make_private_dir(dir).map_err(|e| io_err("creating the directory for", e))?;
            }

            let mut raw_entries = Map::new();
            for (account, value) in entries {
                raw_entries.insert(account.clone(), Value::String(BASE64.encode(value)));
            }
            let root = Value::Object(Map::from_iter([
                ("format".to_string(), Value::String(FORMAT.to_string())),
                ("warning".to_string(), Value::String(WARNING.to_string())),
                ("entries".to_string(), Value::Object(raw_entries)),
            ]));
            let json =
                serde_json::to_string_pretty(&root).expect("a map of strings serializes");

            let tmp = self.path.with_extension("json.tmp");
            // A leftover temp file from a crash may carry stale permissions;
            // recreating it guarantees the 0600 applies.
            let _ = std::fs::remove_file(&tmp);
            write_private_file(&tmp, json.as_bytes()).map_err(|e| io_err("writing", e))?;
            std::fs::rename(&tmp, &self.path).map_err(|e| io_err("replacing", e))
        }
    }

    #[cfg(unix)]
    fn make_private_dir(dir: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)
    }

    #[cfg(not(unix))]
    fn make_private_dir(dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)
    }

    #[cfg(unix)]
    fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)
    }

    #[cfg(not(unix))]
    fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        std::fs::write(path, bytes)
    }

    impl Keychain for FileStore {
        fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
            let mut entries = self.read()?;
            Ok(entries.remove(account).map(Zeroizing::new))
        }

        fn set(&mut self, account: &str, value: &[u8]) -> Result<(), KeychainError> {
            let mut entries = self.read()?;
            entries.insert(account.to_string(), value.to_vec());
            self.write(&entries)
        }

        fn delete(&mut self, account: &str) -> Result<bool, KeychainError> {
            let mut entries = self.read()?;
            let existed = entries.remove(account).is_some();
            if existed {
                self.write(&entries)?;
            }
            Ok(existed)
        }

        fn accounts(&self) -> Result<Vec<String>, KeychainError> {
            Ok(self.read()?.into_keys().collect())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// A store under a fresh temp directory; the caller cleans up.
        fn temp_store(tag: &str) -> (PathBuf, FileStore) {
            let dir = std::env::temp_dir()
                .join(format!("keytap-file-store-test-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            (dir.clone(), FileStore::at(dir.join("remembered.json")))
        }

        #[test]
        fn round_trips_like_any_keychain() {
            let (dir, mut store) = temp_store("round-trip");
            let account = "remember:test-root:round-trip";

            store.set(account, b"keytap-remember-v1:aa").unwrap();
            assert_eq!(&store.get(account).unwrap().unwrap()[..], b"keytap-remember-v1:aa");

            store.set(account, b"keytap-remember-v1:bb").unwrap();
            assert_eq!(&store.get(account).unwrap().unwrap()[..], b"keytap-remember-v1:bb");

            assert!(store.accounts().unwrap().contains(&account.to_string()));

            assert!(store.delete(account).unwrap());
            assert!(!store.delete(account).unwrap());
            assert!(store.get(account).unwrap().is_none());

            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn missing_file_is_an_empty_store_and_reads_create_nothing() {
            let (dir, store) = temp_store("missing");
            assert!(store.get("anything").unwrap().is_none());
            assert!(store.accounts().unwrap().is_empty());
            assert!(!dir.exists(), "read paths must not create the store");
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn corrupt_file_fails_loudly_never_silently_clobbers() {
            let (dir, mut store) = temp_store("corrupt");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(store.path(), "not json at all").unwrap();

            assert!(store.get("x").is_err());
            assert!(store.accounts().is_err());
            assert!(store.set("x", b"y").is_err());
            assert_eq!(
                std::fs::read_to_string(store.path()).unwrap(),
                "not json at all",
                "a failed write must leave the original file untouched"
            );

            let _ = std::fs::remove_dir_all(&dir);
        }

        #[cfg(unix)]
        #[test]
        fn store_is_owner_only() {
            use std::os::unix::fs::PermissionsExt;
            let (dir, mut store) = temp_store("perms");
            store.set("remember:test-root:perms", b"keytap-remember-v1:aa").unwrap();

            let file_mode = std::fs::metadata(store.path()).unwrap().permissions().mode();
            let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode();
            assert_eq!(file_mode & 0o777, 0o600);
            assert_eq!(dir_mode & 0o777, 0o700);

            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}

/// Live test against the real platform keychain: the full trait surface,
/// round-tripped through the actual backend. Ignored by default because it
/// needs a live store and writes to it (under a test-only account it cleans
/// up). CI runs it on Linux inside `dbus-run-session` with an unlocked GNOME
/// Keyring; on macOS run it manually with
/// `cargo test -p keytap --bins -- --ignored`.
#[cfg(test)]
mod live_tests {
    use super::*;

    #[test]
    #[ignore = "needs a live OS keychain"]
    fn platform_backend_round_trip() {
        let mut kc = open().expect("open platform keychain");
        let account = "remember:live-test-root:round-trip";

        kc.set(account, b"keytap-remember-v1:aa").unwrap();
        assert_eq!(&kc.get(account).unwrap().unwrap()[..], b"keytap-remember-v1:aa");

        // Setting again overwrites in place.
        kc.set(account, b"keytap-remember-v1:bb").unwrap();
        assert_eq!(&kc.get(account).unwrap().unwrap()[..], b"keytap-remember-v1:bb");

        // Enumeration sees the entry.
        assert!(kc.accounts().unwrap().contains(&account.to_string()));

        // Deletion reports existence exactly once, then reads miss.
        assert!(kc.delete(account).unwrap());
        assert!(!kc.delete(account).unwrap());
        assert!(kc.get(account).unwrap().is_none());
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
