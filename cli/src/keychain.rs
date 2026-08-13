//! Thin, uniform access to the OS keychain for remembered keys.
//!
//! Everything keytap stores lives under one keychain service (`keytap`) so
//! entries stay recognizable and auditable. The trait exists so `remember.rs`
//! holds all policy (naming, formats, root rotation) as plain testable logic,
//! while this module stays a dumb byte store per platform: the macOS Keychain
//! via the Security framework, the freedesktop Secret Service (GNOME Keyring,
//! KWallet, …) via D-Bus on Linux, plus an opt-in plain-file store (see
//! [`file`]) for machines with neither.

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
                write!(
                    f,
                    "remembered keys are not supported on this platform (no OS keychain backend)"
                )
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

    /// `errSecInteractionNotAllowed`: the operation needed an unlock or
    /// access-approval dialog and this session has no way to show one
    /// (SSH, tmux attached from SSH, a sandboxed shell).
    const INTERACTION_NOT_ALLOWED: i32 = -25308;

    /// `errSecAuthFailed`: macOS also reports a locked login keychain as an
    /// authentication failure ("The user name or passphrase you entered is
    /// not correct."). Unlocking the keychain resolves that case.
    const AUTH_FAILED: i32 = -25293;

    const UNLOCK_HINT: &str = "Run `security unlock-keychain`, then retry.";

    pub struct MacosKeychain;

    pub fn open() -> Result<MacosKeychain, KeychainError> {
        Ok(MacosKeychain)
    }

    fn backend_message(code: i32, message: &str) -> String {
        match code {
            INTERACTION_NOT_ALLOWED => format!(
                "the keychain needs to show an unlock or approval dialog, and this session \
                 can't display one (running over SSH or in a sandbox?). Run keytap from a \
                 terminal in your logged-in desktop session. {UNLOCK_HINT}"
            ),
            AUTH_FAILED => format!("{message} {UNLOCK_HINT}"),
            _ => message.to_string(),
        }
    }

    fn backend_err(e: security_framework::base::Error) -> KeychainError {
        KeychainError::Backend(backend_message(e.code(), &e.to_string()))
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

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn authentication_failure_suggests_unlocking_then_retrying() {
            let message = backend_message(
                AUTH_FAILED,
                "The user name or passphrase you entered is not correct.",
            );

            assert_eq!(
                message,
                "The user name or passphrase you entered is not correct. \
                 Run `security unlock-keychain`, then retry."
            );
        }

        #[test]
        fn unavailable_interaction_suggests_unlocking_then_retrying() {
            let message = backend_message(INTERACTION_NOT_ALLOWED, "ignored system message");

            assert!(message.contains(UNLOCK_HINT));
        }

        #[test]
        fn unrelated_security_errors_are_unchanged() {
            let message = "A different Security framework error.";

            assert_eq!(backend_message(-50, message), message);
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
                    Ok(Some(Zeroizing::new(
                        item.get_secret().map_err(backend_err)?,
                    )))
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
            // Service-matching items without an `account` attribute are not
            // keytap-managed remembered keys.
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
    use serde::{Deserialize, Serialize};
    use std::collections::BTreeMap;
    use std::fs::File;
    use std::path::{Path, PathBuf};
    use zeroize::Zeroizing;

    const FORMAT: &str = "keytap-file-store-v1";
    const WARNING: &str =
        "Raw keytap keys, NOT encrypted at rest. Remove entries with `keytap forget` or delete this file.";

    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct StoredFile {
        format: String,
        warning: String,
        entries: BTreeMap<String, String>,
    }

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
        existing_at(path)
    }

    fn existing_at(path: PathBuf) -> Option<FileStore> {
        (path.is_file() || path.with_extension("json.tmp").is_file()).then_some(FileStore { path })
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

    /// A permanent sidecar whose OS lock serializes the complete
    /// read-modify-write transaction. The kernel releases the lock on crash;
    /// keeping the file avoids the stale-sentinel problem of `create_new`.
    struct StoreLock {
        _file: File,
    }

    impl StoreLock {
        fn acquire(store_path: &Path) -> Result<Self, KeychainError> {
            let path = store_path.with_extension("json.lock");
            let io_err = |what: &str, error: std::io::Error| {
                KeychainError::Backend(format!("{what} {}: {error}", path.display()))
            };
            if let Some(dir) = path.parent() {
                make_private_dir(dir)
                    .map_err(|error| io_err("creating the directory for", error))?;
            }
            let file = open_private_lock_file(&path).map_err(|error| io_err("opening", error))?;
            file.lock().map_err(|error| io_err("locking", error))?;
            let temporary = store_path.with_extension("json.tmp");
            match std::fs::remove_file(&temporary) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(KeychainError::Backend(format!(
                        "removing stale temporary store {}: {error}",
                        temporary.display()
                    )))
                }
            }
            Ok(Self { _file: file })
        }
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

        /// Atomic replacement makes an unlocked read consistent. The sole
        /// exception is a crash-leftover temp: lock once to scavenge it,
        /// including when the first write died before publishing the store.
        fn read_for_query(&self) -> Result<BTreeMap<String, Vec<u8>>, KeychainError> {
            if self.path.with_extension("json.tmp").is_file() {
                let _lock = StoreLock::acquire(&self.path)?;
                self.read()
            } else {
                self.read()
            }
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
            let stored: StoredFile =
                serde_json::from_str(&text).map_err(|_| self.corrupt("invalid JSON"))?;
            if stored.format != FORMAT {
                return Err(self.corrupt("unknown format"));
            }
            if stored.warning != WARNING {
                return Err(self.corrupt("invalid warning"));
            }
            let mut entries = BTreeMap::new();
            for (account, encoded) in stored.entries {
                let bytes = BASE64
                    .decode(&encoded)
                    .map_err(|_| self.corrupt("entry is not valid base64"))?;
                if BASE64.encode(&bytes) != encoded {
                    return Err(self.corrupt("entry is not canonical base64"));
                }
                entries.insert(account, bytes);
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

            let stored = StoredFile {
                format: FORMAT.to_string(),
                warning: WARNING.to_string(),
                entries: entries
                    .iter()
                    .map(|(account, value)| (account.clone(), BASE64.encode(value)))
                    .collect(),
            };
            let json = serde_json::to_string_pretty(&stored).expect("a map of strings serializes");

            // The transaction lock makes this fixed name unique among
            // writers, and acquiring that lock removes a crash remnant before
            // any new snapshot is read.
            let tmp = self.path.with_extension("json.tmp");
            if let Err(error) = write_private_file(&tmp, json.as_bytes()) {
                std::fs::remove_file(&tmp).ok();
                return Err(io_err("writing", error));
            }
            if let Err(error) = std::fs::rename(&tmp, &self.path) {
                std::fs::remove_file(&tmp).ok();
                return Err(io_err("replacing", error));
            }
            if let Err(error) = sync_parent(&self.path) {
                crate::note(&format!(
                    "warning: updated the remembered-key store at {}, but couldn't confirm its directory is durable; the update is visible now but might not survive sudden power loss: {error}",
                    self.path.display()
                ));
            }
            Ok(())
        }
    }

    #[cfg(unix)]
    fn make_private_dir(dir: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }

    #[cfg(not(unix))]
    fn make_private_dir(dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)
    }

    fn open_private_lock_file(path: &Path) -> std::io::Result<File> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path)
    }

    #[cfg(unix)]
    fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    }

    #[cfg(not(unix))]
    fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    }

    #[cfg(unix)]
    fn sync_parent(path: &Path) -> std::io::Result<()> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        File::open(parent)?.sync_all()
    }

    #[cfg(not(unix))]
    fn sync_parent(_path: &Path) -> std::io::Result<()> {
        Ok(())
    }

    impl Keychain for FileStore {
        fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
            let mut entries = self.read_for_query()?;
            Ok(entries.remove(account).map(Zeroizing::new))
        }

        fn set(&mut self, account: &str, value: &[u8]) -> Result<(), KeychainError> {
            let _lock = StoreLock::acquire(&self.path)?;
            let mut entries = self.read()?;
            entries.insert(account.to_string(), value.to_vec());
            self.write(&entries)
        }

        fn delete(&mut self, account: &str) -> Result<bool, KeychainError> {
            let _lock = StoreLock::acquire(&self.path)?;
            let mut entries = self.read()?;
            let existed = entries.remove(account).is_some();
            if existed {
                self.write(&entries)?;
            }
            Ok(existed)
        }

        fn accounts(&self) -> Result<Vec<String>, KeychainError> {
            Ok(self.read_for_query()?.into_keys().collect())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const RACE_CHILD_PATH: &str = "KEYTAP_FILE_STORE_RACE_CHILD_PATH";
        const RACE_CHILD_READY: &str = "KEYTAP_FILE_STORE_RACE_CHILD_READY";
        const RACE_CHILD_OPERATION: &str = "KEYTAP_FILE_STORE_RACE_CHILD_OPERATION";

        /// A store under a fresh temp directory; the caller cleans up.
        fn temp_store(tag: &str) -> (PathBuf, FileStore) {
            let dir = std::env::temp_dir().join(format!(
                "keytap-file-store-test-{}-{tag}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            (dir.clone(), FileStore::at(dir.join("remembered.json")))
        }

        fn spawn_race_child(path: &Path, ready: &Path, operation: &str) -> std::process::Child {
            std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg(
                    "keychain::file::tests::cross_process_update_cannot_restore_entries_deleted_while_it_waited",
                )
                .arg("--nocapture")
                .env(RACE_CHILD_PATH, path)
                .env(RACE_CHILD_READY, ready)
                .env(RACE_CHILD_OPERATION, operation)
                .spawn()
                .unwrap()
        }

        fn assert_child_waits_for_lock(child: &mut std::process::Child, ready: &Path, label: &str) {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !ready.is_file() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            assert!(ready.is_file(), "{label} child did not reach the update");
            std::thread::sleep(std::time::Duration::from_millis(50));
            assert!(
                child.try_wait().unwrap().is_none(),
                "child {label} bypassed the transaction lock"
            );
        }

        #[test]
        fn round_trips_like_any_keychain() {
            let (dir, mut store) = temp_store("round-trip");
            let account = "remember:test-root:round-trip";

            store.set(account, b"first secret").unwrap();
            assert_eq!(&store.get(account).unwrap().unwrap()[..], b"first secret");

            store.set(account, b"second secret").unwrap();
            assert_eq!(&store.get(account).unwrap().unwrap()[..], b"second secret");

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

        #[test]
        fn file_store_accepts_only_its_exact_current_schema() {
            let cases = [
                (
                    "missing-warning",
                    serde_json::json!({
                        "format": FORMAT,
                        "entries": {"remember:root:name": "eA=="}
                    }),
                ),
                (
                    "changed-warning",
                    serde_json::json!({
                        "format": FORMAT,
                        "warning": "keys",
                        "entries": {"remember:root:name": "eA=="}
                    }),
                ),
                (
                    "extra-field",
                    serde_json::json!({
                        "format": FORMAT,
                        "warning": WARNING,
                        "entries": {"remember:root:name": "eA=="},
                        "extra": true
                    }),
                ),
                (
                    "non-string-entry",
                    serde_json::json!({
                        "format": FORMAT,
                        "warning": WARNING,
                        "entries": {"remember:root:name": 7}
                    }),
                ),
            ];

            for (tag, value) in cases {
                let (dir, store) = temp_store(tag);
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(store.path(), serde_json::to_vec(&value).unwrap()).unwrap();
                assert!(store.get("remember:root:name").is_err(), "case {tag}");
                let _ = std::fs::remove_dir_all(&dir);
            }
        }

        #[test]
        fn next_mutation_removes_a_crash_leftover_containing_keys() {
            let (dir, mut store) = temp_store("stale-temporary");
            store.set("remember:root:a", b"a").unwrap();
            let temporary = store.path().with_extension("json.tmp");
            std::fs::write(&temporary, b"raw secret from interrupted write").unwrap();

            assert!(!store.delete("missing").unwrap());
            assert!(!temporary.exists());

            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn first_write_crash_is_discovered_and_scavenged_by_a_read_path() {
            let (dir, store) = temp_store("first-write-crash");
            std::fs::create_dir_all(&dir).unwrap();
            let temporary = store.path().with_extension("json.tmp");
            std::fs::write(&temporary, b"raw key from interrupted first write").unwrap();

            let recovered = existing_at(store.path().to_path_buf()).unwrap();
            assert!(recovered.accounts().unwrap().is_empty());
            assert!(!temporary.exists());
            assert!(!recovered.path().exists());

            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn cross_process_update_cannot_restore_entries_deleted_while_it_waited() {
            if let (Some(path), Some(ready), Some(operation)) = (
                std::env::var_os(RACE_CHILD_PATH),
                std::env::var_os(RACE_CHILD_READY),
                std::env::var_os(RACE_CHILD_OPERATION),
            ) {
                let ready = PathBuf::from(ready);
                std::fs::write(ready, b"ready").unwrap();
                let mut store = FileStore::at(PathBuf::from(path));
                match operation.to_str().unwrap() {
                    "set" => store.set("remember:new-root:new", b"new").unwrap(),
                    "delete" => assert!(store.delete("remember:old-root:delete-me").unwrap()),
                    operation => panic!("unknown child operation {operation}"),
                }
                return;
            }

            let (dir, mut store) = temp_store("cross-process-race");
            store.set("remember:old-root:a", b"old-a").unwrap();
            store.set("remember:old-root:b", b"old-b").unwrap();

            let lock = StoreLock::acquire(store.path()).unwrap();
            let ready = dir.join("child-ready");
            let mut child = spawn_race_child(store.path(), &ready, "set");
            assert_child_waits_for_lock(&mut child, &ready, "set");

            // Model init cleanup while the other process is waiting to
            // remember under a new root. Its later update must read this
            // committed map, not republish the stale old-root snapshot.
            let mut entries = store.read().unwrap();
            entries.retain(|account, _| !account.starts_with("remember:old-root:"));
            store.write(&entries).unwrap();
            drop(lock);

            assert!(child.wait().unwrap().success());
            assert_eq!(
                store.accounts().unwrap(),
                vec!["remember:new-root:new".to_string()]
            );

            // Exercise the other public mutation too: a waiting delete must
            // base its rewrite on a competing update committed under the
            // same lock, rather than erase that update with an old snapshot.
            store.set("remember:old-root:delete-me", b"old").unwrap();
            let lock = StoreLock::acquire(store.path()).unwrap();
            let mut entries = store.read().unwrap();
            entries.insert("remember:new-root:preserved".to_string(), b"new".to_vec());
            let ready = dir.join("delete-child-ready");
            let mut child = spawn_race_child(store.path(), &ready, "delete");
            assert_child_waits_for_lock(&mut child, &ready, "delete");
            store.write(&entries).unwrap();
            drop(lock);
            assert!(child.wait().unwrap().success());
            assert_eq!(
                store.accounts().unwrap(),
                vec![
                    "remember:new-root:new".to_string(),
                    "remember:new-root:preserved".to_string(),
                ]
            );

            let _ = std::fs::remove_dir_all(&dir);
        }

        #[cfg(unix)]
        #[test]
        fn store_is_owner_only() {
            use std::os::unix::fs::PermissionsExt;
            let (dir, mut store) = temp_store("perms");
            store.set("remember:test-root:perms", b"secret").unwrap();

            let file_mode = std::fs::metadata(store.path())
                .unwrap()
                .permissions()
                .mode();
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

        kc.set(account, b"first secret").unwrap();
        assert_eq!(&kc.get(account).unwrap().unwrap()[..], b"first secret");

        // Setting again overwrites in place.
        kc.set(account, b"second secret").unwrap();
        assert_eq!(&kc.get(account).unwrap().unwrap()[..], b"second secret");

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
