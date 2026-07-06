//! Remembered keys: explicit, per-machine persistence of derived keys.
//!
//! keytap stays stateless by default — every command derives on demand and
//! stores nothing. `keytap remember NAME` is the one opt-in exception: it runs
//! the normal ceremony, then stores the raw derived key in the OS keychain so
//! later commands for that name skip the prompt. No TTL; entries live until
//! `keytap forget`, `keytap forget --all`, or the passkey is replaced.
//!
//! Every remembered key is tied to a *root*: a fingerprint of the WebAuthn
//! credential that produced it. `keytap init` is the root boundary — it wipes
//! all remembered entries and records the new credential's fingerprint as the
//! active root. Lookups only ever consult entries under the active root, so
//! even if that wipe partially fails, keys from a replaced passkey are never
//! used.
//!
//! Storage layout (service `keytap`, see `keychain.rs`):
//!   account `remember:<root_id>:<name>` → value `keytap-remember-v1:<hex key>`
//!   account `active-root`               → value `keytap-root-v1:<root_id>`

use crate::keychain::{self, Keychain, KeychainError};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const REMEMBER_ACCOUNT_PREFIX: &str = "remember:";
const ACTIVE_ROOT_ACCOUNT: &str = "active-root";
const KEY_VALUE_PREFIX: &str = "keytap-remember-v1:";
const ROOT_VALUE_PREFIX: &str = "keytap-root-v1:";

/// Domain separator for credential fingerprints, so a root id can never be
/// confused with any other hash of the credential ID.
const ROOT_ID_CONTEXT: &[u8] = b"keytap:root-id:v1:";

// ─── Command surface (opens the stores, reports to the user) ───

/// The stores that may hold remembered keys, in lookup order: the OS keychain
/// first, then the plain-file store. The keychain participates when this
/// machine can open one; the file store once some `keytap remember` has
/// stored into it (that is what brings it into existence). Each store carries
/// its own root marker and entries, so the per-store invariants hold
/// independently. `Err` means this machine has no store at all and carries
/// the keychain's reason.
fn open_stores() -> Result<Vec<Box<dyn Keychain>>, KeychainError> {
    let mut stores: Vec<Box<dyn Keychain>> = Vec::new();
    let keychain_error = match keychain::open() {
        Ok(kc) => {
            stores.push(Box::new(kc));
            None
        }
        Err(e) => Some(e),
    };
    if let Some(store) = keychain::file::open_existing() {
        stores.push(Box::new(store));
    }
    match (stores.is_empty(), keychain_error) {
        (true, Some(e)) => Err(e),
        _ => Ok(stores),
    }
}

/// Resolve a remembered key for `name` under the active root, if any store
/// holds one. Never fails: any keychain trouble falls back to `None`, i.e. a
/// normal passkey ceremony. `keytap remembered` surfaces the errors this path
/// deliberately swallows (a stateless user on a keychain-less machine should
/// not see warnings on every command).
pub fn lookup(name: &str) -> Option<Zeroizing<Vec<u8>>> {
    for store in open_stores().unwrap_or_default() {
        match lookup_in(store.as_ref(), name) {
            Ok(Resolution::Hit(key)) => return Some(key),
            Ok(Resolution::Miss) | Err(_) => {}
            Ok(Resolution::Invalid) => eprintln!(
                "warning: ignoring a malformed remembered key for '{name}'; run `keytap forget {name}` to clean it up"
            ),
        }
    }
    None
}

/// Where `keytap remember` will store the key, resolved and validated BEFORE
/// the passkey ceremony so a machine with nowhere to store fails fast instead
/// of after a prompt.
pub struct WriteTarget {
    store: Box<dyn Keychain>,
    /// Where the key ends up, for the success message ("the OS keychain" or
    /// the file path with its caveat).
    location: String,
}

/// The write target for `keytap remember`: conceptually the plain-file store,
/// silently upgraded to the OS keychain when this machine has one. The
/// success message reports which of the two actually holds the key.
pub fn write_target() -> WriteTarget {
    resolve_write_target().unwrap_or_else(|e| crate::die(&e.to_string()))
}

fn resolve_write_target() -> Result<WriteTarget, KeychainError> {
    match keychain::open() {
        Ok(kc) => {
            Ok(WriteTarget { store: Box::new(kc), location: "the OS keychain".to_string() })
        }
        Err(_) => {
            let store = keychain::file::open_default()?;
            Ok(WriteTarget {
                location: format!("{} (a plain file, not encrypted at rest)", store.path().display()),
                store: Box::new(store),
            })
        }
    }
}

/// Store a freshly derived key under the root of the credential that produced
/// it. Called by `keytap remember` after the ceremony.
pub fn remember(target: &mut WriteTarget, name: &str, credential_id: &[u8], raw_key: &[u8]) {
    match remember_in(target.store.as_mut(), name, credential_id, raw_key) {
        Ok(RememberOutcome::Stored) => eprintln!(
            "Remembered '{name}' in {location}. Future keytap commands for this name will not \
             prompt until you run `keytap forget {name}` or replace the passkey.",
            location = target.location
        ),
        Ok(RememberOutcome::RootMismatch) => crate::die(
            "the passkey you just used is not this machine's active keytap root, so remembering \
             under it would store a key that later commands never use. Retry and pick the \
             previously registered passkey, or run `keytap init` to make a fresh passkey the \
             root (that clears existing remembered keys)",
        ),
        Err(e) => crate::die(&e.to_string()),
    }
}

/// Honor a remember opt-in that arrived with a nearby assertion (the user
/// ticked the checkbox on the phone page). Unlike `keytap remember`, storing
/// is best-effort: the command's real job is the key it just derived, so
/// trouble remembering warns and the command carries on.
pub fn remember_requested_nearby(name: &str, credential_id: &[u8], raw_key: &[u8]) {
    let could_not = |why: &str| {
        eprintln!(
            "warning: you asked on your phone to remember '{name}' on this machine, but {why}"
        );
    };
    let mut target = match resolve_write_target() {
        Ok(target) => target,
        Err(e) => return could_not(&e.to_string()),
    };
    match remember_in(target.store.as_mut(), name, credential_id, raw_key) {
        Ok(RememberOutcome::Stored) => eprintln!(
            "Remembered '{name}' in {location}, as requested on your phone. Future keytap \
             commands for this name will not prompt until you run `keytap forget {name}` or \
             replace the passkey.",
            location = target.location
        ),
        Ok(RememberOutcome::RootMismatch) => could_not(
            "the passkey you just used is not this machine's active keytap root, so the stored \
             key would never be used. Run `keytap init` to make this passkey the root (that \
             clears existing remembered keys)",
        ),
        Err(e) => could_not(&e.to_string()),
    }
}

/// Delete the remembered key for `name` under the active root, from every
/// store that holds one.
pub fn forget(name: &str) {
    let mut stores = open_stores().unwrap_or_else(|e| crate::die(&e.to_string()));
    let mut deleted = false;
    for store in &mut stores {
        match forget_in(store.as_mut(), name) {
            Ok(d) => deleted |= d,
            Err(e) => crate::die(&e.to_string()),
        }
    }
    if deleted {
        eprintln!("Forgot '{name}'. The next keytap command for this name will prompt again.");
    } else {
        crate::die(&format!("no remembered key named '{name}' for the current passkey"));
    }
}

/// Delete every remembered key on this machine, including entries left over
/// from previously replaced passkeys, across every store.
pub fn forget_all() {
    let mut stores = open_stores().unwrap_or_else(|e| crate::die(&e.to_string()));
    let mut deleted = 0;
    for store in &mut stores {
        match forget_all_in(store.as_mut()) {
            Ok(n) => deleted += n,
            Err(e) => crate::die(&e.to_string()),
        }
    }
    match deleted {
        0 => eprintln!("No remembered keys to forget."),
        n => eprintln!(
            "Forgot {n} remembered key{}, including any from previous passkeys.",
            if n == 1 { "" } else { "s" }
        ),
    }
}

/// Print the names remembered under the active root, one per line, across
/// every store (each name once, even when stores overlap).
pub fn remembered() {
    let stores = open_stores().unwrap_or_else(|e| crate::die(&e.to_string()));
    let mut names: Vec<String> = Vec::new();
    for store in &stores {
        match list_in(store.as_ref()) {
            Ok(mut listed) => names.append(&mut listed),
            Err(e) => crate::die(&e.to_string()),
        }
    }
    names.sort();
    names.dedup();
    if names.is_empty() {
        eprintln!("No remembered keys for the current passkey.");
    } else {
        for name in names {
            println!("{name}");
        }
    }
}

/// Root rotation after a successful `keytap init`: record the new credential's
/// fingerprint as the active root and wipe every remembered entry, in every
/// store. Must never fail init — the registration already succeeded — so
/// trouble here is only reported, and lookups stay safe regardless because
/// they are scoped to the active root.
pub fn after_init(credential_id: &[u8]) {
    let mut stores: Vec<Box<dyn Keychain>> = Vec::new();
    match keychain::open() {
        Ok(kc) => stores.push(Box::new(kc)),
        // No keychain, no keychain state: nothing there to rotate.
        Err(KeychainError::Unsupported) => {}
        Err(e) => {
            eprintln!("warning: {e}; couldn't check for remembered keys from a previous passkey")
        }
    }
    if let Some(store) = keychain::file::open_existing() {
        stores.push(Box::new(store));
    }

    let root = root_id(credential_id);
    let mut removed = 0;
    for store in &mut stores {
        match rotate_root_in(store.as_mut(), &root) {
            Ok(n) => removed += n,
            Err(e) => eprintln!(
                "warning: {e}; couldn't fully clear remembered keys tied to the previous passkey. \
                 They will not be used, but you can purge them with `keytap forget --all`"
            ),
        }
    }
    if removed > 0 {
        eprintln!("Removed remembered keys tied to the previous passkey.");
    }
}

// ─── Logic (pure over the Keychain trait, unit-tested below) ───

/// Fingerprint of a WebAuthn credential ID, used as the root identifier.
/// 128 bits of SHA-256 — far beyond collision concerns for the handful of
/// credentials a user will ever register, while keeping keychain account
/// names readable.
fn root_id(credential_id: &[u8]) -> String {
    let digest = Sha256::new_with_prefix(ROOT_ID_CONTEXT)
        .chain_update(credential_id)
        .finalize();
    hex::encode(&digest[..16])
}

fn remember_account(root: &str, name: &str) -> String {
    format!("{REMEMBER_ACCOUNT_PREFIX}{root}:{name}")
}

/// Split a `remember:<root>:<name>` account into (root, name).
/// Names may themselves contain `:`; roots are fixed-format hex, so the first
/// separator after the prefix is unambiguous.
fn parse_remember_account(account: &str) -> Option<(&str, &str)> {
    account.strip_prefix(REMEMBER_ACCOUNT_PREFIX)?.split_once(':')
}

fn encode_key_value(raw_key: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(format!("{KEY_VALUE_PREFIX}{}", hex::encode(raw_key)))
}

fn decode_key_value(value: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let text = std::str::from_utf8(value).ok()?;
    let bytes = hex::decode(text.strip_prefix(KEY_VALUE_PREFIX)?).ok()?;
    (bytes.len() == 32).then(|| Zeroizing::new(bytes))
}

/// The active root id, or `None` when absent or unparseable (a corrupt marker
/// self-heals: the next `init` or root-adopting `remember` rewrites it).
fn read_active_root(kc: &(impl Keychain + ?Sized)) -> Result<Option<String>, KeychainError> {
    let Some(value) = kc.get(ACTIVE_ROOT_ACCOUNT)? else {
        return Ok(None);
    };
    Ok(std::str::from_utf8(&value)
        .ok()
        .and_then(|text| text.strip_prefix(ROOT_VALUE_PREFIX))
        .map(str::to_string))
}

fn store_active_root(kc: &mut (impl Keychain + ?Sized), root: &str) -> Result<(), KeychainError> {
    kc.set(ACTIVE_ROOT_ACCOUNT, format!("{ROOT_VALUE_PREFIX}{root}").as_bytes())
}

enum Resolution {
    Hit(Zeroizing<Vec<u8>>),
    Miss,
    /// An entry exists but its value doesn't parse; callers treat it as a
    /// miss (fall back to the ceremony) but may want to tell the user.
    Invalid,
}

fn lookup_in(kc: &(impl Keychain + ?Sized), name: &str) -> Result<Resolution, KeychainError> {
    let Some(root) = read_active_root(kc)? else {
        return Ok(Resolution::Miss);
    };
    let Some(value) = kc.get(&remember_account(&root, name))? else {
        return Ok(Resolution::Miss);
    };
    Ok(match decode_key_value(&value) {
        Some(key) => Resolution::Hit(key),
        None => Resolution::Invalid,
    })
}

enum RememberOutcome {
    Stored,
    /// The asserting credential differs from the active root; storing would
    /// create an entry lookups can never legitimately serve.
    RootMismatch,
}

fn remember_in(
    kc: &mut (impl Keychain + ?Sized),
    name: &str,
    credential_id: &[u8],
    raw_key: &[u8],
) -> Result<RememberOutcome, KeychainError> {
    let root = root_id(credential_id);
    match read_active_root(kc)? {
        // Inits that predate remembered keys stored no root marker; adopt the
        // credential that just asserted as the active root.
        None => store_active_root(kc, &root)?,
        Some(active) if active != root => return Ok(RememberOutcome::RootMismatch),
        Some(_) => {}
    }
    kc.set(&remember_account(&root, name), encode_key_value(raw_key).as_bytes())?;
    Ok(RememberOutcome::Stored)
}

/// Whether the entry for `name` under the active root existed (and was deleted).
fn forget_in(kc: &mut (impl Keychain + ?Sized), name: &str) -> Result<bool, KeychainError> {
    let Some(root) = read_active_root(kc)? else {
        return Ok(false);
    };
    kc.delete(&remember_account(&root, name))
}

/// Delete every `remember:*` entry regardless of root; returns how many.
/// Leaves the active-root marker and any user-managed entries alone.
fn forget_all_in(kc: &mut (impl Keychain + ?Sized)) -> Result<usize, KeychainError> {
    let mut deleted = 0;
    for account in kc.accounts()? {
        if parse_remember_account(&account).is_some() && kc.delete(&account)? {
            deleted += 1;
        }
    }
    Ok(deleted)
}

/// Names remembered under the active root, sorted.
fn list_in(kc: &(impl Keychain + ?Sized)) -> Result<Vec<String>, KeychainError> {
    let Some(root) = read_active_root(kc)? else {
        return Ok(Vec::new());
    };
    let accounts = kc.accounts()?;
    let mut names: Vec<String> = accounts
        .iter()
        .filter_map(|account| parse_remember_account(account))
        .filter(|(entry_root, _)| *entry_root == root)
        .map(|(_, name)| name.to_string())
        .collect();
    names.sort();
    names.dedup();
    Ok(names)
}

/// Make `new_root` the active root, then wipe every remembered entry from any
/// root. Ordered so that even a partial failure leaves stale entries
/// unreachable: once the marker points at the new root, lookups can no longer
/// see them.
fn rotate_root_in(kc: &mut (impl Keychain + ?Sized), new_root: &str) -> Result<usize, KeychainError> {
    store_active_root(kc, new_root)?;
    forget_all_in(kc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::memory::MemoryKeychain;

    const KEY_A: [u8; 32] = [0xAA; 32];
    const KEY_B: [u8; 32] = [0xBB; 32];
    const CRED_1: &[u8] = b"credential-one";
    const CRED_2: &[u8] = b"credential-two";

    fn assert_stored(outcome: RememberOutcome) {
        assert!(matches!(outcome, RememberOutcome::Stored));
    }

    #[test]
    fn root_id_is_stable_and_credential_specific() {
        assert_eq!(root_id(CRED_1), root_id(CRED_1));
        assert_ne!(root_id(CRED_1), root_id(CRED_2));
        assert_eq!(root_id(CRED_1).len(), 32);
        assert!(root_id(CRED_1).chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn remember_then_lookup_round_trips() {
        let mut kc = MemoryKeychain::default();
        assert_stored(remember_in(&mut kc, "deploy", CRED_1, &KEY_A).unwrap());
        match lookup_in(&kc, "deploy").unwrap() {
            Resolution::Hit(key) => assert_eq!(&key[..], &KEY_A),
            _ => panic!("expected a hit"),
        }
        // A name that was never remembered stays a miss.
        assert!(matches!(lookup_in(&kc, "other").unwrap(), Resolution::Miss));
    }

    /// The full remember policy over the plain-file store: it is just another
    /// `Keychain`, so root scoping and rotation behave exactly as they do in
    /// the OS keychain.
    #[test]
    fn remember_policy_holds_over_the_file_store() {
        let dir = std::env::temp_dir()
            .join(format!("keytap-remember-file-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut store = crate::keychain::file::FileStore::at(dir.join("remembered.json"));

        assert_stored(remember_in(&mut store, "deploy", CRED_1, &KEY_A).unwrap());
        match lookup_in(&store, "deploy").unwrap() {
            Resolution::Hit(key) => assert_eq!(&key[..], &KEY_A),
            _ => panic!("expected a hit"),
        }

        // A different credential can't overwrite entries under the active root.
        assert!(matches!(
            remember_in(&mut store, "deploy", CRED_2, &KEY_B).unwrap(),
            RememberOutcome::RootMismatch
        ));

        // Root rotation wipes the file store like any other store.
        assert_eq!(rotate_root_in(&mut store, &root_id(CRED_2)).unwrap(), 1);
        assert!(matches!(lookup_in(&store, "deploy").unwrap(), Resolution::Miss));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn first_remember_adopts_the_asserting_credential_as_root() {
        let mut kc = MemoryKeychain::default();
        assert!(read_active_root(&kc).unwrap().is_none());
        assert_stored(remember_in(&mut kc, "deploy", CRED_1, &KEY_A).unwrap());
        assert_eq!(read_active_root(&kc).unwrap().unwrap(), root_id(CRED_1));
    }

    #[test]
    fn remember_refuses_a_credential_that_is_not_the_active_root() {
        let mut kc = MemoryKeychain::default();
        assert_stored(remember_in(&mut kc, "deploy", CRED_1, &KEY_A).unwrap());
        assert!(matches!(
            remember_in(&mut kc, "deploy", CRED_2, &KEY_B).unwrap(),
            RememberOutcome::RootMismatch
        ));
        // The original entry is untouched.
        match lookup_in(&kc, "deploy").unwrap() {
            Resolution::Hit(key) => assert_eq!(&key[..], &KEY_A),
            _ => panic!("expected the original key"),
        }
    }

    #[test]
    fn lookup_is_scoped_to_the_active_root() {
        let mut kc = MemoryKeychain::default();
        // An entry under some other root must never be served…
        kc.set(
            &remember_account(&root_id(CRED_2), "deploy"),
            encode_key_value(&KEY_B).as_bytes(),
        )
        .unwrap();
        store_active_root(&mut kc, &root_id(CRED_1)).unwrap();
        assert!(matches!(lookup_in(&kc, "deploy").unwrap(), Resolution::Miss));
        // …and without any active root, nothing resolves at all.
        kc.delete(ACTIVE_ROOT_ACCOUNT).unwrap();
        assert!(matches!(lookup_in(&kc, "deploy").unwrap(), Resolution::Miss));
    }

    #[test]
    fn init_rotation_wipes_all_roots_and_sets_the_new_one() {
        let mut kc = MemoryKeychain::default();
        assert_stored(remember_in(&mut kc, "deploy", CRED_1, &KEY_A).unwrap());
        assert_stored(remember_in(&mut kc, "backup", CRED_1, &KEY_B).unwrap());
        // A stray entry from an even older root is wiped too.
        kc.set(
            &remember_account(&root_id(b"ancient"), "old"),
            encode_key_value(&KEY_B).as_bytes(),
        )
        .unwrap();
        // A user-managed entry under the keytap service survives rotation.
        kc.set("deploy", b"user-managed").unwrap();

        assert_eq!(rotate_root_in(&mut kc, &root_id(CRED_2)).unwrap(), 3);
        assert_eq!(read_active_root(&kc).unwrap().unwrap(), root_id(CRED_2));
        assert!(list_in(&kc).unwrap().is_empty());
        assert!(matches!(lookup_in(&kc, "deploy").unwrap(), Resolution::Miss));
        assert_eq!(&kc.get("deploy").unwrap().unwrap()[..], b"user-managed");
    }

    #[test]
    fn forget_removes_only_the_named_entry() {
        let mut kc = MemoryKeychain::default();
        assert_stored(remember_in(&mut kc, "deploy", CRED_1, &KEY_A).unwrap());
        assert_stored(remember_in(&mut kc, "backup", CRED_1, &KEY_B).unwrap());
        assert!(forget_in(&mut kc, "deploy").unwrap());
        assert!(!forget_in(&mut kc, "deploy").unwrap(), "already gone");
        assert!(!forget_in(&mut kc, "never-stored").unwrap());
        assert_eq!(list_in(&kc).unwrap(), vec!["backup".to_string()]);
    }

    #[test]
    fn forget_all_clears_every_root_but_spares_everything_else() {
        let mut kc = MemoryKeychain::default();
        assert_stored(remember_in(&mut kc, "deploy", CRED_1, &KEY_A).unwrap());
        kc.set(
            &remember_account(&root_id(CRED_2), "stale"),
            encode_key_value(&KEY_B).as_bytes(),
        )
        .unwrap();
        kc.set("deploy", b"user-managed").unwrap();

        assert_eq!(forget_all_in(&mut kc).unwrap(), 2);
        assert_eq!(forget_all_in(&mut kc).unwrap(), 0, "idempotent");
        // The root marker and user-managed entries are not "remembered keys".
        assert!(read_active_root(&kc).unwrap().is_some());
        assert_eq!(&kc.get("deploy").unwrap().unwrap()[..], b"user-managed");
    }

    #[test]
    fn list_reports_names_for_the_active_root_sorted() {
        let mut kc = MemoryKeychain::default();
        assert_stored(remember_in(&mut kc, "zeta", CRED_1, &KEY_A).unwrap());
        assert_stored(remember_in(&mut kc, "alpha", CRED_1, &KEY_B).unwrap());
        // Names may contain the account separator.
        assert_stored(remember_in(&mut kc, "ns:key", CRED_1, &KEY_A).unwrap());
        kc.set(
            &remember_account(&root_id(CRED_2), "foreign"),
            encode_key_value(&KEY_B).as_bytes(),
        )
        .unwrap();

        assert_eq!(list_in(&kc).unwrap(), vec!["alpha", "ns:key", "zeta"]);
    }

    #[test]
    fn malformed_entries_resolve_to_invalid_not_a_key() {
        let mut kc = MemoryKeychain::default();
        let root = root_id(CRED_1);
        store_active_root(&mut kc, &root).unwrap();
        for bad in [
            b"garbage".as_slice(),                       // no prefix
            b"keytap-remember-v1:zz".as_slice(),         // not hex
            b"keytap-remember-v1:aabb".as_slice(),       // wrong length
            b"\xff\xfe".as_slice(),                      // not UTF-8
        ] {
            kc.set(&remember_account(&root, "deploy"), bad).unwrap();
            assert!(matches!(lookup_in(&kc, "deploy").unwrap(), Resolution::Invalid));
        }
    }

    #[test]
    fn corrupt_active_root_marker_reads_as_absent_and_self_heals() {
        let mut kc = MemoryKeychain::default();
        kc.set(ACTIVE_ROOT_ACCOUNT, b"not-a-root-marker").unwrap();
        assert!(read_active_root(&kc).unwrap().is_none());
        // The next remember adopts a fresh root over the corrupt marker.
        assert_stored(remember_in(&mut kc, "deploy", CRED_1, &KEY_A).unwrap());
        assert_eq!(read_active_root(&kc).unwrap().unwrap(), root_id(CRED_1));
    }

    #[test]
    fn value_encoding_round_trips_and_rejects_truncation() {
        let encoded = encode_key_value(&KEY_A);
        assert_eq!(&decode_key_value(encoded.as_bytes()).unwrap()[..], &KEY_A);
        assert!(decode_key_value(&encoded.as_bytes()[..encoded.len() - 2]).is_none());
    }
}
