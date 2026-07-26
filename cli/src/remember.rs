//! Remembered keys: explicit, per-machine persistence of derived keys.
//!
//! keytap stays stateless unless the user explicitly chooses local storage,
//! either with `keytap remember NAME` or on the nearby approval page. The raw
//! derived key is then stored in the local key store so later commands for
//! that name skip the prompt. No TTL; entries live until `keytap forget`,
//! `keytap forget --all`, or the passkey is replaced.
//!
//! Every remembered key is tied to a *root*: a fingerprint of the WebAuthn
//! credential that produced it. The nearby identity file is the sole root
//! authority. Publishing a replacement identity makes old-root entries
//! unreachable immediately, even if their best-effort cleanup fails.
//!
//! Storage layout (service `keytap`, see `keychain.rs`):
//!   account `remember:<root_id>:<name>` → value `keytap-remember-v1:<hex key>`

use crate::keychain::{self, Keychain, KeychainError};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const REMEMBER_ACCOUNT_PREFIX: &str = "remember:";
const KEY_VALUE_PREFIX: &str = "keytap-remember-v1:";

/// Domain separator for credential fingerprints, so a root id can never be
/// confused with any other hash of the credential ID.
const ROOT_ID_CONTEXT: &[u8] = b"keytap:root-id:v1:";

// ─── Command surface (opens the stores, reports to the user) ───

/// The stores that may hold remembered keys, in lookup order: the OS keychain
/// first, then the plain-file store. The keychain participates when this
/// machine can open one; the file store once an explicit remember choice has
/// stored into it (that is what brings it into existence). `Err` means this
/// machine has no store at all and carries the keychain's reason.
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

/// Resolve a remembered key for `name` under the authoritative root, if any store
/// holds one. Never fails: any keychain trouble falls back to `None`, i.e. a
/// normal passkey ceremony. `keytap remembered` surfaces the errors this path
/// deliberately swallows (a stateless user on a keychain-less machine should
/// not see warnings on every command).
pub fn lookup(name: &str) -> Option<Zeroizing<Vec<u8>>> {
    // The identity file is the generation authority. In particular, an init
    // that published its new credential but crashed before keychain cleanup
    // must make every old-root entry unreachable immediately.
    let authority = crate::nearby_identity::remember_authority().ok()?;
    for store in open_stores().unwrap_or_default() {
        match lookup_authorized_in(store.as_ref(), name, &authority) {
            Ok(Resolution::Hit(key)) => return Some(key),
            Ok(Resolution::Miss) | Err(_) => {}
            Ok(Resolution::Invalid) => eprintln!(
                "warning: ignoring a malformed remembered key for '{name}'; run `keytap forget {name}` to clean it up"
            ),
        }
    }
    None
}

fn lookup_authorized_in(
    kc: &(impl Keychain + ?Sized),
    name: &str,
    authority: &crate::nearby_identity::RememberAuthority,
) -> Result<Resolution, KeychainError> {
    let resolution = lookup_root_in(kc, &root_id(authority.credential_id()), name)?;
    match authority.revalidate() {
        Ok(true) => Ok(resolution),
        Ok(false) | Err(_) => Ok(Resolution::Miss),
    }
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
        Ok(mut kc) => {
            probe_writable(&mut kc)?;
            Ok(WriteTarget {
                store: Box::new(kc),
                location: "the OS keychain".to_string(),
            })
        }
        Err(_) => {
            let store = keychain::file::open_default()?;
            Ok(WriteTarget {
                location: format!(
                    "{} (a plain file, not encrypted at rest)",
                    store.path().display()
                ),
                store: Box::new(store),
            })
        }
    }
}

/// Account name for the write probe below. Deliberately outside the
/// `remember:` namespace so `remembered` and `forget` never
/// see it, and self-describing in case a crash ever leaves it behind.
const WRITE_PROBE_ACCOUNT: &str = "write-probe";

/// Exercise the write operations `remember` will need after the ceremony so a
/// store that would refuse them
/// (a keychain that needs an unlock dialog in a session that can't show one,
/// an ACL denial) fails BEFORE the user's passkey tap, not after it.
fn probe_writable(kc: &mut (impl Keychain + ?Sized)) -> Result<(), KeychainError> {
    kc.set(WRITE_PROBE_ACCOUNT, b"keytap write probe; safe to delete")?;
    kc.delete(WRITE_PROBE_ACCOUNT)?;
    Ok(())
}

/// Store a freshly derived key under the root of the credential that produced
/// it. Called by `keytap remember` after the ceremony.
pub fn remember(target: &mut WriteTarget, name: &str, credential_id: &[u8], raw_key: &[u8]) {
    let authority = crate::nearby_identity::remember_authority().unwrap_or_else(|error| {
        crate::die(&format!(
            "could not verify the current passkey identity before remembering: {error}"
        ))
    });
    if authority.credential_id() != credential_id {
        crate::die(
            "the passkey you just used is not this machine's current passkey identity; refusing \
             to remember a key that later commands would not use",
        );
    }
    remember_root_in(
        target.store.as_mut(),
        name,
        &root_id(authority.credential_id()),
        raw_key,
    )
    .unwrap_or_else(|error| crate::die(&error.to_string()));
    match authority.revalidate() {
        Ok(true) => eprintln!(
            "Remembered '{name}' in {location}. Future keytap commands for this name will not \
             prompt until you run `keytap forget {name}` or replace the passkey.",
            location = target.location
        ),
        Ok(false) | Err(_) => crate::die(
            "the passkey identity changed while the key was being stored; the stale entry will \
             not be used",
        ),
    }
}

/// Honor the storage disposition signed by the phone's nearby assertion.
/// Storage remains best-effort for ordinary derivation commands: failure is
/// reported to both endpoints, while the verified one-time key can still be
/// used by the command.
pub enum NearbyRememberOutcome {
    Stored,
    /// Identity authority or durable local storage was unavailable. This is
    /// distinct from the phone returning a different credential/PRF result.
    Unavailable,
}

pub fn remember_requested_nearby(
    name: &str,
    credential_id: &[u8],
    raw_key: &[u8],
) -> NearbyRememberOutcome {
    // This may run before a derivation command writes stdout, so every message
    // remains a non-panicking stderr note and cannot corrupt key output.
    let could_not = |why: &str| {
        crate::note(&format!(
            "warning: you asked on your phone to remember '{name}' on this machine, but {why}"
        ));
    };
    let authority = match crate::nearby_identity::remember_authority() {
        Ok(authority) => authority,
        Err(error) => {
            could_not(&format!(
                "the passkey identity could not be checked: {error}"
            ));
            return NearbyRememberOutcome::Unavailable;
        }
    };
    if authority.credential_id() != credential_id {
        could_not("the passkey is no longer this machine's current nearby identity");
        return NearbyRememberOutcome::Unavailable;
    }

    let mut target = match resolve_write_target() {
        Ok(target) => target,
        Err(e) => {
            could_not(&e.to_string());
            return NearbyRememberOutcome::Unavailable;
        }
    };
    match remember_root_in(
        target.store.as_mut(),
        name,
        &root_id(authority.credential_id()),
        raw_key,
    ) {
        Ok(()) => match authority.revalidate() {
            Ok(true) => {
                crate::note(&format!(
                    "Remembered '{name}' in {location}, as requested on your phone. Future keytap \
                     commands for this name will not prompt until you run `keytap forget {name}` or \
                     replace the passkey.",
                    location = target.location
                ));
                NearbyRememberOutcome::Stored
            }
            Ok(false) | Err(_) => {
                could_not("the nearby identity changed while the key was being stored");
                NearbyRememberOutcome::Unavailable
            }
        },
        Err(e) => {
            could_not(&e.to_string());
            NearbyRememberOutcome::Unavailable
        }
    }
}

/// Delete the remembered key for `name` under the authoritative root, from every
/// store that holds one.
pub fn forget(name: &str) {
    let authority = crate::nearby_identity::remember_authority().unwrap_or_else(|error| {
        crate::die(&format!(
            "could not determine the current passkey identity: {error}; use `keytap forget --all` to clear every root"
        ))
    });
    let root = root_id(authority.credential_id());
    let mut stores = open_stores().unwrap_or_else(|e| crate::die(&e.to_string()));
    let mut deleted = false;
    for store in &mut stores {
        match forget_root_in(store.as_mut(), &root, name) {
            Ok(d) => deleted |= d,
            Err(e) => crate::die(&e.to_string()),
        }
    }
    if !matches!(authority.revalidate(), Ok(true)) {
        crate::die(
            "the passkey identity changed while the remembered key was being deleted; retry",
        );
    }
    if deleted {
        eprintln!("Forgot '{name}'. The next keytap command for this name will prompt again.");
    } else {
        crate::die(&format!(
            "no remembered key named '{name}' for the current passkey"
        ));
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

/// Print the names remembered under the authoritative root, one per line, across
/// every store (each name once, even when stores overlap).
pub fn remembered() {
    let authority = crate::nearby_identity::remember_authority().unwrap_or_else(|error| {
        crate::die(&format!(
            "could not determine the current passkey identity: {error}"
        ))
    });
    let root = root_id(authority.credential_id());
    let stores = open_stores().unwrap_or_else(|e| crate::die(&e.to_string()));
    let mut names: Vec<String> = Vec::new();
    for store in &stores {
        match list_root_in(store.as_ref(), &root) {
            Ok(mut listed) => names.append(&mut listed),
            Err(e) => crate::die(&e.to_string()),
        }
    }
    names.sort();
    names.dedup();
    if !matches!(authority.revalidate(), Ok(true)) {
        crate::die("the passkey identity changed while remembered keys were being listed; retry");
    }
    if names.is_empty() {
        eprintln!("No remembered keys for the current passkey.");
    } else {
        for name in names {
            println!("{name}");
        }
    }
}

/// Best-effort cleanup after a successful init. Identity publication already
/// made every old-root entry unreachable, so cleanup failure cannot revive it.
pub fn after_init() {
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

    let mut removed = 0;
    for store in &mut stores {
        match forget_all_in(store.as_mut()) {
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
    account
        .strip_prefix(REMEMBER_ACCOUNT_PREFIX)?
        .split_once(':')
}

fn encode_key_value(raw_key: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(format!("{KEY_VALUE_PREFIX}{}", hex::encode(raw_key)))
}

fn decode_key_value(value: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let text = std::str::from_utf8(value).ok()?;
    let bytes = hex::decode(text.strip_prefix(KEY_VALUE_PREFIX)?).ok()?;
    (bytes.len() == 32).then(|| Zeroizing::new(bytes))
}

enum Resolution {
    Hit(Zeroizing<Vec<u8>>),
    Miss,
    /// An entry exists but its value doesn't parse; callers treat it as a
    /// miss (fall back to the ceremony) but may want to tell the user.
    Invalid,
}

fn lookup_root_in(
    kc: &(impl Keychain + ?Sized),
    root: &str,
    name: &str,
) -> Result<Resolution, KeychainError> {
    let Some(value) = kc.get(&remember_account(&root, name))? else {
        return Ok(Resolution::Miss);
    };
    Ok(match decode_key_value(&value) {
        Some(key) => Resolution::Hit(key),
        None => Resolution::Invalid,
    })
}

fn remember_root_in(
    kc: &mut (impl Keychain + ?Sized),
    name: &str,
    root: &str,
    raw_key: &[u8],
) -> Result<(), KeychainError> {
    kc.set(
        &remember_account(&root, name),
        encode_key_value(raw_key).as_bytes(),
    )?;
    Ok(())
}

/// Whether the entry for `name` under `root` existed (and was deleted).
fn forget_root_in(
    kc: &mut (impl Keychain + ?Sized),
    root: &str,
    name: &str,
) -> Result<bool, KeychainError> {
    kc.delete(&remember_account(&root, name))
}

/// Delete every `remember:*` entry regardless of root; returns how many.
/// Leaves unrelated user-managed entries alone.
fn forget_all_in(kc: &mut (impl Keychain + ?Sized)) -> Result<usize, KeychainError> {
    let mut deleted = 0;
    for account in kc.accounts()? {
        if parse_remember_account(&account).is_some() && kc.delete(&account)? {
            deleted += 1;
        }
    }
    Ok(deleted)
}

/// Names remembered under `root`, sorted.
fn list_root_in(kc: &(impl Keychain + ?Sized), root: &str) -> Result<Vec<String>, KeychainError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::memory::MemoryKeychain;

    const KEY_A: [u8; 32] = [0xAA; 32];
    const KEY_B: [u8; 32] = [0xBB; 32];
    const CRED_1: &[u8] = b"credential-one";
    const CRED_2: &[u8] = b"credential-two";

    /// A store that answers reads but refuses writes, like a keychain that
    /// can't show its unlock dialog.
    struct ReadOnlyKeychain;

    impl Keychain for ReadOnlyKeychain {
        fn get(&self, _: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
            Ok(None)
        }
        fn set(&mut self, _: &str, _: &[u8]) -> Result<(), KeychainError> {
            Err(KeychainError::Backend(
                "interaction not allowed".to_string(),
            ))
        }
        fn delete(&mut self, _: &str) -> Result<bool, KeychainError> {
            Err(KeychainError::Backend(
                "interaction not allowed".to_string(),
            ))
        }
        fn accounts(&self) -> Result<Vec<String>, KeychainError> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn probe_passes_on_a_working_store_and_leaves_no_trace() {
        let mut kc = MemoryKeychain::default();
        probe_writable(&mut kc).unwrap();
        assert!(
            kc.accounts().unwrap().is_empty(),
            "the probe must clean up after itself"
        );
    }

    #[test]
    fn probe_surfaces_a_store_that_refuses_writes() {
        assert!(probe_writable(&mut ReadOnlyKeychain).is_err());
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
        let root = root_id(CRED_1);
        remember_root_in(&mut kc, "deploy", &root, &KEY_A).unwrap();
        match lookup_root_in(&kc, &root, "deploy").unwrap() {
            Resolution::Hit(key) => assert_eq!(&key[..], &KEY_A),
            _ => panic!("expected a hit"),
        }
        // A name that was never remembered stays a miss.
        assert!(matches!(
            lookup_root_in(&kc, &root, "other").unwrap(),
            Resolution::Miss
        ));
    }

    /// The full remember policy over the plain-file store: it is just another
    /// `Keychain`, so root scoping and cleanup behave exactly as they do in
    /// the OS keychain.
    #[test]
    fn remember_policy_holds_over_the_file_store() {
        let dir =
            std::env::temp_dir().join(format!("keytap-remember-file-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut store = crate::keychain::file::FileStore::at(dir.join("remembered.json"));

        let root_one = root_id(CRED_1);
        let root_two = root_id(CRED_2);
        remember_root_in(&mut store, "deploy", &root_one, &KEY_A).unwrap();
        match lookup_root_in(&store, &root_one, "deploy").unwrap() {
            Resolution::Hit(key) => assert_eq!(&key[..], &KEY_A),
            _ => panic!("expected a hit"),
        }

        remember_root_in(&mut store, "deploy", &root_two, &KEY_B).unwrap();
        match lookup_root_in(&store, &root_one, "deploy").unwrap() {
            Resolution::Hit(key) => assert_eq!(&key[..], &KEY_A),
            _ => panic!("the other root must not overwrite this one"),
        }
        assert_eq!(forget_all_in(&mut store).unwrap(), 2);
        assert!(matches!(
            lookup_root_in(&store, &root_one, "deploy").unwrap(),
            Resolution::Miss
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lookup_is_scoped_to_the_authoritative_root() {
        let mut kc = MemoryKeychain::default();
        kc.set(
            &remember_account(&root_id(CRED_2), "deploy"),
            encode_key_value(&KEY_B).as_bytes(),
        )
        .unwrap();
        assert!(matches!(
            lookup_root_in(&kc, &root_id(CRED_1), "deploy").unwrap(),
            Resolution::Miss
        ));
    }

    #[test]
    fn identity_commit_revokes_old_root_before_keychain_cleanup() {
        let path = std::env::temp_dir()
            .join(format!(
                "keytap-remember-identity-authority-test-{}",
                std::process::id()
            ))
            .join("nearby-identity.json");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());

        crate::nearby_identity::prepare_init_at(
            path.clone(),
            crate::nearby_identity::InitMode::Create,
        )
        .unwrap()
        .commit(CRED_1)
        .unwrap();
        let mut kc = MemoryKeychain::default();
        remember_root_in(&mut kc, "deploy", &root_id(CRED_1), &KEY_A).unwrap();
        let replacement = crate::nearby_identity::prepare_init_at(
            path.clone(),
            crate::nearby_identity::InitMode::Replace,
        )
        .unwrap();
        replacement.commit(CRED_2).unwrap();

        // This models a crash immediately after identity publication and
        // before after_init removes the stale keychain entry.
        let authority = crate::nearby_identity::remember_authority_at(path.clone()).unwrap();
        assert!(matches!(
            lookup_authorized_in(&kc, "deploy", &authority).unwrap(),
            Resolution::Miss
        ));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn init_cleanup_wipes_all_roots() {
        let mut kc = MemoryKeychain::default();
        remember_root_in(&mut kc, "deploy", &root_id(CRED_1), &KEY_A).unwrap();
        remember_root_in(&mut kc, "backup", &root_id(CRED_1), &KEY_B).unwrap();
        // A stray entry from an even older root is wiped too.
        kc.set(
            &remember_account(&root_id(b"ancient"), "old"),
            encode_key_value(&KEY_B).as_bytes(),
        )
        .unwrap();
        // A user-managed entry under the keytap service survives cleanup.
        kc.set("deploy", b"user-managed").unwrap();

        assert_eq!(forget_all_in(&mut kc).unwrap(), 3);
        assert!(list_root_in(&kc, &root_id(CRED_1)).unwrap().is_empty());
        assert!(matches!(
            lookup_root_in(&kc, &root_id(CRED_1), "deploy").unwrap(),
            Resolution::Miss
        ));
        assert_eq!(&kc.get("deploy").unwrap().unwrap()[..], b"user-managed");
    }

    #[test]
    fn forget_removes_only_the_named_entry() {
        let mut kc = MemoryKeychain::default();
        let root = root_id(CRED_1);
        remember_root_in(&mut kc, "deploy", &root, &KEY_A).unwrap();
        remember_root_in(&mut kc, "backup", &root, &KEY_B).unwrap();
        assert!(forget_root_in(&mut kc, &root, "deploy").unwrap());
        assert!(
            !forget_root_in(&mut kc, &root, "deploy").unwrap(),
            "already gone"
        );
        assert!(!forget_root_in(&mut kc, &root, "never-stored").unwrap());
        assert_eq!(
            list_root_in(&kc, &root).unwrap(),
            vec!["backup".to_string()]
        );
    }

    #[test]
    fn forget_all_clears_every_root_but_spares_everything_else() {
        let mut kc = MemoryKeychain::default();
        remember_root_in(&mut kc, "deploy", &root_id(CRED_1), &KEY_A).unwrap();
        kc.set(
            &remember_account(&root_id(CRED_2), "stale"),
            encode_key_value(&KEY_B).as_bytes(),
        )
        .unwrap();
        kc.set("deploy", b"user-managed").unwrap();

        assert_eq!(forget_all_in(&mut kc).unwrap(), 2);
        assert_eq!(forget_all_in(&mut kc).unwrap(), 0, "idempotent");
        // User-managed entries are not "remembered keys".
        assert_eq!(&kc.get("deploy").unwrap().unwrap()[..], b"user-managed");
    }

    #[test]
    fn list_reports_names_for_one_root_sorted() {
        let mut kc = MemoryKeychain::default();
        let root = root_id(CRED_1);
        remember_root_in(&mut kc, "zeta", &root, &KEY_A).unwrap();
        remember_root_in(&mut kc, "alpha", &root, &KEY_B).unwrap();
        // Names may contain the account separator.
        remember_root_in(&mut kc, "ns:key", &root, &KEY_A).unwrap();
        kc.set(
            &remember_account(&root_id(CRED_2), "foreign"),
            encode_key_value(&KEY_B).as_bytes(),
        )
        .unwrap();

        assert_eq!(
            list_root_in(&kc, &root).unwrap(),
            vec!["alpha", "ns:key", "zeta"]
        );
    }

    #[test]
    fn malformed_entries_resolve_to_invalid_not_a_key() {
        let mut kc = MemoryKeychain::default();
        let root = root_id(CRED_1);
        for bad in [
            b"garbage".as_slice(),                 // no prefix
            b"keytap-remember-v1:zz".as_slice(),   // not hex
            b"keytap-remember-v1:aabb".as_slice(), // wrong length
            b"\xff\xfe".as_slice(),                // not UTF-8
        ] {
            kc.set(&remember_account(&root, "deploy"), bad).unwrap();
            assert!(matches!(
                lookup_root_in(&kc, &root, "deploy").unwrap(),
                Resolution::Invalid
            ));
        }
    }

    #[test]
    fn value_encoding_round_trips_and_rejects_truncation() {
        let encoded = encode_key_value(&KEY_A);
        assert_eq!(&decode_key_value(encoded.as_bytes()).unwrap()[..], &KEY_A);
        assert!(decode_key_value(&encoded.as_bytes()[..encoded.len() - 2]).is_none());
    }
}
