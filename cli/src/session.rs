//! Implicit sessions: the first derivation of a key name holds the derived
//! key in the OS keychain (macOS Keychain; libsecret on Linux) so repeat uses
//! within the session window skip the passkey ceremony — the sudo model.
//!
//! A held key can never be *stale*: derivation is deterministic, so a session
//! hit is byte-identical to a fresh ceremony. The window only bounds how long
//! the key sits in the keychain and how long processes running as the user
//! can read it through keytap without a prompt.
//!
//! Controls: `KEYTAP_SESSION=off` disables sessions entirely (read and
//! write), `KEYTAP_SESSION=<ttl>` changes the window, and `keytap forget
//! NAME` ends one key's session early. The keychain writes go through an
//! API/stdin — never argv, where other processes could read the key from the
//! process table.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

/// Session window when `KEYTAP_SESSION` is unset: roughly one passkey prompt
/// per key name per workday.
const DEFAULT_TTL: Duration = Duration::from_secs(12 * 3600);

const ENV_VAR: &str = "KEYTAP_SESSION";

/// Keychain coordinates: one fixed service for all keytap entries, one
/// account per key name, so held keys are recognizable and auditable in
/// Keychain Access / seahorse.
const SERVICE: &str = "keytap";

/// Version tag so a future payload layout can be detected instead of
/// misparsed. Entries under the same service that don't start with this
/// (e.g. a consumer's own cache) are left untouched.
const PAYLOAD_PREFIX: &str = "keytap-session-v1";

/// Look up a held key. Misses when sessions are off, the entry is absent or
/// expired (expired entries are deleted), or the payload is unrecognized.
pub fn load(name: &str) -> Option<Zeroizing<Vec<u8>>> {
    ttl_from_env()?;
    let payload = backend::read(name)?;
    let (expires_at, raw_key) = decode_payload(&payload)?;
    if let Some(t) = expires_at {
        if now_unix() >= t {
            let _ = backend::delete(name);
            return None;
        }
    }
    Some(raw_key)
}

/// Start a session for a freshly derived key, best-effort: a keychain failure
/// warns on stderr but never fails the command that derived the key.
pub fn store(name: &str, raw_key: &[u8]) {
    let Some(ttl) = ttl_from_env() else { return };
    if !backend::available() {
        return;
    }
    let expires_at = now_unix().saturating_add(ttl.as_secs());
    let payload = Zeroizing::new(encode_payload(raw_key, expires_at));
    match backend::write(name, &payload) {
        // Announce the posture change: the user should never be surprised
        // that a key stopped prompting.
        Ok(()) => eprintln!(
            "note: holding '{name}' in the OS keychain for {} — `keytap forget {name}` ends the session, KEYTAP_SESSION=off disables sessions",
            humanize(ttl)
        ),
        Err(e) => eprintln!("warning: couldn't hold the key in the OS keychain: {e}"),
    }
}

/// End a session. `Ok(true)` if an entry was removed, `Ok(false)` if there
/// was nothing to remove. Works even when sessions are disabled.
pub fn forget(name: &str) -> Result<bool, String> {
    backend::delete(name)
}

/// The session window: `None` when sessions are off. Unset env → default;
/// `off`/`0` → disabled; otherwise a TTL like `900`, `15m`, `12h`, `7d`.
fn ttl_from_env() -> Option<Duration> {
    match std::env::var(ENV_VAR) {
        Err(_) => Some(DEFAULT_TTL),
        Ok(v) => parse_session_env(&v)
            .unwrap_or_else(|e| crate::die(&format!("invalid {ENV_VAR}: {e}"))),
    }
}

fn parse_session_env(value: &str) -> Result<Option<Duration>, String> {
    match value.trim() {
        "" => Ok(Some(DEFAULT_TTL)),
        "off" | "0" | "none" => Ok(None),
        ttl => parse_ttl(ttl).map(Some),
    }
}

/// Parse a TTL like `900` (seconds), `45s`, `15m`, `12h`, or `7d`.
fn parse_ttl(s: &str) -> Result<Duration, String> {
    let err =
        || format!("invalid TTL '{s}': use seconds or a number with s/m/h/d (e.g. 900, 15m, 12h)");
    let (digits, unit_secs) = match s.as_bytes().last() {
        Some(b's') => (&s[..s.len() - 1], 1u64),
        Some(b'm') => (&s[..s.len() - 1], 60),
        Some(b'h') => (&s[..s.len() - 1], 3600),
        Some(b'd') => (&s[..s.len() - 1], 86400),
        _ => (s, 1),
    };
    let n: u64 = digits.parse().map_err(|_| err())?;
    let secs = n.checked_mul(unit_secs).ok_or_else(err)?;
    if secs == 0 {
        return Err("TTL must be positive".to_string());
    }
    Ok(Duration::from_secs(secs))
}

/// `12h`-style rendering for the session-start note.
fn humanize(d: Duration) -> String {
    let secs = d.as_secs();
    match secs {
        s if s % 86400 == 0 => format!("{}d", s / 86400),
        s if s % 3600 == 0 => format!("{}h", s / 3600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

/// `keytap-session-v1:<expires-unix|0>:<hex key>` — `0` means no expiry.
fn encode_payload(raw_key: &[u8], expires_at: u64) -> String {
    format!("{PAYLOAD_PREFIX}:{expires_at}:{}", hex::encode(raw_key))
}

fn decode_payload(payload: &str) -> Option<(Option<u64>, Zeroizing<Vec<u8>>)> {
    let rest = payload.strip_prefix(PAYLOAD_PREFIX)?.strip_prefix(':')?;
    let (expires, key_hex) = rest.split_once(':')?;
    let expires: u64 = expires.parse().ok()?;
    let expires_at = (expires != 0).then_some(expires);
    let raw_key = Zeroizing::new(hex::decode(key_hex).ok()?);
    Some((expires_at, raw_key))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(target_os = "macos")]
mod backend {
    use security_framework::passwords;
    use zeroize::Zeroizing;

    use super::SERVICE;

    /// SecItemCopyMatching's "not found" — the only error that means a clean
    /// miss rather than a real keychain failure.
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

    pub fn available() -> bool {
        true
    }

    pub fn read(account: &str) -> Option<Zeroizing<String>> {
        let bytes = passwords::get_generic_password(SERVICE, account).ok()?;
        String::from_utf8(bytes).ok().map(Zeroizing::new)
    }

    pub fn write(account: &str, payload: &str) -> Result<(), String> {
        passwords::set_generic_password(SERVICE, account, payload.as_bytes())
            .map_err(|e| e.to_string())
    }

    pub fn delete(account: &str) -> Result<bool, String> {
        match passwords::delete_generic_password(SERVICE, account) {
            Ok(()) => Ok(true),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(false),
            Err(e) => Err(e.to_string()),
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod backend {
    use std::io::Write;
    use std::process::{Command, Stdio};

    use zeroize::Zeroizing;

    use super::SERVICE;

    /// libsecret attribute pairs; matches the manual pattern documented in
    /// the README (`secret-tool lookup service keytap key NAME`).
    fn attributes(account: &str) -> [&str; 4] {
        ["service", SERVICE, "key", account]
    }

    /// Without `secret-tool` there is no holder; sessions silently degrade
    /// to a ceremony per derivation rather than nagging on every command.
    pub fn available() -> bool {
        Command::new("secret-tool")
            .arg("--help")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    pub fn read(account: &str) -> Option<Zeroizing<String>> {
        let out = Command::new("secret-tool")
            .arg("lookup")
            .args(attributes(account))
            .stderr(Stdio::null())
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let payload = String::from_utf8(out.stdout).ok()?;
        let payload = payload.trim_end_matches('\n');
        if payload.is_empty() {
            None
        } else {
            Some(Zeroizing::new(payload.to_string()))
        }
    }

    pub fn write(account: &str, payload: &str) -> Result<(), String> {
        // The key goes through stdin — never argv, where other processes
        // could read it from the process table.
        let mut child = Command::new("secret-tool")
            .args(["store", "--label", &format!("keytap {account}")])
            .args(attributes(account))
            .stdin(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;
        child
            .stdin
            .as_mut()
            .ok_or("secret-tool stdin closed")?
            .write_all(payload.as_bytes())
            .map_err(|e| e.to_string())?;
        let status = child.wait().map_err(|e| e.to_string())?;
        if status.success() {
            Ok(())
        } else {
            Err("secret-tool store failed".to_string())
        }
    }

    pub fn delete(account: &str) -> Result<bool, String> {
        let status = Command::new("secret-tool")
            .arg("clear")
            .args(attributes(account))
            .stderr(Stdio::null())
            .status()
            .map_err(|e| e.to_string())?;
        // secret-tool clear exits nonzero when nothing matched.
        Ok(status.success())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_parses_units() {
        assert_eq!(parse_ttl("900").unwrap(), Duration::from_secs(900));
        assert_eq!(parse_ttl("45s").unwrap(), Duration::from_secs(45));
        assert_eq!(parse_ttl("15m").unwrap(), Duration::from_secs(900));
        assert_eq!(parse_ttl("12h").unwrap(), Duration::from_secs(43200));
        assert_eq!(parse_ttl("7d").unwrap(), Duration::from_secs(604800));
    }

    #[test]
    fn ttl_rejects_garbage() {
        for bad in ["", "0", "0m", "-5", "12x", "h", "1.5h", "99999999999999999999d"] {
            assert!(parse_ttl(bad).is_err(), "expected error for {bad:?}");
        }
    }

    #[test]
    fn env_values() {
        assert_eq!(parse_session_env("off").unwrap(), None);
        assert_eq!(parse_session_env("0").unwrap(), None);
        assert_eq!(parse_session_env("none").unwrap(), None);
        assert_eq!(parse_session_env("").unwrap(), Some(DEFAULT_TTL));
        assert_eq!(
            parse_session_env("30m").unwrap(),
            Some(Duration::from_secs(1800))
        );
        assert!(parse_session_env("soon").is_err());
    }

    #[test]
    fn humanize_prefers_largest_exact_unit() {
        assert_eq!(humanize(Duration::from_secs(43200)), "12h");
        assert_eq!(humanize(Duration::from_secs(86400)), "1d");
        assert_eq!(humanize(Duration::from_secs(90)), "90s");
        assert_eq!(humanize(Duration::from_secs(1800)), "30m");
    }

    #[test]
    fn payload_roundtrip() {
        let key = [7u8; 32];
        let (expires, decoded) = decode_payload(&encode_payload(&key, 1234)).unwrap();
        assert_eq!(expires, Some(1234));
        assert_eq!(decoded.as_slice(), &key);

        let (expires, decoded) = decode_payload(&encode_payload(&key, 0)).unwrap();
        assert_eq!(expires, None);
        assert_eq!(decoded.as_slice(), &key);
    }

    #[test]
    fn payload_rejects_foreign_entries() {
        // Entries under the keytap service written by other tools (e.g. a
        // consumer's own cache) must be a miss, not a parse of garbage.
        assert!(decode_payload("AGE-SECRET-KEY-1...").is_none());
        assert!(decode_payload("keytap-session-v2:0:aa").is_none());
        assert!(decode_payload("keytap-session-v1:soon:aa").is_none());
        assert!(decode_payload("keytap-session-v1:0:not-hex").is_none());
    }

    /// Real keychain roundtrip; needs an unlocked login keychain (or a
    /// secret-service daemon on Linux), so it's opt-in: `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn live_keychain_roundtrip() {
        let name = "keytap-session-selftest";
        let key = [42u8; 32];

        store(name, &key);
        assert_eq!(load(name).expect("held key").as_slice(), &key);
        assert_eq!(forget(name), Ok(true));
        assert!(load(name).is_none());
        assert_eq!(forget(name), Ok(false));
    }
}
