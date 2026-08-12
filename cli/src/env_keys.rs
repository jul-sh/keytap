//! Keys handed in via the environment: the CI path.
//!
//! A CI job can hold secrets, but nobody is there to approve a passkey
//! ceremony. The bridge is one environment variable per key name:
//! `KEYTAP_KEY_<NAME>` holds the derived key for `<name>`, in exactly the
//! encoding `keytap reveal <name> --as age` prints (`AGE-SECRET-KEY-1…`).
//! That single format is deliberate — bech32's checksum makes a mangled
//! secret fail loudly at parse time instead of silently deriving a
//! different key.
//!
//! Resolution is per name and puts a variable above every other source: a
//! present variable wins over remembered keys and ceremonies, while an absent
//! variable falls through to them. The ceremony rung remains guarded under
//! `$CI`. A variable that is present but unusable — empty, wrong encoding — is
//! always a hard error, never a silent fall-through to a prompt no one can
//! answer.

use zeroize::Zeroizing;

const PREFIX: &str = "KEYTAP_KEY_";
const BARE: &str = "KEYTAP_KEY";

/// The environment variable that may hold the key for `name`: `KEYTAP_KEY_`
/// plus the name with letters uppercased and every character outside `A-Z0-9`
/// flattened to `_` (`my-app.prod` → `KEYTAP_KEY_MY_APP_PROD`). Distinct
/// names can collide under this rule; keep CI-bound names to `a-z0-9-` and
/// they never do.
pub fn var_name(name: &str) -> String {
    let suffix: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("{PREFIX}{suffix}")
}

/// Resolve `name` from the environment. `Some` on a hit, `None` only when
/// `$KEYTAP_KEY_<NAME>` is absent.
pub fn resolve(name: &str) -> Option<Zeroizing<Vec<u8>>> {
    let var = var_name(name);
    let Ok(value) = std::env::var(&var) else {
        // A bare $KEYTAP_KEY is a misreading of the contract worth correcting
        // loudly, not silently prompting past.
        if std::env::var_os(BARE).is_some() {
            crate::die(&format!(
                "${BARE} is set, but keytap reads one variable per key name: put the key for \
                 '{name}' in ${var}"
            ));
        }
        return None;
    };
    let value = Zeroizing::new(value);
    let value = value.trim();
    if value.is_empty() {
        crate::die(&format!(
            "${var} is set but empty (is the CI secret it maps from unset?)"
        ));
    }
    match keytap_core::parse_age_secret_key(value) {
        Ok(raw_key) => {
            eprintln!("note: key '{name}' from ${var} (passkey not consulted)");
            Some(Zeroizing::new(raw_key))
        }
        Err(e) => crate::die(&format!(
            "${var} doesn't hold an age secret key ({e}). Expected exactly the output of \
             `keytap reveal {name} --as age`, i.e. AGE-SECRET-KEY-1…"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::var_name;

    #[test]
    fn var_name_uppercases_and_flattens() {
        assert_eq!(var_name("ci"), "KEYTAP_KEY_CI");
        assert_eq!(var_name("deploy"), "KEYTAP_KEY_DEPLOY");
        assert_eq!(var_name("my-app.prod"), "KEYTAP_KEY_MY_APP_PROD");
        assert_eq!(var_name("ns:key two"), "KEYTAP_KEY_NS_KEY_TWO");
        assert_eq!(var_name("Already_UPPER1"), "KEYTAP_KEY_ALREADY_UPPER1");
    }
}
