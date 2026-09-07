//! Three-way merge of vault revisions, for use as a Git merge driver.
//!
//! Values and grants merge independently by name and label with the usual
//! rule: a side that matches the base yields to the other side, agreement
//! wins, and disagreement is a conflict left for the user. The data key is
//! chosen so that a key removed on either side can never read the result.

use std::collections::BTreeSet;

use crate::vault::UnlockedVault;

pub struct Merged {
    pub vault: UnlockedVault,
    /// Variable names and `grant:<label>` entries that could not be merged.
    /// The result keeps our side for each of them.
    pub conflicts: Vec<String>,
}

fn value_of(vault: &UnlockedVault, name: &str) -> Option<String> {
    vault.get(name).map(str::to_owned)
}

fn grant_of(vault: &UnlockedVault, label: &str) -> Option<crate::identity::Recipient> {
    vault
        .grants()
        .find(|grant| grant.label == label)
        .map(|grant| grant.recipient.clone())
}

/// Merge `theirs` into `ours` relative to `base`. All three must be the
/// same vault. A missing base means the file was created on both sides,
/// which only merges if the two creations share a vault ID.
pub fn three_way(
    base: Option<&UnlockedVault>,
    mut ours: UnlockedVault,
    theirs: &UnlockedVault,
) -> Result<Merged, String> {
    if ours.id() != theirs.id() || base.is_some_and(|base| base.id() != ours.id()) {
        return Err(
            "the two sides are different vaults; keep one file and re-add the other side's variables"
                .to_owned(),
        );
    }
    let mut conflicts = Vec::new();

    let mut names: BTreeSet<String> = BTreeSet::new();
    for vault in base.into_iter().chain([&ours, theirs]) {
        names.extend(vault.variables().map(str::to_owned));
    }
    for name in names {
        let in_base = base.and_then(|base| value_of(base, &name));
        let in_ours = value_of(&ours, &name);
        let in_theirs = value_of(theirs, &name);
        if in_ours == in_theirs || in_theirs == in_base {
            continue;
        }
        if in_ours != in_base {
            conflicts.push(name);
            continue;
        }
        match in_theirs {
            Some(value) => {
                ours.set(&name, &value)
                    .map_err(|error| format!("{name}: {error}"))?;
            }
            None => {
                ours.unset(&name)
                    .map_err(|error| format!("{name}: {error}"))?;
            }
        }
    }

    let mut labels: BTreeSet<String> = BTreeSet::new();
    for vault in base.into_iter().chain([&ours, theirs]) {
        labels.extend(vault.grants().map(|grant| grant.label.clone()));
    }
    let mut removed_by_ours = false;
    let mut removed_by_theirs = false;
    for label in labels {
        let in_base = base.and_then(|base| grant_of(base, &label));
        let in_ours = grant_of(&ours, &label);
        let in_theirs = grant_of(theirs, &label);
        if in_base.is_some() && in_ours.is_none() {
            removed_by_ours = true;
        }
        if in_base.is_some() && in_theirs.is_none() {
            removed_by_theirs = true;
        }
        if in_ours == in_theirs || in_theirs == in_base {
            continue;
        }
        if in_ours != in_base {
            conflicts.push(format!("grant:{label}"));
            continue;
        }
        match in_theirs {
            Some(recipient) => {
                ours.grant(&label, &recipient)
                    .map_err(|error| format!("grant {label}: {error}"))?;
            }
            None => {
                ours.remove_grant(&label)
                    .map_err(|error| format!("grant {label}: {error}"))?;
            }
        }
    }

    let ours_rotated = base.is_some_and(|base| base.data_key() != ours.data_key());
    let theirs_rotated = base.is_some_and(|base| base.data_key() != theirs.data_key());
    if theirs_rotated && !ours_rotated && !removed_by_ours {
        // Their key postdates every removal, and ours never left the base.
        let key = *theirs.data_key();
        ours.rekey(&key);
    } else if removed_by_theirs || (theirs_rotated && ours_rotated) {
        ours.rotate().map_err(|error| error.to_string())?;
    }

    Ok(Merged {
        vault: ours,
        conflicts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{LocalIdentity, Recipient};
    use crate::vault::LockedVault;
    use age::x25519;

    fn identity() -> (LocalIdentity, Recipient) {
        let identity = x25519::Identity::generate();
        let recipient = Recipient::Age(identity.to_public());
        (LocalIdentity::Age(identity), recipient)
    }

    fn open(bytes: &[u8], identity: &LocalIdentity) -> UnlockedVault {
        LockedVault::parse(bytes)
            .unwrap()
            .unlock(std::slice::from_ref(identity))
            .unwrap()
    }

    fn can_open(bytes: &[u8], identity: &LocalIdentity) -> bool {
        LockedVault::parse(bytes)
            .unwrap()
            .unlock(std::slice::from_ref(identity))
            .is_ok()
    }

    #[test]
    fn merges_independent_changes_and_flags_conflicts() {
        let (owner, owner_key) = identity();
        let (sam, sam_key) = identity();
        let mut base = UnlockedVault::create("owner", &owner_key).unwrap();
        base.set("A", "a").unwrap();
        base.set("B", "b").unwrap();
        base.set("C", "c").unwrap();
        let base_bytes = base.render().unwrap();
        let base = open(&base_bytes, &owner);

        let mut ours = open(&base_bytes, &owner);
        ours.set("A", "ours").unwrap();
        ours.set("C", "both").unwrap();
        ours.set("NEW_OURS", "1").unwrap();
        ours.grant("sam", &sam_key).unwrap();
        let ours = open(&ours.render().unwrap(), &owner);

        let mut theirs = open(&base_bytes, &owner);
        theirs.set("B", "theirs").unwrap();
        theirs.set("C", "both").unwrap();
        theirs.unset("A").unwrap();
        theirs.set("NEW_THEIRS", "2").unwrap();
        let theirs = open(&theirs.render().unwrap(), &owner);

        let merged = three_way(Some(&base), ours, &theirs).unwrap();
        assert_eq!(merged.conflicts, vec!["A".to_owned()]);
        let mut vault = merged.vault;
        assert_eq!(vault.get("A"), Some("ours"));
        assert_eq!(vault.get("B"), Some("theirs"));
        assert_eq!(vault.get("C"), Some("both"));
        assert_eq!(vault.get("NEW_OURS"), Some("1"));
        assert_eq!(vault.get("NEW_THEIRS"), Some("2"));
        let bytes = vault.render().unwrap();
        assert_eq!(open(&bytes, &sam).granted_as(), "sam");
    }

    #[test]
    fn a_revocation_on_either_side_survives_the_merge() {
        let (owner, owner_key) = identity();
        let (sam, sam_key) = identity();
        let mut base = UnlockedVault::create("owner", &owner_key).unwrap();
        base.set("A", "a").unwrap();
        base.grant("sam", &sam_key).unwrap();
        let base_bytes = base.render().unwrap();
        let base = open(&base_bytes, &owner);

        let mut ours = open(&base_bytes, &owner);
        ours.set("A", "ours").unwrap();
        let ours = open(&ours.render().unwrap(), &owner);
        let mut theirs = open(&base_bytes, &owner);
        theirs.revoke("sam").unwrap();
        let theirs = open(&theirs.render().unwrap(), &owner);

        let merged = three_way(Some(&base), ours, &theirs).unwrap();
        assert!(merged.conflicts.is_empty());
        let mut vault = merged.vault;
        assert_eq!(vault.data_key(), theirs.data_key());
        let bytes = vault.render().unwrap();
        assert!(!can_open(&bytes, &sam));
        assert_eq!(open(&bytes, &owner).get("A"), Some("ours"));

        // Ours rotated as well, so neither parent key may survive.
        let mut ours = open(&base_bytes, &owner);
        ours.rotate().unwrap();
        let ours = open(&ours.render().unwrap(), &owner);
        let mut vault = three_way(Some(&base), ours, &theirs).unwrap().vault;
        assert_ne!(vault.data_key(), theirs.data_key());
        let bytes = vault.render().unwrap();
        assert!(!can_open(&bytes, &sam));

        // A grant removed on our side while theirs only changed a value.
        let mut ours = open(&base_bytes, &owner);
        ours.revoke("sam").unwrap();
        let ours = open(&ours.render().unwrap(), &owner);
        let mut theirs = open(&base_bytes, &owner);
        theirs.set("A", "theirs").unwrap();
        let theirs = open(&theirs.render().unwrap(), &owner);
        let mut vault = three_way(Some(&base), ours, &theirs).unwrap().vault;
        let bytes = vault.render().unwrap();
        assert!(!can_open(&bytes, &sam));
        assert_eq!(open(&bytes, &owner).get("A"), Some("theirs"));
    }

    #[test]
    fn different_vaults_do_not_merge() {
        let (owner, owner_key) = identity();
        let mut ours = UnlockedVault::create("owner", &owner_key).unwrap();
        let mut theirs = UnlockedVault::create("owner", &owner_key).unwrap();
        let ours = open(&ours.render().unwrap(), &owner);
        let theirs = open(&theirs.render().unwrap(), &owner);
        assert!(three_way(None, ours, &theirs).is_err());
    }
}
