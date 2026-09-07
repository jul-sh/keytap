//! Locating, locking, and atomically replacing a vault file.
//!
//! Every mutation holds an exclusive advisory lock, re-reads the file under
//! that lock, and replaces it through a temporary file in the same directory
//! only if the file still has the revision that was parsed. An editor save or
//! a Git checkout that lands in between is therefore never overwritten.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use sha2::{Digest, Sha256};

use crate::vault::MAX_FILE_SIZE;

const MAX_GIT_FILE_SIZE: u64 = 4096;

/// The exact bytes a file had when it was read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Revision([u8; 32]);

pub struct Loaded {
    pub bytes: Vec<u8>,
    pub revision: Revision,
}

fn revision_of(bytes: &[u8]) -> Revision {
    Revision(Sha256::digest(bytes).into())
}

/// Read a regular, non-symlinked file with a size limit, verifying that the
/// inode inspected and the inode opened are the same.
pub fn load(path: &Path) -> Result<Loaded, String> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot access {}: {error}", path.display()))?;
    if before.file_type().is_symlink() {
        return Err(format!("refusing to use symlinked file {}", path.display()));
    }
    if !before.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if before.len() > MAX_FILE_SIZE as u64 {
        return Err(format!("{} exceeds the 16 MiB size limit", path.display()));
    }

    let mut file =
        fs::File::open(path).map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    use std::os::unix::fs::MetadataExt;
    if !opened.is_file() || before.dev() != opened.dev() || before.ino() != opened.ino() {
        return Err(format!(
            "{} changed while it was being opened",
            path.display()
        ));
    }

    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_FILE_SIZE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if bytes.len() > MAX_FILE_SIZE {
        return Err(format!("{} exceeds the 16 MiB size limit", path.display()));
    }
    let revision = revision_of(&bytes);
    Ok(Loaded { bytes, revision })
}

/// Search upward from `start` for the nearest `file_name`, stopping at the
/// first directory that contains `.git`. A symlink or non-regular file with
/// that name fails closed instead of being skipped.
pub fn discover(start: &Path, file_name: &str) -> Result<Option<PathBuf>, String> {
    let mut directory = start.to_path_buf();
    loop {
        let candidate = directory.join(file_name);
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!(
                    "refusing to use symlinked file {}",
                    candidate.display()
                ))
            }
            Ok(metadata) if !metadata.is_file() => {
                return Err(format!("{} is not a regular file", candidate.display()))
            }
            Ok(_) => return Ok(Some(candidate)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot inspect {}: {error}", candidate.display())),
        }
        if fs::symlink_metadata(directory.join(".git")).is_ok() || !directory.pop() {
            return Ok(None);
        }
    }
}

/// An exclusive lock on one vault path, held until dropped.
pub struct Lock {
    file: fs::File,
    path: PathBuf,
}

impl Lock {
    pub fn acquire(path: &Path) -> Result<Self, String> {
        let lock_path = lock_path(path)?;
        let file = open_lock_file(&lock_path)?;
        FileExt::lock_exclusive(&file)
            .map_err(|error| format!("cannot lock {}: {error}", lock_path.display()))?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

/// Lock files live under `.git/envtap/locks` for repository vaults and under
/// the user state directory otherwise, never next to the vault itself.
fn lock_path(vault_path: &Path) -> Result<PathBuf, String> {
    let canonical = fs::canonicalize(vault_path)
        .map_err(|error| format!("cannot locate {}: {error}", vault_path.display()))?;
    let directory = match git_metadata_directory(&canonical)? {
        Some(git_directory) => git_directory.join("envtap").join("locks"),
        None => user_state_directory().join("envtap").join("locks"),
    };
    create_private_directories(&directory).map_err(|error| {
        format!(
            "cannot prepare lock directory {}: {error}",
            directory.display()
        )
    })?;
    let metadata = fs::symlink_metadata(&directory).map_err(|error| {
        format!(
            "cannot inspect lock directory {}: {error}",
            directory.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "lock directory {} is not a directory",
            directory.display()
        ));
    }
    use std::os::unix::ffi::OsStrExt;
    let digest = hex::encode(Sha256::digest(canonical.as_os_str().as_bytes()));
    Ok(directory.join(format!("{digest}.lock")))
}

fn git_metadata_directory(vault_path: &Path) -> Result<Option<PathBuf>, String> {
    let mut directory = vault_path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", vault_path.display()))?;
    loop {
        let marker = directory.join(".git");
        match fs::symlink_metadata(&marker) {
            Ok(metadata) if metadata.is_dir() => return Ok(Some(marker)),
            Ok(metadata) if metadata.is_file() => {
                if metadata.len() > MAX_GIT_FILE_SIZE {
                    return Err(format!(
                        "{} is too large to be a Git metadata file",
                        marker.display()
                    ));
                }
                let contents = fs::read_to_string(&marker)
                    .map_err(|error| format!("cannot read {}: {error}", marker.display()))?;
                let value = contents
                    .trim()
                    .strip_prefix("gitdir:")
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        format!("{} is not a valid Git metadata file", marker.display())
                    })?;
                let git_directory = fs::canonicalize(directory.join(value)).map_err(|error| {
                    format!(
                        "cannot locate Git metadata for {}: {error}",
                        marker.display()
                    )
                })?;
                if !git_directory.is_dir() {
                    return Err(format!(
                        "{} is not a Git metadata directory",
                        git_directory.display()
                    ));
                }
                return Ok(Some(git_directory));
            }
            Ok(_) => {
                return Err(format!(
                    "{} is not a Git metadata directory",
                    marker.display()
                ))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot inspect {}: {error}", marker.display())),
        }
        let Some(parent) = directory.parent() else {
            return Ok(None);
        };
        directory = parent;
    }
}

/// `$XDG_STATE_HOME`, else `~/.local/state`, else a per-user temporary
/// directory.
pub fn user_state_directory() -> PathBuf {
    if let Some(path) = std::env::var_os("XDG_STATE_HOME").filter(|value| !value.is_empty()) {
        return PathBuf::from(path);
    }
    if let Some(home) = std::env::var_os("HOME").filter(|value| !value.is_empty()) {
        return PathBuf::from(home).join(".local").join("state");
    }
    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    std::env::temp_dir().join(format!("envtap-{uid}"))
}

pub fn create_private_directories(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
}

fn open_lock_file(path: &Path) -> Result<fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;

    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(format!("{} is not a regular file", path.display()));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot inspect {}: {error}", path.display())),
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    if !file
        .metadata()
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?
        .is_file()
    {
        return Err(format!("{} is not a regular file", path.display()));
    }
    Ok(file)
}

/// Whether a failed commit left the file untouched or partially applied.
#[derive(Debug)]
pub enum CommitError {
    Before(String),
    After(String),
}

impl CommitError {
    pub fn into_message(self) -> String {
        match self {
            CommitError::Before(message) | CommitError::After(message) => message,
        }
    }
}

/// Create a file that must not already exist.
pub fn create(path: &Path, contents: &[u8]) -> Result<(), CommitError> {
    let parent = parent_of(path)?;
    let mut temporary = temporary_in(parent, path)?;
    write_synced(&mut temporary, contents, path)?;
    temporary.persist_noclobber(path).map_err(|error| {
        CommitError::Before(format!("cannot create {}: {}", path.display(), error.error))
    })?;
    sync_parent(parent).map_err(|error| {
        CommitError::After(format!(
            "{} was created, but its directory could not be synced: {error}",
            path.display()
        ))
    })
}

/// Replace the locked file, provided it still has `expected` revision.
pub fn replace(lock: &Lock, contents: &[u8], expected: Revision) -> Result<(), CommitError> {
    let path = lock.path();
    require_revision(path, expected)?;

    let metadata = fs::symlink_metadata(path).map_err(|error| {
        CommitError::Before(format!("cannot inspect {}: {error}", path.display()))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CommitError::Before(format!(
            "{} is not a regular file",
            path.display()
        )));
    }

    let parent = parent_of(path)?;
    let mut temporary = temporary_in(parent, path)?;
    temporary
        .as_file()
        .set_permissions(metadata.permissions())
        .map_err(|error| {
            CommitError::Before(format!(
                "cannot preserve permissions of {}: {error}",
                path.display()
            ))
        })?;
    write_synced(&mut temporary, contents, path)?;
    // Check again at the last possible point so an editor or Git update that
    // landed while the new contents were written is not overwritten.
    require_revision(path, expected)?;
    temporary.persist(path).map_err(|error| {
        CommitError::Before(format!(
            "cannot replace {}: {}",
            path.display(),
            error.error
        ))
    })?;
    sync_parent(parent).map_err(|error| {
        CommitError::After(format!(
            "{} was updated, but its directory could not be synced: {error}",
            path.display()
        ))
    })
}

fn temporary_in(parent: &Path, path: &Path) -> Result<tempfile::NamedTempFile, CommitError> {
    tempfile::Builder::new()
        .prefix(".envtap.")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|error| CommitError::Before(format!("cannot prepare {}: {error}", path.display())))
}

fn write_synced(
    temporary: &mut tempfile::NamedTempFile,
    contents: &[u8],
    path: &Path,
) -> Result<(), CommitError> {
    temporary.write_all(contents).map_err(|error| {
        CommitError::Before(format!("cannot write {}: {error}", path.display()))
    })?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| CommitError::Before(format!("cannot sync {}: {error}", path.display())))
}

fn require_revision(path: &Path, expected: Revision) -> Result<(), CommitError> {
    let actual = load(path).map_err(CommitError::Before)?.revision;
    if actual == expected {
        Ok(())
    } else {
        Err(CommitError::Before(format!(
            "{} changed while the command was running; retry",
            path.display()
        )))
    }
}

fn parent_of(path: &Path) -> Result<&Path, CommitError> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| CommitError::Before(format!("{} has no parent directory", path.display())))
}

fn sync_parent(parent: &Path) -> io::Result<()> {
    fs::File::open(parent)?.sync_all()
}
