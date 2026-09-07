//! The `envtap` command line, run against a host-provided [`Passkey`].

use std::ffi::OsString;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode, Stdio};

use age::x25519;
use clap::{Args, Parser, Subcommand, ValueEnum};
use zeroize::{Zeroize, Zeroizing};

use crate::identity::{self, Identities, Recipient, IDENTITY_ENVIRONMENT};
use crate::vault::{self, GrantOutcome, LockedVault, SetOutcome, UnlockedVault};
use crate::{dotenv, merge, store, Forgotten, Passkey};

#[derive(Parser)]
#[command(
    name = "envtap",
    version,
    about = "Encrypted .env files with per-person access",
    after_help = "Variable names and grants are readable in tap.env; values are encrypted.\n\
                  Run `envtap <COMMAND> --help` for details.",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(flatten)]
    scope: Scope,
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct Scope {
    /// Use this file instead of the nearest tap.env
    #[arg(short = 'f', long, global = true, value_name = "PATH")]
    file: Option<PathBuf>,

    /// Use tap.<ENV>.env instead of tap.env
    #[arg(
        short = 'e',
        long,
        global = true,
        value_name = "ENV",
        conflicts_with = "file"
    )]
    env: Option<String>,

    /// Decrypt with this age identity file or SSH private key instead of your login
    #[arg(short = 'i', long, global = true, value_name = "PATH")]
    identity: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Log in with your passkey, or remember a key file with -i
    #[command(after_help = LOGIN_HELP)]
    Login {
        /// Create a new passkey instead of using an existing one
        #[arg(long)]
        new: bool,
    },
    /// Forget your key on this machine
    #[command(
        after_help = "This does not delete your passkey, change any file, or revoke access."
    )]
    Logout,
    /// Show the file, your key, your access, variables, and grants
    Status,
    /// Set a variable from a hidden prompt or stdin
    #[command(after_help = SET_HELP)]
    Set {
        name: String,
        /// Label for your key when this command creates the file (default: your user name)
        #[arg(long = "as", value_name = "LABEL")]
        label: Option<String>,
    },
    /// Print one value
    Get { name: String },
    /// Remove a variable from future revisions
    #[command(after_help = "Earlier Git revisions are unchanged.")]
    Unset { name: String },
    /// Run a command with the variables in its environment
    #[command(after_help = RUN_HELP)]
    Run {
        #[arg(required = true, last = true)]
        command: Vec<OsString>,
    },
    /// Print every variable decrypted
    #[command(after_help = EXPORT_HELP)]
    Export {
        #[arg(long, value_enum, default_value_t = Format::Dotenv)]
        format: Format,
    },
    /// Import variables from a plaintext .env file
    #[command(after_help = IMPORT_HELP)]
    Import {
        /// A .env file, or - for stdin
        path: PathBuf,
        /// Label for your key when this command creates the file (default: your user name)
        #[arg(long = "as", value_name = "LABEL")]
        label: Option<String>,
    },
    /// Print your public key for someone to grant
    #[command(name = "public-key")]
    PublicKey,
    /// Grant a public key access
    #[command(after_help = GRANT_HELP)]
    Grant {
        label: String,
        /// An age public key (age1…) or an SSH public key (ssh-ed25519 …)
        #[arg(required = true, num_args = 1.., value_name = "PUBLIC KEY")]
        recipient: Vec<String>,
    },
    /// Remove access and re-encrypt under a new key
    #[command(after_help = REVOKE_HELP)]
    Revoke { label: String },
    /// Re-encrypt every value under a new key
    Rotate,
    /// Create a key for CI, store it with COMMAND, and grant it access
    #[command(name = "grant-ci", after_help = GRANT_CI_HELP)]
    GrantCi {
        label: String,
        #[arg(required = true, last = true)]
        command: Vec<OsString>,
    },
    /// Configure this Git clone to merge and diff envtap files
    #[command(name = "setup-git", after_help = SETUP_GIT_HELP)]
    SetupGit,
    /// Git merge driver: merge THEIRS into OURS relative to BASE
    #[command(hide = true)]
    Merge {
        base: PathBuf,
        ours: PathBuf,
        theirs: PathBuf,
    },
    /// Git textconv: print a file decrypted where possible
    #[command(hide = true)]
    Textconv { path: PathBuf },
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Dotenv,
    Shell,
}

const LOGIN_HELP: &str = "Your key is Keytap's named key `envtap`; envtap is the keytap executable
invoked under this name. `envtap login` approves with your passkey and
remembers the key on this machine, exactly like `keytap remember envtap`, so
one passkey serves every machine and both tools. `envtap login --new` creates
the passkey first, like `keytap init`. When this machine cannot use passkeys
itself, a QR code and a one-use link let a device that can approve instead.
Do not share them.

To use an age identity file or an SSH private key instead of a passkey:

  envtap login -i ~/.ssh/id_ed25519";

const SET_HELP: &str = "Reads the value from a hidden prompt, or from stdin when piped. A missing
tap.env is created in the current directory and grants your key.

  envtap set DATABASE_URL
  envtap set TLS_CERT < cert.pem";

const RUN_HELP: &str =
    "Variables in the file replace inherited variables with the same names; other
variables are preserved. COMMAND is executed directly, keeps this process ID,
and its exit status is returned. ENVTAP_IDENTITY is removed before it starts.";

const EXPORT_HELP: &str =
    "Formats: dotenv (default) and shell, for `eval \"$(envtap export --format shell)\"`.";

const IMPORT_HELP: &str =
    "Every imported variable is stored encrypted. A missing tap.env is created
in the current directory and grants your key.

  envtap import .env";

const GRANT_HELP: &str =
    "LABEL names the key in the file. The public key is what `envtap public-key`
prints on their machine, or their SSH public key.

  envtap grant sam age1…
  envtap grant sam ssh-ed25519 AAAA…";

const REVOKE_HELP: &str = "Values are re-encrypted under a new key that the revoked key never had.
Values already committed remain readable to it in Git history, so rotate
any that matter.";

const GRANT_CI_HELP: &str =
    "The new key's private half is written to COMMAND's stdin. Its public half is
granted only if COMMAND succeeds.

In CI, expose the stored private key as ENVTAP_IDENTITY; `envtap run` uses
it and removes it before starting the command.

  envtap grant-ci github-actions -- gh secret set ENVTAP_IDENTITY
  envtap grant-ci local -- cat";

const SETUP_GIT_HELP: &str =
    "Registers an `envtap` merge driver and diff textconv in this clone's Git
configuration and lists envtap files in .gitattributes. With the driver,
branches that changed different variables merge cleanly and conflicting
variables are named. With the textconv, `git diff` shows values you can
decrypt.";

/// The parsed global options plus the host's passkey. Derefs to [`Scope`]
/// so file selection reads the same everywhere.
struct Context<'a> {
    scope: Scope,
    passkey: &'a dyn Passkey,
}

impl std::ops::Deref for Context<'_> {
    type Target = Scope;

    fn deref(&self) -> &Scope {
        &self.scope
    }
}

pub(crate) fn run(args: impl IntoIterator<Item = OsString>, passkey: &dyn Passkey) -> ExitCode {
    let cli = Cli::parse_from(args);
    let scope = Context {
        scope: cli.scope,
        passkey,
    };
    match dispatch(cli.command, &scope) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(command: Command, scope: &Context) -> Result<ExitCode, String> {
    match command {
        Command::Login { new } => login(scope, new),
        Command::Logout => logout(scope.passkey),
        Command::Status => status(scope),
        Command::Set { name, label } => {
            let value = read_value()?;
            set(scope, &name, &value, label.as_deref())
        }
        Command::Get { name } => get(scope, &name),
        Command::Unset { name } => {
            mutate(scope, |vault| vault.unset(&name).map_err(vault_error))?;
            eprintln!("Removed {name}");
            Ok(ExitCode::SUCCESS)
        }
        Command::Run { command } => run_child(scope, &command),
        Command::Export { format } => export(scope, format),
        Command::Import { path, label } => import(scope, &path, label.as_deref()),
        Command::PublicKey => public_key(scope),
        Command::Grant { label, recipient } => grant(scope, &label, &recipient.join(" ")),
        Command::Revoke { label } => {
            mutate(scope, |vault| vault.revoke(&label).map_err(vault_error))?;
            eprintln!(
                "Revoked {label} and re-encrypted every value under a new key.\n\
                 Values already committed remain readable to that key in Git history; rotate any that matter."
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Rotate => {
            mutate(scope, |vault| vault.rotate().map_err(vault_error))?;
            eprintln!("Re-encrypted every value under a new key.");
            Ok(ExitCode::SUCCESS)
        }
        Command::GrantCi { label, command } => grant_ci(scope, &label, &command),
        Command::SetupGit => setup_git(),
        Command::Merge { base, ours, theirs } => merge_driver(scope, &base, &ours, &theirs),
        Command::Textconv { path } => textconv(scope, &path),
    }
}

// ---------------------------------------------------------------------------
// Locating the file

impl Scope {
    fn file_name(&self) -> Result<String, String> {
        match &self.env {
            None => Ok(vault::DEFAULT_FILE_NAME.to_owned()),
            Some(env) => {
                let valid = !env.is_empty()
                    && env
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
                if !valid {
                    return Err(format!("invalid environment name `{env}`"));
                }
                Ok(format!("tap.{env}.env"))
            }
        }
    }

    /// The existing file this command operates on, if any.
    fn locate(&self) -> Result<Option<PathBuf>, String> {
        if let Some(path) = &self.file {
            return Ok(path.exists().then(|| path.clone()));
        }
        let cwd = std::env::current_dir().map_err(|error| error.to_string())?;
        store::discover(&cwd, &self.file_name()?)
    }

    fn require(&self) -> Result<PathBuf, String> {
        self.locate()?.ok_or_else(|| match &self.file {
            Some(path) => format!("{} does not exist", path.display()),
            None => format!(
                "no {} found here or in a parent directory; run `envtap set NAME` or `envtap import .env` to create one",
                self.file_name().unwrap_or_default()
            ),
        })
    }

    /// Where a new file is created.
    fn creation_path(&self) -> Result<PathBuf, String> {
        match &self.file {
            Some(path) => Ok(path.clone()),
            None => Ok(std::env::current_dir()
                .map_err(|error| error.to_string())?
                .join(self.file_name()?)),
        }
    }
}

// ---------------------------------------------------------------------------
// Opening and committing

struct Opened {
    lock: store::Lock,
    revision: store::Revision,
    vault: UnlockedVault,
}

fn open_for_write(scope: &Context) -> Result<Opened, String> {
    let path = scope.require()?;
    let lock = store::Lock::acquire(&path)?;
    let loaded = store::load(&path)?;
    let locked = LockedVault::parse(&loaded.bytes).map_err(|error| in_file(&path, error))?;
    let identities = identity::resolve(scope.identity.as_deref(), scope.passkey)?;
    let vault = unlock(locked, &identities, &path)?;
    Ok(Opened {
        lock,
        revision: loaded.revision,
        vault,
    })
}

fn open_for_read(scope: &Context) -> Result<(PathBuf, UnlockedVault), String> {
    let path = scope.require()?;
    let loaded = store::load(&path)?;
    let locked = LockedVault::parse(&loaded.bytes).map_err(|error| in_file(&path, error))?;
    let identities = identity::resolve(scope.identity.as_deref(), scope.passkey)?;
    let vault = unlock(locked, &identities, &path)?;
    Ok((path, vault))
}

fn unlock(
    locked: LockedVault,
    identities: &Identities,
    path: &Path,
) -> Result<UnlockedVault, String> {
    match locked.unlock(&identities.list) {
        Ok(vault) => Ok(vault),
        Err(vault::VaultError::NotGranted) => Err(not_granted_message(identities, path)),
        Err(error) => Err(in_file(path, error)),
    }
}

fn not_granted_message(identities: &Identities, path: &Path) -> String {
    let mut message = format!(
        "your key ({}) is not granted access to {}",
        identities.source.describe(),
        path.display()
    );
    let key = identities.public_key().canonical();
    message.push_str(&format!(
        "\n  your public key: {key}\n  ask someone with access to run:\n    envtap grant {} {key}",
        default_label()
    ));
    message
}

fn in_file(path: &Path, error: vault::VaultError) -> String {
    format!("{}: {error}", path.display())
}

fn vault_error(error: vault::VaultError) -> String {
    error.to_string()
}

fn commit(opened: &mut Opened) -> Result<(), String> {
    let bytes = opened.vault.render().map_err(vault_error)?;
    store::replace(&opened.lock, &bytes, opened.revision).map_err(store::CommitError::into_message)
}

fn mutate(
    scope: &Context,
    mutation: impl FnOnce(&mut UnlockedVault) -> Result<(), String>,
) -> Result<(), String> {
    let mut opened = open_for_write(scope)?;
    mutation(&mut opened.vault)?;
    commit(&mut opened)
}

/// Create a new file granting the resolved identity, or fail if one exists.
fn create_vault(scope: &Context, label: Option<&str>) -> Result<(PathBuf, UnlockedVault), String> {
    if std::env::var_os(IDENTITY_ENVIRONMENT).is_some() && scope.identity.is_none() {
        return Err(format!(
            "{IDENTITY_ENVIRONMENT} cannot create a file; use `-i PATH` or `envtap login`"
        ));
    }
    let identities = identity::resolve(scope.identity.as_deref(), scope.passkey)?;
    let owner = identities.public_key();
    let label = label.map(str::to_owned).unwrap_or_else(default_label);
    let vault = UnlockedVault::create(&label, &owner).map_err(vault_error)?;
    Ok((scope.creation_path()?, vault))
}

fn default_label() -> String {
    let user = std::env::var("USER").unwrap_or_default();
    let cleaned: String = user
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .take(vault::MAX_LABEL_BYTES)
        .collect();
    if vault::validate_label(&cleaned).is_ok() {
        cleaned
    } else {
        "owner".to_owned()
    }
}

fn announce_created(path: &Path, vault: &UnlockedVault) {
    eprintln!(
        "Created {} and granted your key as {}",
        path.display(),
        vault.granted_as()
    );
}

// ---------------------------------------------------------------------------
// Commands

fn login(scope: &Context, new: bool) -> Result<ExitCode, String> {
    if let Some(path) = &scope.identity {
        let absolute = identity::remember_identity_file(path)?;
        eprintln!("Logged in with {}", absolute.display());
        let identities = identity::resolve(None, scope.passkey)?;
        eprintln!("Your public key: {}", identities.public_key().canonical());
        return Ok(ExitCode::SUCCESS);
    }
    let passkey = scope.passkey;
    if !new {
        if let Some(identity) = passkey.remembered()? {
            eprintln!(
                "Already logged in with your passkey. Your public key: {}",
                identity.to_public()
            );
            return Ok(ExitCode::SUCCESS);
        }
    }
    let create = if new {
        true
    } else if !io::stdin().is_terminal() || passkey.has_passkey()? {
        false
    } else {
        !ask_yes_no(
            "Do you already have a Keytap passkey? [Y/n] (answer n to create one) ",
            true,
        )?
    };
    if create {
        passkey.init()?;
    }
    passkey.remember()?;
    identity::forget_identity_file()?;
    match passkey.remembered()? {
        Some(identity) => {
            eprintln!("Your public key: {}", identity.to_public());
            Ok(ExitCode::SUCCESS)
        }
        None => Err("the key was not remembered; run `envtap login` again".into()),
    }
}

fn ask_yes_no(prompt: &str, default: bool) -> Result<bool, String> {
    eprint!("{prompt}");
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|error| error.to_string())?;
    Ok(match answer.trim().to_ascii_lowercase().as_str() {
        "" => default,
        "y" | "yes" => true,
        _ => false,
    })
}

fn logout(passkey: &dyn Passkey) -> Result<ExitCode, String> {
    let forgotten = passkey.forget()?;
    let file = identity::forget_identity_file()?;
    match (forgotten, file) {
        (Forgotten::Yes, _) => eprintln!("Logged out; forgot the `envtap` key on this machine."),
        (Forgotten::Nothing, true) => eprintln!("Forgot the remembered key file."),
        (Forgotten::Nothing, false) => eprintln!("Nothing to log out of."),
    }
    Ok(ExitCode::SUCCESS)
}

fn public_key(scope: &Context) -> Result<ExitCode, String> {
    let identities = identity::resolve(scope.identity.as_deref(), scope.passkey)?;
    for identity in &identities.list {
        println!("{}", identity.public_key().canonical());
    }
    Ok(ExitCode::SUCCESS)
}

fn status(scope: &Context) -> Result<ExitCode, String> {
    let mut out = io::stdout().lock();
    let path = match scope.locate()? {
        Some(path) => path,
        None => {
            writeln!(out, "File     none ({} not found)", scope.file_name()?).ok();
            report_identity(&mut out, scope);
            return Ok(ExitCode::SUCCESS);
        }
    };
    writeln!(out, "File     {}", path.display()).ok();
    let identities = report_identity(&mut out, scope);
    let loaded = store::load(&path)?;
    let locked = LockedVault::parse(&loaded.bytes).map_err(|error| in_file(&path, error))?;

    let grants: Vec<(String, String)> = locked
        .grants()
        .map(|grant| (grant.label.clone(), grant.recipient.canonical()))
        .collect();
    let variables: Vec<String> = locked.variables().map(str::to_owned).collect();

    match identities {
        Some(identities) => match locked.unlock(&identities.list) {
            Ok(vault) => writeln!(out, "Access   granted as {}", vault.granted_as()).ok(),
            Err(vault::VaultError::NotGranted) => writeln!(
                out,
                "Access   none; ask someone with access to run: envtap grant {} {}",
                default_label(),
                identities.public_key().canonical()
            )
            .ok(),
            Err(error) => writeln!(out, "Access   error: {error}").ok(),
        },
        None => writeln!(out, "Access   unknown until you log in").ok(),
    };

    writeln!(out, "Values   {}", variables.len()).ok();
    for name in &variables {
        writeln!(out, "  {name}").ok();
    }
    writeln!(out, "Grants").ok();
    let width = grants.iter().map(|(l, _)| l.len()).max().unwrap_or(0);
    for (label, recipient) in &grants {
        writeln!(out, "  {label:width$}  {recipient}").ok();
    }
    Ok(ExitCode::SUCCESS)
}

fn report_identity(out: &mut impl Write, scope: &Context) -> Option<Identities> {
    match identity::resolve(scope.identity.as_deref(), scope.passkey) {
        Ok(identities) => {
            writeln!(
                out,
                "Key      {} ({})",
                identities.public_key().canonical(),
                identities.source.describe()
            )
            .ok();
            Some(identities)
        }
        Err(error) => {
            writeln!(out, "Key      {error}").ok();
            None
        }
    }
}

fn read_value() -> Result<Zeroizing<String>, String> {
    let mut value = if io::stdin().is_terminal() {
        Zeroizing::new(rpassword::prompt_password("Value: ").map_err(|e| e.to_string())?)
    } else {
        let mut raw = String::new();
        io::stdin()
            .take(vault::MAX_VALUE_BYTES as u64 + 1)
            .read_to_string(&mut raw)
            .map_err(|e| e.to_string())?;
        if raw.len() > vault::MAX_VALUE_BYTES {
            raw.zeroize();
            return Err("the value exceeds the 4 MiB limit".into());
        }
        Zeroizing::new(raw)
    };
    if value.ends_with("\r\n") {
        let len = value.len() - 2;
        value.truncate(len);
    } else if value.ends_with('\n') {
        let len = value.len() - 1;
        value.truncate(len);
    }
    Ok(value)
}

fn set(scope: &Context, name: &str, value: &str, label: Option<&str>) -> Result<ExitCode, String> {
    let outcome = match scope.locate()? {
        Some(_) => {
            let mut opened = open_for_write(scope)?;
            let outcome = opened.vault.set(name, value).map_err(vault_error)?;
            if outcome != SetOutcome::Unchanged {
                commit(&mut opened)?;
            }
            outcome
        }
        None => {
            let (path, mut vault) = create_vault(scope, label)?;
            let outcome = vault.set(name, value).map_err(vault_error)?;
            let bytes = vault.render().map_err(vault_error)?;
            store::create(&path, &bytes).map_err(store::CommitError::into_message)?;
            announce_created(&path, &vault);
            outcome
        }
    };
    match outcome {
        SetOutcome::Added => eprintln!("Added {name}"),
        SetOutcome::Replaced => eprintln!("Replaced {name}"),
        SetOutcome::Unchanged => eprintln!("{name} is unchanged"),
    }
    Ok(ExitCode::SUCCESS)
}

fn get(scope: &Context, name: &str) -> Result<ExitCode, String> {
    let (_, vault) = open_for_read(scope)?;
    let value = vault
        .get(name)
        .ok_or_else(|| format!("`{name}` is not set"))?;
    println!("{value}");
    Ok(ExitCode::SUCCESS)
}

fn run_child(scope: &Context, command: &[OsString]) -> Result<ExitCode, String> {
    use std::os::unix::process::CommandExt;

    let (_, vault) = open_for_read(scope)?;
    let mut child = ProcessCommand::new(&command[0]);
    child.args(&command[1..]);
    for (name, value) in vault.values() {
        child.env(name, value);
    }
    child.env_remove(IDENTITY_ENVIRONMENT);
    let error = child.exec();
    Err(format!(
        "could not run {}: {error}",
        command[0].to_string_lossy()
    ))
}

fn export(scope: &Context, format: Format) -> Result<ExitCode, String> {
    let (_, vault) = open_for_read(scope)?;
    let mut out = io::stdout().lock();
    match format {
        Format::Dotenv => {
            for (name, value) in vault.values() {
                writeln!(out, "{name}={}", dotenv::quote(value)).map_err(|e| e.to_string())?;
            }
        }
        Format::Shell => {
            for (name, value) in vault.values() {
                writeln!(out, "export {name}={}", dotenv::shell_quote(value))
                    .map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn import(scope: &Context, source: &Path, label: Option<&str>) -> Result<ExitCode, String> {
    let mut text = String::new();
    if source == Path::new("-") {
        io::stdin()
            .take(vault::MAX_FILE_SIZE as u64)
            .read_to_string(&mut text)
            .map_err(|e| e.to_string())?;
    } else {
        text = fs::read_to_string(source)
            .map_err(|error| format!("cannot read {}: {error}", source.display()))?;
    }
    let mut text = Zeroizing::new(text);
    let variables =
        dotenv::parse(&text).map_err(|error| format!("{}: {error}", source.display()))?;
    text.zeroize();

    let mut added = 0;
    let mut replaced = 0;
    let mut apply = |vault: &mut UnlockedVault| -> Result<(), String> {
        for (name, value) in &variables {
            match vault.set(name, value).map_err(vault_error)? {
                SetOutcome::Added => added += 1,
                SetOutcome::Replaced => replaced += 1,
                SetOutcome::Unchanged => {}
            }
        }
        Ok(())
    };
    let path = match scope.locate()? {
        Some(path) => {
            let mut opened = open_for_write(scope)?;
            apply(&mut opened.vault)?;
            commit(&mut opened)?;
            path
        }
        None => {
            let (path, mut vault) = create_vault(scope, label)?;
            apply(&mut vault)?;
            let bytes = vault.render().map_err(vault_error)?;
            store::create(&path, &bytes).map_err(store::CommitError::into_message)?;
            announce_created(&path, &vault);
            path
        }
    };
    eprintln!(
        "Imported {} variables into {} ({added} added, {replaced} replaced)",
        variables.len(),
        path.display()
    );
    Ok(ExitCode::SUCCESS)
}

fn grant(scope: &Context, label: &str, recipient: &str) -> Result<ExitCode, String> {
    let recipient = Recipient::parse(recipient)?;
    let mut opened = open_for_write(scope)?;
    match opened.vault.grant(label, &recipient).map_err(vault_error)? {
        GrantOutcome::Added => {
            commit(&mut opened)?;
            eprintln!("Granted {label} access");
        }
        GrantOutcome::Unchanged => eprintln!("{label} already has access"),
    }
    Ok(ExitCode::SUCCESS)
}

fn grant_ci(scope: &Context, label: &str, command: &[OsString]) -> Result<ExitCode, String> {
    // The storage command and the grant are one serialized transaction: a
    // second grant with the same label must fail before it can overwrite the
    // credential stored by the first one.
    let mut opened = open_for_write(scope)?;
    let vault_id = opened.vault.id();
    let ci_identity = x25519::Identity::generate();
    let ci_recipient = Recipient::Age(ci_identity.to_public());
    opened
        .vault
        .grant(label, &ci_recipient)
        .map_err(vault_error)?;
    let staged = opened.vault.render().map_err(vault_error)?;

    let secret = identity::age_secret_string(&ci_identity);
    let mut storage = ProcessCommand::new(&command[0]);
    storage
        .args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .env_remove(IDENTITY_ENVIRONMENT);
    let mut child = storage
        .spawn()
        .map_err(|error| format!("could not start the storage command: {error}"))?;
    let written = match child.stdin.take() {
        Some(mut stdin) => stdin
            .write_all(secret.as_bytes())
            .and_then(|_| stdin.write_all(b"\n")),
        None => return Err("could not open the storage command's stdin".into()),
    };
    let status = child.wait().map_err(|error| error.to_string())?;
    written.map_err(|error| format!("could not send the key to the storage command: {error}"))?;
    if !status.success() {
        return Err(format!(
            "the storage command failed with {status}; {} was not changed",
            opened.lock.path().display()
        ));
    }

    // The file may have changed while the storage command ran. Re-apply the
    // grant to the latest revision rather than overwriting it.
    let path = opened.lock.path().to_path_buf();
    let stored_prefix = "the key was stored, but";
    let latest = store::load(&path).map_err(|error| format!("{stored_prefix} {error}"))?;
    let bytes = if latest.revision == opened.revision {
        staged
    } else {
        let locked = LockedVault::parse(&latest.bytes)
            .map_err(|error| format!("{stored_prefix} the updated file is invalid: {error}"))?;
        if locked.id() != vault_id {
            return Err(format!(
                "{stored_prefix} {} was replaced by a different vault; access was not granted",
                path.display()
            ));
        }
        let identities = identity::resolve(scope.identity.as_deref(), scope.passkey)?;
        let mut vault = unlock(locked, &identities, &path)
            .map_err(|error| format!("{stored_prefix} {error}"))?;
        vault
            .grant(label, &ci_recipient)
            .map_err(|error| format!("{stored_prefix} access could not be granted: {error}"))?;
        vault
            .render()
            .map_err(|error| format!("{stored_prefix} the file could not be written: {error}"))?
    };
    store::replace(&opened.lock, &bytes, latest.revision).map_err(|error| match error {
        store::CommitError::Before(message) => {
            format!("{stored_prefix} access was not granted: {message}")
        }
        store::CommitError::After(message) => {
            format!("the key was stored and access was granted, but {message}")
        }
    })?;
    eprintln!("Granted {label} access with a new key");
    Ok(ExitCode::SUCCESS)
}

fn setup_git() -> Result<ExitCode, String> {
    let root = git_output(&["rev-parse", "--show-toplevel"])?;
    let root = PathBuf::from(root.trim_end());
    for (key, value) in [
        ("merge.envtap.name", "envtap merge driver"),
        ("merge.envtap.driver", "envtap merge %O %A %B"),
        ("diff.envtap.textconv", "envtap textconv"),
    ] {
        git_output(&["config", key, value])?;
    }
    let attributes = root.join(".gitattributes");
    let existing = match fs::read_to_string(&attributes) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(format!("cannot read {}: {error}", attributes.display())),
    };
    let wanted = [
        "tap.env merge=envtap diff=envtap",
        "tap.*.env merge=envtap diff=envtap",
    ];
    let missing: Vec<&str> = wanted
        .iter()
        .copied()
        .filter(|line| !existing.lines().any(|existing| existing.trim() == *line))
        .collect();
    if !missing.is_empty() {
        let mut text = existing;
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        for line in &missing {
            text.push_str(line);
            text.push('\n');
        }
        fs::write(&attributes, text)
            .map_err(|error| format!("cannot write {}: {error}", attributes.display()))?;
        eprintln!("Updated {}; commit it", attributes.display());
    }
    eprintln!("Configured the envtap merge driver and diff textconv for this clone.");
    Ok(ExitCode::SUCCESS)
}

fn git_output(args: &[&str]) -> Result<String, String> {
    let output = ProcessCommand::new("git")
        .args(args)
        .stderr(Stdio::inherit())
        .output()
        .map_err(|error| format!("could not run git: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed with {}",
            args.join(" "),
            output.status
        ));
    }
    String::from_utf8(output.stdout).map_err(|_| "git output is not UTF-8".to_owned())
}

fn merge_driver(
    scope: &Context,
    base: &Path,
    ours: &Path,
    theirs: &Path,
) -> Result<ExitCode, String> {
    let identities = identity::resolve(scope.identity.as_deref(), scope.passkey)?;
    let open = |path: &Path| -> Result<Option<UnlockedVault>, String> {
        let loaded = store::load(path)?;
        if loaded.bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(None);
        }
        let locked = LockedVault::parse(&loaded.bytes).map_err(|error| in_file(path, error))?;
        unlock(locked, &identities, path).map(Some)
    };
    let base_vault = open(base)?;
    let ours_vault = open(ours)?.ok_or_else(|| "our side of the merge is empty".to_owned())?;
    let theirs_vault =
        open(theirs)?.ok_or_else(|| "their side of the merge is empty".to_owned())?;
    let merged = merge::three_way(base_vault.as_ref(), ours_vault, &theirs_vault)?;
    let mut vault = merged.vault;
    let bytes = vault.render().map_err(vault_error)?;
    fs::write(ours, bytes).map_err(|error| format!("cannot write {}: {error}", ours.display()))?;
    if merged.conflicts.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }
    eprintln!(
        "envtap: both branches changed {}; kept ours. Fix with `envtap set` or `envtap grant`, then `git add`.",
        merged.conflicts.join(", ")
    );
    Ok(ExitCode::FAILURE)
}

fn textconv(scope: &Context, path: &Path) -> Result<ExitCode, String> {
    let mut out = io::stdout().lock();
    let loaded = match store::load(path) {
        Ok(loaded) => loaded,
        Err(error) => {
            writeln!(out, "# envtap: {error}").ok();
            return Ok(ExitCode::SUCCESS);
        }
    };
    let locked = match LockedVault::parse(&loaded.bytes) {
        Ok(locked) => locked,
        Err(error) => {
            writeln!(out, "# envtap: {error}").ok();
            out.write_all(&loaded.bytes).ok();
            return Ok(ExitCode::SUCCESS);
        }
    };
    for grant in locked.grants() {
        writeln!(
            out,
            "# grant {} {}",
            grant.label,
            grant.recipient.canonical()
        )
        .ok();
    }
    let variables: Vec<String> = locked.variables().map(str::to_owned).collect();
    let unlocked = identity::resolve(scope.identity.as_deref(), scope.passkey)
        .ok()
        .and_then(|identities| locked.unlock(&identities.list).ok());
    match unlocked {
        Some(vault) => {
            for (name, value) in vault.values() {
                writeln!(out, "{name}={}", dotenv::quote(value)).ok();
            }
        }
        None => {
            writeln!(out, "# envtap: values are not readable with your key").ok();
            for name in &variables {
                writeln!(out, "{name}=<encrypted>").ok();
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}
