//! The keytap CLI surface — clap definitions, help rendering, and the argv
//! front-end — as a library, so every keytap frontend parses commands the
//! same way. The native binary consumes it directly; the web terminal at
//! keytap.jul.sh compiles it to WebAssembly. Help text, argument names,
//! defaults, and error messages exist only here and cannot drift between
//! platforms.
//!
//! This crate decides *what was asked*; executing it (passkey ceremonies,
//! stdio, storage) is the platform's job.

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};

mod help;

#[derive(Parser)]
#[command(
    name = "keytap",
    version,
    about = "Derive keys and encrypt files from a passkey.",
    // The top-level help is our own generated single-screen overview (see
    // `invoke`); clap keeps its default `--help` on each subcommand.
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Allow passkey ceremonies under $CI (only affects commands that need one)
    // With $CI set, a command that needs a ceremony fails fast instead of
    // prompting — a prompt in a headless job is a hung runner, not a question.
    // This is the override for the rare run where someone is watching the log.
    #[arg(long, global = true)]
    pub prompt: bool,
}

// Serialization and clap use the same variant and field definitions.
#[derive(Subcommand, serde::Serialize)]
#[serde(tag = "cmd", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Command {
    /// Create a keytap passkey, if you do not already have one
    Init {
        /// Replace an already-registered passkey (every derived key changes)
        // Re-running init is destructive — the new passkey overwrites the old
        // one in the authenticator, so keys derived from it stop being
        // reproducible. Each frontend refuses a detected re-init without this.
        #[arg(long)]
        force: bool,

        /// Register the passkey on a nearby device instead of this machine
        // Registration cannot safely race two authenticators: each successful
        // ceremony can create a different credential and PRF root. Keep this
        // route choice local to init; assertion commands always offer every
        // available approval route concurrently.
        #[arg(long)]
        nearby: bool,
    },

    /// Output the public key
    Public {
        /// Key name for domain separation
        #[arg(default_value = "default")]
        name: String,

        /// Output format
        #[arg(long = "as", value_name = "FORMAT", default_value = "hex")]
        format: Format,
    },

    /// Reveal private key material
    #[command(after_help = help::REUSE)]
    Reveal {
        /// Key name for domain separation
        #[arg(default_value = "default")]
        name: String,

        /// Output format
        #[arg(long = "as", value_name = "FORMAT", default_value = "hex")]
        format: Format,
    },

    /// Encrypt stdin to stdout with the derived age identity
    Encrypt {
        /// Key name for domain separation
        #[arg(default_value = "default")]
        name: String,

        /// Additional age recipient (can be repeated)
        #[arg(long = "to")]
        recipients: Vec<String>,

        /// File containing age recipients (one per line)
        #[arg(short = 'R')]
        recipients_file: Vec<String>,

        /// Don't include self as a recipient when encrypting
        #[arg(long)]
        no_self: bool,
    },

    /// Decrypt age input from stdin to stdout with the derived age identity
    Decrypt {
        /// Key name for domain separation
        #[arg(default_value = "default")]
        name: String,
    },

    /// Remember a derived key on this machine (no more prompts for it)
    #[command(after_help = help::REMEMBER)]
    Remember {
        /// Key name for domain separation. Required: persisting a key should
        /// name it deliberately, never land on 'default' by accident.
        name: String,
    },

    /// Forget a remembered key
    Forget {
        /// Key name for domain separation
        #[arg(default_value = "default")]
        name: String,

        /// Forget every remembered key, including ones from previous passkeys
        #[arg(long, conflicts_with = "name")]
        all: bool,
    },

    /// List keys remembered on this machine (never prints key material)
    Remembered,
}

#[derive(Clone, Copy, ValueEnum, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Hex,
    Base64,
    Age,
    Ssh,
}

impl Format {
    /// Convert the parsed command at the execution boundary, co-locating the
    /// key name with the only output format where it is meaningful as data.
    pub fn public_key_format<'a>(self, key_name: &'a str) -> keytap_core::PublicKeyFormat<'a> {
        match self {
            Self::Hex => keytap_core::PublicKeyFormat::Hex,
            Self::Base64 => keytap_core::PublicKeyFormat::Base64,
            Self::Age => keytap_core::PublicKeyFormat::AgeRecipient,
            Self::Ssh => keytap_core::PublicKeyFormat::Ssh {
                comment: Some(key_name),
            },
        }
    }
}

impl From<Format> for keytap_core::PrivateKeyFormat {
    fn from(f: Format) -> Self {
        match f {
            Format::Hex => keytap_core::PrivateKeyFormat::Hex,
            Format::Base64 => keytap_core::PrivateKeyFormat::Base64,
            Format::Age => keytap_core::PrivateKeyFormat::AgeSecretKey,
            Format::Ssh => keytap_core::PrivateKeyFormat::SshPrivateKey,
        }
    }
}

/// What an argv amounts to, before anything runs.
pub enum Invocation {
    /// Top-level help (bare `keytap`, `-h`, `--help`, or a leading `help`):
    /// the generated single-screen overview, printed to stdout, exit 0.
    Overview(String),
    /// A usage error keytap answers with a friendlier message than clap's,
    /// printed as `error: …` to stderr, exit 1.
    Misuse(String),
    /// Everything else: clap's verdict — a parsed command to execute, or a
    /// rendered subcommand help / version / usage error.
    Parsed(Result<Cli, clap::Error>),
}

/// Resolve an argv (including argv[0]) into an [`Invocation`]. Every keytap
/// frontend funnels through here so they cannot disagree on parsing.
pub fn invoke<I, T>(argv: I) -> Invocation
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let args: Vec<std::ffi::OsString> = argv.into_iter().map(Into::into).collect();

    // Top-level help: no subcommand at all, or a help token (`-h`/`--help`/
    // `help`) before any subcommand is named.
    match args.get(1) {
        None => return Invocation::Overview(overview()),
        Some(first) if first == "-h" || first == "--help" || first == "help" => {
            return Invocation::Overview(overview())
        }
        _ => {}
    }

    // `remember` requires an explicit name (persisting a key should never
    // target 'default' by accident), but the bare invocation deserves a
    // better answer than clap's generic missing-argument error.
    if args.len() == 2 && args[1] == "remember" {
        return Invocation::Misuse(
            "`keytap remember` needs a key name. Did you mean `keytap remember default`? \
             ('default' is the key every other command uses when you don't give a name)"
                .into(),
        );
    }

    Invocation::Parsed(Cli::try_parse_from(args))
}

/// The single-screen overview `keytap --help` prints.
pub fn overview() -> String {
    help::overview(&Cli::command())
}

/// The version string baked into the CLI (`keytap --version` prints it).
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The command surface as data — subcommand names with their visible flags —
/// for frontends that offer completion. Walks the same clap metadata the help
/// is generated from, so completions can't drift either.
pub fn completions() -> Vec<(String, Vec<String>)> {
    let mut commands: Vec<(String, Vec<String>)> = Cli::command()
        .get_subcommands()
        .filter(|c| c.get_name() != "help")
        .map(|c| {
            let flags = c
                .get_arguments()
                .filter(|a| !a.is_positional() && !a.is_hide_set())
                .filter_map(|a| {
                    a.get_long()
                        .map(|l| format!("--{l}"))
                        .or_else(|| a.get_short().map(|s| format!("-{s}")))
                })
                .collect();
            (c.get_name().to_string(), flags)
        })
        .collect();
    // `keytap help` is answered by `invoke` (the overview), not a clap
    // subcommand, so it's appended rather than discovered.
    commands.push(("help".into(), Vec::new()));
    commands
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(line: &str) -> Vec<String> {
        std::iter::once("keytap")
            .chain(line.split_whitespace())
            .map(String::from)
            .collect()
    }

    #[test]
    fn bare_and_help_tokens_yield_overview() {
        for line in ["", "-h", "--help", "help", "help reveal"] {
            assert!(
                matches!(invoke(argv(line)), Invocation::Overview(_)),
                "argv: {line:?}"
            );
        }
    }

    #[test]
    fn bare_remember_is_misuse() {
        assert!(matches!(invoke(argv("remember")), Invocation::Misuse(_)));
        // With a name it parses normally.
        assert!(matches!(
            invoke(argv("remember deploy")),
            Invocation::Parsed(Ok(_))
        ));
    }

    #[test]
    fn subcommand_help_flows_through_clap() {
        match invoke(argv("reveal --help")) {
            Invocation::Parsed(Err(e)) => assert!(!e.use_stderr()),
            _ => panic!("expected clap help"),
        }
    }

    #[test]
    fn parse_defaults() {
        match invoke(argv("reveal")) {
            Invocation::Parsed(Ok(cli)) => match cli.command {
                Command::Reveal { name, .. } => assert_eq!(name, "default"),
                _ => panic!("wrong command"),
            },
            _ => panic!("expected parse"),
        }
    }

    #[test]
    fn public_format_conversion_co_locates_the_ssh_comment() {
        assert!(matches!(
            Format::Hex.public_key_format("deploy"),
            keytap_core::PublicKeyFormat::Hex
        ));
        assert!(matches!(
            Format::Ssh.public_key_format("deploy"),
            keytap_core::PublicKeyFormat::Ssh {
                comment: Some("deploy")
            }
        ));
    }

    #[test]
    fn nearby_is_only_an_init_registration_route() {
        match invoke(argv("init --nearby")) {
            Invocation::Parsed(Ok(cli)) => {
                assert!(matches!(
                    cli.command,
                    Command::Init {
                        force: false,
                        nearby: true
                    }
                ))
            }
            _ => panic!("expected init --nearby to parse"),
        }

        for line in ["--nearby reveal", "reveal --nearby", "--nearby init"] {
            match invoke(argv(line)) {
                Invocation::Parsed(Err(_)) => {}
                _ => panic!("expected {line:?} to reject the init-only flag"),
            }
        }
    }

    #[test]
    fn init_requires_an_explicit_force() {
        match invoke(argv("init")) {
            Invocation::Parsed(Ok(cli)) => {
                assert!(matches!(
                    cli.command,
                    Command::Init {
                        force: false,
                        nearby: false
                    }
                ))
            }
            _ => panic!("expected parse"),
        }
        match invoke(argv("init --force")) {
            Invocation::Parsed(Ok(cli)) => {
                assert!(matches!(
                    cli.command,
                    Command::Init {
                        force: true,
                        nearby: false
                    }
                ))
            }
            _ => panic!("expected parse"),
        }
    }

    #[test]
    fn overview_lists_every_subcommand() {
        let text = overview();
        for cmd in completions() {
            assert!(text.contains(&cmd.0), "overview missing {}", cmd.0);
        }
        assert!(text.contains("init [--nearby]"));
        assert!(!text.contains("Options\n  --nearby"));
    }

    #[test]
    fn completions_scope_nearby_to_init() {
        let completions = completions();
        let flags_for = |command: &str| {
            completions
                .iter()
                .find(|(name, _)| name == command)
                .map(|(_, flags)| flags.as_slice())
                .expect("command should have completions")
        };

        assert!(flags_for("init").iter().any(|flag| flag == "--nearby"));
        assert!(!flags_for("reveal").iter().any(|flag| flag == "--nearby"));
    }
}
