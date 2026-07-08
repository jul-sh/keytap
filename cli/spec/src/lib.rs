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

    /// Run a passkey ceremony even under $CI (the QR code lands in the job log)
    // With $CI set, a missing key fails fast instead of prompting — a prompt
    // in a headless job is a hung runner, not a question. This is the
    // override for the rare run where someone really is watching the log.
    #[arg(long, global = true)]
    pub prompt: bool,
}

#[derive(Subcommand)]
pub enum Command {
    /// Create the passkey (only needed once)
    Init,

    /// Output the public key
    Public {
        /// Key name for domain separation
        #[arg(default_value = "default")]
        name: String,

        /// Output format
        // `--as` is the documented flag; `--format` stays as a hidden alias so
        // existing scripts keep working. (`as` is a Rust keyword, hence the
        // field is still named `format`.)
        #[arg(long = "as", alias = "format", value_name = "FORMAT", default_value = "hex")]
        format: PublicFormat,
    },

    /// Reveal private key material
    #[command(after_help = help::REUSE)]
    Reveal {
        /// Key name for domain separation
        #[arg(default_value = "default")]
        name: String,

        /// Output format
        #[arg(long = "as", alias = "format", value_name = "FORMAT", default_value = "hex")]
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

#[derive(Clone, Copy, ValueEnum)]
pub enum Format {
    Hex,
    Base64,
    Age,
    Ssh,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum PublicFormat {
    Hex,
    Base64,
    Age,
    Ssh,
}

impl Format {
    /// The CLI-facing name of this format — exactly what `--as` accepts.
    pub fn as_str(self) -> String {
        self.to_possible_value().unwrap().get_name().to_string()
    }
}

impl PublicFormat {
    /// The CLI-facing name of this format — exactly what `--as` accepts.
    pub fn as_str(self) -> String {
        self.to_possible_value().unwrap().get_name().to_string()
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

impl From<PublicFormat> for keytap_core::PublicKeyFormat {
    fn from(f: PublicFormat) -> Self {
        match f {
            PublicFormat::Hex => keytap_core::PublicKeyFormat::Hex,
            PublicFormat::Base64 => keytap_core::PublicKeyFormat::Base64,
            PublicFormat::Age => keytap_core::PublicKeyFormat::AgeRecipient,
            PublicFormat::Ssh => keytap_core::PublicKeyFormat::SshPublicKey,
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
        std::iter::once("keytap").chain(line.split_whitespace()).map(String::from).collect()
    }

    #[test]
    fn bare_and_help_tokens_yield_overview() {
        for line in ["", "-h", "--help", "help", "help reveal"] {
            assert!(matches!(invoke(argv(line)), Invocation::Overview(_)), "argv: {line:?}");
        }
    }

    #[test]
    fn bare_remember_is_misuse() {
        assert!(matches!(invoke(argv("remember")), Invocation::Misuse(_)));
        // With a name it parses normally.
        assert!(matches!(invoke(argv("remember deploy")), Invocation::Parsed(Ok(_))));
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
    fn overview_lists_every_subcommand() {
        let text = overview();
        for cmd in completions() {
            assert!(text.contains(&cmd.0), "overview missing {}", cmd.0);
        }
    }
}
