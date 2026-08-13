//! The complete command-line surface for the installed `keytap` binary.
//!
//! Parsing stays deliberately small: there are exactly three executable
//! command states, and each variant carries only the arguments valid for it.

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser, PartialEq, Eq)]
#[command(
    name = "keytap",
    version,
    about = "Derive reproducible keys from a passkey.",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// A valid operation requested by the user.
#[derive(Debug, Subcommand, PartialEq, Eq)]
pub enum Command {
    /// Create a keytap passkey, if you do not already have one
    Init {
        /// Replace an already-registered passkey (every derived key changes)
        #[arg(long)]
        force: bool,
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
    Reveal {
        /// Key name for domain separation
        #[arg(default_value = "default")]
        name: String,

        /// Output format
        #[arg(long = "as", value_name = "FORMAT", default_value = "hex")]
        format: Format,
    },
}

/// The four stable key encodings supported by both output commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Hex,
    Base64,
    Age,
    Ssh,
}

impl Format {
    /// Public SSH output carries the key name as its OpenSSH comment.
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
    fn from(format: Format) -> Self {
        match format {
            Format::Hex => Self::Hex,
            Format::Base64 => Self::Base64,
            Format::Age => Self::AgeSecretKey,
            Format::Ssh => Self::SshPrivateKey,
        }
    }
}

/// The complete outcome of interpreting argv before an operation runs.
pub enum Invocation {
    /// Top-level overview requested explicitly or by omitting a command.
    Overview(String),
    /// A valid command and exactly the data required to execute it.
    Command(Command),
    /// Clap-rendered subcommand help, version output, or syntax error.
    Clap(clap::Error),
}

/// Interpret argv, including argv[0], without executing a command.
pub fn invoke<I, T>(argv: I) -> Invocation
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let args: Vec<std::ffi::OsString> = argv.into_iter().map(Into::into).collect();

    match args.get(1) {
        None => return Invocation::Overview(overview()),
        Some(first) if first == "-h" || first == "--help" || first == "help" => {
            return Invocation::Overview(overview());
        }
        _ => {}
    }

    match Cli::try_parse_from(args) {
        Ok(cli) => Invocation::Command(cli.command),
        Err(error) => Invocation::Clap(error),
    }
}

/// Compact top-level help. Subcommand help remains clap-generated.
pub fn overview() -> String {
    concat!(
        "Derive reproducible keys from a passkey.\n\n",
        "Usage: keytap <COMMAND> [ARGS]\n\n",
        "Commands\n",
        "  init                                       Create a keytap passkey, if you do not already have one\n",
        "  public [NAME] [--as <hex|base64|age|ssh>]  Output the public key\n",
        "  reveal [NAME] [--as <hex|base64|age|ssh>]  Reveal private key material\n\n",
        "Arguments & options\n",
        "  NAME  Key name for domain separation  [default: default]\n",
        "  --as  Output format  [default: hex]\n\n",
        "Run `keytap <COMMAND> --help` for command details.\n",
    )
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    fn argv(line: &str) -> Vec<String> {
        std::iter::once("keytap")
            .chain(line.split_whitespace())
            .map(String::from)
            .collect()
    }

    fn command(line: &str) -> Command {
        match invoke(argv(line)) {
            Invocation::Command(command) => command,
            Invocation::Overview(_) | Invocation::Clap(_) => {
                panic!("expected {line:?} to parse as a command")
            }
        }
    }

    #[test]
    fn init_has_only_its_force_state() {
        assert_eq!(command("init"), Command::Init { force: false });
        assert_eq!(command("init --force"), Command::Init { force: true });
    }

    #[test]
    fn output_commands_default_name_and_format() {
        assert_eq!(
            command("public"),
            Command::Public {
                name: "default".into(),
                format: Format::Hex,
            }
        );
        assert_eq!(
            command("reveal"),
            Command::Reveal {
                name: "default".into(),
                format: Format::Hex,
            }
        );
    }

    #[test]
    fn output_commands_accept_every_format() {
        for (spelling, format) in [
            ("hex", Format::Hex),
            ("base64", Format::Base64),
            ("age", Format::Age),
            ("ssh", Format::Ssh),
        ] {
            assert_eq!(
                command(&format!("public deploy --as {spelling}")),
                Command::Public {
                    name: "deploy".into(),
                    format,
                }
            );
            assert_eq!(
                command(&format!("reveal deploy --as {spelling}")),
                Command::Reveal {
                    name: "deploy".into(),
                    format,
                }
            );
        }
    }

    #[test]
    fn bare_and_leading_help_tokens_return_the_overview() {
        for line in ["", "-h", "--help", "help", "help reveal"] {
            let Invocation::Overview(text) = invoke(argv(line)) else {
                panic!("expected overview for {line:?}")
            };
            assert_eq!(text, overview());
        }
    }

    #[test]
    fn overview_exposes_exactly_three_commands() {
        let text = overview();
        for command in ["init", "public", "reveal"] {
            assert!(text.contains(&format!("  {command}")));
        }
        assert!(text.contains("[default: default]"));
        assert!(text.contains("[default: hex]"));
    }

    #[test]
    fn subcommand_help_remains_a_successful_clap_exit() {
        let Invocation::Clap(error) = invoke(argv("reveal --help")) else {
            panic!("expected clap help")
        };
        assert_eq!(error.kind(), ErrorKind::DisplayHelp);
        assert!(!error.use_stderr());
        assert_eq!(error.exit_code(), 0);
    }

    #[test]
    fn invalid_format_preserves_clap_syntax_error() {
        let Invocation::Clap(error) = invoke(argv("public --as pem")) else {
            panic!("expected clap syntax error")
        };
        assert_eq!(error.kind(), ErrorKind::InvalidValue);
        assert!(error.use_stderr());
        assert_eq!(error.exit_code(), 2);
        let rendered = error.render().to_string();
        assert!(rendered.contains("invalid value 'pem'"));
        assert!(rendered.contains("hex"));
        assert!(rendered.contains("base64"));
        assert!(rendered.contains("age"));
        assert!(rendered.contains("ssh"));
    }

    #[test]
    fn unknown_commands_are_rejected() {
        let Invocation::Clap(error) = invoke(argv("unknown")) else {
            panic!("expected an unknown command to be rejected")
        };
        assert_eq!(error.kind(), ErrorKind::InvalidSubcommand);
        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn format_conversion_keeps_the_named_ssh_comment() {
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
        assert_eq!(
            keytap_core::PrivateKeyFormat::from(Format::Age),
            keytap_core::PrivateKeyFormat::AgeSecretKey
        );
    }
}
