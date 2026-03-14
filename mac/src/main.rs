mod auth;
mod credential;

use objc2_app_kit::{NSApplication, NSApplicationActivationPolicy};
use objc2_foundation::MainThreadMarker;

const FALLBACK_VERSION: &str = "0.1.2";

#[derive(Debug, Clone)]
pub enum OutputFormat {
    Hex,
    Base64,
    Age,
    Raw,
    Ssh,
}

#[derive(Debug, Clone)]
pub struct KeyOptions {
    pub name: String,
    pub format: OutputFormat,
}

#[derive(Debug, Clone)]
pub struct RegisterOptions {
    pub replace_existing: bool,
}

#[derive(Debug, Clone)]
pub enum Command {
    Register(RegisterOptions),
    Derive(KeyOptions),
    PublicKey(KeyOptions),
}

fn print_usage() {
    eprint!(
        "\
Usage: tapkey <command> [options]

Commands:
  register [--replace]             Create the passkey root
  derive                           Derive key material from your passkey
  public-key                       Show the public key for a derived key

Options:
  --name <name>                    Key name for domain separation (default: \"default\")
  --format <fmt>                   Output format: hex, base64, age, raw, ssh
  --replace                        Replace the locally registered passkey root
  --version                        Show version

Examples:
  tapkey register
  tapkey derive --name ssh --format ssh
  tapkey public-key --name ssh --format ssh
  tapkey register --replace
"
    );
}

fn parse_format(s: &str) -> OutputFormat {
    match s {
        "hex" => OutputFormat::Hex,
        "base64" => OutputFormat::Base64,
        "age" => OutputFormat::Age,
        "raw" => OutputFormat::Raw,
        "ssh" => OutputFormat::Ssh,
        _ => {
            eprintln!("error: unknown format '{s}'. Use: hex, base64, age, raw, ssh");
            std::process::exit(1);
        }
    }
}

fn validate_key_name(name: &str) {
    if name.is_empty() {
        eprintln!("error: --name cannot be empty");
        std::process::exit(1);
    }
    if name.len() > 1024 {
        eprintln!("error: --name must be at most 1024 bytes");
        std::process::exit(1);
    }
    if !name.is_ascii() {
        eprintln!("error: --name must contain only ASCII characters");
        std::process::exit(1);
    }
}

fn parse_key_options(args: &[String], default_format: OutputFormat) -> KeyOptions {
    let mut name = "default".to_string();
    let mut format = default_format;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--name" => {
                if i + 1 >= args.len() {
                    eprintln!("error: --name requires a value");
                    std::process::exit(1);
                }
                i += 1;
                name = args[i].clone();
                validate_key_name(&name);
            }
            "--format" => {
                if i + 1 >= args.len() {
                    eprintln!("error: --format requires a value (hex, base64, age, raw, ssh)");
                    std::process::exit(1);
                }
                i += 1;
                format = parse_format(&args[i]);
            }
            other => {
                eprintln!("error: unknown option '{other}'");
                std::process::exit(1);
            }
        }
        i += 1;
    }
    KeyOptions { name, format }
}

fn parse_args() -> Option<Command> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.contains(&"--version".to_string()) || args.contains(&"-v".to_string()) {
        println!("tapkey {FALLBACK_VERSION}");
        std::process::exit(0);
    }

    if args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) || args.is_empty()
    {
        print_usage();
        std::process::exit(0);
    }

    let subcommand = &args[0];
    let rest = &args[1..];

    match subcommand.as_str() {
        "register" => {
            let mut replace = false;
            for arg in rest {
                match arg.as_str() {
                    "--replace" => replace = true,
                    other => {
                        eprintln!("error: unknown option '{other}'");
                        std::process::exit(1);
                    }
                }
            }
            Some(Command::Register(RegisterOptions {
                replace_existing: replace,
            }))
        }
        "derive" => Some(Command::Derive(parse_key_options(
            rest,
            OutputFormat::Hex,
        ))),
        "public-key" => Some(Command::PublicKey(parse_key_options(
            rest,
            OutputFormat::Age,
        ))),
        other => {
            eprintln!("error: unknown command '{other}'");
            print_usage();
            std::process::exit(1);
        }
    }
}

fn main() {
    let command = parse_args().unwrap();
    let mtm = MainThreadMarker::new().expect("must run on main thread");
    let app = NSApplication::sharedApplication(mtm);
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
    let delegate = auth::AuthDelegate::new(mtm, command);
    let delegate_ref = objc2::runtime::ProtocolObject::from_ref(&*delegate);
    app.setDelegate(Some(delegate_ref));
    app.run();
}
