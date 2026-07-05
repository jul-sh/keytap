use age::x25519;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::str::FromStr;
use zeroize::Zeroizing;

/// Validate input/output flags before any authentication happens, so a bad
/// invocation fails immediately rather than after a passkey prompt.
pub fn validate_io(files: &[String], output: Option<&str>) {
    let inputs: Vec<&str> = if files.is_empty() { vec!["-"] } else { files.iter().map(String::as_str).collect() };
    if inputs.len() > 1 {
        if output.is_some() {
            crate::die("--output cannot be used with multiple input files");
        }
        if inputs.iter().any(|f| *f == "-") {
            crate::die("stdin ('-') cannot be mixed with named files");
        }
    }
}

/// Encrypt one or more inputs with the derived age identity (plus optional
/// additional recipients).
///
/// - no files, or `-`  → stdin to stdout (streamed)
/// - one file          → stdout, or `--output PATH`
/// - many files        → each written to `<file>.age` in place (`--output`
///   is rejected — it can't name N outputs). A single `authenticate()` upstream
///   covers the whole batch.
pub fn encrypt(
    raw_key: &[u8],
    files: &[String],
    output: Option<&str>,
    additional_recipients: &[String],
    recipients_files: &[String],
    include_self: bool,
) {
    let recipients = build_recipients(raw_key, additional_recipients, recipients_files, include_self);

    // Normalize: empty means "stdin". Flag validity was already checked by
    // `validate_io` before authentication.
    let inputs: Vec<&str> = if files.is_empty() { vec!["-"] } else { files.iter().map(String::as_str).collect() };

    if inputs.len() > 1 {
        for path in inputs {
            let mut reader = open_reader(path);
            let out_path = format!("{path}.age");
            let mut writer = open_writer(Some(&out_path));
            encrypt_stream(&recipients, &mut reader, &mut writer, &out_path);
        }
    } else {
        let src = inputs[0];
        let mut reader = open_reader(src);
        // Single input with no --output goes to stdout (pipe-first, like `age`);
        // use --output to save to a file.
        let mut writer = open_writer(output);
        let dst_label = output.unwrap_or("<stdout>").to_string();
        encrypt_stream(&recipients, &mut reader, &mut writer, &dst_label);
    }
}

/// Decrypt one or more `.age` inputs using the derived age identity.
///
/// - no files, or `-`  → stdin to stdout (streamed)
/// - one file          → stdout, or `--output PATH`
/// - many files        → each `<name>.age` written to `<name>` (suffix stripped;
///   files without `.age` get `.dec` appended). One `authenticate()` upstream.
pub fn decrypt(raw_key: &[u8], files: &[String], output: Option<&str>) {
    let identity = identity_from_raw_key(raw_key);

    // Flag validity already checked by `validate_io` before authentication.
    let inputs: Vec<&str> = if files.is_empty() { vec!["-"] } else { files.iter().map(String::as_str).collect() };

    if inputs.len() > 1 {
        for path in inputs {
            let mut reader = open_reader(path);
            let out_path = match path.strip_suffix(".age") {
                Some(stripped) => stripped.to_string(),
                None => format!("{path}.dec"),
            };
            let mut writer = open_writer(Some(&out_path));
            decrypt_stream(&identity, &mut reader, &mut writer, &out_path);
        }
    } else {
        let src = inputs[0];
        let mut reader = open_reader(src);
        let mut writer = open_writer(output);
        let dst_label = output.unwrap_or("<stdout>").to_string();
        decrypt_stream(&identity, &mut reader, &mut writer, &dst_label);
    }
}

/// Stream one plaintext reader through the age encryptor into `writer`.
/// Chunked copy — no whole-file buffering, so there is no size ceiling.
fn encrypt_stream(
    recipients: &[Box<dyn age::Recipient + Send>],
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    dst_label: &str,
) {
    let encryptor = age::Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref() as &dyn age::Recipient))
        .unwrap_or_else(|e| crate::die(&format!("failed to create encryptor: {e}")));

    let mut age_writer = encryptor
        .wrap_output(writer)
        .unwrap_or_else(|e| crate::die(&format!("encryption failed: {e}")));

    io::copy(reader, &mut age_writer)
        .unwrap_or_else(|e| crate::die(&format!("encryption failed writing {dst_label}: {e}")));
    age_writer
        .finish()
        .unwrap_or_else(|e| crate::die(&format!("encryption failed finalizing {dst_label}: {e}")));
}

/// Stream one age reader through the decryptor into `writer`. Chunked — no ceiling.
fn decrypt_stream(
    identity: &x25519::Identity,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    dst_label: &str,
) {
    let decryptor = age::Decryptor::new(reader)
        .unwrap_or_else(|e| crate::die(&format!("failed to read age input: {e}")));

    let mut age_reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .unwrap_or_else(|e| crate::die(&format!("decryption failed: {e}")));

    io::copy(&mut age_reader, writer)
        .unwrap_or_else(|e| crate::die(&format!("decryption failed writing {dst_label}: {e}")));
}

/// Collect the recipient set: self (derived identity) plus any `--to` / `-R`.
fn build_recipients(
    raw_key: &[u8],
    additional_recipients: &[String],
    recipients_files: &[String],
    include_self: bool,
) -> Vec<Box<dyn age::Recipient + Send>> {
    let mut recipients: Vec<Box<dyn age::Recipient + Send>> = Vec::new();

    if include_self {
        recipients.push(Box::new(identity_from_raw_key(raw_key).to_public()));
    }

    for r in additional_recipients {
        let recipient = x25519::Recipient::from_str(r)
            .unwrap_or_else(|e| crate::die(&format!("invalid recipient {r}: {e}")));
        recipients.push(Box::new(recipient));
    }

    for file in recipients_files {
        let contents = std::fs::read_to_string(file)
            .unwrap_or_else(|e| crate::die(&format!("failed to read recipients file {file}: {e}")));
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let recipient = x25519::Recipient::from_str(line)
                .unwrap_or_else(|e| crate::die(&format!("invalid recipient in {file}: {line}: {e}")));
            recipients.push(Box::new(recipient));
        }
    }

    if recipients.is_empty() {
        crate::die("no recipients specified (use --to, -R, or remove --no-self)");
    }
    recipients
}

/// A buffered reader over a path, or stdin when the path is `-`.
fn open_reader(path: &str) -> Box<dyn Read> {
    if path == "-" {
        Box::new(BufReader::new(io::stdin()))
    } else {
        let f = File::open(path).unwrap_or_else(|e| crate::die(&format!("failed to open {path}: {e}")));
        Box::new(BufReader::new(f))
    }
}

/// A buffered writer to a path, or stdout when the path is `None`/`-`.
fn open_writer(path: Option<&str>) -> Box<dyn Write> {
    match path {
        None | Some("-") => Box::new(BufWriter::new(io::stdout())),
        Some(p) => {
            let f = File::create(p).unwrap_or_else(|e| crate::die(&format!("failed to create {p}: {e}")));
            Box::new(BufWriter::new(f))
        }
    }
}

fn identity_from_raw_key(raw_key: &[u8]) -> x25519::Identity {
    let secret_key_bytes = Zeroizing::new(
        keytap_core::format_private_key(raw_key, keytap_core::PrivateKeyFormat::AgeSecretKey)
            .unwrap_or_else(|e| crate::die(&format!("key format error: {e}"))),
    );
    let secret_key_str = Zeroizing::new(
        String::from_utf8(secret_key_bytes.to_vec())
            .unwrap_or_else(|e| crate::die(&format!("key format error: {e}"))),
    );
    x25519::Identity::from_str(&secret_key_str)
        .unwrap_or_else(|e| crate::die(&format!("invalid age identity: {e}")))
}
