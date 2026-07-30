//! `keytap encrypt` / `keytap decrypt`: pure stdin→stdout filters over the
//! derived age identity. The crypto engine lives in `keytap_core::encrypt`
//! (shared with the web terminal's wasm build); this adapter owns the
//! platform bits — stdin/stdout, reading recipient files, dying loudly.

use std::io::{self, BufReader, BufWriter, Write};

/// Encrypt stdin to stdout with the derived age identity (plus optional
/// additional recipients). Streamed and chunked; no size ceiling.
pub fn encrypt(
    raw_key: &[u8],
    additional_recipients: &[String],
    recipients_files: &[String],
    include_self: bool,
) {
    let files: Vec<(String, String)> = recipients_files
        .iter()
        .map(|file| {
            let contents = std::fs::read_to_string(file).unwrap_or_else(|e| {
                crate::die(&format!("failed to read recipients file {file}: {e}"))
            });
            (file.clone(), contents)
        })
        .collect();
    let recipients = keytap_core::encrypt::recipients(
        include_self.then_some(raw_key),
        additional_recipients,
        &files,
    )
    .unwrap_or_else(|e| crate::die(&e.to_string()));

    let mut reader = BufReader::new(io::stdin());
    let mut writer = BufWriter::new(io::stdout());
    keytap_core::encrypt::encrypt_stream(&recipients, &mut reader, &mut writer)
        .unwrap_or_else(|e| crate::die(&e.to_string()));
    writer
        .flush()
        .unwrap_or_else(|e| crate::die(&format!("encryption failed flushing stdout: {e}")));
}

/// Decrypt age input from stdin to stdout using the derived age identity.
/// Streamed and chunked; no size ceiling.
pub fn decrypt(raw_key: &[u8]) {
    let mut reader = BufReader::new(io::stdin());
    let mut writer = BufWriter::new(io::stdout());
    keytap_core::encrypt::decrypt_stream(raw_key, &mut reader, &mut writer)
        .unwrap_or_else(|e| crate::die(&e.to_string()));
    writer
        .flush()
        .unwrap_or_else(|e| crate::die(&format!("decryption failed flushing stdout: {e}")));
}
