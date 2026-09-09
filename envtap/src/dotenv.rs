//! The dotenv grammar Envtap reads on import and writes on export.
//!
//! Envtap writes an unquoted value when it round-trips unambiguously and a
//! double-quoted value with `\\`, `\"`, `\n`, and `\r` escapes otherwise. It
//! reads unquoted, double-quoted, and single-quoted values the way common
//! dotenv loaders do, without variable interpolation.

use crate::vault::validate_variable_name;

/// Render a value so that [`unquote`] and common dotenv loaders return it.
pub fn quote(value: &str) -> String {
    let unambiguous = !value.is_empty()
        && value == value.trim()
        && !value.starts_with("envtap:")
        && !value
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | '\'' | '\\' | '#' | '`' | '$'));
    if unambiguous {
        return value.to_owned();
    }
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for c in value.chars() {
        match c {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
}

/// Interpret the text after `=` on a dotenv line.
pub fn unquote(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.len() >= 2 {
        if let Some(inner) = trimmed
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
        {
            return unescape(inner);
        }
        if let Some(inner) = trimmed
            .strip_prefix('\'')
            .and_then(|rest| rest.strip_suffix('\''))
        {
            return inner.to_owned();
        }
    }
    match trimmed.find(" #") {
        Some(index) => trimmed[..index].trim_end().to_owned(),
        None => trimmed.to_owned(),
    }
}

fn unescape(inner: &str) -> String {
    let mut value = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            value.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => value.push('\n'),
            Some('r') => value.push('\r'),
            Some('t') => value.push('\t'),
            Some(other) => value.push(other),
            None => value.push('\\'),
        }
    }
    value
}

/// Quote for `eval "$(envtap export --format shell)"`.
pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Parse a plaintext `.env` file into ordered name and value pairs.
pub fn parse(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut variables: Vec<(String, String)> = Vec::new();
    let mut lines = text.lines().enumerate().peekable();
    while let Some((index, line)) = lines.next() {
        let number = index + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let statement = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        let (name, mut raw) = statement
            .split_once('=')
            .map(|(name, raw)| (name.trim(), raw.to_owned()))
            .ok_or_else(|| format!("line {number}: expected NAME=value"))?;
        validate_variable_name(name).map_err(|error| format!("line {number}: {error}"))?;
        if is_open_double_quote(&raw) {
            loop {
                let Some((_, continuation)) = lines.next() else {
                    return Err(format!("line {number}: unterminated quoted value"));
                };
                raw.push('\n');
                raw.push_str(continuation);
                if !is_open_double_quote(&raw) {
                    break;
                }
            }
        }
        if variables.iter().any(|(existing, _)| existing == name) {
            return Err(format!("line {number}: {name} is defined more than once"));
        }
        variables.push((name.to_owned(), unquote(&raw)));
    }
    Ok(variables)
}

/// Whether the text after `=` opens a double-quoted value it does not close.
fn is_open_double_quote(raw: &str) -> bool {
    let trimmed = raw.trim_start();
    if !trimmed.starts_with('"') {
        return false;
    }
    let mut escaped = false;
    let mut quotes = 0;
    for c in trimmed.chars() {
        match c {
            '\\' if !escaped => escaped = true,
            '"' if !escaped => quotes += 1,
            _ => escaped = false,
        }
    }
    quotes < 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_round_trips() {
        for value in [
            "plain",
            "with space",
            "",
            " leading",
            "tab\tinside",
            "line\nbreak",
            "quote\"and'both",
            "back\\slash",
            "hash # comment",
            "envtap:v1:looks-encrypted",
            "$HOME `cmd`",
        ] {
            assert_eq!(unquote(&quote(value)), value, "{value:?}");
        }
        assert_eq!(quote("plain"), "plain");
        assert_eq!(quote("a b"), "a b");
        assert_eq!(quote(""), "\"\"");
    }

    #[test]
    fn reads_common_dotenv_spellings() {
        let parsed = parse(
            "# comment\nexport A=1\nB=\"two\\nlines\"\nC='single # kept'\nD=unquoted # dropped\nE=\"multi\nline\"\n\nF=\n",
        )
        .unwrap();
        assert_eq!(
            parsed,
            vec![
                ("A".to_owned(), "1".to_owned()),
                ("B".to_owned(), "two\nlines".to_owned()),
                ("C".to_owned(), "single # kept".to_owned()),
                ("D".to_owned(), "unquoted".to_owned()),
                ("E".to_owned(), "multi\nline".to_owned()),
                ("F".to_owned(), String::new()),
            ]
        );
        assert!(parse("A=1\nA=2\n").is_err());
        assert!(parse("1A=1\n").is_err());
        assert!(parse("A=\"open\n").is_err());
        assert!(parse("no equals\n").is_err());
    }

    #[test]
    fn shell_quoting_survives_single_quotes() {
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }
}
