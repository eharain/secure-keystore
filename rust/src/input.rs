//! Reading an input file into a master key and a list of entries.
//!
//! Three formats, chosen by extension, all saying the same thing. They are
//! parsed here rather than in the store so that each can be tested against a
//! string, with no directory involved.

use std::path::Path;

use serde_json::Value;

use crate::error::{Code, Error, Result};
use crate::format as fmt;

/// One of the three shapes an input file can take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputFormat {
    /// `master:<key>` on the first line, then `key:value` lines.
    Colon,
    /// dotenv: `KEY=value`, with comments, quotes and `export`.
    Env,
    /// A flat object with a `master` property.
    Json,
}

/// One key-value pair read out of an input file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The key name.
    pub key: String,
    /// Its value, always as a string.
    pub value: String,
}

/// What an input file said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedInput {
    /// The master key, or `None` if the file did not define one.
    pub master_key: Option<String>,
    /// Everything else, in the order the file gave it.
    pub entries: Vec<Entry>,
}

/// The format an input file will be read as, from its extension.
///
/// `.json` and `.env` are named; everything else is the colon format.
pub fn format_for(input_file: &Path) -> InputFormat {
    match input_file
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("json") => InputFormat::Json,
        Some("env") => InputFormat::Env,
        _ => InputFormat::Colon,
    }
}

/// Reads a file and parses it as whatever its extension says it is.
pub fn parse_input(input_file: &Path) -> Result<ParsedInput> {
    let content = std::fs::read_to_string(input_file).map_err(|_| {
        Error::new(
            Code::BadInput,
            format!("could not read input file: {}", input_file.display()),
        )
    })?;

    parse_text(&content, format_for(input_file))
}

/// Parses input text in a named format. The file-free half of [`parse_input`].
pub fn parse_text(content: &str, format: InputFormat) -> Result<ParsedInput> {
    match format {
        InputFormat::Json => parse_json(content),
        InputFormat::Env => Ok(parse_env(content)),
        InputFormat::Colon => parse_colon(content),
    }
}

/// The default format: `master:<key>` first, then `key:value`.
///
/// Only the first colon splits, so a value may contain as many more as it likes -
/// which is what lets a URL or a connection string go in without escaping.
fn parse_colon(content: &str) -> Result<ParsedInput> {
    let lines: Vec<&str> = content
        .split('\n')
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();

    let first = lines
        .first()
        .ok_or_else(|| Error::new(Code::BadInput, "input file is empty"))?;

    let (head, master_key) = first.split_once(':').filter(|(head, _)| *head == fmt::MASTER_ENTRY_KEY).ok_or_else(|| {
        Error::new(
            Code::BadInput,
            format!(r#"first line must be "{}:your_master_key""#, fmt::MASTER_ENTRY_KEY),
        )
    })?;
    debug_assert_eq!(head, fmt::MASTER_ENTRY_KEY);

    let entries = lines[1..]
        .iter()
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| Entry {
            key: key.to_string(),
            value: value.to_string(),
        })
        .collect();

    Ok(ParsedInput {
        master_key: Some(master_key.to_string()),
        entries,
    })
}

/// dotenv syntax.
///
/// Lines beginning `#` are skipped, as are lines with no `=` and lines with an
/// empty key. A leading `export ` is stripped. A matched pair of single or double
/// quotes around the whole value is stripped - no escape sequences are
/// interpreted. The master entry may appear anywhere.
fn parse_env(content: &str) -> ParsedInput {
    let mut master_key = None;
    let mut entries = Vec::new();

    for raw in content.split('\n') {
        let mut line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(rest) = line.strip_prefix("export ") {
            line = rest.trim();
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        let key = key.trim();
        if key.is_empty() {
            continue;
        }

        let mut value = value.trim();
        if value.len() >= 2 {
            let bytes = value.as_bytes();
            let first = bytes[0];
            let last = bytes[bytes.len() - 1];
            if first == last && (first == b'"' || first == b'\'') {
                value = &value[1..value.len() - 1];
            }
        }

        if key == fmt::MASTER_ENTRY_KEY {
            master_key = Some(value.to_string());
            continue;
        }

        entries.push(Entry {
            key: key.to_string(),
            value: value.to_string(),
        });
    }

    ParsedInput {
        master_key,
        entries,
    }
}

/// A flat object.
///
/// Values that are not strings are serialised to their JSON form rather than
/// refused, so a port number or a feature flag lifted straight out of an existing
/// config file goes in without being quoted first. Everything comes back out as a
/// string, which is what the store holds.
///
/// `serde_json` is built with `preserve_order`, so the document's key order is
/// the order `entries` gets - which is what that field promises.
fn parse_json(content: &str) -> Result<ParsedInput> {
    let document: Value = serde_json::from_str(content)
        .map_err(|_| Error::new(Code::BadInput, "invalid JSON input file"))?;

    let object = document.as_object().ok_or_else(|| {
        Error::new(Code::BadInput, "JSON input must be an object of key-value pairs")
    })?;

    let mut master_key = None;
    let mut entries = Vec::new();

    for (key, value) in object {
        let text = match value {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        };

        if key == fmt::MASTER_ENTRY_KEY {
            master_key = Some(text);
            continue;
        }

        entries.push(Entry {
            key: key.clone(),
            value: text,
        });
    }

    Ok(ParsedInput {
        master_key,
        entries,
    })
}
