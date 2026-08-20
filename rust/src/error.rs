//! One error type, with a code.
//!
//! The code is what the other five implementations agree on: `BAD_USER_KEY`
//! means the same thing in Rust, Go, .NET, Python, PHP and JavaScript, and a
//! script that greps for it keeps working when the team rewrites the service.
//! The message may be reworded between releases; the code will not be.

use std::fmt;

/// A stable identifier for a class of failure.
///
/// [`Code::as_str`] gives the string every implementation of this format shares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Code {
    /// The options given do not make sense.
    InvalidOptions,
    /// A required argument was missing or empty.
    InvalidArgument,
    /// No such store under this keystore directory.
    StoreNotFound,
    /// The directory exists but is not a store, or its metadata is unreadable.
    StoreCorrupt,
    /// No such key - in the named store, or in any of them.
    KeyNotFound,
    /// Decryption failed: the key is wrong, or the bytes have been altered.
    BadUserKey,
    /// A value token is not in the form this format defines.
    BadToken,
    /// The input file is not readable as the format its extension claims.
    BadInput,
    /// The bundle is missing, unreadable, or not a keystore bundle.
    BadBackup,
    /// The store or bundle is in a format version newer than this build reads.
    UnsupportedFormat,
}

impl Code {
    /// The wire string, identical in every implementation.
    pub fn as_str(self) -> &'static str {
        match self {
            Code::InvalidOptions => "INVALID_OPTIONS",
            Code::InvalidArgument => "INVALID_ARGUMENT",
            Code::StoreNotFound => "STORE_NOT_FOUND",
            Code::StoreCorrupt => "STORE_CORRUPT",
            Code::KeyNotFound => "KEY_NOT_FOUND",
            Code::BadUserKey => "BAD_USER_KEY",
            Code::BadToken => "BAD_TOKEN",
            Code::BadInput => "BAD_INPUT",
            Code::BadBackup => "BAD_BACKUP",
            Code::UnsupportedFormat => "UNSUPPORTED_FORMAT",
        }
    }
}

impl fmt::Display for Code {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Returned by every operation in this crate that can fail in a way the caller
/// might want to handle rather than merely report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// Stable across releases and identical across implementations.
    pub code: Code,
    /// What happened, in words meant for a person.
    pub message: String,
}

impl Error {
    pub(crate) fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}

/// The result type every fallible operation in this crate returns.
pub type Result<T> = std::result::Result<T, Error>;
