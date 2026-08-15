//! Error types shared across slopLock.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Underlying I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A failure while processing a specific file.
    #[error("failed to process {}: {source}", path.display())]
    File {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The supplied passphrase is not a valid master key.
    #[error("invalid key")]
    InvalidKey,

    /// The file does not start with the expected `"SLOP"` magic bytes.
    #[error("invalid file format (bad magic bytes)")]
    BadMagic,

    /// The file is too short or internally inconsistent (truncated/corrupt).
    #[error("truncated or malformed slopLock file")]
    Malformed,

    /// The stored original filename was not valid UTF-8.
    #[error("stored filename is not valid UTF-8")]
    BadName,

    /// Decryption/authentication failed (wrong key or tampered data).
    #[error("decryption failed (wrong key or corrupted data)")]
    DecryptFailed,

    /// Low-level encryption failure.
    #[error("encryption failed")]
    EncryptFailed,
}
