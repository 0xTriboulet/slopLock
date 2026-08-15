//! slopLock — disk encryption utility (development utility).
//!
//! Recursively encrypts document files to `.slopLock` (AES-256-GCM) and,
//! given a valid key, decrypts them. The key material is never stored as a
//! plain literal in the binary; only its SHA-256 hash is embedded.

#![deny(warnings)]

pub mod crypto;
pub mod error;
pub mod ops;
pub mod scan;
pub mod user;
