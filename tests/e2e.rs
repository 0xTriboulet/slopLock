//! End-to-end test driving the compiled `slopLock` binary.
//!
//! `CARGO_BIN_EXE_sloplock` is injected by cargo when integration tests run,
//! so this exercises the real CLI (arg parsing, exit codes, output) against
//! real files on disk — the most faithful test of the shipped behavior.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;

const MASTER: &str = "qwenisthebest";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sloplock")
}

fn run(args: &[&str], dir: &Path) -> (std::process::ExitStatus, String, String) {
    let out = Command::new(bin())
        .args(args)
        .arg(dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to spawn slopLock binary");
    (
        out.status,
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Build a `.slopLock` file for `src` using the library's file-level primitive
/// (which encrypts regardless of the dev-user gate — the gate only applies to
/// the tree-level / CLI encrypt command). This lets us place a real encrypted
/// file on disk to hand to the binary's `--decrypt`.
fn put_sloplock(src: &Path) -> std::path::PathBuf {
    // encrypt_file returns the new (.slopLock) path.
    let enc = sloplock::ops::encrypt_file(src).unwrap().expect("new path");
    assert!(enc.exists());
    enc
}

#[test]
fn e2e_decrypt_restores_files_via_binary() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    // Create two documents and encrypt them at the file level.
    let doc1 = dir.join("memo.txt");
    fs::write(&doc1, "sensitive memo content").unwrap();
    let doc2 = dir.join("slides.pptx");
    fs::write(&doc2, "binary-ish payload").unwrap();

    let enc1 = put_sloplock(&doc1);
    let enc2 = put_sloplock(&doc2);
    assert!(enc1.exists() && enc2.exists());
    assert!(!doc1.exists() && !doc2.exists());

    // Wrong key: binary must fail and leave the files untouched.
    let (status, out, err) = run(&["--decrypt", "wrong-key"], dir);
    assert!(
        !status.success(),
        "wrong key must exit non-zero; stdout={out:?} stderr={err:?}"
    );
    assert!(enc1.exists() && enc2.exists());

    // Correct key: binary must restore both files.
    let (status, out, err) = run(&["--decrypt", MASTER], dir);
    assert!(
        status.success(),
        "correct key must exit zero; stdout={out:?} stderr={err:?}"
    );
    assert_eq!(fs::read(&doc1).unwrap(), b"sensitive memo content");
    assert_eq!(fs::read(&doc2).unwrap(), b"binary-ish payload");
    assert!(!enc1.exists() && !enc2.exists());
}

#[test]
fn e2e_decrypt_empty_tree_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let (status, _, _) = run(&["--decrypt", MASTER], tmp.path());
    assert!(status.success());
}

#[test]
fn e2e_nonexistent_root_fails() {
    let out = Command::new(bin())
        .arg("/no/such/directory/anywhere")
        .status()
        .expect("spawn");
    assert!(!out.success());
}
