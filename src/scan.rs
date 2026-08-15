//! Recursive scanning for document files (`iter_doc_files`) and slopLock
//! files (`iter_sloplock_files`).
//!
//! Matching is case-insensitive; paths already carrying the `.slopLock`
//! suffix are never reported as candidates for encryption.

use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Document extensions eligible for encryption (lowercase, no leading dot).
const DOC_EXTENSIONS: &[&str] = &[
    "txt", "pdf", "doc", "docx", "ppt", "pptx", "xls", "xlsx", "odt", "odp", "ods", "md", "rtf",
];

/// Public suffix marking slopLock output (lowercase, no leading dot).
const SLOPLOCK_SUFFIX: &str = "sloplock";

fn file_ext_lower(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
}

/// Return `true` if `path`'s final component ends with the slopLock suffix
/// (case-insensitive).
pub fn is_sloplock_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| {
            n.split('.')
                .next_back()
                .is_some_and(|last| last.eq_ignore_ascii_case(SLOPLOCK_SUFFIX))
        })
        .unwrap_or(false)
}

/// Return `true` if `path` is a document file eligible for encryption:
/// an extension in [`DOC_EXTENSIONS`], no slopLock suffix, and the path is a
/// regular file.
fn is_doc_candidate(path: &Path) -> bool {
    if is_sloplock_path(path) {
        return false;
    }
    let Some(ext) = file_ext_lower(path) else {
        return false;
    };
    DOC_EXTENSIONS.contains(&ext.as_str())
}

fn collect(root: &Path, filter: fn(&Path) -> bool) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .filter(|p| filter(p))
    {
        out.push(entry);
    }
    out.sort();
    out
}

/// Recursively collect document files under `root`, sorted for determinism.
///
/// A missing root yields an empty list.
pub fn iter_doc_files(root: &Path) -> Vec<PathBuf> {
    if !root.exists() {
        return Vec::new();
    }
    collect(root, is_doc_candidate)
}

/// Recursively collect `.slopLock` files under `root`, sorted for determinism.
///
/// A missing root yields an empty list.
pub fn iter_sloplock_files(root: &Path) -> Vec<PathBuf> {
    if !root.exists() {
        return Vec::new();
    }
    collect(root, is_sloplock_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn make(dir: &tempfile::TempDir, rel: &str) -> PathBuf {
        let path = dir.path().join(rel);
        let _ = fs::create_dir_all(path.parent().expect("relative path has a parent"));
        fs::write(&path, b"content").unwrap();
        path
    }

    fn rel_names(paths: Vec<PathBuf>, dir: &tempfile::TempDir) -> Vec<String> {
        paths
            .into_iter()
            .map(|p| {
                p.strip_prefix(dir.path())
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    #[test]
    fn finds_document_files_recursively() {
        let dir = tempdir().unwrap();
        make(&dir, "report.pdf");
        make(&dir, "notes.txt");
        make(&dir, "slides/presentation.pptx");
        make(&dir, "deep/deeper/deepest.docx");
        make(&dir, "readme.md");
        make(&dir, "spreadsheet.xlsx");

        let got = rel_names(iter_doc_files(dir.path()), &dir);
        assert_eq!(
            got,
            vec![
                "deep/deeper/deepest.docx",
                "notes.txt",
                "readme.md",
                "report.pdf",
                "slides/presentation.pptx",
                "spreadsheet.xlsx",
            ]
        );
    }

    #[test]
    fn skips_non_document_extensions() {
        let dir = tempdir().unwrap();
        make(&dir, "photo.jpg");
        make(&dir, "archive.zip");
        make(&dir, "binary.bin");
        make(&dir, "code.rs");
        make(&dir, "noext");

        assert!(iter_doc_files(dir.path()).is_empty());
    }

    #[test]
    fn always_skips_sloplock_files_even_with_doc_ext_shape() {
        let dir = tempdir().unwrap();
        make(&dir, "already.pdf.slopLock");
        make(&dir, "plain.txt.slopLock");

        assert!(iter_doc_files(dir.path()).is_empty());
    }

    #[test]
    fn document_matching_is_case_insensitive() {
        let dir = tempdir().unwrap();
        make(&dir, "REPORT.PDF");

        let found = iter_doc_files(dir.path());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].file_name().unwrap(), "REPORT.PDF");
        assert!(is_sloplock_path(Path::new("x.PDF.slopLock")));
        assert!(is_sloplock_path(Path::new("x.pdf.SLOPLOCK")));
        assert!(!is_sloplock_path(Path::new("x.pdf.sloplocky")));
    }

    #[test]
    fn sloplock_files_are_found_recursively() {
        let dir = tempdir().unwrap();
        make(&dir, "a.txt.slopLock");
        make(&dir, "sub/b.pdf.slopLock");
        make(&dir, "not-encrypted.pdf");

        let mut got = rel_names(iter_sloplock_files(dir.path()), &dir);
        got.sort();
        assert_eq!(
            got,
            vec![
                "a.txt.slopLock".to_string(),
                "sub/b.pdf.slopLock".to_string()
            ]
        );
    }

    #[test]
    fn empty_and_nonexistent_roots() {
        let dir = tempdir().unwrap();
        let empty = tempdir().unwrap();
        assert!(iter_doc_files(empty.path()).is_empty());
        assert!(iter_sloplock_files(empty.path()).is_empty());
        let missing = dir.path().join("does-not-exist");
        // A missing root yields empty results, not panic or error.
        assert!(iter_doc_files(&missing).is_empty());
        assert!(iter_sloplock_files(&missing).is_empty());
    }

    #[test]
    fn results_are_deterministically_sorted() {
        let dir = tempdir().unwrap();
        make(&dir, "b.txt");
        make(&dir, "a.txt");
        make(&dir, "c/sub.txt");
        let first = iter_doc_files(dir.path());
        let second = iter_doc_files(dir.path());
        assert_eq!(first, second);
        let got = rel_names(first, &dir);
        assert_eq!(got, vec!["a.txt", "b.txt", "c/sub.txt"]);
    }
}
