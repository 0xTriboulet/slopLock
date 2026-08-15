//! Cryptographic core: key handling, key derivation, and the AES-256-GCM
//! payload codec.
//!
//! Security model: the master passphrase is **never** embedded as a literal in
//! the shipped binary. Only its SHA-256 hash ([`MASTER_KEY_HASH`]) is embedded;
//! that 32-byte hash doubles as the AES-256 key material. A provided key is
//! accepted iff `sha256(provided) == MASTER_KEY_HASH`.

use crate::error::Error;
use aead::{AeadInPlace, KeyInit, Nonce};
use aes_gcm::Aes256Gcm;
use sha2::{Digest, Sha256};

/// SHA-256 hash of the master passphrase (32 bytes == AES-256 key length).
const MASTER_KEY_HASH: [u8; 32] = [
    0xc4, 0x3f, 0x4c, 0xfe, 0x90, 0x4c, 0x64, 0x3b, 0xd0, 0xa9, 0x96, 0xfe, 0x10, 0x33, 0xcf, 0xc4,
    0x8d, 0x3e, 0x35, 0xe2, 0xf8, 0x46, 0xc5, 0x22, 0x23, 0x12, 0x7e, 0x6d, 0x89, 0x57, 0xc9, 0x83,
];

/// Magic bytes prefixed to every encrypted payload (`.slopLock` files).
pub const MAGIC: [u8; 4] = *b"SLOP";

/// Nonce size for AES-GCM.
const NONCE_LEN: usize = 12;
/// Authentication tag size for AES-GCM.
const TAG_LEN: usize = 16;
/// Size of the fixed leading header (`magic` + `name_len`).
const PREAMBLE_LEN: usize = 4 + 4;

/// Derive a 256-bit key from a candidate master passphrase.
///
/// The derivation is a single SHA-256, so the result for the master key is
/// exactly [`MASTER_KEY_HASH`]. This is also used to turn a user-supplied
/// passphrase into an AES-256 key for decryption.
pub(crate) fn derive_key(passphrase: &str) -> [u8; 32] {
    let digest = Sha256::digest(passphrase.as_bytes());
    digest.into()
}

/// The master AES-256 key: the SHA-256 hash of the master passphrase, which
/// is the only master material embedded in the binary.
pub(crate) fn master_key() -> [u8; 32] {
    MASTER_KEY_HASH
}

/// Return `true` if `passphrase` is the valid master key.
pub fn is_valid_key(passphrase: &str) -> bool {
    derive_key(passphrase) == MASTER_KEY_HASH
}

/// Encrypt `plaintext`, storing `original_name` encrypted-with-the-payload so
/// it can be restored on decryption.
///
/// The on-disk layout (all lengths big-endian) is:
/// ```text
/// [0..4)              magic b"SLOP"
/// [4..8)              u32 original_name_len
/// [8..8+name_len)     original_name (UTF-8)
/// [8+name_len..+12)   nonce
/// [..tail]            ciphertext || 16-byte GCM tag
/// ```
/// The **whole header** (magic through nonce) is used as associated data (AAD),
/// binding the stored filename to the auth tag.
pub fn encrypt_payload(
    plaintext: &[u8],
    original_name: &str,
    key: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    let name_bytes = original_name.as_bytes();
    if name_bytes.len() > u32::MAX as usize {
        return Err(Error::EncryptFailed);
    }

    // Fresh, uniformly random 96-bit nonce (AES-GCM's recommended size).
    let nonce_bytes: [u8; NONCE_LEN] = rand::random();
    let nonce = <Nonce<Aes256Gcm>>::from_slice(&nonce_bytes);

    // Build the header: magic + name_len + name + nonce. The entire header is
    // bound into the auth tag as AAD.
    let mut header = Vec::with_capacity(PREAMBLE_LEN + name_bytes.len() + NONCE_LEN);
    header.extend_from_slice(&MAGIC);
    header.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
    header.extend_from_slice(name_bytes);
    header.extend_from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::EncryptFailed)?;
    let mut buffer = plaintext.to_vec();
    // In aead 0.5 the ciphertext + GCM tag are appended to the buffer in place.
    cipher
        .encrypt_in_place(nonce, &header, &mut buffer)
        .map_err(|_| Error::EncryptFailed)?;

    let mut out = header;
    out.extend_from_slice(&buffer);
    Ok(out)
}

/// Decrypt a blob produced by [`encrypt_payload`], returning
/// `(plaintext, original_name)`.
pub fn decrypt_payload(blob: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, String), Error> {
    // Magic check first: short blobs are malformed, longer ones with the wrong
    // prefix are foreign files.
    if blob.len() < MAGIC.len() {
        return Err(Error::Malformed);
    }
    if blob[0..MAGIC.len()] != MAGIC {
        return Err(Error::BadMagic);
    }
    if blob.len() < PREAMBLE_LEN + NONCE_LEN + TAG_LEN {
        return Err(Error::Malformed);
    }

    let name_len = u32::from_be_bytes([blob[4], blob[5], blob[6], blob[7]]) as usize;
    // Bounds: header + nonce + tag must all fit. Checked arithmetic so a
    // hostile `name_len` cannot overflow.
    let name_end = PREAMBLE_LEN
        .checked_add(name_len)
        .and_then(|end| end.checked_add(NONCE_LEN + TAG_LEN))
        .filter(|&total| total <= blob.len())
        .map(|_| PREAMBLE_LEN + name_len)
        .ok_or(Error::Malformed)?;

    let name = std::str::from_utf8(&blob[PREAMBLE_LEN..name_end]).map_err(|_| Error::BadName)?;

    // The stored name is used to restore the file on disk; reject anything
    // that could escape the sibling file (path traversal) or is empty.
    if name.is_empty() || name.contains('/') || name.contains('\\') {
        return Err(Error::BadName);
    }

    let aad_end = name_end + NONCE_LEN;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::DecryptFailed)?;
    let nonce = <Nonce<Aes256Gcm>>::from_slice(&blob[name_end..aad_end]);

    let mut ct = blob[aad_end..].to_vec();
    cipher
        .decrypt_in_place(nonce, &blob[..aad_end], &mut ct)
        .map_err(|_| Error::DecryptFailed)?;
    // `decrypt_in_place` already stripped the GCM tag from `ct`.

    Ok((ct, name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn master() -> [u8; 32] {
        derive_key("qwenisthebest")
    }

    #[test]
    fn embedded_master_hash_matches_sha256_of_passphrase() {
        let expected = Sha256::digest(b"qwenisthebest");
        let expected: [u8; 32] = expected.into();
        assert_eq!(MASTER_KEY_HASH, expected);
    }

    #[test]
    fn embedded_master_hash_is_the_derivation_of_the_passphrase() {
        assert_eq!(MASTER_KEY_HASH, derive_key("qwenisthebest"));
    }

    #[test]
    fn master_key_derivation_is_deterministic() {
        assert_eq!(derive_key("qwenisthebest"), derive_key("qwenisthebest"));
    }

    #[test]
    fn different_passphrases_derive_different_keys() {
        assert_ne!(derive_key("qwenisthebest"), derive_key("qwenisthebest2"));
        assert_ne!(derive_key("qwenisthebest"), derive_key(""));
    }

    #[test]
    fn is_valid_key_accepts_the_master_key() {
        assert!(is_valid_key("qwenisthebest"));
    }

    #[test]
    fn is_valid_key_rejects_wrong_keys() {
        assert!(!is_valid_key("qwenisthebest2"));
        assert!(!is_valid_key("bestistheqwen"));
        assert!(!is_valid_key(""));
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = master();
        let blob = encrypt_payload(b"hello world", "report.pdf", &key).unwrap();
        let (pt, name) = decrypt_payload(&blob, &key).unwrap();
        assert_eq!(pt, b"hello world");
        assert_eq!(name, "report.pdf");
    }

    #[test]
    fn decrypt_empty_plaintext() {
        let key = master();
        let blob = encrypt_payload(b"", "empty.txt", &key).unwrap();
        let (pt, name) = decrypt_payload(&blob, &key).unwrap();
        assert_eq!(pt, b"");
        assert_eq!(name, "empty.txt");
    }

    #[test]
    fn decrypt_large_binary_plaintext() {
        let key = master();
        let data: Vec<u8> = (0u32..100_000).map(|i| (i % 256) as u8).collect();
        let blob = encrypt_payload(&data, "big.bin", &key).unwrap();
        let (pt, name) = decrypt_payload(&blob, &key).unwrap();
        assert_eq!(pt, data);
        assert_eq!(name, "big.bin");
    }

    #[test]
    fn ciphertext_differs_from_plaintext() {
        let key = master();
        let blob = encrypt_payload(b"secret bytes here", "x.txt", &key).unwrap();
        // The header is unencrypted by design, but the payload region must
        // not contain the plaintext in cleartext.
        let payload = &blob[PREAMBLE_LEN + "x.txt".len() + NONCE_LEN..];
        assert!(!payload
            .windows(b"secret bytes here".len())
            .any(|w| w == b"secret bytes here"));
    }

    #[test]
    fn each_encryption_uses_a_fresh_nonce() {
        let key = master();
        let a = encrypt_payload(b"same", "f.txt", &key).unwrap();
        let b = encrypt_payload(b"same", "f.txt", &key).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let good = master();
        let bad = derive_key("not-the-key");
        let blob = encrypt_payload(b"secret", "s.txt", &good).unwrap();
        assert!(matches!(
            decrypt_payload(&blob, &bad),
            Err(Error::DecryptFailed)
        ));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let key = master();
        let mut blob = encrypt_payload(b"secret data", "s.txt", &key).unwrap();
        // Flip a byte in the ciphertext region.
        *blob.last_mut().unwrap() ^= 0xff;
        assert!(matches!(
            decrypt_payload(&blob, &key),
            Err(Error::DecryptFailed)
        ));
    }

    #[test]
    fn tampered_header_rejected_via_aad() {
        let key = master();
        let mut blob = encrypt_payload(b"secret data", "s.txt", &key).unwrap();
        // Change the stored name (part of AAD).
        let name_start = PREAMBLE_LEN;
        blob[name_start] ^= 0x01;
        assert!(matches!(
            decrypt_payload(&blob, &key),
            Err(Error::DecryptFailed)
        ));
    }

    #[test]
    fn crafted_blob_with_traversal_name_is_rejected() {
        let key = master();
        let _ = (key,);
        // Craft: SLOP + u32be len + "../evil.txt" + 12B nonce + 16B tag garbage.
        for evil in ["../evil.txt", "..\\evil.txt", "a/b.txt", ""] {
            let mut blob = Vec::new();
            blob.extend_from_slice(&MAGIC);
            blob.extend_from_slice(&(evil.len() as u32).to_be_bytes());
            blob.extend_from_slice(evil.as_bytes());
            blob.extend_from_slice(&[0u8; NONCE_LEN]);
            blob.extend_from_slice(&[0u8; TAG_LEN]);
            assert!(
                matches!(decrypt_payload(&blob, &master()), Err(Error::BadName)),
                "expected BadName for {evil:?}"
            );
        }
    }

    #[test]
    fn bad_magic_rejected() {
        let key = master();
        let mut blob = encrypt_payload(b"secret", "s.txt", &key).unwrap();
        blob[0] = b'X';
        assert!(matches!(decrypt_payload(&blob, &key), Err(Error::BadMagic)));
    }

    #[test]
    fn truncated_blob_rejected() {
        let key = master();
        let blob = encrypt_payload(b"secret", "s.txt", &key).unwrap();
        for cut in 0..blob.len().min(40) {
            assert!(matches!(
                decrypt_payload(&blob[..cut], &key),
                Err(Error::Malformed) | Err(Error::BadMagic)
            ));
        }
    }
}
