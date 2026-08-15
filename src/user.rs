//! Current-user helpers.
//!
//! For development purposes, when the current user is the developer identity,
//! slopLock must *not* encrypt. The identity is never embedded as a literal in
//! the binary; only its SHA-256 hash ([`DEV_USER_HASH`]) is, and the live
//! username is compared against that hash.

use sha2::{Digest, Sha256};

/// SHA-256 hash of the developer username (see module docs).
const DEV_USER_HASH: [u8; 32] = [
    0xf1, 0x48, 0x38, 0x9d, 0x08, 0x0c, 0xfe, 0x85, 0x95, 0x29, 0x98, 0xa8, 0xa3, 0x67, 0xe2, 0xf7,
    0xea, 0xf3, 0x5f, 0x2d, 0x72, 0xd2, 0x59, 0x9a, 0x5b, 0x04, 0x12, 0xfe, 0x40, 0x94, 0xd6, 0x5c,
];

/// Return `true` if `username` is the developer identity.
///
/// Pure on `username` so it is directly testable without touching the
/// process environment.
pub fn is_dev_username(username: &str) -> bool {
    let digest = Sha256::digest(username.as_bytes());
    *digest == DEV_USER_HASH
}

/// Return `true` if the current process user is the developer identity.
///
/// If the username cannot be determined, this returns `false` (fail-safe:
/// we do not silently opt out of a requested operation on error).
pub fn is_dev_user() -> bool {
    whoami::username()
        .ok()
        .as_deref()
        .is_some_and(is_dev_username)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_hash_matches_sha256_of_dev_username() {
        let expected = Sha256::digest(b"steve");
        let expected: [u8; 32] = expected.into();
        assert_eq!(DEV_USER_HASH, expected);
    }

    #[test]
    fn is_dev_username_accepts_the_dev_identity() {
        assert!(is_dev_username("steve"));
    }

    #[test]
    fn is_dev_username_rejects_other_names() {
        assert!(!is_dev_username("steve2"));
        assert!(!is_dev_username("Steve"));
        assert!(!is_dev_username("steve "));
        assert!(!is_dev_username(""));
        assert!(!is_dev_username("root"));
    }

    #[test]
    fn is_dev_user_matches_live_username() {
        // Whatever the real user is, the two entry points must agree.
        let live = whoami::username()
            .ok()
            .as_deref()
            .is_some_and(is_dev_username);
        assert_eq!(is_dev_user(), live);
    }
}
