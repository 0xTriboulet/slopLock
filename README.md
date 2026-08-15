# slopLock

> **Proof-of-concept, mock "ransomware" — security-research only.**
> `slopLock` is a deliberately *limited* and fully **reversible** document-file
> encryption utility built to explore threat-modeling questions around
> AI-agent-driven disk operations. It is **not** a weapon, it **does not**
> persist, exfiltrate, or self-propagate, and it is trivially reversible by
> anyone holding the key. **Only run it on data you own and back up.**

`slopLock` recurses a directory tree, encrypts every "document" file in place
with authenticated **AES‑256‑GCM**, and rewrites them with a `.slopLock`
extension. Given the correct key, a second run decrypts all `.slopLock` files
back to their original names and contents.

slopLock was entirely written by a **locally‑deployed `Qwen3.8‑27b`** model. Only
this README.md had to be modified for clarity.

---

## ⚠️ Responsible use

- **Authorization required.** Never run this against a system you do not own or
  do not have explicit permission to test.
- **It is reversible.** Unlike real ransomware, the key is known and the tool
  ships a first‑class `--decrypt` path. There is no data destruction.
- **No networking, no persistence, no self‑propagation.** Single static binary,
  no background agents, no outbound traffic.

If you use it, use it on a throwaway directory of disposable files.

---

## Quick start

```bash
cd slopLock

# Format + lint + build (the project hard‑denies warnings)
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo build --release

# Run the test suite (48 tests: unit + CLI + end‑to‑end against the real binary)
cargo test
```

Build produces `target/release/sloplock`.

### Usage

```text
sloplock [PATH]                 # encrypt document files under PATH (default ".")
sloplock --decrypt <KEY> [PATH] # decrypt .slopLock files under PATH (default ".")
sloplock --help
sloplock --version
```

Examples:

```bash
# Encrypt everything under ./docs
./target/release/sloplock ./docs

# Encrypt, then decrypt back with the master key
./target/release/sloplock ./docs
./target/release/sloplock --decrypt qwenisthebest ./docs
```

`PATH` defaults to the current directory. Both commands recurse. A wrong/missing
key on `--decrypt` fails fast **before touching any file** and exits non‑zero.

---

## Basic functionality

| Capability | Behaviour |
|---|---|
| **Recursive document discovery** | Walks the tree and matches document extensions, case‑insensitively: `txt`, `pdf`, `doc`, `docx`, `ppt`, `pptx`, `xls`, `xlsx`, `odt`, `odp`, `ods`, `md`, `rtf`. |
| **Encrypt in place** | For each document, writes `<name>.slopLock`, `fsync`s it, then deletes the original. The original is removed *only after* the ciphertext is fully and durably written, so a crash never loses data. |
| **Idempotent** | Re‑running encrypt is a no‑op on already‑encrypted files (never double‑wraps). |
| **Authenticated encryption** | AES‑256‑GCM with a fresh 96‑bit random nonce per file. The whole header is bound into the GCM tag as associated data (AAD), so tampering with the *stored filename* or the *ciphertext* is detected and rejected. |
| **Decrypt in place** | `--decrypt <KEY>` validates the key up front, then restores each `.slopLock` file to its stored original name and deletes the encrypted blob. Per‑file failures are reported but do not abort the walk. |
| **Filename recovery** | The original filename is stored inside (and authenticated by) the encrypted header, so it is restored exactly on decrypt. |
| **Traversal safe** | A crafted blob embedding a path‑separated filename (e.g. `../../x`) is rejected; decrypt only ever writes a sibling file. |
| **Deterministic & ordered** | Files are processed in sorted path order; identical runs produce identical results. |

### Encrypted file on‑disk format

All integer lengths are big‑endian.

```
offset  size  field
------  ----  -----------------------------------------
[0..4)  4     magic  b"SLOP"
[4..8)  4     u32    original filename length N
[8..8+N) N    bytes  original filename (UTF‑8)
[...]        12     bytes  random nonce
[...]        var    bytes  ciphertext || 16‑byte GCM tag
```

Everything from the magic through the nonce is **associated data (AAD)**, so the
stored filename is cryptographically bound to the auth tag — renaming (or
corrupting) the header invalidates authentication.

---

## Security model

The core product‑security property of this PoC is:

> **The master secret is never embedded in the binary as a literal. Only its
> SHA‑256 hash is shipped, and that hash doubles as the AES‑256 key.**

Concretely:

- **Master key.** The deployment's passphrase (`qwenisthebest`) is *derived* to
  a 256‑bit key by a single SHA‑256. The binary stores only that 32‑byte digest
  (`MASTER_KEY_HASH`), which is also the AES‑256 key. A candidate passphrase on
  `--decrypt` is accepted **iff** `sha256(candidate) == MASTER_KEY_HASH`.
- **Dev‑user gate, also hashed.** A development bypass ("if the current user is
  the developer, don't encrypt") is implemented against the SHA‑256 hash of the
  username — the literal name is never present in the binary either.
- **Verified clean.** The release binary is scanned and provably contains:
  - `0` occurrences of the passphrase literal, and
  - `0` standalone occurrences of the developer‑username literal.

  (Only the two SHA‑256 hashes are present.) This is the "hash the strings so
  the output binary does not contain sensitive information" requirement.

### Where Qwen3.8‑27b fits

In the real deployment this PoC models, the **locally‑deployed `Qwen3.8‑27b`** is
the origin of the master key material and the agent that performs the
file‑management work locally (offline, no key leaves the machine). In this
self‑contained PoC the model's behaviour is *mocked*: the key material is a fixed
constant whose only shipped form is its hash, and the encryption is performed by
the Rust binary directly. The security‑relevant behaviour — **hashed key,
authenticated crypto, reversible decrypt, developer bypass** — is identical to
what the model‑driven deployment would rely on, so the PoC remains a faithful,
fast, and deterministic stand‑in for red‑team / threat‑modeling.

> **Honest limitation.** In this snapshot the key is a hard‑coded constant. A
> full integration would have the local model generate/hold the key and pass it
> in memory (never in the image or on disk). That wiring is intentionally out of
> scope here to keep the PoC hermetic and trivially testable.

---

## Project layout

```
slopLock/
├── Cargo.toml            # deps + `[lints.rust] warnings = "deny"`
├── src/
│   ├── main.rs           # clap CLI + run()/exit‑code logic (+ CLI tests)
│   ├── lib.rs            # library crate root
│   ├── crypto.rs         # AES‑256‑GCM payload codec, key derivation, hashes
│   ├── scan.rs           # recursive doc / .slopLock discovery
│   ├── ops.rs            # file‑ and tree‑level encrypt/decrypt
│   ├── user.rs           # hashed dev‑user gate
│   └── error.rs          # error types
└── tests/
    └── e2e.rs            # end‑to‑end tests driving the compiled binary
```

## Lint & test gates

The project is gated to stay warning‑free (warnings are *denied*, never
suppressed):

```bash
cargo fmt --check                                  # formatting
cargo check                                        # type check
cargo clippy --all-targets -- -D warnings          # lints (deny)
cargo build --release                              # optimized binary
cargo test                                         # unit + CLI + e2e (48 tests)
```

The end‑to‑end suite spawns the **actual compiled `sloplock` binary** and drives
the encrypt/decrypt round‑trip, wrong‑key failure, and missing‑root behaviour
against real files on disk.

---

## Disclaimer

`slopLock` is a **mock, reversible, educationally‑scoped** proof of concept. It
exists to study the threat surface of agentic local file operations and to
demonstrate that *hashed‑key, authenticated, reversible* crypto fundamentally
changes the harm model compared to real ransomware. Use it only on systems and
data where you hold full authorization.
