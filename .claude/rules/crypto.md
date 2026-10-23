# Crypto

**The golden rule: do not write new crypto in this workspace.** Every
primitive aion-context needs already exists in `aion_context::crypto` or in a
vetted dependency. If you think you need a new primitive, that's an
RFC, not a PR.

## Required dependencies

| Need             | Library                          | Notes                                |
|------------------|----------------------------------|--------------------------------------|
| Signing          | `ed25519-dalek` (via `aion_context::crypto`) | Ed25519, seed from `keystore` |
| Verification     | `ed25519-dalek::VerifyingKey`    | Constant-time via library            |
| Hashing          | `blake3::Hasher`                 | BLAKE3 only — no SHA-1, no MD5       |
| Symmetric AEAD   | `chacha20poly1305`               | XChaCha20-Poly1305 for large payloads |
| Randomness       | `rand::rngs::OsRng`              | Never `thread_rng()` for key material |
| Constant-time eq | `subtle::ConstantTimeEq`         | For any secret-dependent compare     |

## Forbidden

- Rolling your own Ed25519, BLAKE3, ChaCha20, or any symmetric cipher.
- Truncating a BLAKE3 digest below 16 bytes for any **security**
  decision. UX-only truncation (e.g. display prefixes in logs or CLI
  output) is permitted and encouraged — see `.claude/rules/observability.md`
  on the 16-hex-char rule.
- `==` on `[u8]` for signatures, MACs, keys, or any secret. Use
  `subtle::ConstantTimeEq::ct_eq(...).into()` or delegate to the
  library's verify method.
- Storing private keys in `String`, `Vec<u8>` that outlives the signing
  call, or anywhere derive-`Serialize` or `Debug`. Wrap in a zeroizing
  newtype (`zeroize::Zeroizing`).
- Panicking on invalid signatures, malformed keys, or failed
  verification — these are adversary inputs and must return `Err`.

## Required properties

1. **Replay defense.** Every signed artifact carries a monotonically
   increasing `version` AND a source identifier (`author_id`).
   Receivers reject `(source, version)` pairs they have already
   accepted. This applies to policy files, audit entries, and any
   other signed artifact in the file format.
2. **Author binding.** Signatures verify against a pinned
   `HashMap<AuthorId, VerifyingKey>`. Unknown authors are rejected
   **before** signature verification runs — otherwise a malformed
   signature from an unknown author still burns a verify cycle.
3. **Hash domain separation.** When BLAKE3 is used for multiple
   purposes, each call uses a distinct `keyed_hash` key or a single
   prefix byte baked into the input. Never feed raw user-controlled
   input into a shared `blake3::Hasher` without domain separation.
4. **No ambient authority.** A function that verifies a signature
   takes the verifier as a parameter. Global static verifiers are
   forbidden — they make it impossible to test with pinned authors.
5. **Hash chains are append-only.** `signature_chain` and the audit
   chain verify *every* link on read. `verify()` must be O(entries)
   and read nothing external.

## External-spec exceptions

External specifications whose wire format mandates a hash
algorithm other than BLAKE3 may use that algorithm **only** at
the transport/interop boundary, and only when it gates no
aion-internal security decision. Every such exception is named
below with its scope.

- **OCI Image Manifest (`src/oci.rs`)**: SHA-256 is mandated by
  the OCI Image Manifest v1.1 specification for the `digest`
  field on descriptors, layers, and config blobs. aion-context
  emits SHA-256 at the OCI transport layer so artifacts interop
  with cosign / ORAS / registries. Internal content attestation
  (manifest verification, audit chain, transparency log, hybrid
  signatures) remains BLAKE3-only. The SHA-256 use at
  `src/oci.rs` is transport-only; no aion-internal accept/reject
  decision is gated on a SHA-256 comparison.
- **HKDF-SHA256 and HPKE key derivation (RFC-0039)**:
  - **Where:** SHA-256 appears only as the hash function inside
    HKDF-SHA256 (`crypto::derive_key`: the v2 rules key today, and the
    v3 content key) and inside HPKE's DHKEM(X25519, HKDF-SHA256) and
    HKDF-SHA256 KDF.
  - **What it does:** it derives keys only. No SHA-256 output is ever
    stored, signed, or compared. Every commitment and every hash
    compared in an accept/reject decision is BLAKE3: the rules
    commitment, the DEK commitment, version hashes, and the integrity
    hash.
  - **How it can fail:** a SHA-256 weakness could weaken derived-key
    secrecy, which affects confidentiality, or make an open fail. It
    cannot turn a forgery into an accept, because acceptance is decided
    by Ed25519 signatures over BLAKE3 commitments.

- **SHA-3 family inside ML-KEM and X-Wing (RFC-0039 Phase B)**:
  - **Where:** SHA3-256, SHAKE-128/256 and TurboSHAKE appear only
    inside ML-KEM-768 and the X-Wing KEM (`ml-kem`, `x-wing`, and
    `hpke`'s X-Wing binding), where FIPS 203 and the X-Wing draft
    mandate them.
  - **What it does:** it derives keys and shared secrets only. ML-KEM
    compares SHA-3-derived values internally during decapsulation,
    but no SHA-3 output is stored, signed, or compared by
    aion-context, and none gates an accept/reject decision.
  - **How it can fail:** a SHA-3 weakness could weaken an X-Wing
    stanza's confidentiality or make it fail to open
    (`RulesUnopenable`). It cannot turn a forgery into an accept.
- **Fuzz-only keys (`fuzz/`)**: `fuzz/fuzz_targets/fuzz_verify_chain.rs`
  derives a fixed Ed25519 key pair from constant seeds, with the
  distinctive author id `0xF022_F022_F022_F022`. The seed files in
  `fuzz/seeds/fuzz_verify_chain/` are signed with it so that mutations
  reach the checks after signature verification. The key is public by
  construction. The `fuzz` crate is `publish = false`, and the key
  appears in no library, binary, example, or registry. A file signed by
  it proves nothing and must never be pinned outside the fuzz target.

## Key material lifecycle

- Keystore integration uses the OS keyring (`keyring` crate) or an
  HSM. Raw private-key bytes never hit the filesystem except as
  `zeroize`-backed encrypted blobs.
- Key rotation is explicit — rotate == mint new key, sign a rotation
  record with the old key, and from this point on reject anything
  signed with the old key after the rotation version.
- Test keys live in `test_helpers` (cfg-gated). They never appear in
  non-test code, never ship in examples, and never get committed to a
  real `.aion` file that might be mistaken for production.

## Review triggers

Any diff that touches these files is reviewed by the `crypto-auditor`
agent:

- `src/crypto.rs`
- `src/signature_chain.rs`
- `src/multisig.rs`
- `src/keystore.rs`
- `src/audit.rs` (audit hash chain)
- Anything matching `**/crypto*.rs`, `**/sign*.rs`, `**/verify*.rs`

Run `/crypto-scan` to list candidate files for a diff before pushing.
