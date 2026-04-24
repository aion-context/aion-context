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
