# Crypto Primitives

Every cryptographic operation in aion-context goes through one
of a small set of vetted libraries. The crate **does not
implement its own crypto** — `.claude/rules/crypto.md` is
explicit about this.

## Primitives

| Operation | Library | Used for |
|---|---|---|
| Signing | `ed25519-dalek` | Every signature: versions, attestations, manifests, DSSE envelopes, rotation records, revocation records |
| Hashing | `blake3` | Version hashes, parent_hash chain, integrity hash, leaf hashes for transparency log, manifest IDs |
| Symmetric AEAD | `chacha20poly1305` (ChaCha20-Poly1305, 96-bit nonce) | Confidential rules content; format-v2 rules encoding only, see [below](#public-rules-are-not-confidential) |
| Key derivation | `hkdf` (HKDF-SHA256) | Confidential content key from the per-version DEK; v2 rules key from `file_id` + version (both public) |
| Recipient key wrapping | `hpke` 0.14.1 (RFC 9180 base mode) | DEK wrapped per recipient: DHKEM(X25519) or X-Wing (ML-KEM-768 + X25519, via `ml-kem` and `x-wing`) |
| Password-based KDF | `argon2` | Keystore password protection |
| Constant-time compare | `subtle::ConstantTimeEq` | Public-key comparisons (post-PR #43) |
| Randomness | `rand::rngs::OsRng` | Nonces, key generation |
| Post-quantum signing | `pqcrypto-mldsa` (ML-DSA-65) | Hybrid signatures (RFC-0027) |

## Public rules are not confidential

**Format v3, public mode:** rules written with
`RulesProtection::Public` / `--public` are stored in the clear, framed
and Padmé-padded. The version entry signs a BLAKE3 commitment to those
exact stored bytes, so any change fails `verify_file` without any key.
Public means public: the signature makes the rules tamper-evident,
not secret. For secrecy, use [confidential rules](#confidential-rules).

**Format v2 (files written before format v3):** the rules payload is
stored as ChaCha20-Poly1305 ciphertext, but **anyone who holds an
`.aion` file can still read its rules.** The key
comes from HKDF over the file's `file_id` and the version number,
and both are stored in plain sight in the file. No secret goes in.
This is why `operations::show_current_rules(path)` takes only a path.
`aion show <FILE> rules` is the same: its `--registry` holds only
public verifying keys.

What you get from it:

- **No casual exposure.** The rules don't appear as plaintext in the
  raw bytes, so `strings` or `grep` on the file won't find them.
- **Accidental-corruption detection only, from the AEAD tag.** The
  tag catches bit rot and a payload spliced in from another version.
  It gives no integrity against an attacker, because the key is
  public and anyone can compute a valid tag. Real integrity comes
  from the signed `rules_hash`, the signature chain, and the
  whole-file BLAKE3 hash.

What you do **not** get: secrecy from anyone who has the file.
Treat an `.aion` file as **public to everyone who can read it**, and
don't put secrets, credentials, or regulated personal data in rules.
If the policy itself must be kept confidential, encrypt the whole
`.aion` file at rest or in transit with a tool that holds a real key
(age, a KMS envelope, disk encryption).

For either format, real confidentiality needs a key that isn't
stored in the file: that is [confidential rules](#confidential-rules).
`aion init --no-encryption` is now a deprecated alias for `--public`.

## Confidential rules

Format-v3 rules written with `RulesProtection::Confidential` (RFC-0039)
are readable only by the recipients the writer names, and verification
stays key-free.

- **Per version:** a fresh random 32-byte DEK. The content key is
  HKDF-SHA256 of the DEK, salted with `ctx = file_id ‖ author_id ‖
  version`; the framed rules are sealed with ChaCha20-Poly1305 under
  `AION_V3_RULES_AAD_V1\0 ‖ ctx`.
- **Per recipient:** the DEK is sealed with HPKE base mode, `info =
  AION_V3_DEK_WRAP_V1\0 ‖ ctx` and `aad = dek_commitment`, using
  DHKEM(X25519) or X-Wing (ML-KEM-768 + X25519). Or a key service such
  as a KMS wraps it through a `DekWrapper`, bound to the same context
  plus the commitment; whether that recipient is post-quantum depends on
  the service.
- **Key commitment:** `dek_commitment = BLAKE3::derive_key("aion-context
  v3 2026-10 dek commitment", DEK)` is checked before any decryption,
  so every recipient who can open the rules reads the same bytes.
- **Signed:** the version signs the BLAKE3 commitment to the whole
  sealed section, so verification needs no key, and a section copied
  into another author's file or version opens for no one.

Readers use `chain::open_current_rules` with `RecipientKeys` holding
their `confidential::EncryptionIdentity`. Errors are deliberately
coarse: `RecipientKeyRequired` (no identity supplied), `NotARecipient`
(none of yours is listed), and `RulesUnopenable` (listed, but opening
failed at any step). `chain::disclose_version_key` releases one
version's DEK for selective disclosure; it opens that version only.

Still visible to anyone holding the file: recipient public keys and
their KEM kinds, the padded rules length, commit messages, authors,
timestamps, and the version count. Post-quantum confidentiality holds
only when **every** recipient of a version uses X-Wing: an X25519
recipient wraps the same DEK under a classical KEM. Signatures stay
Ed25519 unless RFC-0027 hybrid signatures are used. The `ml-kem` and
`x-wing` crates state that they have not been independently audited.

## Domain separation

Every BLAKE3 use carries a domain separator string baked into
the input bytes, so hashes used for one purpose can't be
confused with hashes used for another. The separators in use:

| Domain | Purpose |
|---|---|
| `AION_V2_VERSION_SIGNATURE_V1` | Per-version signature canonical message |
| `AION_V2_ATTESTATION_V1` | Multi-party attestation message |
| `AION_V2_MANIFEST_SIG_V1\0` | RFC-0022 manifest signature message |
| `AION_V2_ROTATION_V1` | Rotation record canonical message |
| `AION_V2_REVOCATION_V1` | Revocation record canonical message |
| `AION_V2_LOG_LEAF_V1\0` | Transparency-log leaf hash |
| `AION_V2_LOG_NODE_V1\0` | Transparency-log internal-node hash |
| `AION_V2_LOG_STH_V1\0` | Signed Tree Head canonical bytes |
| `AION_V2_LOG_EMPTY_V1\0` | Empty-tree sentinel root |
| `AION_V2_KEY_ATTESTATION_V1` | Hardware-attestation binding (RFC-0026) |
| `AION_V2_HYBRID_V1\0` | Hybrid classical + ML-DSA signature payload (RFC-0027) |
| `AION_V2_MANIFEST_V1` | ArtifactManifest canonical bytes prefix |
| `AION_V3_VERSION_SIGNATURE_V1\0` | Format-v3 version signature canonical message (RFC-0039) |
| `AION_V3_VERSION_HASH_V1\0` | Format-v3 version hash, the value `parent_hash` links to (RFC-0039) |
| `AION_V3_ATTESTATION_V1\0` | Format-v3 multi-party attestation message (RFC-0039) |
| `AION_V3_RULES_COMMIT_V1\0` | Format-v3 commitment to the stored rules section (RFC-0039) |
| `AION_V4_VERSION_SIGNATURE_V1\0` | Format-v4 version signature canonical message; adds the metadata commitment (RFC-0040) |
| `AION_V4_VERSION_HASH_V1\0` | Format-v4 version hash (RFC-0040) |
| `AION_V4_ATTESTATION_V1\0` | Format-v4 multi-party attestation message (RFC-0040) |
| `AION_V4_AUDIT_ENTRY_V1\0` | Format-v4 audit-entry hash: the stored 80 bytes and the details text (RFC-0040) |
| `AION_V4_METADATA_COMMIT_V1\0` | Format-v4 commitment to a version's message and audit entry (RFC-0040) |
| `aion-context v3 2026-10 dek commitment` | BLAKE3 `derive_key` context for the DEK commitment (RFC-0039) |

Key-derivation and HPKE labels (not BLAKE3 domains):
`AION_V3_RULES_KEY_V1\0` (HKDF info), `AION_V3_RULES_AAD_V1\0` (content
AEAD), and `AION_V3_DEK_WRAP_V1\0` (HPKE info).

A trailing `\0` byte forbids any other domain from being
constructed by appending bytes to one of these.

## Replay defense

Every signed artifact carries a monotonically increasing
`version: u64` AND a source identifier (`AuthorId`).
Receivers reject `(source, version)` pairs they have already
accepted — replay is an attack class, not an edge case.

The `KeyRegistry`'s active-epoch-at-version semantics also
serve as a replay defense in a related way: a signature made
with key K at version V is only valid if K was the active
epoch's pinned key at V. An attacker who replays a signature
made with a now-rotated-out key cannot have it accepted at a
version where a different epoch is active.

## Constant-time comparison

Following PR #43, every `==` comparison on key-shaped bytes
goes through `subtle::ConstantTimeEq`:

```rust
use subtle::ConstantTimeEq;
if !bool::from(supplied_pk.ct_eq(&epoch.public_key)) {
    return Err(AionError::KeyMismatch { ... });
}
```

Public keys are not strictly secret, but the project's crypto
rule treats `==` on key bytes as a hard block regardless. The
audit-pass found one violation (in `preflight_registry_authz`)
which PR #43 closed.

## What the library does NOT do

- **Roll its own primitives.** No homemade Ed25519, BLAKE3,
  ChaCha20, or hash-chain linking. RFC-process gates any
  proposal to add a new primitive.
- **Truncate hashes for security decisions.** UX-only
  truncation (e.g., 16-hex-char display prefixes) is fine and
  encouraged — see `.claude/rules/observability.md`.
- **Use `==` on signatures, MACs, or keys.** Constant-time
  always.
- **Store private keys in `String` or `Vec<u8>`** that outlives
  the signing call. Wrapped in `zeroize::Zeroizing` newtypes
  so they zero on drop.
- **Panic on invalid input.** Every adversary input returns
  `Err` instead. Tiger Style + the property + fuzz harness
  layer enforce this at compile time and at test time.

## See also

- `.claude/rules/crypto.md` — the discipline document; every
  PR touching crypto code is reviewed against it.
- `src/crypto.rs` — the public crypto-primitives module.
- The `crypto-auditor` agent in `.claude/agents/` reviews crypto
  diffs before merge.
