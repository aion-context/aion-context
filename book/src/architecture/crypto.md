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
| Symmetric AEAD | `chacha20poly1305` (ChaCha20-Poly1305, 96-bit nonce) | Rules section in `.aion` files — encoding only, see [below](#the-rules-section-is-not-confidential) |
| Key derivation | `hkdf` (HKDF-SHA256) | Rules-section key from `file_id` + version (both public) |
| Password-based KDF | `argon2` | Keystore password protection |
| Constant-time compare | `subtle::ConstantTimeEq` | Public-key comparisons (post-PR #43) |
| Randomness | `rand::rngs::OsRng` | Nonces, key generation |
| Post-quantum signing | `pqcrypto-mldsa` (ML-DSA-65) | Hybrid signatures (RFC-0027) |

## The rules section is not confidential

The rules payload is stored as ChaCha20-Poly1305 ciphertext, but
**anyone who holds an `.aion` file can read its rules.** The key
comes from HKDF over the file's `file_id` and the version number,
and both are stored in plain sight in the file. No secret goes in.
This is why `operations::show_current_rules(path)` takes only a path.
`aion show <FILE> rules` is the same: its `--registry` holds only
public verifying keys.

What you get from it:

- **No casual exposure.** The rules don't appear as plaintext in the
  raw bytes, so `strings` or `grep` on the file won't find them.
- **Integrity, from the AEAD tag.** The ciphertext is bound to its
  version number, and on top of that the signature chain and the
  whole-file BLAKE3 hash detect any change.

What you do **not** get: secrecy from anyone who has the file.
Treat an `.aion` file as **public to everyone who can read it**, and
don't put secrets, credentials, or regulated personal data in rules.
If the policy itself must be kept confidential, encrypt the whole
`.aion` file at rest or in transit with a tool that holds a real key
(age, a KMS envelope, disk encryption).

`aion init --no-encryption` has no effect today: the rules section
is always written the same way. Real confidentiality needs a key
that isn't stored in the file. That's a file-format change and needs
an RFC.

## Domain separation

Every BLAKE3 use carries a domain separator string baked into
the input bytes, so hashes used for one purpose can't be
confused with hashes used for another. The separators in use:

| Domain | Purpose |
|---|---|
| `AION_V2_VERSION_SIG_V1` | Per-version signature canonical message |
| `AION_V2_ATTESTATION_V1` | Multi-party attestation message |
| `AION_V2_MANIFEST_SIG_V1` | RFC-0022 manifest signature message |
| `AION_V2_ROTATION_V1` | Rotation record canonical message |
| `AION_V2_REVOCATION_V1` | Revocation record canonical message |
| `AION_V2_LOG_LEAF_V1\0` | Transparency-log leaf hash |
| `AION_V2_LOG_NODE_V1\0` | Transparency-log internal-node hash |
| `AION_V2_LOG_STH_V1\0` | Signed Tree Head canonical bytes |
| `AION_V2_LOG_EMPTY_V1\0` | Empty-tree sentinel root |
| `AION_V2_KEY_ATTESTATION_V1` | Hardware-attestation binding (RFC-0026) |
| `AION_V2_HYBRID_V1` | Hybrid classical + ML-DSA signature payload (RFC-0027) |
| `AION_V2_MANIFEST_V1` | ArtifactManifest canonical bytes prefix |

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
