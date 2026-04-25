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
| Symmetric AEAD | `chacha20poly1305` (XChaCha20-Poly1305) | Encrypted-rules section in `.aion` files |
| Key derivation | `hkdf` (HKDF-SHA256) | Per-file key from master + file_id + version |
| Password-based KDF | `argon2` | Keystore password protection |
| Constant-time compare | `subtle::ConstantTimeEq` | Public-key comparisons (post-PR #43) |
| Randomness | `rand::rngs::OsRng` | Nonces, key generation |
| Post-quantum signing | `pqcrypto-mldsa` (ML-DSA-65) | Hybrid signatures (RFC-0027) |

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
