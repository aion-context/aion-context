# RFC 0022: External Artifact Manifest

- **Author:** aion-context maintainers
- **Status:** DRAFT
- **Created:** 2026-04-23
- **Updated:** 2026-04-23

## Abstract

Today `AionFile.encrypted_rules` is the only payload an `.aion` file
can attest to, and it lives *inside* the file bytes. Large artifacts
— pretrained model weights, datasets, container images, firmware
images — do not fit this shape: a 500 GB model cannot be embedded
into a governance file, and a verifier should not have to re-read
the full payload from the `.aion` bytes just to confirm it was not
tampered.

This RFC adds an **external artifact manifest**: a signed list of
`(name, size, hash)` triples that lets an `.aion` file attest to
external binary blobs by their BLAKE3 hash. The manifest is a
first-class signable surface, distinct from `VersionEntry`, so
existing single-signer and multisig flows compose with it unchanged.

Phase A (this RFC, this PR) delivers:

- A new `src/manifest.rs` module with `ArtifactEntry`,
  `ArtifactManifest`, and a `verify` method that re-hashes external
  bytes.
- Canonical manifest-message format with domain separation.
- `sign_manifest` / `verify_manifest` using the existing
  `SigningKey` / `VerifyingKey` and the attestation path from
  RFC-0021.
- Hegel property tests for manifest roundtrips, tamper detection,
  size mismatch, and cross-entry swap.

Phase B (future RFC): embedding the manifest in the on-disk
`.aion` file format (requires a format-version bump) and CLI
integration (`aion manifest add`, `aion manifest verify`).

## Motivation

### Problem Statement

In the Nvidia/Microsoft/MLSecOps style supply chain, models ship
as large binary artifacts. The governance artifact — what policy
applies, who approved release, what compliance framework was
satisfied — is a separate, small file. For `.aion` to be a
credible governance layer for signed models, it must:

1. Reference the model by its content hash, not its filename.
2. Carry enough metadata (size, algorithm) to let an offline
   verifier say "yes, this specific 487,123,456-byte blob with
   BLAKE3 root `abcd…` is the one the governance file approved."
3. Be signable and attestable by the same keys and policies used
   for version signatures — no parallel crypto stack.

The current `AionFile` shape forces the caller to either (a) embed
the artifact into `encrypted_rules` (impossible at 500 GB) or (b)
hash it out-of-band with no `.aion`-level attestation.

### Use Cases

- **Model signing**: an `.aion` file attests that this specific
  weights file, approved by these authors under this policy, is
  cleared for production. Verifier re-hashes the weights from disk
  and checks.
- **Dataset attestation**: an `.aion` file attests that training
  used this dataset, with this hash, at this size.
- **Firmware release**: an `.aion` file binds a firmware image
  hash to a multi-party release approval.
- **AIBOM / SBOM**: future work — the manifest becomes the
  aion-native hook point for exporting SPDX 3.0 AI / CycloneDX
  attestations.

### Goals

- **External referencing**: artifacts live on disk or in object
  storage, not in the `.aion` bytes.
- **Hash binding**: any change to the artifact bytes breaks
  manifest verification.
- **Signable unit**: the manifest is itself attestable via
  `SigningKey` and via the RFC-0021 attestation path.
- **Offline verification**: given the `.aion` file and the
  artifact bytes, verification is pure-local, no network.
- **Algorithm extensibility**: hash algorithm field is a `u16`
  so SHA3-256, BLAKE2b, or post-quantum hashes can be added
  without a format break.

### Non-Goals

- **Chunked/streaming verification**. Phase A computes the hash
  over the full artifact bytes. A Merkle-tree / Bao-style proof
  mode (for partial verification and random-access) is Phase B.
- **On-disk file-format change**. Phase A does not modify the
  `AionFile` binary layout; the manifest type exists independently
  and can be written alongside an `.aion` file or (in Phase B)
  embedded in it.
- **Content fetch**. This RFC does not fetch artifacts; it assumes
  the caller has the bytes.

## Proposal

### ArtifactEntry on-disk layout (128 bytes, `#[repr(C)]`)

```
Field             Offset  Size  Type       Notes
────────────────  ──────  ────  ─────────  ──────────────────────────────
name_offset            0     8  u64 LE     offset in string table
name_length            8     4  u32 LE     bytes, no null terminator
hash_algorithm        12     2  u16 LE     1 = BLAKE3-256 (only one for now)
reserved1             14     2  [u8; 2]    must be zero
size                  16     8  u64 LE     artifact size in bytes
hash                  24    32  [u8; 32]   full-artifact hash
reserved2             56    72  [u8; 72]   must be zero; reserved for
                                           Merkle root, chunk size,
                                           signature subscope, etc.
────────────────  ──────  ────  ─────────
                        128 bytes total
```

Compile-time assertion: `size_of::<ArtifactEntry>() == 128`.

### ArtifactManifest

In-memory:

```rust
pub struct ArtifactManifest {
    pub manifest_id: [u8; 32],   // BLAKE3 of the canonical bytes below
    pub entries: Vec<ArtifactEntry>,
    pub name_table: Vec<u8>,     // null-terminated UTF-8
}
```

`manifest_id` is deterministic: it is the BLAKE3 hash of the
canonical manifest bytes (entries laid out head-to-tail + name_table).

### Canonical manifest message (for signing)

```
AION-MANIFEST-v1\0                              17 bytes (domain)
entry_count                              u64     8 bytes LE
entry_0.{name_offset..=reserved2}       128 bytes
entry_1.{name_offset..=reserved2}       128 bytes
...
entry_{N-1}                             128 bytes
name_table bytes                        variable
```

A signer's attestation is always produced on this message under
the attestation domain from RFC-0021 (so the same key cannot be
reused to confuse a version signature with a manifest signature).

### Public API

```rust
// src/manifest.rs

pub const ARTIFACT_ENTRY_SIZE: usize = 128;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Blake3_256 = 1,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, AsBytes)]
pub struct ArtifactEntry { /* per layout above */ }

pub struct ArtifactManifestBuilder { /* name_table + entries accumulator */ }

impl ArtifactManifestBuilder {
    pub fn new() -> Self;
    pub fn add(&mut self, name: &str, bytes: &[u8]) -> ArtifactHandle;
    pub fn build(self) -> ArtifactManifest;
}

pub struct ArtifactManifest { /* as above */ }

impl ArtifactManifest {
    pub fn canonical_bytes(&self) -> Vec<u8>;
    pub fn manifest_hash(&self) -> [u8; 32];
    pub fn verify_artifact(&self, name: &str, bytes: &[u8]) -> Result<()>;
    pub fn verify_all(&self, fetch: impl Fn(&str) -> Option<Vec<u8>>) -> Result<()>;
    pub fn entries(&self) -> &[ArtifactEntry];
}

pub fn sign_manifest(m: &ArtifactManifest, signer: AuthorId, key: &SigningKey)
    -> SignatureEntry;
pub fn verify_manifest_signature(m: &ArtifactManifest, sig: &SignatureEntry)
    -> Result<()>;
```

### Verification semantics

`verify_artifact(name, bytes)`:
1. Look up the entry by name.
2. Check `bytes.len() == entry.size`. Mismatch → `Err`.
3. Recompute `BLAKE3(bytes)`. Constant-time compare to
   `entry.hash`. Mismatch → `Err`.
4. `Ok(())`.

`verify_manifest_signature(manifest, sig)`:
1. Build canonical manifest bytes.
2. Domain-tag with `AION-ATTESTATION-v1\0` + `signer.author_id`
   (same construction as RFC-0021).
3. Verify Ed25519 signature using `sig.public_key`.

### Examples

```rust
// Build a manifest for two artifacts
let weights = std::fs::read("model.safetensors")?;
let tokenizer = std::fs::read("tokenizer.json")?;

let mut builder = ArtifactManifestBuilder::new();
let _h1 = builder.add("model.safetensors", &weights);
let _h2 = builder.add("tokenizer.json", &tokenizer);
let manifest = builder.build();

// Sign the manifest
let signer = AuthorId::new(50_001);
let key = SigningKey::generate();
let sig = sign_manifest(&manifest, signer, &key);

// Later, in a verifier
manifest.verify_artifact("model.safetensors", &weights)?;
verify_manifest_signature(&manifest, &sig)?;
```

### Edge Cases

- **Duplicate names**: second `builder.add` with the same name
  creates a second entry; `verify_artifact` returns the first
  match. Callers that want unique names should check before adding.
- **Empty artifact** (zero bytes): allowed; `size == 0`, `hash`
  is BLAKE3-of-empty (`af1349b9…`). Verification of empty bytes
  passes.
- **Name longer than string table can address**: builder returns
  `Err(ManifestError::NameTooLong)`.
- **Zero-entry manifest**: allowed; canonical bytes have
  `entry_count = 0`, empty name_table. Still signable.

## Rationale and Alternatives

### Why BLAKE3 only for Phase A?

BLAKE3 is already the only hash in `src/crypto.rs`. Adding SHA-3
now would require a second hash primitive and a second fuzzing
campaign. The `hash_algorithm` field reserves space for future
agility; callers that need SHA-3 today can do it out-of-band and
store the SHA-3 digest in `reserved2` — ugly, but explicit.

### Why not a Merkle tree in Phase A?

A Merkle root gives you partial-verification and random-access
proofs; it's strictly more powerful than a single-hash root. It's
also one more binary tree format to specify, fuzz, and cross-verify.
Phase A is "I can sign a 500 GB model by its full-content hash";
Phase B is "I can sign a 500 GB model and verify a 4 MB slice of
it." Separate, ordered wins.

### Why not just extend VersionEntry?

`VersionEntry.rules_hash` is a 32-byte hash already, but a single
hash doesn't carry size or name, and `VersionEntry` is a fixed
152-byte struct — packing multiple artifacts into one version is
a format break. A separate manifest type keeps `VersionEntry`
unchanged and makes the artifact-signing feature opt-in.

### Why a separate canonical message domain (`AION-MANIFEST-v1`)?

The attestation domain from RFC-0021 already gives us one level
of separation (attestation vs single-signer). Manifests introduce
a *different signed object*, so they get their own inner domain
prefix within the canonical manifest bytes. An attacker who holds
an attestation signature over a version cannot replay it as a
manifest signature — the inner content bytes differ, and the
inner domain prefix differs.

## Security Considerations

### Threat Model

1. **Artifact substitution**: attacker replaces the 500 GB model
   with a Trojaned one. Blocked — the manifest's hash no longer
   matches the on-disk bytes.
2. **Manifest tampering**: attacker edits the manifest to point
   to their Trojan's hash. Blocked — the signature over the
   manifest no longer verifies.
3. **Entry swap**: attacker swaps two entries' hashes. Detected —
   `verify_artifact("model.safetensors", …)` sees the wrong hash
   for that name; the full-manifest signature also breaks.
4. **Length extension**: N/A — BLAKE3 is not vulnerable.
5. **Cross-protocol**: see above.

### Security Guarantees

- **Content binding**: for every `(name, size, hash)` in a verified
  manifest, the associated bytes are exactly those that existed at
  sign time.
- **Signer binding**: `verify_manifest_signature` proves the signer
  identified by `signature.author_id` signed the exact manifest
  bytes.

## Performance Impact

- **Building**: O(total_bytes) BLAKE3 — roughly 1-3 GB/s per core
  on modern x86-64. A 500 GB model hashes in ~3 minutes
  single-threaded.
- **Verifying**: identical. Phase B will add partial verification.
- **Canonical bytes**: N × 128 + name_table_len + 25. For 100
  artifacts with 32-byte names, ~16 KB.

## Testing Strategy

### Property-Based Tests (Hegel, Tier-2)

Added to `.claude/rules/property-testing.md`:

- `prop_manifest_build_verify_roundtrip`: for any list of
  (name, bytes), `verify_artifact(name, bytes)` is `Ok` for every
  entry.
- `prop_manifest_size_mismatch_rejects`: truncating or padding
  the artifact bytes causes `verify_artifact` to fail.
- `prop_manifest_byte_flip_rejects`: flipping any single byte in
  the artifact causes `verify_artifact` to fail.
- `prop_manifest_entry_swap_detected`: swapping two entries'
  hashes and then attempting `verify_artifact` under the original
  name fails for at least one artifact.
- `prop_manifest_sign_verify_roundtrip`: `sign_manifest` →
  `verify_manifest_signature` is `Ok`.
- `prop_manifest_sig_rejects_after_mutation`: tampering any entry
  in the manifest causes `verify_manifest_signature` to fail.

### Unit Tests

- Zero-entry manifest: canonical bytes correct, hash of empty
  manifest is deterministic.
- Duplicate names: both entries present; `verify_artifact` returns
  first-match semantics.
- Cross-version: attestation produced for manifest M1 does not
  verify for manifest M2.

## Implementation Plan

### Phase A (this PR)

1. New `src/manifest.rs` with `ArtifactEntry`, `ArtifactManifest`,
   `ArtifactManifestBuilder`, verify, sign/verify.
2. `pub mod manifest;` in `src/lib.rs`.
3. Property tests per above, all placed in
   `src/manifest.rs::tests::properties`.
4. Tier-2 floor updated in `.claude/rules/property-testing.md` and
   `/hegel-audit`.

### Phase B (future)

1. On-disk format bump: `AionFile` gains `manifest_entries` and
   `manifest_name_table` sections; file format version → 3; fuzz
   target extended.
2. CLI: `aion manifest add --name X --path Y`, `aion manifest verify`,
   `aion manifest sign`.
3. Merkle-tree / Bao-style partial verification.
4. SLSA v1.1 provenance emitter bound to the manifest
   (RFC-0023).
5. AIBOM / SPDX 3.0 AI export (RFC-0024).

## Open Questions

1. Should `ArtifactManifest` be lifetime-generic (`<'a>`) to enable
   zero-copy verification like `AionParser`? Phase A answer: no —
   keep it owning for simplicity; revisit in Phase B.
2. Should the name_table live in the existing `StringTable`
   infrastructure? Phase A answer: for isolation, keep it local;
   if Phase B embeds the manifest in the `.aion` file, we'll
   merge the string tables at that point.

## References

- RFC-0002 — Binary File Format (on-disk layout conventions
  inherited here).
- RFC-0014 — Multi-Signature Support.
- RFC-0021 — Multi-Signature Attestation (errata; canonical
  attestation message construction used here).
- BLAKE3 spec: <https://github.com/BLAKE3-team/BLAKE3-specs>.
- Sigstore / cosign model-signing thread (prior art).
- SLSA v1.1 provenance schema (future Phase B alignment).
