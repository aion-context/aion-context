# RFC 0028: Key Rotation and Revocation Protocol

- **Author:** aion-context maintainers
- **Status:** DRAFT
- **Created:** 2026-04-23
- **Updated:** 2026-04-23
- **Depends on:** RFC-0014 (multi-signature), RFC-0021 (attestation)

## Abstract

Today `aion-context` has no protocol-level answer to key compromise:
every `SigningKey` is freestanding, there is no notion of a
"current" versus "past" key for an author, and a verifier has no way
to declare that signatures made by a specific key after some version
must be rejected. In the NVIDIA/Microsoft room this is the first
follow-up to the multisig question — "what happens when a signing
key leaks?"

This RFC adds a **two-tier key protocol**:

- Each author has a long-lived **master key** (rotated rarely,
  guarded carefully).
- Each author has a sequence of **operational keys** — the keys
  that actually sign versions and attestations. Operational keys
  can be rotated frequently and revoked individually.

Rotation and revocation are expressed as **records** signed by the
master key. A [`KeyRegistry`] tracks every author's epoch sequence
and, given `(author, version_number)`, returns the operational key
that was active at sign time. Verification routes through
`verify_signature_with_registry` / `verify_attestation_with_registry`
which check the signature's embedded public key against the
registered active epoch *before* doing the Ed25519 verify.

No on-disk file format change in this RFC. Phase B embeds the
registry in the `.aion` file and bumps the format version.

## Motivation

### Problem Statement

Compromise is not hypothetical. HSMs get stolen, laptops get
phished, insiders go rogue, CI secrets leak. A governance format
that can't answer "what do we do when the key is bad?" is not a
governance format. Specific gaps today:

1. No way for an author to *declare* that their old key is no
   longer trusted.
2. No way to *bind* a signature to a specific key epoch, so
   verifiers can't distinguish "signed before compromise" from
   "signed by the attacker after compromise."
3. No way for an auditor to reconstruct the history of key changes
   in an organization.

### Use Cases

- **Routine rotation**: author rotates operational key every 90
  days per org policy; all prior signatures remain valid; new
  signatures must use the new key.
- **Compromise response**: attacker steals operational key K_n.
  Author signs a revocation record with their master key
  declaring K_n revoked effective from version V_now. Every
  signature with version ≥ V_now under K_n is rejected.
- **Personnel turnover**: engineer leaves the org; their
  operational key is retired without successor.
- **Key ceremony**: org publishes a root of trust that anchors all
  operational keys.

### Goals

- Any signature can be located to a specific key epoch.
- A rotation or revocation takes effect at a *specific version
  number*, not a wall-clock time (wall clocks drift; version
  numbers are authoritative per the distributed-systems rule).
- Every rotation / revocation is cryptographically authorized by
  the master key — an attacker holding an operational key cannot
  rotate themselves into a different key.
- Composes with RFC-0021 attestations: multi-party approvals
  remain per-signer, and each signer's epoch is checked
  independently.
- No on-disk format break in Phase A.

### Non-Goals

- **Transparency log binding** (RFC-0025). Rotation records here
  are verified locally; publishing them to Rekor is a separate
  RFC.
- **Master-key rotation**. Tier-1 keys rotate rarely and that
  story is more involved (it's a "new root of trust" event).
  Phase B.
- **Cross-author revocation**. An org may want to revoke one
  author's key from another author's master. Out of scope.
- **Time-bound keys** (valid-from / valid-until wall-clock).
  Version numbers are authoritative; wall-clock expiry is an
  anti-pattern here.

## Proposal

### Key tiers

```
Master Key (Ed25519)          — rarely rotated, guarded by HSM/HW
  │
  │  signs
  ▼
Operational Key Epoch 1       ──┐
Operational Key Epoch 2       ──┼── signs versions, attestations
Operational Key Epoch 3       ──┘
```

Master key usage is restricted to signing *rotation records* and
*revocation records*. It never appears in a `SignatureEntry` for a
version.

### Canonical messages

Rotation-record body, signed by the master key:

```
domain || author_id || from_epoch || to_epoch || to_public_key || effective_from_version
```

- `domain = "AION_V2_ROTATION_V1"` (22 bytes, distinct from other
  domains in the crate).
- `author_id`: u64 LE (8 bytes).
- `from_epoch`, `to_epoch`: u32 LE (4 bytes each).
- `to_public_key`: 32 bytes.
- `effective_from_version`: u64 LE (8 bytes).

Revocation-record body, signed by the master key:

```
domain || author_id || revoked_epoch || reason || effective_from_version
```

- `domain = "AION_V2_REVOCATION_V1"` (24 bytes).
- `reason`: u16 LE (2 bytes).

Domain separators distinguish both from all other aion signed
objects (version signatures, attestations, manifest signatures).

### Epoch lifecycle

```
   Active  ──rotate──▶  Rotated { successor: N+1 }
   Active  ──revoke──▶  Revoked { reason, from_version }
```

- `Active` → accepted for any version at or after `created_at_version`.
- `Rotated { successor }` → accepted only for versions
  `< successor.effective_from_version`.
- `Revoked { .., from_version }` → accepted only for versions
  `< from_version`.

A rotated-then-revoked epoch (rare but legitimate, e.g. routine
rotation followed by later discovery that the rotated-out key was
always compromised) stays in the registry with a revocation overlay;
the verifier takes the most restrictive window.

### Public API

```rust
// src/key_registry.rs

#[derive(Debug, Clone)]
pub struct KeyEpoch {
    pub author_id: AuthorId,
    pub epoch: u32,
    pub public_key: [u8; 32],
    pub created_at_version: u64,
    pub status: KeyStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    Active,
    Rotated { successor_epoch: u32, effective_from_version: u64 },
    Revoked { reason: RevocationReason, effective_from_version: u64 },
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationReason {
    Compromised = 1,
    Superseded = 2,
    Retired = 3,
    Unspecified = 255,
}

#[derive(Debug, Clone)]
pub struct KeyRotationRecord {
    pub author_id: AuthorId,
    pub from_epoch: u32,
    pub to_epoch: u32,
    pub to_public_key: [u8; 32],
    pub effective_from_version: u64,
    pub master_signature: [u8; 64],
}

#[derive(Debug, Clone)]
pub struct RevocationRecord {
    pub author_id: AuthorId,
    pub revoked_epoch: u32,
    pub reason: RevocationReason,
    pub effective_from_version: u64,
    pub master_signature: [u8; 64],
}

pub struct KeyRegistry {
    // private: Vec<KeyEpoch> per author + master key per author
}

impl KeyRegistry {
    pub fn new() -> Self;

    pub fn register_author(
        &mut self,
        author: AuthorId,
        master_public_key: VerifyingKey,
        initial_operational_key: VerifyingKey,
        created_at_version: u64,
    ) -> Result<()>;

    pub fn apply_rotation(&mut self, record: &KeyRotationRecord) -> Result<()>;

    pub fn apply_revocation(&mut self, record: &RevocationRecord) -> Result<()>;

    pub fn active_epoch_at(
        &self,
        author: AuthorId,
        version_number: u64,
    ) -> Option<&KeyEpoch>;

    pub fn master_key(&self, author: AuthorId) -> Option<&VerifyingKey>;

    pub fn epochs_for(&self, author: AuthorId) -> &[KeyEpoch];
}

pub fn canonical_rotation_message(record: &KeyRotationRecord) -> Vec<u8>;

pub fn canonical_revocation_message(record: &RevocationRecord) -> Vec<u8>;

pub fn sign_rotation_record(
    author: AuthorId,
    from_epoch: u32,
    to_epoch: u32,
    to_public_key: [u8; 32],
    effective_from_version: u64,
    master_key: &SigningKey,
) -> KeyRotationRecord;

pub fn sign_revocation_record(
    author: AuthorId,
    revoked_epoch: u32,
    reason: RevocationReason,
    effective_from_version: u64,
    master_key: &SigningKey,
) -> RevocationRecord;
```

### Registry-aware verification

Added to `src/signature_chain.rs`:

```rust
pub fn verify_signature_with_registry(
    version: &VersionEntry,
    signature: &SignatureEntry,
    registry: &KeyRegistry,
) -> Result<()>;

pub fn verify_attestation_with_registry(
    version: &VersionEntry,
    signature: &SignatureEntry,
    registry: &KeyRegistry,
) -> Result<()>;
```

Both:

1. Look up the signing author (`version.author_id` for
   `verify_signature_with_registry`; `signature.author_id` for
   attestations).
2. Call `registry.active_epoch_at(signer, version.version_number)`.
3. If `None` → `Err(InvalidFormat)`.
4. If `Some(epoch)` and `signature.public_key != epoch.public_key`
   → `Err(InvalidFormat)`.
5. Otherwise delegate to the existing `verify_signature` /
   `verify_attestation`.

The existing (non-registry) verify paths stay — they're the right
tool for single-signer operations where key rotation is out of
scope (tests, fixtures, initial bootstrap).

### Edge Cases

- **Registering an author twice**: second call → `Err`.
- **Rotation record with `from_epoch` not equal to current
  active**: `Err` (rotation must come from the active key).
- **Rotation record with `to_epoch` not equal to
  `current_active.epoch + 1`**: `Err` (epochs are dense).
- **Effective-from-version earlier than the current active
  epoch's `created_at_version`**: `Err` (can't rotate into the
  past).
- **Revoking an already-rotated epoch**: allowed; takes
  additional effect for its live window.
- **Revoking an already-revoked epoch**: `Err` (redundant).
- **Rotation/revocation record with a bad master signature**:
  `Err`.
- **Master key unknown for author** (record claims author X,
  registry never saw X's master): `Err`.

## Rationale and Alternatives

### Why version-number effectivity instead of wall-clock?

Wall clocks drift, skew, and lie. The distributed-systems rule
(`.claude/rules/distributed.md`) specifies version numbers as the
authoritative ordering. A rotation that says "effective from wall
clock 2026-04-23T12:00Z" fails the first time a verifier has a
different clock; "effective from version N" is unambiguous.

### Why a two-tier model?

One-tier (single key per author) is the current state and we just
argued it's broken: no way to rotate. Three-tier (master → key-
signing-key → operational) is what TUF uses, but adds a layer of
complexity for an RFC whose goal is the minimum viable rotation
story. Two-tier matches Sigstore's model and is enough to answer
the room's question.

### Why not just use X.509 / OCSP?

Because the room's alternatives are Sigstore / in-toto / TUF, not
classic PKI. We stay lightweight and self-rooted.

### Why pin public_key bytes in verification?

`SignatureEntry` already carries `public_key: [u8; 32]`. Without
a cross-check against the registered active epoch, an attacker
with a new key could substitute their key into a signature and it
would verify cryptographically. The registry cross-check binds
the signature to the organizationally-approved epoch.

## Security Considerations

### Threat Model

1. **Operational-key compromise**: attacker exfiltrates an
   operational private key. Mitigation: owner signs a revocation
   record with the master key; all versions ≥
   `effective_from_version` under the compromised key are
   rejected.
2. **Master-key compromise**: attacker exfiltrates the master
   key and issues rotations. Mitigation out of scope for this
   RFC; future work around Tier-0 audit trails.
3. **Backdated rotation**: attacker with the master key tries to
   rotate with `effective_from_version < current_active.
   created_at_version`. Blocked — the registry rejects.
4. **Forged rotation**: attacker without the master key submits a
   rotation record. Blocked — the master-signature check fails.
5. **Key-substitution attack**: attacker swaps `signature.
   public_key` in a valid signature to their own key, then signs.
   Blocked — the registry check catches the mismatch before
   Ed25519 verify runs.
6. **Replay of rotation**: attacker resubmits a valid historical
   rotation record. Benign if already applied (idempotent no-op);
   `Err(AlreadyRotated)` otherwise.

### Security Guarantees

- **Rotation authority**: only a holder of the master private
  key can extend an author's epoch sequence.
- **Rotation atomicity**: after `apply_rotation`, every
  subsequent `verify_*_with_registry` uses the new epoch for
  `version_number >= effective_from_version`.
- **Revocation non-repudiation**: a revocation record is
  cryptographic proof from the master key that the epoch was
  revoked; auditors can reconstruct the history by replaying the
  record set.

## Performance Impact

- Per-verify cost: one O(log N) binary search over the author's
  epoch list (typically ≤ 10 epochs), one 32-byte memcmp, then
  the existing Ed25519 verify. Negligible.
- Space: per author, one `VerifyingKey` (32 bytes) + the epoch
  list (~80 bytes per epoch). Tiny.

## Testing Strategy

### Property-Based Tests (Hegel, Tier-2)

Added to `.claude/rules/property-testing.md`:

- `prop_register_and_verify_active`: register author, sign a
  version with the initial key, verify with registry — `Ok`.
- `prop_sig_before_rotation_verifies`: rotate at version V_new;
  signature at V_old < V_new with old key verifies.
- `prop_sig_after_rotation_rejects_old_key`: signature at
  V_old ≥ V_new with old key fails under registry.
- `prop_sig_after_rotation_accepts_new_key`: signature at
  V ≥ V_new with new key verifies.
- `prop_revocation_rejects_later_sigs`: revoke at V_revoke;
  signatures at V ≥ V_revoke fail; V < V_revoke succeed.
- `prop_rotation_requires_valid_master_sig`: `apply_rotation`
  with a tampered master_signature fails.
- `prop_epochs_are_monotonic`: no sequence of legal rotations
  produces non-increasing epoch numbers.
- `prop_multi_hop_rotation_tracks_correctly`: chain of 3+
  rotations; each sig at the right version with the right
  epoch's key verifies, others fail.
- `prop_unknown_author_rejects`: verify against an empty
  registry fails.
- `prop_key_substitution_detected`: valid sig with swapped
  `public_key` field fails.

### Vector Test

Hand-rolled: register (author=1, master, op0); sign version 1 with
op0; verify OK. Rotate to op1 effective at version 5; sign version
7 with op1; verify OK. Sign version 7 with op0 post-rotation; verify
fails. Revoke op1 effective at version 10; sign version 12 with op1;
verify fails.

## Implementation Plan

### Phase A (this RFC, this PR)

1. `src/key_registry.rs` with the full public API.
2. `pub mod key_registry;` in `src/lib.rs`.
3. `verify_*_with_registry` in `src/signature_chain.rs`.
4. Property tests + vector test.
5. Tier-2 floor + `/hegel-audit` update.

### Phase B

1. Embed registry in `AionFile` (format-version bump 2 → 3).
2. CLI: `aion key register`, `aion key rotate`, `aion key revoke`,
   `aion key list`.
3. Master-key rotation protocol.
4. Integration with transparency log (RFC-0025).

## Open Questions

1. Should a revoked-with-reason-`Compromised` retroactively
   invalidate earlier signatures under the same key? Default
   semantics say no (earlier signatures were authentic at sign
   time), but some compliance regimes require "poison all
   signatures forward and backward." Phase A: no retroactive
   invalidation; callers with stricter policies can override
   `effective_from_version = 0`.

## References

- RFC-0014 — Multi-signature support.
- RFC-0021 — Multi-party attestation.
- TUF (The Update Framework) — root key hierarchy.
- Sigstore Fulcio — keyless signing + short-lived certs.
- NIST SP 800-57 — key management lifecycle.

## Appendix

### Terminology

- **Epoch**: a specific operational keypair lifetime, indexed by
  a u32 per author.
- **Active epoch**: the current epoch for an author at a given
  version, determined by the registry.
- **Effective-from version**: the version number at or after which
  a rotation/revocation takes effect.
- **Master key**: the long-lived key that authorizes epoch changes;
  never signs versions or attestations directly.
