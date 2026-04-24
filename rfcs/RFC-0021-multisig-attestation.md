# RFC 0021: Multi-Signature Attestation — Canonical Message and Errata to RFC-0014

- **Author:** Crypto Protocol Maintainer
- **Status:** DRAFT
- **Created:** 2026-04-23
- **Updated:** 2026-04-23
- **Supersedes:** RFC-0014 §"Creating Multi-Signature Proposals" (clarifies; does not replace)

## Abstract

RFC-0014 specifies that multiple distinct signers can collectively
authorize a version via an M-of-N threshold policy. The current
implementation of `verify_signature` in `src/signature_chain.rs`
enforces `version.author_id == signature.author_id`, which makes true
multi-party attestation impossible — every signature has to claim to
be from the version's author. `verify_multisig` inherits this flaw,
and additionally does not deduplicate signers, so K signatures from
the same author currently satisfy a K-of-N policy.

This RFC closes both gaps with:

1. A canonical **attestation** message format that binds a signature
   to a `(version, signer)` pair under a distinct domain separator,
   so each signer's message is unique and unforgeable for any other
   signer.
2. A new public API pair — `sign_attestation` / `verify_attestation`
   — that is used by `verify_multisig`.
3. A dedup rule: a given `AuthorId` contributes at most one
   signature toward the threshold, regardless of how many sig entries
   the caller provides.

The existing `sign_version` / `verify_signature` single-signer path
is preserved unchanged for backward compatibility.

## Motivation

### Problem Statement

RFC-0014 §"Multi-Signature Architecture" describes a workflow where
a proposer creates a version and additional approvers add
signatures. Each approver is a **distinct** `AuthorId` with a
distinct signing key. In the current implementation:

```rust
// src/signature_chain.rs
pub fn verify_signature(version, signature) -> Result<()> {
    if version.author_id != signature.author_id {
        return Err(SignatureVerificationFailed { ... });
    }
    // ...
}
```

This is correct for single-signer attribution (an author cannot
claim a version wasn't signed by them if it was), but it is wrong
for multi-party attestation: approver B signing version V where
`V.author_id == A` fails at this check before the signature bytes
are even looked at.

The Hegel Tier-2 property `prop_quorum_satisfied_accepts` only
passes today because it submits **duplicate** signatures from a
single signer. `verify_multisig` then counts each copy toward the
threshold, which is a second bug: the policy's intent is "M of N
**distinct** signers."

### Use Cases

Same as RFC-0014: SOX dual approval, HIPAA multi-party change
control, regulated AI model release gates (new since RFC-0014:
EU AI Act Article 16 high-risk-system governance).

### Goals

- Enable true M-of-N attestation by distinct signers.
- Preserve the single-signer threat model of `verify_signature`.
- Provide domain separation so an attestation signature cannot be
  replayed as a single-signer version signature.
- Make the fix observable via property tests before the room asks.

### Non-Goals

- Transparency log / Rekor integration (future RFC).
- Key rotation or revocation (future RFC).
- Asynchronous proposal workflow (RFC-0014 §"Pending Versions"
  still pending implementation; orthogonal).

## Proposal

### Canonical Attestation Message

```
AION-ATTESTATION-v1\0                          20 bytes (domain separator)
version_number                          u64     8 bytes LE
parent_hash                             [u8;32] 32 bytes
rules_hash                              [u8;32] 32 bytes
version.author_id                       u64     8 bytes LE
timestamp                               u64     8 bytes LE
message_offset                          u64     8 bytes LE
message_length                          u32     4 bytes LE
signer.author_id                        u64     8 bytes LE
                                        ───────
                                        128 bytes (plus 20-byte prefix)
```

The message includes **both** the version author's id (as metadata
about the version being attested) **and** the signer's id. The
domain separator ensures this message cannot collide with the
existing `AION-SIG-v1\0` single-signer message.

### Public API

```rust
// src/signature_chain.rs

/// Build the canonical attestation message for (version, signer).
pub fn canonical_attestation_message(
    version: &VersionEntry,
    signer: AuthorId,
) -> Vec<u8>;

/// Produce an attestation — a signature by `signer` over `version`.
#[must_use]
pub fn sign_attestation(
    version: &VersionEntry,
    signer: AuthorId,
    signing_key: &SigningKey,
) -> SignatureEntry;

/// Verify an attestation against its version. No author-id equality
/// constraint — the signer's id comes from the signature entry.
pub fn verify_attestation(
    version: &VersionEntry,
    signature: &SignatureEntry,
) -> Result<()>;
```

`verify_attestation` uses `signature.author_id` as the `signer` in
`canonical_attestation_message`, so a forged signature claiming to
be from a different signer cannot verify (the message bytes don't
match what was signed).

### Multisig dedup

`verify_multisig` is updated to:

1. Switch from `verify_signature` → `verify_attestation`.
2. Track a `HashSet<AuthorId>` of signers already seen in this
   verification call.
3. Skip any signature whose `author_id` is already in the set
   (neither count it as valid nor as invalid — duplicates are a
   caller bug, not a policy violation).

### Examples

```rust
let version = create_genesis_version(rules_hash, author, ts, 0, 0);
let signers: Vec<(AuthorId, SigningKey)> = (0..3)
    .map(|i| (AuthorId::new(100 + i), SigningKey::generate()))
    .collect();
let attestations: Vec<SignatureEntry> = signers
    .iter()
    .take(2)
    .map(|(who, key)| sign_attestation(&version, *who, key))
    .collect();
let policy = MultiSigPolicy::new(2, signers.iter().map(|(a, _)| *a).collect())?;
let result = verify_multisig(&version, &attestations, &policy)?;
assert!(result.threshold_met);
assert_eq!(result.valid_count, 2);
```

### Edge Cases

- **Same signer signs twice**: counted once toward threshold. If the
  policy is 2-of-3, a signer submitting two of their own sigs still
  needs a second distinct signer.
- **Signer not in authorized list**: skipped before verification,
  same as today.
- **Signer is also the version author**: allowed; `signer.author_id
  == version.author_id` is not a collision because the domain
  separator and signer-id suffix still distinguish the message from
  a single-signer `sign_version` signature.
- **Zero signatures against 1-of-N policy**: `valid_count == 0`,
  `threshold_met == false`.

## Rationale and Alternatives

### Why a separate attestation path?

Alternative A: relax `verify_signature` to drop the author-id check.
Rejected — that weakens the single-signer guarantee. A malicious
caller could then strip an author's signature and re-attribute it.

Alternative B: overload `verify_signature` with a policy parameter.
Rejected — makes the single-signer path more complex for the
majority of callers who don't need multisig.

Alternative C (chosen): two distinct top-level functions with
distinct domain separators. Each call site opts into the semantics
it needs. Clear, testable, minimal change to existing callers.

### Why include version.author_id in the attestation message?

The attester is vouching for a specific version authored by a
specific party. Omitting `version.author_id` would let the same
attestation cover a new version with the same content but a
different author — undesirable. Including it binds the attestation
to the full version identity.

### Why dedup in the verifier and not require it at the storage layer?

The storage layer can't enforce dedup without re-running the policy
check. Dedup at verify time is the narrow waist.

## Security Considerations

### Threat Model

1. **Impersonation**: an attacker with signer X's public key but
   not the private key tries to forge an attestation. Blocked by
   Ed25519 unforgeability over a message bound to (version, signer).
2. **Replay across signers**: signer A's attestation over V1 is
   copied and re-used with `author_id` changed to B. Blocked — the
   message bytes include `signer.author_id`, so the signature won't
   verify under B's reconstructed message.
3. **Replay across versions**: signer A's attestation over V1 is
   re-applied to V2 (same author, same content, different version
   number). Blocked — `version_number` and other version fields are
   in the signed message.
4. **Cross-protocol attack**: forcing a single-signer signature to
   count as an attestation or vice-versa. Blocked by the domain
   separators `AION-SIG-v1\0` vs `AION-ATTESTATION-v1\0`.
5. **Ballot-stuffing by a single signer**: submitting K copies of
   the same signer's attestation to satisfy a K-of-N policy. Blocked
   by the dedup rule.

### Security Guarantees

- **Attester authenticity**: a verifying attestation proves the
  `signer` identified by `signature.author_id` signed the exact
  (version, signer) tuple.
- **Non-repudiation**: the signer cannot later deny signing the
  attestation without repudiating the Ed25519 key binding.
- **Policy integrity**: with dedup, `valid_count` equals the number
  of distinct authorized signers who produced valid attestations.

## Performance Impact

- **Time**: same per-signature cost as `verify_signature` (one
  Ed25519 verify). Dedup adds O(K) hash-set inserts per
  `verify_multisig` call where K is the number of submitted sigs.
- **Space**: a `HashSet<AuthorId>` of at most K entries during
  verification; dropped on return. No on-disk impact — the
  `SignatureEntry` byte layout is unchanged.

## Testing Strategy

### Property-Based Tests (Hegel, Tier-2)

All additions to `.claude/rules/property-testing.md` Tier-2:

- `prop_attestation_roundtrip`: for any (version, signer, key),
  `sign_attestation` → `verify_attestation` is `Ok`.
- `prop_attestation_rejects_wrong_signer`: tampering
  `signature.author_id` after signing → `verify_attestation` fails.
- `prop_attestation_rejects_wrong_version`: attestation bound to V1
  applied to V2 with differing fields → `verify_attestation` fails.
- `prop_multisig_k_distinct_signers_accepts`: K distinct authorized
  signers each attest with their own key → `threshold_met` AND
  `valid_count == K`.
- `prop_multisig_kminus1_distinct_rejects`: K-1 distinct attestations
  against K-of-N policy → NOT `threshold_met`.
- `prop_multisig_duplicate_attestations_count_once`: N attestations
  all from the same signer against a K-of-M policy where K ≥ 2 →
  NOT `threshold_met`.
- (Kept) `prop_unauthorized_signers_do_not_count`.

### Negative tests that would have failed before the fix

- `prop_multisig_k_distinct_signers_accepts` — impossible with the
  old `verify_signature` author-id check; passes after the fix.
- `prop_multisig_duplicate_attestations_count_once` — currently fails
  (duplicates count), passes after dedup.

## Implementation Plan

### Phase 1 (this PR)

- Add `ATTESTATION_DOMAIN` constant.
- Add `canonical_attestation_message`, `sign_attestation`,
  `verify_attestation` to `src/signature_chain.rs`.
- Switch `verify_multisig` in `src/multisig.rs` to use
  `verify_attestation` and dedup via `HashSet`.
- Replace the three existing Tier-2 multisig properties with the
  seven listed above.
- Update `.claude/rules/property-testing.md` Tier-2 floor +
  `/hegel-audit` table.

### Phase 2 (follow-up RFC)

- Pending-version storage and asynchronous approval workflow from
  RFC-0014 §"Creating Multi-Signature Proposals" is still not
  implemented; that stays on the queue.
- Transparency-log integration for attestations (Sigstore/Rekor).

## Open Questions

1. Should `verify_multisig` also return the set of **distinct**
   signers rather than just `valid_count`? Current plan: yes —
   `valid_signers: Vec<AuthorId>` already exists; dedup naturally
   makes it distinct.

## References

- RFC-0014 — Multi-Signature Support (original spec; this RFC is
  errata + concrete canonical message).
- Hegel Tier-2 property-testing rule:
  `.claude/rules/property-testing.md`.
- BIP-340 domain separator pattern (prior art for domain-tagged
  signatures).

## Appendix

### Terminology

- **Signer / Attester**: an `AuthorId` with an Ed25519 keypair who
  provides an attestation over a version.
- **Version author**: the `AuthorId` stored in `VersionEntry.author_id`
  — the party who *proposed* the version; distinct from attesters.
- **Attestation**: a `SignatureEntry` produced by `sign_attestation`.
- **Single-signer signature**: a `SignatureEntry` produced by
  `sign_version`. Domain-separated from attestations.
