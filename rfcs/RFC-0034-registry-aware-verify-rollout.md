# RFC 0034: Registry-aware verify rollout (RFC-0028 Phase C)

- **Author:** aion-context maintainers
- **Status:** DRAFT
- **Created:** 2026-04-24
- **Updated:** 2026-04-24

## Abstract

RFC-0028 Phase A introduced a two-tier key registry
(`KeyRegistry` + epoch model) and two registry-aware verifiers in
`signature_chain`: `verify_signature_with_registry` and
`verify_attestation_with_registry`. Every **other** `verify_*`
entry point in the crate still takes its verifying key from the
raw `signature.public_key` bytes on the wire, not from a pinned
registry — that covers `manifest::verify_manifest_signature`,
`release::SignedRelease::verify`, `hw_attestation` binding
verification, and (indirectly) the manifest-linkage checks inside
`SignedRelease`. This RFC proposes Phase C: a uniform
`_with_registry` rollout across those entry points with a
migration path that neither breaks existing callers nor ambiguously
"sometimes trusts the wire, sometimes pins."

## Motivation

### Problem Statement

The crypto-auditor findings on PR #1 (Findings 1 and 3) are
correct: an adversary who controls any Ed25519 key *of the valid
shape* can:

1. Produce a `SignatureEntry` with a chosen `author_id` and a
   `public_key` of their own minting.
2. Submit a bit-perfect-valid signature under that minted key.
3. Have the existing verifiers succeed.

The only thing that today stops this from being a silent takeover
is that the **application layer** upstream of `verify_*` is
expected to have pinned the right public key. That's a contract
the type system doesn't enforce, and the one failure mode the
crypto-auditor rule set is designed to prevent:

> **Author binding.** Signatures verify against a pinned
> `HashMap<AuthorId, VerifyingKey>`. Unknown authors are rejected
> **before** signature verification runs — otherwise a malformed
> signature from an unknown author still burns a verify cycle.
> (`.claude/rules/crypto.md`)

RFC-0028 Phase A gave us the mechanism. Phase C closes the gap
for every other verify path.

### Use Cases

- A federated `.aion` consumer receives a manifest-signed artifact
  set from one of several known trusted publishers. The consumer
  pins each publisher's `AuthorId → active VerifyingKey`
  registry-side; verification must reject artifacts signed by an
  `AuthorId` it knows but with a key not in the registry, and
  reject `AuthorId`s it doesn't know at all.
- A SLSA-style release pipeline rotates its signing key on a
  schedule (RFC-0028). A `SignedRelease::verify` call 18 months
  later must resolve the signature's `(author, version)` against
  the right epoch, and reject signatures from the prior,
  rotated-out key even if the bytes are shaped correctly.
- A TEE-attested key registration (RFC-0026) binds a
  provisioning-time public key to a master authority. Later
  signature checks must re-confirm that binding via the registry,
  not via whatever public key a later attacker can stuff into a
  signature blob.

### Goals

- Every public `verify_*` entry point that currently takes
  `signature.public_key` as authoritative gets a sibling
  `verify_*_with_registry` variant.
- A single, consistent call shape:
  `fn verify_X_with_registry(artifact, signature, registry, at_version) -> Result<()>`.
- `SignedRelease::verify` accepts an optional registry. When
  `Some`, every sub-verify uses the registry path; when `None`,
  the current "trust the pinning layer upstream" behaviour holds,
  documented as such.
- Zero format changes on disk. No `.aion` version bump. Registry
  content is still caller-supplied.

### Non-Goals

- **No new crypto primitives.** All new code calls existing
  `key_registry` + `signature_chain` helpers.
- **No deprecation of the raw-key paths in this RFC.** The
  deprecation policy is an Open Question the RFC resolves in one
  direction only once Phase C has been in production at least
  one release.
- **No change to multi-party attestation verification.**
  `multisig::verify_multisig` already delegates to
  `verify_attestation`; registry-awareness there is a trivial
  follow-up once this RFC lands.
- **No registry embedding in `.aion` files.** That's RFC-0028
  Phase B.

## Proposal

### Overview

Introduce five new public functions, each a thin registry-aware
wrapper over an existing verifier. Add one new method on
`SignedRelease`. Land behind `#[must_use]` and explicit
documentation that raw-key callers are trusting their own
out-of-band pinning.

### New surface

```rust
// src/manifest.rs
pub fn verify_manifest_signature_with_registry(
    manifest: &ArtifactManifest,
    signature: &SignatureEntry,
    registry: &KeyRegistry,
    at_version: u64,
) -> Result<()>;

// src/dsse.rs
pub fn verify_envelope_with_registry(
    envelope: &DsseEnvelope,
    registry: &KeyRegistry,
    at_version: u64,
) -> Result<Vec<String>>;

// src/hw_attestation.rs
pub fn verify_binding_with_registry(
    binding: &KeyAttestationBinding,
    registry: &KeyRegistry,
    at_version: u64,
    evidence_verifier: &dyn EvidenceVerifier,
) -> Result<()>;

// src/release.rs
impl SignedRelease {
    pub fn verify_with_registry(
        &self,
        registry: &KeyRegistry,
    ) -> Result<()>;
}

// src/multisig.rs
pub fn verify_multisig_with_registry(
    version: &VersionEntry,
    signatures: &[SignatureEntry],
    policy: &MultiSigPolicy,
    registry: &KeyRegistry,
) -> Result<MultiSigVerification>;
```

### Algorithm, per verifier

For every `_with_registry` entry point:

1. Read the signer identity from the artifact (not from the
   signature): `signer = signature.author_id` for
   manifest/envelope, `signer = binding.author_id` for hardware
   binding, `signer = signatures[i].author_id` for multisig.
2. Look up `registry.active_epoch_at(signer, at_version)`.
   `None` → `Err(SignatureVerificationFailed { version, author })`
   (sanitized; no epoch detail — consistent with RFC-0033 C10).
3. Compare `signature.public_key == epoch.public_key` by byte
   equality. Mismatch → same sanitized error.
4. Only then call the existing raw-key verifier
   (`verify_signature`, `verify_attestation`,
   `verify_manifest_signature`, etc.) to confirm the signature
   bytes.

This is the same four-step pattern already used by
`verify_signature_with_registry` in `signature_chain.rs`. Phase C
does not invent new semantics; it replicates the proven one.

### `SignedRelease::verify_with_registry`

`SignedRelease` currently bundles: the DSSE manifest envelope, the
AIBOM envelope, the SLSA envelope, the OCI primary + attestation
manifests, and the transparency-log entries. Its existing
`verify()` method walks these in four internal steps
(`verify_dsse_envelopes`, `verify_aibom_manifest_linkage`,
`verify_oci_linkage`, `verify_log_entry_kinds`). Phase C adds a
top-level `verify_with_registry(&KeyRegistry)` that routes each
DSSE verify through `verify_envelope_with_registry` at the
release's `release_version`. The linkage checks (OCI referrer
subjects, AIBOM model hash vs manifest primary) are byte-equality
checks; they are unchanged.

### Backward compatibility

All existing `verify_*` functions **remain**. The new ones live
alongside them. A caller that doesn't have a registry keeps
calling the old API and retains the "trust your pinning layer"
semantics — a doc-comment warning flags the contract:

```rust
/// Verifies a manifest signature against the public key carried in
/// `signature`. If you maintain a pinned registry of active keys
/// per [`AuthorId`], prefer [`verify_manifest_signature_with_registry`]
/// — the raw-key form here trusts the caller's out-of-band pinning
/// layer to have validated the public key bytes first.
pub fn verify_manifest_signature(...);
```

### Edge cases

- **Empty registry**: `active_epoch_at` returns `None` for the
  signer → sanitized failure. Callers must populate the registry
  before invoking the `_with_registry` verifier. This is
  intentional — an empty registry is never a valid
  post-initialization state.
- **`at_version = 0`**: resolves to the first registered epoch if
  one exists, else `None`. This maps to the RFC-0028
  `effective_from_version` semantics; no new edge case.
- **DSSE multi-signer with mixed registry results**: a single
  keyid not present in the registry now fails the whole
  envelope, matching the RFC-0033 C6 dedup semantics: an envelope
  is verified iff **every** signature in it verifies.
- **Hybrid signatures (RFC-0027)**: out of scope for this RFC.
  `HybridVerifyingKey::verify` already pins its PQ public key
  by construction; adding a `_with_registry` variant waits on
  Phase B embedding the PQ public key in the registry.

## Rationale and Alternatives

### Why parallel `_with_registry` functions over replacing the originals?

Replacing the originals is a breaking API change that forces
every caller — including downstream crates, examples, and tests —
to produce a `KeyRegistry`. That's the right end state, but it's
a 1.0 decision. Phase C is a 0.x rollout: the `_with_registry`
variants get exercised, property-tested, and benchmarked in
parallel; a later minor-release deprecation marks the raw-key
variants; a subsequent major release removes them. This RFC
commits only to Step 1 of that sequence.

### Why not just require a registry at `AionParser::new`?

`AionParser` is a zero-copy parser. The registry is a
caller-owned, mutable pinning artifact. Coupling them in the
parser type would force every read path — including pure-parsing
inspection tools that do not verify — to allocate a registry.
Separating parsing from verification preserves the current
ownership story. (Tolnay-style: make the easy thing easy, the
right thing possible; here "parse without verifying" is an easy
thing some callers legitimately need.)

### Why not accept `Option<&KeyRegistry>` in the existing verifiers?

Considered and rejected. `Option` as an API-level pinning mode
invites call sites that pass `None` out of convenience and lose
the safety of the feature. Two distinct functions force every
caller to name the mode explicitly in code review.

### Alternatives considered

1. **Make `signature.public_key` a derived field computed from
   the registry at verify time.** Rejected: the field is on the
   wire; callers without a registry (the raw-key path) still need
   the bytes. Keeping it in the struct is simpler than conditional
   derivation.
2. **Change every wire format to remove `public_key` entirely
   and always require registry lookup.** Rejected: hard break of
   the RFC-0002 `SignatureEntry` format; a 2→3 format bump is not
   warranted for an incremental safety improvement.
3. **Add a "mode" enum parameter on existing verifiers.**
   Rejected: same hazard as `Option` + API noise.

## Security Considerations

### Threat Model

**In scope**:

- Adversary with a valid-shaped Ed25519 keypair (public + private)
  who wants to sign under a target `AuthorId` they do not control.
- Adversary who replays a signature from an
  already-rotated-out-or-revoked key.
- Adversary who tampers with `signature.public_key` to point to
  their own key.

**Out of scope** (addressed by other RFCs):

- Adversary who steals an active private key (registry cannot
  protect — key rotation is the response; RFC-0028 Phase B CLI).
- Adversary who compromises the registry itself (the registry is
  signed by the master key; RFC-0028's two-tier model).

### Attack vectors

| Vector                                      | Pre-Phase-C | Post-Phase-C                         |
|---------------------------------------------|-------------|--------------------------------------|
| Substitute `public_key` in a `SignatureEntry` | Succeeds if caller didn't pin | Rejected at the equality check (step 3) |
| Sign with rotated-out key at post-rotation version | Succeeds if caller didn't re-resolve | Rejected at the epoch lookup (step 2) |
| Sign with revoked key                       | Succeeds if caller didn't check revocation | Rejected at the epoch lookup (step 2) |
| Sign with unknown `AuthorId`                | Wastes a verify cycle on untrusted material | Rejected at the epoch lookup (step 2) — short-circuit the verify |

### Security Guarantees

- Any `_with_registry` verifier that returns `Ok(())` has
  confirmed: (a) the signer is in the registry, (b) the active
  epoch at `at_version` holds the exact public-key bytes carried
  on the wire, (c) the signature verifies under those bytes.
- Any `_with_registry` verifier that returns `Err(_)` returns the
  sanitized `SignatureVerificationFailed { version, author }`
  variant. No epoch number or internal-state detail leaks through
  the error path (RFC-0033 C10 precedent).

## Performance Impact

- **Time**: one `HashMap` lookup + one 32-byte byte equality +
  the existing Ed25519 verify (~50 µs on modern hardware). The
  overhead is negligible compared to the Ed25519 verify cost.
- **Space**: no new allocations in the happy path. Error path
  allocates a small sanitized error struct.
- **Benchmarks**: add a criterion bench `verify_with_registry_vs_raw`
  under `benches/crypto.rs` to confirm the overhead stays in the
  noise floor.

## Testing Strategy

### Property-Based Tests (Hegel, Tier-2)

Add to `.claude/rules/property-testing.md` Tier 2:

| Module                | Required Tier-2 property                                                  |
|-----------------------|---------------------------------------------------------------------------|
| `src/manifest.rs`     | registry verify accepts signature produced by active-epoch key            |
| `src/manifest.rs`     | registry verify rejects signature from rotated-out key at post-rotation version |
| `src/manifest.rs`     | registry verify rejects `public_key` substitution                         |
| `src/dsse.rs`         | envelope registry verify accepts every signer present in registry         |
| `src/dsse.rs`         | envelope registry verify rejects signer not in registry                   |
| `src/dsse.rs`         | envelope registry verify rejects revoked signer                           |
| `src/release.rs`      | `SignedRelease::verify_with_registry` accepts a fresh registry-pinned release |
| `src/release.rs`      | `SignedRelease::verify_with_registry` rejects after rotation if signer pre-rotation |
| `src/hw_attestation.rs` | registry verify accepts a freshly-bound key                             |
| `src/hw_attestation.rs` | registry verify rejects after master-key rotation ambiguous case       |

All properties follow the RFC-0028 Phase A testing shape: a seed
registry with one or two rotations, a signature, flip one variable
(active epoch / signer identity / `public_key` bytes), assert the
expected verdict.

### Integration Tests

One end-to-end test per entry point under `tests/`:

- `tests/rfc_0034_manifest_registry_verify.rs`
- `tests/rfc_0034_release_registry_verify.rs`
- `tests/rfc_0034_dsse_registry_verify.rs`

These exercise realistic call patterns a downstream consumer
would use: build a registry, rotate once, sign under the old and
new keys, verify both under `_with_registry` at the corresponding
versions.

### Property-test tier update

`/hegel-audit` must register the new properties as Tier-2 floor
entries so a regression drops the floor and blocks
`/quality-gate`.

## Implementation Plan

### Phase C (this RFC, one PR)

1. `verify_manifest_signature_with_registry` in `src/manifest.rs`.
2. `verify_envelope_with_registry` in `src/dsse.rs`.
3. `verify_binding_with_registry` in `src/hw_attestation.rs`.
4. `verify_multisig_with_registry` in `src/multisig.rs`.
5. `SignedRelease::verify_with_registry` in `src/release.rs`.
6. Property tests + integration tests per the Testing Strategy.
7. Update `.claude/rules/property-testing.md` Tier-2 floor.
8. Bench `verify_with_registry_vs_raw`.

### Phase D (follow-up RFC, separate PR)

1. Mark all raw-key `verify_*` functions `#[deprecated(since =
   "0.X", note = "use verify_*_with_registry; RFC-0034")]`.
2. Migrate in-crate doctests, examples, and CLI to the
   `_with_registry` path.
3. Release note: migration guide for downstream crates.

### Phase E (0.Y or 1.0)

1. Remove raw-key `verify_*` functions.
2. Rename `verify_*_with_registry` to the short form.

## Open Questions

1. **Default registry for test helpers.** Should
   `aion_context::test_helpers` ship a "trust-everything"
   registry implementation gated behind `#[cfg(test)]` so the
   migration in Phase D doesn't break every sibling crate's test
   suite? Leaning yes; needs a separate `TestRegistry` newtype so
   it can never accidentally appear in production code.
2. **Multi-crate impact.** Downstream consumers of `aion-context`
   (none today, but the RFC is forward-looking) will need to
   build registries. What's the minimum-viable registry shape we
   should document for them? Probably the
   `HashMap<AuthorId, VerifyingKey>` tutorial plus a short note
   that rotation and revocation are opt-in extensions.
3. **`verify_attestation_with_registry` is already the public
   surface**. Should we rename it in Phase E to match
   `verify_envelope_with_registry` etc.? A small API-polish
   question; out of scope here.
4. **CLI `aion verify --registry=<path>`** — a natural follow-up
   for the CLI binary once Phase C lands. Separate RFC unless the
   Phase C PR lands it as a convenience flag.

## References

- RFC-0021 — multi-signature attestation
- RFC-0022 — external-artifact manifest
- RFC-0023 — DSSE envelope
- RFC-0026 — hardware attestation
- RFC-0028 — key rotation + revocation (Phase A / B)
- RFC-0032 — release orchestration
- RFC-0033 — post-audit carryovers (§ C4)
- `.claude/rules/crypto.md` — author-binding rule
- `.claude/rules/property-testing.md` — Tier-2 floor

## Appendix

### Terminology

- **Registry-aware verifier**: a `verify_*` function that consults
  a `KeyRegistry` for the signer's active epoch before verifying
  signature bytes.
- **Raw-key verifier**: a `verify_*` function that takes the
  verifying key from the `SignatureEntry` on the wire. Retained
  through Phase D for callers with their own pinning layer.
- **Epoch**: a single (active_from_version, public_key) record
  inside the registry for one signer. RFC-0028 §Epoch lifecycle.
- **Pinning**: establishing that a given `AuthorId` maps to a
  specific `VerifyingKey` at a given `version_number`. Pinning
  can live in the caller (out-of-band) or in the registry
  (in-band); Phase C moves the crypto surface to prefer the
  latter.
