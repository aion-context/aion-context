# RFC 0038: External Version Signer

- **Author:** copyleftdev
- **Status:** ACCEPTED
- **Created:** 2026-08-09
- **Updated:** 2026-08-09
- **Depends on:** RFC-0003 (cryptography), RFC-0004 (key management),
  RFC-0005 (signature chain), RFC-0012 (versioning), RFC-0026
  (hardware attestation), RFC-0028 (key rotation and revocation),
  RFC-0034 (registry-aware verify rollout), RFC-0037 (crypto/RNG
  stack upgrade)

## Abstract

Every append to an `.aion` chain today requires the caller to hand
`aion-context` a `SigningKey` — an in-process Ed25519 private key.
That requirement is incompatible with the environments the format is
built for. An organization that keeps its policy-signing key in a
KMS, an HSM, a TPM, or a hardware token cannot use `commit_version`
without first exporting the key into process memory, which is exactly
the property those devices exist to prevent. This RFC introduces
`VersionSigner`, a narrow provider boundary carrying two methods —
"what is your public key" and "sign these exact bytes" — plus
`commit_version_with_signer` and `ExternalCommitOptions`. Private key
material never crosses the interface. Critically, the boundary is
placed so that the **core keeps every security decision**: chain
verification, registry authorization, canonical message construction,
verification of the signature the provider hands back, and the atomic
write. The provider is a signing oracle over a message it did not
choose, not a participant in artifact assembly. No new cryptography
is introduced; RFC-0005's `canonical_version_message` and
`SIGNATURE_DOMAIN` are reused byte-for-byte, so an externally signed
version is indistinguishable from a locally signed one on disk.

## Motivation

### Problem Statement

`CommitOptions` holds `signing_key: &SigningKey`. `SigningKey` wraps
`ed25519_dalek::SigningKey`, whose seed lives in this process's
address space. This forces one of three bad outcomes on any
organization with a hardware key custody policy:

1. **Export the key.** Defeats the custody control entirely, and in
   most regulated environments voids the attestation that made the
   key trustworthy in the first place. For an FIPS-validated HSM the
   key is typically non-exportable by design, so this is not merely
   unwise but impossible.
2. **Reimplement the format.** The integrator builds `VersionEntry`
   values, computes `canonical_version_message` themselves, signs
   with their HSM, and hand-assembles a `.aion` file with the
   serializer. This works and some integrators have done it, but it
   moves the domain separator, the parent-hash linkage, the
   registry-epoch check, and the atomic-write discipline into
   third-party code where `aion-context` cannot enforce any of them.
   Every such integration is a place the format's invariants can
   silently rot.
3. **Skip signing.** Not an option for a signed-artifact format.

The second outcome is the dangerous one, because it *looks* like it
works. An integrator who reimplements the assembly path gets a file
that parses and verifies today, and inherits full responsibility for
matching every future change to the canonical message. The format's
security properties become the integrator's problem, distributed
across N private codebases, with no versioned contract.

RFC-0026 already established that `aion-context` can bind a
hardware-resident key to an author through an attestation — but that
RFC binds the key's *provenance*. It says "this operational key
demonstrably lives in a TEE." It does not give the caller a way to
actually **use** that key to append to a chain without exporting it.
RFC-0026 and this RFC are the two halves of the same story:
RFC-0026 proves where the key lives, RFC-0038 lets it sign.

### Use Cases

- **KMS-backed policy release.** A platform team keeps the policy
  signing key in AWS KMS / GCP Cloud KMS / Azure Key Vault. Their
  release tool implements `VersionSigner` over the cloud SDK's
  asymmetric-sign call and commits normally. The key never leaves
  the KMS boundary; the audit trail is the cloud provider's own
  key-usage log plus the `.aion` chain.
- **HSM under a compliance mandate.** A financial institution's
  policy is that signing keys for regulated artifacts are
  non-exportable and reside in a FIPS 140-3 Level 3 HSM. The
  institution can now adopt `aion-context` without an exception
  request.
- **Air-gapped / split-process signing.** The signing key lives in a
  separate hardened process, container, or physically separate
  machine. The `VersionSigner` implementation is an IPC or serial
  transport that ships 156 bytes out and 64 bytes back. Nothing
  about the format needs to be understood on the far side.
- **Hardware token, human-in-the-loop.** A YubiKey or smartcard
  where each signature requires a physical touch. The single
  `sign_version_message` call maps to exactly one touch prompt,
  which is only true because the core calls the provider exactly
  once per commit (see Goals).
- **Composition with RFC-0026.** A TEE-resident key is bound to an
  author with `hw_attestation::verify_binding`, registered as an
  operational key in the registry (RFC-0028), and then used to sign
  through this interface. The verifier chain is complete: the key is
  attested, registered, and used, all without export.

### Goals

- Allow a commit to be signed by a key `aion-context` cannot read.
- Keep **all** trust decisions in the core. The provider receives
  bytes and returns a signature; it authorizes nothing, verifies
  nothing, and assembles nothing.
- **Exactly one** provider call per commit. Hardware signing is
  slow (network round-trip for KMS, physical touch for a token) and
  frequently metered or rate-limited. A design that signs twice, or
  signs speculatively before authorization, is a design that gets
  turned off.
- **Fail closed and fail clean.** Any provider failure, key
  mismatch, or invalid returned signature leaves the target artifact
  byte-identical to its pre-call state.
- **Identical signed material.** A version committed through an
  external signer must produce a byte-identical `VersionEntry` and
  `SignatureEntry` to the same version committed with an in-process
  key. No new field, no format-version bump, no verifier change.
  (The encrypted rules section is not byte-identical, because
  `encrypt_rules` draws a fresh random nonce per call — two
  *software* commits of the same rules differ there too. Nothing
  signed or chained depends on it.)
- Source compatibility for every existing `commit_version` call
  site.

### Non-Goals

- **Not a keystore replacement.** `src/keystore.rs` continues to
  own local encrypted key storage. This RFC does not route keystore
  operations through the trait.
- **Not a KMS/HSM adapter.** `aion-context` ships the trait, not
  implementations. Shipping a `reqwest`-based cloud adapter would
  drag provider SDKs, credentials handling, and network posture into
  a crate whose network attack surface is currently near zero. That
  belongs in a downstream crate.
- **Not async.** Consistent with `.claude/rules/concurrency.md`, the
  library stays synchronous. A provider needing async wraps the
  commit in `tokio::task::spawn_blocking`.
- **Not extended to every signing path.** Manifests (RFC-0033),
  DSSE envelopes (RFC-0023), attestations (RFC-0021), transparency
  tree heads (RFC-0025), and release seals (RFC-0032) keep taking
  `&SigningKey` for now. Version commits are the highest-value entry
  point and the one with the strictest custody requirements. See
  Unresolved Questions.
- **Not key attestation.** Whether the provider's key really lives
  in hardware is RFC-0026's question, not this one. This RFC assumes
  nothing about where the key is; it only guarantees `aion-context`
  never sees it.

## Proposal

### Overview

Two public items and one function in `src/operations.rs`:

```rust
pub trait VersionSigner {
    fn public_key(&self) -> Result<[u8; 32]>;
    fn sign_version_message(&self, canonical_message: &[u8]) -> Result<[u8; 64]>;
}

pub struct ExternalCommitOptions<'a> {
    pub author_id: AuthorId,
    pub signer: &'a dyn VersionSigner,
    pub message: &'a str,
    pub timestamp: Option<u64>,
}

pub fn commit_version_with_signer(
    path: &Path,
    new_rules: &[u8],
    options: &ExternalCommitOptions<'_>,
    registry: &crate::key_registry::KeyRegistry,
) -> Result<CommitResult>;
```

`SigningKey` implements `VersionSigner`, so the software path is not
a special case — it is the trivial implementation. `commit_version`
and `commit_version_force_unregistered` construct an
`ExternalCommitOptions` from their `CommitOptions` and delegate to
the same private `commit_version_with_signer_inner`. There is
exactly **one** commit implementation; the two public entry points
differ only in how the signer is supplied.

That collapse is the point. A separate hardware path would be a
second implementation of chain linkage, timestamping, and atomic
write, drifting from the first the moment either changes. Unifying
them means every future fix to the commit path applies to both, and
the equivalence is asserted directly by a test that commits the same
logical version through both entry points and compares the resulting
bytes field by field.

### Detailed Design

The commit sequence, in order, with the provider call marked:

1. Read and parse the existing artifact. Reject a malformed or
   truncated file.
2. Verify the existing hash chain end to end.
3. Verify the head signature against the pinned registry.
4. Compute `new_version = header.current_version + 1` (checked).
5. Ask the provider for its public key (`public_key()`).
6. **Authorization gate.** Resolve the author's active registry
   epoch at `new_version`. No active epoch ⇒
   `AionError::UnauthorizedSigner`. Epoch's pinned operational key
   not equal to the provider's key ⇒ `AionError::KeyMismatch`. The
   comparison is `subtle::ConstantTimeEq`, never `==`.
7. Encrypt the new rules, compute `rules_hash`, compute
   `parent_hash` from the current head, resolve the timestamp, and
   build the `VersionEntry`.
8. Construct `canonical_version_message(&new_version_entry)` —
   RFC-0005's exact bytes, domain separator included.
9. **→ Single provider call.** `sign_version_message(&message)`. A
   provider error propagates as `AionError::SigningFailed { reason }`
   and nothing is written.
10. Assemble the `SignatureEntry` from `(author_id, public_key,
    signature)`.
11. **Verify the provider's own output.** Run the returned signature
    through `signature_chain::verify_signature` against the registry
    — the same verification a third-party reader will perform. A
    signature that does not verify ⇒ error, nothing is written.
12. Serialize the updated artifact and write it atomically
    (write-then-rename).

Steps 6 and 11 are the two halves of the trust model, and their
ordering is deliberate. Step 6 is **before** the provider call, so
an unauthorized signer is never asked to sign — no wasted HSM
operation, no spurious touch prompt, no key-usage log entry for a
commit that was never going to be accepted. Step 11 is **after**,
because a provider is not trusted to be correct: a buggy adapter
that returns the wrong 64 bytes, signs a different message, or
returns a signature from a different key must not be able to write
a permanently unverifiable entry into an append-only chain.

Step 11 deserves emphasis. It is redundant in the software path —
`SigningKey::sign` over a message we just built with a key we just
checked cannot fail to verify — and that redundancy costs one
Ed25519 verification (~50 µs) per commit. It is retained
unconditionally because "the artifact I just wrote verifies under
the same rules a stranger will apply" is worth far more than 50 µs
on an operation that already performs file I/O and full-chain
verification. An `.aion` chain is append-only; a bad entry is not
repairable, only forkable.

### Error Model

One new variant:

```rust
#[error("Version signing failed: {reason}")]
SigningFailed { reason: String },
```

`reason` is provider-supplied and therefore the one unbounded string
on this path. Per `.claude/rules/observability.md`, it must not be
used as a `tracing` field value — it is a human-facing diagnostic
for the caller's `Err`, and the bounded discriminator for logs is
the variant itself. Provider implementations are documented to keep
it short, non-secret, and free of key material, endpoint
credentials, or request bodies.

Existing variants carry the rest: `UnauthorizedSigner` (no active
epoch), `KeyMismatch` (provider key ≠ pinned epoch key),
`SignatureVerificationFailed` / `InvalidSignature` (provider output
rejected).

### Examples

```rust
use aion_context::operations::{
    commit_version_with_signer, ExternalCommitOptions, VersionSigner,
};
use aion_context::{AionError, Result};

struct KmsSigner {
    client: KmsClient,
    key_arn: String,
    cached_public_key: [u8; 32],
}

impl VersionSigner for KmsSigner {
    fn public_key(&self) -> Result<[u8; 32]> {
        Ok(self.cached_public_key)
    }

    fn sign_version_message(&self, canonical_message: &[u8]) -> Result<[u8; 64]> {
        self.client
            .sign_ed25519(&self.key_arn, canonical_message)
            .map_err(|e| AionError::SigningFailed {
                reason: e.kind().to_string(),
            })
    }
}

let result = commit_version_with_signer(
    Path::new("policy.aion"),
    &new_rules,
    &ExternalCommitOptions {
        author_id: AuthorId::new(1001),
        signer: &kms_signer,
        message: "Approved district policy release",
        timestamp: None,
    },
    &trusted_registry,
)?;
```

Note what the adapter does **not** contain: no `VersionEntry`, no
domain separator, no parent-hash computation, no serializer, no
registry lookup, no file handling. The whole adapter is a transport.

### Edge Cases

- **Provider returns a valid signature over a different message.**
  Caught at step 11; nothing written.
- **Provider's `public_key()` disagrees with the key it signs
  with.** Step 6 passes (the advertised key matches the registry),
  step 11 fails (the signature does not verify under the advertised
  key). Nothing written. This is the substitution attack the
  post-signing verification exists for.
- **Provider is non-deterministic or stateful across calls.**
  Irrelevant — it is called exactly once.
- **Provider panics.** A panicking provider aborts the process
  before the write, so the artifact is untouched. `aion-context`
  cannot catch this without `catch_unwind`, which would violate the
  crate's Tiger Style posture; providers are documented to return
  `Err` rather than panic. The failure mode is loud and safe.
- **Provider blocks indefinitely.** No timeout is imposed. Timeouts
  are transport policy and belong in the adapter. The artifact is
  untouched for as long as the call is outstanding, since the write
  happens after.
- **Concurrent commits to the same path.** Unchanged from
  `commit_version`: last writer wins at the filesystem level, and
  the loser's parent-hash linkage makes the loss detectable on the
  next verify. External signing does not make this better or worse.
  File-level locking remains out of scope.
- **`commit_version_force_unregistered`.** This path deliberately
  bypasses the registry authorization gate (step 6) for bootstrap,
  and consequently also skips the registry-based verification at
  step 11, since there is no epoch to verify against. It remains
  reachable only through `CommitOptions` with an in-process
  `SigningKey`, where the signature is produced by the same code
  that would verify it. It is **not** exposed for external signers.
  See Unresolved Questions.

## Rationale and Alternatives

### Why place the boundary at the canonical message?

The boundary has to sit somewhere on the spectrum between "provider
gets the raw rules" and "provider gets the finished file." The
canonical message is the only point where the provider's input is
(a) fully determined by the core, (b) meaningless to sign for any
other purpose, thanks to the `AION_V2_VERSION_SIGNATURE_V1` domain
separator, and (c) small and fixed-size.

Below that point — a provider that receives the rules and builds its
own `VersionEntry` — the core loses control of the parent hash and
the version number, which is the entire chain integrity property.
Above it — a provider that receives a pre-built file — the provider
needs to parse the format, which is the reimplementation problem
this RFC exists to eliminate.

### Why is the provider's signature re-verified?

Because a provider is third-party code, frequently talking to a
third-party service over a network, and an append-only chain has no
undo. The cost is one Ed25519 verification on a path that already
does file I/O and full-chain verification. See Detailed Design step
11.

### Why exactly one signature request?

Hardware signing is expensive in ways CPU signing is not: a KMS call
is a network round-trip and is billed and rate-limited; a token
requires a human to physically touch it. A design that calls the
provider twice — once speculatively, once for real — would produce
two touch prompts for one commit, which integrators would work
around by caching signatures, which reintroduces every replay
problem the format is built to prevent. One call is a hard contract,
asserted by a test that counts invocations.

### Alternatives Considered

1. **Take a closure, `FnOnce(&[u8]) -> Result<[u8; 64]>`, instead of
   a trait.** Lighter, and avoids the `dyn` indirection. Rejected
   because the public key must be available *before* the signature
   is requested (step 6 precedes step 9), which a single closure
   cannot express. Two closures would be a trait with worse
   ergonomics and no name to document.

2. **Add `Option<&dyn VersionSigner>` to `CommitOptions`.** Avoids
   a second options struct. Rejected: it makes `signing_key` and
   `signer` mutually exclusive at runtime with no type-level
   enforcement, creating a fourth error case ("both supplied",
   "neither supplied") for a condition the type system should make
   unrepresentable. Adding a field to a public struct is also a
   breaking change absent `#[non_exhaustive]`, whereas a new struct
   plus a new function is purely additive.

3. **Generic `S: VersionSigner` instead of `&dyn`.** Monomorphizes
   and removes the vtable call. Rejected: one virtual call per
   commit is unmeasurable against file I/O plus chain verification,
   and `&dyn` keeps `ExternalCommitOptions` a concrete non-generic
   type that is trivially usable behind an FFI or in a
   dynamically-dispatched plugin registry — plausible shapes for
   exactly the integrators this RFC targets.

4. **Ship KMS/HSM adapters in-crate behind feature flags.** Better
   out-of-box experience. Rejected: it drags cloud SDKs and
   credential handling into a crate whose network attack surface is
   currently one dependency (`reqwest`), and per
   `.claude/rules/supply-chain.md` every one of those SDKs is a
   trust party we would be choosing on our users' behalf. The trait
   is the stable contract; adapters live downstream.

5. **PKCS#11 as the boundary instead of a native trait.** A real
   standard with real HSM support. Rejected as the *primary*
   interface: it constrains the design to one ecosystem, pulls in a
   C FFI (colliding with `unsafe_code = "forbid"`), and excludes
   cloud KMS and split-process signers, which are the more common
   deployments. A PKCS#11 adapter is a natural downstream
   implementation of this trait.

6. **Do nothing.** Integrators keep hand-assembling artifacts. This
   is the status quo and it is actively harmful: it distributes the
   format's security invariants into private codebases with no
   contract and no way to fix them centrally.

## Security Considerations

### Threat Model

| Threat | Mitigation |
|---|---|
| Malicious/compromised provider returns a signature over attacker-chosen content | The provider never chooses the message. It receives bytes built by the core from the verified chain head. A signature over anything else fails step 11. |
| Provider advertises a public key it does not hold | Step 11 verifies the signature against the advertised key, which step 6 pinned to the registry epoch. A mismatch fails. |
| Provider advertises a key not authorized for this author/version | Step 6, constant-time comparison against the registry epoch. Rejected before the provider is asked to sign. |
| Provider returns a stale signature from a previous commit | The canonical message binds version number, parent hash, rules hash, author, timestamp, and message offset/length. A prior version's signature cannot verify against a new `VersionEntry`. |
| Cross-protocol reuse — an Ed25519 signature from another system replayed as a version signature | RFC-0005's `SIGNATURE_DOMAIN` prefix, unchanged and reused verbatim. |
| Provider error path leaks key material through `reason` | Documented constraint on adapters; `reason` is never emitted as a `tracing` field. Not enforceable by the type system — see Unresolved Questions. |
| Partial write on provider failure leaves a corrupt artifact | Every failure path returns before serialization. The write is atomic (write-then-rename). Asserted by tests that compare file bytes before and after a failed commit. |
| Provider used to sign for an author it is not bound to | `author_id` comes from the caller, not the provider, and step 6 binds it to a registry epoch. A provider cannot elect its own author. |

### Security Guarantees

1. **No key export.** `aion-context` never observes private key
   material on this path. The trait has no method that could return
   it.
2. **Authorize before sign.** An unauthorized signer is never asked
   to produce a signature.
3. **Verify before write.** Nothing is written until the provider's
   own output verifies under the rules a third-party reader applies.
4. **Atomic failure.** Any error on this path leaves the artifact
   byte-identical.
5. **Format equivalence.** External and software commits produce
   identical signed material — the same `VersionEntry` bytes and the
   same `SignatureEntry` — for identical inputs. No verifier
   distinguishes them; no format version changes.

### What This Does Not Guarantee

The provider is trusted for **availability and non-repudiation of
its own key**, and nothing else. If the key custodian is compromised
such that an attacker can sign arbitrary messages with it, this RFC
does not help — but neither does any signing design, and that is
precisely the scenario RFC-0028's rotation and revocation channel
exists to remediate.

## Performance Impact

- **Time complexity:** unchanged, O(chain length) for the
  pre-commit verification that dominates. One added Ed25519 verify
  (~50 µs) and one vtable dispatch per commit.
- **Space complexity:** unchanged. The canonical message is 156
  bytes (28-byte domain separator + 128 bytes of fields), stack- or
  small-heap-sized.
- **Provider latency dominates.** A KMS round-trip is 10–100 ms,
  three orders of magnitude above everything the core does. This is
  why the one-call contract matters more than any micro-optimization
  on this path.
- **Software path regression:** one extra `verify_signature` per
  `commit_version`. Measured against `benches/`, this is inside
  noise for any realistic rules payload.

## Testing Strategy

### Unit Tests

- `external_signer_matches_the_software_commit_protocol` — commit
  the same logical version to two files, one via `commit_version`,
  one via `commit_version_with_signer` with a recording adapter over
  the same key and a pinned timestamp. Assert every `VersionEntry`
  field matches, both signature entries match under `ct_eq`, the
  message handed to the provider equals
  `canonical_version_message` of the resulting entry, the provider
  was called exactly once, and both files pass `verify_file`.
- `external_signer_output_is_verified_before_any_write` — adapter
  returns `[0u8; 64]`. Assert `Err` and that the file is
  byte-identical to its pre-call state.
- `external_provider_failure_leaves_the_artifact_unchanged` —
  adapter returns `SigningFailed`. Assert the error propagates and
  the file is byte-identical.
- `external_signer_key_mismatch_is_rejected_before_signing` —
  adapter advertises a key that is not the registry's pinned
  operational key. Assert `KeyMismatch`, that the provider's sign
  method was called **zero** times, and that the file is unchanged.

### Property-Based Tests (Hegel, Tier-2)

Added to `src/operations.rs` under `mod properties`:

| Property | Invariant |
|---|---|
| `prop_external_commit_matches_software_commit` | For arbitrary rules bytes and commit messages, the two entry points produce byte-identical version and signature entries. |
| `prop_external_commit_calls_provider_exactly_once` | The one-call contract holds for any input. |
| `prop_failing_provider_never_mutates_artifact` | For any failure injected at any point, the file bytes are unchanged. |
| `prop_invalid_provider_signature_always_rejected` | For arbitrary corrupted 64-byte returns, the commit fails and nothing is written. |

These are added to the required-coverage table in
`.claude/rules/property-testing.md`.

### Integration Tests

`verify_file` and the CLI `verify` path must accept externally
signed artifacts with no changes, which the equivalence test
establishes by construction.

## Implementation Plan

### Phase A (this RFC's PR)

- `VersionSigner`, `ExternalCommitOptions`,
  `commit_version_with_signer` in `src/operations.rs`.
- `impl VersionSigner for SigningKey`.
- Collapse `commit_version` / `commit_version_force_unregistered`
  onto the shared inner implementation.
- `AionError::SigningFailed`.
- Post-signing verification (step 11).
- Unit and property tests above.
- README and `docs/DEVELOPER_GUIDE.md` sections.

Phase A also carries four unrelated but adjacent constant-time
fixes, replacing `==` / `!=` on public-key bytes with
`subtle::ConstantTimeEq` in `hw_attestation::verify_binding`,
`manifest::verify_manifest_signature`, and
`signature_chain::{verify_signature, verify_attestation}`. These are
`.claude/rules/crypto.md` violations independent of this RFC; they
are bundled because this RFC's review touches the same call sites.

### Phase B

- Extend the boundary to manifest signing (RFC-0033) and DSSE
  envelope signing (RFC-0023), which are the next two paths where a
  custody-constrained key is plausible.
- A reference adapter in `examples/` over a mock provider,
  demonstrating the split-process shape without adding a dependency.

### Phase C

- Evaluate whether release sealing (RFC-0032) should accept a
  provider per artifact kind, or a single provider for all
  signatures in a seal.

## Unresolved Questions

1. **Should `commit_version_force_unregistered` be reachable with an
   external signer?** Currently it is not: the bootstrap path
   accepts only `CommitOptions`. The argument for exposing it is
   that an organization whose *first* key is already in an HSM
   cannot bootstrap a chain without a software key. The argument
   against is that the unregistered path skips both the
   authorization gate and the post-signing verification, which is
   defensible when the signature is produced by the same process
   that would verify it and much less defensible when it comes from
   a provider. A middle path — expose it, but keep step 11 by
   verifying against the provider's advertised key directly rather
   than a registry epoch — is probably right, and is deferred
   pending a real bootstrap request.

2. **Should `reason` on `SigningFailed` be a bounded enum?** An
   unbounded provider-controlled string is the one cardinality risk
   this RFC introduces. It is not currently logged, so it does not
   violate the observability rule today, but a future maintainer
   adding `reason = %e` to a `warn!` would introduce an unbounded
   field. A bounded `SigningFailureKind` plus a free-text detail
   would remove the footgun at the cost of forcing every adapter to
   classify its errors into our taxonomy. Deferred until there are
   enough real adapters to know what the taxonomy should be.

3. **Should the trait expose a batch signing method?** Committing N
   versions requires N provider calls, and N KMS round-trips is slow
   enough that integrators may want a batch. But batch signing
   across chain versions is not obviously safe — version K+1's
   parent hash depends on version K's entry, so the messages cannot
   all be constructed up front without also committing to the whole
   sequence. Probably impossible as stated; recorded here so it is
   not re-proposed without addressing the linkage.

4. **Is one call per commit enough for providers requiring
   pre-authorization?** Some HSM integrations need a separate
   "begin session" or policy-approval step. Adapters can do this
   inside `sign_version_message` or at construction, but if a
   provider needs a *core-supplied* nonce or challenge to
   pre-authorize, this trait has nowhere to put it. No such
   requirement has surfaced yet.

5. **How should key rotation interact with a cached
   `public_key()`?** The `KmsSigner` sketch above caches the public
   key at construction. If the key rotates in the KMS between
   construction and commit, `public_key()` returns a stale value and
   the commit fails at step 6 with `KeyMismatch` — safe, but the
   error points at the registry rather than at the stale cache.
   Guidance for adapter authors, not a code change, but it should be
   written down somewhere more discoverable than an RFC.

## References

- RFC-0003 — Cryptography (Ed25519, BLAKE3, domain separation)
- RFC-0004 — Key management
- RFC-0005 — Signature chain and `canonical_version_message`
- RFC-0012 — Versioning and replay defense
- RFC-0026 — Hardware attestation (key provenance; the other half
  of this story)
- RFC-0028 — Key rotation and revocation
- RFC-0034 — Registry-aware verify rollout
- RFC-0037 — Crypto/RNG stack upgrade
- `.claude/rules/crypto.md` — constant-time comparison, no ambient
  authority, author binding
- `.claude/rules/observability.md` — bounded field cardinality
- NIST SP 800-57 Part 1 Rev. 5 — key management lifecycle
- FIPS 140-3 — non-exportable key requirements motivating this work
- PKCS#11 v3.0 — prior art for a signing-oracle boundary

## Appendix

### Terminology

- **Provider / adapter:** an implementation of `VersionSigner`.
  Third-party code from the core's perspective, even when written
  by the same team.
- **Canonical message:** the 156 bytes produced by
  `signature_chain::canonical_version_message` — domain separator
  plus the `VersionEntry` fields in fixed little-endian order.
- **Authorization gate:** step 6, the pre-signing registry epoch
  check.
- **Post-signing verification:** step 11, re-verifying the
  provider's returned signature before any write.
