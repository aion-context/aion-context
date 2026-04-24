# RFC 0024: SLSA v1.1 Provenance Emit

- **Author:** aion-context maintainers
- **Status:** DRAFT
- **Created:** 2026-04-23
- **Updated:** 2026-04-23
- **Depends on:** RFC-0022 (manifest), RFC-0023 (DSSE envelope)

## Abstract

SLSA v1.1 is the de-facto provenance format for signed software
(and, increasingly, signed ML artifacts). A SLSA provenance is an
in-toto Statement containing a `Predicate` of type
`https://slsa.dev/provenance/v1` that binds a built artifact
(identified by `subject[].digest`) to the build process that
produced it. Sigstore's `slsa-verifier`, NVIDIA NIM's release
gates, Azure's DevOps pipeline attestation, and Kyverno policies
all consume SLSA-v1 provenance natively.

This RFC adds a minimal SLSA v1.1 provenance emitter: given an
aion artifact manifest (RFC-0022) and some build metadata, produce
an in-toto Statement whose subjects are the manifest's entries,
wrap it in a DSSE envelope (RFC-0023), and sign it with an aion
`SigningKey`.

## Motivation

### Problem Statement

In the room, "what SLSA level does aion produce?" is the first
concrete question. Today the answer is "none — aion produces its
own binary signatures." SLSA provenance is the universal lingua
franca of build attestation; emitting it costs us one JSON shape
and one DSSE wrap.

### Use Cases

- **Model-signing**: a model trainer's CI emits a SLSA provenance
  binding `model.safetensors` (hash X) to the training pipeline
  run (git SHA Y, builder Z). Downstream verifiers check the
  provenance before deploying.
- **Policy gates**: Kyverno refuses to deploy a model whose SLSA
  provenance is missing or unsigned.
- **Supply-chain audit**: auditors query stored provenance for a
  given artifact hash and reconstruct the full build chain.

### Goals

- Emit valid SLSA v1.1 provenance consumable by
  `slsa-verifier` / cosign / Kyverno with no aion-specific code.
- Bind provenance subjects to `ArtifactEntry` hashes so tampering
  either the manifest or the artifact invalidates the chain.
- Zero new crypto — everything rides on RFC-0023 DSSE.
- Round-trip stable JSON.

### Non-Goals

- **SLSA Build level assertion**. Levels 1–4 require organizational
  process claims (hermetic builds, isolated runners) that cannot
  be determined by a file format alone. We emit provenance; the
  *level* is declared by the caller.
- **VSA (Verification Summary Attestation).** Different predicate
  type; future RFC.
- **In-toto Link predicates.** Legacy in-toto v0; SLSA v1.1 is
  the forward path.

## Proposal

### SLSA v1.1 shape (spec: <https://slsa.dev/spec/v1.1/provenance>)

An in-toto Statement wrapping a SLSA provenance predicate:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "model.safetensors",
      "digest": { "blake3-256": "ef12..." }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://aion-context.dev/buildtypes/generic/v1",
      "externalParameters": { ... },
      "internalParameters": { ... },
      "resolvedDependencies": [ ... ]
    },
    "runDetails": {
      "builder": {
        "id": "https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.2.3"
      },
      "metadata": {
        "invocationId": "...",
        "startedOn": "2026-04-23T12:00:00Z",
        "finishedOn": "2026-04-23T12:07:23Z"
      },
      "byproducts": []
    }
  }
}
```

### Aion-specific choices

- **subject.digest key**: `"blake3-256"` (in-toto accepts any
  algorithm name the verifier understands; BLAKE3 is our native).
  Verifiers that only speak SHA-256 see an unknown algorithm and
  reject — this is correct behavior.
- **buildType URI**:
  `https://aion-context.dev/buildtypes/generic/v1` for the
  default; callers can override with a domain-specific URI.
- **externalParameters / internalParameters**: opaque
  `serde_json::Value` provided by the caller. aion does not
  inspect.
- **resolvedDependencies**: opaque list; the caller supplies
  `ResourceDescriptor` entries.

### Public API

```rust
// src/slsa.rs

pub const IN_TOTO_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const SLSA_V1_PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";
pub const AION_DEFAULT_BUILD_TYPE: &str =
    "https://aion-context.dev/buildtypes/generic/v1";

pub struct SlsaStatementBuilder {
    subjects: Vec<Subject>,
    build_type: String,
    builder_id: String,
    external_parameters: serde_json::Value,
    internal_parameters: Option<serde_json::Value>,
    resolved_dependencies: Vec<ResourceDescriptor>,
    invocation_id: Option<String>,
    started_on: Option<String>,
    finished_on: Option<String>,
    byproducts: Vec<ResourceDescriptor>,
}

impl SlsaStatementBuilder {
    pub fn new(builder_id: impl Into<String>) -> Self;

    pub fn add_subject_from_entry(&mut self, manifest: &ArtifactManifest,
                                   entry: &ArtifactEntry) -> Result<&mut Self>;
    pub fn add_all_subjects_from_manifest(&mut self, m: &ArtifactManifest) -> Result<&mut Self>;
    pub fn build_type(&mut self, uri: impl Into<String>) -> &mut Self;
    pub fn external_parameters(&mut self, v: serde_json::Value) -> &mut Self;
    pub fn internal_parameters(&mut self, v: serde_json::Value) -> &mut Self;
    pub fn add_resolved_dependency(&mut self, d: ResourceDescriptor) -> &mut Self;
    pub fn invocation_id(&mut self, id: impl Into<String>) -> &mut Self;
    pub fn started_on(&mut self, ts: impl Into<String>) -> &mut Self;
    pub fn finished_on(&mut self, ts: impl Into<String>) -> &mut Self;

    pub fn build(self) -> Result<InTotoStatement>;
}

pub struct InTotoStatement {
    // Fields as shown above
}

impl InTotoStatement {
    pub fn to_json(&self) -> Result<String>;
    pub fn from_json(s: &str) -> Result<Self>;
    pub fn canonical_bytes(&self) -> Result<Vec<u8>>;
}

/// Wrap a statement in a DSSE envelope signed by `signer`.
/// payloadType is `application/vnd.in-toto+json`.
pub fn wrap_statement_dsse(
    statement: &InTotoStatement,
    signer: AuthorId,
    key: &SigningKey,
) -> Result<DsseEnvelope>;

/// Unwrap + parse a DSSE envelope known to contain an in-toto
/// Statement. Returns the statement; the caller must separately
/// verify the DSSE signature via `dsse::verify_envelope`.
pub fn unwrap_statement_dsse(
    envelope: &DsseEnvelope,
) -> Result<InTotoStatement>;

pub struct Subject {
    pub name: String,
    pub digest: std::collections::BTreeMap<String, String>,
}

pub struct ResourceDescriptor {
    pub name: Option<String>,
    pub uri: Option<String>,
    pub digest: Option<std::collections::BTreeMap<String, String>>,
    pub media_type: Option<String>,
}
```

### Canonical bytes

JSON canonicalization for in-toto Statements is underspecified in
the current spec draft. We use:

1. `serde_json::to_string` with sorted-key output (via a small
   adapter), producing stable UTF-8 bytes.
2. No whitespace other than the default single space after `:`
   and `,`.

This gives us deterministic bytes for PAE without needing RFC 8785
JCS. Downstream verifiers that round-trip via `from_json` don't
need byte stability — they verify against the `payload` in the
envelope.

### Edge Cases

- **Empty subjects**: rejected. An SLSA Statement without subjects
  attests to nothing.
- **Subject with empty digest map**: rejected.
- **Duplicate subject names**: allowed per in-toto spec; we do
  not dedupe.
- **Missing builder.id**: rejected — it's mandatory in SLSA v1.1.

## Rationale and Alternatives

### Why SLSA v1.1 and not v1.0 or v0.2?

v1.1 is the current published spec (Jan 2025) and what
`slsa-verifier` 2.6+ expects. v1.0 is compatible at the predicate
level for most consumers.

### Why not emit the full in-toto v0.9 Link format?

Deprecated. SLSA v1.1 subsumes it.

### Why not build this into the RFC-0022 manifest module?

Separation of concerns. RFC-0022 is "what is this artifact?"
RFC-0024 is "how was this artifact built?" A consumer can sign
a manifest without building a SLSA statement (air-gapped inference
deployments don't need build provenance).

## Security Considerations

### Threat Model

1. **Provenance forgery**: attacker crafts a SLSA statement
   claiming a malicious model came from a legitimate CI. Blocked
   — provenance is DSSE-signed by a pinned key controlled by the
   legitimate CI. A forged statement won't verify.
2. **Subject substitution**: attacker swaps a subject's digest
   to point to a Trojaned artifact. Detected — the Statement
   bytes change, DSSE signature fails.
3. **Replay**: attacker reuses an old provenance for a new
   artifact that happens to have the same hash. This is not an
   attack — the hash binding is the guarantee. If the hash
   matches, the bytes match.
4. **Builder spoofing**: attacker claims provenance was produced
   by a different builder. Detected only if the verifier pins
   acceptable `builder.id` values. Standard SLSA policy.

### Security Guarantees

- **Build binding**: a verifying SLSA statement proves the
  holder of the signing key produced the Statement and asserts
  the (subject, predicate) relationship at sign time.
- **Artifact binding**: any change to a subject's digest
  invalidates the signature.
- **Predicate integrity**: any change to buildType, builder,
  parameters, dependencies, metadata, byproducts invalidates
  the signature.

## Performance Impact

Negligible. Building a Statement is JSON serialization; wrapping
in DSSE is one Ed25519 sign; total sub-millisecond for manifests
with ≤100 subjects.

## Testing Strategy

### Property-Based Tests (Hegel, Tier-2)

Added to `.claude/rules/property-testing.md`:

- `prop_slsa_dsse_roundtrip`: build a Statement from an
  arbitrary manifest, wrap, unwrap, and the round-tripped
  statement has the same subjects.
- `prop_slsa_manifest_binding_survives_json`: Statement built
  from a manifest, serialized to JSON, parsed back — subject
  digests match the manifest entries byte-for-byte.
- `prop_slsa_tampered_subject_digest_rejects`: flipping a byte
  in any subject digest after signing causes DSSE verification
  to fail.
- `prop_slsa_envelope_payload_type_is_in_toto`: emitted envelope
  always has `payloadType == "application/vnd.in-toto+json"`.

### Vector Tests

One hand-rolled test emitting a Statement that matches the
example in the SLSA v1.1 spec, ensuring field names and casing
match exactly.

## Implementation Plan

### Phase A (this RFC, this PR)

1. `src/slsa.rs` with the builder + Statement + wrap helpers.
2. `pub mod slsa;` in `src/lib.rs`.
3. Property tests + one vector test.
4. Tier-2 floor + `/hegel-audit` update.

### Phase B

1. **VSA emitter** (`https://slsa.dev/verification_summary/v1`)
   for downstream verifiers summarizing their own verification
   results.
2. **Rekor upload**: submit SLSA statements to a transparency
   log; return the log index.
3. **Policy helpers**: a minimal policy evaluator that accepts
   a statement if `builder.id in allowlist` and all digests
   match a pinned manifest.

## Open Questions

1. Should `add_subject_from_entry` expose the digest algorithm
   as `"blake3-256"` or include a SHA-256 cross-digest for
   broader tool compatibility? Phase A answer: BLAKE3 only;
   Phase B may add SHA-256 cross-signing.

## References

- SLSA v1.1 provenance: <https://slsa.dev/spec/v1.1/provenance>
- in-toto Statement v1: <https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md>
- in-toto ResourceDescriptor: <https://github.com/in-toto/attestation/blob/main/spec/v1/resource_descriptor.md>
- slsa-verifier: <https://github.com/slsa-framework/slsa-verifier>

## Appendix

### Minimal valid SLSA v1.1 statement example

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "a", "digest": { "blake3-256": "00" } }],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://aion-context.dev/buildtypes/generic/v1",
      "externalParameters": {},
      "resolvedDependencies": []
    },
    "runDetails": {
      "builder": { "id": "https://example.com/ci/run/1" }
    }
  }
}
```
