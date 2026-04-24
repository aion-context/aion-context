# RFC 0032: Release Orchestration — ReleaseBuilder / SignedRelease

- **Author:** aion-context maintainers
- **Status:** DRAFT
- **Created:** 2026-04-23
- **Updated:** 2026-04-23
- **Depends on:** RFC-0022, RFC-0023, RFC-0024, RFC-0025, RFC-0029, RFC-0030
- **Phase-B integration RFC** — composes existing primitives, adds no new ones.

## Abstract

Every primitive needed to sign and ship an AI model release now
lives in `aion-context`: external-artifact manifests (RFC-0022),
DSSE envelopes (RFC-0023), SLSA v1.1 provenance (RFC-0024), an
append-only transparency log (RFC-0025), AIBOM (RFC-0029), OCI
artifact packaging (RFC-0030). What the room's "show me the demo"
follow-up wants is a **single call site** that wires them
together.

This RFC adds `release::ReleaseBuilder` and `release::SignedRelease`.
The builder gathers the raw model artifact plus AIBOM-shaped
metadata (frameworks, datasets, licenses, safety attestations,
export controls); `seal()` produces a fully-signed release — a
manifest, an AIBOM, a SLSA statement, three DSSE envelopes, three
transparency-log entries, an OCI primary manifest, and two OCI
attestation referrers. `SignedRelease::verify()` re-checks the
entire graph against a pinned verifying key and asserts every
structural linkage still holds.

No new crypto. No new wire formats. No on-disk format change.
Every byte the builder emits already has Hegel property tests in
its home module. The new properties here are integration
properties: **the sealed graph round-trips end-to-end**, **tamper
anywhere and everything breaks**, **log entries are discoverable
by kind**, **OCI referrer subjects link to the primary digest**.

## Motivation

### Problem Statement

Today, assembling a complete release requires a caller to string
together six separate modules in the right order, compute the
right hashes, pick the right domain separators, remember to
append to the log in kind-order, and build the OCI referrer graph.
Each step has a correct shape; the combined flow has no canonical
example anywhere in the crate. When NVIDIA/Microsoft ask "show
me the code that produces a signed model release", the honest
answer today is "here are ten modules — here's how you glue them."

### Use Cases

- **Release pipeline**: CI builds a model, calls
  `ReleaseBuilder::new(...).primary_artifact(...).add_framework(...)
  .seal(...)`, pushes the resulting OCI manifests to a registry.
- **Verification admission**: consumer pulls the OCI primary +
  all referrers, reconstructs a `SignedRelease`, calls
  `.verify(&pinned_key)`; either `Ok` or `Err`.
- **Audit replay**: auditor replays the transparency log and
  checks that every sealed release's entries appear in order.
- **Demo**: one screen of code that produces a signed,
  transparency-logged, OCI-packaged release.

### Goals

- Single builder + seal + verify triple.
- Every emitted artifact is indexed and re-verifiable from the
  final `SignedRelease` struct.
- `seal()` is deterministic given the same inputs and signer
  (modulo randomness in the signing key).
- `verify()` is pure and offline.
- Composes with the hybrid-signature path (RFC-0027) and the
  registry-aware verification path (RFC-0028) via separate
  methods in Phase C.

### Non-Goals

- **On-disk format change**. The `.aion` binary file format stays
  at v2. Phase C of RFC-0022 / RFC-0028 bumps to v3 and embeds
  these types; that's its own RFC.
- **CLI**. `aion release seal` / `aion release verify` will come
  with RFC-0033 once the library API soaks.
- **ORAS / Rekor HTTP integration**. The builder emits bytes;
  transport is the caller's job.
- **Hybrid-signature seal**. A follow-up `seal_hybrid()` takes a
  `HybridSigningKey` (RFC-0027) and writes paired signatures. Not
  in Phase B.

## Proposal

### `ReleaseBuilder`

```rust
pub struct ReleaseBuilder {
    model_name: String,
    model_version: String,
    model_format: String,
    primary_artifact: Option<(String, Vec<u8>)>,
    auxiliary_artifacts: Vec<(String, Vec<u8>)>,
    frameworks: Vec<FrameworkRef>,
    datasets: Vec<DatasetRef>,
    licenses: Vec<License>,
    hyperparameters: BTreeMap<String, serde_json::Value>,
    safety_attestations: Vec<SafetyAttestation>,
    export_controls: Vec<ExportControl>,
    references: Vec<ExternalReference>,
    builder_id: String,
    external_parameters: serde_json::Value,
    current_aion_version: u64,
}

impl ReleaseBuilder {
    pub fn new(
        model_name: impl Into<String>,
        model_version: impl Into<String>,
        model_format: impl Into<String>,
    ) -> Self;

    pub fn primary_artifact(&mut self, name: impl Into<String>, bytes: Vec<u8>) -> &mut Self;
    pub fn add_auxiliary(&mut self, name: impl Into<String>, bytes: Vec<u8>) -> &mut Self;
    pub fn add_framework(&mut self, f: FrameworkRef) -> &mut Self;
    pub fn add_dataset(&mut self, d: DatasetRef) -> &mut Self;
    pub fn add_license(&mut self, l: License) -> &mut Self;
    pub fn hyperparameter(&mut self, k: impl Into<String>, v: serde_json::Value) -> &mut Self;
    pub fn add_safety_attestation(&mut self, s: SafetyAttestation) -> &mut Self;
    pub fn add_export_control(&mut self, e: ExportControl) -> &mut Self;
    pub fn add_reference(&mut self, r: ExternalReference) -> &mut Self;
    pub fn builder_id(&mut self, id: impl Into<String>) -> &mut Self;
    pub fn external_parameters(&mut self, v: serde_json::Value) -> &mut Self;
    pub fn current_aion_version(&mut self, v: u64) -> &mut Self;

    pub fn seal(
        self,
        signer: AuthorId,
        signing_key: &SigningKey,
        log: &mut TransparencyLog,
    ) -> Result<SignedRelease>;
}
```

### `SignedRelease`

```rust
pub struct SignedRelease {
    pub model_ref: ModelRef,
    pub manifest: ArtifactManifest,
    pub manifest_signature: SignatureEntry,
    pub manifest_dsse: DsseEnvelope,
    pub aibom: AiBom,
    pub aibom_dsse: DsseEnvelope,
    pub slsa_statement: InTotoStatement,
    pub slsa_dsse: DsseEnvelope,
    pub oci_primary: OciArtifactManifest,
    pub oci_aibom_referrer: OciArtifactManifest,
    pub oci_slsa_referrer: OciArtifactManifest,
    pub log_entries: Vec<LogSeq>,
}

pub struct LogSeq {
    pub kind: LogEntryKind,
    pub seq: u64,
}

impl SignedRelease {
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<()>;
    pub fn seal_signer_keyid(&self) -> Option<&str>;
}
```

### `seal()` flow (precise)

1. **Require** the primary artifact is set and `builder_id` is
   non-empty; otherwise `Err(InvalidFormat)`.
2. **Build the manifest** via `ArtifactManifestBuilder`: primary
   artifact first, then each auxiliary. Record the primary's
   entry for step 3.
3. **Build the `ModelRef`** using the primary entry's hash,
   size, and the caller-supplied name + version + format.
4. **Build the AIBOM** via `AiBom::builder(model_ref, current_aion_version)`
   and push the caller's frameworks/datasets/licenses/etc.
5. **Build the SLSA statement** via `SlsaStatementBuilder`:
   subjects from the manifest (every artifact), builder_id and
   external_parameters from the caller.
6. **Sign the manifest** via `sign_manifest` (RFC-0022).
7. **DSSE-wrap** the manifest signature, the AIBOM, and the SLSA
   statement via `wrap_manifest`, `wrap_aibom_dsse`, and
   `wrap_statement_dsse` respectively.
8. **Append to the log**, in stable order:
   a. Manifest signature (`LogEntryKind::ManifestSignature`).
   b. AIBOM DSSE envelope (`LogEntryKind::DsseEnvelope`).
   c. SLSA statement DSSE envelope (`LogEntryKind::SlsaStatement`).
9. **Build the OCI primary manifest** from the aion-file-equivalent
   serialization (Phase B stub: we emit the manifest's
   `canonical_bytes()` as the OCI layer payload, since the on-disk
   format-v3 bump is out of scope).
10. **Build two OCI referrers**, one for the AIBOM envelope and
    one for the SLSA envelope, each with `subject` bound to the
    OCI primary manifest's digest.
11. Return a fully-populated `SignedRelease`.

### `verify(&verifying_key)` flow

1. **Manifest integrity**: `manifest.verify_artifact(name, bytes)`
   for every `(name, bytes)` the primary + auxiliaries — but since
   the `SignedRelease` doesn't carry the raw bytes, we verify
   `manifest_signature` via `verify_manifest_signature` (RFC-0022)
   and the manifest's own canonical hash (`manifest_id`) matches
   what's inside `manifest_signature`.
2. **DSSE manifest envelope**: `dsse::verify_envelope(&manifest_dsse,
   verifying_key)` must pass.
3. **DSSE AIBOM envelope**: same.
4. **DSSE SLSA envelope**: same.
5. **AIBOM↔manifest binding**: `aibom.model.hash` equals the
   primary artifact's hash from the manifest (looked up by
   `model_ref.name`).
6. **SLSA↔manifest binding**: every SLSA subject's digest
   appears as an artifact hash in the manifest.
7. **OCI primary digest stability**: recompute
   `oci_primary.digest()?` and check.
8. **OCI referrer linkage**: each referrer's `subject.digest`
   equals `oci_primary.digest()?`.
9. **Log entries**: `log_entries.len() == 3` and each has the
   expected `kind` in the order
   `ManifestSignature, DsseEnvelope, SlsaStatement`.

### Edge Cases

- **Seal without a primary**: `Err(InvalidFormat)`.
- **Duplicate artifact names**: allowed at the `ArtifactManifest`
  layer; `ModelRef.name` always resolves to the first matching
  entry.
- **Empty auxiliary list**: valid; the release has exactly one
  subject.
- **Seal with an already-populated log**: the log's existing
  entries are left untouched; new entries are appended with
  fresh seqs.
- **Verify after log mutation**: `SignedRelease.log_entries`
  holds snapshot seqs at seal time; later log appends don't
  invalidate them (only a log rewrite would, and logs are
  append-only).

## Rationale and Alternatives

### Why a single builder instead of a procedural macro or codegen?

A builder is one ~400-line file. A proc macro is a second crate,
a syntax to document, and a testing matrix. The complexity of the
flow is in the ordering, not the syntax — a builder captures the
ordering cleanly.

### Why does `seal` take `&mut TransparencyLog` instead of
returning fresh log entries?

The log is the authoritative ordering. Returning entries means
the caller has to merge them correctly; passing the log
guarantees the seq ordering for this release's entries is
contiguous. Callers who want a release without log entries can
pass a throwaway empty log and discard it.

### Why verify via a dedicated method instead of re-running `seal`
with the same inputs?

Verification doesn't have the original artifact bytes — the
`SignedRelease` only has hashes. A `seal` replay would require
callers to retain all the bytes, defeating the point of
hash-based attestation.

## Security Considerations

### Threat Model

- **Tampered artifact in transit**: manifest's BLAKE3 catches it
  at `verify_artifact` time; since the release doesn't store
  raw bytes, the caller re-verifies with the bytes they received.
- **Tampered AIBOM**: DSSE signature fails.
- **Swapped referrer subject**: OCI digest mismatch at
  `verify()` step 8.
- **Replayed seal into a different release**: the signer
  commits to exact bytes of each envelope; nothing transfers.

### Security Guarantees

- **End-to-end**: if `SignedRelease::verify(&key)` returns `Ok`,
  every component signature verified, every linkage check
  passed, every OCI digest matched.
- **Nothing hidden**: every artifact the builder consumed is
  either in the manifest (by hash) or explicitly excluded by the
  caller (and thus not attested).

## Performance Impact

- **Seal**: one BLAKE3 per artifact + one Ed25519 sign per DSSE
  envelope (3) + one sign for the manifest signature (4 total) +
  O(N) OCI layer hashing. For a 500 MB model, dominated by the
  single BLAKE3 on the primary artifact (~300 ms).
- **Verify**: four Ed25519 verifies + a handful of SHA-256
  digests. Sub-millisecond.

## Testing Strategy

### Property-Based Tests (Hegel, Tier-2)

Added to `.claude/rules/property-testing.md`:

- `prop_release_seal_verify_roundtrip`: build → seal → verify is
  `Ok` for any valid builder input.
- `prop_release_tampered_manifest_detected`: mutating any byte
  in the serialized `manifest_dsse` payload causes `verify` to
  fail.
- `prop_release_oci_referrers_link_to_primary`: both OCI
  referrers have `subject.digest` equal to the OCI primary's
  digest.
- `prop_release_aibom_model_ref_matches_manifest`: the AIBOM's
  model hash equals the primary entry's hash in the manifest.
- `prop_release_log_has_expected_kinds`: `log_entries` has
  exactly three entries with the kinds
  `[ManifestSignature, DsseEnvelope, SlsaStatement]`.

And for RFC-0031 Phase B:

- `prop_aibom_to_jcs_bytes_matches_helper`: `aibom.to_jcs_bytes()
  == jcs::to_jcs_bytes(&aibom)`.
- `prop_slsa_statement_to_jcs_bytes_matches_helper`.
- `prop_oci_manifest_to_jcs_bytes_matches_helper`.

## Implementation Plan

### Phase B (this RFC, this PR)

1. `src/release.rs` with `ReleaseBuilder`, `SignedRelease`,
   `LogSeq`, `seal`, `verify`.
2. `pub mod release;` in `src/lib.rs`.
3. `to_jcs_bytes()` methods on `AiBom`, `InTotoStatement`,
   `OciArtifactManifest`.
4. Property tests per above.
5. Tier-2 floor + `/hegel-audit` update.

### Phase C

1. `seal_hybrid(HybridSigningKey, …)` for RFC-0027 signatures.
2. `seal_with_registry(…, &KeyRegistry)` that cross-checks
   signer epoch via RFC-0028 before signing.
3. `aion release seal / verify` CLI subcommand.
4. On-disk `.aion` v3 bump embedding manifest + AIBOM + log +
   registry (RFC-0022, RFC-0028, RFC-0025 Phase B).
5. ORAS thin wrapper for `push`/`pull` of the full artifact graph.

## Open Questions

1. Should `verify` require a single pinned `VerifyingKey`, or a
   `key_for(keyid) -> Option<VerifyingKey>` closure to support
   multi-signer envelopes? Phase B answer: single key (the
   signer). Multi-signer verify is already available at the DSSE
   layer; we expose it for advanced callers but the single-key
   path is the common case.
2. Should `seal` accept optional hardware-attestation binding
   (RFC-0026) inline? Phase B answer: no; bindings are attached
   at the key-identity layer, not per release.

## References

- All Phase-A RFCs it composes: 0021, 0022, 0023, 0024, 0025,
  0026, 0027, 0028, 0029, 0030, 0031.

## Appendix

### Call-site sketch

```rust
let mut log = TransparencyLog::new();
let key = SigningKey::generate();

let weights = std::fs::read("model.safetensors")?;
let tokenizer = std::fs::read("tokenizer.json")?;

let mut builder = ReleaseBuilder::new("acme-7b-chat", "0.3.1", "safetensors");
builder
    .primary_artifact("model.safetensors", weights)
    .add_auxiliary("tokenizer.json", tokenizer)
    .add_framework(FrameworkRef { name: "pytorch".into(), version: "2.3.1".into(), cpe: None })
    .add_license(License {
        spdx_id: "Apache-2.0".into(),
        scope: LicenseScope::Weights,
        text_uri: None,
    })
    .add_export_control(ExportControl {
        regime: "US-ECCN".into(),
        classification: "EAR99".into(),
        notes: None,
    })
    .builder_id("https://github.com/acme/models/.github/workflows/release.yml@refs/tags/v0.3.1")
    .current_aion_version(42);

let signed = builder.seal(AuthorId::new(50_001), &key, &mut log)?;

// Push signed.oci_primary and both referrers to the registry
// (caller's job, using ORAS / cosign / curl).

// Consumer side:
signed.verify(&key.verifying_key())?;
```
