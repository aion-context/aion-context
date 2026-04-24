# RFC 0029: AI Bill of Materials (AIBOM)

- **Author:** aion-context maintainers
- **Status:** DRAFT
- **Created:** 2026-04-23
- **Updated:** 2026-04-23
- **Depends on:** RFC-0022 (manifest), RFC-0023 (DSSE)

## Abstract

Signing a model artifact proves **who** released it, not **what
went into it**. Regulators, procurement teams, and downstream
integrators increasingly require an *AI Bill of Materials* —
the ingredient list for a trained model: framework versions,
training dataset identifiers, license surface, hyperparameters,
red-team / safety attestations, and export-control
classifications. SPDX 3.0 added an AI profile; CycloneDX 1.6
shipped an ML extension; the EU AI Act Article 13 enumerates
transparency obligations that an AIBOM is the natural vehicle
for.

This RFC adds a first-class, canonically-serializable,
DSSE-signable **AiBom** type. Phase A ships an aion-native JSON
schema that captures the essential fields, emits byte-stable
JSON via sorted `BTreeMap` keys, and rides over the existing
RFC-0023 DSSE envelope as
`application/vnd.aion.aibom.v1+json`. Phase B adds bi-directional
conversion with SPDX 3.0 AI profile and CycloneDX 1.6 ML.

## Motivation

### Problem Statement

A signed `.aion` file today attests *that* a model release was
approved by an authorized signer. It does not attest *what* was
released in terms of ingredients. Consumers need answers to:

- What framework and version does this model require?
- What datasets were used to train it? (hash or reference)
- What licenses apply to the weights, training data, and code?
- What hyperparameters define the build?
- Which red-team / eval reports endorse it for production?
- Is it subject to export controls (EAR99, 5D002, EU dual-use)?

Regulated industries (finance, healthcare, defence) cannot
deploy a model without these answers. Today aion has no
structure for them.

### Use Cases

- **Procurement**: enterprise legal rejects any model without an
  AIBOM listing license terms for weights + training data.
- **Vulnerability response**: a CVE lands against PyTorch 2.3.0;
  the AIBOM tells you which deployed models are affected.
- **Export compliance**: a government customer requires export
  classification inline with the model release.
- **EU AI Act Article 13**: providers of high-risk AI systems
  must supply transparency information; an AIBOM is the natural
  deliverable.
- **Supply chain audit**: downstream integrators verify that a
  foundation model wasn't silently updated — they pin both the
  model hash and the AIBOM hash.

### Goals

- Capture the minimal set of fields that answer the above use
  cases.
- Byte-stable JSON output so AIBOM hashes are deterministic and
  cross-implementation comparable.
- Sign via DSSE so every signer and every verifier already
  speaks the transport.
- Multi-signer friendly (legal + security + ML team co-sign).
- Maps cleanly to SPDX 3.0 AI / CycloneDX 1.6 ML in Phase B.

### Non-Goals

- **Full SPDX 3.0 compliance** in Phase A. SPDX 3.0 is an
  RDF/JSON-LD format with namespaces, blank nodes, and ~40
  classes in the AI profile alone. Our Phase A schema is a
  minimal flat JSON that captures the fields; translation to
  SPDX happens in a Phase B adapter.
- **CycloneDX compliance** in Phase A. Same reasoning.
- **Training provenance proofs** (e.g. cryptographically binding
  a training dataset hash to the trained weights). That's an
  open research problem; AIBOM here just *references* the
  inputs.
- **CVE correlation**. The AIBOM lists framework names/versions;
  vulnerability correlation is the consumer's job against a
  CVE feed.

## Proposal

### Core type

```rust
pub struct AiBom {
    pub schema_version: String,              // "aion.aibom.v1"
    pub model: ModelRef,
    pub frameworks: Vec<FrameworkRef>,
    pub datasets: Vec<DatasetRef>,
    pub licenses: Vec<License>,
    pub hyperparameters: BTreeMap<String, serde_json::Value>,
    pub safety_attestations: Vec<SafetyAttestation>,
    pub export_controls: Vec<ExportControl>,
    pub references: Vec<ExternalReference>,
    pub created_at_version: u64,
}
```

### Field types

```rust
pub struct ModelRef {
    pub name: String,
    pub version: String,
    pub hash_algorithm: String,   // "BLAKE3-256"
    pub hash: [u8; 32],
    pub size: u64,
    pub format: String,           // "safetensors" | "gguf" | "onnx" | ...
}

pub struct FrameworkRef {
    pub name: String,             // "pytorch", "tensorflow", "jax"
    pub version: String,          // "2.3.1"
    pub cpe: Option<String>,      // optional CPE 2.3 string for CVE feeds
}

pub struct DatasetRef {
    pub name: String,
    pub hash_algorithm: Option<String>,
    pub hash: Option<[u8; 32]>,
    pub size: Option<u64>,
    pub uri: Option<String>,
    pub license_spdx_id: Option<String>,
}

pub struct License {
    pub spdx_id: String,          // "Apache-2.0", "LLAMA3-COMMUNITY", "CC-BY-4.0"
    pub scope: LicenseScope,
    pub text_uri: Option<String>,
}

pub enum LicenseScope {
    Weights,
    SourceCode,
    TrainingData,
    Documentation,
    Combined,                     // "the whole release"
}

pub struct SafetyAttestation {
    pub name: String,             // "red-team-2026-03"
    pub result: String,           // "PASS" | "REVIEW" | site-specific
    pub report_hash_algorithm: Option<String>,
    pub report_hash: Option<[u8; 32]>,
    pub report_uri: Option<String>,
}

pub struct ExportControl {
    pub regime: String,           // "US-ECCN", "EU-dual-use", "UK-export"
    pub classification: String,   // "EAR99", "5D002.c.1", ...
    pub notes: Option<String>,
}

pub struct ExternalReference {
    pub kind: String,             // "model_card", "paper", "changelog"
    pub uri: String,
}
```

### Canonical JSON

- All maps (`hyperparameters`) and structs are serialized with
  sorted keys via serde + `serde_json::Map` with the
  `preserve_order` feature **disabled** — we rely on serde's
  field order for structs plus BTreeMap for user-provided keys.
- 32-byte hashes are emitted as lowercase hex.
- `serde_json::to_vec` on the resulting value yields byte-stable
  output for a given AiBom, independent of HashMap iteration
  order.

### DSSE payload type

```
application/vnd.aion.aibom.v1+json
```

### API

```rust
// src/aibom.rs

pub const AIBOM_PAYLOAD_TYPE: &str = "application/vnd.aion.aibom.v1+json";
pub const AIBOM_SCHEMA_VERSION: &str = "aion.aibom.v1";

impl AiBom {
    pub fn builder(model: ModelRef, created_at_version: u64) -> AiBomBuilder;
    pub fn to_json(&self) -> Result<String>;
    pub fn from_json(s: &str) -> Result<Self>;
    pub fn canonical_bytes(&self) -> Result<Vec<u8>>;
}

pub struct AiBomBuilder { /* builder pattern */ }

impl AiBomBuilder {
    pub fn add_framework(&mut self, f: FrameworkRef) -> &mut Self;
    pub fn add_dataset(&mut self, d: DatasetRef) -> &mut Self;
    pub fn add_license(&mut self, l: License) -> &mut Self;
    pub fn hyperparameter(&mut self, k: impl Into<String>, v: serde_json::Value) -> &mut Self;
    pub fn add_safety_attestation(&mut self, s: SafetyAttestation) -> &mut Self;
    pub fn add_export_control(&mut self, e: ExportControl) -> &mut Self;
    pub fn add_reference(&mut self, r: ExternalReference) -> &mut Self;
    pub fn build(self) -> AiBom;
}

pub fn wrap_aibom_dsse(
    aibom: &AiBom,
    signer: AuthorId,
    key: &SigningKey,
) -> Result<DsseEnvelope>;

pub fn unwrap_aibom_dsse(envelope: &DsseEnvelope) -> Result<AiBom>;
```

### Edge Cases

- **Empty lists**: allowed everywhere except `licenses` — Phase A
  does not enforce non-empty licenses at the type level (a
  consumer-side policy validator can), but the builder documents
  that shipping an AIBOM without licenses is a bug.
- **Unknown framework / dataset / license**: opaque strings; aion
  does not validate SPDX IDs against the registry (Phase B
  adds validation).
- **Hyperparameters with nested structure**: the field is a
  `BTreeMap<String, serde_json::Value>`, so arbitrarily deep
  JSON is supported and canonically ordered by top-level key
  only (deeper values retain their serde order, which is stable
  for arrays / structs).

## Rationale and Alternatives

### Why a flat schema instead of SPDX 3.0 directly?

SPDX 3.0 in JSON-LD has roughly 40 classes and requires namespace
handling, `@context` blobs, and blank-node references. For the
core question in the room — "do you have an AIBOM?" — we need
*something shippable today*, not a year of SPDX committee
modelling. The flat aion schema answers the essential questions
in ~200 lines of Rust and maps 1:1 onto SPDX fields for Phase B
export.

### Why not CycloneDX?

CycloneDX 1.6 ML is closer to our shape but the tooling universe
is split — SBOM consumers in regulated industries are at ~60/40
SPDX/CycloneDX. An aion-native schema that maps cleanly to
*both* is the defensible choice.

### Why include hyperparameters?

Two reasons: (a) some compliance regimes (financial model risk
management, medical devices) require they be part of the
attested release; (b) reproducibility auditors need them. We
treat them as opaque JSON so aion doesn't enumerate every
possible hyperparameter shape.

### Why a separate DSSE payload type?

Distinct payload type lets admission controllers filter on
`application/vnd.aion.aibom.v1+json` specifically without having
to peek inside the payload. Matches the RFC-0023 pattern.

## Security Considerations

### Threat Model

1. **Tampered AIBOM bytes**: attacker modifies the AIBOM after
   signing. Blocked — DSSE envelope signature verification
   fails.
2. **Swapped model reference**: attacker swaps the `model.hash`
   to point to a Trojan. Blocked — same.
3. **License misrepresentation**: attacker lists a permissive
   license when the actual model is GPL. *Not* blocked at the
   file-format layer — this is a policy/attestation trust
   issue, mitigated by requiring multi-party signatures (legal
   + ML team co-sign).
4. **Dataset provenance lies**: attacker claims a training
   dataset that wasn't actually used. *Not* blocked at the
   file-format layer — requires cryptographic training
   provenance (out of scope here; open research).
5. **AIBOM omission**: attacker ships a model with no AIBOM.
   Mitigated by policy: admission controllers require a
   matching AIBOM attestation to exist.

### Security Guarantees

- **Content integrity**: any change to any field invalidates the
  DSSE signature.
- **Signer binding**: each signer on the envelope
  cryptographically commits to the exact AIBOM bytes.
- **Multi-party gate**: DSSE's native multi-signature lets an
  organization require N co-signers (legal, security, ML lead,
  ops) before the AIBOM is accepted.

## Performance Impact

Negligible. AIBOM serialization is JSON; DSSE wrap is one
Ed25519 signature (or one hybrid signature via RFC-0027 if the
caller uses the hybrid path). For a 100-entry AIBOM (rare), JSON
size is ~30 KB.

## Testing Strategy

### Property-Based Tests (Hegel, Tier-2)

Added to `.claude/rules/property-testing.md`:

- `prop_aibom_json_roundtrip`: `from_json(to_json(aibom)) == aibom`.
- `prop_aibom_canonical_bytes_deterministic`: two consecutive
  `canonical_bytes()` calls on the same AIBOM yield identical
  bytes.
- `prop_aibom_model_hash_survives_json`: after JSON round-trip,
  the 32-byte model hash equals the original byte-for-byte.
- `prop_aibom_dsse_roundtrip`: `wrap_aibom_dsse` followed by
  DSSE verify followed by `unwrap_aibom_dsse` yields the
  original AIBOM.
- `prop_aibom_tampered_json_rejects`: any byte flip in the DSSE
  envelope payload invalidates the signature.
- `prop_aibom_multi_signer_envelope`: two signers sign the same
  AIBOM envelope; both verify.
- `prop_aibom_payload_type_constant`: `wrap_aibom_dsse` always
  produces `payload_type == AIBOM_PAYLOAD_TYPE`.

### Vector Test

Hand-rolled: an AIBOM with one framework (PyTorch 2.3.1), two
datasets (one hashed, one URI-only), two licenses
(Apache-2.0 + CC-BY-4.0), and one ECCN classification; assert
the JSON encode is stable byte-for-byte across two runs.

## Implementation Plan

### Phase A (this RFC, this PR)

1. `src/aibom.rs` with full public API above.
2. `pub mod aibom;` in `src/lib.rs`.
3. Property tests per above.
4. Tier-2 floor + `/hegel-audit` update.

### Phase B

1. **SPDX 3.0 AI profile translator** — aion AiBom ↔ SPDX 3.0
   JSON-LD round-trip.
2. **CycloneDX 1.6 ML translator** — same for CycloneDX.
3. **License-SPDX-ID validation** against the SPDX license
   registry snapshot.
4. **CLI**: `aion aibom build`, `aion aibom sign`, `aion aibom verify`.
5. **Transparency-log integration**: AIBOM DSSE envelopes
   appended to the RFC-0025 log with `LogEntryKind::Aibom`
   (new discriminant).
6. **Embedded in `.aion` file** as a new on-disk section
   (format-version bump).

## Open Questions

1. Should `DatasetRef.hash` be mandatory? Argument for: enforces
   reproducibility. Argument against: some training datasets are
   private or streaming. Phase A: optional; Phase B policy
   validator may require it.
2. Should `SafetyAttestation.result` be an enum instead of a
   string? Today the enum would be too narrow; enterprises use
   site-specific labels. Keep as string.

## References

- SPDX 3.0 AI profile: <https://spdx.github.io/spdx-spec/v3.0.1/model/AI/>
- CycloneDX 1.6 ML: <https://cyclonedx.org/docs/1.6/json/#components_items_mlModel>
- EU AI Act Article 13 (transparency obligations).
- NIST AI RMF 1.0.
- OWASP LLM Top 10 — Supply Chain Vulnerabilities.
- MITRE ATLAS (Adversarial ML Threat Matrix).

## Appendix

### Minimal AIBOM JSON example

```json
{
  "schema_version": "aion.aibom.v1",
  "model": {
    "name": "acme-7b-chat",
    "version": "0.3.1",
    "hash_algorithm": "BLAKE3-256",
    "hash": "ab12cd34...",
    "size": 487123456,
    "format": "safetensors"
  },
  "frameworks": [
    { "name": "pytorch", "version": "2.3.1", "cpe": null }
  ],
  "datasets": [
    {
      "name": "c4-en-v2",
      "hash_algorithm": "BLAKE3-256",
      "hash": "ef56...",
      "size": null,
      "uri": "s3://acme-datasets/c4-en-v2/",
      "license_spdx_id": "ODC-By-1.0"
    }
  ],
  "licenses": [
    { "spdx_id": "Apache-2.0", "scope": "Weights", "text_uri": null }
  ],
  "hyperparameters": {
    "context_length": 8192,
    "precision": "bf16"
  },
  "safety_attestations": [
    {
      "name": "red-team-2026-03",
      "result": "PASS",
      "report_hash_algorithm": null,
      "report_hash": null,
      "report_uri": "https://acme.example/reports/rt-2026-03.pdf"
    }
  ],
  "export_controls": [
    {
      "regime": "US-ECCN",
      "classification": "EAR99",
      "notes": null
    }
  ],
  "references": [
    {
      "kind": "model_card",
      "uri": "https://acme.example/models/acme-7b-chat/card"
    }
  ],
  "created_at_version": 42
}
```
