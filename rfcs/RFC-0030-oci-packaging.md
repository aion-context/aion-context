# RFC 0030: OCI Artifact Packaging

- **Author:** aion-context maintainers
- **Status:** DRAFT
- **Created:** 2026-04-23
- **Updated:** 2026-04-23
- **Depends on:** RFC-0023 (DSSE), RFC-0024 (SLSA), RFC-0029 (AIBOM)

## Abstract

Every modern supply-chain toolchain pushes artifacts to OCI
registries (Docker Hub, GHCR, ECR, GAR, Harbor, Artifactory,
Quay). ORAS (OCI Registry As Storage) made non-image artifacts
first-class, and OCI Image Manifest v1.1 (July 2023) added
`artifactType` and `subject` fields that let us attach signed
attestations (DSSE envelopes) to a primary artifact as
**referrers**. The entire Sigstore stack — `cosign attach`,
`cosign verify`, admission controllers, slsa-verifier —
speaks this pattern.

This RFC reserves aion-specific **media types** and provides
builders that emit spec-compliant OCI manifests as JSON. An
`.aion` file becomes a first-class OCI artifact; every attached
attestation (RFC-0021 DSSE version attestation, RFC-0022 manifest
signature, RFC-0024 SLSA provenance, RFC-0029 AIBOM) becomes a
referrer linked via the `subject` field.

Phase A, this RFC: media types, descriptor + manifest types,
canonical JSON serialization, SHA-256 layer digests, property
tests. No HTTP client — push/pull is the caller's job (ORAS,
cosign, Docker, `curl`). Phase B adds a thin HTTP wrapper and
CLI integration.

## Motivation

### Problem Statement

Today an `.aion` file is a loose binary on disk. To ship it
through existing supply-chain infrastructure — CI publishing,
admission control, vulnerability scanning, release gating — it
needs to become an OCI artifact. Without this:

- No `docker push`/`oras push` support.
- No `cosign attach attestation --predicate aibom.json`
  workflow.
- No `kyverno` policy that reads from a registry.
- No Artifact Hub listings.

### Use Cases

- **Release pipeline**: a CI job builds an `.aion` governance
  file plus the AIBOM, pushes both to `ghcr.io/acme/models/
  acme-7b-chat:0.3.1` with the AIBOM attached as a referrer.
- **Admission control**: Kyverno evaluates a policy requiring an
  AIBOM referrer with specific signers before permitting the
  associated model image to run.
- **Offline mirror**: `oras pull` a full artifact graph
  (primary + all referrers) into an air-gapped registry.
- **Cross-registry replication**: standard OCI replication tools
  propagate aion artifacts alongside images.

### Goals

- Reserve aion media types in the `application/vnd.aion.*`
  namespace.
- Emit OCI Image Manifest v1.1 JSON byte-stable across runs.
- Support both primary artifacts (the `.aion` file) and
  referrers (attached attestations).
- Compute SHA-256 layer digests per OCI spec (while aion's
  internal content hashing stays BLAKE3 per RFC-0002; OCI is
  a transport concern).
- Round-trip: build → JSON → parse → equal.

### Non-Goals

- **HTTP client / registry protocol**. ORAS, cosign, and
  `reqwest` handle that. `aion-context` emits the bytes.
- **Image index / multi-arch manifests**. Not needed for
  governance artifacts.
- **Legacy Docker Image Manifest v2**. OCI v1.1 only.
- **Signing the OCI manifest itself**. Signing is still DSSE
  (RFC-0023). OCI manifests are transport; cosign does image
  signing if the caller wants it.

## Proposal

### Reserved media types

```
application/vnd.aion.context.v2                    artifactType
application/vnd.aion.context.v2+binary             .aion file payload
application/vnd.aion.context.config.v1+json        config blob
```

For attached referrers we reuse payload types from earlier RFCs:

```
application/vnd.aion.attestation.v1+json           RFC-0023
application/vnd.aion.manifest.v1+json              RFC-0022 / RFC-0023
application/vnd.aion.aibom.v1+json                 RFC-0029
application/vnd.in-toto+json                       RFC-0024 SLSA
application/vnd.dev.sigstore.bundle+json;version=0.3   (future)
```

### OCI descriptor

```rust
pub struct OciDescriptor {
    pub media_type: String,
    pub digest: String,      // "sha256:<hex>"
    pub size: u64,
    pub annotations: BTreeMap<String, String>,
}
```

### OCI artifact manifest (Image Manifest v1.1)

```rust
pub struct OciArtifactManifest {
    pub schema_version: u32,    // always 2
    pub media_type: String,     // OCI_MANIFEST_MEDIA_TYPE
    pub artifact_type: Option<String>,
    pub config: OciDescriptor,
    pub layers: Vec<OciDescriptor>,
    pub subject: Option<OciDescriptor>,
    pub annotations: BTreeMap<String, String>,
}
```

### Aion config blob

The config blob is a small JSON document carrying aion-specific
metadata that's too structured for annotations. Lives inside the
manifest as `config.digest` pointing at its own SHA-256.

```rust
pub struct AionConfig {
    pub schema_version: String,     // "aion.oci.config.v1"
    pub format_version: u32,        // the .aion binary format version (2)
    pub file_id: u64,               // mirrors AionFile.file_id
    pub created_at_version: u64,
    pub created_at: String,         // RFC 3339 timestamp, informational only
}
```

### Builders

```rust
// src/oci.rs

pub const OCI_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
pub const AION_CONTEXT_ARTIFACT_TYPE: &str = "application/vnd.aion.context.v2";
pub const AION_CONTEXT_LAYER_MEDIA_TYPE: &str = "application/vnd.aion.context.v2+binary";
pub const AION_CONFIG_MEDIA_TYPE: &str = "application/vnd.aion.context.config.v1+json";

pub fn sha256_digest(bytes: &[u8]) -> String;    // "sha256:<lowercase-hex>"

pub fn build_aion_manifest(
    aion_bytes: &[u8],
    file_title: &str,
    config: &AionConfig,
) -> Result<OciArtifactManifest>;

/// Attach an attestation (DSSE envelope bytes) as a referrer to
/// `subject_manifest`.
pub fn build_attestation_manifest(
    envelope_json: &[u8],
    attestation_media_type: &str,
    subject_manifest: &OciArtifactManifest,
) -> Result<OciArtifactManifest>;

impl OciArtifactManifest {
    pub fn to_json(&self) -> Result<String>;
    pub fn canonical_bytes(&self) -> Result<Vec<u8>>;
    pub fn from_json(s: &str) -> Result<Self>;
    pub fn digest(&self) -> Result<String>;
}
```

### Example manifest — primary aion artifact

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.aion.context.v2",
  "config": {
    "mediaType": "application/vnd.aion.context.config.v1+json",
    "digest": "sha256:abc12...",
    "size": 187
  },
  "layers": [
    {
      "mediaType": "application/vnd.aion.context.v2+binary",
      "digest": "sha256:def34...",
      "size": 487123,
      "annotations": {
        "org.opencontainers.image.title": "rules.aion"
      }
    }
  ],
  "annotations": {
    "org.opencontainers.image.created": "2026-04-23T12:00:00Z",
    "dev.aion.format.version": "2"
  }
}
```

### Example manifest — attached AIBOM referrer

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.aion.aibom.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.empty.v1+json",
    "digest": "sha256:44136...",
    "size": 2
  },
  "layers": [
    {
      "mediaType": "application/vnd.aion.aibom.v1+json",
      "digest": "sha256:987...",
      "size": 3242
    }
  ],
  "subject": {
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "digest": "sha256:def34...",
    "size": 789
  }
}
```

The `subject` digest is the SHA-256 of the primary manifest's
canonical JSON bytes, letting the OCI Referrers API
(`GET /v2/{repo}/referrers/{digest}`) enumerate all attestations.

### Canonical JSON

- `#[derive(Serialize)]` in struct-declaration order.
- `BTreeMap<String, String>` for annotations gives sorted keys.
- Numbers emitted as JSON numbers (no leading zeros).
- No whitespace beyond `:` and `,`. We use default
  `serde_json::to_vec` for this.

### Edge Cases

- **Empty config**: OCI 1.1 allows `config.mediaType =
  "application/vnd.oci.empty.v1+json"` with a 2-byte `{}`
  payload. Used when no aion-specific config applies (e.g.
  attestation manifests).
- **Annotations with non-ASCII values**: allowed; JSON encodes
  as UTF-8.
- **Multiple layers**: permitted by the type; aion primary
  artifacts have exactly one layer (the `.aion` file).
  Attestation manifests also have exactly one layer (the DSSE
  envelope JSON).
- **Missing subject on a referrer**: subject is optional per
  OCI, but our builder for referrers makes it mandatory —
  caller cannot skip it.

## Rationale and Alternatives

### Why OCI Image Manifest v1.1 and not Artifact Manifest v1.0?

The dedicated Artifact Manifest spec (v1.0, 2023) was folded
back into Image Manifest v1.1 in mid-2023. Major registries
(ECR, GHCR, GAR, Harbor) support v1.1 artifactType today. v1.0
Artifact Manifests are deprecated; emitting them would create
tooling gaps.

### Why SHA-256 when aion uses BLAKE3 internally?

OCI spec mandates SHA-256 for layer/config digests. Cosign, ORAS,
every registry expects it. aion's content-addressed hashing
(manifest_id, audit-chain prev_hash, tree-head root_hash) stays
BLAKE3 per RFC-0002. The OCI digest is a transport hash, not a
content hash — they coexist fine.

### Why a separate config blob?

Annotations are limited to strings. Structured aion metadata
(format version, file_id, timestamps) fits a JSON config blob.
Plus: the config blob has its own SHA-256 digest and is
referenceable independently, which lets future tooling fetch
just the config to answer "what aion format version is this
artifact?" without pulling the full `.aion` bytes.

### Why not wrap DSSE envelopes in cosign's bundle format?

Future work. Cosign bundle (`application/vnd.dev.sigstore.bundle
+json;version=0.3`) wraps a DSSE envelope plus an optional
Rekor inclusion proof plus optional certificate chain. Phase C
adds this when we wire up Rekor and keyless signing.

## Security Considerations

### Threat Model

1. **Digest collision**: SHA-256 is collision-resistant; a
   registry that serves wrong bytes for a given digest is
   detected at pull time.
2. **Manifest tampering**: the primary manifest's SHA-256
   digest is what attached referrers commit to via `subject`.
   Any tampering breaks the referrer link.
3. **Layer substitution**: the `.aion` layer's SHA-256 is in
   the primary manifest. Substitution is detected at pull.
4. **Referrer forgery**: OCI registries don't authenticate
   referrers intrinsically — anyone who can push to the repo
   can attach any referrer. aion's security model is that
   attestations are DSSE-signed; the OCI layer is transport.
   A Kyverno/cosign policy must require a specific signer.

### Security Guarantees (for this RFC)

- **Content integrity on pull**: SHA-256 digests catch all
  byte tampering in transit or at rest.
- **Referrer linkage**: a valid `subject` digest cryptographically
  binds an attestation to its primary artifact.
- **Not a substitute for DSSE**: OCI manifests are *unsigned*
  containers. Actual trust comes from the DSSE envelope inside
  the layer.

## Performance Impact

- **SHA-256 over the full `.aion` bytes**: one-time cost at
  push; ~1-2 GB/s on commodity x86-64. A 500 MB `.aion` file
  hashes in ~300 ms.
- **Manifest JSON size**: ~400 bytes for a primary; ~600 bytes
  for a referrer. Negligible.

## Testing Strategy

### Property-Based Tests (Hegel, Tier-2)

Added to `.claude/rules/property-testing.md`:

- `prop_oci_manifest_json_roundtrip`: build → `to_json` →
  `from_json` equals the original.
- `prop_oci_manifest_digest_deterministic`: two `digest()`
  calls return identical strings.
- `prop_aion_primary_has_expected_media_types`: a primary
  manifest built via `build_aion_manifest` has `artifactType
  == AION_CONTEXT_ARTIFACT_TYPE` and its one layer has
  `mediaType == AION_CONTEXT_LAYER_MEDIA_TYPE`.
- `prop_aion_layer_size_matches_payload`: the layer's `size`
  equals the input aion bytes length.
- `prop_aion_layer_digest_matches_payload_sha256`: the layer's
  digest equals `sha256_digest(aion_bytes)`.
- `prop_attestation_manifest_subject_links_to_primary`: a
  referrer built via `build_attestation_manifest` has
  `subject.digest` equal to the primary manifest's `digest()`.
- `prop_oci_manifest_tamper_rejects_digest`: any byte flip in
  a manifest JSON produces a different digest.

### Vector Test

Hand-rolled: build a primary manifest from a fixed 16-byte aion
payload and a fixed AionConfig; assert the resulting JSON equals
a pre-computed string byte-for-byte.

## Implementation Plan

### Phase A (this RFC, this PR)

1. `src/oci.rs` with the full public API.
2. `pub mod oci;` in `src/lib.rs`.
3. Property tests per above.
4. Tier-2 floor + `/hegel-audit` update.

### Phase B

1. **ORAS thin wrapper**: `aion_context::oci::push(registry,
   repo, manifest, layers)` using `reqwest`, optional feature
   flag to avoid pulling HTTP deps by default.
2. **CLI**: `aion oci push`, `aion oci pull`, `aion oci attach`.
3. **Cosign bundle** (`application/vnd.dev.sigstore.bundle
   +json;version=0.3`) as an alternative attestation wrapper.
4. **OCI referrers API** client: enumerate attached
   attestations for a primary digest.

### Phase C

1. **Keyless** (Fulcio / Rekor) signing on push — cosign-style.
2. **Signed manifest lists** for multi-arch (model variants by
   quantization / hardware profile).
3. **Policy-aware admission** helpers for Kyverno / OPA
   Gatekeeper.

## Open Questions

1. Should empty configs use OCI's `empty.v1+json` sentinel
   digest (`sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe7
   7e8310c060f61caaff8a`)? Phase A answer: yes for attestation
   referrers; primary aion manifests always have a real
   AionConfig.
2. Should annotations include a BLAKE3 of the aion content
   alongside the OCI SHA-256? Phase A answer: no — duplicative
   and risks divergence. The `.aion` file itself carries its
   BLAKE3 integrity hash internally.

## References

- OCI Image Manifest v1.1:
  <https://github.com/opencontainers/image-spec/blob/main/manifest.md>
- OCI Distribution v1.1 Referrers API:
  <https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers>
- ORAS: <https://oras.land/>
- Cosign attach attestation:
  <https://docs.sigstore.dev/cosign/attestation/>
- Sigstore bundle v0.3:
  <https://github.com/sigstore/protobuf-specs>

## Appendix

### Terminology

- **Artifact** — any OCI manifest with `artifactType` set to a
  non-image media type.
- **Referrer** — an artifact whose `subject` points at another
  artifact. Used to attach attestations.
- **Primary** — the top-level aion artifact (not a referrer).
- **Layer digest** — SHA-256 hash of the layer bytes, prefixed
  with `sha256:`.
