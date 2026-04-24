# RFC 0023: DSSE Envelope Support

- **Author:** aion-context maintainers
- **Status:** DRAFT
- **Created:** 2026-04-23
- **Updated:** 2026-04-23
- **Depends on:** RFC-0021 (attestation), RFC-0022 (manifest)

## Abstract

Every mature model-signing / supply-chain toolchain in 2026 speaks
**DSSE** — the Dead Simple Signing Envelope from the Secure Systems
Lab. Sigstore/cosign, in-toto, SLSA provenance verifiers, Kyverno
admission controllers, and every major OCI registry attestation
workflow expect DSSE envelopes on the wire. Today `aion-context`
produces its own binary `SignatureEntry` bytes, which nothing
outside this crate can consume.

This RFC adds a DSSE envelope layer that can **emit** and **verify**
aion signatures in the canonical DSSE JSON format. The underlying
Ed25519 signatures still come from `aion_context::crypto::SigningKey`
— only the *wire format* changes. DSSE's native multi-signature
support maps directly onto RFC-0021 multi-party attestations.

## Motivation

### Problem Statement

An `.aion` file today is a standalone binary artifact. To interop
with the rest of the supply-chain ecosystem we must be able to:

1. Emit a DSSE-wrapped JSON envelope carrying an aion version
   attestation (RFC-0021) that cosign/Kyverno/sigstore-policy-
   controller can consume with no aion-specific code.
2. Emit a DSSE-wrapped JSON envelope carrying an aion manifest
   (RFC-0022) so a CI system can verify an external artifact hash
   against the signed manifest using standard tooling.
3. Ingest DSSE envelopes produced by external tools and verify them
   against pinned `aion_context::crypto::VerifyingKey` instances.

### Use Cases

- **Attach-to-OCI**: push an `.aion` file alongside a model into
  an OCI registry, then attach a DSSE attestation via
  `cosign attach attestation --predicate ...`.
- **Admission control**: Kyverno / OPA / Gatekeeper policies that
  accept only DSSE-verified artifacts can now accept aion
  attestations.
- **Air-gapped verification**: a DSSE envelope + a pinned
  `VerifyingKey` is enough to verify offline — no network, no
  Rekor, no OIDC.
- **Multi-party attestation wire format**: RFC-0021 produces N
  attestations; DSSE natively carries N signatures in one envelope
  `signatures: [...]` array. Clean mapping.

### Goals

- **Byte-for-byte DSSE compliance** — any compliant verifier
  accepts aion envelopes.
- **Round-trip stability** — `from_json(to_json(e)) == e` for every
  envelope.
- **Multi-signature native** — a single envelope carries N
  signatures from distinct signers.
- **No new crypto** — reuses Ed25519 from `aion_context::crypto`.
- **No on-disk format change** — DSSE is a parallel transport.

### Non-Goals

- **Full in-toto predicate framework.** This RFC ships the DSSE
  envelope; in-toto Statement wrapping and SLSA provenance
  predicates are RFC-0024's scope.
- **Certificate chains / keyless signing (Fulcio).** Phase A uses
  pinned public keys; keyless is a separate RFC.
- **COSE envelopes.** Different ecosystem; not needed for the
  NVIDIA/Microsoft room today.

## Proposal

### DSSE recap (spec: <https://github.com/secure-systems-lab/dsse>)

An envelope is JSON:

```json
{
  "payloadType": "application/vnd.aion.attestation.v1+json",
  "payload": "<base64-standard-no-padding(payload_bytes)>",
  "signatures": [
    {
      "keyid": "aion:author:50001",
      "sig": "<base64-standard-no-padding(raw_signature_bytes)>"
    }
  ]
}
```

Signatures are computed over the **PAE** (Pre-Authentication
Encoding), not the base64:

```
PAE(type, body) = UTF8("DSSEv1") || SP || UTF8(LEN(type)) || SP
               || UTF8(type)     || SP || UTF8(LEN(body)) || SP
               || body
```

where `SP = 0x20` and `LEN(x)` is ASCII-decimal of `x.len()` in
bytes. `type` is UTF-8; `body` is raw bytes (typically JSON).

### Aion payload types

| URI                                               | Body shape (JSON)                                       |
|---------------------------------------------------|---------------------------------------------------------|
| `application/vnd.aion.attestation.v1+json`        | `{_type, version, signer}` — see below                  |
| `application/vnd.aion.manifest.v1+json`           | `{_type, manifest_id, entries}`                         |

Both bodies begin with an `_type` URI so recipients can dispatch
without parsing the full payload:

```json
// attestation body
{
  "_type": "https://aion-context.dev/attestation/v1",
  "version": {
    "version_number": 1,
    "parent_hash": "00...",      // 64 hex
    "rules_hash": "ab...",       // 64 hex
    "author_id": 50001,
    "timestamp": 1700000000000000000,
    "message_offset": 0,
    "message_length": 15
  },
  "signer": 50001
}

// manifest body
{
  "_type": "https://aion-context.dev/manifest/v1",
  "manifest_id": "cd...",
  "entries": [
    {
      "name": "model.safetensors",
      "size": 487123456,
      "hash_algorithm": "BLAKE3-256",
      "hash": "ef..."
    }
  ]
}
```

JSON fields use `snake_case` to match the rest of the aion API;
this is non-standard for in-toto (camelCase). RFC-0024 reconciles
this by wrapping aion payloads in an in-toto Statement that uses
in-toto's conventions at the outer layer.

### Keyid construction

```
keyid = "aion:author:" + decimal(author_id)
```

Deliberately simple. No public-key hash prefix (keeps `AuthorId` as
the canonical key identifier). When key rotation lands (RFC-0028),
this extends to `aion:author:<id>:key:<rotation_epoch>`.

### Public API

```rust
// src/dsse.rs

pub const DSSE_PREAMBLE: &str = "DSSEv1";
pub const AION_ATTESTATION_TYPE: &str = "application/vnd.aion.attestation.v1+json";
pub const AION_MANIFEST_TYPE: &str = "application/vnd.aion.manifest.v1+json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DsseEnvelope {
    pub payload_type: String,
    pub payload: Vec<u8>,               // raw bytes; JSON ser/de handles base64
    pub signatures: Vec<DsseSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DsseSignature {
    pub keyid: String,
    pub sig: Vec<u8>,
}

// PAE encoding (public for testing / interop)
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8>;

// Envelope lifecycle
pub fn sign_envelope(
    payload: &[u8],
    payload_type: &str,
    signer: AuthorId,
    key: &SigningKey,
) -> DsseEnvelope;

pub fn add_signature(
    envelope: &mut DsseEnvelope,
    signer: AuthorId,
    key: &SigningKey,
) -> Result<()>;

/// Verify every signature in the envelope against the supplied key
/// lookup. Returns the list of keyids that verified. An empty envelope
/// or a missing key for a keyid is an error.
pub fn verify_envelope<F>(envelope: &DsseEnvelope, key_for: F) -> Result<Vec<String>>
where
    F: Fn(&str) -> Option<VerifyingKey>;

// JSON wire format
impl DsseEnvelope {
    pub fn to_json(&self) -> Result<String>;
    pub fn from_json(s: &str) -> Result<Self>;
}

// Aion-native payload constructors
pub fn version_attestation_payload(version: &VersionEntry, signer: AuthorId) -> Vec<u8>;
pub fn manifest_payload(manifest: &ArtifactManifest) -> Vec<u8>;

// Sugar helpers
pub fn wrap_version_attestation(
    version: &VersionEntry,
    signer: AuthorId,
    key: &SigningKey,
) -> DsseEnvelope;

pub fn wrap_manifest(
    manifest: &ArtifactManifest,
    signer: AuthorId,
    key: &SigningKey,
) -> DsseEnvelope;
```

### Verification semantics

`verify_envelope`:

1. Compute `message = pae(envelope.payload_type, &envelope.payload)`.
2. For each `sig` in envelope.signatures:
   a. `verifying_key = key_for(&sig.keyid)?` — absent key ⇒ Err.
   b. `verifying_key.verify(&message, sig.sig.as_slice())?` — Err
      on any failure.
   c. On success, push `sig.keyid.clone()` into the result.
3. Return the list of verified keyids (in envelope order).

Any failure is hard: we do not return partial success. Callers
that want partial-tolerance can iterate signatures themselves.

### JSON serialization

base64-standard, no padding, per DSSE spec. `payload` and `sig`
are the only fields that are base64 on the wire; other fields are
plain strings. Serde wrappers handle encode/decode transparently.

### Edge Cases

- **Empty payload**: allowed; PAE still produces `DSSEv1 <type_len>
  <type> 0 `.
- **Empty signatures array**: `verify_envelope` returns Err
  (nothing to verify is not valid).
- **Duplicate keyids**: allowed; each verified independently and
  each appears in the returned list once.
- **payload_type longer than 256 bytes**: allowed (DSSE has no
  length cap); PAE includes a length prefix.
- **Non-UTF-8 payload_type**: rejected at JSON deserialization
  (serde's Deserialize for String enforces UTF-8).

## Rationale and Alternatives

### Why DSSE and not JWS?

JWS (JSON Web Signatures) is the alternative. DSSE was designed
*because* JWS composes poorly for supply-chain use cases:

- JWS puts the signed payload inside the JWT (base64url-encoded),
  which fights with large payloads.
- JWS's canonicalization story for JSON headers is ambiguous; PAE
  is explicit byte-for-byte.
- The entire Sigstore / in-toto / SLSA stack is DSSE-native. JWS
  would leave us isolated.

### Why not COSE?

COSE is the other major envelope format (used in IETF SCITT,
WebAuthn attestation). Valuable but different ecosystem — the room
this RFC is written for runs DSSE. COSE support is a future RFC.

### Why raw Ed25519 and not PKIX-wrapped?

DSSE's signature field is algorithm-agnostic — it's just bytes.
Consumers look up the verification algorithm from the keyid or out
of band. Keeping the signature bytes raw Ed25519 (32-byte R + 32-byte
S) matches `aion_context::crypto::SigningKey::sign` and lets every
existing verification path reuse.

### Why in-source JSON instead of an IDL?

The DSSE JSON shape is 3 fields deep. Hand-written serde derives
are ~10 lines; an IDL-generated layer would be heavier and give us
nothing. If we grow to dozens of payload types we revisit.

## Security Considerations

### Threat Model

1. **Payload tampering**: attacker modifies the base64 payload on
   the wire. Detected — PAE changes, signature fails.
2. **Payload type confusion**: attacker relabels a manifest
   envelope as an attestation envelope. Detected — payloadType is
   inside PAE, so signature fails.
3. **Signature substitution**: attacker swaps a valid signature
   for another. Detected — signatures are over PAE and tied to the
   signer's keyid.
4. **Keyid remapping**: attacker changes the keyid in the envelope
   to point to a different public key. Mitigation: the keyid is
   inside the JSON but *not* inside PAE, so the signature still
   verifies against the original key. `verify_envelope` uses the
   keyid only to select the pinned key — if the attacker remaps
   to a different legitimate signer's keyid, verification fails
   (because that key's signature is different). If they remap to a
   keyid that has no pinned key, verification fails.
5. **Replay across envelopes**: a signature over envelope A is
   copied into envelope B with the same payload. Mitigation: PAE
   is deterministic over (payloadType, payload), so if A and B
   have the same payloadType and payload, the signature IS valid
   on both — by design. This is not an attack; it is DSSE's
   identity semantics. Applications that require single-use
   envelopes include a nonce or monotonic counter in the payload.

### Security Guarantees

- **Payload integrity** — any modification to the body or
  payloadType invalidates every signature.
- **Signer authenticity** — a verifying signature proves the
  holder of the pinned private key produced the envelope.
- **Multi-party agreement** — when an envelope carries N
  signatures and all N verify, all N signers independently
  committed to the exact same (payloadType, payload) bytes.

## Performance Impact

- **Signing**: 1 Ed25519 sign + 1 base64 encode of the sig + 1
  SHA-agnostic PAE build. Sub-millisecond for typical payloads.
- **Verifying**: N × (1 Ed25519 verify). ~75 µs per sig on
  commodity x86-64.
- **JSON ser/de**: dominated by base64. For a 1 MB payload (rare;
  aion manifests are kilobytes), ~3 ms encode.

## Testing Strategy

### Property-Based Tests (Hegel, Tier-2)

Added to `.claude/rules/property-testing.md`:

- `prop_dsse_sign_verify_roundtrip`: for any payload and
  payload_type, `sign_envelope` → `verify_envelope` is `Ok`.
- `prop_dsse_tampered_payload_rejects`: flipping any byte in the
  payload causes verification to fail.
- `prop_dsse_tampered_payload_type_rejects`: any change to
  `payload_type` causes verification to fail.
- `prop_dsse_wrong_key_rejects`: supplying a different public
  key for the keyid causes verification to fail.
- `prop_dsse_json_roundtrip`: `from_json(to_json(env)) == env`.
- `prop_dsse_multi_signature_all_verify`: N distinct signers
  added via `add_signature`; `verify_envelope` returns all N
  keyids.
- `prop_dsse_pae_injective_on_type_and_body`: two distinct
  (type, body) pairs produce distinct PAE outputs.

### Vector Tests (from DSSE spec)

At least one hand-rolled test with a fixed payload and a
fixed key material, checking the exact PAE bytes and the exact
base64 encoding match the DSSE spec examples. Catches any drift
from the reference implementation.

## Implementation Plan

### Phase A (this RFC, this PR)

1. `base64 = "0.22"` dep.
2. `src/dsse.rs` with the full public API listed above.
3. `pub mod dsse;` in `src/lib.rs`.
4. Property tests + vector tests per above.
5. Tier-2 floor + `/hegel-audit` update.

### Phase B (future)

1. **CLI**: `aion attest --dsse <version_id>`, `aion verify-dsse
   <envelope.json>`, `aion manifest sign --dsse`.
2. **RFC-0024**: wrap aion payloads in in-toto Statements so
   slsa-verifier and cosign's built-in predicates accept them.
3. **Transparency log** (RFC-0025): submit envelopes to Rekor;
   verify inclusion proofs.

## Open Questions

1. Should `verify_envelope` require *all* signatures valid, or
   accept a threshold? Phase A answer: all-or-nothing. Callers
   that want thresholds loop manually. (Matches DSSE's own
   semantics.)
2. Should keyids be canonicalized (e.g. always lowercase)?
   Phase A answer: treat as opaque strings, byte-exact compare.

## References

- DSSE spec: <https://github.com/secure-systems-lab/dsse>
- DSSE protocol: <https://github.com/secure-systems-lab/dsse/blob/master/protocol.md>
- in-toto Statement: <https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md>
- SLSA v1.1 provenance: <https://slsa.dev/spec/v1.1/provenance>
- Sigstore model-signing discussion: <https://github.com/sigstore/model-transparency>

## Appendix

### Vector test — PAE of "hello"

```
payload_type = "test"
payload      = "hello"

PAE = "DSSEv1 4 test 5 hello"
     = 44 53 53 45 76 31 20 34 20 74 65 73 74 20 35 20 68 65 6c 6c 6f
```

An Ed25519 sign over those 21 bytes is the DSSE signature.

### Terminology

- **PAE** — Pre-Authentication Encoding. The deterministic byte
  string the signer signs (NOT the base64 on the wire).
- **payloadType** — URI identifying the body's schema. Signed.
- **keyid** — opaque string identifying the public key. Not
  signed; used only for key lookup.
- **Envelope** — the JSON object carrying `(payloadType, payload,
  signatures[])`.
