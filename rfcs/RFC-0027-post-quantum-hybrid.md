# RFC 0027: Post-Quantum Hybrid Signatures (Ed25519 + ML-DSA-65)

- **Author:** aion-context maintainers
- **Status:** DRAFT
- **Created:** 2026-04-23
- **Updated:** 2026-04-23
- **Depends on:** RFC-0014 (multi-sig), RFC-0021 (attestation), RFC-0028 (key rotation)

## Abstract

Ed25519 — the Signature algorithm `aion-context` uses for every
version signature, attestation, manifest signature, rotation
record, revocation record, transparency-log tree head, and
hardware-attestation binding — is broken by Shor's algorithm on a
sufficiently large quantum computer. NIST finalized three
post-quantum signature schemes in 2024 (FIPS 204 **ML-DSA**, FIPS
205 **SLH-DSA**, and **FN-DSA**/Falcon forthcoming). Regulated
programs (NIST SP 800-208 / CNSA 2.0) now require a migration
plan and, in many cases, **hybrid** signing during the transition.

This RFC adds a hybrid-signature primitive: every signed artifact
can optionally carry both an Ed25519 signature and an ML-DSA-65
signature over a domain-separated message; a verifier accepts
only when **both** signatures verify. Hybrid mode gives defense in
depth against (a) quantum attacks (ML-DSA covers), (b) ML-DSA
cryptanalysis (Ed25519 covers), and (c) implementation bugs in
either backend.

Phase A, this RFC: the primitive, a new module, Hegel property
tests. No on-disk file-format change; hybrid signatures are new
in-memory types. Phase B integrates them into
`src/signature_chain.rs`, `src/multisig.rs`, and the RFC-0023
DSSE envelope as an alternative signing path.

## Motivation

### Problem Statement

Ed25519 alone is the right engineering choice today for
performance and size, but it is a one-algorithm bet. The moment a
cryptanalytic advance lands (classical or quantum), every
historical `.aion` signature is retroactively in question.
Auditors — especially for regulated AI model releases under
emerging quantum-safe mandates (CNSA 2.0 deadlines, EU AI Act
Article 15 security requirements) — will reject
single-algorithm signatures on any artifact expected to live past
~2028.

### Use Cases

- **Long-term attestation**: a model shipped in 2026 must still
  be verifiable in 2040 against the possibility of CRQCs.
- **Dual-algorithm compliance**: regulated industries that
  require "traditional + approved PQ" signatures during the
  migration window.
- **Defense in depth**: hedge against cryptanalysis of either
  Ed25519 or ML-DSA without re-signing existing artifacts.

### Goals

- A hybrid keypair type holding both Ed25519 and ML-DSA-65
  material.
- A hybrid-signature type carrying both signatures with
  algorithm identifiers.
- Verification requires **both** component signatures to verify.
- Domain separation from single-algorithm Ed25519 signatures.
- No change to the existing single-signer path — callers opt in
  to hybrid.
- Property-tested: tampering either component, either key, or
  the message breaks verification.

### Non-Goals

- **On-disk format change** (Phase B).
- **SLH-DSA / Falcon**. One PQ backend at a time; SLH-DSA is
  hash-based (larger, slower, different trade-offs) and is a
  separate RFC if demanded.
- **Key-encapsulation / PQ encryption**. Different primitive;
  orthogonal.
- **Ed448 or ECDSA-P384 as classical half**. Keeping Ed25519
  aligned with the rest of the crate.

## Proposal

### Algorithm choice

**Classical**: Ed25519 (same as existing aion crypto).

**Post-quantum**: ML-DSA-65 (aka Dilithium3 pre-standardization).
FIPS 204 finalized in August 2024. Security parameters:

| Tier      | Classical security | Signature size | Public key size |
|-----------|--------------------|----------------|-----------------|
| ML-DSA-44 | ~128-bit           | 2420 bytes     | 1312 bytes      |
| ML-DSA-65 | ~192-bit           | 3293 bytes     | 1952 bytes      |
| ML-DSA-87 | ~256-bit           | 4627 bytes     | 2592 bytes      |

ML-DSA-65 matches Ed25519's ~128-bit classical security tier with
headroom and is NIST's recommended long-term tier. Phase B may
expose the lower/higher tiers as caller choices.

### Canonical hybrid message

Both signatures sign the same domain-tagged message:

```
"AION_V2_HYBRID_V1\0" || payload
```

Using one domain separator (not one per algorithm) means neither
component signature is useful as a stand-alone aion signature:
the `AION_V2_HYBRID_V1` prefix is distinct from
`AION_V2_VERSION_SIGNATURE_V1` (RFC-0014),
`AION_V2_ATTESTATION_V1` (RFC-0021), `AION_V2_MANIFEST_V1`
(RFC-0022), `AION_V2_LOG_*` (RFC-0025),
`AION_V2_KEY_ATTESTATION_V1` (RFC-0026),
`AION_V2_ROTATION_V1`, `AION_V2_REVOCATION_V1` (RFC-0028).

### Types

```rust
#[repr(u16)]
pub enum PqAlgorithm {
    MlDsa65 = 1,
    // Reserved: MlDsa44 = 2, MlDsa87 = 3, SlhDsa128s = 4, ...
}

/// Classical + PQ keypair.
pub struct HybridSigningKey {
    pub classical: crate::crypto::SigningKey,
    pq_secret: Vec<u8>,   // ML-DSA secret key bytes (4032 for ML-DSA-65)
    pq_public: Vec<u8>,   // cached public key bytes
}

pub struct HybridVerifyingKey {
    pub classical: crate::crypto::VerifyingKey,
    pub pq_algorithm: PqAlgorithm,
    pub pq_public: Vec<u8>,
}

pub struct HybridSignature {
    pub algorithm: PqAlgorithm,
    pub classical: [u8; 64],          // Ed25519 signature
    pub pq: Vec<u8>,                  // ML-DSA signature bytes
}
```

### API

```rust
// src/hybrid_sig.rs

pub const HYBRID_DOMAIN: &[u8] = b"AION_V2_HYBRID_V1\0";

impl HybridSigningKey {
    pub fn generate() -> Self;
    pub fn from_classical(ed25519: SigningKey) -> Self; // generates PQ half
    pub fn verifying_key(&self) -> HybridVerifyingKey;
    pub fn sign(&self, payload: &[u8]) -> HybridSignature;
}

impl HybridVerifyingKey {
    pub fn verify(&self, payload: &[u8], sig: &HybridSignature) -> Result<()>;
}

pub fn canonical_hybrid_message(payload: &[u8]) -> Vec<u8>;
```

### Verification semantics

`HybridVerifyingKey::verify`:

1. Reject if `sig.algorithm != self.pq_algorithm`.
2. Compute `message = HYBRID_DOMAIN || payload`.
3. Verify the classical half: `self.classical.verify(&message, &sig.classical)?`.
4. Verify the PQ half: `pq_verify(&sig.pq, &message, &self.pq_public)?`.
5. Both must succeed. Either failure returns `Err`.

### Edge Cases

- **Empty payload**: allowed; domain prefix alone is 18 bytes of
  signed material.
- **Mismatched algorithm**: `sig.algorithm != verifying_key.pq_algorithm`
  → `Err` before any crypto runs.
- **Truncated PQ signature**: caught by the PQ library's own
  length check.
- **All-zero PQ key**: caught by the PQ library (invalid public
  key).

## Rationale and Alternatives

### Why ML-DSA over SLH-DSA (SPHINCS+)?

ML-DSA is ~60x smaller in signature size (3.3 KB vs ~8 KB for
SLH-DSA-128s) and ~100x faster to sign. SLH-DSA is stateless-hash-
based and has the conservative pedigree of Merkle trees over
classical hashes, but the size/speed cost makes it impractical
for per-version signing. If an ML-DSA cryptanalysis lands, a
follow-up RFC adds SLH-DSA as an alternative PQ backend.

### Why not a ternary hybrid (Ed25519 + ML-DSA + SLH-DSA)?

Each algorithm is independently a TCB entry and a maintenance
burden. Three simultaneous signatures per artifact triple the
signature bytes, key bytes, sign/verify cost, and attack surface.
Deferred.

### Why composite (both must verify) instead of threshold?

"Both must verify" gives strict defense-in-depth: breaking one
algorithm is not enough. A threshold ("either") would be strictly
weaker than the weakest algorithm — pointless for hybrid.

### Why `pqcrypto-mldsa` crate vs pure-Rust `ml-dsa`?

`pqcrypto-mldsa` (C reference implementation wrapped via FFI)
tracks the FIPS 204 reference directly and has received more
scrutiny. The pure-Rust `ml-dsa` crate is promising but at
pre-1.0 (0.1.0-rc.8) and the community has not yet completed
independent cryptographic review. When `ml-dsa` reaches 1.0 and
has third-party review, a follow-up PR can swap backends behind
the same module API (the public `HybridSigningKey` type does not
leak the crate choice).

## Security Considerations

### Threat Model

1. **CRQC on Ed25519**: a sufficiently large quantum computer
   breaks every Ed25519 signature. Mitigated — the attacker still
   needs a valid ML-DSA signature.
2. **ML-DSA cryptanalysis**: a novel lattice attack breaks ML-DSA.
   Mitigated — the attacker still needs a valid Ed25519
   signature.
3. **Nonce-reuse attack on Ed25519 (e.g. bad RNG)**: mitigated —
   ML-DSA's deterministic-nonce signing is unaffected.
4. **Implementation bug in either backend**: mitigated — a bug
   that lets one signature verify without knowledge of the secret
   still requires the other half to verify.
5. **Cross-algorithm confusion (attacker reuses a single-algorithm
   sig as hybrid)**: blocked — the domain separator
   `AION_V2_HYBRID_V1` makes the signed message distinct from
   every other domain in the crate.
6. **Truncation (attacker drops the PQ half to save bytes)**:
   blocked — `HybridSignature::pq` is mandatory; verification
   fails on missing bytes.

### Security Guarantees

- **Algorithm independence**: forgery requires breaking *both*
  Ed25519 and ML-DSA-65.
- **Domain separation**: hybrid signatures cannot be replayed as
  any other signed aion object.
- **Algorithm-agile**: the `PqAlgorithm` discriminant leaves
  headroom for future migration (ML-DSA-87, SLH-DSA, hybrid
  multi-PQ).

## Performance Impact

- **Keygen**: Ed25519 ~μs + ML-DSA-65 ~100 μs.
- **Sign**: Ed25519 ~μs + ML-DSA-65 ~200 μs. ~30x classical.
- **Verify**: Ed25519 ~50 μs + ML-DSA-65 ~70 μs. ~2x classical.
- **Signature size**: 64 (Ed25519) + 3293 (ML-DSA-65) + ~8
  (algorithm ID + length prefix) ≈ **3.4 KB** per signature.
- **Public key size**: 32 (Ed25519) + 1952 (ML-DSA-65) ≈ **2 KB**.

All well within practical budget for governance artifacts. A
1 GB model with 10 hybrid signatures is 34 KB of signature
bytes — noise.

## Testing Strategy

### Property-Based Tests (Hegel, Tier-2)

Added to `.claude/rules/property-testing.md`:

- `prop_hybrid_sign_verify_roundtrip`: for any payload, sign and
  verify is `Ok`.
- `prop_hybrid_tampered_payload_rejects`: flipping any byte in
  the payload → `Err`.
- `prop_hybrid_wrong_classical_key_rejects`: verifying-key with a
  substituted Ed25519 half → `Err`.
- `prop_hybrid_wrong_pq_key_rejects`: verifying-key with a
  substituted ML-DSA half → `Err`.
- `prop_hybrid_corrupted_classical_sig_rejects`: flipping a byte
  in the classical signature → `Err`.
- `prop_hybrid_corrupted_pq_sig_rejects`: flipping a byte in the
  PQ signature → `Err`.
- `prop_hybrid_domain_separated_from_plain_ed25519`: an Ed25519
  signature over `payload` (no HYBRID_DOMAIN) must not verify
  when plugged into a `HybridSignature`.
- `prop_hybrid_algorithm_mismatch_rejects`: a `HybridSignature`
  whose `algorithm` field disagrees with the key → `Err`.

### Vector Test

Hand-rolled round-trip with a fixed RNG seed, asserting that the
Ed25519 public key, ML-DSA public key, and both signature
lengths are the FIPS-204 / RFC-8032 expected sizes.

## Implementation Plan

### Phase A (this RFC, this PR)

1. Add `pqcrypto-mldsa = "0.1"` and `pqcrypto-traits = "0.3"`
   (both MIT/Apache-2.0).
2. `src/hybrid_sig.rs` with the public API above.
3. `pub mod hybrid_sig;` in `src/lib.rs`.
4. Property tests + vector test.
5. Tier-2 floor + `/hegel-audit` update.

### Phase B

1. Extend `SignatureEntry` (new section in on-disk format v3)
   with an optional `hybrid` variant that carries the full
   hybrid signature.
2. `sign_version_hybrid` / `verify_signature_hybrid` parallels in
   `src/signature_chain.rs`.
3. RFC-0021 attestation path gains a hybrid variant.
4. RFC-0023 DSSE envelope with `application/vnd.aion.hybrid+json`
   carrying algorithm ID + base64 both-sigs.
5. Hybrid mode for rotation/revocation records (RFC-0028).

### Phase C

1. Swap `pqcrypto-mldsa` for pure-Rust `ml-dsa` when it reaches
   1.0 and has third-party audit.
2. Add SLH-DSA as an alternative PQ backend.
3. Consider zkSNARKed hybrid attestation for compressed
   multi-sig.

## Open Questions

1. Should hybrid keys have independent rotation epochs (one
   could rotate only the PQ half)? Phase A: no; the hybrid is
   atomic. If a bug mandates rotating only one half, that's an
   emergency-response RFC.
2. Should we support signing with only one algorithm "for testing"?
   Phase A: no; every `HybridSigningKey::sign` produces both.
   Callers who want a single-algorithm sig use the existing APIs.

## References

- FIPS 204 — Module-Lattice-Based Digital Signature Standard:
  <https://csrc.nist.gov/pubs/fips/204/final>
- NIST SP 800-208 — Recommendation for Stateful Hash-Based
  Signature Schemes.
- CNSA 2.0 — Commercial National Security Algorithm Suite:
  <https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF>
- `pqcrypto-mldsa` crate: <https://docs.rs/pqcrypto-mldsa>
- Hybrid signatures prior art: OpenSSH `sntrup761x25519`, Open
  Quantum Safe `liboqs-rust`.

## Appendix

### Terminology

- **Hybrid signature**: a pair of signatures (one classical, one
  PQ) over the same message; both must verify.
- **CRQC**: Cryptographically Relevant Quantum Computer — one
  capable of running Shor's algorithm at sizes that break
  256-bit ECC.
- **ML-DSA-65**: the 192-bit-classical-security parameter set of
  FIPS 204 ML-DSA. Was CRYSTALS-Dilithium-3 pre-standardization.
