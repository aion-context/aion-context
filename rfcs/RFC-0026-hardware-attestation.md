# RFC 0026: Hardware Attestation Binding

- **Author:** aion-context maintainers
- **Status:** DRAFT
- **Created:** 2026-04-23
- **Updated:** 2026-04-23
- **Depends on:** RFC-0028 (key rotation + master keys)

## Abstract

For confidential-compute deployments — NVIDIA H100 Confidential
Compute, Intel TDX, AMD SEV-SNP, AWS Nitro Enclaves, Arm CCA —
the critical question is *not* "did you sign this?" but "did you
sign this **inside a trusted execution environment**?" The answer
is a hardware attestation quote: a TEE-rooted signature over the
enclave measurement plus a caller-provided payload (typically the
public key being attested).

This RFC adds a `KeyAttestationBinding` — a signed record that
ties a specific aion operational-key epoch to a specific TEE
quote. The quote itself is a platform-specific byte blob (TPM2
`TPMS_ATTEST`, NVIDIA NRAS JWT, SEV-SNP report, TDX quote, …);
aion-context does not verify TEE quotes directly. Instead:

1. The binding carries the quote bytes plus metadata.
2. The author's master key signs a canonical message that commits
   to `(author, epoch, pubkey, kind, nonce, blake3(evidence))`.
3. An `EvidenceVerifier` trait lets callers delegate the
   platform-specific quote-validation step to an external library
   (e.g. `tpm2-tss`, NVIDIA's `nvtrust`, AMD's SNP guest/host
   tooling, Microsoft's Azure Attestation SDK).

The binding is a **first-class, signable record** — it can ride
inside a `.aion` file, be DSSE-wrapped (RFC-0023) for transport,
or be appended to the transparency log (RFC-0025) so auditors can
replay "this key was attested by this TEE at this version."

## Motivation

### Problem Statement

In the NVIDIA/Microsoft room the first question after RFC-0028
key rotation is:

> "How do we know the signing key was never exfiltrated? How do
> we know it lives in an H100 Confidential Compute enclave and
> not on an analyst's laptop?"

Today aion has no answer. `aion_context::crypto::SigningKey` is
just 32 bytes of Ed25519 seed — it may have been generated in an
HSM, in a TEE, or in a Python notebook. The file format gives no
way to distinguish.

### Use Cases

- **NVIDIA NIM release attestation**: a model container is
  signed by a key that lives inside an H100 CC TEE; the
  KeyAttestationBinding carries an NRAS token proving the key
  was minted in a CC GPU.
- **Azure Confidential VM**: signing key is generated inside a
  TDX or SEV-SNP CVM; the binding carries the platform report
  from Azure Attestation.
- **AWS Nitro model-signing CI**: signing key is generated
  inside a Nitro Enclave; binding carries a signed
  AttestationDocument.
- **Compliance**: an auditor retrieves a binding for a key epoch
  and verifies out-of-band that the TEE root-of-trust signed the
  quote, that the quote's measurements match an approved build,
  and that the pubkey inside the quote matches the epoch.

### Goals

- Carry arbitrary TEE quote bytes with metadata (kind, nonce).
- Bind the quote to a specific `(author_id, epoch, public_key)`
  triple with a master-key signature.
- Domain-separate the binding message from every other aion
  signed object.
- Extensible: new attestation kinds can be added without a
  format change.
- Offline verifiable by the master-signature path; platform
  quote validation is deferred to callers.

### Non-Goals

- **Implementing TPM2, NRAS, SEV-SNP, TDX quote validation**.
  These are multi-thousand-line libraries that exist already;
  re-implementing them would be malpractice. The
  `EvidenceVerifier` trait lets callers plug them in.
- **Trusted root certificate distribution**. Also out of scope;
  every TEE vendor has their own cert distribution (Intel PCS,
  NVIDIA NRAS, AMD root cert chain). Callers configure these.
- **Remote attestation protocols (RATS, SCITT)**. These are
  adjacent; aion-context can *carry* evidence collected via
  RATS but doesn't speak the protocol.

## Proposal

### Canonical message

```
"AION_V2_KEY_ATTESTATION_V1"        27 bytes (domain separator)
LE64(author_id)                      8
LE32(epoch)                          4
public_key                          32
LE16(kind)                           2
nonce                               32
BLAKE3(evidence)                    32
                                   ────
                                   137 bytes
```

Signed by the author's master key (same key that authorizes
rotations/revocations in RFC-0028). Using `BLAKE3(evidence)` in
the signed message keeps the master-signed bytes bounded; a TPM2
quote can be 1-3 KB and an Azure Attestation JWT can be 10+ KB.

### Types

```rust
#[repr(u16)]
pub enum AttestationKind {
    Tpm2Quote        = 1,
    NvidiaNras       = 2,
    AmdSevSnp        = 3,
    IntelTdxReport   = 4,
    IntelSgxReport   = 5,
    AwsNitroEnclave  = 6,
    ArmCca           = 7,
    AzureAttestation = 8,
    Custom           = 0xFFFF,
}

pub struct AttestationEvidence {
    pub kind: AttestationKind,
    pub nonce: [u8; 32],
    pub evidence: Vec<u8>,
}

pub struct KeyAttestationBinding {
    pub author_id: AuthorId,
    pub epoch: u32,
    pub public_key: [u8; 32],
    pub evidence: AttestationEvidence,
    pub master_signature: [u8; 64],
}
```

### API

```rust
// src/hw_attestation.rs

pub const HW_ATTESTATION_DOMAIN: &[u8] = b"AION_V2_KEY_ATTESTATION_V1";

pub fn canonical_binding_message(binding: &KeyAttestationBinding) -> Vec<u8>;

pub fn sign_binding(
    author: AuthorId,
    epoch: u32,
    public_key: [u8; 32],
    evidence: AttestationEvidence,
    master_key: &SigningKey,
) -> KeyAttestationBinding;

pub fn verify_binding_signature(
    binding: &KeyAttestationBinding,
    master_verifying_key: &VerifyingKey,
) -> Result<()>;

/// Trait for platform-specific evidence validation. Implementations
/// verify the TEE quote's own internal signatures, check the
/// enclave measurements against a policy, and confirm that the
/// quote includes `expected_pubkey`.
pub trait EvidenceVerifier {
    fn verify(
        &self,
        evidence: &AttestationEvidence,
        expected_pubkey: &[u8; 32],
    ) -> Result<()>;
}

/// Testing verifier that unconditionally accepts.
pub struct AcceptAllEvidenceVerifier;
/// Testing verifier that unconditionally rejects.
pub struct RejectAllEvidenceVerifier;
/// Testing verifier that accepts iff `expected_pubkey` is a
/// byte-prefix of `evidence.evidence` — a minimal model of "the
/// quote contains the public key."
pub struct PubkeyPrefixEvidenceVerifier;

/// Full binding verification: master signature + platform
/// evidence check (delegated to `verifier`).
pub fn verify_binding<V: EvidenceVerifier>(
    binding: &KeyAttestationBinding,
    master_verifying_key: &VerifyingKey,
    verifier: &V,
) -> Result<()>;
```

### Verification semantics

`verify_binding_signature`:

1. Rebuild canonical message from the binding fields (including
   `BLAKE3(evidence)`).
2. Call `master_verifying_key.verify(&message, &binding.master_signature)`.

`verify_binding`:

1. `verify_binding_signature(...)`.
2. `verifier.verify(&binding.evidence, &binding.public_key)`.

Callers that don't yet have a platform verifier can call
`verify_binding_signature` alone and delegate platform validation
separately.

### Integration with RFC-0028 KeyRegistry

Phase B will add a method:

```rust
impl KeyRegistry {
    pub fn attach_attestation(
        &mut self,
        binding: KeyAttestationBinding,
    ) -> Result<()>;

    pub fn attestation_for(
        &self,
        author: AuthorId,
        epoch: u32,
    ) -> Option<&KeyAttestationBinding>;
}
```

So a policy can require "every epoch must carry an attestation
binding verified against an approved TEE configuration."

### Edge Cases

- **Empty evidence**: allowed; `BLAKE3(b"")` is a well-defined
  32-byte hash. Platform verifier will presumably reject.
- **Unknown kind**: caller submits `Custom`; the master signature
  still binds the evidence bytes. Platform verifier is
  responsible for interpreting custom kinds.
- **Extremely large evidence (MB-scale)**: allowed at the type
  level; serialization cost is the caller's problem. Transparency
  log entries should consider chunked representation.
- **Nonce collision**: not an attack (nonce is signer-chosen
  freshness data; the TEE quote ties its interior nonce to the
  pubkey via the measurement).

## Rationale and Alternatives

### Why a trait instead of pluggable backends?

A trait keeps aion-context free of platform dependencies. Adding
`tpm2-tss` as a mandatory dep would mean every aion consumer
pulls in a 40 MB transitive closure and needs libtpms at build
time — unacceptable.

### Why hash the evidence?

Keeps the signed message bounded (137 bytes). Signature size and
cost is constant regardless of quote size. Trade-off: the
verifier needs the full evidence bytes anyway to run the platform
check, so we don't save transmission — only signing/verifying
cost.

### Why master-key signed, not operational-key signed?

The binding authorizes the operational key. An operational key
cannot authorize itself — the whole point of the two-tier model
(RFC-0028). The master key attests "this operational key lives
in this TEE."

### Why not use DSSE directly as the binding envelope?

DSSE (RFC-0023) is a transport layer. The binding is a *data
structure* that can be DSSE-wrapped for transport, log-
published, or embedded in a `.aion` file. Conflating them would
conflate "what's being committed to" with "how it's being
shipped."

## Security Considerations

### Threat Model

1. **Evidence tampering**: attacker modifies the evidence bytes.
   Blocked — `BLAKE3(evidence)` in the signed message no longer
   matches; master signature verification fails.
2. **Pubkey substitution**: attacker swaps `public_key` in the
   binding. Blocked — master signature was over the original
   pubkey; verification fails. Separately, the TEE quote binds to
   a specific pubkey, so a mismatched pubkey fails platform
   verification too.
3. **Replay across authors**: attacker lifts a binding from
   author A to author B. Blocked — `author_id` is in the signed
   message; verification fails.
4. **Replay across epochs**: attacker uses a binding for epoch 0
   to claim attestation of epoch 1. Blocked — `epoch` is in the
   signed message.
5. **Replay across sessions**: `nonce` is chosen per binding; a
   TEE quote typically includes the nonce in its signed
   measurement, so reusing a nonce fails platform verification.
6. **Master-key compromise**: out of scope for this RFC (see
   RFC-0028 master-key hierarchy future work).
7. **TEE root-of-trust compromise**: out of scope; the platform
   vendor's cert distribution is the TCB.

### Security Guarantees

- **Authenticity**: a verifying binding proves the holder of the
  master key signed exactly this `(author, epoch, pubkey,
  kind, nonce, evidence_hash)` tuple.
- **Key-to-TEE binding**: when combined with a platform verifier
  that confirms the TEE quote includes `public_key`, the binding
  proves the pubkey was materially present inside the TEE at
  quote time.
- **Replay resistance**: across authors, epochs, and (via nonce)
  sessions.

## Performance Impact

- **Sign**: 1 BLAKE3 over evidence + 1 Ed25519 sign. ~microseconds
  for typical evidence sizes.
- **Verify** (signature only): 1 BLAKE3 + 1 Ed25519 verify.
- **Platform verifier cost**: entirely the verifier's budget;
  typical TPM2 quote validation runs in single-digit
  milliseconds.

## Testing Strategy

### Property-Based Tests (Hegel, Tier-2)

Added to `.claude/rules/property-testing.md`:

- `prop_binding_signature_roundtrip`: any binding produced by
  `sign_binding` verifies under `verify_binding_signature`.
- `prop_binding_rejects_wrong_master`: verification under a
  different master key fails.
- `prop_binding_rejects_tampered_evidence`: flipping any byte in
  `evidence.evidence` → verification fails.
- `prop_binding_rejects_tampered_pubkey`: swapping the
  `public_key` field → verification fails.
- `prop_binding_rejects_tampered_nonce`: swapping the `nonce`
  field → verification fails.
- `prop_binding_rejects_tampered_author_or_epoch`: any mutation
  of `author_id` or `epoch` → verification fails.
- `prop_verify_binding_accept_all_ok`: `AcceptAllEvidenceVerifier`
  + signature Ok → `verify_binding` returns Ok.
- `prop_verify_binding_reject_all_err`: `RejectAllEvidenceVerifier`
  + signature Ok → `verify_binding` returns Err.
- `prop_pubkey_prefix_verifier_matches_prefix`: evidence starting
  with the pubkey bytes → accept; otherwise reject.

## Implementation Plan

### Phase A (this RFC, this PR)

1. `src/hw_attestation.rs` with the full public API.
2. `pub mod hw_attestation;` in `src/lib.rs`.
3. Property tests + mock verifiers.
4. Tier-2 floor + `/hegel-audit` update.

### Phase B

1. `KeyRegistry::attach_attestation` + policy helpers.
2. Transparency-log entry kind for `KeyAttestationBinding`.
3. DSSE wrapper for transport.

### Phase C (per-platform verifiers)

1. `hw-attestation-tpm2` crate — depends on `tpm2-tss` /
   `tss-esapi`.
2. `hw-attestation-nvidia` crate — depends on `nvtrust` FFI.
3. `hw-attestation-amd-sev` / `hw-attestation-intel-tdx` / etc.

Separate crates so aion-context itself stays
platform-agnostic and dependency-light.

## Open Questions

1. Should the binding carry a `not_before` / `not_after`
   wall-clock window? Phase A answer: no; per the distributed-
   systems rule, version numbers are authoritative. TEE quotes
   carry their own validity windows from the platform.
2. Should `EvidenceVerifier` be async? Platform attestation
   sometimes hits a network (Intel PCS, Azure Attestation).
   Phase A answer: keep it sync; async wrappers are trivial for
   callers. aion-context is sync (per
   `.claude/rules/concurrency.md`).

## References

- RATS (Remote ATtestation procedureS): RFC 9334.
- TPM 2.0 TPMS_ATTEST: TCG TPM 2.0 Library, Part 2.
- NVIDIA Confidential Computing + NRAS: <https://docs.nvidia.com/cc-deployment-guide-snp.pdf>
- AMD SEV-SNP: <https://www.amd.com/content/dam/amd/en/documents/epyc-business-docs/white-papers/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf>
- Intel TDX: <https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html>
- Microsoft Azure Attestation: <https://learn.microsoft.com/en-us/azure/attestation/>
- AWS Nitro Enclaves: <https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html>
- Arm CCA: <https://developer.arm.com/documentation/107893/latest>

## Appendix

### Terminology

- **TEE** — Trusted Execution Environment.
- **Attestation quote** — TEE-rooted signature over enclave
  measurement + caller payload.
- **Binding** — A `KeyAttestationBinding` linking an aion
  operational-key epoch to a TEE quote.
- **Evidence** — The platform-specific quote bytes.
- **Evidence verifier** — A library that validates the platform
  signature and measurement of the quote.
