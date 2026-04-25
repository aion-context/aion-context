# Federation — cross-domain HW attestation

> Two independent aion deployments, each with TEE-bound
> signing keys, cross-verifying a joint release.

The example file is at `examples/federation_hw_attest.rs`. Run
it (note the required feature flag):

```bash
cargo run --release --example federation_hw_attest --features test-helpers
```

## What it exercises

| Library surface | RFC | Why it's interesting |
|---|---|---|
| `KeyAttestationBinding` + `sign_binding` + `verify_binding` | RFC-0026 | TEE-bound key authorization |
| The `EvidenceVerifier` trait | RFC-0026 | Pluggable platform-policy extension point |
| Two independent `KeyRegistry` instances | RFC-0028 | Federation model |
| `PubkeyPrefixEvidenceVerifier` / `RejectAllEvidenceVerifier` | (test-helpers) | Stand-ins for real platform verifiers (NRAS, DCAP, Azure Attestation) |

The `test-helpers` feature gates the test-double evidence
verifiers — they exist for property testing and demonstrations,
not for production use. A real consumer wires in
platform-specific verifiers under the same `EvidenceVerifier`
trait.

## The scenario

**Helios Labs** (Singapore, TPM2-bound keys) and **Polaris
Research** (Berlin, Intel TDX-bound keys) co-publish a joint
foundation model. Each lab maintains its own `KeyRegistry`.

Six phases:

**A. Helios bootstraps** — 2 signers, master + operational
keys for each, TPM2 evidence bindings.

**B. Polaris bootstraps** — 2 signers, master + operational
keys for each, Intel TDX evidence bindings.

**C. Joint release attestation, cross-domain.**

- Helios's signature verifies under Helios's registry (in-domain) ✅
- Polaris's signature verifies under Polaris's registry (in-domain) ✅
- Helios's verifier loads Polaris's registry out-of-band and
  verifies Polaris's signature under it (cross-domain) ✅
- Polaris's verifier loads Helios's registry and verifies
  Helios's signature under it (cross-domain) ✅
- A signer from one org rejected against the other org's
  registry ❌ (correctly)

**D. Both labs' bindings verified under
`PubkeyPrefixEvidenceVerifier`** — a stand-in for a real TEE
verifier that checks the evidence contains the expected
public key.

**E. Polaris swaps in `RejectAllEvidenceVerifier`** — models a
firmware-CVE response where Helios's TPM batch is suddenly
distrusted. Same bindings, different verifier:

- Helios's bindings under `RejectAllEvidenceVerifier`: ❌ REJECTED
- Polaris's bindings under `PubkeyPrefixEvidenceVerifier`: ✅ still VALID

**F. Adversarial binding mutations** — flip one byte in
`binding.public_key`, in `binding.evidence`, in
`master_signature`. All three paths: ❌ REJECTED.

## Why this matters

The `EvidenceVerifier` trait is the cleanest application-level
extension point in the library. The crate ships test doubles,
not real platform verifiers — those live in separate crates
the consumer wires in. So:

- A lab running on H100 GPUs slots in `NvidiaNrasVerifier`.
- A lab running on Intel SGX slots in `IntelDcapVerifier`.
- A lab running on Azure slots in `AzureAttestationJwtVerifier`.

All under the same trait, all consumed by the same
`verify_binding(&binding, &registry, at_version, &verifier)`
call. The library doesn't bundle every platform's library;
the consumer chooses.

## Cross-domain trust bootstrap

The federation model assumes that **registries travel
out-of-band**. Helios doesn't trust Polaris's key choices by
default; Polaris ships Helios its registry JSON through
whatever channel the consortium has agreed on (signed
Slack message, manual exchange, certificate-pinned API
call). Each lab's verifier then has the foreign registry
on disk and can verify foreign signatures locally.

The example exercises both directions of this exchange.

## Sample output (abbreviated)

```text
═══════════════════════════════════════════════════════════════════════
║ Phase C — Joint release attested by one signer from each lab          ║
═══════════════════════════════════════════════════════════════════════
  • Helios's sig verifies against Helios registry (in-domain): ✅ OK
  • Polaris's sig verifies against Polaris registry (in-domain): ✅ OK
  • Helios verifies Polaris's sig using the FOREIGN registry: ✅ OK
  • Polaris verifies Helios's sig using the FOREIGN registry: ✅ OK
  • Polaris's sig attempted against Helios registry (must reject): ✅ REJECTED

═══════════════════════════════════════════════════════════════════════
║ Phase E — TPM firmware vulnerability → Polaris distrusts Helios       ║
═══════════════════════════════════════════════════════════════════════
  • Helios Helios Research Lead: binding under distrust policy ❌ REJECTED
  • Polaris Polaris Chief Scientist: binding still ✅ VALID
```

## What you'll learn from running it

- How RFC-0026 separates the binding (master-signed,
  registry-checked) from the evidence verification (delegated
  to a platform verifier the consumer chooses).
- How a federation maintains independent trust roots while
  still cross-verifying joint releases.
- How a policy change (TPM firmware CVE) rolls out by
  swapping the verifier without changing the bindings or the
  signed artifacts.
