# RFC Index

Authoritative protocol documents live in the `rfcs/`
directory of the repository. Each RFC has its own format and
deliberation history; this page is the table of contents.

| RFC | Title | Topic |
|---|---|---|
| 0001 | Architecture | High-level system shape |
| 0002 | File Format | Byte-level layout of the `.aion` file |
| 0003 | Cryptography | Primitive choices and domain separation |
| 0004 | Key Management | Keystore, master vs operational |
| 0005 | Signature Chain | Per-version signature semantics |
| 0006 | Threat Model | Adversary classes, in-scope / out-of-scope |
| 0007 | Rust Conventions | Tiger Style + crate-specific rules |
| 0008 | Error Handling | `AionError`, `Result`, `thiserror` |
| 0009 | Testing Strategy | Unit / property / fuzz / integration tiers |
| 0010 | Data Structures | The fixed-size structs and their layouts |
| 0011 | Serialization | Wire formats, zerocopy, JCS |
| 0012 | Versioning | File-format version, semver, breaking changes |
| 0013 | Sync Protocol | Distribution patterns (deferred) |
| 0014 | Multi-Signature | Quorum and multi-signer arithmetic |
| 0015 | Conflict Resolution | Concurrent-write semantics |
| 0016 | CLI Interface | The `aion` binary's surface |
| 0018 | Performance | Hot paths, benches, Criterion targets |
| 0019 | Audit Trail | The audit-log inside an `.aion` file |
| 0020 | Regulatory Compliance | SOX / HIPAA / GDPR mapping |
| 0021 | Multisig Attestation | RFC-0014 + the registry-aware verify path |
| 0022 | External Artifact Manifest | Binding model files / PDFs / etc. |
| 0023 | DSSE Envelope | Sigstore / in-toto interop format |
| 0024 | SLSA Provenance | Build-system attestation |
| 0025 | Transparency Log | Append-only Merkle log |
| 0026 | Hardware Attestation | TEE-bound key bindings |
| 0027 | Post-Quantum Hybrid | Ed25519 + ML-DSA-65 |
| 0028 | Key Rotation / Revocation | The two-tier key registry |
| 0029 | AIBOM | AI Bill of Materials |
| 0030 | OCI Packaging | OCI artifact manifests + referrers |
| 0031 | JCS Canonical JSON | RFC 8785 canonicalization |
| 0032 | Release Orchestration | Sealed-release composer |
| 0033 | Post-Audit Carryovers | Tracked findings from prior audit cycles |
| 0034 | Registry-Aware Verify Rollout | The Phase-A through Phase-E migration that removed raw-key verify_* |
| 0035 | Chain Architecture Guide | Per-file genesis vs growing-chain |

## Status legend (where present in each RFC)

- **DRAFT** — proposal, not yet ratified
- **PROPOSED** — under review
- **ACCEPTED** — ratified; implementation may or may not exist
- **IMPLEMENTED** — in code; further changes need a new RFC
- **SUPERSEDED** — replaced by a later RFC; kept for history

## Reading order suggestion

If you're new and want to understand the spec:

1. RFC-0001 (Architecture) — the 30,000-foot view
2. RFC-0006 (Threat Model) — what aion-context is defending
   against
3. RFC-0002 (File Format) — what's actually on disk
4. RFC-0028 (Key Rotation / Revocation) — the registry,
   which underpins all of registry-aware verify
5. RFC-0034 (Registry-Aware Verify Rollout) — how the
   registry became mandatory
6. RFC-0032 (Release Orchestration) — the supply-chain
   integration story

The remaining RFCs cover specific subsystems and can be
read on demand.

## See also

- The full RFCs live at
  [github.com/copyleftdev/aion-context/tree/main/rfcs](https://github.com/copyleftdev/aion-context/tree/main/rfcs)
- New RFCs go through the process documented in
  `.claude/rules/rfc-discipline.md`
- The `rfc-writer` agent in `.claude/agents/` scaffolds new
  RFCs matching the existing template
