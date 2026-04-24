---
description: Inventory Hegel property tests and enforce the Tier-1 + Tier-2 floor per .claude/rules/property-testing.md.
---

Audit Hegel property-test coverage against
`.claude/rules/property-testing.md`. Read-only — no edits.

## Steps

1. Count `#[hegel::test]` attributes across library source:

   ```bash
   grep -rn --include='*.rs' '#\[hegel::test\]' src/ | wc -l
   ```

2. Inventory them by `file:line — name`:

   ```bash
   grep -rn --include='*.rs' -A1 '#\[hegel::test\]' src/ \
     | awk '/fn /{sub(/^[^:]*:[^:]*:/,""); print prev" — "$0; next}{prev=$0}'
   ```

3. Cross-check against the enforced floor table in
   `.claude/rules/property-testing.md`. The current floor:

   **Tier 1** (7 properties, foundational correctness):

   | Module                | Required property                                                |
   |-----------------------|------------------------------------------------------------------|
   | `src/parser.rs`       | parser-totality on arbitrary bytes                               |
   | `src/parser.rs`       | accessor-totality on successfully-constructed parser             |
   | `src/crypto.rs`       | sign → verify round-trip                                         |
   | `src/crypto.rs`       | verify rejects wrong key                                         |
   | `src/crypto.rs`       | verify rejects tampered payload                                  |
   | `src/crypto.rs`       | hash is deterministic                                            |
   | `src/crypto.rs`       | `VerifyingKey` to-bytes / from-bytes round-trip                  |

   **Tier 2** (101 properties — chain integrity, multi-party attestation (RFC-0021), external artifact manifest (RFC-0022), DSSE envelope interop (RFC-0023), SLSA v1.1 provenance (RFC-0024), transparency log (RFC-0025), hardware attestation binding (RFC-0026), post-quantum hybrid signatures (RFC-0027), key rotation + revocation (RFC-0028), AIBOM (RFC-0029), OCI artifact packaging (RFC-0030), JCS canonicalization (RFC-0031), release orchestration (RFC-0032)):

   | Module                   | Required property                                              |
   |--------------------------|----------------------------------------------------------------|
   | `src/serializer.rs`      | serialize → parse → `verify_integrity` holds                   |
   | `src/serializer.rs`      | serialize is deterministic                                     |
   | `src/signature_chain.rs` | N-version chain ⇒ `verify_hash_chain` Ok                       |
   | `src/signature_chain.rs` | non-terminal tamper ⇒ `verify_hash_chain` fails                |
   | `src/signature_chain.rs` | `sign_version` → `verify_signature` round-trip                 |
   | `src/signature_chain.rs` | `sign_attestation` → `verify_attestation` round-trip (RFC-0021) |
   | `src/signature_chain.rs` | attestation rejects tampered `signature.author_id`             |
   | `src/signature_chain.rs` | attestation rejects wrong version                              |
   | `src/signature_chain.rs` | attestation vs version signature are domain-separated          |
   | `src/audit.rs`           | appended chain ⇒ each `validate_chain` is Ok                   |
   | `src/audit.rs`           | tampered `previous_hash` ⇒ `validate_chain` fails              |
   | `src/multisig.rs`        | K distinct attestations / K-of-N ⇒ `threshold_met`             |
   | `src/multisig.rs`        | K-1 distinct / K-of-N ⇒ NOT `threshold_met`                    |
   | `src/multisig.rs`        | duplicate attestations from same signer count ≤ 1              |
   | `src/multisig.rs`        | unauthorized signers do not count                              |
   | `src/multisig.rs`        | forged `signature.author_id` rejects                           |
   | `src/manifest.rs`        | build → `verify_artifact` round-trip (RFC-0022)                |
   | `src/manifest.rs`        | single-byte flip in artifact ⇒ `verify_artifact` fails         |
   | `src/manifest.rs`        | size mismatch ⇒ `verify_artifact` fails                        |
   | `src/manifest.rs`        | `sign_manifest` → `verify_manifest_signature` round-trip        |
   | `src/manifest.rs`        | mutating manifest breaks prior signature                        |
   | `src/manifest.rs`        | manifest signature rejects tampered signer                      |
   | `src/string_table.rs`    | builder add → `get` recovers the exact string                  |
   | `src/string_table.rs`    | `builder.len` strictly increases on every `add`                |
   | `src/dsse.rs`            | `sign_envelope` → `verify_envelope` round-trip (RFC-0023)      |
   | `src/dsse.rs`            | single-byte flip in payload ⇒ verify fails                     |
   | `src/dsse.rs`            | tampered `payloadType` ⇒ verify fails                          |
   | `src/dsse.rs`            | wrong key ⇒ verify fails                                       |
   | `src/dsse.rs`            | JSON round-trip preserves envelope                             |
   | `src/dsse.rs`            | N-signer envelope: all N verify                                |
   | `src/dsse.rs`            | PAE injective on (type, body)                                  |
   | `src/slsa.rs`            | Statement → DSSE → unwrap round-trip (RFC-0024)                |
   | `src/slsa.rs`            | manifest → subjects JSON round-trip                            |
   | `src/slsa.rs`            | tampered subject digest ⇒ envelope verify fails                |
   | `src/slsa.rs`            | wrapped envelope is `application/vnd.in-toto+json`             |
   | `src/key_registry.rs`    | register → `active_epoch_at` resolves initial epoch (RFC-0028) |
   | `src/key_registry.rs`    | pre-rotation version resolves to old epoch                     |
   | `src/key_registry.rs`    | post-rotation version resolves to new epoch                    |
   | `src/key_registry.rs`    | revocation cuts off later sigs, preserves earlier               |
   | `src/key_registry.rs`    | rotation requires valid master signature                       |
   | `src/key_registry.rs`    | epochs monotonic in number and `created_at_version`            |
   | `src/key_registry.rs`    | multi-hop rotation tracks each window correctly                |
   | `src/key_registry.rs`    | unknown author ⇒ `active_epoch_at` returns `None`              |
   | `src/key_registry.rs`    | tampered revocation record rejected                            |
   | `src/signature_chain.rs` | `verify_signature_with_registry` accepts active-epoch sig      |
   | `src/signature_chain.rs` | registry verify rejects rotated-out key                        |
   | `src/signature_chain.rs` | registry verify rejects revoked key                            |
   | `src/signature_chain.rs` | registry verify detects `public_key` substitution              |
   | `src/transparency_log.rs`| `tree_size` matches entry count (RFC-0025)                      |
   | `src/transparency_log.rs`| inclusion proof round-trip for every leaf at any N              |
   | `src/transparency_log.rs`| tampered payload invalidates proof                              |
   | `src/transparency_log.rs`| wrong leaf index rejects valid proof                            |
   | `src/transparency_log.rs`| any audit-path sibling byte flip rejects                        |
   | `src/transparency_log.rs`| `prev_leaf_hash` chain is monotonic                             |
   | `src/transparency_log.rs`| `sign_tree_head` → `verify_tree_head` round-trip                 |
   | `src/transparency_log.rs`| mutating an STH field after signing rejects                     |
   | `src/hw_attestation.rs`  | binding sign → verify round-trip (RFC-0026)                     |
   | `src/hw_attestation.rs`  | wrong master rejects                                            |
   | `src/hw_attestation.rs`  | tampered evidence rejects                                       |
   | `src/hw_attestation.rs`  | tampered pubkey rejects                                         |
   | `src/hw_attestation.rs`  | tampered nonce rejects                                          |
   | `src/hw_attestation.rs`  | tampered author/epoch rejects                                   |
   | `src/hw_attestation.rs`  | AcceptAll verifier path Ok                                      |
   | `src/hw_attestation.rs`  | RejectAll verifier path Err                                     |
   | `src/hw_attestation.rs`  | PubkeyPrefix verifier matches iff pubkey prefixes evidence      |
   | `src/hybrid_sig.rs`      | hybrid sign → verify round-trip (RFC-0027)                      |
   | `src/hybrid_sig.rs`      | tampered payload rejects                                        |
   | `src/hybrid_sig.rs`      | wrong classical key half rejects                                |
   | `src/hybrid_sig.rs`      | wrong ML-DSA key half rejects                                   |
   | `src/hybrid_sig.rs`      | corrupted classical signature rejects                           |
   | `src/hybrid_sig.rs`      | corrupted ML-DSA signature rejects                              |
   | `src/hybrid_sig.rs`      | classical sig without HYBRID_DOMAIN prefix rejects              |
   | `src/hybrid_sig.rs`      | ML-DSA signature length mismatch rejects                        |
   | `src/aibom.rs`           | AIBOM JSON round-trip (RFC-0029)                                |
   | `src/aibom.rs`           | canonical bytes deterministic                                   |
   | `src/aibom.rs`           | model hash survives hex round-trip                              |
   | `src/aibom.rs`           | AIBOM → DSSE → unwrap round-trip                                |
   | `src/aibom.rs`           | tampered AIBOM DSSE payload rejects                             |
   | `src/aibom.rs`           | multi-signer AIBOM envelope accepts all                          |
   | `src/aibom.rs`           | wrapped envelope payloadType == `AIBOM_PAYLOAD_TYPE`            |
   | `src/oci.rs`             | OCI manifest JSON round-trip (RFC-0030)                          |
   | `src/oci.rs`             | manifest digest deterministic                                    |
   | `src/oci.rs`             | primary artifactType + layer mediaType constants                 |
   | `src/oci.rs`             | layer size equals payload length                                 |
   | `src/oci.rs`             | layer digest equals sha256 of payload                            |
   | `src/oci.rs`             | attestation referrer subject digest equals primary digest         |
   | `src/oci.rs`             | any manifest mutation changes the digest                          |
   | `src/jcs.rs`             | JCS canonicalization is idempotent (RFC-0031)                   |
   | `src/jcs.rs`             | top-level object keys sorted in JCS output                       |
   | `src/jcs.rs`             | no whitespace between tokens outside strings                     |
   | `src/jcs.rs`             | parsing JCS bytes recovers semantic value                        |
   | `src/jcs.rs`             | reordering input keys preserves JCS output                       |
   | `src/aibom.rs`           | `AiBom::to_jcs_bytes` matches `jcs::to_jcs_bytes` (RFC-0031 B)  |
   | `src/slsa.rs`            | `InTotoStatement::to_jcs_bytes` matches helper                   |
   | `src/oci.rs`             | `OciArtifactManifest::to_jcs_bytes` matches helper               |
   | `src/release.rs`         | RFC-0032 seal → verify round-trip                                |
   | `src/release.rs`         | tampered manifest DSSE rejects                                   |
   | `src/release.rs`         | OCI referrer subjects link to primary digest                     |
   | `src/release.rs`         | AIBOM model hash matches manifest primary                        |
   | `src/release.rs`         | log has 3 entries with expected kinds                            |

   For each row: if no matching `#[hegel::test]` exists in the listed
   module whose body exercises the listed invariant, mark MISSING.

4. Optionally run `cargo test -q` and flag any Hegel property whose
   wall-clock exceeds 5 s at default case count as
   `needs-attention` (slow PBTs hide at scale).

## Report format

```
HEGEL AUDIT — aion-context

| module          | required | present | verdict |
|-----------------|----------|---------|---------|
| src/parser.rs   | 2        | 3       | ✓       |
| src/crypto.rs   | 5        | 5       | ✓       |

Properties:
  src/parser.rs:NNN — prop_parser_new_never_panics_on_arbitrary_bytes
  src/crypto.rs:NNN — prop_sign_verify_roundtrip
  …

VERDICT: ALL TIER-1 COVERED | UNDER-COVERED (modules: …)
```

## When to use

- Before pushing a branch that touches `src/parser.rs`,
  `src/crypto.rs`, `src/signature_chain.rs`, `src/audit.rs`,
  `src/multisig.rs`, or `src/serializer.rs`.
- As part of `/quality-gate` (step 6).
- After a refactor that might delete tests — a drop in
  `hegel_properties` vs `.claude/drift/baseline.json` is a hard
  block.

## Authoring new properties

Invoke the globally-installed `hegel` skill when writing a new
property. Place the test in a `mod properties { … }` submodule
inside the source file's existing `#[cfg(test)]` mod (see the
placement section of `.claude/rules/property-testing.md`).
