# Property-Based Testing (Hegel)

Invariants are cheaper to check with a generator than with 40
example tests. `aion-context` ships a cryptographic file format —
round-trips, hash-chain integrity, and parser totality are all
contract-level claims that a PBT framework can falsify directly.

**Framework: [`hegeltest`](https://crates.io/crates/hegeltest)** (the
`hegel` crate name at call sites). Added as a `dev-dependency` in
`Cargo.toml`. Do not introduce `proptest` / `quickcheck` — one
framework, one generator API, one shrinker. The globally-installed
`hegel` skill (`~/.claude/skills/hegel/SKILL.md`) is the reference
for authoring new properties.

> Hegel's backend is a `uv`-launched `hegel-core` server. `uv` is
> expected on `PATH` at test time; absent that, `hegeltest`
> self-installs a private copy into `~/.cache/hegel`. CI images must
> either ship `uv` or accept the one-time download.

## Placement

Property tests live in a `mod properties { … }` submodule **inside
the same source file's existing `#[cfg(test)]` mod**. No separate
`tests/*_properties.rs` file unless the property needs heavy shared
fixtures that can't live in-source. This matches the Hegel skill's
guidance: property tests are tests like any other and belong with
the code they test.

Skeleton:

```rust
#[cfg(test)]
mod tests {
    // existing example-based tests …

    mod properties {
        use super::*;
        use hegel::generators as gs;

        #[hegel::test]
        fn prop_<invariant>(tc: hegel::TestCase) {
            let input = tc.draw(gs::binary().max_size(4096));
            // run code under test
            // assert invariant
        }
    }
}
```

Inside tests, prefer `.unwrap_or_else(|_| std::process::abort())`
over `.unwrap()` so a Hegel-shrunk counterexample surfaces a clean
abort rather than a panic stack that buries the minimized input.

## Required coverage — enforced

Each row below is a floor: at least one `#[hegel::test]` property in
the listed module covering the listed invariant. The
`/hegel-audit` command inventories them; the `/quality-gate` command
blocks on a drop.

### Tier 1 — foundational correctness

| Module                          | Required Tier-1 property                                      |
|---------------------------------|---------------------------------------------------------------|
| `src/parser.rs`                 | `AionParser::new(&[u8])` never panics on arbitrary bytes      |
| `src/parser.rs`                 | Accessors on a successfully-constructed `AionParser` never panic |
| `src/crypto.rs`                 | `sign` → `verify` round-trip succeeds for any payload         |
| `src/crypto.rs`                 | `verify` rejects a signature made by a different key          |
| `src/crypto.rs`                 | `verify` rejects a tampered payload (single-bit flip)         |
| `src/crypto.rs`                 | `hash` is deterministic                                       |
| `src/crypto.rs`                 | `VerifyingKey::to_bytes → from_bytes` is a round-trip         |

### Tier 2 — chain integrity, multi-party attestation, external artifacts

| Module                          | Required Tier-2 property                                      |
|---------------------------------|---------------------------------------------------------------|
| `src/serializer.rs`             | serialize → parse → `verify_integrity` holds for any file     |
| `src/serializer.rs`             | serialize is deterministic (same file ⇒ same bytes)           |
| `src/signature_chain.rs`        | grow chain of N versions ⇒ `verify_hash_chain` succeeds       |
| `src/signature_chain.rs`        | tamper at a non-terminal entry ⇒ `verify_hash_chain` fails    |
| `src/signature_chain.rs`        | `sign_version` → `verify_signature` round-trip for any version |
| `src/signature_chain.rs`        | RFC-0021 `sign_attestation` → `verify_attestation` round-trip |
| `src/signature_chain.rs`        | attestation rejects tampered `signature.author_id`            |
| `src/signature_chain.rs`        | attestation rejects wrong version                             |
| `src/signature_chain.rs`        | attestation and version signature are domain-separated        |
| `src/audit.rs`                  | appended chain of N entries ⇒ each `validate_chain` is `Ok`   |
| `src/audit.rs`                  | tampered `previous_hash` ⇒ `validate_chain` fails             |
| `src/multisig.rs`               | K distinct valid attestations / K-of-N ⇒ `threshold_met`      |
| `src/multisig.rs`               | K-1 distinct attestations / K-of-N ⇒ NOT `threshold_met`      |
| `src/multisig.rs`               | duplicate attestations from same signer count at most once    |
| `src/multisig.rs`               | signatures from unauthorized signers do not count             |
| `src/multisig.rs`               | forged `signature.author_id` rejects under the attestation path |
| `src/manifest.rs`               | build → `verify_artifact` round-trip for any (name, bytes)    |
| `src/manifest.rs`               | any single-byte flip in artifact ⇒ `verify_artifact` fails    |
| `src/manifest.rs`               | size mismatch ⇒ `verify_artifact` fails                       |
| `src/manifest.rs`               | `sign_manifest` → `verify_manifest_signature` round-trip       |
| `src/manifest.rs`               | mutating the manifest breaks a prior manifest signature        |
| `src/manifest.rs`               | manifest signature rejects tampered `signature.author_id`      |
| `src/string_table.rs`           | builder add → `StringTable::get` recovers the exact string    |
| `src/string_table.rs`           | `builder.len` strictly increases on every `add` (even `""`)   |
| `src/dsse.rs`                   | RFC-0023 `sign_envelope` → `verify_envelope` round-trip       |
| `src/dsse.rs`                   | single-byte flip in payload ⇒ `verify_envelope` fails         |
| `src/dsse.rs`                   | any change to `payload_type` ⇒ `verify_envelope` fails        |
| `src/dsse.rs`                   | wrong pinned key ⇒ `verify_envelope` fails                    |
| `src/dsse.rs`                   | JSON round-trip preserves the envelope                        |
| `src/dsse.rs`                   | multi-signer envelope: all N keyids verify                    |
| `src/dsse.rs`                   | PAE is injective on (type, body) bytes                        |
| `src/slsa.rs`                   | RFC-0024 Statement → DSSE → unwrap round-trip                 |
| `src/slsa.rs`                   | manifest → subjects JSON round-trip preserves digests         |
| `src/slsa.rs`                   | tampered subject digest ⇒ envelope fails to verify            |
| `src/slsa.rs`                   | wrapped envelope `payloadType` == `application/vnd.in-toto+json` |
| `src/key_registry.rs`           | RFC-0028 register → `active_epoch_at` resolves initial epoch  |
| `src/key_registry.rs`           | signature before rotation version still resolves to old epoch |
| `src/key_registry.rs`           | signature at/after rotation version resolves to new epoch     |
| `src/key_registry.rs`           | revocation rejects later sigs, preserves earlier sigs         |
| `src/key_registry.rs`           | rotation requires valid master signature                      |
| `src/key_registry.rs`           | epochs and `created_at_version` are monotonic                 |
| `src/key_registry.rs`           | multi-hop rotation tracks each epoch window correctly         |
| `src/key_registry.rs`           | unknown author ⇒ `active_epoch_at` returns `None`             |
| `src/key_registry.rs`           | tampered revocation record rejected                           |
| `src/signature_chain.rs`        | `verify_signature_with_registry` accepts active-epoch sig     |
| `src/signature_chain.rs`        | registry verify rejects rotated-out key                       |
| `src/signature_chain.rs`        | registry verify rejects revoked key                           |
| `src/signature_chain.rs`        | registry verify detects `public_key` substitution             |
| `src/transparency_log.rs`       | RFC-0025 `tree_size` matches entry count                      |
| `src/transparency_log.rs`       | inclusion proof round-trip for every leaf at any N            |
| `src/transparency_log.rs`       | tampering the payload invalidates a valid inclusion proof     |
| `src/transparency_log.rs`       | claiming a wrong `leaf_index` for a valid proof rejects        |
| `src/transparency_log.rs`       | flipping any sibling byte in the audit path rejects            |
| `src/transparency_log.rs`       | leaf chain `prev_leaf_hash` is strictly monotonic             |
| `src/transparency_log.rs`       | `sign_tree_head` → `verify_tree_head` round-trip              |
| `src/transparency_log.rs`       | mutating an STH field after signing rejects                   |
| `src/hw_attestation.rs`         | RFC-0026 binding signature round-trip                         |
| `src/hw_attestation.rs`         | wrong master key rejects binding                              |
| `src/hw_attestation.rs`         | tampered evidence bytes ⇒ binding rejects                     |
| `src/hw_attestation.rs`         | tampered pubkey ⇒ binding rejects                             |
| `src/hw_attestation.rs`         | tampered nonce ⇒ binding rejects                              |
| `src/hw_attestation.rs`         | tampered author or epoch ⇒ binding rejects                    |
| `src/hw_attestation.rs`         | `AcceptAllEvidenceVerifier` path yields Ok                    |
| `src/hw_attestation.rs`         | `RejectAllEvidenceVerifier` path yields Err                   |
| `src/hw_attestation.rs`         | `PubkeyPrefixEvidenceVerifier` accepts iff pubkey is prefix   |
| `src/hybrid_sig.rs`             | RFC-0027 hybrid sign → verify round-trip                      |
| `src/hybrid_sig.rs`             | tampered payload ⇒ hybrid verify rejects                      |
| `src/hybrid_sig.rs`             | wrong classical key half ⇒ rejects                            |
| `src/hybrid_sig.rs`             | wrong ML-DSA key half ⇒ rejects                               |
| `src/hybrid_sig.rs`             | corrupted classical signature bytes ⇒ rejects                 |
| `src/hybrid_sig.rs`             | corrupted ML-DSA signature bytes ⇒ rejects                    |
| `src/hybrid_sig.rs`             | classical sig without HYBRID_DOMAIN prefix rejects            |
| `src/hybrid_sig.rs`             | ML-DSA signature length mismatch rejects                      |
| `src/aibom.rs`                  | RFC-0029 AIBOM JSON round-trip preserves all fields           |
| `src/aibom.rs`                  | AIBOM canonical bytes are deterministic                       |
| `src/aibom.rs`                  | model hash field survives hex ↔ binary round-trip             |
| `src/aibom.rs`                  | AIBOM → DSSE → unwrap round-trip                              |
| `src/aibom.rs`                  | tampered DSSE payload ⇒ verify rejects                         |
| `src/aibom.rs`                  | multi-signer DSSE envelope accepts all signers                 |
| `src/aibom.rs`                  | wrapped envelope payloadType == `AIBOM_PAYLOAD_TYPE`           |
| `src/oci.rs`                    | RFC-0030 OCI manifest JSON round-trip                          |
| `src/oci.rs`                    | manifest `digest()` is deterministic                           |
| `src/oci.rs`                    | aion primary has artifactType + layer mediaType constants      |
| `src/oci.rs`                    | aion layer size equals payload length                          |
| `src/oci.rs`                    | aion layer digest equals `sha256_digest(payload)`              |
| `src/oci.rs`                    | attestation referrer subject digest equals primary digest      |
| `src/oci.rs`                    | any manifest mutation changes the digest                        |
| `src/jcs.rs`                    | RFC-0031 JCS canonicalization is idempotent                    |
| `src/jcs.rs`                    | top-level object keys are sorted in JCS output                 |
| `src/jcs.rs`                    | no whitespace between tokens outside of string values          |
| `src/jcs.rs`                    | parsing JCS bytes recovers the semantic value                  |
| `src/jcs.rs`                    | reordering input keys does not change JCS output               |
| `src/aibom.rs`                  | RFC-0031 Phase B: `AiBom::to_jcs_bytes` matches `jcs::to_jcs_bytes` |
| `src/slsa.rs`                   | RFC-0031 Phase B: `InTotoStatement::to_jcs_bytes` matches helper |
| `src/oci.rs`                    | RFC-0031 Phase B: `OciArtifactManifest::to_jcs_bytes` matches helper |
| `src/release.rs`                | RFC-0032 seal → verify round-trip for any valid builder input  |
| `src/release.rs`                | tampering the sealed manifest envelope ⇒ verify rejects        |
| `src/release.rs`                | OCI referrer subjects link to primary digest                   |
| `src/release.rs`                | AIBOM model hash matches the manifest's primary entry hash     |
| `src/release.rs`                | log has exactly three entries with expected kinds in order     |
| `src/manifest.rs`               | RFC-0034 registry verify accepts signature under active epoch  |
| `src/manifest.rs`               | RFC-0034 registry verify rejects signature from rotated-out key |
| `src/manifest.rs`               | RFC-0034 registry verify rejects `public_key` substitution     |
| `src/dsse.rs`                   | RFC-0034 envelope registry verify accepts pinned signer        |
| `src/dsse.rs`                   | RFC-0034 envelope registry verify rejects unregistered signer  |
| `src/dsse.rs`                   | RFC-0034 envelope registry verify rejects revoked signer       |
| `src/hw_attestation.rs`         | RFC-0034 registry verify accepts freshly-bound key             |
| `src/hw_attestation.rs`         | RFC-0034 registry verify rejects binding signed by wrong master |
| `src/release.rs`                | RFC-0034 `verify_with_registry` accepts a pinned release       |
| `src/release.rs`                | RFC-0034 `verify_with_registry` rejects rotated-out signer     |

## Tier 3 (model / stateful — required once the audit chain is stable)

Borrowed from the sibling `aion-compliance-mesh` ledger rule.
Stateful mutators (`AuditChain`, `SignatureChain`) get a model test
that runs a rule-set against a reference `Vec`/`HashMap` and asserts
equivalence after every rule.

## Taxonomy (pick the right kind)

1. **Parser robustness.** Any parser must not panic on arbitrary
   bytes. Pairs with the `fuzz/` target — PBT runs per-commit and
   shrinks, fuzz runs for minutes-to-hours and explores deeper.
2. **Round-trip.** Every `encode`/`decode`, `sign`/`verify`,
   `build`/`extract` pair gets a round-trip with broad generators.
3. **Monotonicity.** `(author, version)` replay defense, audit
   sequence numbers — express the ordering directly.
4. **Model / stateful.** `AuditChain`, `SignatureChain` — define
   rules for each public mutator and assert equivalence to a
   reference implementation after every rule.
5. **Idempotence.** `f(f(x)) == f(x)` — normalization, dedup,
   canonicalization.
6. **Boundary.** Integer `MIN`/`MAX`/`0`, empty collections,
   maximum-length inputs inside every generator. Do not shrink
   bounds to avoid these — they are the test.

## Generator discipline

- Broad by default. Use the widest generator the contract allows
  (`gs::binary().max_size(N)` not a hand-built random slice).
- Constrain only for correctness, never for speed.
- Dependent draws: draw in order and derive. Do not `.filter()` —
  rejection sampling is expensive.
- No manual seeded RNGs inside the code under test during a Hegel
  run. Inject state or use Hegel's RNG via `tc.draw(…)`.

## When NOT to write a PBT

- The test asserts an **exact** output string, byte sequence, or
  error message. Keep that as an example test.
- The property is trivial (`x == x`, `len(xs) >= 0`). Every property
  must be falsifiable by a buggy implementation.
- The setup requires a real network, real filesystem beyond
  `tempfile`, or an HSM. Keep that as an integration test with
  explicit fixtures.

## Relationship to fuzzing

`fuzz/` targets stay. PBT and fuzz do not substitute:

- Fuzz runs for minutes-to-hours, explores wider input space.
- PBT runs per-commit in `cargo test`, shrinks failures to a
  minimal example, and serves as regression documentation.

For the parser: the `prop_parser_new_never_panics_on_arbitrary_bytes`
property in `src/parser.rs` and the libFuzzer target
`fuzz/fuzz_targets/fuzz_file_parser.rs` make the same claim; keep
both.

## Commands

- `/hegel-audit` — inventory `#[hegel::test]` attributes against
  Tier-1 floor; report coverage and flag regressions.
- `/quality-gate` — runs `cargo test` which includes property tests;
  a Tier-1 count drop vs baseline is hard-block.
