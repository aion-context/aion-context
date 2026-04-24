# Property-Based Testing

**Aspirational, not yet enforced.** Aion-v2 uses example-based tests
and integration tests plus cargo-fuzz targets in `fuzz/`.
This file documents where property-based testing would add value and
what shape it should take when we start. There are no tier floors
yet — introduce properties one invariant at a time.

## Where property tests earn their keep in aion-context

| Invariant                                           | Crate / module                       | Tier   |
|-----------------------------------------------------|--------------------------------------|--------|
| File encode → decode round-trip                     | `aion-context::serializer` / `parser`   | Tier 1 |
| Signature sign → verify round-trip                  | `aion_context::crypto`              | Tier 1 |
| Signature chain: append → verify succeeds           | `aion_context::signature_chain`     | Tier 1 |
| Signature chain: tamper → verify fails              | `aion_context::signature_chain`     | Tier 2 |
| Multisig: quorum satisfied ⇒ accept                 | `aion_context::multisig`            | Tier 2 |
| Hash chain linking on audit log                     | `aion_context::audit`               | Tier 1 |
| Audit chain tamper-detection                        | same                                | Tier 2 |
| Parser totality on arbitrary bytes (no panic)       | `aion_context::parser`              | Tier 1 |
| Version monotonicity on accept                      | any receive path                    | Tier 2 |

## Recommended framework

`proptest` is the mature Rust choice and already widely used in
signature/crypto libraries. `quickcheck` works but is less
ergonomic. If you add property tests, add one framework to the
workspace — don't mix.

The `hegel` framework (used in sibling project
`aion-compliance-mesh`) offers deterministic shrinking and a CI
mode; if we pick it up, it goes in as its own RFC first.

## Taxonomy (pick the right kind)

1. **Round-trip.** Every `encode`/`decode`, `sign`/`verify`,
   `build`/`extract` pair gets a round-trip property with broad
   generators.
2. **Parse robustness.** Any parser must not panic on arbitrary
   input. Return `Err`, `None`, or skip; never crash. This overlaps
   with the fuzz targets in `fuzz/` — fuzz runs deeper,
   properties run per-commit.
3. **Idempotence.** Any normalization, case conversion, or
   deduplication function satisfies `f(f(x)) == f(x)`.
4. **Monotonicity.** Versions, sequences, timestamps, and other
   counters increase. A property expresses the ordering directly.
5. **Model tests (stateful).** Mutable state (`AuditChain`,
   `SignatureChain`, `GuardrailChain`) gets a model test: define
   rules for each public mutator and assert equivalence to a
   reference implementation (`Vec`, `HashMap`) after every rule.
6. **Boundary.** Integer `MIN`/`MAX`/`0`, empty collections, and
   maximum-length inputs in every generator. Do not add bounds to
   avoid these cases; they are the test.

## Generator discipline

- Broad by default. Use the widest generator the contract allows.
- Constrain only for correctness, not for speed or comfort. If the
  contract says "non-empty", add the constraint. Otherwise don't.
- Dependent draws: for relationships between values, draw in order
  and derive. Don't `.filter()` — rejection sampling is expensive.
- No manual seeded RNGs inside the code under test during a
  property run. Inject an RNG as a parameter or use the framework's
  RNG.

## When NOT to write a PBT

- The test asserts an **exact** output string or error message. Keep
  that as a unit test.
- The property is trivial (`x == x`, `len(xs) >= 0`). Every property
  must be *falsifiable* by a buggy implementation.
- The setup requires a running network, real filesystem, or HSM.
  Keep that as an integration test with explicit fixtures.

## Placement

Properties live in the **same test module** as the example tests for
the code under test, unless they share heavy fixtures — in which
case, a dedicated `tests/<module>_properties.rs` integration file is
acceptable.

## Relationship to fuzzing

`fuzz/` targets (parser, crypto-verify) already exist. Fuzz
and PBT overlap but don't substitute:

- Fuzz runs for minutes to hours, explores wider input space.
- PBT runs per-commit, shrinks failures to a minimal example, and
  serves as regression documentation.

For the parser specifically, a PBT that asserts "no panic on
arbitrary `&[u8]`" plus a fuzz target with the same invariant is the
right combination.
