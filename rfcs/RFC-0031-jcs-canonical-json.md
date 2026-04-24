# RFC 0031: JCS (RFC 8785) Canonical JSON

- **Author:** aion-context maintainers
- **Status:** DRAFT
- **Created:** 2026-04-23
- **Updated:** 2026-04-23
- **Depends on:** (independent)

## Abstract

Our existing JSON emitters (`InTotoStatement`, `AiBom`,
`OciArtifactManifest`) rely on serde's struct-declaration-order
output plus `BTreeMap` for user-keyed maps. This gives byte-stable
JSON **within the Rust + serde_json implementation**, but
different JSON libraries (Python's `json.dumps`, Go's
`encoding/json`, JavaScript's `JSON.stringify`, Python
`canonicalize`, other Rust crates) will legitimately emit
byte-different output for the same logical document.

RFC 8785 (JCS — JSON Canonicalization Scheme) is the IETF standard
for cross-implementation byte-stable JSON: lexicographic key
ordering, no extraneous whitespace, UTF-8, ECMAScript-style
number formatting, minimal string escaping.

This RFC adds an **additive** JCS helper module. Existing
`canonical_bytes()` methods keep their current semantics so
historical DSSE-signed envelopes still verify. New call sites that
need cross-implementation byte stability (future Rekor integration,
detached JSON hashes, Go/Python/JS verifier interop) use
`jcs::to_jcs_bytes()` instead.

## Motivation

### Problem Statement

Today, a Python slsa-verifier would hash our Rust-emitted
`InTotoStatement` JSON and get a different digest than our own
`serde_json::to_vec` output, because:

- serde emits struct fields in declaration order; Python dumps in
  insertion or sorted order by default, Go sorts alphabetically.
- serde_json's default has no canonical whitespace rule.
- Number formatting differs — `1.0` vs `1.0e0` vs `1`.

For DSSE (RFC-0023) this mostly doesn't matter: the signer commits
to exact bytes and verifiers operate on those same exact bytes. But
*around* DSSE, there are cases where canonical bytes across
implementations matter:

1. **Content-addressed storage**: hashing a logical document to
   produce a stable identifier (e.g. "AIBOM id" that multiple
   tools must agree on).
2. **Rekor / CT integration** (RFC-0025 Phase C): transparency
   logs that canonicalize JSON before Merkle-leaf hashing so
   entries submitted by different tools for the same logical
   content collide intentionally.
3. **Reproducibility audits**: a Python auditor re-emitting the
   same logical AIBOM and comparing to a checked-in hash.
4. **Multi-implementation signing**: a logical statement signed
   by different implementations (Go CI, Rust CLI) that should
   produce identical signed bytes — and thus identical
   signatures under deterministic schemes.

### Use Cases

- `jcs::to_jcs_bytes(&aibom)` for a cross-implementation AIBOM
  hash pinned in a catalog.
- `jcs::canonicalize_json_bytes(incoming_bytes)` before comparing
  two externally-sourced JSON documents for logical equality.
- Future RFC-0025 Phase C: Rekor entries for aion use JCS leaves.

### Goals

- Thin wrapper around an audited JCS implementation.
- Additive: no breaking changes to existing `canonical_bytes`.
- Byte-exact RFC 8785 compliance.
- Property-tested: idempotence, lexicographic key ordering,
  no whitespace, semantic round-trip.

### Non-Goals

- **Replacing `canonical_bytes`** in existing modules.
  Signatures that already exist over those bytes must continue
  to verify.
- **Implementing JCS ourselves**. `serde_jcs` (MIT/Apache-2.0) is
  the maintained Rust implementation; wrapping it is cleaner than
  re-rolling 200 lines of ECMAScript number formatting.
- **JSON5, RJSON, CBOR-diagnostic**. JCS only.

## Proposal

### Public API

```rust
// src/jcs.rs

/// Serialize a value directly to JCS-canonical bytes.
///
/// Equivalent to: serde → serde_json::Value → RFC-8785 bytes.
pub fn to_jcs_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>>;

/// Re-canonicalize existing JSON bytes. Useful when you receive
/// a JSON document from a third party and want to compute its
/// canonical digest without trusting its on-wire byte order.
pub fn canonicalize_json_bytes(bytes: &[u8]) -> Result<Vec<u8>>;
```

### Semantics (per RFC 8785)

- Object keys sorted by UTF-16 code-unit code point.
- No whitespace between tokens.
- Strings: minimal-escaping UTF-8 with `"` and `\` escaped, plus
  control characters as `\u00XX`.
- Numbers: shortest round-trip representation per ECMAScript
  JSON.stringify rules (I-D.ietf-rfc8785-06 §3.2.2.3).
- Arrays preserve element order.
- Booleans and null emit as the literal keywords.

### Choice of underlying library

`serde_jcs = "0.2"` — the de facto Rust JCS library. MIT/Apache-2.0
dual-licensed. Maintained by members of the W3C DID community.

### Integration points

Phase A: the helper module and property tests only. No call sites
inside aion-context modules are changed.

Phase B: opt-in `to_jcs_bytes()` methods on `InTotoStatement`,
`AiBom`, `OciArtifactManifest` as *additional* serialization paths
alongside `canonical_bytes`. Will need explicit migration notes if
we ever want to use JCS as the signed-bytes source — that's a
breaking change to signature formats and will need its own RFC.

### Edge Cases

- **Invalid UTF-8 in input JSON**: returns `Err`.
- **Non-UTF-8 strings via serde**: impossible in Rust (`String` is
  UTF-8 by construction).
- **Float precision edge cases** (`1.0000000000000001`): handled
  by `serde_jcs`'s ECMAScript shortest-repr logic.
- **Empty object / array**: emits `{}` / `[]` verbatim.

## Rationale and Alternatives

### Why wrap `serde_jcs` instead of vendoring?

A vendored 200-line JCS implementation would need its own
property-testing suite against the RFC 8785 test vectors, plus
maintenance. `serde_jcs` has a community of users, bug reports,
and test vectors already exercised. Wrapping it keeps our
attack surface small.

### Why additive, not replacement?

Existing DSSE envelopes signed via `aibom::wrap_aibom_dsse`,
`slsa::wrap_statement_dsse`, etc. commit to the exact bytes
produced by the current `canonical_bytes()` functions. Switching
those to JCS changes the bytes and breaks every historical
signature. Phase A preserves backward compatibility.

### Why not use `serde_json` with a custom `Map` that sorts on
serialize?

Key ordering is only one part of JCS. Number formatting, string
escaping, and UTF-16 ordering rules make a from-scratch
implementation risky.

## Security Considerations

### Threat Model

1. **Canonicalization discrepancy attack**: an attacker crafts
   JSON that two implementations canonicalize differently,
   causing signature confusion. Mitigated by using one audited
   implementation (`serde_jcs`) and property-testing idempotence
   + output constraints.
2. **Injection via key/value content**: JCS guarantees structural
   canonicalization but not content safety. Consumers still need
   to validate field values against their schema.
3. **DoS via deeply nested JSON**: serde_json's default recursion
   limit (~128 levels) applies; adversarial inputs are rejected.

### Security Guarantees

- **Byte-stability across runs**: two calls to `to_jcs_bytes` on
  the same Value produce identical bytes.
- **Logical-equality determinism**: two semantically equal JSON
  documents produce identical canonical bytes regardless of their
  original on-wire ordering.
- **No additional crypto**: pure serialization; no keys or
  secrets touched.

## Performance Impact

JCS adds one extra pass vs serde_json default:

1. Parse into `serde_json::Value`.
2. Sort keys and re-emit.

Measured cost: roughly 2× the default `serde_json::to_vec` time.
For aion's typical payload sizes (~kB), this is sub-millisecond.

## Testing Strategy

### Property-Based Tests (Hegel, Tier-2)

Added to `.claude/rules/property-testing.md`:

- `prop_jcs_idempotent`: `to_jcs_bytes(parse(to_jcs_bytes(v))) ==
  to_jcs_bytes(v)`.
- `prop_jcs_keys_sorted`: every object key in the output is `<=`
  its successor in code-point order.
- `prop_jcs_no_whitespace_between_tokens`: output contains no
  SP / HT / LF / CR bytes outside of string values.
- `prop_jcs_parse_roundtrip_semantic`: parsing JCS bytes yields a
  `serde_json::Value` that compares equal (structurally) to the
  source.
- `prop_jcs_reordering_input_preserves_output`: two input
  documents that differ only in object-key order produce the
  same JCS output.

### Vector Test

From RFC 8785 Appendix A: canonicalize the example object and
assert the expected byte sequence matches.

## Implementation Plan

### Phase A (this RFC, this PR)

1. `serde_jcs = "0.2"` dep.
2. `src/jcs.rs` wrapping it with aion-typed errors.
3. `pub mod jcs;` in `src/lib.rs`.
4. Property tests + the RFC 8785 Appendix A vector.
5. Tier-2 floor + `/hegel-audit` update.

### Phase B

1. Opt-in `to_jcs_bytes()` methods on `InTotoStatement`, `AiBom`,
   `OciArtifactManifest`.
2. Rekor adapter (when RFC-0025 Phase C lands) uses JCS leaves.
3. A migration RFC if/when we want JCS as the default for new
   envelope creation (requires format-version-bump of wrappers).

## Open Questions

1. Should `to_jcs_bytes` ensure valid UTF-8 on output? RFC 8785
   mandates UTF-8; `serde_jcs` emits UTF-8. No extra check
   needed.

## References

- RFC 8785 — JSON Canonicalization Scheme:
  <https://datatracker.ietf.org/doc/html/rfc8785>
- `serde_jcs` crate: <https://crates.io/crates/serde_jcs>
- ECMAScript 2019 JSON number formatting §6.1.6.1.20.
- SPDX 3.0 canonicalization notes (Phase B reference for
  RFC-0029 translator).

## Appendix

### RFC 8785 §3.2.3 Example

Input JSON (pretty-printed):

```json
{
  "numbers": [333333333.33333329, 1E30, 4.50, 0.000002, 0.0],
  "string": "€$
A'B"\\\\"\/",
  "literals": [null, true, false]
}
```

Expected JCS output (single-line, bytes shown as Rust string):

```
{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.000002,0],"string":"€$\nA'B\"\\\\\"/"}
```

(Note the exact number formatting and string escape details.)

### Terminology

- **Canonical JSON**: a byte sequence that any conformant
  emitter produces for a given logical JSON document.
- **JCS**: JSON Canonicalization Scheme, RFC 8785.
- **Lexicographic UTF-16 ordering**: keys compared by their
  UTF-16 code-unit sequences.
