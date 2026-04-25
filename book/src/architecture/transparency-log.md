# Transparency Log (RFC-0025)

An append-only Merkle log. Lets a verifier prove that a
specific event was logged at a specific position, without
having to share the entire log. Every sealed release appends
three leaves; auditors can request inclusion proofs against
a signed root.

## Tree shape

RFC 6962 binary Merkle tree. Each leaf is a domain-tagged
BLAKE3 hash of `(kind, seq, timestamp_version, prev_leaf_hash,
payload_hash)`. Internal nodes are domain-tagged BLAKE3 of
`left || right`.

The tree is unbalanced when the leaf count isn't a power of
two — the root splits at the largest power of two strictly
less than `n`. The construction follows RFC 6962 §2.1 exactly.

## Append (O(log n))

`TransparencyLog::append(kind, payload, timestamp_version)`:

1. Computes the leaf hash.
2. Pushes it onto `leaf_hashes`.
3. Cascades the **subtree-roots cache** — a `Vec<Vec<[u8; 32]>>`
   indexed by `(level, j)` that holds every COMPLETE 2^level
   subtree's hash. Updated incrementally.

The cache is the post-PR #38 optimization that took the log
from O(n) to O(log n) on `inclusion_proof` and `root_hash`.

## Inclusion proof (O(log n))

`TransparencyLog::inclusion_proof(leaf_index)` returns an
`InclusionProof { leaf_index, tree_size, audit_path }`. The
audit path is the list of sibling subtree roots along the
path from the leaf to the root — exactly `ceil(log2(n))`
hashes.

Verification:

```rust
use aion_context::transparency_log::verify_inclusion_proof;

let leaf = log.leaf_hash_at(seq).unwrap();        // post-PR #30
let proof = log.inclusion_proof(seq)?;
verify_inclusion_proof(
    leaf,
    proof.leaf_index,
    proof.tree_size,
    &proof.audit_path,
    log.root_hash(),
)?;
```

`leaf_hash_at(seq)` is the constant-time accessor for the
stored leaf hash — added by PR #30 so verifiers don't need
the original payload bytes to construct an inclusion proof.

## Signed Tree Heads (STH)

A signed root + tree size. The log operator's master key
signs the canonical `(tree_size, root_hash)` bytes:

```rust
let operator_key = SigningKey::generate();
log.set_operator(operator_key.verifying_key());
let sth = log.sign_tree_head(&operator_key);
log.verify_tree_head(&sth)?;
```

An STH is the unit of public-audit distribution. An auditor
holding an STH and an `InclusionProof` can verify any leaf's
inclusion against the signed root without trusting the log
operator further.

## Performance

Numbers from PR #38's perf bench (single-threaded, blake3
software impl):

| Operation | N=100 | N=10k | N=100k |
|---|---:|---:|---:|
| `append` | 0.5 µs | 0.5 µs | 0.5 µs |
| `inclusion_proof` (gen) | 0.22 µs | 0.75 µs | 1.10 µs |
| `verify_inclusion_proof` | 1 µs | 2 µs | 2.7 µs |

`inclusion_proof` is **12,500× faster** at N=100k than
pre-#38 (was ~14 ms, now ~1.1 µs). The win comes from the
subtree-roots cache; the audit path itself is O(log n)
hashes — what changed is how the proof construction reads
the sibling subtree roots.

## What lives where

- **In-memory only.** The cache is rebuilt from leaf payloads
  when a log is loaded or constructed. No on-disk format
  change.
- **The leaf hashes are stored in the log** (`leaf_hashes:
  Vec<[u8; 32]>`); raw payloads are not. Verifiers using
  `leaf_hash_at` get self-contained proofs without needing
  payloads.

## See also

- RFC-0025 in `rfcs/` — protocol details
- `src/transparency_log.rs` — implementation (and 22 tests +
  9 property tests)
- `benches/transparency_log_benchmarks.rs` — Criterion bench
  that documents the post-#38 curve
