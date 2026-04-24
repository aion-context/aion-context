# RFC 0025: Transparency Log (Aion-Native Merkle Log)

- **Author:** aion-context maintainers
- **Status:** DRAFT
- **Created:** 2026-04-23
- **Updated:** 2026-04-23
- **Depends on:** RFC-0021 (attestation), RFC-0022 (manifest), RFC-0023 (DSSE), RFC-0028 (key rotation)

## Abstract

Every signed artifact produced by `aion-context` — version attestations,
manifest signatures, key rotations, key revocations, SLSA statements —
needs to be **public-log discoverable** so auditors can answer
"when was this submitted?" and adversaries cannot silently backdate.
Sigstore's Rekor is the de-facto transparency log in the industry;
integration with Rekor is a Phase B goal. Phase A (this RFC) ships
an **aion-native, offline-first append-only Merkle log** that any
verifier can replay locally without network access.

The log:

- Uses BLAKE3 with RFC 6962-style domain-separated leaf/node
  hashes (distinct from all existing aion crypto domains).
- Supports inclusion proofs (Merkle audit paths) so anyone holding
  a proof and a trusted tree head can verify that a payload is in
  the log.
- Supports operator-signed tree heads (Ed25519) so verifiers can
  pin a root-of-trust.
- Carries enough metadata per leaf (seq, kind, aion
  version-at-submission, prev-leaf-hash chain) that a reader can
  fully replay the log and answer "was this submitted before or
  after key X was revoked at version V?"

No on-disk file format change. Phase B embeds the log / proofs in
`.aion` files and bumps the format version. Phase C adds Rekor
adapters for bidirectional interop.

## Motivation

### Problem Statement

Today an `.aion` file verification is **local and stateless** — the
verifier sees the signed bytes, checks the signatures, and says
OK. No history, no ordering, no way to detect a signer who
*privately* signed something that was then withdrawn from the
official record. In the NVIDIA/Microsoft room the exact follow-up
to key rotation (RFC-0028) is:

> "How do we know this rotation wasn't backdated? How do we know
> someone with the compromised key didn't sign 20 attestations
> before revocation was published?"

The answer is a transparency log. A rotation record in the log at
seq N, with a signed tree head at size ≥ N, is public evidence
that the rotation happened before any later submission. An
attestation published to the log *after* a compromised key was
revoked cannot hide — its seq number betrays it.

### Use Cases

- **Audit replay**: a compliance auditor downloads the full log
  and recomputes every leaf hash, node hash, and root hash. The
  STH signature by the log operator proves the log's integrity
  at a point in time.
- **Inclusion proof verification**: a PR reviewer needs to verify
  that the DSSE envelope they received was recorded in the log.
  They fetch an inclusion proof for that payload, verify locally.
- **Backdating detection**: when a rotation record is published
  to the log at seq N, any attestation appearing at seq > N by
  the rotated-out key is suspicious.
- **Offline verification**: an air-gapped release officer has a
  pinned root hash in a trusted config. Any DSSE envelope paired
  with an inclusion proof can be verified without network.
- **Future**: cross-publish to Rekor for ecosystem interop
  (Phase C).

### Goals

- Append-only log — no leaf can be removed or altered after
  insertion (without invalidating the root).
- Inclusion proofs are O(log N) bytes and verifiable without
  the full log.
- Tree heads (STHs) are signed by the log operator so verifiers
  can pin trust.
- Each leaf carries the aion version-number-at-submission so
  the log's ordering is aligned with the rest of the
  crate (per `.claude/rules/distributed.md`: version numbers,
  not wall clocks, are authoritative).
- Domain separators prevent any leaf or node hash from colliding
  with any existing aion signed object.

### Non-Goals

- **Consistency proofs** (proving log A is a prefix of log B).
  Useful but deferred to Phase B — the single-operator case in
  Phase A doesn't need them.
- **Gossip / witness network** — also Phase B / C.
- **Rekor adapter** — Phase C.
- **Log persistence** — Phase A is an in-memory type; callers
  serialize if they need persistence.

## Proposal

### Merkle tree construction (RFC 6962 §2.1)

Leaves are 32-byte BLAKE3 hashes of domain-tagged leaf data:

```
leaf_hash(data) = BLAKE3("AION_V2_LOG_LEAF_V1\0" || data)
```

Internal nodes:

```
node_hash(left, right) = BLAKE3("AION_V2_LOG_NODE_V1\0" || left || right)
```

Merkle Tree Hash (MTH), defined recursively:

```
MTH([])     = BLAKE3("AION_V2_LOG_LEAF_V1\0")   # empty-tree sentinel
MTH([l_0])  = l_0                                # already a leaf hash
MTH(leaves) = node_hash(MTH(leaves[..k]), MTH(leaves[k..]))
              where k = largest power of 2 strictly less than n
```

Inclusion proofs are the siblings along the path from leaf to
root, innermost first. Verification mirrors the construction
recursively.

### Leaf data

Each log leaf carries:

| Field                  | Type       | Purpose                                                 |
|------------------------|-----------|---------------------------------------------------------|
| `kind`                 | `u16`     | What kind of object is logged (see [`LogEntryKind`]).   |
| `seq`                  | `u64`     | 0-indexed position in the log.                          |
| `timestamp_version`    | `u64`     | aion version number at submission time.                 |
| `prev_leaf_hash`       | `[u8; 32]`| Hash of previous leaf (`[0u8; 32]` for `seq == 0`).     |
| `payload_hash`         | `[u8; 32]`| BLAKE3 of the raw payload bytes.                        |

The canonical leaf-data bytes (fed into `leaf_hash`) are:

```
LE16(kind) || LE64(seq) || LE64(timestamp_version) || prev_leaf_hash || payload_hash
```

The `prev_leaf_hash` chain gives the log a secondary append-only
property independent of the Merkle tree: even if the Merkle root
is unknown, a reader walking the leaves in order can verify that
no leaf was substituted.

### LogEntryKind

```rust
#[repr(u16)]
pub enum LogEntryKind {
    VersionAttestation = 1,
    ManifestSignature  = 2,
    KeyRotation        = 3,
    KeyRevocation      = 4,
    SlsaStatement      = 5,
    DsseEnvelope       = 6,
}
```

New kinds can be added without breaking existing proofs — kind
is part of the leaf-data bytes, so old proofs still verify.

### Signed Tree Head

The log operator signs tree heads with an Ed25519 master key:

```
STH canonical = "AION_V2_LOG_STH_V1\0" || LE64(tree_size) || root_hash
```

The `SignedTreeHead` structure:

```rust
pub struct SignedTreeHead {
    pub tree_size: u64,
    pub root_hash: [u8; 32],
    pub operator_signature: [u8; 64],
}
```

### Public API

```rust
// src/transparency_log.rs

pub const LOG_LEAF_DOMAIN: &[u8] = b"AION_V2_LOG_LEAF_V1\0";
pub const LOG_NODE_DOMAIN: &[u8] = b"AION_V2_LOG_NODE_V1\0";
pub const LOG_STH_DOMAIN:  &[u8] = b"AION_V2_LOG_STH_V1\0";

pub struct LogEntry { /* kind, seq, timestamp_version, prev_leaf_hash, payload_hash */ }
pub struct InclusionProof { pub leaf_index: u64, pub tree_size: u64, pub audit_path: Vec<[u8; 32]> }
pub struct SignedTreeHead { pub tree_size: u64, pub root_hash: [u8; 32], pub operator_signature: [u8; 64] }

pub struct TransparencyLog { /* entries, leaf_hashes, operator_master_key */ }

impl TransparencyLog {
    pub fn new() -> Self;
    pub fn set_operator(&mut self, master_key: VerifyingKey);

    pub fn append(&mut self, kind: LogEntryKind, payload: &[u8], timestamp_version: u64) -> Result<u64>;
    pub fn tree_size(&self) -> u64;
    pub fn root_hash(&self) -> [u8; 32];
    pub fn entry(&self, index: u64) -> Option<&LogEntry>;
    pub fn inclusion_proof(&self, leaf_index: u64) -> Result<InclusionProof>;

    pub fn sign_tree_head(&self, operator_key: &SigningKey) -> SignedTreeHead;
    pub fn verify_tree_head(&self, sth: &SignedTreeHead) -> Result<()>;
}

pub fn leaf_hash(kind: LogEntryKind, seq: u64, timestamp_version: u64,
                 prev_leaf_hash: &[u8; 32], payload: &[u8]) -> [u8; 32];

pub fn verify_inclusion_proof(
    leaf_hash: [u8; 32],
    leaf_index: u64,
    tree_size: u64,
    proof: &[[u8; 32]],
    expected_root: [u8; 32],
) -> Result<()>;
```

### Verification semantics

`verify_inclusion_proof`:

1. Reject if `leaf_index >= tree_size`.
2. Recompute the root by walking the proof (innermost sibling
   first) alongside the tree structure derived from
   `(leaf_index, tree_size)`.
3. Compare computed root to `expected_root`.

`verify_tree_head`:

1. Verify the operator's Ed25519 signature over the canonical STH
   bytes.
2. Verify the STH's `root_hash` matches the log's current root.

### Edge Cases

- **Empty log** (`tree_size == 0`): `root_hash` is the BLAKE3 of
  the empty-leaf domain sentinel; no inclusion proofs exist.
- **Single leaf** (`tree_size == 1`): audit path is empty; root
  equals the single leaf hash.
- **Duplicate payloads**: allowed — each gets its own seq and
  `prev_leaf_hash`. Identical payloads appear at different leaf
  indices.
- **Out-of-range index**: `inclusion_proof` and
  `verify_inclusion_proof` return `Err`.
- **Unset operator**: `verify_tree_head` returns `Err` if the
  operator master key is not registered.

## Rationale and Alternatives

### Why a new log instead of Rekor-only?

Rekor is excellent but: network-dependent, Sigstore-operated,
requires HTTP round-trips, and adds a runtime dependency on
infrastructure outside the aion project. For a file format that
must work offline and in air-gapped environments, we need a
log layer that functions locally. Rekor integration is
strictly additive.

### Why RFC 6962 Merkle construction?

It's the industry standard — Certificate Transparency uses it,
Rekor uses it, every major transparency-log implementation
copies it. Interop with Rekor in Phase C requires the same
tree shape. Rolling our own balanced-tree variant would save
nothing and lose interop.

### Why BLAKE3 instead of SHA-256 (the CT default)?

`aion_context::crypto::hash` is already BLAKE3 (RFC-0002), and
matching the crate's existing primitive avoids a second fuzzing
campaign. When Phase C adds Rekor export we'll also emit a
SHA-256 shadow tree for wire compatibility; internal verification
stays BLAKE3.

### Why `prev_leaf_hash` in addition to Merkle?

Defense in depth. If a verifier only has the leaf chain and no
Merkle proof, they can still verify append-only-ness. This also
simplifies `/hegel-audit` of the log (linear replay, O(N)).

### Why `timestamp_version` instead of wall-clock?

`.claude/rules/distributed.md` — aion uses version numbers as
the authoritative ordering. A log entry says "this was submitted
in the context of aion version V_submit"; comparing against a
rotation's `effective_from_version` directly answers
before/after questions.

## Security Considerations

### Threat Model

1. **Silent tampering with historical leaves**: attacker modifies
   entry N's payload. Detected — `leaf_hash(N)` changes, so the
   tree root changes, so any pinned STH no longer matches.
2. **Reordering / insertion**: attacker swaps two leaves.
   Detected — `prev_leaf_hash` chain breaks; Merkle root changes.
3. **Operator compromise**: attacker with the operator master
   key signs a fraudulent STH. Out of scope for this RFC; the
   standard mitigation is witness gossip (Phase B).
4. **Forged inclusion proof**: attacker fabricates siblings.
   Detected — the recomputed root won't match the pinned STH.
5. **Replay of old STH**: attacker presents a tree head smaller
   than the current log state. Detected by any party tracking the
   maximum observed `tree_size`.

### Security Guarantees

- **Append-only**: after `append(N)`, no caller can modify leaf
  N without invalidating the root.
- **Global ordering**: `seq` is strictly monotonic and dense.
- **Non-repudiation**: a signed tree head proves the operator
  committed to exactly this sequence at that size.
- **Offline verifiability**: given the full log or a payload +
  inclusion proof + pinned STH, verification is pure-local.

## Performance Impact

- **Append**: one BLAKE3 leaf hash + recomputed root. The root
  recomputation is O(N) in the naïve Phase-A implementation; a
  frontier cache (Phase B) brings it to O(log N).
- **Inclusion proof**: O(log N) siblings, O(N log N) to
  generate in Phase A.
- **Verify**: O(log N) hashes, independent of log size.
- **Storage**: ~80 bytes per entry (in-memory representation).

## Testing Strategy

### Property-Based Tests (Hegel, Tier-2)

Added to `.claude/rules/property-testing.md`:

- `prop_inclusion_proof_roundtrip_for_any_n`: for any N and any
  index < N, `inclusion_proof` → `verify_inclusion_proof` is
  `Ok` against the current root.
- `prop_tampered_payload_rejects`: flipping any byte in a
  leaf's payload after proof generation invalidates the proof.
- `prop_wrong_index_rejects`: claiming a different
  `leaf_index` with the same proof fails.
- `prop_tampered_proof_sibling_rejects`: flipping any byte in
  any sibling in the proof invalidates it.
- `prop_leaf_chain_is_monotonic`: for every sequential pair of
  entries, `entry[i+1].prev_leaf_hash == leaf_hash(entry[i])`.
- `prop_sth_sign_verify_roundtrip`: `sign_tree_head` →
  `verify_tree_head` is `Ok`.
- `prop_forged_sth_rejects`: mutating any STH field after
  signing invalidates the signature.
- `prop_tree_size_matches_entries`: after N appends,
  `tree_size() == N`.

### Vector Test

Append three leaves with fixed payloads; assert the BLAKE3 root
matches a precomputed value. Catches any drift from the RFC 6962
split-point definition.

## Implementation Plan

### Phase A (this RFC, this PR)

1. `src/transparency_log.rs` with the full public API.
2. `pub mod transparency_log;` in `src/lib.rs`.
3. Property tests + one vector test.
4. Tier-2 floor + `/hegel-audit` update.

### Phase B

1. **Consistency proofs**: prove log-at-size-N is a prefix of
   log-at-size-M.
2. **Frontier cache** for O(log N) appends.
3. **Persisted log**: on-disk serialization format for the log
   state + periodic checkpointing.
4. **CLI integration**: `aion log append`, `aion log prove`,
   `aion log verify`.

### Phase C

1. **Rekor adapter**: submit DSSE envelopes to a Rekor instance;
   fetch inclusion proofs; round-trip.
2. **SHA-256 shadow tree** for CT/Rekor wire interop.
3. **Witness protocol** for operator-compromise resilience.

## Open Questions

1. Should the log persist as its own `.aionlog` file format,
   or ride inside an `.aion` file as a new section? Phase A
   answer: orthogonal; both are Phase B choices.
2. Should `verify_inclusion_proof` accept an arbitrary
   `expected_root` (as proposed), or only a `SignedTreeHead`?
   Phase A answer: accept raw `root_hash`; callers compose with
   STH verification as they need.

## References

- RFC 6962 — Certificate Transparency (Merkle tree definitions).
- Sigstore Rekor: <https://github.com/sigstore/rekor>
- Trillian (production CT log): <https://github.com/google/trillian>
- Transparency logs in supply chain: <https://transparency.dev/>

## Appendix

### Terminology

- **Leaf hash**: BLAKE3 of the domain-tagged canonical leaf data.
- **Node hash**: BLAKE3 of the domain-tagged concatenation of
  two child hashes.
- **MTH**: Merkle Tree Hash — the root hash under the RFC 6962
  split-point construction.
- **Audit path / inclusion proof**: the sequence of siblings
  from a leaf to the root.
- **STH**: Signed Tree Head.
- **Operator master key**: the Ed25519 key that signs STHs.
