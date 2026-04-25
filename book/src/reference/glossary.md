# Glossary

A reference for terms used throughout this book and the
project's RFCs.

### `.aion` file

The on-disk binary format. Header + audit trail + version
chain + signatures + string table + encrypted rules +
integrity hash. Zero-copy parseable.

### active epoch

For an author at a given version, the unique `KeyEpoch` whose
`is_valid_for(version)` predicate holds. The registry's
`active_epoch_at(author, version)` resolves it.

### AIBOM

AI Bill of Materials (RFC-0029). Captures frameworks,
datasets, licenses, safety attestations, and export-control
classifications for an AI model release.

### AionError

The crate's top-level error enum. `#[non_exhaustive]` since
PR #44 — adding a variant is no longer a breaking change for
downstream `match` arms.

### attestation

A signature made by a non-author (RFC-0021). Multi-party
attestations let multiple signers endorse a single version.

### audit trail

The append-only log inside an `.aion` file. Each entry is
hash-chained to the prior; tampering breaks the chain.

### author

An identity that signs versions or attestations. Identified
by `AuthorId(u64)`. Pinned in the registry with a master key
and an operational-key epoch sequence.

### chain architecture

The choice between **per-file genesis** (each `.aion` at v1,
files independent) and **growing-chain** (one `.aion`,
amendments accrete via `commit`). See RFC-0035 and the
[chain-architecture page](../operations/chain-architecture.md).

### compute_version_hash

The function that produces the BLAKE3 hash of a `VersionEntry`'s
canonical bytes, used as the `parent_hash` of the next entry
in the chain.

### DSSE

Dead Simple Signing Envelope (RFC-0023). Sigstore / in-toto
interop format. aion-context uses DSSE to wrap manifest
signatures, AIBOM records, and SLSA statements for
ecosystem compatibility.

### effective_from_version

The version number at which a rotation or revocation takes
effect. The outgoing epoch's window closes at this version;
the incoming epoch's window opens at this version.

### epoch

A time window during which a specific operational key was
authoritative for an author. Epochs are append-only;
transitions (rotation, revocation) are master-signed records.

### evidence (RFC-0026)

Opaque bytes from a TEE attestation quote (TPM2, NVIDIA NRAS,
Intel TDX, AWS Nitro, Arm CCA, Azure Attestation, ...).
aion-context treats evidence as opaque; consumers slot in
platform-specific verifiers under the `EvidenceVerifier` trait.

### file_id

A `u64` random identifier baked into a file's header at
genesis. Distinguishes files of the same name on different
machines.

### genesis

The first version (`v1`) of a `.aion` file, produced by
`aion init`. Has `parent_hash = [0u8; 32]`.

### growing chain

See **chain architecture**.

### head signature

The signature on the most recent version in the chain. Post-PR
#37, `commit_version` verifies the head signature (and the
integrity hash + parent_hash chain) before appending a new
version.

### hybrid signature (RFC-0027)

A signature pair combining a classical Ed25519 sig and a
post-quantum ML-DSA-65 sig over the same payload. Both must
verify for the hybrid signature to be accepted.

### integrity hash

The trailing 32-byte BLAKE3 hash at the end of an `.aion`
file. Covers all bytes above it. Detects whole-file
tampering.

### KeyEpoch

A struct in the registry: `epoch: u32`, `public_key:
[u8; 32]`, `created_at_version: u64`, `status: KeyStatus`.

### KeyRegistry

The trusted-key registry. `from_trusted_json` / `to_trusted_json`
round-trip a JSON form. `active_epoch_at(author, version)` is
the resolver verifiers use.

### KeyStatus

One of `Active`, `Rotated { successor_epoch,
effective_from_version }`, `Revoked { reason,
effective_from_version }`.

### master key

The long-lived per-author key that authorizes rotations and
revocations. Distinct from operational keys, which sign
day-to-day amendments.

### model_ref

The AIBOM's reference to the primary artifact: name, version,
hash, size, format.

### multisig (RFC-0021)

K-of-N threshold attestation. `MultiSigPolicy::m_of_n(k,
authors)` declares the policy; `verify_multisig` evaluates a
bag of signatures against it.

### non-exhaustive

Per `.claude/rules/api-design.md`, a Rust-stability discipline:
public enums that are expected to grow are marked
`#[non_exhaustive]` so downstream consumers' exhaustive `match`
statements don't break on minor releases. `AionError` is
non-exhaustive (PR #44); `SignedRelease` is non-exhaustive;
`SignedReleaseComponents` is **not** (it's the constructible
counterpart, PR #47).

### operational key

The per-author per-epoch signing key that produces the
day-to-day signatures on versions and attestations. Rotates
and revokes over time, as recorded in the registry's epoch
sequence. Cf. **master key**.

### parent_hash

A 32-byte field in `VersionEntry` containing
`compute_version_hash(prev_version)`. The chain link.

### per-file genesis

See **chain architecture**.

### registry-aware verify (RFC-0034)

Every signature-verification path takes a `&KeyRegistry`
parameter. The library has no raw-key verify_* variants —
PR #22 removed them. The registry resolves which public key
to expect for `(author, version)`.

### retroactive invalidation

Setting `--effective-from-version` for a rotation to a value
that collapses the outgoing epoch's window to zero length,
making every prior signature at that version invalid. The
CLI warns when this smell triggers; see RFC-0035.

### sealed release (RFC-0032)

The composite object: manifest + signature + AIBOM + SLSA
statement + 3 DSSE envelopes + OCI primary + 2 OCI referrers
+ 3 transparency-log entries, all cryptographically
cross-linked.

### SignatureEntry

The 112-byte struct holding `(author_id, public_key,
signature, reserved)`. `reserved` must be zero on parse.

### SignedTreeHead (STH)

A signed `(tree_size, root_hash)` pair from a transparency
log, signed by the log operator's master key. The unit of
public-audit distribution.

### SLSA

Supply-chain Levels for Software Artifacts. `aion-context`
emits SLSA v1.1 in-toto Statements as part of sealed
releases (RFC-0024).

### subtree-roots cache

The post-PR #38 in-memory structure on `TransparencyLog` that
holds every COMPLETE 2^level subtree hash, indexed by
`(level, j)`. Updated incrementally on `append`. Made
`inclusion_proof` and `root_hash` O(log n) instead of O(n).

### Tiger Style / NASA Power-of-10

Discipline rules enforced at the compiler level via crate
clippy lints: zero panics in production, max 60-line
function bodies, every loop with a visible termination
condition, etc. See `.claude/rules/tiger-style.md`.

### transparency log (RFC-0025)

The append-only Merkle log. Each leaf is a hash-chained
record `(kind, seq, timestamp_version, prev_leaf_hash,
payload_hash)`. STHs travel separately from inclusion
proofs.

### version chain

The sequence of `VersionEntry` records inside an `.aion`
file. Each version's `parent_hash` is the BLAKE3 of the
prior version's canonical bytes.

### VersionEntry

The 152-byte struct holding `(version_number, parent_hash,
rules_hash, author_id, timestamp, message_offset,
message_length, reserved)`. `reserved` must be zero on parse.

### VerificationReport

The struct produced by `verify_file`. Four independent
boolean fields (`structure_valid`, `integrity_hash_valid`,
`hash_chain_valid`, `signatures_valid`) plus an aggregate
`is_valid`. The CLI's exit-code contract maps `is_valid` to
`ExitCode::SUCCESS` / `ExitCode::FAILURE` via
`VerificationReport::exit_code()`.
