# RFC 0035: Chain-Architecture Guide

- **Author:** aion-context maintainers (surfaced from SEC quarterly audit roleplay)
- **Status:** ACCEPTED
- **Created:** 2026-04-25
- **Updated:** 2026-04-25

## Abstract

There are two valid ways to lay out an archive of `.aion` files,
and they have very different interactions with key rotation
([RFC-0028]). **Per-file genesis** stores every governance event
in its own `.aion`, each starting at version 1. **Growing-chain**
accrues amendments into a single `.aion` via `aion commit`, with
each amendment incrementing a global version number. This RFC is
operator-facing guidance: it documents both architectures,
explains when to choose each, and gives concrete migration steps
when an operator chose wrong and needs to consolidate.

This RFC is documentation only. No new code, no protocol change.
The CLI warning that catches the most common per-file genesis
mistake is implemented separately ([issue #49] / PR #52); the
auditor-side bulk-verify subcommand is [issue #48] / PR #51.

## Motivation

### Problem Statement

The SEC quarterly audit roleplay (see issue #48 thread) put a
synthetic auditor in front of a 13-week archive of governance
files. The publisher had naively chosen per-file genesis (each
weekly file at version 1) and rotated the CCO's operational key
mid-quarter. The result: post-rotation files signed with the new
key failed to verify under the new registry, **and** there was
no value of `--effective-from-version` for the rotation that
would simultaneously preserve prior valid signatures and admit
new ones. Per-file genesis fundamentally cannot accommodate key
rotation, because every file is at v1 and a `KeyRegistry` can
pin exactly one epoch as active at any given version.

The mistake is currently invisible at choose-time and only
surfaces months or years later when a key actually rotates. By
then the archive has grown and consolidation is painful.

This RFC makes the choice visible and documents the consequences
up-front.

### Use Cases

1. **A new operator** opening the docs to decide how to lay out
   their first archive.
2. **An existing operator** who chose per-file genesis and is
   now staring at a CCO departure that requires rotation. They
   need to know what their migration looks like.
3. **A reviewer** examining an archive who wants to understand
   why one author has multiple distinct keys observed across
   files (rotation? compromise? something else?).

### Goals

- Document both architectures clearly enough that an operator
  can decide between them in 15 minutes.
- Provide a 3-question diagnostic matrix: how often will keys
  rotate, do amendments need to be re-orderable, will a single
  event need to be verifiable in isolation.
- Spell out the migration path from per-file genesis to a
  growing chain, since that is the realistic recovery story.

### Non-Goals

- Not deprecating either architecture. Both are valid for
  different use cases.
- Not adding tooling to migrate existing files. The migration
  is straightforward enough to do by hand for archives smaller
  than ~1000 files; large archives can script it.
- Not changing on-disk format. This is purely about how to
  arrange a collection of `.aion` files relative to each other.

## Proposal

### Overview

Two architectures; both supported, neither favored:

```
Per-file genesis:                          Growing chain:

  ./archive/                                  ./governance/
    ├── week-01.aion   (genesis, v1)            └── policy.aion
    ├── week-02.aion   (genesis, v1)                ├── v1  (genesis)
    ├── week-03.aion   (genesis, v1)                ├── v2  (commit)
    ├── ...                                          ├── v3  (commit)
    └── week-13.aion   (genesis, v1)                └── ...
```

In **per-file genesis**, each file is independent. There is no
linkage between files at the cryptographic level — the archive's
ordering is filename ordering, not chain ordering.

In **growing-chain**, every amendment chains to its predecessor
via `parent_hash`. The file grows monotonically; rolling back is
not possible without a new policy version that supersedes the
old.

### Detailed Design

#### Per-file genesis

**When to use:**
- Events are independent and need to be verifiable in isolation.
  An auditor receiving file N should not need files 1..N-1 to
  validate it.
- Keys do not rotate. Or rotate so rarely (every 5+ years) that
  archive consolidation at rotation time is acceptable.
- Amendments are atomic and self-contained — each file's rules
  are the complete authoritative content as of that date.

**Behavior under rotation:**
- A `KeyRegistry` can pin exactly one operational epoch as
  active at any given version number.
- Every per-file genesis file is at version 1.
- After a rotation with any choice of `--effective-from-version`,
  either prior or post-rotation files at v1 will fail to verify.
- This is not a bug; it is the unavoidable consequence of
  combining per-file genesis with key rotation.

**Mitigation:** the archive must be re-signed under the new
registry, OR the operator must keep multiple registries
(one per author rotation generation) and verify each file
against the registry that was in effect when it was signed.

#### Growing-chain

**When to use:**
- Amendments are sequential and each builds on the prior. Roll-
  back is undesirable; the chain is the canonical history.
- Keys rotate on a normal cadence (annually or more frequently).
- A reviewer needs the full timeline to make sense of any
  individual amendment.

**Behavior under rotation:**
- Versions are monotonic across the entire chain.
- A rotation effective at version V cleanly partitions the
  history: epoch 0 covers `[0, V)`; epoch 1 covers `[V, ∞)`.
- All prior signatures stay valid (they're at versions `< V`).
- All future commits use the new operational key (epoch 1).

**Operational caveat:** the file grows unboundedly. Archives
spanning years of weekly amendments will reach hundreds of
kilobytes (after issues #35, #36, this is no longer a perf
problem — verify is O(n) at ~2 µs/version, so a 10k-version
chain verifies in under 25 ms).

#### Hybrid: shard by signer or by quarter

A middle path. Two examples:

- **Per-author chain.** Each signer has their own growing chain.
  CCO commits flow into `cco-policy.aion`, Risk Officer commits
  into `risk-policy.aion`. Rotation is per-author and clean.
  Auditor walks both chains.

- **Per-period chain.** Each calendar quarter is its own growing
  chain. `2026-Q1.aion`, `2026-Q2.aion`. Rotation that happens
  mid-quarter still has the per-file genesis problem within
  that quarter, but quarters before and after are clean.

Hybrid is appropriate when the chain shape needs to bound the
file size or isolate concerns, AND key rotation is rare enough
that the within-shard rotation problem is acceptable.

### Examples

#### Per-file genesis archive

```bash
# Each weekly file is its own genesis.
$ aion init week-01.aion --author 401001 --key cco-key \
    --rules week-01-rules.yaml --message "Q3 W1"
$ aion init week-02.aion --author 401001 --key cco-key \
    --rules week-02-rules.yaml --message "Q3 W2"
# ... 11 more weeks ...

# Auditor walks the directory:
$ aion archive verify ./q3-archive/ --registry registry.json
```

#### Growing-chain archive

```bash
# Genesis once; subsequent commits accrete.
$ aion init policy.aion --author 401001 --key cco-key \
    --rules genesis.yaml --message "Q3 genesis"
$ aion commit policy.aion --author 401001 --key cco-key \
    --rules week-02-rules.yaml --message "Q3 W2 amendment" \
    --registry registry.json
$ aion commit policy.aion --author 401001 --key cco-key \
    --rules week-03-rules.yaml --message "Q3 W3 amendment" \
    --registry registry.json
# ... 11 more commits ...

# Auditor walks the chain in one file:
$ aion verify policy.aion --registry registry.json
$ aion show policy.aion --registry registry.json history
```

### Edge Cases

**Key rotation mid-quarter, growing-chain.** Pass
`--effective-from-version` equal to the version number that the
NEXT commit will produce. Example: chain is at v7 today; rotation
takes effect at v8.

```bash
$ aion registry rotate --author 401001 --from-epoch 0 --to-epoch 1 \
    --new-key new-cco-key --master-key cco-master \
    --effective-from-version 8 \
    --registry registry.json
```

The next commit (v8) and all subsequent ones use the new key;
versions 1–7 keep verifying under epoch 0.

**Key rotation mid-quarter, per-file genesis.** Choose:

- (a) Pass `--effective-from-version 2` (or any value > 1). All
  pre-rotation v1 files keep verifying. All post-rotation files
  built with the new key will need to be at v=2 (forces the
  publisher to use `aion commit` after the first init for those
  files, which contradicts the "per-file genesis" choice).
- (b) Re-sign the entire archive under a freshly-pinned registry
  that has the new key as epoch 0. Loses the rotation history
  but produces a clean archive.
- (c) Maintain multiple registries (one per rotation generation)
  and have downstream verifiers select the correct one per
  file. Operationally painful.

The CLI emits a warning when `--effective-from-version` matches
the active epoch's `created_at_version` (issue #49 / PR #52),
which catches the (a) case at rotation time.

### Migration: per-file genesis → growing chain

Mechanical and lossy. Lossy because the migration produces a
single .aion whose internal version chain is the new ground
truth; the original per-file archive becomes historical evidence
but no longer the primary verifiable artifact.

```bash
# 1. Pick the genesis file. Its rules become v1 of the new chain.
$ cp week-01.aion governance.aion

# 2. For each subsequent week, commit its rules into the chain.
#    The new commits are signed by whoever holds the current op
#    key — typically a one-shot script run by the original signer.
$ for week in 2 3 4 ... 13; do
    aion commit governance.aion --author 401001 --key cco-key \
        --rules "week-${week}-rules.yaml" \
        --message "(migrated from week-${week}.aion)" \
        --registry registry.json
  done

# 3. Verify the consolidated chain:
$ aion verify governance.aion --registry registry.json

# 4. Archive the original per-file directory as historical
#    evidence; serve `governance.aion` as the new canonical
#    artifact.
```

After migration, future rotations use the growing-chain rules
(set `--effective-from-version` to the next commit's version
number).

## Rationale and Alternatives

### Why guidance over a forced architecture?

aion-context is a primitive, not a framework. Operators have
legitimate reasons to choose either architecture, and forcing
one would break use cases the library is designed to support.

### Alternatives Considered

1. **Forbid per-file genesis when a registry is pinned.** Rejected:
   the only-active-epoch problem is real, but per-file genesis
   has legitimate uses (independent attestations, single-event
   verification). A documentation answer is better than a
   compile-time constraint.

2. **Add a "chain-of-chains" format**: a top-level chain that
   indexes per-file genesis files. Rejected: adds format
   complexity for a problem that is fully solved by either
   choosing growing-chain up front or migrating to it later.

3. **Make `aion init` produce non-v1 files when the registry
   has a non-v0 active epoch.** Rejected: would silently
   diverge from operator intent and obscure the architectural
   choice.

## Security Considerations

### Threat Model

This RFC is documentation; it does not introduce new
cryptographic primitives. The threat model is unchanged from
RFC-0028 (key registry) and the umbrella aion-context threat
model in `.claude/rules/distributed.md`.

### Attack Vectors

The architectural choice intersects with one threat: an attacker
who controls the time of a forced rotation could deliberately
choose a poorly-architected archive to mass-invalidate prior
signatures. With per-file genesis archives, this is unavoidable
under the current registry semantics. Operators concerned about
forced rotations should choose growing-chain, where rotation
effective-from-version cleanly partitions history.

### Security Guarantees

- Per-file genesis: each file's signature is independent.
  Compromise of an individual file's bytes is contained.
- Growing-chain: the parent-hash chain links every entry, so
  tampering of any entry breaks the chain and is detected by
  `verify_file`. Issue #43 also runs the chain check at commit
  time.
- Hybrid: composes the guarantees of its component shards.

## Performance Impact

No code change in this RFC.

For sizing reference, given the perf fixes from PRs #37 and #38:

- Growing-chain verify_file: ~2 µs/version. A 10k-version chain
  verifies in ~25 ms.
- Per-file genesis archive verify: each file ~3 ms (parse +
  verify). A 1000-file archive: ~3 s.
- Both are far below operator-pain thresholds for typical
  audit cadences.

## Testing Strategy

This RFC introduces no testable code paths. The existing tests
that validate the architectures separately:

- `commit_succeeds_on_clean_chain_of_many_versions` exercises
  growing-chain at N=200.
- The CLI integration tests for `aion archive verify`
  (PR #51) exercise per-file genesis archives.
- The CLI integration tests for `aion registry rotate`
  (PR #52) exercise the rotation warning specific to per-file
  genesis.

## Implementation Plan

This RFC ships only the text. The associated CLI surface
(archive verify, rotate warning) is already implemented:

- PR #51 (#48): `aion archive verify <DIR>` — auditor side.
- PR #52 (#49): `aion registry rotate` warning — publisher side.

If a future RFC introduces a chain-of-chains format or other
material change to how archives are laid out, it would
supersede the recommendations here.

## Open Questions

1. Should `aion init` emit a one-line note suggesting growing-
   chain when it detects an existing `.aion` file in the same
   directory? Probably not — that crosses from documentation
   into opinionated tooling. Tracked as a future-improvement
   if operator feedback warrants.

2. Is per-author hybrid sharding worth a dedicated CLI helper
   (e.g., `aion archive new --shard-by author`)? Same answer:
   wait for operator demand.

## References

- [RFC-0028]: Key rotation and revocation registry semantics.
- [RFC-0034]: Registry-aware verify rollout (the Phase E
  removal that made registry mandatory).
- Issue #48: `aion archive verify` (auditor side).
- Issue #49: `aion registry rotate` warning (publisher side).
- The SEC quarterly audit roleplay session (this RFC's
  motivating scenario).
- `.claude/rules/distributed.md`: aion-context threat model.

## Appendix

### Terminology

- **Per-file genesis**: archive layout where every governance
  event lives in its own `.aion`, each at version 1. Files are
  cryptographically independent.
- **Growing-chain**: archive layout where amendments accrete
  into a single `.aion` via `aion commit`, with version numbers
  monotonic across the lifetime of the chain.
- **Hybrid sharding**: a finite set of growing chains, sharded
  by signer, calendar period, or some other dimension.
- **Active epoch's window**: the half-open version-number
  interval `[created_at_version, effective_from_version_of_next_epoch_or_revocation)`
  within which the epoch's pinned operational key is the
  signer of record for that author.
- **Retroactive invalidation**: setting `--effective-from-version`
  for a rotation to a value `V` such that the outgoing epoch's
  window collapses to zero length, making every prior v=`V`
  signature by that author invalid against the post-rotation
  registry.

[RFC-0028]: ./RFC-0028-key-rotation-revocation.md
[RFC-0034]: ./RFC-0034-registry-aware-verify-rollout.md
[issue #48]: https://github.com/aion-context/aion-context/issues/48
[issue #49]: https://github.com/aion-context/aion-context/issues/49
