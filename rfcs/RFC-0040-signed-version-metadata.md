# RFC 0040: Signed Version Metadata (Format v4)

- **Author:** copyleftdev
- **Status:** ACCEPTED (2026-10-23; crypto-auditor PASS, round 3)
- **Created:** 2026-10-23
- **Updated:** 2026-10-23 (crypto-auditor rounds 1–2 addressed; see Review history)
- **Depends on:** RFC-0002 (file format), RFC-0005 (signature chain),
  RFC-0021 (attestations), RFC-0023 (DSSE), RFC-0039 (format v3)
- **Fixes:** GHSA-69cp-fwrw-82vh
- **Unblocks:** RFC-0039 Phase C2, `aion migrate` (a signed migration link)

## Abstract

Version signatures cover each version entry's fixed fields, but not the
commit-message text and not the audit trail. Both are protected only by
unkeyed hashes, which detect accidental corruption but not forgery, so
anyone holding a file can rewrite them without any key
(GHSA-69cp-fwrw-82vh). Format v4 adds a signed **metadata commitment** to
every version. It commits to the version's commit-message bytes and to
the version's audit entry, whose v4 hash covers its details text and,
through the audit chain, every earlier entry. v4 also fixes the string
table to a canonical layout, ties the header's copies to signed values,
and displays metadata only from verified bytes. The same commitment
carries the signed migration link that `aion migrate` needs.

## Motivation

### Problem Statement

The format-v3 canonical version message (RFC-0039) signs:

```
domain ‖ format ‖ file_id ‖ mode ‖ version ‖ parent_hash ‖ rules_commitment ‖
author ‖ timestamp ‖ message_offset ‖ message_length
```

`message_offset` and `message_length` locate the commit message in the
string table; the message bytes are not signed. Audit entries chain by
`BLAKE3(entry bytes)`, which covers each entry's 80 fixed bytes but not
its details text, and the chain is unkeyed. The whole-file integrity hash
is unkeyed too. So, in format v2 (1.x) and format v3 (2.x):

1. A commit message can be rewritten (same length) and the integrity hash
   recomputed; `verify_file` reports the file valid and `show history`
   shows the forged text.
2. Any audit entry (timestamp, author, action, details) can be rewritten
   and the audit chain and integrity hash recomputed.

Both need only the file bytes. Commit messages and audit entries are
routinely approval and compliance records ("Approved by: …"). The README
and the security audit guide promise that any modification is detectable.

Separately, `show_version_history` and `show_file_info` read a file,
check nothing, and print its metadata; an out-of-range message silently
prints as empty. Signing the metadata is useless if the display path does
not go through verification.

RFC-0039 Phase C puts the `aion migrate` continuity link in an audit
entry, which without this RFC would be forgeable the same way.

### Use Cases

- An auditor relies on a policy file's commit messages and audit trail as
  the record of who approved which change.
- A v2 or v3 file is migrated to a new file, and a verifier must be able
  to prove the new file continues the old one's rules, under a policy for
  who may continue it.

### Goals

- In new (v4) files, the commit messages, the audit trail with its
  details, and the migration link are covered by version signatures, and
  every other byte that could be shown as metadata is either canonical or
  checked against a signed value.
- Metadata is displayed only from bytes that verification checked.
- Verification stays key-free and O(entries).
- Old readers reject the new format deterministically; new readers keep
  reading v2 and v3 and say plainly that their metadata is unsigned.

### Non-Goals

- Fixing existing v2 or v3 files in place. Their signatures never covered
  the metadata. `aion migrate` re-signs the rules into v4; it does not
  import, and so cannot vouch for, the source's history.
- Commit-message confidentiality (RFC-0039 Unresolved Question 4).
- Signing the signature entries' raw bytes. They are verified, not
  displayed as content; see "Header and signature entries".

## Proposal

### Overview

```
version N's audit entry ──v4 audit hash (covers details, chains to N-1)──┐
version N's commit message bytes ────────────────────────────────────────┤
                                                                          ▼
                     metadata_commitment = BLAKE3(domain ‖ len ‖ message ‖ audit_hash)
                                                                          │ stored in VersionEntry.reserved[1..33]
                                                                          ▼
                                signed by the author (v4 signature domain)
```

### Detailed Design

#### Header

- `version = 4`. Format v4 is format v3 plus everything in this RFC.
  Every RFC-0039 rule (rules modes, commitment, framing, envelope,
  confidential recipients, acceptance) applies unchanged.
- Flags: bit 0 is HEAD_CONFIDENTIAL; **every other bit must be zero**.
  The header's reserved bytes must be zero, and its section offsets and
  counts must pass the existing structural checks (RFC-0002, GHSA-9c6x
  bounds). Together with the header-copy equalities below, every header
  byte is either structural, checked, or equal to a signed value.
- Readers older than this RFC fail at the header with
  `AionError::UnsupportedVersion` (`FormatVersion::from_u16`). v3 readers
  would also reject a v4 entry's non-zero `reserved[1..33]`.

#### Version entry

`VersionEntry.reserved` (52 bytes) in v4:

| Bytes | Meaning |
|---|---|
| `0` | `rules_mode` (RFC-0039) |
| `1..33` | `metadata_commitment` |
| `33..52` | Reserved, must be zero |

The 152-byte layout is unchanged. Reading the reserved bytes becomes
format-aware: `RulesMode::of` (and the internal `from_reserved`, which
rejects any non-zero `reserved[1..]`) gain a format parameter, and a v4
accessor returns the commitment. `FormatVersion` gains `V4`, which breaks
exhaustive matches downstream (acceptable in the major release).

#### Audit trail: one entry per version

In v4 the audit trail is a commit log: **exactly one entry per version,
in version order.** `audit_trail_count == version_chain_count`, and
audit entry `i` (0-based) belongs to version `i + 1`. Each entry must
agree with its version: same `author_id`, same `timestamp`, and
`action_code`:

- version 1: `CreateGenesis` (1) or `MigratedFrom` (5);
- later versions: `CommitVersion` (2).

`Verify` (3) and `Inspect` (4) entries cannot appear in v4 files. Every
current writer already appends exactly one entry per `init` and per
commit, through one append path that `commit_version`,
`commit_version_with_signer`, and `commit_version_force_unregistered` all
share; this codifies it.

Details rules:

- `CreateGenesis` and `CommitVersion`: no details; `details_offset` and
  `details_length` must both be 0.
- `MigratedFrom`: details hold the migration link (see Migration), parsed
  strictly.

`ActionCode` gains `MigratedFrom = 5`, and the "5–99 reserved" text is
updated.

#### v4 audit-entry hash and chain

```
audit_hash_v4(entry) = BLAKE3("AION_V4_AUDIT_ENTRY_V1\0" ‖ entry_bytes[80] ‖
                              u32_le(details_len) ‖ details_bytes)
```

In v4 every entry's `previous_hash` is the v4 hash of the entry before
it, and the first entry's is zero. The v2 `AuditEntry::compute_hash` and
`validate_chain` are not used on v4 files; v4 has its own walk. Because
each version commits to its own entry's v4 hash, and the count rule
leaves no entry without a version, the head version's signature covers
the whole trail.

#### Canonical string table

In v4 the string table holds exactly the referenced strings, in order,
and nothing else. For each version `N = 1..=count`:

```
message_N ‖ 0x00 ‖ (details_N ‖ 0x00, only when details_length_N > 0)
```

Every `message_offset`/`details_offset` must point at its slot in this
layout, and the table's total length must match it exactly. So there are
no gaps, overlaps, or unreferenced bytes for anyone to edit, and an
out-of-range offset is a verification failure, never an empty string.
Message and details lengths are bounded by `u32` (and by the file).

#### Metadata commitment

```
metadata_commitment(version N) = BLAKE3("AION_V4_METADATA_COMMIT_V1\0" ‖
                                        u64_le(N) ‖
                                        u32_le(message_len) ‖ message_bytes ‖
                                        audit_hash_v4(version N's own audit entry,
                                                      at 0-based index N-1))
```

The version number is included for defence in depth; the signature
already binds it.

**Text rules.** In v4, commit messages and audit details must be valid
UTF-8 with no NUL bytes (the string table uses NUL as a terminator).
Writers and verifiers reject a length that does not fit in `u32`.
Display escapes control characters, so signer-authored text cannot
inject terminal escapes.

#### Header and signature entries

- **Header copies.** v4 verification requires the header's copies to
  equal signed values: `current_version` = head version, `root_hash` =
  genesis rules commitment, `current_hash` = head rules commitment,
  `created_at` = genesis timestamp, `modified_at` = head timestamp, and
  flags bit 0 = head mode (as in v3); all other flag bits and all
  reserved header bytes must be zero. A disagreement rejects the file.
- **Signature entries.** Each entry's `author_id` must equal its
  version's author, and its public key is checked against the registry's
  active epoch, as today. Signature bytes are verified, never displayed.

#### Signatures and version hash

The v4 canonical message adds the commitment after the mode, under new
domains:

```
AION_V4_VERSION_SIGNATURE_V1\0 ‖ format_version u16 ‖ file_id u64 ‖ mode u8 ‖
metadata_commitment[32] ‖ version u64 ‖ parent_hash[32] ‖ rules_commitment[32] ‖
author u64 ‖ timestamp u64 ‖ message_offset u64 ‖ message_length u32
```

- The v4 version hash is `BLAKE3(AION_V4_VERSION_HASH_V1\0 ‖ fields)`,
  where `fields` is everything after the signature domain. Metadata is
  part of each version's identity, so parent links and the RFC-0039
  acceptance store bind it.
- RFC-0021 attestations use `AION_V4_ATTESTATION_V1\0` with the same
  fields; `verify_multisig` dispatches on the format through
  `FileContext`.
- RFC-0027 hybrid signatures and RFC-0038 external signers sign the v4
  canonical message. A KMS or HSM sees only the commitment hash, never
  the commit text; the core computes the commitment, so the provider
  cannot sign a different message.
- **DSSE.** The version-attestation payload gets a new `payloadType`
  for v4 (`application/vnd.aion.version-attestation.v4+json`) and binds
  `file_id`, `format_version`, `rules_mode`, and `metadata_commitment`.
  The v2/v3 payload is unchanged.
- No `AION_V4_*\0` domain is a prefix of a v2 (no NUL) or v3 domain;
  tests check this.

#### Verification (key-free)

For v4, `verify_file` and `VerifiedChain::from_bytes` add, before any
metadata is returned:

1. The audit count, order, and per-entry agreement rules.
2. The v4 audit chain.
3. The canonical string table.
4. Each version's `metadata_commitment`, recomputed from its message and
   audit entry.
5. The header copies.

Failures use bounded reasons: `audit_version_mismatch`,
`string_table_noncanonical`, `metadata_commitment_mismatch`,
`header_mismatch`.

`metadata_signed` is derived from the format, never stored: true for v4,
false for v2 and v3. `VerificationReport` and `VerifiedChain` expose it.

#### Displaying metadata

- `VerifiedChain` keeps each version's verified message and its audit
  entry, so `VerifiedEntry::message()` and the audit accessors return
  exactly the bytes verification checked, signatures included. No
  second read of the file.
- `chain::verified_history(&VerifiedChain)` replaces
  `operations::show_version_history` for display.
- **The registry-less display functions refuse v4.**
  `operations::show_version_history` and `show_file_info` take no
  registry, so they cannot check signatures, and a structure check alone
  is no assurance: the commitment is not secret, so a forger can
  recompute it. For a v4 file they return an error pointing at
  `verified_history`. For v2 and v3 files they keep working, are
  deprecated, and are documented as returning unauthenticated metadata.
- **CLI.** `aion show` already requires `--registry`, but `show history`
  ignores it today. In 3.0.0 `show history` and `show info` verify the
  file with that registry and display from the `VerifiedChain`; a file
  that does not verify displays nothing. For v2 and v3 files they print a
  note that the metadata is unsigned. This is a behaviour change for
  `show history` (it now fails on files that do not verify).

#### Writers

- `init` writes format v4.
- `commit` keeps the file's format. A v3 file stays v3 and its metadata
  stays unsigned; the CLI prints a note pointing to `aion migrate`.
- Write order: build the string table with this version's message (and
  details, if any) at their canonical offsets; build the audit entry
  (chained under the v4 hash); compute the metadata commitment; build
  the version entry; sign it; set the header copies.

#### Migration (RFC-0039 Phase C2)

```
aion migrate <SOURCE> <DEST> --registry <REG> --author <ID> --key <KEY_ID>
             (--public | --recipient … | --keep-recipients) [--identity …]
```

1. Verify `SOURCE` (v2, v3, or v4) with the registry. Refuse on failure.
2. Open its head rules (an `--identity` for a confidential head).
3. Write `DEST` as a new v4 file with a new random `file_id`, whose
   genesis audit entry has action `MigratedFrom` and details text:

   ```
   aion-migrated-from:v<2|3|4>:<file_id, 16 lowercase hex>:<head version, decimal>:<head version hash, 64 lowercase hex>
   ```

   Parsed strictly: lowercase hex, exact field count, no trailing bytes.
   The genesis metadata commitment covers that entry, so the link is
   signed by the migrating author.
4. `SOURCE` is left untouched, to be archived.

**What the link attests:** "this author asserts that this file continues
that file as of its head version." It is the migrating author's signed
claim, not a proof of content equivalence: `verify_migration` checks the
link and the policy, not that `DEST`'s genesis rules equal `SOURCE`'s head
rules (which cannot be checked key-free for confidential rules). A
pinned author may legitimately change the rules while migrating. The
destination imports no history. For a v2 or v3 source the source head
version hash does not cover the source's metadata, so the link vouches
for the source's signed fields only; for a v4 source it covers the
source's metadata too.

**Entitlement is mandatory.**
`chain::verify_migration(dest, source, &MigrationPolicy)` takes a policy
with no default:

- `SameAuthor`: the migrating author authored the source head.
- `Author(AuthorId)`: the migrating author must equal this ID. (That the
  author is registry-pinned follows from `dest` having been verified
  with the registry; `verify_migration` itself takes no registry.)
- `AnyOf(Vec<AuthorId>)`: one of a named, non-empty set. An empty set is
  rejected when the policy is built.

It fails unless the link matches `source`'s format, `file_id`, head
version, and head version hash exactly, and the policy holds.

**Supersession.** `acceptance::accept_migration(dest_path, source_chain,
&registry, &AcceptPolicy, &MigrationPolicy, &dyn AcceptedVersionStore)`
accepts a migrated file. Order, all before anything is written:

1. Fully verify `DEST` with the registry (signatures included).
2. `verify_migration(dest, source, policy)` against the caller's verified
   `SOURCE` chain.
3. The normal acceptance checks for `DEST`.
4. Only then, inside the store's compare-and-swap, the migration record
   `source file_id → (DEST file_id, DEST genesis hash)`.

Keyed by the source `file_id`. Presenting the same destination chain
again is idempotent; any other destination is rejected as
`migration_conflict` (first verified claim wins). Because the record is
written only after steps 1–3, squatting requires a validly signed,
policy-satisfying migration, not just a submission. Recovery from a
mistaken migration is an explicit store operation
(`AcceptedVersionStore::clear_migration(source file_id)`), never
automatic. A source that keeps advancing after migration is still a
valid file; whether to accept it is the deployment's policy.

### Examples

```rust
let chain = verify_file_chain(path, &registry)?;
assert!(chain.metadata_signed());                       // format v4
for entry in chain.entries() {
    println!("v{}: {}", entry.version().as_u64(), entry.message());
}

let migrated = verify_file_chain(new_path, &registry)?;
let original = verify_file_chain(old_path, &registry)?;
verify_migration(&migrated, &original, &MigrationPolicy::SameAuthor)?;
```

### Edge Cases

- **Empty commit messages** commit to `u32_le(0)` and occupy one NUL in
  the string table.
- **Confidential versions.** Unchanged; the metadata commitment covers
  the plaintext message, which is plaintext in the file.
- **Migrating a migrated file.** Allowed; each hop is its own signed,
  policy-checked link.
- **v3 files.** Still read, verified, and accepted.
  `AcceptPolicy::min_format(V4)` lets a deployment require signed
  metadata.
- **v4 → v3 downgrade.** Impossible to pass off: the format is in the
  signed message, and v3 rejects the non-zero reserved bytes.

### Implementation notes

- **Audit entries are checked as stored.** The parser rebuilds each audit
  entry from its fields and drops the three reserved fields, so a v4
  verifier also requires each entry's stored 80 bytes to equal the
  rebuilt entry (reserved bytes zero). Found by the byte-flip property
  test; without it, 18 bytes per entry were editable.
- **Contiguous layout.** v4 requires sections back to back in their fixed
  order (header, rules, versions, signatures, audit, string table,
  integrity hash), with one signature per version, so no byte lies
  outside a checked section.
- **Migration (P3).**
  - `operations::migrate_file(source, rules, dest, options, registry)`
    refuses, before writing, an author/key pair the registry does not
    pin for the new genesis, as `commit_version` does.
  - Errors are `AionError::MigrationRejected` with `not_migrated`,
    `self_migration`, `link_malformed`, `source_mismatch`,
    `policy_unmet`, or `empty_author_set`.
    `VersionRejectReason::MigrationConflict` is the store's
    first-claim-wins rejection.
  - A destination may not share its source's `file_id`
    (`self_migration`), checked in `verify_migration` and again in the
    store. Otherwise a pinned author could sign a v4 genesis under the
    source's id and, on a store that had not seen the source, squat it
    (crypto review of P3, finding M1).
  - When the store has a record for the source, the compare-and-swap
    also checks the presented source against it (read-only), so a
    migration anchored on a stale or forked copy of a tracked source is
    refused as `version_replay` or `version_equivocation`.
  - `AcceptedVersionStore` gains `check_and_advance_migration(dest,
    source)` (both as `ChainSummary`; the migration record and the
    destination's version record in one compare-and-swap) and
    `clear_migration`, which is always traced (`migration_cleared`). Both default to failing
    closed with `migration_unsupported`, so a custom store written for
    2.x refuses migrations rather than accepting them unrecorded.
  - `FileStore` saves `{"records", "migrations"}` and still reads the
    flat 2.x layout; a 2.x reader of the new layout fails closed.
  - The chain keeps the raw signed details text (crate-internal);
    `MigrationLink::parse` checks it, so a malformed link fails
    `verify_migration`, not chain verification.
  - Argument order puts the subject first: `migrate_file(source, …,
    dest)` writes `dest` from `source`, as the CLI's `migrate SOURCE
    DEST` does; `verify_migration(dest, source, …)` and
    `accept_migration(dest_path, source, …)` check `dest`, as
    `accept_file(path, …)` does.
  - The `VersionEntry.reserved` layout, including the metadata
    commitment at bytes 1–32, is public by design (this RFC and the
    book), so `stored_metadata_commitment` and
    `with_metadata_commitment` stay `pub` for third-party verifiers and
    writers.
- **One bounded reason.** A v4 metadata failure reports
  `audit_chain_valid = false` and classifies as `metadata_invalid`; the
  specific code (`audit_version_mismatch`, `string_table_noncanonical`,
  `metadata_commitment_mismatch`, `header_mismatch`) is in the error text.

## Rationale and Alternatives

### Why This Approach?

One 32-byte commitment in existing reserved space, covered by the same
signature, closes the message, audit and migration gaps together, and
verification stays key-free and linear. The canonical string table and
header checks close the remaining editable bytes rather than leaving
them to a "never displayed" promise.

### Alternatives Considered

1. **Reuse format v3 and fill the reserved bytes.** Readers since 2.0.0
   reject non-zero reserved bytes, so the files would be just as
   unreadable to them while claiming the same format. Rejected.
2. **Sign only the commit message.** Leaves the audit trail forgeable.
   Rejected.
3. **Sign each audit entry separately.** Doubles signatures for data the
   version signature can already cover. Rejected.
4. **Declare unreferenced string-table bytes and header copies
   non-authoritative.** Weaker and easy to break later. Rejected in favour
   of canonical layout and equality checks.
5. **Document the metadata as unsigned.** Kept only as the advisory's
   workaround for existing files.

## Security Considerations

### Threat Model

Holders of a file who can modify and redistribute it without the authors'
signing keys; registry-pinned but semi-trusted authors (for migration);
and RFC-0039's adversaries.

### Attack Vectors

- Rewrite any commit message, audit field, or details text with every
  unkeyed hash recomputed: rejected in v4.
- Reorder, drop, or add audit entries; swap equal-length messages between
  versions or files: rejected.
- Edit unreferenced string-table bytes or header copies: rejected
  (canonical layout, equality checks).
- Present a v4 entry to a v3 verifier, or a v3 signature as v4: domain
  separation and the format in the signed message.
- Mint a destination claiming to continue someone else's file: fails the
  mandatory migration policy; a second claim fails the acceptance store.

### Security Guarantees

In v4, commit messages, audit entries with their details, and migration
links are covered by version signatures. The string table and header
copies are canonical or checked, and metadata is shown only from verified
bytes. Nothing changes for v2 and v3 files: GHSA-69cp-fwrw-82vh documents
that their messages and audit trail are unauthenticated. The rules
payload and its signatures were sound before and remain so.

## Performance Impact

- One extra BLAKE3 pass per version over its message and one audit hash;
  negligible next to signature verification.
- No size change; the canonical string table is what writers produce
  today.

## Testing Strategy

### Property-based tests (Hegel)

- v4 build → verify → `verified_history` round trip for any messages.
- Any byte flip in any message or details, with every unkeyed hash
  recomputed, fails v4 verification.
- Audit count, order, author, timestamp, or action disagreement fails.
- Any string-table gap, overlap, extra byte, or out-of-range offset fails.
- Any header-copy disagreement fails.
- v4 domains and messages are separated from v3; a v4 file fed to a v3
  reader fails cleanly.
- `verify_migration` accepts exactly the true source under each policy
  variant, and rejects malformed or non-canonical link text.

### Unit, known-answer, and fuzz

- Golden v4 canonical message, version hash, audit hash, metadata
  commitment, and DSSE v4 payload.
- The GHSA reproduction (message and audit rewrites) as regression tests
  that fail on v4, and as documented "still accepted" checks on v3.
- Equal-length message swap across versions and across files.
- Hybrid-signature, external-signer, and multisig attestation round trips
  on v4.
- Acceptance store: a second destination claiming the same source is
  `migration_conflict`; the same destination again is idempotent; a
  destination failing verification or policy writes no record.
- The deprecated `show_version_history` refuses a v4 file, including one
  whose message was forged with the commitment and hashes recomputed.
- `MigrationPolicy::AnyOf(vec![])` is rejected; non-zero header flag bits
  other than bit 0 are rejected; non-UTF-8, NUL-containing, and
  over-`u32` messages are rejected.
- `fuzz_verify_chain` gains v4 seeds, including truncated and oversized
  details.

## Implementation Plan

1. **P1, read and verify.** `FormatVersion::V4`, format-aware reserved
   parsing, v4 messages, hashes and audit chain, canonical string table,
   header checks, `metadata_signed`, `VerifiedEntry::message()`, and
   `verified_history`.
2. **P2, write.** `init` writes v4; commit preserves format; CLI display
   from verified chains and v2/v3 notes; DSSE v4 payload.
3. **P3, migrate.** `ActionCode::MigratedFrom`, `aion migrate`,
   `verify_migration` with `MigrationPolicy`, and the acceptance-store
   migration record.

Format v4 is a new on-disk field, so it ships in a major release (3.0.0),
with a stability-page row "3.x: writes v4; reads v2, v3, v4."

## Unresolved Questions

1. **Release vehicle.** RFC-0039 Phase B (confidential rules) is on main,
   unreleased. Shipped alone as 2.1.0, it would create confidential v3
   files whose messages and audit trail are forgeable. Recommendation:
   release Phase B only together with v4, in 3.0.0. Owner to decide.
2. **CLI default for v2/v3.** Should `aion verify` warn, or fail unless
   `--allow-unsigned-metadata`, on v2/v3 files? Should
   `AcceptPolicy::min_format` default to v4 in 3.0.0?
3. **History import.** Should `aion migrate` optionally carry the source's
   messages into the destination as signed, clearly labelled "imported,
   unverified" records? This RFC says no.
4. **Disclosure timing.** This RFC and its implementation are developed
   privately until GHSA-69cp-fwrw-82vh is published with the fix.
5. **The v2/v3 DSSE version-attestation payload** does not bind
   `file_id` or rules mode. This RFC leaves it unchanged for v2/v3 files
   (v4 gets a new payload type that does). Whether to deprecate the old
   payload, or note it in the advisory, is open.

## References

- GHSA-69cp-fwrw-82vh; GHSA-7625-44v8-v62f (the same class of gap for the
  rules payload in 1.0.0).
- RFC-0002, RFC-0005, RFC-0021, RFC-0023, RFC-0027, RFC-0038, RFC-0039.

## Appendix

### Review history

- **2026-10-23, `crypto-auditor`, round 1: BLOCK** (6 must-fix). All
  addressed in this revision:
  - F1: metadata is displayed only from `VerifiedChain`; the unverified
    `show_*` path is deprecated and structure-checked for v4; out-of-range
    ranges fail.
  - F2: canonical string table; header copies must equal signed values;
    signature-entry authors checked; guarantee text narrowed.
  - F3: a full v4 audit chain, per-action details rules, `MigratedFrom`
    added to `ActionCode`.
  - F4: format-aware reserved-byte parsing; `FormatVersion::V4` breakage
    listed.
  - F5: a new DSSE payload type for v4 binding `file_id`, format, mode
    and commitment; hybrid, external-signer and multisig paths named.
  - F6: mandatory `MigrationPolicy`; first-claim-wins migration record
    in the acceptance store; what the link attests; the `v<format>`
    token pinned.
  - Should-fix: release-vehicle recommendation, format-derived
    `metadata_signed`, the 1:1 audit rule's writers cited, write order,
    stability row, downgrade and domain-prefix tests.
- **2026-10-23, `crypto-auditor`, round 2: BLOCK** (2 must-fix, 4
  should-fix). F2–F5 closed; core judged sound. Addressed:
  - R1: the registry-less display functions refuse v4 outright (a
    structure check is not assurance); `show history`/`show info` verify
    with `--registry` in 3.0.0; the wrong CLI claim corrected.
  - R2: `accept_migration` writes the migration record only after full
    verification, the migration policy, and acceptance; records the
    destination genesis hash; idempotent for the same destination;
    explicit `clear_migration` recovery; empty `AnyOf` rejected;
    `Author(AuthorId)` wording.
  - R3: all non-bit-0 header flags and reserved bytes must be zero.
  - R4: the link is the migrating author's assertion, not content
    equivalence.
  - R5: commitment indexing clarified; the v2/v3 DSSE payload gap listed.
  - R6: UTF-8, no NUL, `u32` bounds, control-character escaping, and the
    matching tests.
- **2026-10-23, `crypto-auditor`, round 3: PASS** (0 must-fix). The
  zero-flags rule moved into the normative header-copy text; the v2/v3
  DSSE payload's missing `file_id`/mode binding is to be noted in the
  advisory as a separate, pre-existing item.
