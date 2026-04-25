# Hash Chain

Every version in a `.aion` file is linked to its parent by a
BLAKE3 hash. Tampering with a single byte of any prior version
breaks the chain at the next version, and `verify_file`
detects it.

## What gets hashed

`compute_version_hash(&VersionEntry)` is BLAKE3 over the
canonical bytes:

```text
version_number (u64 LE)
parent_hash    (32 bytes)
rules_hash     (32 bytes)
author_id      (u64 LE)
timestamp      (u64 LE)
message_offset (u64 LE)
message_length (u32 LE)
```

The signature region and the reserved bytes are NOT included
in the hash. A signature is over the canonical bytes plus a
domain separator (`AION_V2_VERSION_SIG_V1`); the chain link is
over the same canonical bytes minus the domain separator, so
both can be derived from the same VersionEntry.

## Chain construction

For version `N`:

```text
version_N.parent_hash = compute_version_hash(version_{N-1})
                      = BLAKE3(canonical_bytes(version_{N-1}))
```

Genesis (version 1) has `parent_hash = [0u8; 32]`.

## Chain verification

`verify_hash_chain(versions: &[VersionEntry]) -> Result<()>`
walks the slice in order. For each pair `(prev, curr)`:

1. `expected = compute_version_hash(prev)`
2. If `curr.parent_hash != expected`, return `Err`.

`verify_file` calls this after `verify_integrity()` and as
part of the four independent gates that produce a
`VerificationReport`.

## Why the chain matters

Three independent invariants live in the chain:

1. **Tamper detection of intermediate entries.** The integrity
   hash covers all bytes; if you flip a byte in entry K but
   regenerate the trailing integrity hash, the parent_hash at
   entry K+1 still points at the OLD entry K's content.
   Mismatch.

2. **Pre-write protection in `commit_version`.** Issue #43
   added integrity + chain checks to commit, so an attacker
   with write access between fsyncs cannot launder a corrupt
   chain by waiting for a legitimate commit to overwrite the
   integrity hash while leaving the broken parent_hash links
   in place.

3. **No reordering.** Each entry's hash is over its own
   `version_number` plus the prior `parent_hash`. Swapping
   two version entries breaks both their parent_hash links
   and their version_number ordering simultaneously.

## Performance

Chain verification is **O(n)** in the number of versions:
one BLAKE3 hash per version + one 32-byte compare. Numbers
from PR #38's perf bench (post-#37 + post-#43):

- N=1000:  ~2 µs/version → ~2 ms total to verify the chain
- N=10000: ~2 µs/version → ~20 ms total

These numbers are well below operator-pain thresholds for
typical audit workflows, even on machines without hardware
BLAKE3 acceleration.
