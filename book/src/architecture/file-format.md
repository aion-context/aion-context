# The `.aion` File Format

The on-disk binary format for a versioned, signed governance
file. RFC-0002 in the `rfcs/` directory is authoritative for
every byte; this page is the operator-facing summary.

## High-level layout

```text
┌──────────────────────────────────────┐
│ Header (fixed size)                   │
│   magic "AION", format version,       │
│   counts, section offsets             │
├──────────────────────────────────────┤
│ Audit Trail                           │
│   chained audit entries (RFC-0003)    │
├──────────────────────────────────────┤
│ Version Chain                         │
│   N × VersionEntry (152 bytes each)   │
├──────────────────────────────────────┤
│ Signatures                            │
│   N × SignatureEntry (112 bytes)      │
├──────────────────────────────────────┤
│ String Table                          │
│   null-delimited UTF-8 messages       │
├──────────────────────────────────────┤
│ Encrypted Rules (XChaCha20-Poly1305)  │
│   payload + nonce                     │
├──────────────────────────────────────┤
│ Integrity Hash                        │
│   BLAKE3 over all preceding bytes     │
└──────────────────────────────────────┘
```

The file is **zero-copy parseable** — `AionParser::new(&[u8])`
returns a parser that points into the input slice without
allocating. Internal entry types (`VersionEntry`,
`SignatureEntry`, `ArtifactEntry`) are `#[repr(C)]` and use
`zerocopy::AsBytes` for direct byte-level access.

## VersionEntry (152 bytes)

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | `version_number: u64` |
| 8 | 32 | `parent_hash: [u8; 32]` (BLAKE3 of prior version's canonical bytes) |
| 40 | 32 | `rules_hash: [u8; 32]` (BLAKE3 of plaintext rules) |
| 72 | 8 | `author_id: u64` |
| 80 | 8 | `timestamp: u64` (nanoseconds since epoch) |
| 88 | 8 | `message_offset: u64` (into string table) |
| 96 | 4 | `message_length: u32` |
| 100 | 52 | `reserved` — must be zero |

The `reserved` region is **strictly validated as zero**
(post-PR #42). Tampering with reserved bytes would let an
attacker plant data that the integrity hash detects but a
subsequent `commit_version` could silently launder by
dropping the reserved bytes during rebuild. Strict
validation closes that path.

## SignatureEntry (112 bytes)

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | `author_id: u64` |
| 8 | 32 | `public_key: [u8; 32]` (Ed25519 verifying key) |
| 40 | 64 | `signature: [u8; 64]` (Ed25519 signature) |
| 104 | 8 | `reserved` — must be zero |

The signature is over the canonical message produced by
`canonical_attestation_message(version, signer)` — see the
[hash chain](./hash-chain.md) and [crypto primitives](./crypto.md)
chapters for the message format.

## How parsing rejects malformed input

`AionParser::new` is **total over `&[u8]`** — it returns an
`Err` rather than panicking on adversary input. The parser
totality is exercised by:

- The Hegel property test
  `prop_parser_new_never_panics_on_arbitrary_bytes`.
- The libFuzzer target `fuzz/fuzz_targets/fuzz_file_parser.rs`
  (27.4M iterations + zero panics in the latest run).

Reserved-byte validation at the entry level is exercised by
analogous fuzz harnesses for `from_canonical_bytes` (manifest)
and `from_trusted_json` (registry).

## Verification gates

`verify_file` walks the file end-to-end and returns a
`VerificationReport` with four independent boolean fields:

1. **`structure_valid`** — header parses, all section offsets
   are in bounds.
2. **`integrity_hash_valid`** — the trailing 32-byte BLAKE3 hash
   matches the file's contents above it.
3. **`hash_chain_valid`** — every `parent_hash` link is
   consistent.
4. **`signatures_valid`** — every per-version signature verifies
   against the active registry epoch at the signed version
   number.

A failure of any one short-circuits `is_valid`. The CLI's
exit-code contract maps `is_valid` to `ExitCode::SUCCESS` /
`ExitCode::FAILURE` via `VerificationReport::exit_code()` — a
single pure function, the only producer of the verify-path
exit code. See [issue #23] and the `cmd_verify` page in the
CLI reference.

[issue #23]: https://github.com/aion-context/aion-context/issues/23

## Provenance, not archival

A growing-chain `.aion` file is an attestation of how a body of
content evolved — not an archive of every historical version's
bytes. The file stores:

- **one** encrypted_rules section: the **latest** version's
  payload bytes
- the **full hash-chained version history**: every historical
  `(parent_hash, rules_hash, signature)` triple is in the chain
  and signed

So the file proves that bytes hashing to `rules_hash` existed at
version V (because V's `rules_hash` is in a signed chain link),
but it cannot reproduce those bytes on its own.

To reconstruct any past version's content, pair the `.aion` with
an external content-addressed store keyed by `rules_hash`:

| Where the bytes live | Where the proof of authenticity lives |
|---|---|
| S3 / IPFS / git-LFS / a transparency-log archive | the `.aion` file |
| addressed by `rules_hash` | which signs every `rules_hash` |

Why this shape: most consumers of an `.aion` care most about
the **current** policy and the **provenance** of how it got
that way. They don't want a 200 MB file just to prove a 5 MB
current policy is authentic. The hash-chained signature history
is small and bounded; the bytes can live wherever your archival
infrastructure prefers.

If your use case truly needs every historical body inside one
artifact, the right shape is **per-file genesis** — one `.aion`
per version, each at v1, kept together in a directory or tar.
The [chain-architecture page](../operations/chain-architecture.md)
walks through the per-file vs growing-chain trade-off.

The [`corpus_to_aion`](../examples/corpus_to_aion.md) example
documents this property concretely with metrics from a 63-version
real-world replay (188 MB total payload across versions, 14 MB
final file).
