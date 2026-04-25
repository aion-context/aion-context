# Mental Model

A 2-minute conceptual map. Read this if the Quick Start ran but
you don't yet have a feel for *why* the moving parts are
arranged the way they are.

## The four objects

```text
┌─────────────────┐      ┌──────────────────┐
│  KeyRegistry    │      │   .aion file      │
│  (JSON)         │      │   (binary)        │
│                 │      │                   │
│  per author:    │      │   header          │
│   - master key  │      │   audit trail     │
│   - epoch[0]    │      │   version chain   │
│   - epoch[1]    │      │   signatures      │
│   - ...         │      │   string table    │
│  + revocations  │      │   encrypted rules │
└─────────────────┘      │   integrity hash  │
        ▲                └──────────────────┘
        │                          ▲
        │                          │
        │ pinned by                │ produced by
        │ verifiers                │ the publisher
        │                          │
   ┌────┴───────┐            ┌────┴────────┐
   │  verifier  │            │  publisher   │
   │  (auditor) │            │  (signer)    │
   └────────────┘            └─────────────┘
```

The publisher writes `.aion` files. The auditor reads them. The
**registry** is the source of truth for who is allowed to sign
under which AuthorId, at which version, with which key.

## The chain

A single `.aion` file is, internally, a hash-chained sequence of
versions:

```text
genesis  ─────►  v2  ─────►  v3  ─────►  ...  ─────►  vN
   │ parent_hash    parent_hash    parent_hash         ▲
   │                                                   │
   └── rules_hash ──┐                                   │
                    ▼                                   │
              encrypted rules                           │
                                                        │
              + a SignatureEntry per version ───────────┘
```

Every `parent_hash` is the BLAKE3 of the previous version's
canonical bytes. Tampering with version K breaks the chain at
version K+1, which is what `verify_file` detects.

Each version carries one signature. The signature is over the
version's canonical bytes plus the AuthorId; the registry tells
the verifier which public key to expect for `(author, version)`.

## The lifecycle

| Action | What happens | What changes |
|---|---|---|
| `aion init` | Genesis version written, signed | New file at v1 |
| `aion commit` | Pre-checks integrity + chain + head sig + registry; writes v(N+1) | File grows by one version |
| `aion verify` | Walks the file end-to-end, returns a 4-bit verdict | Read-only; produces a `VerificationReport` |
| `aion registry rotate` | Master-signed rotation record minted; epoch advances | Registry updated |
| `aion registry revoke` | Master-signed revocation; epoch's window closes at version V | Registry updated |
| `aion archive verify` | Walks every `.aion` in a directory; signer breakdown + rotation detection | Read-only |

## The four guarantees

When `aion verify` returns `VALID`, four independent properties
hold:

1. **Structure** — the file parses; every section is in bounds.
2. **Integrity** — the trailing BLAKE3 hash matches the contents
   above it; no byte has been flipped.
3. **Hash chain** — every `parent_hash` link is consistent;
   intermediate version entries are intact.
4. **Signatures** — every per-version signature verifies under
   the active epoch in the supplied registry at that version.

A failure of any one breaks the verdict. Each is reported in
the structured `VerificationReport`, so an auditor can tell
*which* property failed.

## What lives where

- **In the file:** the chain itself, signatures, encrypted rules,
  the integrity hash.
- **In the registry:** master keys, operational-key epochs,
  rotation/revocation records.
- **In the keystore:** secret keys (OS keyring or fallback file).
- **Out of band:** the registry travels separately from `.aion`
  files. An auditor receives one of each.

## Where to go next

- [The .aion File Format](../architecture/file-format.md) — the
  byte-level layout.
- [Key Registry](../architecture/registry.md) — epoch semantics
  and the active-epoch-at-version resolver.
- [Chain Architecture](../operations/chain-architecture.md) —
  the architectural choice that catches new operators off guard.
