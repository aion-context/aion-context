# aion-context

**Cryptographically-signed, versioned business-context files.**

`aion-context` is a Rust crate and `aion` CLI for producing, signing,
verifying, and auditing append-only governance artifacts. It exists
to answer one question, posed by a regulator months or years after
the fact:

> *Show me, with a chain of custody, what was authoritative as of
> date X — who signed it, what they signed, and that nothing has
> been tampered with since.*

The file format binds together: a hash-chained version log, a set
of Ed25519 signatures over each version, an audit trail, optional
encrypted rules content, and (in the supply-chain story) an AIBOM,
SLSA provenance, DSSE envelopes, OCI manifests, and transparency-log
entries with inclusion proofs. A pinned `KeyRegistry` resolves which
operational key was active for each signer at each version, so
rotation, revocation, and post-quantum key migration are all
first-class.

## What this book covers

| Section | Audience | What you get |
|---|---|---|
| [Getting Started](./getting-started/quickstart.md) | New users | Install, generate keys, init a file, verify it — under 5 minutes. |
| [CLI Reference](./cli/README.md) | Operators | Every `aion` subcommand with examples and exit-code semantics. |
| [Architecture](./architecture/file-format.md) | Library consumers | Format, registry, crypto, sealed releases — the conceptual stack. |
| [Operations](./operations/chain-architecture.md) | Compliance / audit teams | Choose an archive layout; rotate keys without tears; perform an audit. |
| [Examples](./examples/aegis.md) | Engineers building on top | Full runnable scenarios for multisig + PQC + federation + HW attestation. |
| [Reference](./reference/rfcs.md) | Anyone tracking the spec | Full RFC index, glossary, version posture. |

## What this book deliberately doesn't cover

- The internal invariants of every private function. Read the
  rustdoc (`cargo doc --open`) and the source — both have been
  audit-passed.
- The history of every breaking change. Read the [RFC index](./reference/rfcs.md);
  the deprecation/removal cycle for major changes is itself
  an RFC.

## Status

aion-context is **0.2.x** as of the last update to this book.
Pre-1.0 means breaking changes are permitted on minor bumps,
called out in the changelog and (where structural) in their
own RFC.

The library is **single-binary, single-crate, no async, no
unsafe in normal code** (the parser has one audited `unsafe`
for mmap-lifetime extension). Tiger Style / NASA Power-of-10
constraints are enforced at the compiler level via crate-level
clippy lints.

## Quick links

- Source: [github.com/copyleftdev/aion-context](https://github.com/copyleftdev/aion-context)
- The `rfcs/` directory in the repo is authoritative for protocol decisions.
- `examples/` directory has runnable Rust examples; this book documents what they're showing.
- `.claude/rules/` documents the discipline that governs PR review.
