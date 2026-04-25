# aion-context

> **Tamper-evident policy files. The gate your AI agent can't bypass —
> and the audit trail your regulator wants to see.**

[![crates.io](https://img.shields.io/crates/v/aion-context.svg)](https://crates.io/crates/aion-context)
[![docs.rs](https://img.shields.io/docsrs/aion-context)](https://docs.rs/aion-context)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

**Live demo:** [demo.aion-context.dev](https://demo.aion-context.dev/) — running `.aion` policies in a real agent loop.

## What it is

`aion-context` is a Rust library and CLI for a binary file format
(`.aion`) that wraps any byte payload — a YAML policy, a Markdown
spec, a JSON config — in a **hash-chained signature trail**. Every
change is signed, every change is versioned, every byte is bound
into an integrity hash. Verifying any past version is an O(log n)
cryptographic operation against a small pinned key registry.

Built for two audiences:

- **AI / agent operators** — your model proposes an action, your
  `.aion` policy gates it. Even a maximally jailbroken or prompt-
  injected model cannot bypass a policy that lives outside it.
- **Compliance / regulated industries** — every change to a
  policy is signed and dated. An auditor reading the file at any
  point in the future can verify exactly what the policy said and
  who signed off on it.

It is *not* a replacement for sigstore, in-toto, or SLSA. It is
the **document/policy-shaped** sibling those systems leave on the
table — see [the comparison chapter] for the contrast.

[the comparison chapter]: book/src/comparison.md

## Hello world

```rust
use aion_context::crypto::SigningKey;
use aion_context::key_registry::KeyRegistry;
use aion_context::operations::{init_file, verify_file, InitOptions};
use aion_context::types::AuthorId;
use std::path::Path;

fn main() -> anyhow::Result<()> {
    let key = SigningKey::generate();
    let author = AuthorId::new(1);
    let mut registry = KeyRegistry::new();
    registry.register_author(author, key.verifying_key(), key.verifying_key(), 0)?;

    init_file(
        Path::new("/tmp/policy.aion"),
        b"allow: read\nallow: write",
        &InitOptions { author_id: author, signing_key: &key, message: "v1", timestamp: None },
    )?;

    let report = verify_file(Path::new("/tmp/policy.aion"), &registry)?;
    assert!(report.is_valid);
    Ok(())
}
```

That's a signed, tamper-evident policy file in twelve lines. Flip
one byte of the file and `report.is_valid` is `false` — no further
configuration needed.

## Install

```bash
# CLI:
cargo install aion-context

# Library:
cargo add aion-context
```

Or from source:

```bash
git clone https://github.com/aion-context/aion-context
cd aion-context
cargo install --path . --bin aion
aion --help
```

## What's in the box

| Layer | What you get |
|---|---|
| **CLI** (`aion`) | `init` / `commit` / `verify` / `inspect` / `registry rotate \| revoke` / `release seal \| verify` / `archive verify` / `key generate` |
| **Library** | `init_file` / `commit_version` / `verify_file` / `KeyRegistry` / `verify_multisig` (RFC-0021) / sealed releases (RFC-0032) / hardware attestation (RFC-0026) / hybrid PQC (RFC-0027) / transparency log (RFC-0025) |
| **Format** | Zero-copy binary layout. One header, one chained signature history, one encrypted_rules section, one trailing integrity hash. The latest payload is always inline; historical payloads are addressed by their `rules_hash` for external archival. |
| **Tracing** | `AION_LOG=info` produces structured per-event lines (`event=file_verified`, `event=signature_rejected reason=...`, etc.). `AION_LOG_FORMAT=json` for log-store ingest. |
| **Examples** | `policy_loop`, `llm_policy_agent` (Claude as proposer + `.aion` as gate), `aegis_consortium` (5-party PQC quorum), `federation_hw_attest` (cross-domain TEE keys), `corpus_to_aion` (any git history → signed chain) |

## Documentation

- **[The Book](book/src/SUMMARY.md)** — quickstart, mental model,
  CLI reference, architecture deep-dives, operations playbooks,
  examples narratives. Build with `mdbook serve book/`.
- **[CHANGELOG](CHANGELOG.md)** — what's in the version you're
  running.
- **[RFCs](rfcs/)** — 35 RFCs covering the protocol design from
  threat model through sealed releases.
- **[CONTRIBUTING](CONTRIBUTING.md)** — branch / commit / PR
  conventions.
- **[SECURITY](SECURITY.md)** — disclosure policy.

## Status

**1.0.0** — public API, on-disk binary format, CLI exit-code
contract, structured tracing event vocabulary, and bounded
`reason` codes are now under semver. The full written stability
promise lives at [`book/src/architecture/stability.md`].

The crypto primitives (Ed25519, BLAKE3, ChaCha20-Poly1305,
HKDF-SHA-256, ML-DSA-65) will not change without a major version
and an RFC. Breaking changes carry `!` in the commit subject and
are documented in [CHANGELOG.md].

[`book/src/architecture/stability.md`]: book/src/architecture/stability.md
[CHANGELOG.md]: CHANGELOG.md

## Below the fold — for current contributors

### Build

```bash
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo bench                                  # criterion benches
cargo audit && cargo deny check              # supply chain
```

### Project layout

```
src/                    library — the public crate
  audit.rs              append-only hash-chained audit log
  crypto.rs             Ed25519 + BLAKE3 + ChaCha20-Poly1305 primitives
  key_registry.rs       RFC-0028 trusted-key registry, rotations, revocations
  manifest.rs           RFC-0022 external-artifact manifests
  multisig.rs           RFC-0021 K-of-N quorum
  operations.rs         init / commit / verify public API
  parser.rs             zero-copy binary decoder
  release.rs            RFC-0032 sealed release composer
  serializer.rs         deterministic binary encoder
  signature_chain.rs    per-version signing & verification
  transparency_log.rs   RFC-0025 Merkle log + STH
  types.rs              FileId, AuthorId, VersionNumber newtypes
  bin/aion.rs           CLI binary
benches/                criterion perf benches
fuzz/                   cargo-fuzz targets (parser totality)
examples/               runnable demos + per-industry rules YAMLs
rfcs/                   the protocol specification
book/                   mdbook source for the operator manual
.claude/                rules + agents + hooks for agentic contributors
```

### Core principles

1. **Tiger Style** — zero `unwrap()` / `expect()` / `panic!` /
   `todo!` / `unreachable!` in library code. Every fallible
   function returns `Result<T, AionError>`. `unsafe_code` is
   forbidden. The crate-level clippy lints enforce this at compile
   time.
2. **Crypto is sacred** — load-bearing primitives come from
   `ed25519-dalek`, `blake3`, `chacha20poly1305`. Never hand-rolled.
3. **Zero-copy where it matters** — the parser uses `zerocopy` to
   avoid allocation on the hot path.
4. **RFC-first** — non-trivial format / crypto / protocol changes
   need an RFC under `rfcs/` before code lands.
5. **Offline-first** — the library never touches the network. The
   `aion` CLI is a single static binary.

## License

Dual-licensed under [MIT](LICENSE-MIT) **OR** [Apache-2.0](LICENSE-APACHE),
at your option.

## Community

- Bug reports → [GitHub Issues](https://github.com/aion-context/aion-context/issues/new/choose)
- Security reports → see [SECURITY.md](SECURITY.md) (private flow only)
- Open-ended questions / design discussions → [Discussions](https://github.com/aion-context/aion-context/discussions) (enabled with the announcement, [#74])
- Contribution rules → [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

[#74]: https://github.com/aion-context/aion-context/issues/74
