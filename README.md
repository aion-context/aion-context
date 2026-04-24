# aion-context

**Cryptographically-signed, versioned business-context file format.**

A Rust crate (`aion_context`) and CLI (`aion`) that read, write, sign,
verify, and export `.aion` files — a binary format for business rules,
policies, and AI-consumable context that regulators can audit with
cryptographic proof.

> "Stop retraining models. Start versioning context."

## Status

Pre-alpha. 20 RFCs cover the specification. The library compiles,
tests pass, and a criterion bench suite tracks perf hot paths.

## What's in the box

- **File format** — zero-copy binary layout with a string table,
  header, signature chain, and audit log.
- **Crypto** — Ed25519 signing, BLAKE3 hashing, ChaCha20-Poly1305
  encryption, HKDF key derivation, multisig quorum.
- **Keystore** — OS keyring integration (macOS Keychain, Linux Secret
  Service, Windows Credential Manager), encrypted export/import with
  Argon2 password hashing.
- **Operations** — init, commit, verify, export with tamper
  detection.
- **Compliance** — pluggable frameworks (SOX, HIPAA, GDPR
  placeholders) and export formats (JSON, Markdown).
- **CLI** — single static binary `aion` for all of the above.

## Build

```bash
cargo build --release
cargo test
cargo clippy -- -D warnings
cargo fmt --check
cargo bench
```

## Quick start

```bash
# create a signed .aion file from a YAML rules source
cargo run --bin aion -- init rules.aion --rules policies.yaml

# verify it
cargo run --bin aion -- verify rules.aion

# export to a human-readable form
cargo run --bin aion -- export rules.aion --format markdown
```

## Project layout

```
src/                    # library
  audit.rs              # append-only hash-chained audit log
  compliance/           # SOX/HIPAA/GDPR frameworks
  conflict.rs           # merge/conflict detection
  crypto.rs             # Ed25519 + BLAKE3 + ChaCha20 primitives
  export/               # JSON / Markdown exporters
  keystore.rs           # OS keyring integration
  multisig.rs           # quorum signatures
  operations.rs         # init/commit/verify public API
  parser.rs             # zero-copy binary decoder
  serializer.rs         # binary encoder
  signature_chain.rs    # linked signed version history
  string_table.rs       # deduplicated string storage
  types.rs              # FileId, AuthorId, VersionNumber newtypes
  bin/aion.rs           # CLI
benches/                # criterion perf benches
fuzz/                   # cargo-fuzz targets
examples/               # domain examples (enterprise, finance, …)
rfcs/                   # 20 RFCs covering the spec
docs/                   # user guide, dev guide, security audit prep
```

## Core principles

1. **Tiger Style** — zero `unwrap()`, zero `panic!`, zero
   `unreachable!`. Every library function returns
   `Result<T, AionError>`. `unsafe_code = forbid`.
2. **Crypto is sacred** — load-bearing primitives are taken from
   `ed25519-dalek`, `blake3`, `chacha20poly1305`, never hand-rolled.
3. **Zero-copy where it matters** — `parser.rs` and `serializer.rs`
   use `zerocopy` to avoid allocations on hot paths.
4. **RFC-first** — non-trivial format or crypto changes need an RFC
   before code lands. See `rfcs/`.
5. **Offline-first** — the library never touches the network. The
   CLI binary is a single statically-linkable executable.

## Documentation

- [`CLAUDE.md`](CLAUDE.md) — rules for agentic contributors.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — commit / PR conventions.
- [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) — CLI usage.
- [`docs/DEVELOPER_GUIDE.md`](docs/DEVELOPER_GUIDE.md) — extending
  the library.
- [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md) — bench interpretation.
- [`docs/SECURITY_CRITICAL_CODE.md`](docs/SECURITY_CRITICAL_CODE.md)
  — where the crypto lives.
- [`rfcs/`](rfcs/) — the specification.

## License

Dual-licensed under MIT or Apache-2.0, at your option.
