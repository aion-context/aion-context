# Stability

> Following 1.0.0, `aion-context` follows strict
> [semantic versioning][semver]. This page is the
> **written promise** about what that means.
> It exists so a downstream maintainer never has to guess.

[semver]: https://semver.org/spec/v2.0.0.html

## What's stable (covered by semver)

A change to anything in this list requires a **major version bump**:

### 1. Public API surface

Anything `pub` outside the `test_helpers` module follows semver.
That includes:

- function and method signatures
- struct and enum field shapes
- error variants on the public `AionError` type, **except** that
  `AionError` is `#[non_exhaustive]` — adding a new variant is a
  minor change, downstream `match` arms cannot break exhaustively
  on it
- trait definitions (`EvidenceVerifier`, etc.) and their required
  method signatures
- public re-exports (`AionError`, `Result` at the crate root)

### 2. On-disk binary format (`.aion`)

The `.aion` byte layout is independently versioned. The header
carries a `format_version` field. Any change to the byte-level
layout requires:

1. an RFC under `rfcs/`,
2. a `format_version` bump,
3. updated fuzz coverage for the new format,
4. a major-version bump of the crate.

Older readers reject newer-format files with a deterministic
`Error::UnsupportedFormat(version)`. We will **never** silently
misparse an older format.

### 3. Cryptographic primitives

The pinned primitives are:

- **Ed25519** (via `ed25519-dalek`) — author signatures
- **BLAKE3** (via `blake3`) — file hashing, hash-chain links, integrity hash
- **ChaCha20-Poly1305** (via `chacha20poly1305`) — rules-section encryption
- **HKDF-SHA-256** (via `hkdf` / `sha2`) — key derivation
- **ML-DSA-65** (via `pqcrypto-mldsa`) — RFC-0027 hybrid PQC signatures

Replacing any of these is a major version bump and requires an RFC.

### 4. CLI exit-code contract

The `aion` binary follows a strict contract:

| Outcome | Exit code |
|---|---|
| Success / VALID verdict | `0` |
| Failure / INVALID verdict | `1` |
| Argument / configuration error before reaching a verdict | `2` |

This holds for `verify`, `archive verify`, `release verify`, and
every other subcommand that produces a verdict. The verdict-to-exit-
code mapping is a single pure function `VerificationReport::exit_code()`
— the bug class "INVALID printed but exit 0" is unrepresentable.

### 5. Structured tracing event vocabulary

Every `tracing::*!` event in the crate carries a stable
`event = "..."` discriminator. The current event catalog is
documented at [`book/src/architecture/observability.md`](./observability.md).
**Adding** a new event is a minor change; **removing** or
**renaming** an existing one is major.

The `reason` field on `warn!` events follows the same rule —
adding a new reason value is minor, removing or renaming is major.
Alert rules in downstream systems can pin to these tokens.

## What's not covered

The following are explicitly **not** part of the stability surface
and may change in any release without warning:

- **Internal crate organization** — anything `pub(crate)` or
  private. Reorganizing module boundaries internally is fine.
- **Default `RUST_LOG` levels** — we may bump an event from
  `info!` to `debug!` if it proves noisy in practice. Pin
  explicit `AION_LOG=info` if you depend on visibility.
- **`test_helpers` feature** — gated behind the `test-helpers`
  feature, explicitly marked as not part of stability. Used by
  property tests and demos, never by production code.
- **`llm-agent-example` / `corpus-tool` features** — example
  scaffolding, not the library surface.
- **Internal layout of generated artifacts** under `target/`,
  `book/book/`, etc.
- **The `.claude/` tooling directory** — agentic-contributor rules
  that change as the engineering discipline evolves.

## What triggers a release

| Change shape | Bump |
|---|---|
| Bug fix that doesn't touch a public API | patch (`x.y.Z`) |
| New `pub` item, new tracing event, new `reason` value, new RFC implementation | minor (`x.Y.0`) |
| Removed `pub` item, signature change, new on-disk-format field, primitive change, breaking CLI flag | major (`X.0.0`) |

A breaking change without `!` in the commit subject is a bug —
file an issue.

## Yanking policy

A crate version is yanked **only** when leaving it published would
mislead a verifier. Specifically:

- A known crypto bug that produces accept-when-it-shouldn't decisions
- A license-incompatible artifact accidentally included in the published bundle
- A wrongly-built release binary

Routine bug fixes do **not** yank — they ship as a higher version.
Yanking a release breaks `cargo install` for everyone who pinned
it, and we treat that as a last-resort response.

## How we'll communicate breaks

Every breaking change lands with three things:

1. The `!` in the commit subject (per Conventional Commits)
2. A `### Removed` or `### Changed` entry in [`CHANGELOG.md`](../../../CHANGELOG.md)
3. A migration paragraph in the relevant RFC (or the linked PR)
   explaining what callers do differently

If you're tracking aion-context in a downstream project, watching
the [CHANGELOG](../../../CHANGELOG.md) and pinning a major version
is the simplest path. The crate emits structured tracing events
that downstream alerts can pin to — those event names and their
reason vocabularies are stable in the same way the function
signatures are.

## Pre-1.0 history

Versions before 1.0.0 (the development arc originally numbered
`0.2.0` on `main`) are documented in [CHANGELOG.md](../../../CHANGELOG.md)
for historical interest but were never published to crates.io.
1.0.0 is the first published release.
