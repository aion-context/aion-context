# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog 1.1.0],
and the project follows [Semantic Versioning].

[Keep a Changelog 1.1.0]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html

## [Unreleased]

_Nothing here yet. Next changes land in this section._

## [1.0.0] — 2026-04-25

The 1.0.0 cut. The public API surface, the on-disk binary format,
the CLI exit-code contract, the structured tracing event names,
and the bounded `reason` vocabulary are now under semver. See
[`book/src/architecture/stability.md`] for the written promise of
what's stable, what isn't, and what triggers a major-version bump.

The release content is the work that landed on `main` over the
0.x development arc (originally numbered `0.2.0`) — it is the
first version pushed to crates.io.

[`book/src/architecture/stability.md`]: book/src/architecture/stability.md
Adds the registry-aware verify rollout (RFC-0034), the operator
surface (`aion registry`, `aion release`, `aion archive`), three
new examples, the operator-facing mdbook, and structured tracing
across the library + CLI. Closes the two CRITICAL findings from
the session audit.

### Added

- **RFC-0034 registry-aware verify rollout** (Phases C/D/E, #14, #19, #22) —
  every signature-verification path now takes a `&KeyRegistry`; raw-key
  variants of `verify_*` removed. Active-epoch resolution at signed
  version replaces flat author→key maps. Full Phase-by-Phase migration
  documented in `rfcs/RFC-0034-registry-aware-verify-rollout.md`.
- **CLI: `aion verify --registry`** (#20) — required flag pinning the
  trusted-key registry for verification.
- **CLI: `aion registry rotate / revoke`** (#31) — operator surface for
  RFC-0028 key lifecycle. Rotation warning on retroactive invalidation
  (#52).
- **CLI: `aion release seal / verify / inspect`** (#32) — operator
  surface for RFC-0032 sealed-release composition.
- **CLI: `aion archive verify`** (#51) — bulk-verify a directory of
  `.aion` files with summary report.
- **`AION_LOG` / `AION_LOG_FORMAT`** (#58) — structured `tracing`
  emitted from operations / signature_chain / multisig / audit /
  parser / keystore. `text` (default) or `json` output. Library
  uses the facade only; CLI binary owns the subscriber.
- **`transparency_log::leaf_hash_at`** (#30) — public accessor that
  lets verifiers compute inclusion proofs without re-hashing the
  whole leaf payload.
- **`test_helpers::TestRegistry`** (#21) — convenience newtype for
  pinning authors in property tests.
- **RFC-0035 chain-architecture guide** (#53) — per-file genesis vs.
  growing-chain trade-off, with a diagnostic matrix and migration
  shell snippets.
- **Operator-facing mdbook** (#54) — quickstart, mental model, full
  CLI reference, architecture deep-dives, operations playbooks
  (chain architecture, rotation, audit), examples narratives, RFC
  index, glossary. Builds with `mdbook 0.5+` from `book/`.
- **Examples**:
  - `aegis_consortium` (#33) — 5-party consortium with K-of-N quorum,
    hybrid PQC, rotation, revocation across a four-act timeline.
  - `federation_hw_attest` (#34) — cross-domain HW-attested key
    bindings (RFC-0026) with a TPM firmware-CVE Phase E.
  - `policy_loop` (#56) — tight-loop agent re-verifying its `.aion`
    policy on every tick.
  - `llm_policy_agent` (#60, gated by `llm-agent-example`) — Claude
    proposes, the policy gates. `ANTHROPIC_API_KEY` from env, never
    logged.
  - `corpus_to_aion` (#62, gated by `corpus-tool`) — generic git-
    history → signed `.aion` replay tool. Verified end-to-end on a
    real ISMS corpus (63 versions, 14 MB).
- **Initial supply-chain RFC sweep** (#1) — RFC-0021..RFC-0033 cover
  multisig attestation, external artifact manifest, DSSE envelope,
  SLSA provenance, transparency log, hardware attestation, post-
  quantum hybrid, key rotation/revocation, AIBOM, OCI packaging,
  JCS, sealed releases, and the post-audit carryover ledger.

### Changed

- `AionError` is now `#[non_exhaustive]`; commit-path functions are
  `#[must_use]` (#44). Adding a variant is no longer a breaking
  change for downstream `match` arms.
- `KeyRegistry::to_trusted_json` emits an explicit per-epoch
  `status` field (#46) instead of inferring it on parse — round-trip
  is now byte-stable.
- `transparency_log` property tests now cover N up to 256 (was 16,
  #45) — exercises the subtree-roots cache at realistic scales.
- Fuzz harnesses for parser / manifest / registry replaced placeholder
  stubs with real targets (#39).
- Six per-industry `.aion` fixtures replaced with a regeneration
  script (`examples/regenerate_fixtures.sh`, #76) — the originals
  were extracted from `aion-v2` with keys that did not survive, so
  external readers could not verify them.

### Removed (Breaking)

- **Raw-key `verify_signature` / `verify_attestation` / `verify_multisig`
  variants** (RFC-0034 Phase E, #22). Every verify now takes a
  `&KeyRegistry`. Migration: build a registry pinning your authors
  and pass it through.
- **`SignedRelease::from_components(13-arg)` signature** (#47).
  Replaced by `SignedRelease::from_components(SignedReleaseComponents)`
  — a named-field struct that's no longer a positional bear trap.

### Performance

- `commit_version` is O(1) at the verification step (head-only),
  was O(versions) (#37). Closes issue #35.
- `transparency_log` inclusion proofs are O(log n) via a subtree-
  roots cache (#38), was O(n). Closes issue #36.

### Fixed

- **CRITICAL**: `preflight_registry_authz` was using `!=` on
  Ed25519 public keys (timing side-channel surface) — now uses
  `subtle::ConstantTimeEq` (#43).
- **CRITICAL**: `commit_version` did not verify integrity hash or
  hash chain before writing a new entry, so a tampered file could
  have a new clean entry layered on top hiding the corruption
  beneath. Now performs full pre-write verification (#43).
- `AionParser::header` and other accessors no longer use
  `.expect(...)` — `from_seed` is fallible, internal lookups
  return `Result` (#4, #12).
- ML-DSA secret material is `Zeroize`-backed (#5).
- Library code is panic-free: every `.unwrap()` / `.expect()` / `panic!()`
  / `todo!()` / `unreachable!()` removed; clippy `unwrap_used` /
  `expect_used` / `panic` denied at crate scope (#9, #10, #11, #13).
- `cmd_verify` exit code is sourced from a single pure function
  `VerificationReport::exit_code()`; the bug class "INVALID printed
  but exit 0" is unrepresentable (#24).
- `commit_version` refuses to write entries that wouldn't subsequently
  verify (#26).
- `Manifest::from_canonical_bytes` and `KeyRegistry::from_trusted_json`
  reject non-zero reserved fields (#41, #42), closing fuzz-found
  laundering paths.

### Security

The two CRITICAL findings (#43) and the manifest / parser laundering
paths (#41, #42) above are the security-relevant items. None had
known external exploitation; all surfaced from the in-house audit
pass and were closed in the same release window. Reporters: `crypto-auditor`
agent + manual review.

### Maintenance / hygiene (towards #63 — public-launch readiness)

- `cargo audit` clean dashboard (#75) — `audit.toml` mirrors the
  RUSTSEC-2024-0436 ignore from `deny.toml`.
- `fuzz/target/` added to `.gitignore` (#75).
- `SECURITY.md`, `CODE_OF_CONDUCT.md`, GitHub issue forms + PR
  template added (#77).
- SPDX license headers on every Rust source file in tree (#78).
- Drift baseline + initial GitHub Actions CI (#2). Note: GA
  workflows are currently disabled at the repo level (action-
  minutes budget); local-CI discipline is documented in
  `.claude/rules/`.

## [0.1.0] — 2026-04-23

### Added

- Initial extraction of the aion-context file format and crate from
  `aion-v2@da951e1`.
