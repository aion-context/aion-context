# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog 1.1.0],
and the project follows [Semantic Versioning].

[Keep a Changelog 1.1.0]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html

## [Unreleased]

### Added

- **RFC-0039 Phase A2a: reading and verifying format-v3 files.** The
  parser accepts format 2 and 3 (`FileHeader::format`,
  `FileHeader::context`). For v3 it reads a per-entry rules mode from
  `reserved[0]` and still rejects any other non-zero reserved byte.
  `verify_file`, `show_signatures`, and `show_current_rules` handle
  both formats. For v3, verification is key-free:
  - the chain is checked with v3 version hashes;
  - signatures cover the v3 canonical message;
  - the head's stored section must commit to its signed
    `rules_hash` under its own mode;
  - header flag bit 0 must mirror the head's mode;
  - a public section must be a canonical frame.

  `show_current_rules` returns a public v3 head's plaintext, and
  returns the new `AionError::RecipientKeyRequired` for a confidential
  one. New `FileContext` methods are the format-aware signing API:
  `sign_version`, `verify_signature`, `verify_signatures`,
  `verify_hash_chain`, `sign_attestation`, `verify_attestation`, and
  `verify_multisig`, which takes RFC-0021 quorums with v3 attestations.
  The v2 free functions in `signature_chain` and `multisig` are
  unchanged and documented as format-v2 only. Readers accept format 2
  and 3; `parser::FORMAT_VERSION` is now documented as the version
  written by default. **Breaking:** `AionFile` gains a `format` field
  and is now `#[non_exhaustive]`. Build files through `AionFile::builder()`. Committing to
  a v3 file returns `UnsupportedVersion` until the v3 writer lands
  (Phase A2b). Writers still produce v2.
- **RFC-0039 Phase A1: format-v3 primitives.** No change to what is
  written yet.
  - A new `format` module with `FormatVersion`, `RulesMode`,
    `rules_commitment` (a BLAKE3 commitment to the stored rules
    section), Padmé `padme_len` / `frame_rules` / `unframe_rules`, and
    `FileContext`. `FileContext` is constructor-only and is the single
    public entry point for building v2 or v3 version messages, version
    hashes, and attestation messages.
  - The v3 message and hash bind `file_id`, the format version, and the
    per-entry rules mode under new NUL-terminated domains, exported as
    `signature_chain::{SIGNATURE_DOMAIN_V3, VERSION_HASH_DOMAIN_V3,
    ATTESTATION_DOMAIN_V3}`. Golden-vector tests pin the byte layout.
  - `VersionEntry::with_rules_mode`.
  - The SHA-256 key-derivation exception is recorded in
    `.claude/rules/crypto.md`.
- **RFC-0036 Enforcement Receipt** (#151, #154) — the `enforcement_receipt`
  module attests that a runtime *applied* a policy, the claim the
  provenance chain (DSSE/SLSA/transparency-log) does not make. A receipt
  is a DSSE-wrapped in-toto predicate binding policy identity, the pinned
  key-registry epoch, the decision (`allow`/`deny`/`degraded`/
  `fail_closed`), gating-approval references, and the enforcing runtime's
  identity. Policy-issuing and enforcement-attesting authorities are
  distinct registry identities by construction; `verify_with_registry`
  rejects unless the runtime's own signature is present and verifies
  (author binding). Composes existing primitives — no new cryptography.
- **Opt-in approval verification** — `verify_with_registry_and_approvals`
  resolves each approval reference against an `AttestationStore` and
  hard-fails on any that cannot be independently verified; the base path
  binds approval references without resolving them.
- **Independent witness co-signature** — `add_witness_signature` lets a
  second party co-sign the same envelope, resolved at its own version
  space; receipts append to the transparency log as
  `LogEntryKind::EnforcementReceipt`, and reconstruct out-of-process via
  `EnforcementReceipt::from_envelope` / `from_json`.
- **`AionError::UnresolvedApproval`** — bounded failure for
  unresolvable or invalid approval references in the receipt path.
- **RFC-0038 Hardware-backed version commits** — `VersionSigner`,
  `ExternalCommitOptions`, and `commit_version_with_signer` let KMS/HSM
  adapters sign the canonical version message without exporting private key
  material or reimplementing AION artifact assembly. The core checks the
  provider public key against the active registry epoch, verifies the returned
  Ed25519 signature, and writes atomically only after every check succeeds.
  The provider is asked for exactly one signature per commit, and only after
  authorization passes.
- **`AionError::SigningFailed`** — provider-safe failure propagation for
  external signing adapters.

### Changed

- **BREAKING (RFC-0037, #165)** — `SigningKey::generate`,
  `crypto::generate_nonce`, and `HybridSigningKey::generate` return
  `Result`, propagating `AionError::EntropyUnavailable` instead of
  panicking when the OS RNG fails. The Ed25519 stack moved to
  `ed25519-dalek` 3.0 and `rand` 0.10. Key and signature byte
  encodings are unchanged.
- **BREAKING** — `dsse::version_attestation_payload`,
  `dsse::manifest_payload`, `dsse::wrap_version_attestation`, and
  `dsse::wrap_manifest` return `Result` instead of aborting the process
  if JSON serialization fails. Payload bytes are unchanged, so existing
  envelopes still verify. Migration: add `?` (or handle the `Err`) at
  each call site; the error is `AionError::InvalidFormat`.
- `commit_version` and the software-keystore CLI path now use the same internal
  signer abstraction as hardware-backed commits. Existing public call sites
  remain source-compatible.

### Fixed

- **Declared `rust-version` corrected from 1.70 to 1.85.** The 1.70
  declaration has been wrong since the RFC-0037 dependency upgrade
  (#165): `ed25519-dalek` 3.0, `rand` 0.10, `chacha20poly1305` 0.11, and
  `getrandom` 0.4 (edition 2024) all require 1.85, and 1.84 cannot even
  parse the dependency graph. A new `msrv (1.85)` CI job builds the
  library and CLI on 1.85.0. Raising the declaration let clippy apply
  lints it had suppressed for 1.70, so a few setters became `const fn`
  and `map_err` logging closures became `inspect_err`.
- **Constant-time public-key comparison** — `hw_attestation::verify_binding`,
  `manifest::verify_manifest_signature`, and
  `signature_chain::{verify_signature, verify_attestation}` compared pinned
  public keys with `==` / `!=`, against the hard rule in
  `.claude/rules/crypto.md`. All four now use `subtle::ConstantTimeEq`.
- **Documentation overstated rules confidentiality** — the rules section
  is ChaCha20-Poly1305 ciphertext under a key derived only from public
  header fields (`file_id`, version), so anyone holding an `.aion` file
  can read its rules. The README, book, `SECURITY.md`, the audit guide,
  and an RFC-0003 errata now say so plainly. `aion init --no-encryption`
  never changed behavior; its help text and the init banner now say so.
  Restoring real confidentiality is a format change and needs an RFC.
- **No process aborts in library code** — rules encryption propagated
  an OS-RNG failure as `std::process::abort()` rather than through its
  `Result`. The four abort sites in non-test library code are gone:
  `operations::encrypt_rules` uses `?`, the manifest capacity hint
  saturates, and the DSSE payload builders return `Result`.
- **`cargo audit` ignore list was never applied** — the config lived at
  the repo root as `audit.toml`, where cargo-audit does not look. Moved
  to `.cargo/audit.toml` and synced with `deny.toml`.

### Security

- **GHSA-7625-44v8-v62f: `verify_file` did not bind the rules payload to
  the signed `rules_hash`.** The rules key is public and the whole-file
  integrity hash is unkeyed. So a substituted payload, with the
  integrity hash recomputed, passed `verify_file`, `aion verify`, and
  `aion archive verify`. `verify_file` now decrypts the latest payload
  and compares it with the latest signed `rules_hash`. A mismatch fails
  `hash_chain_valid` and `is_valid`. Reads through `show_current_rules`
  were already fail-closed. Also fixed in 1.0.1.
- Bumped `rustls` 0.23.39 → 0.23.46, `rustls-webpki` 0.103.13 →
  0.103.16, and `webpki-roots` 1.0.7 → 1.0.10 for RUSTSEC-2026-0285,
  -0346, -0348, -0349, -0381, and -0382. These are only reachable
  through the optional `llm-agent-example` feature's `ureq` client.
- Replaced the yanked `chacha20` 0.10.1 with 0.10.2, and bumped `blake3`
  to 1.8.7, which drops the `arrayref` dependency after its crates.io
  owner account was compromised. The locked `arrayref` 0.3.9 predates
  the compromise.
- `unsafe-libyaml` (RUSTSEC-2024-0449, via the deprecated `serde_yaml`)
  is ignored with a written reason pending migration to a safe-Rust
  YAML crate.

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
