# RFC 0037: Crypto/RNG Stack Upgrade (ed25519-dalek 3.0 + rand 0.10)

- **Author:** copyleftdev
- **Status:** DRAFT
- **Created:** 2026-07-20
- **Updated:** 2026-07-20
- **Depends on:** RFC-0003 (cryptography), RFC-0004 (key management)

## Abstract

`aion-context` pins two load-bearing crypto/RNG dependencies —
`ed25519-dalek` (currently resolving to 2.2.0) and `rand` (currently
0.8.6) — per the allowlist in `.claude/rules/crypto.md` and
`.claude/rules/supply-chain.md`. Dependabot has opened two
independent major-version PRs: #162 bumps `ed25519-dalek` to 3.0.0,
#163 bumps `rand` to 0.10.2. Neither PR builds in isolation: 3.0.0's
`SigningKey::generate` requires a `rand_core` `CryptoRng` bound that
`rand` 0.8's `OsRng` does not satisfy, and `rand` 0.10 relocated
`RngCore` and `OsRng` out of the paths `aion-context` currently
imports them from. This RFC proposes landing both bumps **in a
single coordinated PR**, migrating every RNG call site to the
aligned `rand_core` 0.9+ surface both crates now share, with zero
change to key formats, signature bytes, or the on-disk `.aion`
format — this is a build/API migration, not a wire-format change.

## Motivation

### Problem Statement

`Cargo.lock` currently resolves `ed25519-dalek` to `2.2.0`, `rand`
to `0.8.6` (with a *second*, transitively-pulled `rand = 0.10.2` /
`rand_core = 0.10.1` already present in the graph from an unrelated
dependency), and `rand_core` to `0.6.4` for the `ed25519-dalek`
edge. That split — two `rand` majors and two `rand_core` majors
coexisting in one lockfile — is exactly the kind of drift
`.claude/rules/supply-chain.md`'s SBOM-diff process exists to catch:
`ed25519-dalek` 3.0.0's public `SigningKey::generate` signature
requires its RNG argument to implement the `rand_core` 0.9+
`CryptoRng` trait. `rand` 0.8's `rngs::OsRng` implements the older
`rand_core` 0.6 traits, and `rand` 0.10 is the first `rand` release
whose own `OsRng` implements the 0.9+ trait set `ed25519-dalek` 3.0.0
now depends on. The two dependabot PRs are therefore not independent
maintenance bumps — they are two halves of one required migration,
and the SBOM/dep-bump review process needs to treat them as such
rather than merging whichever lands first.

### Evidence: the bumps are coupled, not independent

**#162 alone (`ed25519-dalek` 2.2.0 → 3.0.0, `rand` left at 0.8.6)**
fails to compile:

```
error[E0277]: the trait bound `OsRng: ed25519_dalek::rand_core::CryptoRng` is not satisfied
   --> src/crypto.rs:143:44
    |
143 |         let key = Ed25519SigningKey::generate(&mut rand::rngs::OsRng);
    |                                       -------- ^^^^^^^^^^^^^^^^^^^^^ the trait `ed25519_dalek::rand_core::CryptoRng` is not implemented for `rand::rngs::OsRng`
    |
    = note: required by a bound in `ed25519_dalek::SigningKey::generate`
```

**#163 alone (`rand` 0.8.6 → 0.10.2`, `ed25519-dalek` left at 2.2.0)**
fails to compile with five errors — `rand` 0.9 relocated `RngCore`
out of the crate root and `OsRng` out of `rand::rngs`:

```
error[E0432]: unresolved import `rand::RngCore`
  --> src/crypto.rs:106:5
  --> src/keystore.rs:38:5
  --> src/test_helpers.rs:202:9

error[E0433]: failed to resolve: could not find `OsRng` in `rngs`
  --> src/crypto.rs:143:40
  --> src/crypto.rs:438:5
  --> src/keystore.rs:530:5
  --> src/test_helpers.rs:204:5
```

**Bumping both together aligns `rand_core`** — `ed25519-dalek` 3.0.0
and `rand` 0.10.2 converge on `rand_core = 0.10.1`, collapsing the
duplicate-major split. This is the central finding of this RFC: **the
two dependency bumps must be reviewed, migrated, and merged as one
PR**, not as two independently-approved dependabot PRs, or the
crate does not build in the intermediate state either PR alone
produces.

Alignment is necessary but **not sufficient**: a migration prototype
found that `rand` 0.10.2 removes `OsRng` in favour of the *fallible*
`rand::rngs::SysRng`, which does not satisfy `ed25519-dalek` 3.0.0's
infallible `CryptoRng` bound directly. Under this crate's zero-panic
rule, reconciling that is a design decision (fallible public API vs. a
documented panic exception), detailed in Unresolved Questions — it is
the gate that must clear before implementation.

### RUSTSEC status

`cargo audit` against the current lockfile reports no advisory
against `ed25519-dalek`, `rand`, or `rand_core` at their pinned
versions — the current findings are unrelated `paste` /
`pqcrypto-*` unmaintained-crate warnings. This bump is **not**
security-incident-driven; it is dependency-currency maintenance that
happens to require a coordinated migration because of the
`rand_core` coupling above. That matters for how urgently this lands
(see Alternatives).

### Goals

- Land `ed25519-dalek` 3.0.0 and `rand` 0.10.2 in the same PR so the
  crate builds at every intermediate commit a bisector might land
  on.
- Preserve `OsRng` as the sole RNG for key material and nonces —
  per `.claude/rules/crypto.md`, "Never `thread_rng()` for key
  material" — only the import path and the `generate()` call shape
  change to the `rand_core` 0.9+ API.
- Zero change to Ed25519 signature bytes, verifying-key bytes, or
  the on-disk `.aion` format. Existing signed files and pinned
  `VerifyingKey`s in `KeyRegistry` remain valid without
  re-signing.
- Full `fuzz/` suite and `cargo test` (including the `crypto.rs`
  Hegel sign/verify and key-round-trip properties) pass on the
  migrated code before merge, per `.claude/rules/supply-chain.md`'s
  "major version bumps are RFCs and run through the full
  `aion-context/fuzz` target suite before merge."

### Non-Goals

- No new crypto primitive, no change to `blake3`, `chacha20poly1305`,
  or `zerocopy` pins — those are untouched by this RFC.
- No change to `KeyRegistry` epoch semantics (RFC-0028) or to any
  `_with_registry` verifier (RFC-0034) — the migration is beneath
  those APIs, not a change to them.
- No MSRV bump decision beyond documenting the impact (Unresolved
  Questions) — if `rand` 0.10 / `ed25519-dalek` 3.0 force an MSRV
  change past the current `rust-version = "1.70"`, that is called
  out explicitly at implementation time, not silently absorbed.

## Proposal

### Overview

A single migration PR bumps both `Cargo.toml` entries together,
updates every RNG call site to the `rand_core` 0.9+ API shape, syncs
`fuzz/Cargo.lock`, and runs the full test + fuzz gate before merge.
No `src/` module outside the six call sites below changes.

### Migration surface

Every production and test-helper site touching the RNG:

| Site                        | Current                                          | Change required                                                        |
|------------------------------|---------------------------------------------------|--------------------------------------------------------------------------|
| `src/crypto.rs:106`          | `use rand::RngCore;`                              | import path relocation to wherever `rand` 0.10 re-exports `RngCore`     |
| `src/crypto.rs:143`          | `Ed25519SigningKey::generate(&mut rand::rngs::OsRng)` | `OsRng` source + `generate` call shape updated to satisfy the `CryptoRng` bound `ed25519-dalek` 3.0.0 requires |
| `src/crypto.rs:438`          | `rand::rngs::OsRng.fill_bytes(&mut nonce)` (12-byte AEAD nonce) | same `OsRng` relocation                                                |
| `src/keystore.rs:38`         | `use rand::RngCore;`                              | import path relocation                                                  |
| `src/keystore.rs:530`        | `rand::rngs::OsRng.fill_bytes(&mut salt)` (KDF salt) | same `OsRng` relocation                                                |
| `src/test_helpers.rs:129,195,202,204` | `rand::RngCore` / `rand::rngs::OsRng` (test-only key + fixture generation) | same relocation, `#[cfg(test)]`-gated, no production impact |

No other file in `src/` imports `rand` or `ed25519_dalek::rand_core`
directly (verified via `grep -rn "rand::" src/` at RFC-drafting
time); the migration surface above is exhaustive, not illustrative.

`OsRng` remains the RNG for every site above — this RFC does not
introduce, and explicitly rejects, any use of `rand::thread_rng()`
for key or nonce material, consistent with the existing
`.claude/rules/crypto.md` requirement.

### Byte-encoding stability

`ed25519-dalek` 2→3 does not change the Ed25519 signature encoding
(64 bytes, `R || s`) or the `VerifyingKey`/`SigningKey` byte encoding
(32 bytes each) — these are fixed by the Ed25519 spec (RFC 8032), not
by the crate's internal API. This RFC requires, as an explicit
acceptance check rather than an assumption:

- A known-answer test: sign a fixed message with a fixed seed under
  the pre-migration crate, assert the signature bytes are
  byte-identical when the same seed signs the same message under the
  post-migration crate.
- The existing Hegel property
  `VerifyingKey::to_bytes → from_bytes` round-trip (already required
  by `.claude/rules/property-testing.md` Tier 1) continues to pass
  unmodified — it is a property of the wire encoding, not of the
  crate's internal RNG plumbing, and should not need to change
  shape.

Passing both means every `.aion` file signed and every `KeyRegistry`
entry pinned before this migration remains valid after it, with no
re-signing and no format-version bump.

### RNG-acquisition helper (churn minimization)

To avoid six independent call sites re-discovering the `rand_core`
0.9+ API shape on the *next* `rand_core` shift, this RFC proposes a
single `pub(crate)` helper in `src/crypto.rs`:

```rust
// src/crypto.rs
/// Returns the process-wide OS entropy source used for all key and
/// nonce material. Centralizing this call is the only place a
/// future `rand`/`rand_core` major bump needs to touch.
pub(crate) fn os_rng() -> impl rand_core::CryptoRng + rand_core::RngCore {
    rand::rngs::OsRng
}
```

`src/crypto.rs`, `src/keystore.rs`, and `src/test_helpers.rs` call
`crate::crypto::os_rng()` instead of naming `rand::rngs::OsRng`
directly. This is a design preference, not a hard requirement of the
migration — see Rationale for the trade-off.

### Acceptance criteria (merge gate)

Per `.claude/rules/supply-chain.md`'s major-bump posture for
load-bearing crypto deps, this RFC sets the following as hard
merge-blocking criteria, not aspirational goals:

1. `cargo build --release` and `cargo test` pass with both deps at
   their target versions in the same commit.
2. Every Hegel property in `.claude/rules/property-testing.md`
   Tier 1 for `src/crypto.rs` passes unmodified: sign→verify
   round-trip, verify-rejects-wrong-key, verify-rejects-tampered-
   payload, `hash` determinism, `VerifyingKey` byte round-trip.
3. The full `fuzz/` target suite (`fuzz_file_parser`,
   `fuzz_manifest_canonical`, `fuzz_registry_json`) runs clean for a
   bounded duration (consistent with existing CI fuzz budget) against
   the migrated crate.
4. `fuzz/Cargo.lock` is regenerated and synced to the workspace
   lockfile — the same step already performed for the prior
   `chacha20poly1305` bump.
5. `.claude/drift/sbom.json` is regenerated from the migrated `main`
   and reviewed for the two version bumps plus any transitive
   `rand_core` graph collapse (the current dual-`rand_core` entries
   in `Cargo.lock` are expected to collapse to one after this
   migration — that collapse is itself a signal the fix worked).
6. `cargo audit` and `cargo deny check` are clean (no new advisory,
   no license violation) on the post-migration lockfile.

## Rationale and Alternatives

### Do nothing / stay pinned

Stay at `ed25519-dalek` 2.2.0 + `rand` 0.8.6. Viable in the short
term: there is no RUSTSEC advisory against either pinned version
today (confirmed above), so this is not an incident-response bump.
Rejected as a permanent posture because:

- Dependabot will keep re-opening #162/#163 (or their successors)
  every cycle; closing them without a plan is a recurring review
  cost with no expiration.
- Every crate in the workspace that later wants a dependency
  requiring `rand_core` 0.9+ (a plausible direction for the broader
  Rust crypto ecosystem, matching where `blake3` and
  `chacha20poly1305`'s own dependency trees are heading) will force
  this exact migration anyway, at a moment not of our choosing and
  possibly bundled with other unrelated changes.
- The lockfile today already carries two `rand` majors and two
  `rand_core` majors simultaneously (see Motivation) — staying
  pinned does not undo that; it only means `ed25519-dalek`'s edge of
  the graph stays on the older line while some other dependency's
  edge is already on the newer one. The drift already exists; this
  RFC proposes resolving it deliberately rather than continuing to
  carry it.

This is an acceptable *near-term* posture (e.g. if reviewer bandwidth
is unavailable this cycle) but not a permanent one.

### Bump only one dependency

Rejected outright — demonstrated in Motivation to be a hard compile
break in either direction. Recorded here because it is the naive
per-dependabot-PR review path a reviewer might otherwise take: merge
#162 because "it's just ed25519-dalek," merge #163 separately
because "it's just rand." Neither PR should be approved in isolation
for exactly the trait-bound and import-path failures shown above.

### Vendor / directly pin `rand_core`

An alternative to the `os_rng()` helper: add `rand_core` as a direct
`[dependencies]` entry (rather than relying on the version
`ed25519-dalek` and `rand` transitively agree on) to make the shared
version an explicit, reviewable line in `Cargo.toml` and `deny.toml`.
Considered; not adopted in this RFC's Proposal because it adds a
fifth crypto-adjacent dependency to the load-bearing list in
`.claude/rules/supply-chain.md` ("Aion-v2-specific posture") for a
version that `ed25519-dalek` and `rand` already have to agree on
regardless — an explicit `rand_core` pin cannot diverge from what
those two crates require without breaking the build, so it adds a
line to review without adding a degree of freedom. Left as an
Unresolved Question rather than closed, since a reviewer may
reasonably weigh "explicit is better than implicit" differently.

### Internal RNG helper vs. inline `rand::rngs::OsRng` at each site

Covered as the Proposal's default (`os_rng()` helper). The
alternative — leaving six independent call sites naming
`rand::rngs::OsRng` directly, as today — was the status quo that
produced this RFC in the first place: the next `rand_core` shift
would again require finding and updating every site by hand. The
helper's cost is one extra indirection layer reviewers must trace
through when auditing RNG usage — acceptable, given
`.claude/rules/crypto.md`'s review trigger already puts `crypto.rs`
under `crypto-auditor` review regardless of indirection depth.

## Security Considerations

### Threat model

This is a build/API migration, not a change to any wire format,
signature scheme, or trust boundary. No new attack surface is
introduced by this RFC; the risk profile is entirely about
**regression**, not new exposure:

- **Regression risk**: a botched migration could accidentally
  introduce `rand::thread_rng()` or a non-CSPRNG source for key or
  nonce material. Mitigated by the explicit `os_rng()` centralization
  (Proposal) and by the Tier-1 Hegel properties in
  `.claude/rules/property-testing.md`, none of which change shape
  and all of which must continue passing.
- **Signature/key compatibility regression**: a botched migration
  could subtly change signature or key byte encoding. Mitigated by
  the known-answer test and the existing `VerifyingKey` round-trip
  property (Proposal → Byte-encoding stability).
- **Supply-chain regression**: pulling in `ed25519-dalek` 3.0.0 or
  `rand` 0.10.2 could itself introduce a new transitive dependency
  outside the license allowlist or with an open RUSTSEC advisory.
  Mitigated by acceptance criteria 5–6 (SBOM diff, `cargo audit`,
  `cargo deny check`) before merge.

### Guarantees preserved

- `OsRng` remains the sole source of key and nonce material —
  `.claude/rules/crypto.md`'s "Never `thread_rng()` for key material"
  is unchanged after this migration.
- No `.aion` file format version bump; no re-signing of existing
  signed artifacts is required.
- No change to `subtle::ConstantTimeEq` usage anywhere in
  `signature_chain.rs` / `multisig.rs` — those call sites are
  untouched by this RFC.

## Testing Strategy

- **Known-answer test** (new): fixed seed, fixed message, assert
  byte-identical Ed25519 signature pre- and post-migration (see
  Byte-encoding stability).
- **Existing Hegel Tier-1 properties** in `src/crypto.rs` (sign→verify
  round-trip, verify-rejects-wrong-key, verify-rejects-tampered-
  payload, `hash` determinism, `VerifyingKey` byte round-trip) run
  unmodified against the migrated code — a shape change in any of
  these properties during this PR is itself a red flag that the
  migration touched more than RNG plumbing.
- **Full `fuzz/` suite** (`fuzz_file_parser`, `fuzz_manifest_canonical`,
  `fuzz_registry_json`) for the CI-standard duration, per
  `.claude/rules/supply-chain.md`'s major-bump requirement.
- **`fuzz/Cargo.lock` sync** verified by a clean `cargo build` inside
  `fuzz/` against the migrated workspace lockfile.

No new Hegel properties are required by this RFC — it changes no
observable API surface, so it adds no new Tier-1/Tier-2 floor entries
to `.claude/rules/property-testing.md`.

## Implementation Plan

1. Bump `ed25519-dalek` to `3.0.0` and `rand` to `0.10.2` in
   `Cargo.toml`, in the same commit.
2. Migrate the six call sites in the Migration Surface table to the
   `rand_core` 0.9+ API, introducing the `crate::crypto::os_rng()`
   helper.
3. Add the known-answer signature test.
4. Run full `cargo test`, confirm Tier-1 Hegel properties pass
   unmodified.
5. Sync `fuzz/Cargo.lock`; run the full `fuzz/` target suite.
6. Regenerate `.claude/drift/sbom.json`; confirm the dual-`rand`/
   dual-`rand_core` graph entries collapse to one line each.
7. `cargo audit` + `cargo deny check` clean.
8. Close dependabot PRs #162 and #163 in favor of this coordinated
   migration PR, referencing this RFC number.

## Unresolved Questions

- **RESOLVED by prototype — and it forces a bigger decision than a path swap.**
  A throwaway migration prototype (deps bumped, build attempted)
  established the concrete facts: `rand` 0.10.2 **removes `OsRng`
  entirely**. The OS entropy source is now `rand::rngs::SysRng`
  (re-exported from `getrandom`), and it is **fallible** —
  `rand_core` 0.10.1 splits infallible (`RngCore: Rng`,
  `CryptoRng: Rng + TryCryptoRng<Error = Infallible>`) from fallible
  (`TryRngCore: TryRng`, with `try_fill_bytes -> Result`), and the OS
  source implements only the fallible set because `getrandom` can
  fail. `ed25519-dalek` 3.0.0's `SigningKey::generate<R: CryptoRng>`
  requires the **infallible** `CryptoRng`, which the fallible
  `SysRng` does not satisfy directly. Because this crate bans
  `panic!`/`unwrap`/`expect` in library code (Tiger Style, compiler-
  enforced), the usual `UnwrapErr(SysRng)` / `.expect()` bridge is
  **not available**. The migration therefore forces a choice the
  reviewers must make before implementation:
  - **(A) Make the RNG-consuming functions fallible.**
    `crypto::SigningKey::generate`, `crypto::generate_nonce`, and
    `keystore::generate_salt` return `Result<_, AionError>` (new
    `AionError` variant for OS-RNG failure), propagating
    `try_fill_bytes` / `try_generate_from_rng` errors. Correct and
    panic-free, but **`SigningKey::generate`'s signature is public
    API** — this is a semver-major break against the 1.0.0 stability
    promise (`book/src/architecture/stability.md`), rippling to every
    caller and the `test_helpers`.
  - **(B) A narrowly-scoped, documented panic exception.** Treat OS-
    RNG failure as an unrecoverable abort (`std::process::abort()` or
    a single `#[allow]`-ed `expect`) with a written rationale in
    `Cargo.toml` / `.claude/rules/crypto.md`. Keeps signatures
    infallible but **violates the zero-panic invariant** and needs
    explicit sign-off.
  - **(C) Stay pinned** (the do-nothing alternative below) — no CVE
    forces the bump today.
  This RFC does **not** pick between (A) and (B); that is the
  gating decision. Implementation must not start until it is made.
- **Direct `rand_core` dependency vs. transitive-only.** Rationale
  above leans against adding `rand_core` as an explicit
  `[dependencies]` entry, but a reviewer favoring "explicit over
  implicit" for a load-bearing crypto dep could reasonably overrule
  that lean. Left open for implementation-time review.
- **MSRV impact.** Neither `ed25519-dalek` 3.0.0's nor `rand`
  0.10.2's minimum supported Rust version has been checked against
  the crate's pinned `rust-version = "1.70"` (`Cargo.toml`) as part
  of drafting this RFC. If either forces an MSRV bump, that is a
  separate, explicit decision for the implementation PR to surface,
  not something this RFC pre-approves.
- **`zeroize` interaction.** `zeroize` is currently pinned at `1.7`
  (workspace `Cargo.toml`) and wraps `SigningKey`'s raw bytes
  (`Zeroizing<[u8; 32]>`). Whether `ed25519-dalek` 3.0.0's internal
  key types change their own zeroization behavior (some major
  `dalek` releases have changed which types implement
  `ZeroizeOnDrop`) needs to be checked at implementation time — this
  RFC assumes no change to `aion-context`'s own `Zeroizing` wrapper,
  but does not verify upstream's internal zeroization story stayed
  identical.
- **Timing of the SBOM/dependabot-review process change.** This RFC
  argues #162 and #163 should never have been reviewable
  independently. Whether that implies a process change (e.g.
  dependabot grouping rules for known-coupled crypto deps, matching
  the existing `patch-updates` group already used elsewhere in this
  repo's dependabot config) is a tooling question this RFC raises
  but does not resolve.

## References

- RFC-0003 — Cryptography (Ed25519 signing, BLAKE3 hashing
  primitives this crate is built on).
- RFC-0004 — Key management (keystore integration, key material
  lifecycle this migration must not disturb).
- `.claude/rules/crypto.md` — "Never `thread_rng()` for key
  material"; load-bearing dependency list (`ed25519-dalek`, `blake3`,
  `chacha20poly1305`, `rand`, `zerocopy`).
- `.claude/rules/supply-chain.md` — "Aion-v2-specific posture": major
  version bumps of the crypto dependencies are RFCs and run through
  the full `aion-context/fuzz` target suite before merge.
- Dependabot PR #162 — `ed25519-dalek` 2.2.0 → 3.0.0.
- Dependabot PR #163 — `rand` 0.8.6 → 0.10.2.
- `ed25519-dalek` changelog / migration notes (2.x → 3.0.0), upstream
  repository.
- `rand` 0.9/0.10 migration guide (`RngCore`/`OsRng` relocation),
  upstream repository.
