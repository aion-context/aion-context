# RFC 0033: Post-Audit Cleanup and Hardening Carryovers

- **Author:** aion-context maintainers
- **Status:** DRAFT (tracking)
- **Created:** 2026-04-23
- **Updated:** 2026-04-23
- **Type:** Tracking RFC (no new design; enumerates deferred work
  from the RFC-0021 through RFC-0032 session + synthetic-team
  review)

## Abstract

The 12-RFC session that delivered RFC-0021 through RFC-0032 was
audited by a four-agent synthetic team (`crypto-auditor`,
`api-reviewer`, `rust-gatekeeper`, `drift-sentinel`). Every
in-scope blocker for the session's additions was closed by a
focused follow-up pass. This RFC enumerates the findings that
were explicitly **deferred** — either because they are
pre-existing tech debt from commit `31f27e0` (the extraction
commit) or because the fix is a cross-cutting architectural
change that warrants its own design RFC.

None of these carryovers affect the "room answer" for the
NVIDIA/Microsoft model-signing conversation: every externally-
visible guarantee verified in the session-level property tests
still holds. These are internal-hygiene and defense-in-depth
items that a follow-up cleanup PR (or a small set of them) can
close without further design work.

## Motivation

Why track these in one place instead of filing 9 issues:

1. **Shared rubric**: each item has the same "agent finding → fix
   shape → priority tier" shape, which is easier to review in one
   document than in scattered tickets.
2. **Attribution clarity**: several items were flagged by the
   synthetic team but actually date to commit `31f27e0`. A single
   RFC lets us document the attribution so future reviewers don't
   re-litigate.
3. **Sequencing**: some of these cleanups should land together
   (e.g. the registry-aware verify rollout in RFC-0028 Phase C
   affects multiple call sites). Listing them in one place lets
   us plan the PR shape.

## Carryover inventory

The matrix below summarizes every deferred item. Each has a
dedicated section below with file:line, attribution, and fix
shape.

| #  | Area                                     | Origin          | Priority | Fix shape                    |
|----|------------------------------------------|-----------------|----------|------------------------------|
| C1 | `test_helpers.rs` panic under feature    | Pre-existing    | P1       | Fallible `from_seed`         |
| C2 | `parser.rs` `.expect` on header          | Pre-existing    | P1       | Type-state or `Option`       |
| C3 | Clippy `.unwrap()` in `#[cfg(test)]`     | Pre-existing    | P3       | Replace or allow at mod-root |
| C4 | Registry-aware verify rollout (RFC-0028) | Session defer   | P0       | Its own sub-RFC              |
| C5 | OCI SHA-256 rule-conflict                | Session         | P2       | Amend `crypto.md`            |
| C6 | DSSE envelope keyid dedup                | Session         | P2       | Dedup in `verify_envelope`   |
| C7 | Manifest synthetic VersionEntry          | Session         | P2       | Dedicated canonical message  |
| C8 | Transparency-log empty-root domain       | Session         | P3       | Distinct empty-domain tag    |
| C9 | HybridSigningKey Drop/Zeroize            | Session         | P1       | Local PQ-secret newtype      |
| C10| Registry verify error info leakage       | Session         | P3       | Sanitize error messages      |

### C1 — `test_helpers.rs:121` panic under `feature = "test-helpers"`

**File/line**: `src/test_helpers.rs:121`
**Attribution**: `^31f27e0` (pre-existing; extraction commit)
**Rule violated**: `.claude/rules/tiger-style.md` — "No `panic!()`
in library code." The module is gated
`#[cfg(any(test, feature = "test-helpers"))]` at `src/lib.rs:86`,
so when a downstream crate enables the `test-helpers` feature,
the panic compiles into production library output.

**Current code**:

```rust
// src/test_helpers.rs:118-121
// Note: This panic is acceptable in test code
#[allow(clippy::panic)]
let signing = SigningKey::from_bytes(&key_bytes)
    .unwrap_or_else(|_| panic!("Failed to create key from seed {seed}"));
```

**Fix shape**: make `from_seed` fallible.

```rust
pub fn from_seed(seed: u64) -> Result<Self> {
    // ...
    let signing = SigningKey::from_bytes(&key_bytes)?;
    Ok(Self { signing, verifying: signing.verifying_key() })
}
```

All call sites are inside test code and already propagate
errors; `.unwrap_or_else(|_| std::process::abort())` is the
fallback per the sibling convention (`tiger-style.md`).

**Priority**: P1 — tech debt, not exploitable today.

### C2 — `parser.rs:401` `.expect()` on header construction

**File/line**: `src/parser.rs:395-401`
**Attribution**: `^31f27e0` (pre-existing)
**Rule violated**: `tiger-style.md` — "`#[allow(clippy::expect_used)]`
bypasses workspace-level `expect_used = "deny"` without an RFC."

**Current code**:

```rust
/// Should never panic as the header was validated during construction.
#[must_use]
#[allow(clippy::expect_used)] // Validated during construction
pub fn header(&self) -> &'a FileHeader {
    // Safety: We validated during construction that data is large enough
    FileHeader::ref_from_prefix(self.data).expect("header validated during construction")
}
```

**Fix shape options** (pick one in the follow-up):

**Option A (preferred)**: type-state proof. Change the
`AionParser` constructor to return the header alongside the
parser in a single owned value, then expose it via
`parser.header()` that reads from the owned copy — no runtime
`ref_from_prefix` on the hot path.

**Option B**: fallible accessor. Change to
`pub fn header(&self) -> Result<&'a FileHeader>`. All current
callers already operate inside fallible functions.

**Option C**: document as an intentional exception in
`.claude/rules/tiger-style.md` with this site listed explicitly.
Least effort but weakest position.

**Priority**: P1 — the invariant is genuinely upheld by
construction, but the rule weakening is a per-site `#[allow]`
that should require an RFC.

### C3 — Clippy `.unwrap()` violations in `#[cfg(test)]` modules

**Files (sample, not exhaustive)**:

- `src/conflict.rs:379` (`^31f27e0`, pre-existing)
- `src/multisig.rs:254` (`^31f27e0`, pre-existing)
- Many more across the pre-existing ~176 clippy violations that
  appear under `cargo clippy --all-targets`.

**Rule posture**: crate-level `unwrap_used = "deny"` applies to
every `--all-targets` compile, including `#[cfg(test)]` modules.
Sibling-project convention (per CLAUDE.md) is to use
`.unwrap_or_else(|_| std::process::abort())` inside
`#[cfg(test)]` modules, which both compiles and matches the
Tiger-Style-compatible failure mode.

**Fix shape**: systematic replacement. Grep for `.unwrap()` in
any `#[cfg(test)]` module under `src/`, replace with
`.unwrap_or_else(|_| std::process::abort())`. Some modules
already carry `#[allow(clippy::unwrap_used)]` at the `mod tests`
level (this session's new modules all do); the pre-existing ones
do not.

**Priority**: P3 — cosmetic / lint-hygiene. Does not affect
correctness or security. Blocks `cargo clippy --all-targets
-- -D warnings` from being green, which is the real cost.

### C4 — Registry-aware verify rollout (RFC-0028 Phase C)

**File/line (lead)**: `src/manifest.rs:363` — `verify_manifest_signature`
**Related**: every `verify_*` path that consumes
`signature.public_key` directly without consulting a pinned key
registry.
**Attribution**: session-level defer. The crypto-auditor's
Finding 1 and Finding 3 (author binding / manifest author
binding) are correct — the existing architecture takes the
verifying key from the signature bytes, which lets an adversary
with a valid-shaped key substitute.

**Context**: RFC-0028 (key rotation + revocation) added
`verify_signature_with_registry` and `verify_attestation_with_registry`
to the signature_chain module. These are the canonical
registry-pinning path. They were not retrofitted to
`verify_manifest_signature` in Phase A because (a) the existing
single-signer flow worked that way in the pre-session code, and
(b) retrofitting across every call site is a cross-cutting
change that deserves its own RFC.

**Fix shape**: RFC-0028 Phase C. New RFC branches out from this
one.

```rust
// Add to src/manifest.rs
pub fn verify_manifest_signature_with_registry(
    manifest: &ArtifactManifest,
    signature: &SignatureEntry,
    registry: &KeyRegistry,
    at_version: u64,
) -> Result<()>;

// In release.rs SignedRelease::verify
// - accept an optional &KeyRegistry argument
// - when provided, use the registry-aware path for every verify
//   step; when None, fall back to the current raw-public-key path
//   (documented as "trusting the caller's pinning layer")
```

Migration plan:

1. Land `verify_manifest_signature_with_registry` alongside the
   existing function.
2. Add `SignedRelease::verify_with_registry(&KeyRegistry)`.
3. Deprecate `SignedRelease::verify(&VerifyingKey)` in Phase D
   with a clear warning explaining the trust-pinning gap.

**Priority**: P0 — it's the largest-surface crypto improvement
remaining, and it's the exact question an auditor asks after
seeing RFC-0028 land.

### C5 — OCI SHA-256 for referrer binding vs BLAKE3-only rule

**File/line**: `src/oci.rs:70` — `sha256_digest`
**Attribution**: session (RFC-0030).
**Rule surface**: `.claude/rules/crypto.md` — "BLAKE3 only — no
SHA-1, no MD5."

**Tension**: OCI Image Manifest v1.1 mandates SHA-256 for
`digest` fields. We cannot emit a spec-compliant OCI artifact
without SHA-256. BLAKE3 is load-bearing inside `.aion` files; the
OCI layer is transport only. No security decision is made over a
hash we don't also verify via BLAKE3 internally — the aion
`manifest.verify_artifact` path is BLAKE3 end-to-end; the OCI
SHA-256 is redundant content-addressing for the registry.

**Fix shape**: amend `.claude/rules/crypto.md` with an explicit
exception:

```markdown
## External-spec exceptions

- **OCI Image Manifest (`src/oci.rs`)**: SHA-256 is mandated by
  OCI spec (OCI Image Manifest v1.1) for layer and config
  digests. aion emits SHA-256 at the OCI transport layer to
  interoperate with cosign / ORAS / registries. Internal content
  attestation (manifest, audit chain, transparency log, hybrid
  signatures) remains BLAKE3-only. The SHA-256 use at
  `src/oci.rs:70` is transport-only and does not gate any
  aion-internal security decision.
```

**Priority**: P2 — rule conflict rather than code bug. Safe to
ship as-is; the rule text is the artifact to amend.

### C6 — DSSE envelope dedup by keyid

**File/line**: `src/dsse.rs:199-230` — `verify_envelope`
**Attribution**: session (RFC-0023).
**Finding**: when an envelope carries two `DsseSignature` entries
with the same `keyid`, `verify_envelope` verifies both and the
returned `verified` vector has the same keyid twice. A caller
counting `verified.len()` for a quorum check would double-count.

**Why not fixed in Phase A**: the single-signer `SignedRelease`
flow never produces duplicate keyids. The bug only surfaces when
callers build multi-signer envelopes via `add_signature` and
accidentally reuse a signer. RFC-0021's multisig dedup path
already handles this correctly at the `verify_multisig` layer;
the concern is specifically at the raw DSSE verify boundary.

**Fix shape**:

```rust
pub fn verify_envelope<F>(envelope: &DsseEnvelope, key_for: F) -> Result<Vec<String>>
where
    F: Fn(&str) -> Option<VerifyingKey>,
{
    // ... existing checks ...
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for sig_entry in &envelope.signatures {
        if !seen.insert(&sig_entry.keyid) {
            continue; // duplicate keyid; do not count twice
        }
        // ... verify as before ...
    }
}
```

Or document in the method's docstring that the caller must dedup
and change the return type to `HashSet<String>`.

**Priority**: P2 — not a vulnerability today; prevents future
misuse.

### C7 — `manifest::sign_manifest` synthetic `VersionEntry`

**File/line**: `src/manifest.rs:325-335` — `manifest_as_version`
**Attribution**: session (RFC-0022).
**Finding**: to reuse `canonical_attestation_message` (RFC-0021)
the manifest-signing path constructs a synthetic `VersionEntry`
with zeroed fields and the manifest's BLAKE3 hash in
`rules_hash`. Works because BLAKE3 is collision-resistant, but
non-obvious and leaves `AuthorId(0)` and `VersionNumber(0)` as
"ghost author" values in signed material.

**Fix shape**: introduce a dedicated canonical message for
manifest signatures with its own domain separator.

```rust
const MANIFEST_SIGNATURE_DOMAIN: &[u8] = b"AION_V2_MANIFEST_SIG_V1\0";

pub fn canonical_manifest_signature_message(
    manifest: &ArtifactManifest,
    signer: AuthorId,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(64 + 32 + 8);
    msg.extend_from_slice(MANIFEST_SIGNATURE_DOMAIN);
    msg.extend_from_slice(manifest.manifest_id());
    msg.extend_from_slice(&signer.as_u64().to_le_bytes());
    msg
}
```

Then `sign_manifest` and `verify_manifest_signature` use this
function directly rather than synthesizing a `VersionEntry`.
This is a signature-format change — existing manifest
signatures would not verify under the new code. Landing strategy
is either a format-version bump or a side-by-side `_v2` function
alongside the existing one until migration is complete.

**Priority**: P2 — correctness finding for clarity, not a bug
that produces wrong answers today.

### C8 — Transparency-log empty-tree sentinel domain

**File/line**: `src/transparency_log.rs:191-195` — `empty_root`
**Attribution**: session (RFC-0025).
**Finding**: `empty_root()` returns
`BLAKE3(LOG_LEAF_DOMAIN)` — the same domain prefix used for
leaf hashing. A zero-entry tree and a (hypothetical) one-leaf
tree whose leaf produces the same bytes as the empty sentinel
would collide. In practice no real leaf can have those bytes
(leaf bytes include size-and-field prefix), so this is
non-exploitable. But the construction is not cleanly
domain-separated and may become a correctness hazard under
future extensions.

**Fix shape**:

```rust
pub const LOG_EMPTY_DOMAIN: &[u8] = b"AION_V2_LOG_EMPTY_V1\0";

fn empty_root() -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LOG_EMPTY_DOMAIN);
    *hasher.finalize().as_bytes()
}
```

Existing callers are internal; no API break.

**Priority**: P3 — hygiene; not exploitable.

### C9 — `HybridSigningKey` Drop/Zeroize for ML-DSA secret

**File/line**: `src/hybrid_sig.rs:77-81` — `HybridSigningKey`
fields.
**Attribution**: session (RFC-0027).
**Finding**: `pqcrypto_mldsa::mldsa65::SecretKey` is a C-FFI
wrapper that does not implement `zeroize::Zeroize`. When a
`HybridSigningKey` drops, the classical half's
`Zeroizing<[u8; 32]>` clears correctly, but the 4 KB ML-DSA
secret stays in heap memory until the allocator reuses it.

**Fix shape**: a local newtype that wraps the `mldsa65::SecretKey`
and implements `Drop` with an explicit zero-fill. `unsafe`
required because the PQ type hides its internal byte layout; the
`unsafe` block is audited per `.claude/rules/crypto.md`.

Actually the cleanest fix may be to copy the secret bytes into a
`Zeroizing<Vec<u8>>` on construction, then reconstitute the
`mldsa65::SecretKey` on each sign call via `from_bytes`. That
burns a few hundred microseconds per sign but puts the only
persistent storage in a zeroizing container.

Alternative: upstream a patch to `pqcrypto-mldsa` (already on
their issue tracker as of 2025) and pin that version here.

**Priority**: P1 — exposure surface is a small window but it's
key material.

### C10 — Registry verify error messages leak epoch numbers

**File/line**: `src/signature_chain.rs:318` (and the
`verify_attestation_with_registry` parallel).
**Attribution**: session (RFC-0028).
**Finding**: error messages include the current active epoch
number, e.g. `"signature public_key does not match registered
active epoch 3 for author 50001"`. To an unauthenticated caller
this is a side channel leaking the rotation state of a given
author.

**Fix shape**: replace internal-state-bearing error messages
with opaque ones at the public boundary:

```rust
return Err(crate::AionError::SignatureVerificationFailed {
    version: version.version_number,
    author: signer,
});
```

And log the detailed reason at `tracing::warn!` level (per
`.claude/rules/observability.md`) rather than including it in
the error variant.

**Priority**: P3 — information disclosure only; rotation state
is eventually public anyway once a transparency log publishes
the record.

## Suggested PR sequencing

The fix-shape priorities suggest three landing PRs:

**Cleanup PR 1 (P0–P1, tight scope)**

- C4 — the RFC-0028 Phase C sub-RFC itself, plus
  `verify_manifest_signature_with_registry` + the
  `SignedRelease::verify_with_registry` path.
- C1 — fallible `from_seed`.
- C2 — choose Option A/B for `parser.rs:401` and land the fix.
- C9 — `HybridSigningKey` zeroize path.

**Cleanup PR 2 (P2, rule / interop)**

- C5 — `crypto.md` OCI exception.
- C6 — DSSE dedup.
- C7 — manifest canonical message with dedicated domain.

**Cleanup PR 3 (P3, polish)**

- C3 — `.unwrap()` → `.unwrap_or_else(|_| std::process::abort())`
  sweep in pre-existing test modules.
- C8 — transparency-log empty-root domain tag.
- C10 — registry verify error message sanitization.

## Non-goals of this RFC

- **No new crypto or wire formats**. Every fix is a local
  refactor or a canonical-message addition bound to existing
  domain-separator discipline.
- **No new public API shape beyond the existing pattern**.
  `verify_*_with_registry` mirrors the RFC-0028 convention.
- **No `.aion` file-format change**. The v3 bump remains a
  separate follow-up per RFC-0022 Phase B.

## Open questions

1. **Deprecation policy for the raw-key verify paths** — hard
   deprecate in Phase D or keep them alive indefinitely with a
   "trust-your-caller" warning? The synthetic team favours hard
   deprecation; the pragmatic argument is that not every caller
   has a `KeyRegistry`.
2. **Who owns the `test-helpers` feature**? C1's fix makes
   `from_seed` fallible; any downstream consumer using
   `test-helpers` needs to update. Audit the dependency graph
   before PR 1 lands.

## References

- Four-agent synthetic-team review report (session output,
  2026-04-23).
- RFC-0021 through RFC-0032 (the work this cleanup follows).
- `.claude/rules/tiger-style.md`, `.claude/rules/crypto.md`,
  `.claude/rules/api-design.md`.

## Appendix A — verified attribution

git blame output confirming pre-existing lines, captured
2026-04-23:

- `src/test_helpers.rs:121` — `^31f27e0 (copyleftdev 2026-04-23)`
- `src/parser.rs:401` — `^31f27e0 (copyleftdev 2026-04-23)`
- `src/conflict.rs:379` — `^31f27e0 (copyleftdev 2026-04-23)`
- `src/multisig.rs:254` — `^31f27e0 (copyleftdev 2026-04-23)`

All four lines predate the 12-RFC session.

## Appendix B — post-fix metrics (session baseline for drift)

```
Tests:                  645 passing, 0 failed
  lib:                  463
  integration (cli):     22 passing, 2 ignored
  integration:          112 (three files)
  doc:                   85 passing, 1 ignored
Hegel properties:       108
Module count:           24 (13 pre-existing + 11 new)
Public API items:      ~476
LoC (src/):         ~20,800
Max function body:      53 lines (release::build_core)
Panic count (src/):    362 (unfiltered; includes test modules
                        and #[cfg(test)])
fmt --check:            clean
clippy (all-targets):   ~176 per-violation errors (all
                        pre-existing; zero introduced by this
                        session)
```

These values anchor the would-be drift baseline. Once
`.claude/drift/baseline.json` is populated from a clean post-
cleanup tree, `/drift-check` can regress against it.
