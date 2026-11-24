# RFC 0041: Migrate the Hybrid Signature's ML-DSA-65 Half to the Pure-Rust `ml-dsa` Crate

- **Author:** copyleftdev
- **Status:** ACCEPTED
- **Created:** 2026-11-23
- **Updated:** 2026-11-24
- **Depends on:** RFC-0027 (post-quantum hybrid), RFC-0037 (crypto/RNG stack upgrade), RFC-0033 (post-audit hardening, C9 zeroization)

## Abstract

RFC-0027's hybrid signature (Ed25519 + ML-DSA-65, `src/hybrid_sig.rs`)
takes its ML-DSA half from `pqcrypto-mldsa` 0.1.2, a wrapper over
PQClean's C code. PQClean is archived, so that crate and its two
helper crates will receive no further releases, and one known defect
in its AVX2 verifier (RUSTSEC-2026-0586) will never be patched
upstream. This RFC proposes replacing the backend with RustCrypto's
pure-Rust `ml-dsa` crate (0.1.2). The public hybrid API keeps its
shape. FIPS 204 public keys (1952 bytes) and signatures (3309 bytes)
are standard encodings, so existing signatures keep verifying. The
one real design decision is secret-key export. `ml-dsa` stores keys as
the 32-byte FIPS 204 seed and deprecates the 4032-byte expanded
encoding that `export_pq_secret` returns today. This RFC adds a
seed-based export and import, and keeps the expanded export as a
deprecated, export-only path for one release. There is no `.aion`
on-disk format change and no format-version bump.

## Motivation

### Problem Statement

**1. The backend is unmaintained and carries four advisory ignores.**
`deny.toml` and `.cargo/audit.toml` ignore:

| Advisory            | Subject                          | Nature                       |
|---------------------|----------------------------------|------------------------------|
| RUSTSEC-2026-0166   | `pqcrypto-mldsa`                 | unmaintained (PQClean archived) |
| RUSTSEC-2026-0162   | `pqcrypto-traits`                | unmaintained                 |
| RUSTSEC-2026-0163   | `pqcrypto-internals`             | unmaintained                 |
| RUSTSEC-2026-0586   | `pqcrypto-mldsa` AVX2 verifier   | verification defect          |

The first three entries are on `main` today. RUSTSEC-2026-0586 was
added by PR #245 (commit `c917b2a`, branch
`fix/243-244-mldsa-avx2-url`); the working tree this RFC was drafted
against had not yet pulled it. A fifth entry, RUSTSEC-2024-0436
(`paste`), is reachable only through this crate (see Rollout).
`.claude/rules/supply-chain.md` calls ignores a tax on the next
maintainer, and `deny.toml` already says to remove these "on the
`ml-dsa` migration". This RFC is that migration.

**2. RUSTSEC-2026-0586 is a verification bypass, not hygiene.**
PQClean's AVX2 ML-DSA verifier skips the FIPS 204 Algorithm 8
infinity-norm check on `z` and mishandles a `use_hint` boundary case.
Before the mitigation, on an x86_64 AVX2 machine our hybrid `verify`
accepted 41 invalid and rejected 1 valid of Wycheproof's 203 ML-DSA-65
non-context verify vectors. PR #245 mitigates it by building
`pqcrypto-mldsa` with `default-features = false, features = ["std"]`,
so only the portable reference code is compiled, and adds
`hybrid_sig::tests::wycheproof_mldsa65_verify_vectors` over a
six-vector subset in `tests/fixtures/mldsa/`. The mitigation is real
but fragile: the advisory matches on version, not features, and the
protection is one `Cargo.toml` line plus a six-vector test. Because
the crate is archived, a similar defect found later will have no
upstream fix.

**3. C via FFI in a crate that forbids unsafe.** `unsafe_code =
"forbid"` covers our source but not `pqcrypto-mldsa`'s FFI layer or
the `cc` build of `pqclean/`. The backend also brings a build-time C
toolchain requirement and `paste` (RUSTSEC-2024-0436). RFC-0027
accepted this because `ml-dsa` was then at `0.1.0-rc.8`; that
reasoning is revisited under Unresolved Questions.

### Why now

`ml-dsa` 0.1.2 (2026-10-31) is a stable `0.1` release, not a release
candidate. Its changelog lists fixes that matter to this threat model:
the Wycheproof verification failures and the `use_hint` fix for
`r0 = 0` (0.1.0, #1187 and #1194), constant-time work (0.1.2,
"Security: Fixed constant time issues", #1386), and rejection of
oversized contexts. Its dependency footprint overlaps heavily with
`ml-kem` 0.3.3, which `hpke` and `x-wing` (RFC-0039) already pull in.

### Goals

- Replace `pqcrypto-mldsa` and `pqcrypto-traits` with `ml-dsa`, with
  no change to the public hybrid API signatures except additions.
- Existing hybrid signatures and `HybridVerifyingKey` public-key bytes
  verify unchanged.
- Verification (accept/reject) behaviour passes the full Wycheproof
  ML-DSA-65 sets, not a six-vector subset.
- Remove the four ML-DSA-related advisory ignores, and the `paste`
  ignore if confirmed unused.
- Remove all C from the hybrid signature path.

### Non-Goals

- No `.aion` file-format change and no format-version bump. Hybrid
  signatures are not part of the on-disk format (RFC-0027 Phase A).
  Only `src/hybrid_sig.rs` and `examples/aegis_consortium.rs` use
  them.
- No Phase B integration (signature chain, multisig, DSSE) and no
  change to the canonical hybrid message or `HYBRID_DOMAIN`
  (`AION_V2_HYBRID_V1\0`).
- No change to the algorithm. It stays ML-DSA-65 with the empty
  context string, i.e. FIPS 204 "pure" signing. ML-DSA-44/87 and
  HashML-DSA are out of scope.
- No ML-DSA key persistence in the keystore. That remains future work
  (RFC-0027 Phase A) and would be its own RFC.

## Proposal

### Overview

`src/hybrid_sig.rs` is the only source file that names the backend.
It changes internally; the types `HybridSigningKey`,
`HybridVerifyingKey`, `HybridSignature`, `PqAlgorithm` and the
function `canonical_hybrid_message` keep their signatures.
`Cargo.toml` swaps two dependencies for one.

### Dependency declaration

```toml
# Post-quantum signatures (RFC-0027, RFC-0041). Pure-Rust FIPS 204.
# default-features off: no getrandom (RNG stays centralised in
# crypto::fill_os_entropy, RFC-0037), no pkcs8 (we never use PKCS#8).
ml-dsa = { version = "=0.1.2", default-features = false, features = ["alloc", "rand_core", "zeroize"] }
```

- **Exact pin (`=0.1.2`).** This follows `hpke = "=0.15.1"` in the same
  file. `.claude/rules/supply-chain.md` treats crypto dependencies as
  load-bearing and forbids loose pinning, and `0.x` minor bumps are
  breaking in Cargo semver anyway. The cost is manual bumps. That is
  intended, because each bump re-runs the verification plan below.
- **`zeroize`.** Under this feature `SigningKey` and
  `ExpandedSigningKey` implement `ZeroizeOnDrop` and the SHAKE state
  is wiped (0.1.2, #1473). It is required, not optional.
- **`alloc`.** Needed for heap offload of large values and the
  precomputed verifying key. `rand_core` is needed for randomized
  signing (see Signing randomness).
- Expected dependency effect, to be confirmed by the SBOM diff and
  `cargo tree`: `signature 3`, `hybrid-array 0.4`, `crypto-common
  0.2`, `ctutils`, `shake 0.1` and `zeroize` are already in
  `Cargo.lock`. `module-lattice` moves from 0.2.3 to 0.2.4 (`ml-dsa`
  requires `>=0.2.4`) and `ctutils` from 0.4.5 to at least 0.4.7. No
  `pkcs8`, `const-oid` or `der` additions because `pkcs8` is
  feature-gated off.
- License `Apache-2.0 OR MIT` is on the allowlist. `rust-version =
  1.87` is below our 1.89.
- Removed: `pqcrypto-mldsa`, `pqcrypto-traits`, `pqcrypto-internals`,
  and `paste` (see Rollout).

### Internal structure

```rust
use ml_dsa::{ExpandedSigningKey, MlDsa65, Signature, SigningKey, VerifyingKey};

pub struct HybridSigningKey {
    classical: ClassicalSigningKey,
    pq: SigningKey<MlDsa65>,          // seed + expanded; ZeroizeOnDrop
    pq_public: VerifyingKey<MlDsa65>,
}
```

Today the secret is stored as `Zeroizing<Vec<u8>>` and re-parsed on
every `sign`, because the FFI `SecretKey` has no `Zeroize` (RFC-0033
C9). With `ml-dsa`'s `zeroize` feature the typed key zeroizes itself,
so the key can be held live and the reparse-per-sign disappears. This
is both safer, since there is no per-call 4 KB copy, and cheaper.
`HybridVerifyingKey` caches the encoded 1952-byte public key so
`pq_public_bytes() -> &[u8]` keeps its current borrowing signature.

Key generation draws the 32-byte seed ξ from `crypto::fill_os_entropy`
(RFC-0037, fallible, no panic path) and calls `SigningKey::from_seed`.
It does not use `ml_dsa::Generate`, which would put a second RNG route
in a crate that centralised them. `HybridSigningKey::generate` already
returns `Result` (`EntropyUnavailable`); `from_classical` becomes
`-> Result<Self>` for the same reason. See Unresolved Questions on
that signature change.

### Verification path

```rust
fn verify_mldsa65(public: &VerifyingKey<MlDsa65>, message: &[u8], sig: &[u8]) -> Result<()>
```

This replaces the helper PR #245 introduced. It does three things.

1. `Signature::<MlDsa65>::try_from(sig)` rejects any length other
   than 3309 and any malformed hint encoding (`Signature::decode`
   returns `Option`). Maps to `AionError::InvalidFormat`.
2. `public.verify_with_context(message, &[], &sig)` returns `bool`,
   which maps to `InvalidFormat` on `false`. Context is the empty
   string, matching pqcrypto's `detached_sign`/`verify_detached_signature`
   (FIPS 204 pure mode, `mu = H(tr || 0x00 || 0x00 || M)`).
3. `VerifyingKey::decode` is infallible in 0.1.2 (public keys are
   fixed-size and every 1952-byte string decodes). Length is checked
   by `HybridVerifyingKey` construction, so `pq_public_bytes` cannot
   hold anything but 1952 bytes. This RFC does not claim that
   structurally malformed public keys are detectable, because FIPS 204
   defines no validity check for `t1`.

The classical half still verifies first, and an unknown `algorithm`
discriminant is still rejected before either half runs. Both halves
still must verify. The verdict logic, error variants and the
`warn!`/`info!` events (once the module is instrumented per
`.claude/rules/observability.md`) do not change.

### Signing randomness

`pqcrypto`'s `detached_sign` is **hedged**: PQClean's `sign.c` draws
`rnd` from `randombytes`, so two signatures over the same message
differ. `ml-dsa` offers both modes: `SigningKey`'s `Signer` impl is
**deterministic** (`rnd = 0^32`), and `ExpandedSigningKey::
sign_randomized` is hedged.

Decision: keep **hedged** signing. Implementation: sign through
`ExpandedSigningKey` using `sign_randomized(message, &[], &mut rng)`
with `rand::rngs::SysRng` (`rand` 0.10, already a dependency, and a
`TryCryptoRng`), which makes OS RNG failure a returned error rather
than a panic. FIPS 204 recommends hedged signing as the default and
deterministic signing mainly as a fallback where no RNG exists. A
deterministic signature is also easier to exploit through fault
injection. Cost: signing needs the OS RNG (it already did), and the
failure path is a new `Err(EntropyUnavailable)` from `sign`.

Byte-identical signatures between the two backends are **not
required** and not possible under hedging. Only verification
interoperability is. Tests assert verification, never byte equality of
signatures. Public keys, however, are deterministic from ξ, so a
known-answer test on `from_seed` public-key bytes is byte-exact (see
Verification plan).

`sign` must not call `sign_mu_deterministic`, which panics when
rejection sampling is exhausted (documented in 0.1.2). It uses only
the `Result`-returning APIs, whose rejection-sampling exhaustion fix
is in 0.1.2 (#1481). That error maps to `SigningFailed`, not the
`InvalidFormat` the old reconstitution failure used.

### Secret-key export: options

This is the one compatibility-sensitive decision. FIPS 204 permits
storing a private key as the 32-byte seed ξ. `ml-dsa` makes the seed
the primary form (`SigningKey::from_seed`, `to_seed`, `as_seed`) and
marks the expanded 4032-byte form deprecated since 0.1.0
(`ExpandedSigningKey::{from_expanded, to_expanded}`). The
`from_expanded` documentation warns that it does not validate
expanded keys and **can panic on malformed or maliciously generated
input**. Today `HybridSigningKey::export_pq_secret` returns the
4032-byte expanded key. aion-context does not persist PQ keys and
there is no import API, so nothing in this crate can read an exported
key back. Callers may nevertheless hold exported 4032-byte blobs in
their own storage.

**Option 1 - Switch export to the seed (breaking).** `export_pq_secret`
returns the 32-byte seed. Simplest and safest. Silently changes the
length and meaning of a returned `Zeroizing<Vec<u8>>`, so a caller
who stored the old output and later feeds it to their own FIPS 204
tooling gets a wrong-size secret. Rejected as a silent semantic change
under an unchanged name.

**Option 2 - Keep the expanded form only.** Retain 4032-byte export
via deprecated `to_expanded`, and add an import via `from_expanded`.
Maximises continuity but imports an adversary-reachable panic: a
malformed blob would panic inside `from_expanded`, which violates the
zero-panic rule on untrusted input. Importing into a hybrid key would
also need a manual structural validation we would have to write, which
conflicts with "do not write new crypto". Rejected.

**Option 3 - Versioned export (recommended).**

```rust
impl HybridSigningKey {
    /// 32-byte FIPS 204 seed xi. The only supported persistence form.
    #[must_use]
    pub fn export_pq_seed(&self) -> zeroize::Zeroizing<[u8; 32]>;

    /// Rebuild a hybrid key from a classical key and a PQ seed.
    /// Infallible on length because the type is `[u8; 32]`.
    #[must_use]
    pub fn from_seeds(classical: ClassicalSigningKey, pq_seed: &[u8; 32]) -> Self;

    #[deprecated(since = "4.0.0", note = "use export_pq_seed; expanded keys are deprecated in FIPS 204 practice and ml-dsa")]
    #[must_use]
    pub fn export_pq_secret(&self) -> zeroize::Zeroizing<Vec<u8>>; // still 4032 B
}
```

- `export_pq_seed` and `from_seeds` are new additions, with no existing
  caller affected.
- `export_pq_secret` keeps returning the same 4032-byte FIPS 204
  `skEncode` value, derived from the seed through
  `ExpandedSigningKey::from_seed(..).to_expanded()` inside
  `#[allow(deprecated)]`. Encoding does not panic; only decoding
  does. Callers' existing stored blobs stay meaningful as FIPS 204
  secret keys for external tools. The export is deprecated, and
  removed at the next major version.
- There is deliberately **no** expanded-key import. A caller holding an
  old 4032-byte blob cannot load it into `HybridSigningKey`. Such a
  key must be treated as retired: generate a new hybrid key and rotate
  (the PQ half is not pinned in any `.aion` file today, so rotation is
  a caller-side action). This is the cost of the recommendation, and
  Unresolved Questions asks whether that is acceptable.
- The deprecated path derives the expanded form from the seed, so the
  signing key holds a seed. A key that originated from an expanded
  blob cannot exist here, which is why no import is offered.

### API surface after migration

| Item                                        | Change                      |
|---------------------------------------------|-----------------------------|
| `HybridSigningKey::generate() -> Result<Self>` | unchanged signature      |
| `HybridSigningKey::from_classical`          | `Self` to `Result<Self>` (entropy; see Unresolved) |
| `HybridSigningKey::verifying_key`           | unchanged                   |
| `HybridSigningKey::sign() -> Result<HybridSignature>` | unchanged; may now return `EntropyUnavailable` |
| `HybridSigningKey::classical_seed`          | unchanged                   |
| `HybridSigningKey::export_pq_secret`        | deprecated, same bytes      |
| `HybridSigningKey::export_pq_seed`, `from_seeds` | new                    |
| `HybridVerifyingKey::{algorithm, classical, pq_public_bytes, verify}` | unchanged |
| `HybridSignature { algorithm, classical, pq }` | unchanged                |
| `canonical_hybrid_message`, `PqAlgorithm`, `HYBRID_DOMAIN` | unchanged     |

No `ml_dsa` or `signature` type appears in a public signature, so the
rule in `.claude/rules/api-design.md` against exposing third-party
types is respected, and the crate's public API stays decoupled from
the backend.

### Wire compatibility

| Artifact          | pqcrypto-mldsa 0.1.2  | ml-dsa 0.1.2 | Compatible |
|-------------------|-----------------------|--------------|------------|
| Public key        | 1952 B, FIPS 204 `pkEncode` | 1952 B, `pkEncode` (Alg. 22/23) | yes |
| Signature         | 3309 B, FIPS 204 `sigEncode` | 3309 B (`Signature::encode`) | yes |
| Secret key (export) | 4032 B `skEncode`   | 4032 B via deprecated `to_expanded`; 32 B seed new | yes / new |
| Signing context   | empty                 | empty        | yes        |

(`src/hybrid_sig.rs`'s `HybridSignature::pq` doc comment says "3293
for ML-DSA-65". That is wrong, since the module's own size assertion
and FIPS 204 give 3309, and the implementation PR fixes the comment.)

Hybrid signatures are not embedded in `.aion` files in Phase A, so no
on-disk reader sees a changed byte. No `UnsupportedVersion` path,
migration tool or format bump is needed. The `api-design.md` format-
stability checklist (RFC, version bump, migration path, fuzz target)
applies to the on-disk format and is not triggered, and this RFC says
so explicitly rather than by omission.

## Verification plan

Acceptance is gated on all of the following. The implementation PR
must show them, not assert them.

1. **Full Wycheproof, verify.** Run every vector of
   `testvectors_v1/mldsa_65_verify_test.json` (the C2SP/wycheproof
   commit `20b256949ea8` used for the existing fixture, or a newer
   pinned commit recorded in the fixture header) through
   `verify_mldsa65`. Expected: 203 non-context vectors, all verdicts
   match `result` (`valid` accepts, `invalid` rejects), with 0
   mismatches. Replace the six-vector subset with the full file in
   `tests/fixtures/mldsa/` (Apache-2.0 header retained), and keep
   `wycheproof_mldsa65_verify_vectors` as the test name so CI history
   is continuous. Vectors with a non-empty context are out of scope
   because `hybrid_sig` fixes the context to empty. Their handling
   must be listed in the test, with a count, not skipped silently.
2. **Full Wycheproof, sign.** `mldsa_65_sign_*` vectors drive
   `ExpandedSigningKey` from the vector's seed, using the internal
   deterministic path only if public, or otherwise checking sign
   outputs by verification. Hedged signing does not allow byte
   comparison. Public keys derived from vector seeds are compared
   byte-for-byte.
3. **NIST ACVP KATs, if feasible.** ML-DSA-65 `keyGen` (seed to
   public key, byte-exact, which holds for any backend) and `sigVer`
   cases from the ACVP-Server vectors. `sigGen` is byte-exact only for
   deterministic mode and applies to a test-only path. If the
   `sigGen` vectors cannot be reached without a deprecated or
   `doc(hidden)` API, drop them and say so in the PR. Whether this
   is feasible is an open item, not a promise.
4. **Cross-backend interop, migration-period test.** Generate
   signatures with the clean `pqcrypto-mldsa` (portable build, no
   `avx2`) and verify them under `ml-dsa`, and the reverse, over a
   fixed corpus plus a Hegel-generated one. This needs `pqcrypto-mldsa`
   as a `[dev-dependencies]` entry during the migration PR and one
   follow-up release, then removal in a final PR. The ignores for the
   dev-only crates remain until then, so the "remove four ignores"
   step lands with that last PR, not the backend swap. Cargo
   `dev-dependencies` are still compiled in CI, so the SBOM and
   `cargo deny` see them.
5. **Existing Hegel properties unchanged**, all eight under
   `src/hybrid_sig.rs` in `.claude/rules/property-testing.md`: sign/verify
   round-trip, tampered payload, wrong classical key, wrong PQ key,
   corrupted classical sig, corrupted PQ sig, domain separation from
   plain Ed25519, algorithm mismatch. Two of them
   (`prop_hybrid_wrong_pq_key_rejects`,
   `prop_hybrid_domain_separated_from_plain_ed25519`) call
   `mldsa65::keypair()` and `mldsa65::detached_sign` directly and are
   rewritten to the new API. Their asserted invariant must not weaken.
   Added properties: `export_pq_seed` then `from_seeds` yields the
   same verifying key bytes, and a signature from the rebuilt key
   verifies under the original verifying key.
6. **Fuzzing.** There is currently **no** hybrid-signature fuzz target
   (`fuzz/fuzz_targets/` has parser, manifest, registry, chain and
   envelope targets only). `.claude/rules/supply-chain.md` requires
   the full fuzz suite on crypto-dependency changes, so the existing
   targets run, and this RFC adds
   `fuzz_hybrid_verify.rs`: arbitrary `(pq_public, message, sig)`
   bytes into `verify_mldsa65`, asserting no panic and that
   `Ok` implies the signature re-verifies. The fuzz crate's own
   `Cargo.lock` is synced (it currently carries `paste` and
   `pqcrypto-*` entries).
7. **Performance.** `benches/crypto_benchmarks.rs` has Ed25519 and
   BLAKE3 benches but **no** ML-DSA bench. Add `mldsa65_keygen`,
   `mldsa65_sign` and `mldsa65_verify` over 1 KB and 64 KB payloads,
   recorded on the pqcrypto backend before the swap and on `ml-dsa`
   after. RFC-0027's budget governs, and a regression beyond the
   budget is reported in the PR for a decision, not ignored. Pure
   Rust ML-DSA is typically slower than AVX2 C, but that
   expectation is unmeasured here and must be measured.
8. **Supply chain.** `cargo deny check`, `cargo audit`, SBOM diff of
   `.claude/drift/sbom.json` (expect `pqcrypto-*` and `paste` removed;
   `ml-dsa` added; `module-lattice` and `ctutils` bumped; no other
   new package), per `.claude/rules/supply-chain.md`.
9. **Crypto review.** The diff touches `src/hybrid_sig.rs`, which
   matches the `crypto-auditor` triggers in `.claude/rules/crypto.md`
   (hybrid signing and `**/sign*.rs`-adjacent logic). The
   `crypto-auditor` agent reviews the PR before merge. This is a
   blocking gate, not a courtesy.

## Rationale and Alternatives

### Do nothing: stay on `pqcrypto-mldsa` with the clean build

Keep `default-features = false, features = ["std"]`, the six-vector
test, and the four ignores. Lowest effort, and PR #245 already makes
the shipped build pass all 203 non-context Wycheproof verify vectors.
Rejected as the end state because:

- The crate is frozen. The next defect in PQClean's C will have no
  upstream fix, and we would be the maintainers of an ML-DSA
  verifier we did not write.
- The mitigation is a feature flag and a subset test. The advisory
  keeps firing on version, so every future audit run depends on an
  ignore whose justification we have to keep re-reading.
- It leaves C, FFI and a `cc` build in the only path that verifies
  post-quantum signatures.

It remains a valid interim state, and it is what ships until this RFC
is implemented.

### Vendor or fork PQClean

Copy the ML-DSA-65 `clean` directory into the tree (or maintain a
fork of `pqcrypto-mldsa`) and patch it ourselves. Rejected. It makes
us maintainers of C cryptography, which contradicts "do not roll your
own" in `.claude/rules/crypto.md`, keeps `unsafe` FFI, and gives up
the entire value of an upstream. It would also need its own
side-channel review each time we pulled in a PQClean fix.

### `libcrux-ml-dsa` (Cryspen)

Formally verified (hax/F*) Rust ML-DSA, with a fast portable and SIMD
implementation. Technically the strongest candidate on assurance, and
the one to revisit if our requirements tighten. Not chosen here
because I have not verified its current release, license, MSRV or API
stability against our supply-chain rules, so this RFC cannot claim
it fits. It would add a separate dependency tree (it does not share
`hybrid-array`, `module-lattice` or `shake` with `ml-kem`), and its
SIMD paths bring back architecture-dispatched code, which is the
feature that failed us in RUSTSEC-2026-0586. Its verified guarantees
cover specific implementation configurations, and whether our usage
falls inside them is unexamined. Listed in Unresolved Questions as a
reviewer decision.

### Other pure-Rust crates (`pqc-sig`, `krypteia-quantica`)

Both appear in `cargo search` for ML-DSA. Rejected on evidence we can
state: neither is under the RustCrypto organisation or a
formally-verified project, and we have no independent audit or
maintenance record to cite for either. This RFC did not read their
source. Judged on maintenance and review pedigree alone, `ml-dsa`
has an organisation behind it that already supplies `ml-kem`, which
this repository already trusts through `hpke`/`x-wing`. A reviewer
who has better information about either crate should say so, and that
would reopen this section.

### Keep both backends behind a feature flag

Ship `pqcrypto-mldsa` and `ml-dsa` together with a Cargo feature
choosing one. Rejected. It keeps the advisory ignores alive for
anyone who enables the old backend, doubles the verification surface,
and invites verifier disagreement, which is the failure mode that
RUSTSEC-2026-0586 demonstrated. Cross-backend testing is confined to
dev-dependencies and a single release.

## Security Considerations

### Threat model

This swaps the implementation of a primitive behind an unchanged
interface. It adds no new trust boundary, but it changes who we trust
for ML-DSA arithmetic, from PQClean's reviewed C to a 0.1-series
pure-Rust crate. The risk profile is regression in verification
behaviour and key hygiene.

- **Verifier divergence.** The hybrid accepts only when both halves
  verify, so a wrong-accept in ML-DSA is bounded by Ed25519 and a
  wrong-reject is a denial-of-signature, not a forgery. That bound
  covers only a classical break that has not happened. It does not
  cover a post-quantum adversary, for whom the ML-DSA half is the
  only protection. Mitigation: full Wycheproof, ACVP, fuzzing and
  cross-backend tests (Verification plan).
- **Side channels.** `ml-dsa` states constant-time work (0.1.2,
  Barrett reduction in 0.1.0, `ctutils`-based selection). Compiler-
  level constant time is not guaranteed in pure Rust and has not been
  independently measured for this crate by us. Signing keys live on
  the signer's machine, so this is a signer-side concern and not a
  verifier concern. Recorded under Unresolved Questions.
- **Panics on adversary input.** `Signature::try_from` and
  `VerifyingKey::decode` are non-panicking on arbitrary bytes. The
  deprecated `from_expanded` can panic and is therefore never called
  on external input (Option 2 is rejected for this reason). The
  `sign_mu_deterministic` API can panic and is not used. The fuzz
  target in the Verification plan covers the verifier path.
- **Key material.** Seed and expanded key are zeroized on drop
  (`zeroize` feature). `export_pq_seed` returns
  `Zeroizing<[u8; 32]>`. None of seed, expanded key, or full public
  key may appear in a trace field, per `observability.md`.

### Guarantees preserved

- Both halves must verify. Classical verification and the algorithm
  discriminant check precede the PQ half.
- Domain separation: the signed message is still
  `HYBRID_DOMAIN || payload`.
- Existing signatures and public keys remain valid without
  re-signing.
- OS entropy remains the only randomness source for key and signing
  randomness, and its failure returns `EntropyUnavailable`.

### Crypto-rule text

`.claude/rules/crypto.md` should be updated in the implementation PR,
not this RFC:

- Add `ml-dsa` to the required-dependency table (Signing row, PQ
  hybrid).
- Extend the "SHA-3 family inside ML-KEM and X-Wing (RFC-0039
  Phase B)" exception: ML-DSA uses SHAKE-128/256 internally for
  matrix expansion, challenge sampling and `mu`/`tr`/`c_tilde`
  hashing. Unlike the ML-KEM case, SHAKE output **is** an input to an
  accept/reject comparison inside `ml-dsa` (`c_tilde == cp_tilde`),
  though not a comparison aion-context performs, and no
  aion-internal hash is derived with it. The exception text must say
  this rather than copy the ML-KEM wording, and the crypto-auditor
  should confirm the wording.

## Testing Strategy

Covered by the Verification plan. In summary: full Wycheproof verify
and sign, ACVP where feasible, cross-backend interop for one release,
the eight existing hybrid Hegel properties plus the seed round-trip
property, a new fuzz target, new benches, and the supply-chain gate.
`.claude/rules/property-testing.md` gains the seed round-trip
property row under `src/hybrid_sig.rs`.

## Implementation Plan

1. Land this RFC as accepted.
2. Pull `main` so PR #245's `verify_mldsa65` and fixture are present.
3. PR A (backend swap): add `ml-dsa`, keep `pqcrypto-mldsa` as a
   `dev-dependency`, rewrite `src/hybrid_sig.rs`, add seed export and
   import, full Wycheproof fixtures, cross-backend tests, the fuzz
   target, benches. `crypto-auditor` review. `fuzz/Cargo.lock`
   synced. SBOM regenerated.
4. PR B (cleanup, after one release): remove `pqcrypto-mldsa` and
   `pqcrypto-traits` from `Cargo.toml`, remove the ignores
   RUSTSEC-2026-0166, -0162, -0163 and -0586 from `deny.toml` and
   `.cargo/audit.toml`, drop the cross-backend tests, regenerate the
   SBOM.
5. Update `.claude/rules/crypto.md` (dependency table, SHAKE
   exception) and `.claude/rules/property-testing.md`.
6. Follow-up PR: mark RFC-0027 "Why `pqcrypto-mldsa`" section as
   superseded by this RFC (a status or cross-reference edit only), and
   set this RFC to IMPLEMENTED.

### Rollout: advisory ignores

After PR B, remove `pqcrypto-traits` and the three advisory entries
plus RUSTSEC-2026-0586. Also check RUSTSEC-2024-0436 (`paste`): in
the current tree `cargo tree -i paste` shows `paste` reached only
through `pqcrypto-mldsa`, so it should go too. The comment in
`.cargo/audit.toml` says `hegeltest` also pulls it, which the current
`Cargo.lock` does not bear out (hegeltest 0.52.2 is the dev
dependency in this tree), but `fuzz/Cargo.lock` is separate and must
be checked on its own. Keep the `paste` ignore if any resolution
still contains it.

## Unresolved Questions

**Resolved at acceptance (2026-11-24):** the maintainer accepted the
recommended defaults for three of the questions below.
- **Export:** take option 3. Callers holding stored expanded keys rotate.
- **Pin:** pin `ml-dsa` exactly at `=0.1.2`, accepting that no
  third-party audit was found.
- **Target:** `ml-dsa` is the target. `libcrux-ml-dsa` stays an
  alternative to revisit later.

The remaining questions stay open for the implementation PR.

- **Audit and advisory history of `ml-dsa`.** I could not verify that
  `ml-dsa` has had an independent third-party audit, and I did not
  query RustSec for past advisories against it. The 0.1.2 changelog
  lists "Security: Fixed constant time issues" and 0.1.0 lists
  Wycheproof and `use_hint` fixes, which shows the crate has had
  correctness and timing bugs in this area. Before acceptance,
  someone must check the RustSec database and RustCrypto's tracker
  and record the result here. If no audit exists, reviewers must
  decide whether a `0.1` crate with no audit is acceptable for a
  verifier. RFC-0027 declined `ml-dsa` on exactly this ground (no
  1.0, no review), and 0.1.2 is still pre-1.0.
- **Is trading a reviewed-but-frozen C verifier for a newer pure-Rust
  one a net win?** The case here is maintenance, memory safety and
  supply chain. The counter-case is that PQClean has had years of
  scrutiny and `ml-dsa` has about 6 months since 0.1.0 (2026-05-17).
  The full Wycheproof and ACVP pass is the evidence offered, and it
  is necessary rather than sufficient.
- **Export decision.** Option 3 strands any caller holding a stored
  4032-byte key: they can sign with it externally but cannot load it
  into `HybridSigningKey`. Is there a known caller with persisted
  expanded keys? If so, an import path would need a validated
  decoder, which is a larger and riskier change. Also: does deprecating
  `export_pq_secret` and adding two methods count as a minor release
  under `book/src/architecture/stability.md`, and what version
  number do we put in the `deprecated` attribute?
- **`from_classical` signature.** Moving from `Self` to `Result<Self>`
  is a source-breaking change in a public function (needed because
  seed generation can fail). Alternatives: keep `Self` by taking the
  PQ seed as a parameter, or add `try_from_classical` and deprecate
  the old name. Reviewers should choose, and the choice affects the
  semver story above.
- **Hedged vs deterministic default.** Recommended hedged. If a reviewer
  wants reproducible signatures for test vectors or audit replay, a
  deterministic mode could be exposed `#[cfg(test)]` only. Offering it
  publicly is not recommended here.
- **ACVP feasibility.** `sigGen` vectors may need an internal
  deterministic entry point that is `doc(hidden)` or deprecated in
  `ml-dsa`. Whether the KAT set is reachable through public API is
  unchecked.
- **Performance budget.** There are no ML-DSA benches today and no
  baseline, so whether pure-Rust meets RFC-0027's budget is unknown.
  The "typically slower than AVX2 C" claim is a prior, not a
  measurement.
- **Side-channel assurance.** We have not measured constant-time
  behaviour of `ml-dsa` on our target compilers, and the only evidence
  is the upstream changelog. Is a dudect-style or `ctgrind` check in
  scope for the implementation PR, or accepted risk?
- **`libcrux-ml-dsa` as the better long-term answer.** Its formal
  verification may justify the larger dependency delta. Someone needs
  to read its license, MSRV, release state and verified-code scope
  before this Alternatives entry can be closed.
- **Dependency pin style.** `=0.1.2` follows `hpke` but blocks
  automatic patch releases. If upstream ships a security fix we must
  bump by hand, and Dependabot has to be configured to propose it.
- **`ml-dsa` default-feature set.** This RFC disables `getrandom` and
  `pkcs8`. If a later RFC wants PKCS#8 key interchange, it can enable
  it then. Is dropping `pkcs8` now premature?
- **RFC-0027 text.** RFC-0027 explains why it chose `pqcrypto-mldsa`.
  RFCs are historical records and are not edited in place, so the
  superseding link belongs here and in a status note only.

## References

- RFC-0027 - Post-Quantum Hybrid Signatures. Origin of the module and
  of the "pqcrypto vs ml-dsa" choice this RFC revisits.
- RFC-0037 - Crypto/RNG Stack Upgrade. Fallible OS entropy
  (`crypto::fill_os_entropy`, `AionError::EntropyUnavailable`) and the
  format of a crypto dependency RFC.
- RFC-0033 - Post-Audit Cleanup and Hardening Carryovers, C9 (zeroization of the PQ secret).
- RFC-0039 - Confidential rules. Brings `ml-kem`, `x-wing` and `shake`
  into the tree.
- `.claude/rules/crypto.md`, `.claude/rules/supply-chain.md`,
  `.claude/rules/property-testing.md`, `.claude/rules/api-design.md`.
- `deny.toml` and `.cargo/audit.toml` (advisory ignores).
- PR #245 / commit `c917b2a` - AVX2 mitigation for RUSTSEC-2026-0586,
  issues #243 and #244.
- FIPS 204, Module-Lattice-Based Digital Signature Standard (NIST,
  2024), Algorithms 2, 3, 6, 8, 22-25.
- `ml-dsa` 0.1.2 (RustCrypto/signatures), `CHANGELOG.md` and
  `src/signing.rs` (seed API, deprecated expanded API, randomized
  and deterministic signing).
- C2SP/wycheproof `testvectors_v1/mldsa_65_verify_test.json` and
  `mldsa_65_sign_*`, commit `20b256949ea8`.
- NIST ACVP-Server ML-DSA vectors.
- PQClean (archived). RUSTSEC-2026-0166, -0162, -0163, -0586, and
  RUSTSEC-2024-0436.
