# RFC 0039: Confidential Rules (Format v3)

- **Author:** copyleftdev
- **Status:** ACCEPTED (2026-10-23). Phase A IMPLEMENTED (2.0.0). Questions 1 and 8 decided 2026-10-23 (native HPKE envelope; X25519 and X-Wing stanzas, X-Wing by default). Question 3 must be decided before Phase D.
- **Created:** 2026-10-23
- **Updated:** 2026-10-23 (five crypto-review rounds; Phase B decisions; see Review history)
- **Depends on:** RFC-0002 (file format), RFC-0003 (cryptography),
  RFC-0004 (key management), RFC-0005 (signature chain), RFC-0012
  (versioning), RFC-0028 (key rotation and revocation), RFC-0038
  (external version signer)
- **Supersedes (in part):** RFC-0003 § "Rule Encryption Protocol"

## Abstract

Format v2 stores the rules payload as ChaCha20-Poly1305 ciphertext
under a key derived only from public header fields. Anyone holding a
file can read its rules, and the signed `rules_hash` is a BLAKE3 hash
of the plaintext, stored in the clear. This RFC defines **format v3**
with two explicit rules-protection modes:

- **Public:** the payload is stored in the clear.
- **Confidential:** the payload is encrypted under a fresh per-version
  data-encryption key (DEK). The DEK is wrapped for each named
  recipient, using HPKE (RFC 9180) X25519 keys or an external
  KMS/HSM wrapper.

In both modes the signed version entry commits to the **stored
bytes** of the rules section (encrypt-then-sign). Any verifier can
therefore check that the payload is the one the author signed
without holding a decryption key. That closes the GHSA-7625-44v8-v62f
class by construction.

## Motivation

### Problem Statement

Three facts about v2 motivate this RFC.

1. **No confidentiality.** `encrypt_rules` derives its key from
   `"aion-v2-master-{file_id}"`, salted with `file_id`. Every input is
   public. This is documented as of #196, but users who need secret
   policies have no option except encrypting the whole file outside
   aion. That also hides it from verifiers.
2. **The plaintext hash is in the clear.** `VersionEntry.rules_hash =
   BLAKE3(plaintext)` is signed and stored unencrypted. Even with a
   secret key, anyone can confirm a guessed policy ("is the refund
   limit 500 or 5000?") offline. Low-entropy policies are exactly the
   ones people want hidden.
3. **What is signed is not what is stored.** The signature covers the
   plaintext hash, but readers consume the stored ciphertext. Binding
   the two requires decryption. In v2 that is possible because the
   key is public, and `verify_file` simply forgot to do it
   (GHSA-7625-44v8-v62f, fixed in 1.0.1). With a real secret key,
   verifiers without the key could not perform that check at all. So
   a naive "just use a real key" fix would make the advisory's bug
   class unfixable for third-party verifiers.

### Use Cases

- **Regulated policy content.** A clinical-escalation or fraud-
  threshold policy must be enforceable by an agent runtime and
  auditable by a regulator. It must not be readable by everyone who
  can see the artifact store or the transparency log.
- **Third-party verification without disclosure.** An auditor
  verifies the full signature chain, registry epochs, and payload
  binding of a confidential file without being a recipient.
- **Selective disclosure.** A recipient proves to a third party what
  version N said by revealing one per-version key. No long-term key
  and no other version is exposed.
- **KMS custody.** The DEK is wrapped by a cloud KMS or HSM key that
  never leaves the provider, mirroring RFC-0038's signer boundary.

### Goals

- Two explicit modes, Public and Confidential, chosen per version. No
  "encryption" that protects nothing.
- Key-free payload binding: every verifier can check the stored rules
  section against the signed commitment.
- Confidential payloads readable only by named recipients. Recipients
  are added or removed by committing a new version.
- No offline confirmation of guessed plaintexts by non-recipients.
- Every recipient who can open a version's stanza decrypts the same
  plaintext (key commitment).
- No new hand-rolled cryptography. HPKE comes from a vetted crate;
  content encryption reuses the existing `crypto::encrypt` /
  `derive_key`.
- v3 readers read v2 files. v2 readers reject v3 files with
  `UnsupportedVersion` (already true: `parser.rs` accepts exactly
  `FORMAT_VERSION`).

### Non-Goals

- **Metadata confidentiality.** Commit messages (string table), the
  audit trail, author IDs, timestamps, version count, and recipient
  public keys stay in the clear. See [Leakage](#what-remains-visible).
- **Forward secrecy.** Compromising a recipient's private key exposes
  every version ever wrapped to it.
- **Revoking past access.** Removing a recipient only affects future
  versions. Anything they could already decrypt, they may have kept.
- **Access control inside one version.** Every recipient of a version
  reads the whole payload.
- **Rewriting v2 history.** Existing v2 signatures cover v2 semantics
  and cannot be re-signed. See [Migration](#migration-from-v2).

## Proposal

### Overview

```
stored rules section  ──BLAKE3(domain ‖ bytes)──▶  rules_commitment
                                                     │ (in VersionEntry.rules_hash)
                                                     ▼
                                    signed by the author (v3 domain)

Public mode:        section = framed plaintext
Confidential mode:  section = envelope {
                       suite, dek_commitment,
                       recipient stanzas (DEK wrapped per recipient),
                       nonce, ChaCha20-Poly1305(K_enc, framed plaintext)
                    }
```

A verifier hashes the section and compares it with the signed
commitment, in either mode and with no key. The signed message also
covers `file_id` and the mode, so a signed entry cannot be moved into
another file or reinterpreted under the other mode. A recipient
additionally:

1. unwraps the DEK,
2. checks it against `dek_commitment`,
3. decrypts (the AEAD tag authenticates the plaintext under the
   committed key).

### Detailed Design

#### Header

- `version = 3`.
- `flags` bit 0 is redefined as **HEAD_CONFIDENTIAL** for v3 files: it
  mirrors the mode of the latest version, so tools can tell from the
  header alone whether the inline section is an envelope. Bits 1–15
  stay reserved and must be zero.
- v3 readers interpret bit 0 by `version`. The v2 "Encrypted" bit
  keeps its v2 meaning: obfuscated, not confidential.
- Every other header field is unchanged.

#### Version entry: per-version mode

Modes may differ between versions, and only the latest section is
stored inline. So each version records its own mode, in
`VersionEntry.reserved[0]` as `rules_mode`: `0x00` public, `0x01`
confidential. The other 51 reserved bytes must still be zero. The
152-byte layout is unchanged.

v2 readers already reject any non-zero reserved byte, so this is a
v3-only change. That rejection, together with the format-version
check, is the migration guard.

**The mode's single source of truth is the stored `rules_mode` of
each entry.** The reader never infers a mode from the section's bytes
(for example by sniffing the envelope magic). It checks:

1. Each entry's signature over the v3 canonical message, which
   includes that entry's stored `rules_mode`. So a modified mode byte
   fails the signature.
2. For the latest entry, `rules_commitment` is recomputed over the
   inline section using the stored `rules_mode`.
3. Header flags bit 0 must equal the latest entry's `rules_mode`.

Any disagreement fails verification. Historical entries' modes are
covered by step 1. Their sections are not in the file; see
[Reading](#reading) for archived sections.

#### Rules commitment (replaces the meaning of `rules_hash` in v3)

```
rules_commitment = BLAKE3(RULES_COMMIT_DOMAIN ‖ u8 mode ‖ section_bytes)
RULES_COMMIT_DOMAIN = b"AION_V3_RULES_COMMIT_V1\0"
mode = 0x00 (public) | 0x01 (confidential)
```

The mode byte makes the two encodings unambiguous. A public section
whose bytes happen to look like an envelope commits differently from
the same bytes read as an envelope.

The commitment is stored in `VersionEntry.rules_hash`; only the
field's definition changes. It is also mirrored in the header's
`current_hash` / `root_hash`, as in v2.

#### Plaintext framing (both modes)

```
framed = u64_le(plaintext_len) ‖ plaintext ‖ zero_padding
```

Padding brings `len(framed)` up to the Padmé size of
`8 + plaintext_len`. Padmé bounds the overhead at about 12% and leaks
only O(log log n) bits of length. Public mode uses the same framing
so the two modes share one decoder. Readers reject non-zero padding
and a `plaintext_len` that exceeds the frame.

#### Confidential envelope

All integers are little-endian. Every length is bounded before
allocation.

```
envelope := magic[8]               = b"AIONENV1"
            suite: u8              = 0x01
            dek_commitment[32]
            stanza_count: u16      (1..=64)
            stanzas[stanza_count]
            nonce[12]
            ct_len: u64            (≤ the reader's rules-size limit + framing + 16; checked before allocation)
            ciphertext[ct_len]     (ChaCha20-Poly1305 output, tag included)

stanza  := kind: u8
           body_len: u16           (≤ 4096)
           body[body_len]
```

Parsing limits and canonical form:

- The total size of all stanzas is capped at 160 KiB. That fits 64
  X-Wing stanzas (2,387 bytes each with their headers). The cap is
  checked before any HPKE or provider work.
- Stanzas must be sorted by `(kind, body)`, and duplicates are
  rejected. Writers produce exactly one encoding for a given recipient
  set, so a reordered or duplicated set is a different, unsigned
  section.

**Suite 0x01 key schedule.**

- The DEK is 32 random bytes from `crypto::fill_os_entropy`.
- It is fresh for every version **and for every attempt**: a failed
  or retried commit, such as an external wrapper timing out, draws a
  new DEK and a new nonce rather than reusing either.
- `ctx = file_id_le ‖ author_id_le ‖ version_le` (24 bytes).

```
K_enc          = crypto::derive_key(ikm = DEK, salt = ctx,
                                    info = b"AION_V3_RULES_KEY_V1\0")   // HKDF-SHA256, 32 bytes
dek_commitment = BLAKE3::derive_key("aion-context v3 2026-10 dek commitment", DEK)
nonce          = 12 random bytes
ciphertext     = ChaCha20-Poly1305(K_enc, nonce, framed,
                                   aad = b"AION_V3_RULES_AAD_V1\0" ‖ ctx)
```

`crypto::derive_key(ikm, salt, info, output)` is the existing
argument order. The commitment uses BLAKE3's `derive_key` mode with a
fixed, globally unique context string, which is BLAKE3's own
domain-separation mechanism. Every value compared in an accept or
reject decision is therefore a BLAKE3 output, as
`.claude/rules/crypto.md` requires.

`file_id` is chosen by the author and is only 64 bits. It is a binding
input, never a uniqueness assumption: nothing stops two authors from
picking the same `file_id`. `author_id` is in `ctx` for exactly that
reason. Without it, a malicious author could copy another author's
confidential section verbatim, signing ciphertext they cannot read,
and recipients would decrypt the victim's rules under the copier's
name.

**Why `dek_commitment` is a key commitment.**

- **Binding:** it is a deterministic BLAKE3 `derive_key` output of the
  DEK, and BLAKE3 is collision-resistant. So no two DEKs produce the
  same commitment.
- **Fixed key:** `K_enc` is a deterministic function of the DEK and
  `ctx`, both fixed by the signed section. A given ciphertext
  therefore has exactly one key it can decrypt under. That defeats
  "invisible salamanders" despite ChaCha20-Poly1305 not being
  key-committing.
- **Hiding:** it reveals nothing only because the DEK has full 256-bit
  entropy. A leaked DEK can be confirmed against it, which is
  harmless because the DEK itself is then known.

No separate plaintext commitment is needed. Once the key is fixed,
the AEAD tag authenticates the plaintext for anyone who holds the DEK,
recipients and selective-disclosure parties alike.

**Stanza kinds.**

| kind | Name | Body |
|---|---|---|
| `0x01` | HPKE X25519 recipient | `recipient_pk[32] ‖ enc[32] ‖ wrapped_dek[48]`. `body_len` must be exactly 112. |
| `0x02` | External wrapper | `provider_id_len u8 ‖ provider_id ‖ key_ref_len u16 ‖ key_ref ‖ blob_len u16 ‖ blob`. The inner lengths plus their 5 length bytes must sum exactly to `body_len`; trailing or missing bytes reject. `provider_id` (1–64 bytes) and `key_ref` (1–1024 bytes) are non-empty UTF-8, and `blob` is non-empty. |
| `0x03` | HPKE X-Wing recipient | `recipient_pk[1216] ‖ enc[1120] ‖ wrapped_dek[48]`. `body_len` must be exactly 2,384. |
| `0x00`, `0x04`–`0xFF` | Reserved | Readers skip unknown kinds. A reader that holds no identity matching any stanza fails with `NotARecipient`. |

**Stanza ordering and identity.**

- Stanzas are sorted by bytewise-lexicographic comparison of
  `kind ‖ body`.
- The parser checks every known kind's exact body length or inner
  length sum before any KEM, HPKE, or provider work. A wrong length
  rejects the whole envelope.
- A section with two stanzas for the same **recipient identity** is
  rejected. The identity is `(kind, recipient_pk)` for kinds `0x01`
  and `0x03`, `(0x02, provider_id, key_ref)` for kind `0x02`, and
  `(kind, body)` for an unknown kind. Different `enc` or blob bytes do
  not make them different recipients. Identities of different kinds
  never collide: the X25519 half inside an X-Wing public key is
  derived from the X-Wing seed and is not a usable X25519 identity on
  its own.
- Sorting is deterministic even though HPKE `enc` is random per seal.
  For kinds `0x01` and `0x03` the identity is the body prefix, and
  kind `0x02` bodies are length-prefixed. So a re-wrap to the same recipient set
  always yields the same order.

**HPKE (kinds `0x01` and `0x03`).**

- **Mode:** RFC 9180 base mode, with HKDF-SHA256 and
  ChaCha20-Poly1305. The KEM depends on the kind:
  - `0x01`: DHKEM(X25519, HKDF-SHA256), KEM ID `0x0020`.
  - `0x03`: X-Wing (ML-KEM-768 + X25519), KEM ID `0x647a`, as defined
    by draft-ietf-hpke-pq-03 over X-Wing draft-06 and implemented by
    `hpke` 0.14.1 (`x-wing` 0.1.1). The hybrid stays confidential while
    either ML-KEM-768 or X25519 holds, which defends files kept for
    years against harvest-now-decrypt-later.
- **Inputs:** `info = b"AION_V3_DEK_WRAP_V1\0" ‖ ctx`, where
  `ctx = file_id ‖ author_id ‖ version`, and `aad = dek_commitment`.
- **Why these inputs:**
  - Binding `info` to `ctx` stops a stanza being transplanted into
    another file, version, or author's section.
  - Binding `aad` stops it being paired with a different DEK
    commitment.
  - `recipient_pk` and the suite are deliberately left out of `info`.
    HPKE's key schedule binds the suite ID (`kem_id ‖ kdf_id ‖
    aead_id`), so kinds `0x01` and `0x03` derive disjoint secrets.
    The recipient key is bound per KEM:
    - DHKEM(X25519) puts the recipient public key in its KEM context.
    - X-Wing has no KEM context. Its combiner binds the X25519
      ciphertext and public key and both shared secrets, and ML-KEM's
      Fujisaki-Okamoto transform binds the ML-KEM ciphertext to the
      ML-KEM key. A stanza presented to the wrong recipient fails to
      open.
- **No sender authentication:** base mode does not authenticate the
  sender. Authorship comes from the version signature, and `author_id`
  in `ctx` is what ties the two together.
- **Recipient key:** `recipient_pk` is stored in full. A committer can
  then re-wrap the next version for the same recipient set without
  out-of-band key distribution. The cost is that recipient keys are
  visible; see the Unresolved Questions.
- **Encryption identities.** An identity record is `(kind, seed,
  recipient_pk)`:
  - `seed` is 32 bytes drawn from the OS RNG for that identity alone,
    held in `Zeroizing`, never logged, and never serialized outside
    the keystore's encrypted blob.
  - Kind `0x01`: the seed is the X25519 secret key, loaded with
    `hpke`'s `PrivateKey::from_bytes`.
  - Kind `0x03`: the seed is the X-Wing decapsulation-key seed, loaded
    raw with `hpke`'s `PrivateKey::from_bytes`, which expands it to
    ML-KEM-768 and X25519 keys. `derive_keypair` is not used; it
    applies an extra labeled derivation and would yield a different
    key.
  - **One seed, one kind.** A seed is never used for a second kind,
    for signing, or as input to any other derivation. Using the same
    32 bytes as both an X25519 key and an X-Wing seed would be
    cross-protocol key reuse.
  - `recipient_pk` is cached next to the seed, so listing or matching
    identities never repeats an ML-KEM key generation.
- **Draft pinning.** X-Wing and its HPKE binding are IETF drafts. The
  crate pins `hpke = "=0.14.1"`. `x-wing` 0.1.x and `ml-kem` 0.3.x are
  held by the committed `Cargo.lock`. A known-answer test fixes the
  exact stanza bytes produced from a fixed seed and fixed
  encapsulation randomness: `hpke`'s seal takes the caller's
  `CryptoRng`, and the test passes a deterministic test-only RNG. A dependency update that changes those
  bytes fails the test. A later, incompatible X-Wing or HPKE-PQ
  revision gets a **new stanza kind**; kind `0x03` keeps meaning
  exactly this encoding forever, so existing files stay openable.
  A RUSTSEC fix in any of these crates is taken as a patch bump that
  must still pass the known-answer test. A fix that changes the wire
  encoding is a new kind, not an in-place change.

**External wrapper (kind `0x02`).** This mirrors RFC-0038. A provider
implements:

```rust
pub trait DekWrapper {
    fn provider_id(&self) -> &str;          // ≤ 64 bytes, e.g. "gcp-kms"
    fn key_ref(&self) -> &str;              // ≤ 1024 bytes, provider key name
    fn wrap(&self, dek: &[u8; 32], context: &[u8]) -> Result<Vec<u8>>;   // blob ≤ 4096
}
pub trait DekUnwrapper {
    fn unwrap(&self, stanza: &ExternalStanza<'_>, context: &[u8]) -> Result<Zeroizing<[u8; 32]>>;
}
```

`context = b"AION_V3_DEK_WRAP_V1\0" ‖ ctx ‖ dek_commitment` is passed
as the KMS encryption context, or as AAD, where the provider supports
it.

The core always checks the unwrapped DEK against `dek_commitment`
before using it, so a provider bug cannot cause plaintext divergence.
Calls to `wrap` and `unwrap` run under a caller-configured timeout,
and the returned blob is bounded at 4096 bytes.

#### Signatures

v2's `canonical_version_message` (`src/signature_chain.rs`) covers
the version number, parent hash, `rules_hash`, author, timestamp, and
message offset and length. It does **not** cover `file_id`, the format
version, or the flags.

That was tolerable in v2 only because the rules key derived from
`file_id`, so a transplanted entry failed decryption. In v3, public
mode has no key and verification is key-free by design. So the v3
canonical message is:

```
AION_V3_VERSION_SIGNATURE_V1\0 ‖ format_version u16 ‖ file_id u64 ‖ mode u8 ‖
version u64 ‖ parent_hash[32] ‖ rules_commitment[32] ‖ author u64 ‖
timestamp u64 ‖ message_offset u64 ‖ message_length u32
```

Here `mode` is the entry's stored `rules_mode`, `format_version` is
the header's `version`, and `file_id` is the header's `file_id`.

- **No transplant:** a signed entry cannot be moved into a header with
  another `file_id` or format version.
- **No mode change:** no version's mode can be changed without
  breaking its signature. A non-author therefore cannot flip any
  version, historical or head, between public and confidential.
- **Other signed messages:** RFC-0021 attestations get
  `AION_V3_ATTESTATION_V1\0` with the same added fields.
- **Every path that signs or verifies a version uses the v3 canonical
  message for v3 files.** That includes:
  - registry-aware verification: `verify_signature_with_registry`,
    `verify_signatures_batch`, and the RFC-0028/0034 paths;
  - RFC-0027 hybrid signatures;
  - RFC-0038 external signers: the provider receives the v3 message;
  - RFC-0021 multisig attestations;
  - the DSSE version-attestation payload, which adds `rules_mode`,
    `file_id`, and `format_version` fields for v3.

**v3 version hash.** In v2, `compute_version_hash`, the value each
`parent_hash` links to, covers the v2 canonical fields. For v3 it
covers the **v3 canonical message**: every field listed above,
including `format_version`, `file_id`, and the entry's `rules_mode`.
It is computed under its own domain:
`BLAKE3(AION_V3_VERSION_HASH_V1\0 ‖ fields)`, where `fields` is
everything in the signed message after the signature domain. So the
value `parent_hash` links to is never the same BLAKE3 input as a
signed message. A version's mode is therefore part of its identity. Re-signing the
same version number with a different mode yields a different version
hash, which the parent links of later versions, and the acceptance
store, treat as a different version (equivocation).

Every new v3 domain string ends in `\0`, so no domain is a prefix of
another. This follows the transparency-log and hybrid-signature
domains.

#### Verification (key-free)

For v3, `verify_file` adds one check to the v2 set, and needs no key:

- `hash_chain_valid` additionally requires
  `rules_commitment(stored section) == latest.rules_hash`.

This is the structural form of the 1.0.1 fix. Public-mode files also
validate the framing.

**Integrity versus acceptance.** Two separate APIs, so replay defense
can't be forgotten by omission:

- `verify_file(path, &registry) -> VerificationReport` stays a
  **stateless integrity verdict**: "is this file internally consistent
  and correctly signed?". It does not, and cannot, defend against
  replay. Its docs say so.
- `accept_file(path, &registry, &AcceptPolicy, &dyn
  AcceptedVersionStore) -> Result<VerifiedChain>` is the
  **receiver-side acceptance** API required by `crypto.md` property 1
  and `distributed.md`. The store is a mandatory parameter: there is
  no default and no `Option`.

`AcceptPolicy` carries:

- `min_format_version`: reject v2 files where v3 is required;
- `require_confidential: Option<ConfidentialScope>`:
  - `Head` rejects a file whose latest `rules_mode` is public.
  - `AllVersions` rejects a file in which **any** entry's `rules_mode`
    is public.
  - Both read the signed per-entry modes, so neither needs a key.

`AcceptedVersionStore` semantics:

- **Key:** `file_id`. Version numbers are file-global: one chain, many
  authors, one monotonic sequence. Keying by author would let an older
  prefix whose head has a different author slip past the record.
- **Value:** `(genesis_hash, head_version, head_hash)`. All are v3
  version hashes, which cover `rules_mode` (see Signatures), taken from
  the verified chain. A **pinned** record, created by
  `pin(file_id, genesis_hash)`, has `head_version = 0` and no
  `head_hash`.
- **Decision**, applied only **after** every integrity, signature and
  policy check has passed, so an attacker cannot burn version numbers
  with invalid files. Let `P` be the presented verified chain, and
  `P[v]` its entry at version `v`.

  | Stored vs presented | Result |
  |---|---|
  | no record | accept and record |
  | pinned record (`head_version = 0`) and `hash(P[1]) = stored.genesis_hash` | accept and advance |
  | `hash(P[1]) ≠ stored.genesis_hash`, pinned or not | reject as a **foreign chain** under the same `file_id` (`reason = "file_id_conflict"`) |
  | `P.head_version < stored.head_version` | reject as **rollback** (`reason = "version_replay"`) |
  | `hash(P[stored.head_version]) ≠ stored.head_hash` | reject as a **fork or equivocation**: the presented chain does not extend what was accepted (`reason = "version_equivocation"`). This covers both a different chain at the same version and a higher-versioned fork. |
  | `P.head_version == stored.head_version` (and the hash matches) | accept, idempotent; no write |
  | `P.head_version > stored.head_version` (and the ancestor matches) | accept and advance to `(genesis_hash, P.head_version, hash(P.head))` |

  The ancestry check is O(1), because `P` is already a verified hash
  chain. Matching one entry's hash at the stored version proves that
  the whole accepted prefix is contained in `P`. The rows are
  evaluated in order. The rollback row precedes the ancestry row, so
  `P[stored.head_version]` is always defined when it is looked up.
- **`file_id` squatting:** `file_id` is author-chosen. A store that
  first accepts an attacker's chain under a victim's `file_id` will
  then reject the victim's chain as `file_id_conflict`. Acceptance
  still requires a signature valid under the caller's pinned registry,
  so the attacker must be a registered author. Squatting is therefore
  a **denial of service against acceptance, not a forgery**: the
  victim's rules are never replaced. Deployments that consume specific
  policies should pin the expected `(file_id, genesis_hash)` up front
  with `pin`, rather than learning it on first use.
- **Trait surface:**

  ```rust
  pub trait AcceptedVersionStore {
      fn pin(&self, file_id: FileId, genesis_hash: [u8; 32]) -> Result<()>;
      fn check_and_advance(&self, file_id: FileId, chain: &ChainSummary<'_>)
          -> Result<StoreDecision>;
  }
  pub enum StoreDecision { Accepted, AcceptedIdempotent }
  ```

  - **Rejections:** a rejection is
    `Err(AionError::VersionRejected { reason })`, where the bounded
    `reason` is `VersionRejectReason::{Replay, Equivocation,
    FileIdConflict}`. These are logged as `version_replay`,
    `version_equivocation` and `file_id_conflict`.
  - **Store errors** are `Err(AionError::StoreUnavailable)`.
  - **New variants:** both are new `AionError` variants. `AionError`
    is `#[non_exhaustive]`.
- **`ChainSummary` contract:** it exposes `genesis_hash()`,
  `head_version()`, `head_hash()`, and `hash_at(version) -> [u8; 32]`.
  - **Callback timing:** the implementation calls `hash_at` **inside**
    its critical section, after reading the stored record and before
    writing. The whole read, compare and write is one atomic
    compare-and-swap.
  - **Concurrency:** the trait takes `&self`, and implementations
    provide their own synchronization, as `AttestationStore` does in
    RFC-0036. Concurrent acceptances of the same `file_id` cannot both
    win.
  - **Valid input:** `hash_at(v)` is only called for
    `1 ≤ v ≤ head_version()`. Row order guarantees this, and
    `ChainSummary` returns an error rather than panicking if the
    contract is violated.
- **Failure:** any store error fails the acceptance closed, as a
  `StoreUnavailable` error. The store is never skipped.

*Implementation note (Phase A4):*
- **Module:** these live in the `acceptance` module.
- **Decision table:** it is the public pure function
  `decide(record, chain)`, which every store calls inside its
  compare-and-swap.
- **Trait signature:** the store trait is
  `check_and_advance(&self, ChainSummary)`, without a separate
  `file_id`, because the summary carries it.
- **Policy errors:** violations return
  `AionError::PolicyRejected { reason }` (`format_below_minimum`,
  `head_not_confidential`, `version_not_confidential`).
- **Stores:** `MemoryStore` and the single-process `FileStore` ship
  with the crate.
- **CLI:** it adds `--min-format` and `--require-confidential`.
  - `--state` must exist unless `--init-state` is given.
  - `--pin` is a check against the presented genesis, not a persisted
    pin, so a mistyped pin cannot lock the state. Library callers still
    persist pins with `AcceptedVersionStore::pin`.
  - Exit 2 means the store was unusable and no verdict was reached.
- **`FileStore` writes:** they take an exclusive `<state>.lock`, so a
  concurrent writer fails closed instead of racing.

The CLI gets `aion accept <FILE> --registry … --state <path>`, backed
by a file store. The store writes a temp file, fsyncs it, renames it
over the old one, and fsyncs the directory, so a crash cannot lose an
advance or tear a record. `aion verify` remains the stateless check.

#### Reading

Reading never trusts an unverified entry, and never re-reads the
file. A `VerifiedChain` **owns** the exact bytes it verified, as an
owned buffer or a held mmap that it does not re-open. Every opening
function reads the section from those bytes, never from the path, so
swapping the file between verification and opening has no effect.
Every opening function
takes a `VerifiedEntry<'_>`, a typestate value that can only be
obtained from a `VerifiedChain`. A `VerifiedChain` is returned by
`accept_file`, or by `verify_file_chain(path, &registry)`, which is the
stateless form. A `VerifiedEntry` carries the signature-checked
`file_id`, `format_version`, `author_id`, `version`, `rules_mode` and
`rules_commitment`. The public API has no way to build one from raw
fields. So a forged entry can never drive `ctx` or the commitment
check, a caller cannot pass a mismatched `file_id`, and nothing reads
state before it is verified.

| Function | Behavior |
|---|---|
| `show_current_rules(path)` | Kept for compatibility. It reads the file **once** into a buffer and reads the section from that same buffer, never re-opening the path. It takes no registry, so it checks the head's commitment (key-free) but cannot verify signatures. Public mode: returns the plaintext. Confidential mode: `Err(AionError::RecipientKeyRequired)`. New code should use `open_current_rules(&VerifiedChain, …)`. |
| `open_current_rules(&VerifiedChain, &RecipientKeys)` | **New.** Opens the head section. |
| `open_rules_section(section, VerifiedEntry<'_>, &RecipientKeys \| &Dek)` | **New.** Opens an **archived** section, such as a historical version's section stored outside the file under its `rules_commitment`. It first recomputes the commitment over `section` and compares it with the verified entry's. A disclosed DEK opens that one section and no other, because each DEK is independent random. |
| `disclose_version_key(section, VerifiedEntry<'_>, &RecipientKeys)` | **New.** Returns that version's DEK, for selective disclosure. |

**Opening errors** (new `AionError` variants; `AionError` is
`#[non_exhaustive]`):

- `NotARecipient`: none of the held identities matches a stanza. This
  reveals nothing, because recipient identities are public in the
  stanzas.
- `RulesUnopenable`: a matching stanza exists, but any later step
  failed: unwrap, `dek_commitment`, AEAD, or framing. This one variant
  is deliberately opaque about *which* step. The padding check runs
  only after the AEAD verifies, so there is no padding oracle. A
  recipient whose own key is listed but who gets `RulesUnopenable`
  knows the author shipped an undecryptable stanza for them. That is
  the only party who can know it.

The file holds only the latest section, as in v2. Historical versions
can be opened only if someone archived their sections. Archival is
the operator's job, and the commitment is the archive key.

*Implementation note (Phase A3):* these live in the `chain` module.
`VerifiedChain::from_bytes` verifies bytes already in memory, and
`verify_file_chain` reads a path. Failures return
`AionError::ChainRejected { reason }`, with the same bounded reason as
the `file_rejected` trace event. `RecipientKeys` ships as a
`#[non_exhaustive]` placeholder, where `RecipientKeys::none()` opens
public and v2 rules. `disclose_version_key` and the
`NotARecipient` / `RulesUnopenable` split arrive with Phase B, the
first phase that has confidential sections to open. Until then a
confidential section returns `RecipientKeyRequired`.

#### Writing

`InitOptions` / `CommitOptions` / `ExternalCommitOptions` gain a
`protection: RulesProtection<'a>` field:

```rust
#[non_exhaustive]
pub enum RulesProtection {
    Public,
    Confidential { recipients: Vec<Recipient> },   // non-empty
}
#[non_exhaustive]
pub enum Recipient {
    X25519([u8; 32]),
    XWing(Box<[u8; 1216]>),
    External(Arc<dyn DekWrapper>),   // Phase C
}
```

There is **no default**. Callers name the mode. This is a breaking
change, and the next release is already 2.0.0.

*Implementation note (Phase A2b):* `RulesProtection` and `Recipient`
own their data rather than borrowing, so the shipped type is
`RulesProtection` with no lifetime parameter, `#[non_exhaustive]`.
With only `Public` in Phase A, a borrowed `'a` would have been unused.
Adding the parameter later would have been a second breaking change.
Phase B's `Confidential` variant holds an owned recipient list, with
external wrappers held behind a shared pointer.

*Decision (Phase A2b):* `InitOptions`, `CommitOptions`, and
`ExternalCommitOptions` stay struct-literal, with no
`#[non_exhaustive]` and no constructors. They borrow keys and messages,
so literals read naturally, and the required `protection` field keeps
the no-default rule visible at every call site. Their fields are
frozen. New per-write choices grow inside `RulesProtection` (Phase B's
recipients) rather than as new fields.

`commit_version` never needs the previous version's plaintext.

The CLI never carries recipients over silently. `aion commit` takes
either explicit `--recipient …` arguments or `--keep-recipients`.
`--keep-recipients` takes the inherited stanzas from the `VerifiedChain`
of the file being extended, never from an unverified re-read. It
prints the inherited X25519 set before committing,
and fails if the previous version had any external (`0x02`) stanza.
External wrappers need live provider handles, which the file cannot
supply, so those must be re-specified. This keeps a recipient who
should have been removed from carrying over by default.

#### CLI

- `aion init` requires exactly one of `--public` or one or more
  `--recipient <x25519-pubkey-file | kms:<provider>:<key>>`.
- `aion commit` requires exactly one of `--public`, one or more
  `--recipient …`, or `--keep-recipients`.
  - `--keep-recipients` fails with a message naming the problem if the
    previous version was public (there are no recipients to keep), or
    had any external (`0x02`) or unknown-kind stanza (it cannot be
    re-wrapped from the file alone).
- `--no-encryption` becomes an alias for `--public` with a deprecation
  note.
- `aion key generate --encryption [--kem xwing|x25519]` creates an
  encryption identity in the keystore. **X-Wing is the default.** This
  is a separate key kind from Ed25519 signing keys. The exported
  public-key file names its KEM, so `--recipient <file>` needs no
  separate kind flag.
- Committing with any X25519 recipient or any external wrapper next
  to an X-Wing recipient prints a note: the version is only as
  post-quantum-safe as its weakest stanza.
- `aion show <FILE> rules --identity <key-id>` decrypts. Without an
  identity, a confidential file reports `RecipientKeyRequired` and
  exits 1. With an identity that isn't listed, it reports
  `NotARecipient`; with one that is listed but can't open the stanza,
  `RulesUnopenable`.
- `aion verify` is unchanged and key-free.

#### What remains visible

In confidential mode an observer still sees:

- the recipient public keys, each stanza's kind (so whether a
  recipient uses X25519 or X-Wing), and the count of external
  wrappers;
- payload length to within the Padmé bucket;
- commit messages, audit entries, author IDs, timestamps, and the
  version count;
- whether two versions share recipients.

They do **not** see the plaintext, nor any hash an attacker could use
to confirm a guess about it.

#### Migration from v2

v2 signatures commit to v2 semantics, so a v2 history cannot be
converted in place.

- **Phase C ships `aion migrate <v2> <v3> --public|--recipient …`.**
  It creates a new v3 genesis whose first audit entry is a
  `MigratedFrom` record: a new on-disk `ActionCode` value (5), which
  is an audit-log format addition covered by this RFC. The record
  carries the v2 file's `file_id`, head version number, and head
  version hash.
- **The v2 file is archived unchanged.** Verifying both files and the
  link establishes continuity.
- **v3 readers keep reading v2 files.** They are reported as format 2
  with the existing "not confidential" semantics.

### Examples

```rust
let recipients = vec![
    Recipient::XWing(auditor.public_key()),
    Recipient::External(kms.clone()),
];
init_file(path, rules, &InitOptions {
    author_id, signing_key: &key, message: "v1", timestamp: None,
    protection: RulesProtection::Confidential { recipients },
})?;

let report = verify_file(path, &registry)?;          // no key needed
assert!(report.is_valid);

let chain = accept_file(path, &registry, &policy, &store)?;   // or verify_file_chain
let rules = open_current_rules(&chain, &RecipientKeys::from(&auditor))?;   // kind comes from the identity
```

### Edge Cases

- **Zero recipients.** `Confidential { recipients: &[] }` is rejected
  at the API boundary. A confidential file nobody can read would only
  be a public file with extra steps.
- **Duplicate recipients.** Deduplicated by public key or by
  `(provider_id, key_ref)` before wrapping.
- **Unknown stanza kinds.** Skipped. If nothing is openable, reading
  fails with `NotARecipient`; verification is unaffected.
- **Conflict detection (`conflict.rs`).** It compares `rules_hash` to
  decide whether two branches hold the same rules. In confidential
  mode, equal plaintexts produce different commitments, because the
  DEKs and nonces differ. Only a recipient can establish equality, by
  decrypting. Divergence reports must say "content unknown" rather
  than "content differs".
- **DSSE, SLSA, and attestation payloads** that embed `rules_hash`
  carry the v3 commitment. Their consumers must not treat it as a
  plaintext hash.
- **Mixed modes across versions.** These are allowed. Each entry's
  signed `rules_mode` records its own mode. A public v1 followed by a
  confidential v2 is valid, but v1's plaintext stays public in any
  copy of the file made before v2. `AcceptPolicy` with
  `AllVersions` exists for deployments that must forbid this.

## Rationale and Alternatives

### Why encrypt-then-sign?

The author signs a commitment to the bytes on disk. Payload binding
then needs no secret, and every verifier can do it. That includes
auditors, transparency-log monitors, and `aion archive verify`. The
reverse order (sign the plaintext, then encrypt) recreates
GHSA-7625-44v8-v62f for every non-recipient.

### Why a key commitment?

ChaCha20-Poly1305 is not key-committing. A malicious author could wrap
different DEKs for different recipients, so that one ciphertext
decrypts to different plaintexts for each of them: the "invisible
salamanders" attack. The signed `dek_commitment` forces every
recipient to use the same DEK; the argument is under "Why
`dek_commitment` is a key commitment" in the key schedule.

An earlier draft also stored a DEK-keyed `plaintext_commitment`. It
was removed after crypto review, because it added nothing. With the
key committed, the AEAD tag already authenticates the plaintext for
every DEK holder, recipients and selective-disclosure parties alike.

### Why HPKE rather than raw X25519?

RFC 9180 is a reviewed, standardized KEM-plus-AEAD construction with
test vectors. Writing our own ECDH-plus-KDF composition violates
`.claude/rules/crypto.md`.

### Alternatives Considered

1. **Keep v2 and point users at whole-file encryption.** This is the
   status quo after #196. It works for storage, but verifiers cannot
   check signatures without the key. That defeats third-party
   auditability, the product's core claim. It remains the
   recommendation until this RFC ships.
2. **Embed an age payload (`age` 0.12, MIT/Apache).** This is the
   strongest alternative. age is well specified, has X25519 and
   plugin recipients, and its header MAC gives key commitment.
   Rejected for Phase A for three reasons:
   - It puts a second untrusted-input format parser into the trust
     base.
   - KMS integration goes through age's plugin protocol, which spawns
     external binaries.
   - age's per-file key is not bound to our signed context (`file_id`,
     `author_id`, version). Selective disclosure would depend on age
     internals rather than a documented per-version key.

   This is revisited in the Unresolved Questions.
3. **Derive X25519 keys from authors' Ed25519 signing keys.**
   Rejected: reusing one key across signing and encryption protocols
   is discouraged, it couples confidentiality to signing-key rotation,
   and it forces readers to be signers.
4. **Shared symmetric key or passphrase only.** Rejected as the
   primary mechanism: it doesn't scale to multiple parties and offers
   no per-recipient revocation. A passphrase stanza (Argon2id, already
   a dependency) is a possible future stanza kind.
5. **Real key, but keep `rules_hash = BLAKE3(plaintext)`.** Rejected.
   It keeps offline guess confirmation, and verifiers without the key
   still can't bind the payload.

## Security Considerations

### Threat Model

Adversaries:

- **(a)** A reader of the file who is not a recipient: storage,
  transit, a log mirror.
- **(b)** A modifier of the file without signing keys.
- **(c)** A malicious author: holds a valid signing key, crafts
  envelopes.
- **(d)** A malicious recipient.
- **(e)** A compromised KMS provider.

### Security Guarantees

- **Against (a):** confidentiality of the framed plaintext under
  ChaCha20-Poly1305 with a 256-bit per-version key. There is no
  offline guess confirmation, because the commitments are keyed or
  computed over ciphertext. Against a future quantum adversary
  holding today's ciphertext, the DEK stays secret only if **every**
  stanza is X-Wing (kind `0x03`): one X25519 stanza wraps the same DEK
  under a classical-only KEM.
- **Against (b):** any change to the rules section, a stanza, or the
  envelope changes `rules_commitment` and fails key-free
  verification. So does moving a signed entry into another file or
  mode, because `file_id` and the mode are in the signed message.
  Stanza transplant also fails the HPKE `info`/`aad` binding.
- **Against (c):**
  - Every recipient who can open a stanza gets the same plaintext
    (key commitment).
  - The author *can* include a stanza that does not open, or that
    wraps a different DEK. Only the affected recipient detects that,
    as `RulesUnopenable` against a stanza listing their own key;
    other parties cannot.
  - Copying another author's section fails for recipients, because
    `author_id` is in `ctx`.
  - The author can still sign garbage. Authorship is trusted for
    content, as in v2.
- **Against (d):** a recipient can read and disclose, which cannot be
  prevented. They cannot produce a new signed version without a
  registered signing key.
- **Against (e):** the provider sees the DEK for versions it wraps.
  It cannot make recipients accept a different DEK.

### What This Does Not Guarantee

- Metadata confidentiality (see [What remains visible](#what-remains-visible)).
- Forward secrecy, or revocation of past access.
- Post-quantum confidentiality for a version that has any X25519
  (`0x01`) stanza, or any external (`0x02`) stanza whose provider is
  classical.
- Post-quantum integrity. Signatures stay Ed25519 unless RFC-0027
  hybrid signatures are used.
- An independent audit of the KEM code. `ml-kem` and `x-wing` state
  that they have not been independently audited. The hybrid limits
  the damage: a flaw in one half still leaves the other, but it does
  not remove the risk.
- Protection of plaintext once a recipient has decrypted it.

### Attack Vectors to Test

- Envelope parser on adversary bytes: bounded counts and lengths,
  no panics. A new fuzz target and a Tier-1 property.
- A stanza moved between files, versions, or envelopes.
- Two stanzas wrapping different DEKs (must fail `dek_commitment`).
- Non-zero padding and an oversized `plaintext_len`.
- A v2 signature presented as v3 (domain separation).
- A signed entry and section moved under a header with a different
  `file_id`, or with flags bit 0 flipped (must fail key-free verify).
- Another author's confidential section re-signed verbatim (must fail
  open for every recipient).
- Reordered or duplicated stanzas, and total stanza bytes over the
  cap.
- Timing or error-shape differences among a commitment mismatch, an
  AEAD failure, and bad padding behind a matching stanza. All three
  must surface as the same `RulesUnopenable`. `NotARecipient` is
  distinct by design, because recipient identities are public.

### SHA-256 and SHA-3 usage (crypto-rule exception)

`.claude/rules/crypto.md` allows non-BLAKE3 hashes only at named
boundaries. Phase A adds an exception entry, because the existing
`crypto::derive_key` already uses HKDF-SHA256. Its scope:

- **Where:** SHA-256 appears only as the hash function inside
  HKDF-SHA256 (v3 `K_enc`, and the existing v2 rules-key derivation in
  `operations::{encrypt_rules, decrypt_rules}`) and
  inside HPKE's DHKEM(X25519, HKDF-SHA256) and HKDF-SHA256 KDF.
- **SHA-3 (Phase B):** SHA3-256, SHAKE-128/256 and TurboSHAKE appear
  only inside ML-KEM-768 and the X-Wing KEM (`ml-kem`, `x-wing`, and
  `hpke`'s X-Wing binding), where the standards mandate them. The same
  rules apply: they derive keys and shared secrets only, and no SHA-3
  output is stored, signed, or compared by aion-context.
- **Key derivation only:** it derives keys and nothing else. No
  SHA-256 output is ever stored, signed, or compared. Every
  commitment and every hash compared in an accept/reject decision is
  BLAKE3: `rules_commitment`, `dek_commitment`, the version chain, and
  the integrity hash.
- **How it can fail:** a SHA-256 or SHA-3 weakness could weaken the
  secrecy of derived keys, which affects confidentiality. It could also cause a
  derived key to be wrong, which shows up as a failed AEAD or HPKE
  open, an opaque `RulesUnopenable`. It cannot turn a forgery
  into an accept, because acceptance is decided by Ed25519 signatures
  over BLAKE3 commitments.

The exception text in `crypto.md` mirrors the OCI entry's form:
transport and key-derivation boundary only, gating no comparison.

## Performance Impact

- **Verify:** one BLAKE3 pass over the rules section. Cheaper than
  the 1.0.1 decrypt-and-hash.
- **Commit:** one DEK, one AEAD pass, and one HPKE seal per recipient:
  an X25519 scalar multiplication for kind `0x01`, and an ML-KEM-768
  encapsulation plus an X25519 multiplication for kind `0x03` (to be
  benchmarked in `benches/crypto_benchmarks.rs`). Plus one provider
  call per external wrapper.
- **Space:** 79 bytes of envelope overhead (magic, suite, DEK
  commitment, stanza count, nonce, length, tag), plus 8 bytes of
  framing, plus 115 bytes per X25519 stanza or 2,387 bytes per
  X-Wing stanza, plus Padmé padding (≤ about 12%).

## Testing Strategy

### Property-Based Tests (Hegel, Tier-2 rows to add)

- Public and confidential seal → `verify_file` (key-free) → `open`
  round-trip, for any rules and 1–8 recipients of either KEM kind,
  mixed.
- Any single-byte change anywhere in the rules section ⇒ `verify_file`
  rejects.
- Every recipient decrypts identical bytes. Forcing a different DEK
  into any stanza ⇒ open fails on `dek_commitment`.
- A stanza transplanted to another file or version ⇒ open fails.
- No key ⇒ `show_current_rules` returns `RecipientKeyRequired` and
  never plaintext.
- Padmé framing round-trips, and malformed framing rejects.
- The disclosed DEK opens exactly that version and no other.
- A v2 file read by the v3 reader verifies exactly as under 1.0.1.
- A signed entry moved to another `file_id` or mode ⇒ `verify_file`
  rejects (key-free).
- A confidential section re-signed by another author ⇒ every
  recipient's open fails.
- Writers emit stanzas in canonical order. A permuted or duplicated
  stanza list ⇒ the parser rejects.
- `AcceptPolicy { require_confidential: Head }` rejects a public head,
  and `AllVersions` rejects a chain with any public entry.
  `min_format_version = 3` rejects v2.
- Flipping any entry's stored `rules_mode`, historical or head ⇒ that
  entry's signature fails. Flipping header flags bit 0 alone ⇒ the
  head cross-check fails.
- Two stanzas for one recipient identity, even with different `enc`
  or blob bytes ⇒ the parser rejects. A re-wrap to the same recipient
  set yields the same stanza order.
- `open_rules_section` and `disclose_version_key` accept only a
  `VerifiedEntry`. A test that tries to build one from raw fields must
  fail to compile (`trybuild`).
- `accept_file` store semantics, as a Hegel model test against a
  `HashMap` reference implementation, covering every decision-table
  row:
  - an identical re-verify ⇒ `AcceptedIdempotent`;
  - the same version with a different hash ⇒ `Equivocation`;
  - a lower version ⇒ `Replay`;
  - a different genesis, pinned or not ⇒ `FileIdConflict`;
  - a pinned record ⇒ accepts its genesis;
  - an invalid file never advances the store;
  - a store error ⇒ `StoreUnavailable`, fail closed.
- The same version re-signed with a different `rules_mode` ⇒ a
  different v3 version hash ⇒ `Equivocation`.
- An identity not listed ⇒ `NotARecipient`. A listed identity with a
  corrupted stanza ⇒ `RulesUnopenable`. That includes a corrupted
  X-Wing `enc` (ML-KEM's implicit rejection yields a pseudorandom
  secret, so the failure surfaces at the AEAD) and a corrupted X25519
  `enc`: both must give the same `RulesUnopenable`.
- A `0x01` or `0x03` stanza of the wrong body length ⇒ the envelope
  parser rejects before any KEM call.
- An archived section opened with `open_rules_section` against the
  wrong entry, or with another version's DEK ⇒ rejected.
- Store: after accepting a multi-author chain at v5, presenting its v3
  prefix ⇒ `version_replay`, whoever authored v3. A higher-versioned
  fork that diverges at or below v5 ⇒ `version_equivocation`. A
  different genesis under the same `file_id` ⇒ `file_id_conflict`.
- After `accept_file` returns, replacing the file on disk does not
  change what `open_current_rules(&chain, …)` decrypts.

### Unit and Known-Answer Tests

- HPKE RFC 9180 vectors for both KEMs, via the crate's own vectors.
- A golden stanza per kind: fixed recipient seed, fixed DEK, fixed
  `ctx`, and fixed encapsulation randomness (test-only RNG) produce
  exact bytes. This pins the X-Wing draft encoding (see Draft
  pinning).
- Golden v3 files, public and confidential, checked into
  `tests/fixtures/`.

### Fuzzing

- `fuzz_confidential_envelope`: arbitrary envelope bytes into the
  parser and opener.
- Extend `fuzz_file_parser` with v3 headers.

## Implementation Plan

### Phase A: Format v3, public mode, key-free commitment

- Parser and serializer for v3, with v2 read support kept.
- The rules commitment, and the v3 canonical version message with
  `file_id`, format version, and mode.
- The new `\0`-terminated signature domains, the framing, and the
  Padmé decoder.
- Per-entry `rules_mode` in `VersionEntry.reserved[0]`, and the header
  flag cross-check.
- The `VerifiedChain` / `VerifiedEntry` typestate, and
  `verify_file_chain`.
- `accept_file` with `AcceptPolicy` (`min_format_version`,
  `require_confidential` `Head` / `AllVersions`), the mandatory
  `AcceptedVersionStore` trait (`pin` and atomic
  `check_and_advance`), `StoreDecision`, the `VersionRejected` /
  `StoreUnavailable` variants, a file-backed store, and
  `aion accept --state` / `--pin`.
- The v3 version hash over the v3 canonical message, so `rules_mode`
  is bound into parent links.
- The SHA-256 exception entry in `.claude/rules/crypto.md`.
- `RulesProtection::Public` only. `--public` replaces
  `--no-encryption`.
- No new dependencies. This closes Problem Statement item 3 for every
  v3 file: the signature now commits to the stored bytes.
- *Implementation note:* `fuzz_verify_chain` fuzzes
  `VerifiedChain::from_bytes` and `unframe_rules` from signed v3 seeds
  in `fuzz/seeds/fuzz_verify_chain/`. Passing that directory to
  `fuzz_file_parser` as an extra corpus covers v3 headers there too.

### Phase B: Confidential mode with X25519 and X-Wing recipients

Four PRs, each reviewed by `crypto-auditor` and `api-reviewer`:

- **B1, envelope codec.** Parse and serialize the envelope and
  stanzas with every bound, canonical order, and identity
  de-duplication above. No new dependency. A `fuzz_confidential_envelope`
  target and Tier-1 parser properties.
  - *Implementation note:* the `envelope` module. `Envelope::parse`
    is zero-copy and accepts only the canonical encoding, so
    `parse(b)?.to_bytes() == b`. The writer-side encoder is
    crate-internal and re-parses its own output.
  - A parsed envelope is structural only and unauthenticated. Its bytes
    are trusted after the signature and rules commitment verify.
  - `parse` bounds `ct_len` by the input length and the 24-byte minimum.
    B3 applies the reader's rules-size limit before any AEAD work.
  - An unknown content suite is rejected as `InvalidFormat`, not
    skipped, because nothing in it can be opened. A new suite needs
    its own RFC.
- **B2, key schedule and stanzas.** DEK, `K_enc`, `dek_commitment`, the
  content AEAD, and HPKE seal/open for kinds `0x01` and `0x03`, with
  the known-answer tests above.
  - *Implementation note:* the crate-private `confidential` module.
    HPKE randomness is drawn with `crypto::fill_os_entropy` and served
    from a buffer: 32 bytes per X25519 encapsulation, 64 per X-Wing.
    If `hpke` asks for more, the seal is discarded with
    `EntropyUnavailable`.
  - Opening failures are one `DecryptionFailed` until B3 splits
    `NotARecipient` from `RulesUnopenable`.
  - `hkdf` and `sha2` were bumped to `hpke`'s versions, leaving one of
    each in the build.
- **B3, library read and write.** `RulesProtection::Confidential`,
  `Recipient`, `RecipientKeys`, the `NotARecipient` /
  `RulesUnopenable` split, `open_current_rules` /
  `open_rules_section` for confidential sections, and
  `disclose_version_key`.
  - *Implementation note:* `Recipient` lives in `format`;
    `EncryptionKem`, `EncryptionIdentity` and `VersionKey` in the now
    public `confidential` module, whose sealing and opening functions
    stay crate-internal.
  - The disclosed key is opened with `open_rules_section_with_key`,
    a separate function rather than an overload of
    `open_rules_section`.
  - `VerifiedChain::head_recipients` serves `--keep-recipients`.
  - Writers refuse framed rules over 16 MiB
    (`format::MAX_CONFIDENTIAL_RULES_LEN`); readers check the same
    bound before decrypting. `verify_file` parses a confidential head's
    envelope key-free.
  - Empty recipients are `AionError::NoRecipients`; confidential
    protection on a format-v2 file is
    `AionError::ConfidentialityUnsupported`. `disclose_version_key`
    takes `(section, entry, keys)`, matching the other openers.
- **B4, keystore and CLI.** The encryption-identity key kind (X-Wing
  default), `aion key generate --encryption`, `--recipient`,
  `--keep-recipients`, and `--identity`.

Dependencies (B2):

- **`hpke = "=0.14.1"`** (MIT/Apache-2.0), with default features off
  and only `alloc`, `x25519`, `mlkem`, `chacha`, and `hkdfsha2`
  enabled. Randomness comes from the crate's existing OS RNG path, not
  `hpke`'s `getrandom` feature.
  - These pull in `x25519-dalek` 3.0 (BSD-3-Clause), `ml-kem` 0.3,
    `x-wing` 0.1, `sha3` 0.12, `shake` 0.1, `turboshake` 0.7, `hkdf`
    0.13 and `sha2` 0.11. All are RustCrypto or dalek crates on the
    license allowlist; the exact closure is in the B2 SBOM diff.
  - The crate itself is on `hkdf` 0.12 and `sha2` 0.10. B2 either
    accepts duplicate versions or bumps ours, and a crypto-dependency
    major bump goes through the full fuzz suite.
  - Before merge: `cargo deny`, `cargo audit`, the SBOM diff, and the
    fuzz suite, per `supply-chain.md`.
- `hpke`'s HKDF and DHKEM use falls under the SHA-256 exception that
  Phase A added. B2 extends the `crypto.md` entry to the SHA-3 family
  inside ML-KEM and X-Wing.
- `hpke`, `ml-kem` and `x-wing` require Rust 1.85. The crate already
  declares 1.87 (#206).

### Phase C: External wrappers and migration

- The `DekWrapper` / `DekUnwrapper` traits and stanza kind `0x02`,
  plus `aion migrate` with a `MigratedFrom` audit record.

### Phase D (conditional on Unresolved Question 3)

- Recipient keys pinned in the `KeyRegistry`.

## Unresolved Questions

1. **age instead of a native envelope?** *Resolved 2026-10-23: native
   HPKE envelope.* age 0.12.1 is built on an older crypto stack
   (`chacha20poly1305` 0.10, `x25519-dalek` 2, `rand` 0.8, `hkdf` 0.12)
   that we would ship alongside our own, adds i18n dependencies, has
   no built-in post-quantum recipient, and does not bind its file key
   to our signed `ctx`. The native envelope keeps one crypto stack and
   the documented per-version key.
2. **Recipient-key privacy.** Storing `recipient_pk` in full lets
   committers re-wrap without a side channel, but reveals who can
   read. An anonymous mode would store only `enc` and make readers
   trial-decrypt. Is that worth the extra CLI state?
3. **Should recipients be authorized by the registry?** Today any
   signer chooses the recipient set. Pinning recipient keys per
   policy in the `KeyRegistry` would let verifiers reject a version
   that adds an unauthorized reader. That is a registry format change.
4. **Commit-message confidentiality.** Messages often describe the
   change ("raise refund limit to 5000"). Encrypt them in the same
   envelope? The cost is that `show history` needs a key.
5. **Padding default.** Should Padmé be mandatory, optional, or
   replaced with fixed buckets?
6. **Is `RulesProtection` with no default too strict?** It forces
   every existing caller to choose a mode at the 2.0 upgrade.
7. **Do enforcement receipts (RFC-0036) need a confidential-mode
   policy identity** that avoids the public commitment, so a receipt
   doesn't make two versions linkable?
8. **Post-quantum confidentiality.** *Resolved 2026-10-23: both, X-Wing
   by default.* Phase B ships X25519 (kind `0x01`) and X-Wing (kind
   `0x03`) stanzas together, and new encryption identities are X-Wing
   unless the user asks for X25519. X-Wing is a stanza kind rather
   than an envelope suite, because the envelope `suite` byte selects
   the content key schedule, which is the same for both KEMs. This
   gives post-quantum **confidentiality** only, in the spirit of
   RFC-0027: version signatures stay Ed25519 unless RFC-0027 hybrid
   signatures are used. Draft risk is handled by pinning and
   known-answer tests (see Draft pinning).

## References

- RFC 9180, Hybrid Public Key Encryption.
- RFC 8439, ChaCha20 and Poly1305.
- Albertini et al., "How to Abuse and Fix Authenticated Encryption
  Without Key Commitment" (USENIX Security 2022).
- Dodis et al., "Fast Message Franking: From Invisible Salamanders to
  Encryptment" (CRYPTO 2018).
- Nikitin et al., "Reducing Metadata Leakage from Encrypted Files and
  Communication with PURBs" (PETS 2019): Padmé.
- age v1 format specification (C2SP).
- GHSA-7625-44v8-v62f; RFC-0003 errata; `book/src/architecture/crypto.md`.

## Appendix

### Terminology

- **DEK:** data-encryption key. 32 random bytes per version.
- **Stanza:** one recipient's wrapping of the DEK.
- **Rules commitment:** a domain-separated BLAKE3 hash of the stored
  rules section, signed via `VersionEntry.rules_hash`.
- **Key commitment:** `dek_commitment`, which binds every recipient
  to one DEK.
- **X-Wing:** the hybrid KEM ML-KEM-768 + X25519 (IETF draft), used
  by stanza kind `0x03`.
- **ctx:** `file_id ‖ author_id ‖ version`, little-endian. The binding
  context used in the HKDF salt, the AEAD aad, the HPKE `info`, and
  the external-wrapper context.

### Review history

- **2026-10-23, `crypto-auditor`, round 1: BLOCK.** Findings and how
  this draft resolves them:
  - B1: the signed message lacked `file_id` and mode. Added to the v3
    canonical message.
  - B2: cross-author section plagiarism. Fixed by adding `author_id`
    to `ctx`.
  - S1: SHA-256 exception. Added.
  - S2: `plaintext_commitment` was redundant. Removed.
  - S3: key-commitment argument. Documented, and the "provably" claim
    corrected.
  - S4: downgrade and rollback. Added `VerifyPolicy`.
  - S5: stanza caps, canonical order, and opaque errors. Added.
  - S6: `\0` on every v3 domain, and the book's domain table
    corrected.
  - N1–N4: incorporated as notes.
- **2026-10-23, `crypto-auditor`, round 2: BLOCK.** Round 1's S1, S4
  and S5 were judged only partially resolved. New findings and their
  resolutions:
  - N1 (blocker): the per-version mode had no stored source. Now
    `VersionEntry.reserved[0] = rules_mode`, signed per entry. Header
    flags bit 0 mirrors the head, and the cross-check is defined
    against stored values.
  - N2: the SHA-256 exception contradicted a SHA-256-based key
    commitment. `dek_commitment` is now BLAKE3 `derive_key`; the
    exception covers key derivation only and lands in Phase A.
  - N3: canonical order is now bytewise `kind ‖ body`, and duplicates
    are rejected by recipient identity, not body bytes.
  - N4: added `open_rules_section` for archived historical sections,
    and scoped `disclose_version_key` to the current version.
  - N5: registry verification paths use the v3 message.
  - N6: the CLI requires `--keep-recipients` explicitly, and refuses
    it when the previous version had external stanzas.
  - N7: the `derive_key` argument order is stated.
  - S4: now specifies `Head` versus `AllVersions`, and a
    caller-provided `AcceptedVersionStore`.
- **2026-10-23, `crypto-auditor`, round 3: BLOCK.** Round 2's N1–N3,
  N5–N7 and round 1's S1 and S5 were judged resolved. N4 and S4 were
  partial. Findings and their resolutions:
  - B1: `open_rules_section` trusted an unverified entry. Every
    opening function now takes a `VerifiedEntry`, a typestate
    obtainable only from a verified chain, so there is no raw
    `file_id` parameter.
  - S1: the replay store key lacked `file_id`, rejected idempotent
    re-verification, and had no update or failure rules. It is now
    keyed `(file_id, author)` and stores `(version, head hash)`:
    - equal version and hash accepts;
    - equal version with a different hash rejects as equivocation;
    - a lower version rejects as rollback;
    - the store advances only after full verification, through an
      atomic `check_and_advance`;
    - a store error fails closed.
  - S2: replay was undefended by default. Split into a stateless
    `verify_file` (integrity) and `accept_file` (acceptance), where
    the store is mandatory.
  - Notes:
    - the SHA-256 failure wording now admits the confidentiality
      impact;
    - the CLI rules cover `--keep-recipients` after a public version
      or with unknown stanza kinds;
    - kind `0x02` inner lengths must sum to `body_len`;
    - `NotARecipient` and `RulesUnopenable` are now separate;
    - every signing and verification path is enumerated for the v3
      message.
- **2026-10-23, `crypto-auditor`, round 4: BLOCK.** B1 (round 3), S2,
  the CLI items, the `0x02` lengths and the error split were judged
  resolved. Findings and their resolutions:
  - Blocker: the store key `(file_id, head author)` allowed rollback
    across authors, and higher-versioned forks. It is now keyed by
    `file_id` alone, with value `(genesis_hash, head_version,
    head_hash)`. Advancing requires `hash(P[stored.head_version]) ==
    stored.head_hash` (ancestry). A different genesis is rejected as
    `file_id_conflict`. Added guidance on `file_id` squatting and
    `store.pin`.
  - TOCTOU: `VerifiedChain` owns its verified bytes, and openers never
    re-read the path.
  - The test list contradicted the error split; corrected.
  - Notes: stale `VerifyPolicy`, example, and key text fixed;
    `--keep-recipients` reads from the `VerifiedChain`; the file store
    fsyncs the temp file and the directory.
- **2026-10-23, `crypto-auditor`, round 5: PASS** (0 blockers) for
  draft → proposed. The non-blocking items, now addressed:
  - `pin` is defined, with a decision-table row and a Phase A item.
  - The rejection surface is named: `StoreDecision`, `VersionRejected`
    with its bounded reasons, and `StoreUnavailable`.
  - The `ChainSummary` contract is specified: `hash_at` is called
    inside the CAS, its domain is guaranteed by row order, and it
    returns an error instead of panicking.
  - The v3 version hash covers `rules_mode`, so a mode re-sign counts
    as equivocation.
  - Squatting is stated to be a denial of service, not a forgery.
  - `show_current_rules` reads and verifies once, from one buffer.
- **2026-10-23, owner decisions before Phase B.** Unresolved Question 1:
  native HPKE envelope, not age. Question 8: X25519 and X-Wing stanzas
  both ship in Phase B, X-Wing by default. Amendment: X-Wing is stanza
  kind `0x03`; the stanza-total cap is 160 KiB; `hpke` is pinned with
  known-answer tests; the SHA-3 exception is added; Phase B is split
  into B1–B4.
- **2026-10-23, `crypto-auditor`, Phase B amendment: PASS, conditional**
  on four must-fix items, all addressed in this revision:
  - M1: identity is `(kind, recipient_pk)`, and exact body lengths
    for `0x01` (112) and `0x03` (2,384) are checked before any KEM
    work.
  - M2: identity records are `(kind, seed, recipient_pk)`, with one
    seed per kind, X-Wing seeds loaded raw (not `derive_keypair`), and
    the seed held in `Zeroizing`.
  - M3: the recipient-key binding is justified per KEM; X-Wing has no
    KEM context.
  - M4: the SHA-3 entry is in `.claude/rules/crypto.md` now.
  - Should-fix: owned `Recipient` types and an X-Wing example; ml-kem
    and x-wing are disclosed as unaudited, and the pin and RUSTSEC
    policy are stated; the CLI warning covers external wrappers;
    implicit-rejection and wrong-length tests; post-quantum applies to
    confidentiality only.
