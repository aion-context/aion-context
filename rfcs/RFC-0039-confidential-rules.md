# RFC 0039: Confidential Rules (Format v3)

- **Author:** copyleftdev
- **Status:** DRAFT
- **Created:** 2026-10-23
- **Updated:** 2026-10-23
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
- All recipients of a version provably decrypt the same plaintext
  (key commitment).
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
                       suite, dek_commitment, plaintext_commitment,
                       recipient stanzas (DEK wrapped per recipient),
                       nonce, ChaCha20-Poly1305(K_enc, framed plaintext)
                    }
```

A verifier hashes the section and compares it with the signed
commitment, in either mode and with no key. A recipient additionally:

1. unwraps the DEK,
2. checks it against `dek_commitment`,
3. decrypts,
4. checks the plaintext against `plaintext_commitment`.

### Detailed Design

#### Header

- `version = 3`.
- `flags` bit 0 is redefined as **CONFIDENTIAL** for v3 files (1 =
  confidential envelope, 0 = public). Bits 1–15 stay reserved and
  must be zero.
- v3 readers interpret bit 0 by `version`. The v2 "Encrypted" bit
  keeps its v2 meaning: obfuscated, not confidential.
- Every other header field is unchanged.

#### Rules commitment (replaces the meaning of `rules_hash` in v3)

```
rules_commitment = BLAKE3(RULES_COMMIT_DOMAIN ‖ u8 mode ‖ section_bytes)
RULES_COMMIT_DOMAIN = b"AION_V3_RULES_COMMIT_V1\0"
mode = 0x00 (public) | 0x01 (confidential)
```

The commitment is stored in `VersionEntry.rules_hash`. The 152-byte
layout is unchanged, only the field's definition changes. It is also
mirrored in the header's `current_hash` / `root_hash`, as in v2.

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
            plaintext_commitment[32]
            stanza_count: u16      (1..=64)
            stanzas[stanza_count]
            nonce[12]
            ct_len: u64            (≤ the reader's rules-size limit + framing + 16; checked before allocation)
            ciphertext[ct_len]     (ChaCha20-Poly1305 output, tag included)

stanza  := kind: u8
           body_len: u16           (≤ 4096)
           body[body_len]
```

**Suite 0x01 key schedule.** The DEK is 32 random bytes from
`crypto::fill_os_entropy`, fresh for every version. All derivations
use the existing `crypto::derive_key` (HKDF-SHA256) with
`salt = file_id_le ‖ version_le`:

| Output | HKDF `info` |
|---|---|
| `K_enc` (content key) | `AION_V3_RULES_KEY_V1` |
| `K_pc` (plaintext-commitment key) | `AION_V3_PLAINTEXT_COMMIT_KEY_V1` |
| `dek_commitment` | `AION_V3_DEK_COMMIT_V1` |

```
plaintext_commitment = BLAKE3::keyed_hash(K_pc, framed)
ciphertext = ChaCha20-Poly1305(K_enc, nonce, framed,
             aad = b"AION_V3_RULES_AAD_V1" ‖ file_id_le ‖ version_le)
```

**Stanza kinds.**

| kind | Name | Body |
|---|---|---|
| `0x01` | HPKE X25519 recipient | `recipient_pk[32] ‖ enc[32] ‖ wrapped_dek[48]` |
| `0x02` | External wrapper | `provider_id_len u8 ‖ provider_id ‖ key_ref_len u16 ‖ key_ref ‖ blob_len u16 ‖ blob` |
| `0x03`–`0xFF` | Reserved | Readers skip unknown kinds. A file with no stanza the reader can open fails with `RecipientKeyRequired`. |

**HPKE (kind `0x01`).**

- **Mode:** RFC 9180 base mode, with DHKEM(X25519, HKDF-SHA256),
  HKDF-SHA256, and ChaCha20-Poly1305.
- **Inputs:** `info = b"AION_V3_DEK_WRAP_V1" ‖ file_id_le ‖ version_le`
  and `aad = dek_commitment`.
- **Why these inputs:** binding `info` to the file and version stops a
  stanza being transplanted into another file. Binding `aad` stops it
  being paired with a different DEK commitment.
- **Recipient key:** `recipient_pk` is stored in full. A committer can
  then re-wrap the next version for the same recipient set without
  out-of-band key distribution. The cost is that recipient keys are
  visible; see the Unresolved Questions.

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

`context = b"AION_V3_DEK_WRAP_V1" ‖ file_id_le ‖ version_le ‖
dek_commitment` is passed as KMS encryption context or AAD where the
provider supports it.

The core always checks the unwrapped DEK against `dek_commitment`
before using it. A provider bug cannot cause plaintext divergence.

#### Signatures

v3 version signatures use a new domain,
`AION_V3_VERSION_SIGNATURE_V1`, over the same canonical field layout
as v2. The new domain separates v2 and v3 signed messages, even
though a v2 `rules_hash` and a v3 `rules_commitment` can never
collide anyway: they come from different BLAKE3 inputs.

RFC-0021 attestations get `AION_V3_ATTESTATION_V1` in the same way.

#### Verification (key-free)

For v3, `verify_file` adds one check to the v2 set, and needs no key:

- `hash_chain_valid` additionally requires
  `rules_commitment(stored section) == latest.rules_hash`.

This is the structural form of the 1.0.1 fix. Public-mode files also
validate the framing.

#### Reading

| Function | Behavior |
|---|---|
| `show_current_rules(path)` | Public mode: returns the plaintext. Confidential mode: `Err(AionError::RecipientKeyRequired)` (new variant; `AionError` is `#[non_exhaustive]`). |
| `open_current_rules(path, &RecipientKeys)` | **New.** Tries each held identity (X25519 secret keys and/or `&dyn DekUnwrapper`) against the stanzas. Checks `dek_commitment`, decrypts, checks `plaintext_commitment` and framing, and returns `Zeroizing<Vec<u8>>`. |
| `disclose_version_key(path, &RecipientKeys)` | **New.** Returns the version's DEK for selective disclosure. A third party with that DEK, and nothing else, can run `open_current_rules` for that version only. |

#### Writing

`InitOptions` / `CommitOptions` / `ExternalCommitOptions` gain a
`protection: RulesProtection<'a>` field:

```rust
pub enum RulesProtection<'a> {
    Public,
    Confidential { recipients: &'a [Recipient<'a>] },   // non-empty
}
pub enum Recipient<'a> {
    X25519([u8; 32]),
    External(&'a dyn DekWrapper),
}
```

There is **no default**. Callers name the mode. This is a breaking
change, and the next release is already 2.0.0.

`commit_version` never needs the previous version's plaintext. The
CLI defaults a commit's recipient set to the previous version's
`0x01` stanzas, and the operator can override it.

#### CLI

- `aion init` / `aion commit` require exactly one of `--public` or
  one or more `--recipient <x25519-pubkey-file | kms:<provider>:<key>>`.
  `--no-encryption` becomes an alias for `--public` with a
  deprecation note.
- `aion key generate --encryption` creates an X25519 identity in the
  keystore. This is a separate key kind from Ed25519 signing keys.
- `aion show <FILE> rules --identity <key-id>` decrypts. Without an
  identity, a confidential file reports `RecipientKeyRequired` and
  exit code 1.
- `aion verify` is unchanged and key-free.

#### What remains visible

In confidential mode an observer still sees:

- the recipient public keys and the count of external wrappers;
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
let recipients = [Recipient::X25519(auditor_pk), Recipient::External(&kms)];
init_file(path, rules, &InitOptions {
    author_id, signing_key: &key, message: "v1", timestamp: None,
    protection: RulesProtection::Confidential { recipients: &recipients },
})?;

let report = verify_file(path, &registry)?;          // no key needed
assert!(report.is_valid);

let rules = open_current_rules(path, &RecipientKeys::x25519(&auditor_sk))?;
```

### Edge Cases

- **Zero recipients.** `Confidential { recipients: &[] }` is rejected
  at the API boundary. A confidential file nobody can read would only
  be a public file with extra steps.
- **Duplicate recipients.** Deduplicated by public key or by
  `(provider_id, key_ref)` before wrapping.
- **Unknown stanza kinds.** Skipped. If nothing is openable, reading
  fails with `RecipientKeyRequired`; verification is unaffected.
- **Conflict detection (`conflict.rs`).** It compares `rules_hash` to
  decide whether two branches hold the same rules. In confidential
  mode, equal plaintexts produce different commitments, because the
  DEKs and nonces differ. Only a recipient can establish equality, by
  decrypting. Divergence reports must say "content unknown" rather
  than "content differs".
- **DSSE, SLSA, and attestation payloads** that embed `rules_hash`
  carry the v3 commitment. Their consumers must not treat it as a
  plaintext hash.
- **Mixed modes across versions.** These are allowed. A public v1
  followed by a confidential v2 is valid, but v1's plaintext stays
  public in any copy of the file made before v2.

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
recipient to use the same DEK.

The signed `plaintext_commitment`, keyed by a DEK-derived key, gives
recipients and selective-disclosure parties an explicit plaintext
check. It leaks nothing to anyone without the DEK.

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
   - age exposes no per-file key we can derive a disclosure-safe
     plaintext commitment from.

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
  computed over ciphertext.
- **Against (b):** any change to the rules section, a stanza, or the
  envelope changes `rules_commitment` and fails key-free
  verification. Stanza transplant fails HPKE `info`/`aad` binding.
- **Against (c):** all recipients decrypt the same plaintext (key
  commitment). The author can still sign garbage. Authorship is
  trusted for content, as in v2.
- **Against (d):** a recipient can read and disclose, which cannot be
  prevented. They cannot produce a new signed version without a
  registered signing key.
- **Against (e):** the provider sees the DEK for versions it wraps.
  It cannot make recipients accept a different DEK.

### What This Does Not Guarantee

- Metadata confidentiality (see [What remains visible](#what-remains-visible)).
- Forward secrecy, or revocation of past access.
- Protection of plaintext once a recipient has decrypted it.

### Attack Vectors to Test

- Envelope parser on adversary bytes: bounded counts and lengths,
  no panics. A new fuzz target and a Tier-1 property.
- A stanza moved between files, versions, or envelopes.
- Two stanzas wrapping different DEKs (must fail `dek_commitment`).
- Non-zero padding and an oversized `plaintext_len`.
- A v2 signature presented as v3 (domain separation).

## Performance Impact

- **Verify:** one BLAKE3 pass over the rules section. Cheaper than
  the 1.0.1 decrypt-and-hash.
- **Commit:** one DEK, one AEAD pass, and one HPKE seal per X25519
  recipient (dominated by one X25519 scalar multiplication each; to
  be benchmarked in `benches/crypto_benchmarks.rs`), plus one
  provider call per external wrapper.
- **Space:** 111 bytes of envelope overhead (magic, suite, two
  commitments, stanza count, nonce, length, tag), plus 8 bytes of
  framing, plus 115 bytes per X25519 stanza, plus Padmé padding
  (≤ about 12%).

## Testing Strategy

### Property-Based Tests (Hegel, Tier-2 rows to add)

- Public and confidential seal → `verify_file` (key-free) → `open`
  round-trip, for any rules and 1–8 recipients.
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

### Unit and Known-Answer Tests

- HPKE RFC 9180 vectors for the chosen suite, via the crate's own
  vectors.
- Golden v3 files, public and confidential, checked into
  `tests/fixtures/`.

### Fuzzing

- `fuzz_confidential_envelope`: arbitrary envelope bytes into the
  parser and opener.
- Extend `fuzz_file_parser` with v3 headers.

## Implementation Plan

### Phase A: Format v3, public mode, key-free commitment

- Parser and serializer for v3 (v2 read support kept), the rules
  commitment, the new signature domains, framing, and the Padmé
  decoder.
- `RulesProtection::Public` only. `--public` replaces
  `--no-encryption`.
- No new dependencies. This closes Problem Statement item 3 for every
  v3 file: the signature now commits to the stored bytes.

### Phase B: Confidential mode with X25519 recipients

- The envelope, HPKE stanzas, keystore X25519 key kind, and CLI
  `--recipient` / `--identity`.
- **New dependency `hpke` 0.14.x** (MIT/Apache-2.0; pulls in
  `x25519-dalek` 3.0, BSD-3-Clause; both on the allowlist). Before
  merge it goes through `cargo deny`, `cargo audit`, the SBOM diff,
  and the full fuzz suite, per `supply-chain.md`.
- `hpke` requires Rust 1.85. That is already the effective minimum
  through `ed25519-dalek` 3.0, `rand` 0.10, and `chacha20poly1305`
  0.11, but `Cargo.toml` still declares `rust-version = "1.70"`.
  Correct the declaration in this phase or earlier.

### Phase C: External wrappers and migration

- The `DekWrapper` / `DekUnwrapper` traits and stanza kind `0x02`,
  plus `aion migrate` with a `MigratedFrom` audit record.

### Phase D (conditional on Unresolved Question 3)

- Recipient keys pinned in the `KeyRegistry`.

## Unresolved Questions

1. **age instead of a native envelope?** age would remove our
   envelope parser and give mature plugin and KMS recipients. We
   would lose the DEK-derived plaintext commitment and selective
   disclosure, and gain a second format in the trust base. Decide
   before Phase B.
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
- **Plaintext commitment:** a BLAKE3 keyed hash of the framed
  plaintext under a DEK-derived key. It can be checked only by
  holders of the DEK.
