# RFC 0036: Enforcement Receipt

- **Author:** copyleftdev
- **Status:** DRAFT
- **Created:** 2026-07-20
- **Updated:** 2026-07-20
- **Depends on:** RFC-0012 (versioning), RFC-0014 (multi-signature), RFC-0019
  (audit trail), RFC-0021 (multisig attestation), RFC-0023 (DSSE envelope),
  RFC-0024 (SLSA provenance), RFC-0025 (transparency log), RFC-0028 (key
  rotation and revocation), RFC-0031 (JCS canonical JSON), RFC-0032 (release
  orchestration)

## Abstract

`aion-context` can today prove **"these policy bytes were validly
signed and verified"** end to end: a `.aion` file's rules are signed
(RFC-0005), wrapped in DSSE (RFC-0023), given SLSA-shaped provenance
(RFC-0024), logged in an append-only transparency log (RFC-0025), and
bundled into a single release seal (RFC-0032). None of that chain
proves that a runtime **applied** the policy to a real decision. This
RFC introduces the **Enforcement Receipt**: a DSSE-wrapped, in-toto
shaped predicate that binds a policy identity, a pinned key-registry
epoch, an enforcement decision, any approvals that gated it, and a
runtime identity, into one signed, replayable, logged artifact. It
reuses every existing primitive — DSSE envelopes, in-toto Statements,
JCS canonicalization, BLAKE3 subject digests, the key registry, the
transparency log — and introduces no new cryptography. The RFC's
central concern is not the wire format (which is a straightforward
composition) but the trust model: the entity being held accountable
for a decision is the same entity producing the evidence of that
decision, and a naive design lets a dishonest or compromised runtime
manufacture receipts it never earned.

## Motivation

### Problem Statement

Everything `aion-context` attests today answers a **provenance**
question: is this artifact / policy / manifest what it claims to be,
and who signed it? Nothing answers an **enforcement** question: did
a runtime actually gate a real action on this policy, and what did it
decide? In the NVIDIA/Microsoft room the follow-up question to "show
me your signed rulebook" is inevitably:

> "OK, the rulebook is authentic. Prove to me it was *applied* the
> last time someone tried to do the thing it prohibits."

Today the honest answer is "we log that out of band, in a system
`aion-context` knows nothing about, with no cryptographic binding to
the policy version or the trust context that was live at decision
time." A regulator or an internal auditor cannot reproduce which key
set, which policy version, and which approvals were in force when a
runtime said "allow" or "deny" — they can only trust the runtime's
own unsigned log line.

### Use Cases

- **Regulatory audit reproduction**: an auditor is handed a receipt
  and a copy of the `.aion` file plus the key registry snapshot. They
  must be able to answer, offline, "was this decision made under a
  policy version and key set that were legitimately trusted at that
  moment?" without asking the runtime operator to vouch for anything.
- **Post-incident forensics**: a policy was later found defective.
  The audit team needs every enforcement decision that cited that
  policy version, filtered by the decision (`allow` / `deny` /
  `degraded` / `fail_closed`), without depending on the runtime's own
  logs (which may have been altered by whoever caused the incident).
- **Human-in-the-loop approval gates**: a `deny`-by-default policy
  permits an `allow` only when a quorum of approvers signs off
  (RFC-0014 / RFC-0021 multisig). The receipt must show which
  approvals gated the decision, not just that "someone approved it."
- **Runtime attestation under key compromise**: a runtime's signing
  key is later found to be compromised. Every receipt it produced
  after the compromise date needs to be identifiable and
  distinguishable from receipts produced before — the same rotation
  and revocation machinery that protects policy-signing keys
  (RFC-0028) must protect enforcement-signing keys.
- **Independent witnessing**: a regulator does not want to rely
  solely on the runtime's own signature — they want a second,
  independently operated party to have co-signed or logged the
  receipt at (near) decision time, so a runtime cannot fabricate
  history after the fact.

### Goals

- A receipt cryptographically binds: policy identity (`file_id`,
  `policy_version`, `policy_author_id`), the key-registry epoch
  pinned at verification time, the enforcement decision, any gating
  approvals, the enforcing runtime's identity, and BLAKE3 digests of
  the decision inputs.
- Every receipt carries a per-runtime monotonic `receipt_version` for
  `(runtime_author_id, receipt_version)` replay defense, matching the
  crate's existing `(author, version)` discipline
  (`.claude/rules/distributed.md`).
- The runtime signs with its **own** registered, epoch-tracked key —
  distinct from the key(s) that signed the policy itself — so
  policy-issuing authority and enforcement-attesting authority are
  never the same trust root by construction.
- Receipts are DSSE-wrapped in-toto Statements (RFC-0023 / RFC-0024
  shape) with a distinct `payloadType`/`predicateType`, canonicalized
  via JCS (RFC-0031), so existing tooling that already speaks
  DSSE/in-toto needs zero new parsing code to at least extract
  subjects and predicate type.
- Receipts are loggable in the transparency log (RFC-0025) using a
  new `LogEntryKind`, giving them the same backdating resistance
  policy rotations already get.
- The design states plainly, in this document, what a receipt does
  and does not prove (see Security Considerations).
- Zero new crypto primitives, zero on-disk `.aion` format change.

### Non-Goals

- **Proving the runtime's internal decision logic was correct.** A
  receipt proves a claim was staked under a pinned, revocable,
  logged identity — it is not a formal verification of the policy
  evaluator.
- **Real-time receipt streaming / an RPC protocol for receipt
  submission.** This RFC defines the artifact and its verification
  semantics; transport (gRPC, webhook, batch upload to a log
  operator) is caller's choice, same posture as RFC-0025 Phase A.
- **Mandating witness co-signing.** Optional and recommended (see
  Design), not required — some deployments are genuinely air-gapped
  and single-party.
- **A new compliance-framework mapping** (SOC 2, HIPAA, etc.) that
  consumes receipts. That is a `src/compliance/` RFC once this
  primitive exists.
- **Runtime-identity provisioning mechanics** (how a runtime gets its
  key registered in the first place). RFC-0026 hardware attestation
  already covers binding a runtime's key to a master authority via
  TEE evidence; this RFC assumes that machinery, it does not
  reinvent it.

## Proposal

### Overview

An Enforcement Receipt is produced by an **enforcement runtime** at
the moment it renders a policy decision. The runtime:

1. Reads the `.aion` file's policy identity and the pinned
   `KeyRegistry` snapshot it is using to trust that policy.
2. Renders a decision (`allow` / `deny` / `degraded` / `fail_closed`)
   against a set of decision inputs (e.g. request payload, prior
   approvals).
3. Builds an `EnforcementPredicate` (below), wraps it in an in-toto
   Statement whose `subject[]` is the BLAKE3 digests of the decision
   inputs, and signs it via DSSE using its **own** registered
   operational key (never the policy-author's key).
4. Optionally appends the DSSE envelope to a `TransparencyLog`
   (`LogEntryKind::EnforcementReceipt`) and/or forwards it to an
   independent witness for co-signature.

A verifier later checks the DSSE signature(s), resolves the runtime's
signing key through the `KeyRegistry` at the receipt's own version,
confirms the policy identity matches the `.aion` file under audit,
and — if present — checks the witness co-signature and the
transparency-log inclusion proof.

### `EnforcementPredicate` shape

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "decision-input-0", "digest": { "blake3-256": "9a3f..." } }
  ],
  "predicateType": "https://aion-context.dev/enforcement-receipt/v1",
  "predicate": {
    "policy": {
      "file_id": 7001,
      "policy_version": 42,
      "policy_author_id": 50001
    },
    "trust_context": {
      "registry_epoch": {
        "author_id": 50001,
        "epoch": 3
      }
    },
    "decision": "deny",
    "approvals": [
      { "approver_author_id": 50010, "attestation_ref": "blake3:ab12..." },
      { "approver_author_id": 50011, "attestation_ref": "blake3:cd34..." }
    ],
    "runtime": {
      "runtime_author_id": 60001,
      "receipt_version": 118,
      "nonce": "e7c1...  (16 bytes, hex)"
    }
  }
}
```

Field notes:

- `policy.*` mirrors the `.aion` `VersionEntry` identity fields
  already on the wire (`file_id`, `version_number`, `author_id`) —
  no new identity scheme.
- `trust_context.registry_epoch` is the `(author_id, epoch)` pair the
  runtime resolved via `KeyRegistry::active_epoch_at` for the
  **policy author's** key at verification time — this is what lets
  an auditor later reproduce "which key set did the runtime trust
  when it read the policy," independent of what the registry looks
  like today.
- `decision` is a closed, bounded enum on the wire (see
  `EnforcementDecision` below) — never a freeform string, matching
  the observability rule's low-cardinality requirement.
- `approvals[]` references prior RFC-0021 attestations by digest, not
  by embedding them — keeps the receipt small and avoids duplicating
  signature bytes that already exist and are independently verifiable.
- `runtime.nonce` is server-supplied or drawn from a distributed
  randomness source (see Design → Anti-replay) and is itself part of
  the signed predicate, not a side channel.
- `subject[]` follows the existing in-toto/SLSA convention
  (RFC-0024): BLAKE3 digests of whatever the runtime is willing to
  disclose about its decision inputs. A runtime that cannot disclose
  raw inputs (PII, secrets) still commits to their hash.

### Public API

```rust
// src/enforcement_receipt.rs

pub const ENFORCEMENT_RECEIPT_PREDICATE_TYPE: &str =
    "https://aion-context.dev/enforcement-receipt/v1";

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementDecision {
    Allow = 1,
    Deny = 2,
    Degraded = 3,
    FailClosed = 4,
}

#[derive(Debug, Clone)]
pub struct PolicyIdentity {
    pub file_id: u64,
    pub policy_version: u64,
    pub policy_author_id: AuthorId,
}

#[derive(Debug, Clone)]
pub struct RegistryEpochRef {
    pub author_id: AuthorId,
    pub epoch: u32,
}

#[derive(Debug, Clone)]
pub struct ApprovalRef {
    pub approver_author_id: AuthorId,
    pub attestation_digest: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct EnforcementPredicate {
    pub policy: PolicyIdentity,
    pub registry_epoch: RegistryEpochRef,
    pub decision: EnforcementDecision,
    pub approvals: Vec<ApprovalRef>,
    pub runtime_author_id: AuthorId,
    pub receipt_version: u64,
    pub nonce: [u8; 16],
}

pub struct EnforcementReceiptBuilder {
    // private: mirrors EnforcementPredicate fields, plus subject inputs
}

impl EnforcementReceiptBuilder {
    pub fn new(policy: PolicyIdentity, registry_epoch: RegistryEpochRef) -> Self;

    pub fn decision(&mut self, d: EnforcementDecision) -> &mut Self;
    pub fn add_approval(&mut self, a: ApprovalRef) -> &mut Self;
    pub fn add_input_digest(&mut self, name: impl Into<String>, digest: [u8; 32]) -> &mut Self;
    pub fn runtime(&mut self, runtime_author_id: AuthorId, receipt_version: u64) -> &mut Self;
    pub fn nonce(&mut self, nonce: [u8; 16]) -> &mut Self;

    /// Builds the in-toto Statement and signs it via DSSE with the
    /// runtime's own key. Distinct from the policy-signing key by
    /// construction: callers pass the runtime's `SigningKey`, never
    /// the policy author's.
    pub fn seal(
        self,
        runtime_key: &SigningKey,
    ) -> Result<EnforcementReceipt>;
}

pub struct EnforcementReceipt {
    pub statement: InTotoStatement,
    pub envelope: DsseEnvelope,
}

impl EnforcementReceipt {
    /// Verifies the DSSE signature(s) against the key registry,
    /// resolving the runtime's active epoch at `predicate.
    /// runtime_author_id, predicate.receipt_version`. Does not
    /// check replay state — that is the caller's persisted
    /// `(runtime_author_id, receipt_version)` ledger, per
    /// `.claude/rules/distributed.md`.
    pub fn verify_with_registry(&self, registry: &KeyRegistry) -> Result<()>;

    /// Adds an independent witness co-signature to the same DSSE
    /// envelope. The witness signs the identical PAE bytes the
    /// runtime signed — DSSE's native multi-signature support
    /// (RFC-0023) carries this with no format change.
    pub fn add_witness_signature(
        &mut self,
        witness_author_id: AuthorId,
        witness_key: &SigningKey,
    ) -> Result<()>;

    pub fn predicate(&self) -> Result<EnforcementPredicate>;
}

/// Appends the receipt's DSSE envelope to the transparency log as
/// `LogEntryKind::EnforcementReceipt`.
pub fn log_receipt(
    receipt: &EnforcementReceipt,
    log: &mut TransparencyLog,
    timestamp_version: u64,
) -> Result<u64>;
```

Added to `src/transparency_log.rs`:

```rust
#[repr(u16)]
pub enum LogEntryKind {
    VersionAttestation   = 1,
    ManifestSignature    = 2,
    KeyRotation          = 3,
    KeyRevocation        = 4,
    SlsaStatement        = 5,
    DsseEnvelope         = 6,
    EnforcementReceipt   = 7,
}
```

### Verification flow, precise

`verify_with_registry(&KeyRegistry)`:

1. Parse the DSSE envelope's payload into an `InTotoStatement`;
   `predicateType` must equal `ENFORCEMENT_RECEIPT_PREDICATE_TYPE` or
   `Err(InvalidFormat)`.
2. Extract `EnforcementPredicate` from the predicate JSON.
3. Resolve `registry.active_epoch_at(predicate.runtime_author_id,
   predicate.receipt_version)`. `None` ⇒
   `Err(SignatureVerificationFailed { version, author })` (sanitized,
   per the RFC-0033 §C10 precedent already used by RFC-0034).
4. Confirm every `DsseSignature.keyid` in the envelope that claims to
   be the runtime resolves to a public key matching the resolved
   epoch's `public_key` bytes.
5. Call `dsse::verify_envelope` (RFC-0023) over the resolved keys;
   any failure is hard — same all-or-nothing semantics DSSE already
   has.
6. Caller-side, **not** inside this function: check
   `predicate.nonce` was not previously observed for this
   `runtime_author_id` (replay ledger), and check
   `(runtime_author_id, receipt_version)` has not been previously
   accepted (RFC-0012 semantics). This RFC does not introduce a new
   persisted-state type; it reuses the same acceptance-ledger pattern
   every other versioned artifact in the crate already requires of
   its caller.

### Anti-replay and anti-fabrication mechanisms

Four complementary mechanisms, because no single one is sufficient
against a runtime that is willing to lie about itself:

1. **Separate trust roots for policy and enforcement.** A policy's
   `author_id` and a runtime's `author_id` are distinct entries in
   the `KeyRegistry`, each with their own master key
   (RFC-0028). Compromising the policy-signing key lets an attacker
   forge policy versions; it does **not** let them forge enforcement
   receipts, and vice versa. This is the load-bearing structural
   decision in this RFC — collapsing the two into one identity would
   let a single compromised key both rewrite the rules and attest
   that the rules were followed.
2. **Registered, epoch-tracked, revocable runtime keys.** A runtime's
   signing key is provisioned and rotated through the exact same
   `KeyRegistry` machinery as any other author (RFC-0028). If a
   runtime's key is later found compromised, its owner (or, in a TEE
   deployment, the master authority that issued the hardware binding
   per RFC-0026) revokes it effective at a specific
   `effective_from_version`, and every receipt claiming that runtime
   identity at or after that version is rejected under
   `verify_with_registry`.
3. **Nonce binding.** `predicate.nonce` is part of the signed bytes.
   A verifier or witness that supplies the nonce out-of-band (a
   challenge/response handshake at decision time) can confirm the
   receipt was produced *after* the challenge was issued, not
   pre-fabricated. A runtime that self-generates its own nonce (the
   degraded, no-witness case) gets weaker anti-fabrication — this
   is named explicitly in Unresolved Questions, not hidden.
4. **Transparency-log anchoring and optional witness co-signature.**
   Logging the receipt (`LogEntryKind::EnforcementReceipt`) gives it
   a `seq` position that an operator's Signed Tree Head (RFC-0025)
   later attests to; a receipt whose claimed decision time doesn't
   fit its log position is suspicious the same way a backdated key
   rotation is suspicious (RFC-0025's original motivating scenario).
   `add_witness_signature` lets a second, independently operated
   party — ideally one that issued the nonce in mechanism 3 — commit
   to the identical PAE bytes via DSSE's native multi-signature
   support, so the runtime is not the sole attester of its own
   compliance.

None of these make forgery by a runtime that is dishonest *and* not
yet revoked *and* colludes with its witness impossible — see Security
Considerations for exactly what is and is not proven.

### Edge Cases

- **Receipt with zero approvals**: valid. Not every policy decision
  requires human approval; `approvals` is empty when the decision
  path was fully automated.
- **Decision `fail_closed` with no policy read**: allowed — a
  runtime that could not resolve the registry epoch at all should
  still be able to emit a receipt recording that it failed closed,
  with `registry_epoch` set to the last-known-good epoch it had
  cached, and a `reason` field (bounded enum, added to the runtime
  block) explaining why. This is deliberately in scope: "we don't
  know, so we blocked" is exactly the kind of claim regulators want
  evidence of.
- **Duplicate `nonce` across two different `receipt_version`s from
  the same runtime**: rejected by the caller's replay ledger (not by
  `verify_with_registry` itself, matching the layering the crate
  already uses for `(author, version)` — see `signature_chain`).
- **Witness co-signature added after transparency-log append**: the
  logged leaf's `payload_hash` is over the DSSE envelope bytes at
  append time; adding a witness signature after logging changes
  those bytes and therefore is a **new** leaf, not a mutation of the
  old one (append-only invariant preserved, same as any other
  post-hoc DSSE `add_signature` call per RFC-0023).
- **Empty `subject[]`** (no decision-input digests disclosed):
  rejected, matching RFC-0024's "an SLSA Statement without subjects
  attests to nothing" precedent — a receipt with no bound inputs
  attests to nothing decidable.

## Rationale and Alternatives

### Why a distinct artifact type and not an audit-chain entry (RFC-0019)?

The audit chain (`src/audit.rs`) is **file-internal** — it lives
inside a specific `.aion` file, is appended to by whoever holds
write access to that file, and its `verify()` reads nothing external
(`.claude/rules/distributed.md`). An enforcement receipt is produced
by a runtime that may not have — and should not need — write access
to the `.aion` file it is enforcing; it needs to travel with the
runtime's own outputs (request logs, response payloads) and be
independently verifiable by a party who has never seen the `.aion`
file's audit chain at all, only a pinned registry and the receipt
itself. Folding receipts into the audit chain would require every
verifier to obtain, parse, and validate the *entire* `.aion` file
just to check one decision — a poor shape for a high-volume runtime
emitting one receipt per request. The audit chain remains the record
of *changes to the policy*; the receipt is the record of *an
application of* the policy. Distinct lifecycles, distinct artifacts.

### Why not fold enforcement state into the SLSA provenance predicate (RFC-0024)?

SLSA provenance answers "how was this artifact built?" — a
one-time, build-time claim about a subject that then remains fixed
for the artifact's life. An enforcement decision is a recurring,
runtime-time claim, potentially thousands per day, about inputs that
have nothing to do with how the *policy itself* was built. Reusing
the SLSA predicate type would either overload `predicateType`
semantics that downstream `slsa-verifier` tooling depends on, or
require every SLSA consumer to special-case a predicate shape it
does not expect. A distinct `predicateType`
(`.../enforcement-receipt/v1`) costs nothing and keeps the two
concepts — "this build happened" and "this decision happened" —
separately queryable and separately rate-shaped (build provenance:
rare, large; enforcement receipts: frequent, small).

### Why not have the runtime just append a signed log line to its own log?

That is the status quo this RFC replaces. An unsigned or
runtime-signed-only log line cannot be checked against a pinned
trust context by anyone who does not already trust the runtime
operator's own infrastructure — which is precisely the party the
audit exists to check. It also has no standard shape; every runtime
invents its own log format, and no tooling (DSSE/in-toto verifiers,
Rekor, cosign policy engines) can consume it without bespoke
integration work.

### Do nothing

Continue relying on out-of-band, unsigned operational logging (APM
traces, application logs, SIEM entries) as the evidence that a
policy was enforced. Rejected: this fails the reproducibility bar a
regulator or auditor requires — there is no cryptographic binding
between "the log line says allow" and "the pinned key set / policy
version that was actually live at that moment," and nothing prevents
an operator from editing their own logs after the fact. This is also
the actual status quo today, which is the motivating gap for this
RFC.

## Security Considerations

### Threat Model

**In scope:**

1. **Runtime key compromise.** Attacker steals a runtime's
   operational signing key. Mitigated by the same rotation/
   revocation machinery as any other author (RFC-0028) — once
   revoked, receipts at or after `effective_from_version` under that
   key are rejected by `verify_with_registry`.
2. **Policy/runtime key confusion.** Attacker tries to get a receipt
   accepted as if it were signed by the policy author, or vice
   versa. Rejected structurally — `registry.active_epoch_at` is keyed
   by `AuthorId`, and the predicate names `policy_author_id` and
   `runtime_author_id` as distinct fields; a verifier that conflates
   them is a caller bug, not a receipt-format weakness, and the
   Testing Strategy below includes a property test asserting the
   distinct fields cannot be swapped without invalidating the
   receipt.
3. **Receipt tampering in transit.** Attacker modifies the decision,
   approvals, or policy identity after signing. Detected — any
   change to the predicate JSON changes the PAE bytes, and DSSE
   verification fails (RFC-0023 threat model, inherited unchanged).
4. **Receipt pre-fabrication.** Attacker (or a dishonest runtime)
   produces a receipt for a decision before the inputs that justify
   it exist. Partially mitigated by the nonce mechanism when the
   nonce is externally supplied (challenge/response); **not**
   mitigated when the runtime self-generates its own nonce — that
   configuration is explicitly weaker and named as such in
   Unresolved Questions.
5. **Backdating via delayed logging.** A runtime holds a receipt and
   logs it later, claiming an earlier position. Detected — the
   transparency log's `seq` and any operator STH reflect actual
   submission order; a receipt that surfaces suspiciously late
   relative to its claimed decision context is visible the same way
   a backdated key rotation is visible (RFC-0025's original
   motivating threat).

**Out of scope (named, not hidden):**

6. **A dishonest runtime that is not yet revoked, colluding with its
   own witness (or operating with no witness at all).** If the
   runtime's key is legitimately active and it chooses to sign a
   receipt describing a decision that never happened, or misreports
   its own internal logic's outcome, the receipt is
   cryptographically valid and this RFC provides no mechanism to
   detect the lie. This is the single most important limit of the
   design and is restated in the Abstract deliberately: **a receipt
   proves a runtime staked its revocable, logged identity on a
   claim — it does not prove the claim's internal truth.** Detecting
   this class of dishonesty requires either an independent witness
   with its own decision-relevant visibility (mechanism 4 above,
   only as strong as the witness's independence and honesty) or
   out-of-band process controls (code review of the runtime,
   reproducible builds of the enforcement binary) that are entirely
   outside this RFC's scope.
7. **Compromise of the registry's master key for either the policy
   or runtime author.** Same posture as RFC-0028 — out of scope
   there, out of scope here.
8. **Malicious log operator colluding with a dishonest runtime to
   suppress or reorder log entries.** RFC-0025's own threat model
   defers operator-compromise resilience to a Phase B/C witness
   gossip protocol; receipts inherit that limitation unchanged.

### Security Guarantees

- A receipt that passes `verify_with_registry` proves: the runtime
  identified by `runtime_author_id` held the active, non-revoked
  operational key for `receipt_version` at verification time, and
  that identity's signature covers the exact `(policy identity,
  registry epoch, decision, approvals, input digests, nonce)` tuple
  with no tampering.
- Revoking a runtime's key retroactively removes trust in every
  receipt at or after the revocation's `effective_from_version`,
  exactly mirroring policy-author key revocation (RFC-0028) — the
  same auditor who understands one understands the other.
- A logged and witness-co-signed receipt additionally proves: an
  independent party committed to the identical bytes, and the
  receipt occupies a specific, tamper-evident position in an
  append-only sequence.
- The guarantee explicitly does **not** extend to the correctness of
  the runtime's internal decision logic (see Threat Model item 6).

## Performance Impact

- **Seal**: one BLAKE3 digest per decision input + one JCS
  canonicalization pass + one Ed25519 sign — the same per-receipt
  cost profile as an RFC-0024 SLSA statement, sub-millisecond for
  typical inputs.
- **Verify**: one registry epoch lookup (`O(log N)` over a small
  per-author epoch list, per RFC-0028) + one or two Ed25519 verifies
  (runtime, optionally witness) — negligible, dominates by neither
  factor at the volumes a runtime enforcement path implies (expect
  low tens of thousands of receipts/day per runtime, not per
  microsecond).
- **Logging**: append cost identical to any other `TransparencyLog`
  leaf (RFC-0025) — one BLAKE3 leaf hash, O(N) root recomputation in
  the current Phase-A implementation, same caveat already on record
  for high-volume logging pending the Phase B frontier cache.
- **Volume caveat**: enforcement receipts are, by nature, higher
  frequency than policy signatures or SLSA statements. A production
  deployment logging one receipt per request should not use the
  Phase-A in-memory `TransparencyLog` without the frontier-cache
  follow-up; this RFC does not change that existing constraint, it
  just makes the caller aware they will hit it sooner.

## Testing Strategy

### Property-Based Tests (Hegel, Tier-2)

Added to `.claude/rules/property-testing.md`:

- `prop_enforcement_receipt_seal_verify_roundtrip`: for any valid
  builder input and a registered runtime key, `seal` →
  `verify_with_registry` is `Ok`.
- `prop_enforcement_receipt_tampered_decision_rejects`: flipping the
  `decision` field after signing causes `verify_with_registry` to
  fail.
- `prop_enforcement_receipt_wrong_runtime_key_rejects`: signing with
  a key not registered as the claimed `runtime_author_id`'s active
  epoch fails verification.
- `prop_enforcement_receipt_rotated_out_runtime_key_rejects`: a
  receipt signed by a runtime key valid before rotation, presented
  at a `receipt_version` at or after the rotation's
  `effective_from_version`, fails.
- `prop_enforcement_receipt_revoked_runtime_key_rejects`: same shape
  for revocation.
- `prop_enforcement_receipt_policy_and_runtime_author_not_swappable`:
  swapping `policy_author_id` and `runtime_author_id` in the
  predicate invalidates the signature (they are both inside PAE).
- `prop_enforcement_receipt_empty_subject_rejects`: a predicate with
  zero input digests is rejected at build time.
- `prop_enforcement_receipt_witness_cosignature_roundtrip`: adding a
  witness signature via `add_witness_signature` yields an envelope
  where both the runtime's and the witness's keyids verify.
- `prop_enforcement_receipt_log_entry_kind_is_stable`: appending a
  receipt to a `TransparencyLog` always uses
  `LogEntryKind::EnforcementReceipt`, and its inclusion proof
  verifies like any other leaf (reuses RFC-0025's existing property
  suite against the new kind).

### Vector Test

One hand-rolled test: build a receipt for a `deny` decision with two
approvals and one input digest, seal it with a fixed test key,
assert the JCS-canonicalized predicate bytes and the DSSE PAE bytes
match a checked-in fixture. Catches drift in field ordering or
canonicalization the same way the RFC-0023/0024 vector tests do.

## Implementation Plan

### Phase A (this RFC, first PR)

1. `src/enforcement_receipt.rs` with `EnforcementPredicate`,
   `EnforcementReceiptBuilder`, `EnforcementReceipt`, and
   `verify_with_registry`.
2. `LogEntryKind::EnforcementReceipt` added to
   `src/transparency_log.rs` (additive; existing proofs unaffected
   per RFC-0025's own extensibility note).
3. `pub mod enforcement_receipt;` in `src/lib.rs`.
4. Property tests + one vector test per above.
5. Tier-2 floor + `/hegel-audit` update.

### Phase B

1. `add_witness_signature` end-to-end example wiring two independent
   `SigningKey`s through a shared envelope.
2. CLI: `aion receipt seal`, `aion receipt verify --registry=<path>`.
3. Integration with `release::SignedRelease` — a release may
   optionally carry a bundle of receipts covering its own rollout
   decision, reusing the existing `LogSeq` bookkeeping pattern from
   RFC-0032.
4. `TransparencyLog` frontier cache adoption for high-volume receipt
   logging (tracked in RFC-0025 Phase B already; this RFC does not
   duplicate that work, only depends on it).

### Phase C

1. A `src/compliance/` mapping from receipt fields to specific
   regulatory evidence requirements (e.g. SOC 2 CC7.2, HIPAA
   §164.312(b)) — separate RFC once receipts exist in the wild.
2. Standardized witness-service reference implementation (nonce
   issuance + co-signature) as an example, not a library dependency.

## Unresolved Questions

Honestly, more of these remain open than closed:

1. **Self-supplied nonce is a real weakness, not a formality.** In
   the no-witness deployment (a realistic majority case — air-gapped
   or cost-sensitive operators will not stand up a witness service),
   the runtime generates its own nonce and the anti-fabrication
   guarantee collapses to "the runtime says this happened at
   roughly this time relative to its own log position." Should
   Phase A require an external randomness beacon (e.g. NIST
   randomness beacon, drand) as a *minimum* bar even without a full
   witness protocol, so a self-issued nonce is at least publicly
   unpredictable? Leaning toward yes for the reference
   implementation, but this adds an external dependency the crate
   has avoided everywhere else (`.claude/rules/supply-chain.md`
   posture on network-attack-surface deps).
2. **Lost enforcement-runtime master key (the RFC-0028 DR case,
   restated for a new identity class).** RFC-0028 never resolved
   what happens when a master key itself is lost or compromised
   (Open Question territory there too). This RFC inherits that gap
   exactly, but the stakes are arguably different: losing a policy
   master key freezes governance; losing a runtime master key
   freezes the ability to ever rotate or revoke an enforcement
   identity, which means a compromised runtime key stays trusted
   forever unless there's an out-of-band emergency-revocation path
   this RFC does not define.
3. **Witness availability and independence assumptions are
   undefined.** "An independent witness co-signs" is easy to write
   and hard to operationalize: who runs it, what SLA does it have,
   what happens to in-flight enforcement decisions if the witness
   service is down (does the runtime fail closed, fail open, or
   emit an unwitnessed receipt with a flag)? This RFC does not
   pick an answer.
4. **Clock and nonce sourcing are unspecified beyond "not
   wall-clock for ordering."** The predicate has no timestamp field
   at all — deliberately, per `.claude/rules/distributed.md` — but
   auditors will want *some* approximate wall-clock correlation for
   human review (not correctness). Should a `debug`-tier,
   non-authoritative `observed_at` field exist purely for human
   triage, with an explicit doc comment that it is never used in
   any accept/reject decision? Unresolved; the existing crate
   convention (`created_at` / `timestamp` fields in `VersionEntry`,
   `AuditEntry`) suggests yes, but adding it invites someone,
   someday, to accidentally gate logic on it.
5. **Is a dishonest-but-not-yet-revoked runtime in or out of
   scope?** This RFC says out of scope (Threat Model item 6) and
   treats witness co-signing as a partial, opt-in mitigation. A
   reviewer could reasonably argue that a receipt format whose
   central selling point is auditability should not ship with that
   big a hole undocumented in code (only in this RFC's prose). Should
   `EnforcementReceipt` carry a machine-readable
   `witness_status: Unwitnessed | Witnessed` field so downstream
   compliance tooling can programmatically flag or reject
   unwitnessed receipts for high-stakes decisions, rather than
   relying on human policy to notice the absence of a second
   signature? Leaning toward yes, not yet designed.
6. **Approval-reference integrity.** `ApprovalRef.attestation_digest`
   points at an RFC-0021 attestation by hash but the receipt does
   not require the verifier to have that attestation in hand to
   verify the receipt itself. Is that the right layering (receipt
   verification is local; approval verification is a separate,
   optional deeper check), or should `verify_with_registry` take an
   optional attestation store and hard-fail if a referenced approval
   cannot be resolved and independently verified?

## References

- RFC-0012 — Versioning and replay semantics.
- RFC-0014 — Multi-signature support.
- RFC-0019 — Audit trail.
- RFC-0021 — Multi-party attestation.
- RFC-0023 — DSSE envelope.
- RFC-0024 — SLSA v1.1 provenance.
- RFC-0025 — Transparency log.
- RFC-0026 — Hardware attestation.
- RFC-0028 — Key rotation and revocation.
- RFC-0031 — JCS canonical JSON.
- RFC-0032 — Release orchestration.
- RFC-0033 — Post-audit carryovers (§C10 sanitized-error precedent;
  §C6 DSSE all-or-nothing dedup precedent).
- RFC-0034 — Registry-aware verify rollout (the `_with_registry`
  call-shape this RFC reuses verbatim).
- `.claude/rules/crypto.md` — author-binding rule; the structural
  basis for separating policy and runtime trust roots.
- `.claude/rules/distributed.md` — version-number-authoritative
  ordering; the basis for omitting wall-clock fields from the
  signed predicate.
- `.claude/rules/observability.md` — bounded, low-cardinality field
  discipline; the basis for `EnforcementDecision` being a closed
  enum rather than a string.
- in-toto Statement v1: <https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md>
- Sigstore Rekor (transparency log precedent):
  <https://github.com/sigstore/rekor>
- NIST SP 800-57 — key management lifecycle (informs the
  runtime-key rotation posture, same citation as RFC-0028).

## Appendix

### Terminology

- **Enforcement runtime**: the system that evaluates a policy against
  real inputs and renders a decision. Holds its own registered,
  epoch-tracked signing key distinct from any policy author's key.
- **Enforcement Receipt**: the signed artifact this RFC defines — a
  DSSE-wrapped in-toto Statement whose predicate binds policy
  identity, trust context, decision, approvals, and runtime identity.
- **Witness**: an independently operated party that co-signs a
  receipt's DSSE envelope, or issues the nonce the receipt commits
  to, to reduce reliance on the runtime's sole word.
- **Registry epoch**: as defined in RFC-0028 — a specific operational
  keypair lifetime for an author, resolved by `(author_id, version)`.
- **Trust context**: the specific registry epoch a runtime pinned for
  the policy author at the moment it made its decision — the datum
  an auditor needs to reproduce "what did the runtime trust, when."

### Call-site sketch

```rust
let mut receipt = EnforcementReceiptBuilder::new(
    PolicyIdentity {
        file_id: 7001,
        policy_version: 42,
        policy_author_id: AuthorId::new(50_001),
    },
    RegistryEpochRef { author_id: AuthorId::new(50_001), epoch: 3 },
);

receipt
    .decision(EnforcementDecision::Deny)
    .add_approval(ApprovalRef {
        approver_author_id: AuthorId::new(50_010),
        attestation_digest: approval_digest,
    })
    .add_input_digest("request", blake3::hash(&request_bytes).into())
    .runtime(AuthorId::new(60_001), 118)
    .nonce(challenge_nonce);

let sealed = receipt.seal(&runtime_signing_key)?;

// Optional: independent witness co-signs the same envelope.
sealed.add_witness_signature(AuthorId::new(70_001), &witness_key)?;

// Optional: anchor in the transparency log.
enforcement_receipt::log_receipt(&sealed, &mut log, current_aion_version)?;

// Verifier side, offline, given the pinned registry:
sealed.verify_with_registry(&registry)?;
```
