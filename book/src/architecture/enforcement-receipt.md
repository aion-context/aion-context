# Enforcement Receipt (RFC-0036)

Everything else in aion-context attests **provenance**: *is this
policy authentic, and who signed it?* An enforcement receipt attests
the missing half — **enforcement**: *did a runtime actually apply this
policy to a real decision, and what did it decide?* A valid rulebook
and a compliant execution are separate claims; the receipt is the
evidence for the second one.

A receipt is a DSSE envelope ([RFC-0023](../reference/rfcs.md)) wrapping
an in-toto Statement, with no new cryptography — it composes the DSSE,
in-toto, key-registry, and transparency-log primitives already in the
crate.

## What a receipt binds

The predicate binds, under the runtime's own signature:

- **Policy identity** — the `.aion` `file_id`, `policy_version`, and
  `policy_author_id` the decision was rendered against.
- **Trust context** — the key-registry **epoch** the runtime pinned
  for the policy author at decision time, so an auditor can reproduce
  *which key set the runtime trusted* independent of what the registry
  looks like today.
- **Decision** — a bounded enum: `allow`, `deny`, `degraded`,
  `fail_closed`.
- **Approval references** — digests of the gating attestations
  (RFC-0021), bound but not resolved by base verification (see below).
- **Runtime identity** — the enforcing runtime's `author_id`, a
  monotonic `receipt_version` for `(author, version)` replay defense,
  and a 16-byte nonce.
- **Subject digests** — BLAKE3 digests of the decision inputs the
  runtime commits to (it can commit to a hash without disclosing
  raw inputs).

## Producing one

```rust
use aion_context::enforcement_receipt::{
    EnforcementReceiptBuilder, EnforcementDecision, PolicyIdentity, RegistryEpochRef,
};

let mut builder = EnforcementReceiptBuilder::new(
    PolicyIdentity { file_id: 7001, policy_version: 42, policy_author_id },
    RegistryEpochRef { author_id: policy_author_id, epoch: 3 },
);
builder
    .decision(EnforcementDecision::Deny)
    .add_input_digest("request", request_digest)
    .runtime(runtime_author_id, 118)
    .nonce(challenge_nonce);

let receipt = builder.seal(&runtime_key)?;   // signed with the runtime's OWN key
receipt.verify_with_registry(&registry)?;
```

## Author binding — the load-bearing property

The runtime signs with its **own** registry-tracked key, which is a
distinct identity from the policy author's. Policy-issuing authority
and enforcement-attesting authority are separate trust roots by
construction: one compromised key cannot both rewrite the rules and
attest that they were followed.

`verify_with_registry` enforces this. It **rejects unless the named
runtime's own signature is present and verifies** against its active
registry epoch at `receipt_version`. A "check every runtime-claiming
keyid" test without the presence requirement is vacuously true on an
envelope that carries no runtime signature — so a different,
validly-registered signer could otherwise produce a receipt attributed
to a victim runtime. That path is a hard-fail with a dedicated
regression test.

Because runtime keys live in the same registry
([Key Registry](./registry.md)), a compromised runtime identity is
**rotated or revoked** exactly like a policy key, and every receipt at
or after the revocation version stops verifying.

## Witnesses and the transparency log

An independent **witness** may co-sign the same envelope so the runtime
is not the sole attester. Witnesses resolve at their **own** version
space, never the runtime's `receipt_version` — a single version cannot
resolve two independent signers' key timelines. The witness binding is
an out-of-band hint; a wrong hint only selects a key the signature
won't verify against, so it fails closed.

Receipts can be appended to the [Transparency Log](./transparency-log.md)
as `LogEntryKind::EnforcementReceipt`, giving them the same
backdating-resistance a sealed release gets. Note that log position
bounds *submission order*, not how soon after the decision the receipt
was signed.

## Approvals are opt-in

Base `verify_with_registry` binds the approval **references** (they are
inside the signed bytes) but does not resolve them — it is a local
check needing only the receipt and a pinned registry. Callers gating a
high-stakes `allow` on human approval use
`verify_with_registry_and_approvals(&registry, &store)`, which resolves
each `ApprovalRef` against an `AttestationStore` and hard-fails
(`UnresolvedApproval`) on any that cannot be independently verified.

## What a receipt does and does not prove

A verifying receipt proves that the named runtime **staked its
revocable, logged identity** on a decision under a pinned trust
context, with the exact `(policy, epoch, decision, approvals, inputs,
nonce)` tuple untampered.

It does **not** prove the runtime's internal decision logic was
correct. A dishonest-but-not-yet-revoked runtime that signs a receipt
for a decision it never made produces a cryptographically valid
receipt; detecting that requires an independent witness with its own
decision-relevant visibility, or out-of-band process controls. This
boundary is stated plainly in the RFC and the code, not hidden.

## See also

- RFC-0036 in `rfcs/` — full design, threat model, and unresolved
  questions
- `src/enforcement_receipt.rs` — implementation (16 tests incl. 5
  property tests; two independent crypto-auditor passes)
- [DSSE Envelope](../reference/rfcs.md) and [Key Registry](./registry.md)
  — the primitives it composes
