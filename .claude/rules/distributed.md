# Distributed Systems (Lamport / Kleppmann)

An `.aion` file is a replicated artifact even when it looks local:
the same bytes may be shipped between signers, readers, and archival
systems over years. Treat every boundary as adversarial, every clock
as a liar, and every receiver as capable of restarting at the worst
possible moment.

## Versioning and replay

- **Every signed artifact carries a `version: u64`.** Receivers reject
  anything with `version <= last_accepted_version[source]`.
- **Last-accepted version is persisted.** A receiver that restarts
  with an empty cache must not accept a replayed older artifact. The
  file header's `version` field is authoritative; the audit chain
  inside the file itself is the persistence mechanism for verifiers
  that track acceptance state across restarts.
- **Version + author together.** `version` is per-author, not global.
  Two authors can legitimately produce `version = 5` simultaneously;
  the tuple `(author, version)` is the unique key.
- **No wall-clock comparisons for ordering.** Wall clocks drift,
  leap, and lie. Use version numbers, logical clocks, or hash-chain
  positions. `chrono::DateTime` is fine for *display*; never for
  *correctness*.

## Idempotency

- Every receive path must be idempotent. Replaying the same valid
  audit entry or signed commit produces the same end state as
  processing it once.
- Mutating operations that succeed partway must leave the system in a
  state where a retry completes the work — not one where the retry
  double-applies. The signature_chain's "append" is the canonical
  example: it's idempotent against `(author, version)`.

## Failure modes

Design for all four:

| Failure      | Example                                  | Handling                |
|--------------|------------------------------------------|-------------------------|
| Omission     | File never reaches a verifier            | External retransmit     |
| Duplication  | Same file arrives twice                  | `(author, version)` dedupe |
| Reordering   | v5 arrives before v4                     | Highest-version wins    |
| Byzantine    | Malicious signer with compromised key    | Revocation channel      |

Byzantine failure is **in scope** — the file format is designed for
environments where the signer set is adversarial (regulated
enterprises, multi-party contracts). Revocation records are signed
by a higher-tier key and invalidate everything signed with the
revoked key after a declared version. See `src/multisig.rs` for the
quorum model.

## Audit chain

`src/audit.rs` is the persistence of record inside an `.aion` file.
It must:

1. Be append-only at the API boundary — no `update`, no `delete`. A
   "redaction" is a new entry linking to and marking the old one.
2. Chain entries by BLAKE3 hash — tampering with entry N invalidates
   N+1…end. `verify()` walks the chain and returns the first break.
3. Expose `verify()` that is **O(entries)** and reads nothing
   external.
4. Survive process crash between append and fsync — use
   write-then-rename or a real WAL; don't invent a new durability
   protocol. Storage implementations document their durability
   guarantee explicitly.

## Observability

- Every accepted commit / audit entry emits a `tracing` event at
  `info!` with a stable `event` field.
- Every rejected input emits a `warn!` with a bounded `reason` code.
  "We silently dropped it because the signature was bad" is an attack
  signal, not noise.

See `.claude/rules/observability.md` for the field lexicon.
