# Aegis Consortium

> 5-party governance with K-of-N quorum, hybrid PQC signatures,
> rotation, revocation, and a 4-act adversarial timeline.

The example file is at `examples/aegis_consortium.rs`. Run it:

```bash
cargo run --release --example aegis_consortium
```

## What it exercises

| Library surface | RFC | Why it's interesting |
|---|---|---|
| `MultiSigPolicy` + `verify_multisig` | RFC-0021 | K-of-N threshold enforcement |
| `HybridSigningKey` (Ed25519 + ML-DSA-65) | RFC-0027 | Post-quantum hedge |
| `sign_rotation_record` + `apply_rotation` | RFC-0028 | Mid-timeline rotation |
| `sign_revocation_record` + `apply_revocation` | RFC-0028 | Compromise response |
| `KeyRegistry` window resolution | RFC-0028/0034 | Active-epoch-at-version |

## The four acts

**Act I — Genesis v1, all 5 parties dual-sign.**

5 classical attestations + 5 hybrid signatures. Quorum 3-of-5
met. Hybrid signatures verify both halves (Ed25519 + ML-DSA-65)
— the post-quantum hedge.

**Act II — Staff departure at v10, AI-Safety's op key rotates.**

Master-signed rotation record minted. Epoch 1 active from
version 10. Quorum at v11 reaches threshold via the
successor's new key + CRO + Engineering.

**Act III — Legal's key compromised at v20, revoked.**

Master-signed revocation record. Epoch 0's window closes at
v20. A Byzantine quorum attempt with Legal's revoked key
tallies `valid=1, invalid_signers=[Legal]` — threshold not
met. Legitimate fallback quorum (CRO + Safety-successor + Eng
+ Sec) reaches threshold.

**Act IV — PQC migration at v30.**

Hybrid required from this point. Adversarial mutations:

- Malformed hybrid (classical valid, PQ junk): ❌ REJECTED
- Tampered ML-DSA half (1 bit flipped): ❌ REJECTED
- Tampered Ed25519 half (1 bit flipped): ❌ REJECTED

## Sample output (abbreviated)

```text
═══════════════════════════════════════════════════════════════════════
║ Aegis Consortium — 3-of-5 governance with hybrid PQC                  ║
═══════════════════════════════════════════════════════════════════════
  Quorum policy: 3-of-5
    ├─    Chief Risk Officer (author 100001, ...)
    ├─    AI Safety Director (author 100002, ...)
    ├─    General Counsel (author 100003, ...)
    ├─    Engineering Lead (author 100004, ...)
    ├─    Security Officer (author 100005, ...)

═══════════════════════════════════════════════════════════════════════
║ Act III — Legal's key compromised at v20 → revoke + Byzantine attempt ║
═══════════════════════════════════════════════════════════════════════
  • Revocation applied: General Counsel epoch 0 revoked effective v20 (Compromised)
  • Byzantine v25 quorum: valid=1, invalid_signers=[100003], threshold_met=false
  • ✅ Rogue quorum REJECTED
```

## What you'll learn from running it

- How `verify_multisig` interacts with the registry to
  classify a Byzantine signer's contribution as
  `invalid_signers` rather than `valid_signers`.
- How rotation effective-from-version cleanly partitions a
  growing chain when versions are monotonic.
- How hybrid signatures' both-halves-required contract
  defends against a future where one half is broken.

The example file is ~390 lines of Rust composing existing
public APIs — no new primitives. The `examples/` directory is
the right place to look when you want a compact, runnable
case study of the library's surface.
