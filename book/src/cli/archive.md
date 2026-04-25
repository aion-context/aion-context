# `archive verify` — bulk-verify a directory

Walk a directory of `.aion` files, verify each against a
supplied registry, and aggregate the verdicts into an
auditor-facing dashboard.

```bash
aion archive verify <DIR> \
    --registry <REGISTRY_FILE> \
    [--format text|json|yaml]
```

## What it produces

**Text format** (default):

```text
═══════════════════════════════════════════════════════════════════════
 Archive verification — ./archive
═══════════════════════════════════════════════════════════════════════

Pass 1 — Per-file verification
──────────────────────────────
  FILE                          VERDICT     DETAILS
  week-01.aion                  ✅ VALID
  week-02.aion                  ✅ VALID
  week-05.aion                  ❌ INVALID   File integrity hash mismatch: ...
  week-11.aion                  ❌ INVALID   Signature verification failed: ...

  Summary: 10/13 VALID, 3 INVALID

Pass 2 — Signer breakdown
─────────────────────────
  ⚙  Author 401001 — ROTATED (2 distinct keys observed)
       key 38adddc322a5900b…  files: week-01.aion, week-03.aion, ...
       key d9c7a1e7f69f96b2…  files: week-11.aion, week-13.aion
  ✓  Author 401002 — stable
       key d5f5a5cd8dd3b9c5…  files: week-02.aion, week-04.aion, ...

Findings
────────
  ❗ 3 of 13 files failed verification.
     - week-05.aion
     - week-11.aion
     - week-13.aion
```

**JSON format** emits a structured `ArchiveReport` for downstream
tooling (dashboards, ticketing systems, weekly digests). YAML
emits the same shape.

## Exit-code contract

- All files VALID → exit `0`
- Any file INVALID → exit `1`

So `aion archive verify` slots into shell pipelines:

```bash
aion archive verify ./quarterly-archive --registry reg.json \
  || pager-the-on-call --reason "audit anomaly"
```

## What the breakdown catches

**Pass 1** — per-file verdicts. Independent verification of
every file in the directory. The `error` column carries the
specific reason from `verify_file`'s `VerificationReport`.

**Pass 2** — distinct-pubkey histogram per author. If an
author shows more than one operational key across the archive,
the dashboard reports `⚙ ROTATED` with the file lists per key.
This is a structural finding even if every file individually
verifies, because it tells the auditor *something
operationally significant happened* between the files using
key A and the files using key B.

**Findings** — aggregate summary. Lists every file that failed
for the SEC writeup or equivalent.

## What the breakdown does NOT do

- Doesn't reconstruct timeline / audit-log linkage across
  files. Each `.aion` is verified independently.
- Doesn't recurse into subdirectories. Top-level only by
  default. (Recursive is a future flag.)
- Doesn't differentiate "rotation" from "key compromise" —
  both look like "two distinct keys for the same author."
  Cross-referencing with the registry's revocation records
  would catch the difference; that's a future improvement.

## Where this fits

Originally the audit pattern was a 140-line bash loop over
`aion verify`. The CLI subcommand replaces it for a built-in
operator-facing UX, and produces structured JSON for any
ticket-tracker or dashboard that wants to consume it. See
[issue #48] / PR #51.

If your archive uses **per-file genesis** (every file at v1)
and a key rotation occurred, expect every post-rotation file
to fail verify when the rotation effective_from_version
falls at v1. That's the architectural choice documented in
[RFC-0035](../operations/chain-architecture.md). The dashboard
will surface those failures as a structural finding, not a
bug.

[issue #48]: https://github.com/copyleftdev/aion-context/issues/48
