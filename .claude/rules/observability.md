# Observability (Cantrill)

Bryan Cantrill's rule: **you cannot debug what you cannot see**. For a
compliance and governance format that must justify every decision to
a regulator, tracing is not optional — it is part of the contract.

## Scope

`aion-context` (the library crate) depends on the `tracing` crate and
instruments its public surface. Binaries (the `aion` CLI) own the
subscriber configuration. Test code does NOT require a subscriber; if
you want log output from a specific test, set `AION_LOG=debug` and
call `tracing_subscriber::fmt::init()` in the test.

## What must be traced

Every decision point. A "decision point" is anywhere the code branches
on trust, version, signature, or identity:

| Module                             | Decisions                                                           |
|------------------------------------|---------------------------------------------------------------------|
| `aion_context::crypto`             | Signature verify success/failure; hash computed                     |
| `aion_context::signature_chain`    | Append success; chain verified; chain tamper (with reason code)     |
| `aion_context::multisig`           | Quorum reached; quorum short; signer rejected                       |
| `aion_context::parser`             | Format version detected; truncated input; unknown field             |
| `aion_context::operations`         | File initialized / committed / verified                             |
| `aion_context::audit`              | Entry appended; chain verified; redaction record written            |
| `aion_context::keystore`           | Key loaded / created / rotated / rejected                           |
| `aion_context::compliance`         | Framework matched; export generated                                 |

Each event carries a stable `event = "…"` field — this is the primary
discriminator. Additional fields are **structured**
(`version`, `sequence`, `author`, `reason`), not freeform strings.

## What must NEVER be traced

- **Signing keys.** Ed25519 private-key material must not appear in
  any `%` or `?` formatted field. If you need to identify a signer,
  use the verifying-key-derived `author_id`, truncated to 16 hex
  chars.
- **Raw signatures as full bytes.** A 64-byte hex blob is visual
  noise. Log signature length on failures, nothing more.
- **Full file payload bytes.** Log `payload_bytes = len` only. For
  debugging, attach the payload to an audit entry with the
  appropriate privacy level; don't smuggle it into a log line.
- **Full hex hashes.** Prefix to 16 chars (`short_hex(&h)`) — 64
  bits is plenty for correlation and keeps log lines scannable.

## Levels

- **`trace!`** — reserved. Do not use in library code without a
  TODO-level justification.
- **`debug!`** — routine operations (encode, decode, hash, parse).
  Called on every signal; must be zero-cost when no subscriber is
  attached.
- **`info!`** — verdicts and state transitions: file verified, commit
  accepted, audit appended, chain verified. Auditors read these.
- **`warn!`** — rejections and suspicious input: stale file, unknown
  author, invalid signature, tamper detected. Security operators read
  these.
- **`error!`** — operational failure that the caller cannot recover
  from. We prefer `Result::Err` over `error!`, so this is rare.

## Field naming

Stable, `lower_snake_case` keys. Reserve these tokens:

- `event` — the discriminator (always `snake_case`)
- `reason` — sub-discriminator for `warn!` events
  (`invalid_signature`, `unknown_author`, `version_replay`,
  `prev_mismatch`, `truncated_input`, `unknown_format_version`, …)
- `version` — u64 monotonic version
- `sequence` — u64 audit sequence number
- `author` — truncated author_id (16 hex chars)
- `file_hash`, `aion_hash` — first 16 hex chars
- `bytes` / `payload_bytes` — sizes, never contents

Do NOT invent synonyms (`ver` vs `version`, `auth` vs `author`).
Query stability depends on consistent field keys.

## Cardinality

Every field value must be bounded. High-cardinality strings (full
author_ids, UUIDs, unique error messages) blow up log index memory
in aggregation systems.

- OK: `reason = "invalid_signature"` (fixed set of ~20 values)
- OK: `version = 42` (u64, but usually small)
- OK: `author = "a7c3e9f18b22d04c"` (16 hex chars, stable per key)
- BAD: `error = format!("signature byte {i} mismatched {byte}")` —
  unbounded
- BAD: `trace_id = Uuid::new_v4().to_string()` — one-of-a-kind per
  log line. If you need a trace_id, use `tracing`'s span facility,
  not a field.

If an error value is unbounded, classify it into a bounded `reason`
first and log the rest at `debug!`.

## Subscriber wiring

- **Library code** (anything in `src/` except `src/bin/`) does NOT
  initialize a subscriber. Doing so in a library competes with the
  binary's configuration.
- **The `aion` CLI binary** (`src/bin/aion.rs`) initializes
  `tracing_subscriber::fmt` with an `EnvFilter` driven by `AION_LOG`.
  `AION_LOG_FORMAT=json` emits one JSON line per event, suitable for
  ingest into any structured log store.
- **Tests** that need logs call `tracing_subscriber::fmt::init()`
  once (typically in a test helper). Production libraries should not
  see a subscriber at test time unless the test explicitly attaches
  one.

## The Cantrill rule, applied

> The single most important thing you can do is to ensure that when
> production has a problem, you can see it — not guess it, not infer
> it, *see* it.

For `aion-context`, that means a compliance auditor should be able to
answer **"why did the verifier reject this `.aion` file at time T?"**
by reading a single structured log line. Every `file_rejected` event
must carry enough fields (author, version, reason) to answer that
question without rehydrating state from elsewhere.

If a trace event cannot stand alone as an audit line, it's not yet
instrumented correctly.
