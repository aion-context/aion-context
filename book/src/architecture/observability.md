# Observability

> **Bryan Cantrill's rule:** you cannot debug what you cannot see.
> For a compliance-and-governance file format that must justify
> every decision to a regulator, structured tracing is part of the
> contract — not an optional add-on.

aion-context emits structured `tracing` events at every decision
point. The library uses the `tracing` facade only; the `aion` CLI
binary owns subscriber configuration. Library code never installs
a subscriber — that would compete with consumers' own setup.

## Subscriber wiring

The CLI configures the subscriber from two environment variables:

| Env var | Default | Effect |
|---|---|---|
| `AION_LOG` | `warn` | EnvFilter directive — same syntax as `RUST_LOG` |
| `AION_LOG_FORMAT` | `text` | `text` or `json` (one structured line per event) |

Examples:

```bash
# default — only rejections (warn) on stderr
aion verify rules.aion

# show every decision as a human-readable line
AION_LOG=info aion verify rules.aion

# emit JSON for ingest into a log store
AION_LOG=info AION_LOG_FORMAT=json aion verify rules.aion

# debug mode — every routine op (parse, hash, decrypt)
AION_LOG=debug aion verify rules.aion
```

Library consumers wire their own `tracing-subscriber` (or
`tracing_log`, OpenTelemetry, etc.) — the events are framework-
neutral.

## Event lexicon

Every emit carries a stable `event = "..."` field. The aggregated
catalog as of the current release:

### Verdicts (`info!` on accept, `warn!` on reject)

| `event=` | Module | When |
|---|---|---|
| `file_initialized` | `operations::init_file` | new `.aion` file genesis written |
| `file_verified` | `operations::verify_file` | all four guarantees pass |
| `file_rejected` | `operations::verify_file` | any guarantee failed; `reason` classifies |
| `commit_accepted` | `operations::commit_version` | new version signed and written |
| `multisig_threshold_met` | `multisig::verify_multisig` | K-of-N quorum reached, no Byzantine signers |
| `multisig_threshold_short` | `multisig::verify_multisig` | quorum failed; `reason` distinguishes Byzantine vs. insufficient |
| `signature_rejected` | `signature_chain::verify_signature` / `verify_attestation` | per-signature rejection with `reason` |
| `parser_rejected` | `parser::AionParser::new` | structural rejection of file bytes |
| `audit_chain_broken` | `audit::AuditEntry::validate_chain` | hash chain or timestamp invariant violated |
| `keystore_key_created` | `keystore::generate_keypair` | new key minted and stored |
| `keystore_load_rejected` | `keystore::load_signing_key` | load failed; `reason` classifies |

### Bounded `reason` codes

`warn!` events always carry a bounded `reason` field — a fixed
vocabulary that keeps log-store cardinality predictable.

| Module | `reason` values |
|---|---|
| `file_rejected` | `structure_invalid`, `integrity_hash_mismatch`, `hash_chain_broken`, `signature_invalid`, `unknown` |
| `signature_rejected` | `author_mismatch`, `no_active_epoch`, `pubkey_substitution`, `bad_signature`, `bad_attestation` |
| `multisig_threshold_short` | `byzantine_signer`, `insufficient_signers` |
| `parser_rejected` | `truncated_input`, `header_unparseable`, `header_invalid` |
| `audit_chain_broken` | `prev_hash_mismatch`, `timestamp_regression`, `reserved_nonzero` |
| `keystore_load_rejected` | `key_not_found`, `invalid_key_bytes`, `keyring_error`, `load_error` |

These tokens are stable. Adding a new value is a documented event;
removing or renaming one is a breaking change to consumers' alert
rules.

## Field discipline

| Field | Type | Notes |
|---|---|---|
| `event` | `&'static str`, `lower_snake_case` | the discriminator |
| `reason` | `&'static str` from the table above | sub-discriminator on `warn!` |
| `version` | `u64` | monotonic per author |
| `timestamp` | `u64` (ns since Unix epoch) | for audit-chain entries |
| `author` | 16-hex-char string | truncated `AuthorId` |
| `file_id` | 16-hex-char string | truncated 64-bit file ID |
| `file_hash` / `aion_hash` / `version_hash` / `rules_hash` | 16-hex-char string | first 16 chars of BLAKE3 |
| `bytes` / `payload_bytes` | `u64` | sizes only — never contents |
| `valid` / `required` / `invalid` / `missing` | `u32` | quorum tallies |
| `versions` | `u64` | version chain count |
| `backend` | `"file"` or `"os_keyring"` | keystore backend tag |

What never appears in any field: signing keys, raw signatures,
plaintext rules, full hashes (always truncated to 16 chars), full
author IDs (always truncated). See
`.claude/rules/observability.md` for the cardinality and privacy
rationale.

## Sample output

Default (warn) — only rejections:

```text
2026-04-25T14:02:11.842Z  WARN aion_context::operations:
  event=file_rejected file_id=37f0767fab9e57ab versions=2
  reason=integrity_hash_mismatch
```

`AION_LOG=info` — verdicts on every action:

```text
2026-04-25T14:02:30.118Z  INFO aion_context::operations:
  event=file_verified file_id=92c1d4b803aa18ee versions=3
2026-04-25T14:02:30.119Z  INFO aion_context::operations:
  event=commit_accepted file_id=92c1d4b803aa18ee
  author=000000000001119a version=4
  version_hash=8a32f0b7e4c91d62 rules_hash=d40e2a6f917cc8b1
```

`AION_LOG_FORMAT=json AION_LOG=info` — one JSON line per event:

```json
{"timestamp":"2026-04-25T14:02:30.118Z","level":"INFO","fields":{"event":"file_verified","file_id":"92c1d4b803aa18ee","versions":3},"target":"aion_context::operations"}
```

## What you do with this

The Cantrill rule, applied to aion-context: **a compliance auditor
should be able to answer "why did the verifier reject this file at
time T?" by reading a single structured log line.** Every
`file_rejected` and `multisig_threshold_short` event carries enough
fields (file_id, version count, reason) to answer that without
rehydrating state from elsewhere.

For an example of an agent that consumes these events, see
[Policy Loop](../examples/policy_loop.md) — it emits its own
`agent_decided` and `agent_refused` events on top of the library's
verdicts.
