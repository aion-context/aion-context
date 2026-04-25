# `show` / `report` / `export`

Read-only subcommands for human-readable inspection,
compliance-framework reporting, and downstream-tooling export.
None of them mutate the file.

## `aion show`

Pretty-print one of four views into a file.

```bash
aion show <FILE> --registry <REGISTRY_FILE> <SUBCOMMAND>

Subcommands:
  rules        Show the current rules content (decrypted if needed)
  history      Show every version's metadata
  signatures   Show every signature with its verified status
  info         Show file ID + version count + signature summary
```

`--registry` is required by `signatures` and `info` (both run
the verify path internally). `rules` and `history` ignore it.

Format flag is `--format text|json|yaml`, default `text`.

### `show signatures`

```text
Signatures (3 total)
==================

Version 1: ✅ VALID
  Author: 50001
  Public Key: a5cfc10031a2e52b...

Version 2: ✅ VALID
  Author: 50001
  Public Key: a5cfc10031a2e52b...

Version 3: ❌ INVALID
  Author: 50001
  Public Key: 4bb5bdcc8b5fac7e...
  Error: Signature verification failed for version 3 by author 50001
```

A row's `verified` field reflects the registry-aware verdict:
`Author Y signed v3 with key K, but the registry says epoch
active at v3 is a different key`.

### `show history`

```text
Version History (3 versions)
================================

Version 1:
  Author:    50001
  Timestamp: 2026-01-15T09:00:00Z
  Message:   Genesis policy
  Rules Hash: 39f695ee668a4479...

Version 2:
  Author:    50001
  Timestamp: 2026-02-01T09:00:00Z
  Message:   Tighten threshold
  Rules Hash: 4f23abd0d4d77ff3...
  Parent Hash: 3ac2f4f7011beb62...
```

## `aion report`

Generate a compliance report for a single file.

```bash
aion report <FILE> \
    --framework <generic|sox|hipaa|gdpr> \
    --format <text|markdown|json> \
    --registry <REGISTRY_FILE> \
    [--output <PATH>]
```

`--framework` selects the templated narrative (Sarbanes-Oxley
Section 404, HIPAA 45 CFR §164.312, etc.). Implementation lives
in `src/compliance.rs`.

Sample (HIPAA / markdown, abbreviated):

```markdown
# HIPAA Compliance Report

**Generated**: 2026-04-25T18:39:57Z
**File**: `mercy-ai-gov-clean.aion`
**File ID**: `0x537dbed49eb8dbbf`

## Verification Summary

| Check | Status |
|-------|--------|
| Overall | ✅ VALID |
| Structure | ✅ |
| Integrity | ✅ |
| Hash Chain | ✅ |
| Signatures | ✅ |

## Version History

| Version | Author | Timestamp | Message |
|---------|--------|-----------|---------|
| 1 | 250001 | 2026-04-24T18:39:57Z | Genesis |
| 2 | 250002 | 2026-06-15T... | GDPR amendment |
| 3 | 250003 | 2026-09-01T... | FDA Part 11 amendment |
```

## `aion export`

Export the file's full contents (versions + signatures + audit
metadata) as JSON / YAML / CSV.

```bash
aion export <FILE> \
    --format <json|yaml|csv> \
    --registry <REGISTRY_FILE> \
    [--output <PATH>]
```

JSON shape:

```json
{
  "export_version": "1.0",
  "source_file": "policy.aion",
  "file_info": {
    "file_id": "0x537dbed49eb8dbbf",
    "current_version": 3,
    "version_count": 3
  },
  "versions": [ ... ],
  "signatures": [
    {
      "version": 1,
      "author_id": 250001,
      "public_key": [ ... ],
      "verified": true
    },
    ...
  ]
}
```

CSV format produces one row per audit-trail entry — useful for
spreadsheet-driven compliance reviews.

## Why these are separate from `verify`

`verify` is the trust gate: a binary verdict + structured
errors. `show` / `report` / `export` are reading verbs on top
of an already-verified file (or a file you want to inspect
even if it doesn't verify, for forensic purposes). Treating
them as separate verbs keeps the type-level exit-code contract
(verify exits non-zero on INVALID; the others exit 0 on
successful read regardless of verdict).
