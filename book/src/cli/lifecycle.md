# `init` / `commit` / `verify`

The three core operations on a single `.aion` file: create it,
amend it, validate it.

## `aion init`

Create a new `.aion` file with a v1 genesis version.

```bash
aion init <FILE> \
    --author <AUTHOR_ID> \
    --key <KEY_ID> \
    [--rules <RULES_FILE> | --rules -]   # stdin if `-`
    [--message <MESSAGE>]                # defaults to "Genesis version"
    [--force]                            # overwrite if FILE exists
    [--no-encryption]
```

`init` deliberately does **not** take a registry. Genesis trust
flows from the original signing key alone; the registry is
established later (or in parallel) by an operator running
`aion registry pin`.

## `aion commit`

Append a new signed version to an existing file.

```bash
aion commit <FILE> \
    --author <AUTHOR_ID> \
    --key <KEY_ID> \
    --message <MESSAGE> \
    --registry <REGISTRY_FILE> \
    [--rules <RULES_FILE> | --rules -]
    [--force-unregistered]
```

`commit` runs four pre-write gates in order before any byte is
written:

1. **Integrity hash** — the file's trailing BLAKE3 hash must
   match the contents above it. Catches whole-file tampering.
2. **Hash chain** — every `parent_hash` link must be consistent.
   Catches tampering of intermediate version entries that the
   integrity check might miss if the operator regenerated the
   trailing hash.
3. **Head signature** — the most recent signature must verify
   under the active registry epoch.
4. **Registry pre-check** — the supplied `(author, signing key)`
   must match the active epoch in the registry at the new
   version number. Catches the most common operator mistake:
   running `aion commit --author X --key Y` where Y is not
   pinned for X.

If any gate fails, `commit` exits with `Err` and **does not
mutate** the file. The bytes on disk are byte-identical to
pre-attempt.

### `--force-unregistered`

Escape hatch for staged-rollout / offline-signer workflows
where the operator signs first and pins the new author into
the registry afterward. Skips gate 4 only; gates 1-3 still run.

Prints a loud warning to stderr:

```text
⚠️  --force-unregistered: skipping registry authz pre-check.
The resulting file will NOT pass `aion verify --registry`
until the registry is updated to pin this signer.
```

The function this dispatches to (`commit_version_force_unregistered`)
is `#[must_use]` with a message reminding the caller to update
the registry.

## `aion verify`

Validate a file end-to-end.

```bash
aion verify <FILE> \
    --registry <REGISTRY_FILE> \
    [--format text|json|yaml] \
    [--verbose]
```

Output (text format):

```text
🔍 Verifying AION file: policy.aion
   Registry: registry.json (registry-aware verify)

Verification Results:
====================
Overall: ✅ VALID

Structure:     ✅
Integrity:     ✅
Hash Chain:    ✅
Signatures:    ✅
```

Each of the four gates is reported independently, so an auditor
can tell exactly which property failed. Errors are listed
beneath the table:

```text
Errors:
  • Signature verification failed: Signature verification
    failed for version 5 by author 250001
```

JSON format emits a structured `VerificationReport` for
downstream tooling.

## How the lifecycle interacts with the registry

A common operator flow:

```bash
# 1. Generate keys (master + operational).
aion key generate --id 50001
aion key generate --id 150001

# 2. Pin a registry. This is the trust anchor for every
#    later verifier.
aion registry pin \
    --author 50001 --key 50001 --master 150001 \
    --output registry.json

# 3. Create the file. init does not consult the registry,
#    but the AuthorId in the file should match the pinned
#    author.
aion init policy.aion --author 50001 --key 50001 \
    --rules genesis.yaml

# 4. Subsequent amendments use commit. These DO consult the
#    registry — the pre-check makes sure the (author, key)
#    pair matches the active epoch.
aion commit policy.aion --author 50001 --key 50001 \
    --rules amendment.yaml \
    --message "Tighten threshold" \
    --registry registry.json

# 5. Anyone holding the same registry can verify.
aion verify policy.aion --registry registry.json
```
