# `registry`

Manage the trusted-key registry that pins which operational
key was active for which signer at which version. The registry
is a single JSON file; every verifier consults it.

```bash
aion registry <SUBCOMMAND>

Subcommands:
  pin       Pin an author's master + initial operational key
  rotate    Mint a new operational-key epoch (RFC-0028)
  revoke    Invalidate an epoch from a target version onward
```

Every subcommand takes `--registry <PATH>` (or `--output` on
`pin` if creating); the file is updated atomically (write to a
sibling `.tmp` and rename, never half-written).

## `aion registry pin`

Register an author. If the registry file does not exist, it is
created. If it exists, the new author is appended.

```bash
aion registry pin \
    --author <AUTHOR_ID> \
    --key <KEY_ID> \
    [--master <MASTER_KEY_ID>] \
    --output <REGISTRY_FILE>
```

If `--master` is omitted, the same key is pinned as both
master and operational. **Convenience for development and
tests; production deployments must supply a distinct master
key** so rotations can be authorized.

## `aion registry rotate` (RFC-0028)

Mint a new operational epoch.

```bash
aion registry rotate \
    --author <AUTHOR_ID> \
    --from-epoch <N> \
    --to-epoch <N+1> \
    --new-key <KEY_ID> \
    --master-key <MASTER_KEY_ID> \
    --effective-from-version <V> \
    --registry <REGISTRY_FILE> \
    [--no-warn]
```

**Mechanics.** Builds a master-signed rotation record (see
RFC-0028) and applies it. Epoch `from_epoch` keeps its
existing window `[created_at_version, V)`; epoch `to_epoch` is
created with window `[V, ∞)`.

### Retroactive-invalidation warning

If `--effective-from-version V` matches the current active
epoch's `created_at_version`, epoch `from_epoch`'s window
collapses to `[V, V)` (zero length), and **every existing
v=V signature by this author becomes invalid** under the new
registry.

The CLI emits a stderr warning:

```text
⚠️  --effective-from-version 0 matches epoch 0's created_at_version.
    Epoch 0's window collapses to [0, 0); every existing signature
    by author 401001 at version 0 will fail verify under the new
    registry.
   Suggested fix: pass `--effective-from-version 1` (or higher) to
    leave existing v0 signatures valid, OR migrate to a growing-chain
    architecture (RFC-0035).
   Use `--no-warn` to suppress this message.
```

`--no-warn` suppresses the warning. Use it on growing-chain
architectures or in test harnesses where the smell is
intentional.

The warning is informational only — rotation still proceeds.

## `aion registry revoke` (RFC-0028)

Invalidate an epoch from a target version onward.

```bash
aion registry revoke \
    --author <AUTHOR_ID> \
    --epoch <N> \
    --reason <compromised|superseded|retired|unspecified> \
    --master-key <MASTER_KEY_ID> \
    --effective-from-version <V> \
    --registry <REGISTRY_FILE>
```

After revocation, signatures by author `A` with epoch `N` at
version `>= V` no longer resolve. Signatures at version `< V`
remain valid (append-only history).

## How the registry serializes

The on-disk format is JSON. Each author entry carries:

- `master_key` — base64 32-byte verifying key
- `epochs[]` — every epoch with `epoch`, `public_key` (base64),
  `active_from_version`, and an explicit `status` (`active` /
  `rotated` / `revoked`)
- `revocations[]` — for each revoked epoch: `epoch`, `reason`,
  `effective_from_version`

The `status` field was added (PR #46) so an auditor diffing
two registry files sees at a glance which keys are still in
force without reconstructing the implicit Rotated state from
epoch ordering. The in-memory status is reconstructed
independently, so a malformed JSON cannot elevate a rotated
key back to active.

## Worked example: rotate after a staff departure

```bash
# Pin the original CCO.
aion registry pin --author 50001 --key 50001 --master 150001 \
    --output registry.json

# CCO leaves at chain version 8. Mint a new operational key
# for the successor.
aion key generate --id 50002

# Rotate. effective_from_version=9 means signatures at v1..v8
# under the OLD key keep verifying; v9 onward requires the NEW
# key. (The smell warning does NOT fire here — V > created_at.)
aion registry rotate \
    --author 50001 \
    --from-epoch 0 --to-epoch 1 \
    --new-key 50002 \
    --master-key 150001 \
    --effective-from-version 9 \
    --registry registry.json

# Successor commits v9 using the new key.
aion commit policy.aion --author 50001 --key 50002 \
    --rules new-rules.yaml \
    --message "Successor's first amendment" \
    --registry registry.json
```

The pre-#37 history (v1..v8) still verifies under the
post-rotation registry because epoch 0's window is `[0, 9)`
and every old signature is at a version inside that window.
