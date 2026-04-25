# Key Rotation Playbook

Step-by-step guide for rotating an operational key without
breaking the existing archive.

Three scenarios, ordered by frequency:

1. Routine rotation on a growing-chain archive (the easy case)
2. Rotation on a per-file genesis archive (the bookend case)
3. Compromise-driven rotation (the urgent case)

## Scenario 1: Growing-chain rotation

The operator sees the rotation coming (annual cadence, staff
departure, security policy). The chain is at version `K`.

```bash
# 1. Generate the new operational key.
aion key generate --id 50002 --description "successor op key"

# 2. Mint the rotation. effective_from_version = K + 1.
aion registry rotate \
    --author 50001 \
    --from-epoch 0 --to-epoch 1 \
    --new-key 50002 \
    --master-key 150001 \
    --effective-from-version $((K+1)) \
    --registry registry.json

# 3. Successor signs the next commit using the new key.
aion commit policy.aion \
    --author 50001 --key 50002 \
    --rules new-amendment.yaml \
    --message "First amendment under successor" \
    --registry registry.json
```

After rotation:

- Signatures at versions `1..K` keep verifying under epoch 0.
- Signatures at versions `K+1..` use epoch 1.
- `aion verify policy.aion --registry registry.json` walks
  the whole chain and resolves the right epoch per version.

## Scenario 2: Per-file genesis rotation (the gotcha)

Every file is at v1. There is no clean rotation here — see
[chain-architecture](./chain-architecture.md) for the
underlying reason. Three options:

**Option A: Migrate to growing-chain first**, then rotate
under Scenario 1's playbook. This is the recommended path.
Migration steps in the chain-architecture page.

**Option B: Re-sign the entire archive under a fresh
registry.** Loses the rotation history but produces an
archive that verifies cleanly under one registry generation.

```bash
# 1. Generate the new key.
aion key generate --id 50002

# 2. Pin a fresh registry with the NEW key as epoch 0.
aion registry pin --author 50001 --key 50002 \
    --master 150001 --output registry-new.json

# 3. Re-sign every file. (Read each file's rules, re-init
#    under the new key.) This loses the original
#    timestamps and signatures — the new file is a fresh
#    genesis with the same rules content.
for week in 1 2 3 ... 13; do
    aion show "week-$week.aion" --registry registry.json rules \
        > "week-$week-rules.yaml"
    aion init "new-week-$week.aion" \
        --author 50001 --key 50002 \
        --rules "week-$week-rules.yaml" \
        --force
done
```

**Option C: Maintain multiple registries** (one per rotation
generation) and have downstream verifiers select the correct
one per file based on filename / date. Operationally painful;
documented for completeness.

## Scenario 3: Compromise-driven rotation

The operator believes the current operational key has been
exposed. Treat it as urgent: rotate AND revoke.

```bash
# 1. Mint the new key offline (different machine, no network).
aion key generate --id 50002

# 2. Apply the rotation (effective from the next version,
#    same as routine rotation).
aion registry rotate \
    --author 50001 \
    --from-epoch 0 --to-epoch 1 \
    --new-key 50002 \
    --master-key 150001 \
    --effective-from-version $((K+1)) \
    --registry registry.json

# 3. Apply a revocation marking epoch 0 compromised.
#    effective_from_version = K+1 means signatures at v1..K
#    using epoch 0 still verify (they were made before the
#    compromise was discovered); signatures at v=K+1 onward
#    using epoch 0 are rejected.
aion registry revoke \
    --author 50001 \
    --epoch 0 \
    --reason compromised \
    --master-key 150001 \
    --effective-from-version $((K+1)) \
    --registry registry.json

# 4. Distribute the updated registry through the same
#    out-of-band channel that handed it out originally.
#    Every verifier needs the post-revocation registry.

# 5. Audit the archive: did anything get signed AT OR AFTER
#    the suspected compromise time using the old key? If yes,
#    treat those amendments as suspect.
aion archive verify ./archive --registry registry.json
```

The revocation is a stronger statement than the rotation: it
says "this key is bad," not just "this key was rotated out."
Auditors reading the registry see the `Compromised` reason
and can adjust their trust posture for any signature made
under that epoch.

## Common mistakes

**Mistake 1: `--effective-from-version V` matches the active
epoch's `created_at_version`.** The CLI now warns. The
warning is informational; rotation still proceeds. Per-file
genesis archives hit this every time — see Scenario 2.

**Mistake 2: deleting the old operational key from the
keystore before rotation lands.** The rotation record needs
the master key, not the old operational key, but operators
sometimes confuse the two. Keep both keys until the
post-rotation registry is distributed and at least one
post-rotation signature has verified.

**Mistake 3: running `aion init` with the new key after
rotation.** `init` creates a new genesis at v1, not a v=K+1
amendment. Use `aion commit` for amendments to an existing
file.

## See also

- [The CLI's `registry rotate`](../cli/registry.md) page —
  every flag and the smell warning
- [Chain Architecture](./chain-architecture.md) — why
  Scenario 2 is the way it is
- [Auditor Workflow](./audit.md) — the receiving side of a
  rotation
