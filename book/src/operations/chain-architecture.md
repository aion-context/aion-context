# Chain Architecture: per-file vs growing-chain

The single most consequential operational choice when
deploying aion-context. Get it right at the start; migration
is mechanical but lossy.

[RFC-0035] in the repo is authoritative — this page is the
operator-facing summary.

## The two architectures

```text
Per-file genesis:                     Growing chain:

  ./archive/                            ./governance/
    week-01.aion (v1)                     policy.aion
    week-02.aion (v1)                       v1 (genesis)
    week-03.aion (v1)                       v2 (commit)
    ...                                     v3 (commit)
    week-13.aion (v1)                       ...
```

In **per-file genesis**, every file is its own chain starting
at v1. Files are cryptographically independent.

In **growing-chain**, every amendment chains to the last via
`parent_hash`. One file, monotonic version numbers, append-
only history.

## How to choose

Three diagnostic questions:

| Question | Per-file genesis | Growing chain |
|---|:---:|:---:|
| Will keys rotate annually or more often? | ❌ avoid | ✅ choose |
| Should a single event be verifiable in isolation (without the rest of the archive)? | ✅ favored | ⚠️ requires walking the chain |
| Is the chain itself the canonical timeline (rollback undesirable)? | ❌ no chain | ✅ append-only is the design |

**Rule of thumb:** if you'd rotate the signing key more than
once across the lifetime of the archive, choose growing-chain.
The rotation-incompatibility of per-file genesis is the
biggest practical gotcha aion-context has.

## Why per-file genesis breaks under rotation

A `KeyRegistry` pins exactly one operational epoch as active
at any given `(author, version)` pair. In per-file genesis,
every file is at v1.

When the operator rotates with `--effective-from-version V`:

| Choice of `V` | Pre-rotation v1 files | Post-rotation v1 files |
|---|:---:|:---:|
| `V = 1` | ❌ INVALID — epoch 0 window collapses to `[0, 1)` | ❌ INVALID — epoch 0 still active at v1 |
| `V = 2` | ✅ VALID — epoch 0's window is `[0, 2)` | ❌ INVALID — epoch 1's window starts at v2, not v1 |

There is no value of `V` that simultaneously preserves prior
v1 sigs AND admits new v1 sigs. The architecture fundamentally
cannot accommodate rotation while staying per-file genesis.

The CLI's `aion registry rotate` warns at rotation time when
the smell triggers (PR #52, issue #49). That's a band-aid —
the right fix is choosing growing-chain up front.

## Migration: per-file genesis → growing chain

When the per-file architecture has accumulated and the
operator now needs rotation:

```bash
# 1. The genesis file becomes v1 of the new chain.
cp week-01.aion governance.aion

# 2. For each subsequent week, commit its rules into the
#    chain. The operator running this loop is the current
#    holder of the signing key.
for week in 2 3 4 ... 13; do
    aion commit governance.aion \
        --author 50001 --key 50001 \
        --rules week-$week-rules.yaml \
        --message "(migrated from week-$week.aion)" \
        --registry registry.json
done

# 3. Verify.
aion verify governance.aion --registry registry.json

# 4. Archive the original per-file directory as evidence;
#    serve `governance.aion` as canonical going forward.
```

Lossy because the migration produces a *new* chain whose v1
is the original genesis but whose internal version-hash chain
is the new ground truth. The original per-file archive
remains as historical evidence but no longer the primary
verifiable artifact.

## Hybrid sharding

A middle path. Two patterns:

**Per-author chain.** Each signer has their own growing chain.
CCO commits flow into `cco-policy.aion`, Risk Officer commits
into `risk-policy.aion`. Rotation is per-author and clean.
Auditor walks both files with `aion archive verify`.

**Per-period chain.** Each calendar quarter is its own
growing chain: `2026-Q1.aion`, `2026-Q2.aion`. Rotation that
happens mid-quarter still has the per-file genesis problem
within that quarter, but quarters before and after are clean.

Hybrid is appropriate when:
- The chain shape needs to bound the file size, AND
- Concerns naturally separate per-author or per-period, AND
- Within-shard rotation is rare enough to tolerate.

## Verification across either architecture

**Per-file genesis:** use `aion archive verify <DIR>`. The
dashboard's Pass 2 surfaces rotation events as `⚙ ROTATED`
when more than one operational key for an author is observed
across the archive.

**Growing chain:** use `aion verify <FILE>`. The chain itself
is the timeline; rotation is invisible at the file level
because the registry handles epoch resolution per version.

## See also

- [RFC-0035] in `rfcs/` — protocol-level details, alternatives
  considered
- The CLI's [`registry rotate`](../cli/registry.md) page —
  the warning catches the most common operator mistake
- The CLI's [`archive verify`](../cli/archive.md) page —
  auditor-side dashboard

[RFC-0035]: https://github.com/aion-context/aion-context/blob/main/rfcs/RFC-0035-chain-architecture-guide.md
