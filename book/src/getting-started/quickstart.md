# Quick Start

Five minutes from cold install to a verified `.aion` file.

## Install

```bash
git clone https://github.com/aion-context/aion-context
cd aion-context
cargo install --path . --bin aion
```

`cargo install` puts the `aion` binary on your `PATH` from the
crate's source. Alternatively, build in-place:

```bash
cargo build --release --bin aion
# binary at ./target/release/aion
```

## Generate keys

The crate uses Ed25519 throughout. Each signer has two keys:

- a **master key** that authorizes rotations and revocations
- an **operational key** that signs day-to-day amendments

```bash
aion key generate --id 50001  --description "operational key"
aion key generate --id 150001 --description "master key (rotates op keys)"
```

Key IDs are arbitrary numeric strings used by the keystore. The
CLI stores secret keys in the OS keyring (or a fallback file
keystore on systems without one); public bytes are printed at
generation time.

## Pin a registry

A `KeyRegistry` is a JSON file that pins, for each AuthorId, the
master key plus the active operational-key epoch. Verifiers use
it to resolve which key was active at which version.

```bash
aion registry pin \
    --author 50001 \
    --key 50001 \
    --master 150001 \
    --output registry.json
```

The CLI is per-author, so building a registry with multiple
signers is several `pin` invocations against the same file.

## Initialize and commit

`init` creates a new `.aion` file with a v1 genesis. The author
ID written into the file should match what's pinned in the
registry.

```bash
echo "threshold: 75%" > rules.yaml

aion init policy.aion \
    --author 50001 \
    --key 50001 \
    --rules rules.yaml \
    --message "Genesis policy"
```

Subsequent amendments use `commit`, which requires the registry
(it pre-checks that the supplied signing key matches the active
epoch's pinned operational key for the author at the new
version):

```bash
echo "threshold: 80%" > rules-v2.yaml

aion commit policy.aion \
    --author 50001 \
    --key 50001 \
    --rules rules-v2.yaml \
    --message "Tighten threshold" \
    --registry registry.json
```

## Verify

```bash
aion verify policy.aion --registry registry.json
```

Output:

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

Exit code is `0` for VALID, `1` for any failure — the contract
is type-level enforced (see [RFC-0023 / issue #23] for details).

## What's next

- The [Mental Model](./mental-model.md) chapter explains *why*
  the pieces fit together this way.
- The [CLI Reference](../cli/README.md) covers every subcommand.
- The [Operations](../operations/chain-architecture.md) section
  is for production deployment: how to choose an archive layout,
  rotate keys without tears, and run audits.

[RFC-0023 / issue #23]: https://github.com/aion-context/aion-context/issues/23
