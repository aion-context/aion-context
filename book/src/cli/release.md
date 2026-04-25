# `release` (RFC-0032 sealed releases)

A sealed release is one operation that produces:

- An [`ArtifactManifest`](../architecture/file-format.md) over the primary artifact (and any auxiliaries)
- A signature over that manifest
- An [AIBOM](https://github.com/aion-context/aion-context/blob/main/rfcs/RFC-0029-aibom.md) record (frameworks, datasets, licenses, safety attestations, export controls)
- A SLSA v1.1 in-toto Statement
- Three [DSSE](https://github.com/aion-context/aion-context/blob/main/rfcs/RFC-0023-dsse-envelopes.md) envelopes (manifest, AIBOM, SLSA)
- An OCI primary manifest + two OCI attestation referrers
- Three transparency-log entries

All cryptographically cross-linked. RFC-0032 in the repo has
the protocol details; this page documents the operator surface.

## `aion release seal`

```bash
aion release seal \
    --primary <PATH>                       # raw model bytes
    --primary-name <NAME>                  # in-manifest name
    --model-name <NAME> --model-version <VERSION> \
    --model-format <FORMAT>                # safetensors / gguf / onnx / ...
    --framework <NAME:VERSION>             # repeatable
    --license <SPDX:SCOPE>                 # weights|source|data|docs|combined
    --safety-attestation <NAME:RESULT>     # repeatable
    --export-control <REGIME:CLASS>        # repeatable
    --builder-id <URI>                     # SLSA builder.id
    --aion-version <N> \
    --author <AUTHOR_ID> --key <KEY_ID> \
    --out-dir <DIR>
```

Output layout under `--out-dir`:

```text
release.json     # the bundle (single JSON file)
primary.bin      # copy of the primary artifact
```

The bundle is a single `release.json` that captures the entire
SignedRelease structure — manifest, signatures, DSSE envelopes,
OCI manifests, log entries — using the existing serde derives
on most types, with hex-encoded fields for the three zerocopy
types (`ArtifactManifest`, `SignatureEntry`, `LogSeq`).

## `aion release verify`

```bash
aion release verify \
    --bundle <DIR>                  # directory produced by `seal`
    --registry <REGISTRY_FILE>      # pins the signer
    --at-version <N>                # version number for registry epoch resolution
```

Reloads the bundle, reconstructs a `SignedRelease` via
`SignedRelease::from_components(SignedReleaseComponents { ... })`,
and runs `.verify(&registry, at_version)`. Exit code is `0` for
VALID, `1` for any failure (matches the [exit-code typestate
contract](./README.md#exit-code-contract)).

The verifier checks:

1. The manifest signature against the pinned registry epoch.
2. Each DSSE envelope's signatures against the same registry.
3. AIBOM model hash + size match the primary manifest entry.
4. SLSA subjects are a subset of the manifest entries.
5. OCI referrer subjects link to the primary manifest's digest.
6. The three transparency-log entry kinds appear in seal order.

## `aion release inspect`

Pretty-print a bundle summary without crypto verification.
Useful for "what's in this archive?" queries.

```bash
aion release inspect --bundle <DIR> [--format text|json|yaml]
```

Sample output (text):

```text
Release bundle: bundle/release.json
  signer:        900010
  model:         cirrus-7b-safety v0.3.1 (safetensors)
  model size:    4096 bytes
  model hash:    c7b3f3baf573f92b...  (BLAKE3-256)
  frameworks:    2
  licenses:      2
  safety atts:   2
  export ctrl:   1
  log entries:   3
```

## Worked example: end-to-end seal + verify

```bash
# Generate the operational key + a master key for the registry.
aion key generate --id 900010
aion key generate --id 1900010

# Pin the registry.
aion registry pin --author 900010 --key 900010 \
    --master 1900010 --output reg.json

# Synth a primary artifact (replace with real model bytes).
dd if=/dev/urandom of=model.safetensors bs=1024 count=4

# Seal.
aion release seal \
    --primary model.safetensors --primary-name model.safetensors \
    --model-name cirrus-7b-safety --model-version 0.3.1 \
    --model-format safetensors \
    --framework pytorch:2.3.1 \
    --license Apache-2.0:weights \
    --safety-attestation rlhf:PASS \
    --export-control US-EAR:EAR99 \
    --builder-id "https://ci.example/run/1" \
    --aion-version 1 \
    --author 900010 --key 900010 \
    --out-dir bundle/

# Verify.
aion release verify --bundle bundle/ --registry reg.json --at-version 1
# → ✅ VALID at version 1, exit 0

# Inspect.
aion release inspect --bundle bundle/
```

## Why a single bundle file (not a per-component layout)?

The CLI ships `release.json` as the unit of distribution.
RFC-0032 contemplates a per-component layout (separate files
for `manifest.dsse.json`, `aibom.dsse.json`, etc.) for
cosign / slsa-verifier interop; that's tracked as a future
issue.
