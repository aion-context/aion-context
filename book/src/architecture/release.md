# Sealed Releases (RFC-0032)

A sealed release is the top-level supply-chain object: one
operation that produces a manifest of artifacts, an AIBOM,
SLSA v1.1 provenance, three DSSE envelopes, an OCI primary
manifest, two OCI attestation referrers, and three
transparency-log entries — all cryptographically cross-linked
and signed by a single signer at a single version.

If `verify_file` answers "is this governance file untampered,"
`SignedRelease::verify` answers "is this **release** —
manifest + AIBOM + SLSA + OCI graph + log entries —
internally consistent under the registry, with all the
linkages intact."

## What gets sealed

```text
ReleaseBuilder::seal()
        │
        ├── ArtifactManifest          (RFC-0022)
        │      └── primary + auxiliaries, each with hash + size
        │
        ├── SignatureEntry over the manifest
        │
        ├── DsseEnvelope wrapping the manifest signature
        │
        ├── AiBom                     (RFC-0029)
        │      └── frameworks, datasets, licenses,
        │           safety attestations, export controls
        │
        ├── DsseEnvelope wrapping the AIBOM
        │
        ├── InTotoStatement (SLSA v1.1)   (RFC-0024)
        │      └── subjects (from manifest entries)
        │      └── builder.id, externalParameters
        │
        ├── DsseEnvelope wrapping the SLSA statement
        │
        ├── OciArtifactManifest       (RFC-0030)
        │      └── primary artifact descriptor
        │      └── config descriptor
        │
        ├── OciArtifactManifest (AIBOM referrer)
        │      └── subject ← primary digest
        │
        ├── OciArtifactManifest (SLSA referrer)
        │      └── subject ← primary digest
        │
        └── 3 × LogSeq
               └── (manifest sig, DSSE envelope, SLSA stmt)
                    appended to the transparency log
```

The whole bundle is the unit of signing. A `SignedRelease`
ties it together with one `signer: AuthorId` and verifies
under one registry epoch.

## What `SignedRelease::verify` checks

Eight gates, all must pass:

1. The manifest signature against the pinned registry epoch.
2. The manifest DSSE envelope's keyids against the registry.
3. The AIBOM DSSE envelope's keyids against the registry.
4. The SLSA DSSE envelope's keyids against the registry.
5. The AIBOM `model.hash` and `model.size` match the
   manifest's first (primary) entry.
6. SLSA subjects' digests are a subset of the manifest's
   entries' digests.
7. Both OCI referrer manifests' `subject.digest` match the
   primary manifest's digest.
8. The three log entries appear in the expected kind order:
   ManifestSignature, DsseEnvelope, SlsaStatement.

## Programmatic shape

```rust
use aion_context::release::{ReleaseBuilder, SignedRelease};

let mut builder = ReleaseBuilder::new("acme-7b-chat", "0.3.1", "safetensors");
builder.primary_artifact("model.safetensors", weights);
builder.add_framework(framework);
builder.add_license(license);
builder.add_safety_attestation(attestation);
builder.builder_id("https://ci.example/run/1");
builder.current_aion_version(1);

let signed: SignedRelease = builder.seal(signer, &signing_key, &mut log)?;
signed.verify(&registry, 1)?;
```

For reconstructing a release from disk (e.g., after the CLI
serialised it through `aion release seal`):

```rust
use aion_context::release::{SignedRelease, SignedReleaseComponents};

let release = SignedRelease::from_components(SignedReleaseComponents {
    signer,
    model_ref,
    manifest,
    manifest_signature,
    manifest_dsse,
    aibom,
    aibom_dsse,
    slsa_statement,
    slsa_dsse,
    oci_primary,
    oci_aibom_referrer,
    oci_slsa_referrer,
    log_entries,
});
release.verify(&registry, at_version)?;
```

The `SignedReleaseComponents` struct (PR #47) replaced an
earlier 13-positional-argument signature; named-field
construction makes argument transposition a compile error.

## CLI surface

The CLI's `aion release seal / verify / inspect` page
documents the operator-facing wrappers. The CLI's bundle
format (`release.json` + `primary.bin`) is one of several
valid distributions; consumers that prefer cosign-friendly
per-component layouts can produce them programmatically by
serialising each component directly (each has its own
`to_json` method).

## See also

- RFC-0032 in `rfcs/` — protocol details
- `examples/aegis_consortium.rs` (sort of related — uses
  multisig but not full sealed-release flow)
- The Nimbus driver in this conversation's history (and the
  earlier `/tmp/nimbus-release-demo` directory in the agent's
  scratch space) — full sealed-release programmatic example
