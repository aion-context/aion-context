# vs. Other Supply-Chain Crypto Tools

`aion-context` lives in a niche the existing ecosystem doesn't fill:
**signed, versioned, append-only document/policy files** that
carry their own audit chain. Most of the well-known tools in this
space target *artifacts* (containers, binaries, blobs); a few
target *attestations*; one targets *frameworks*. None of them
ship a self-contained file format with growing-chain provenance
of evolving content.

This page sets the contrast. The tone is neutral — sigstore,
in-toto, SLSA, and the rest are excellent at what they're built
for, and most consumers will use both.

## vs. Sigstore / cosign

[Sigstore](https://www.sigstore.dev/) signs **artifacts**
(container images, blobs, files) using ephemeral keys backed by
Fulcio (CA) and OIDC identity, with public records in the Rekor
transparency log. The key innovation is *keyless* signing — you
don't manage long-lived keys; you sign with a short-lived cert
tied to your OIDC identity at signing time.

| | sigstore / cosign | aion-context |
|---|---|---|
| Primary artifact | container images, files, blobs | versioned policy / spec / document files |
| Key management | ephemeral via Fulcio + OIDC | long-lived author keys, registry-pinned |
| Trust root | Fulcio CA + Rekor log | per-deployment registry JSON |
| Versioning | external (one signature per blob) | first-class — chain inside the file |
| Audit log | external (Rekor) | inside the file |
| Network at sign / verify time | Fulcio + Rekor (online) | offline by default |

**When to use which.** Sigstore for "did this binary come from a
trusted CI run?". `aion-context` for "did this policy say what it
says now? what did it say six months ago? who signed off then?"

## vs. in-toto

[in-toto](https://in-toto.io/) defines a layout for software-
supply-chain **attestations** — each step (source → build → test →
publish) emits a signed link. It's the format underneath much of
the SLSA tooling. The crate emits in-toto Statements (RFC-0024) for
sealed releases.

| | in-toto | aion-context |
|---|---|---|
| Scope | attestation format for build steps | self-contained file with hash chain |
| Granularity | one link per pipeline step | one version per logical change |
| Storage | links sit alongside the artifact | history sits inside the file |
| Use case | proving how a binary was built | proving what a policy said over time |

**When to use which.** in-toto inside CI, attesting that the binary
you produced went through certain steps. `aion-context` for content
that *evolves* (policies, specs, regulatory text) and where each
version's provenance matters indefinitely.

## vs. SLSA

[SLSA](https://slsa.dev/) (Supply-chain Levels for Software
Artifacts) is a **framework**, not a tool — it defines requirements
(build provenance, source integrity, isolation, etc.) at four
ascending levels. Tools like in-toto + sigstore implement SLSA;
`aion-context` emits SLSA v1.1 Statements as part of sealed releases
(RFC-0024).

**When to use which.** SLSA tells you the *bar* a build pipeline
should clear. `aion-context` is one of the *tools* that helps you
prove you cleared it for a specific class of artifact (signed
policy / context files), and produces SLSA Statements you can ship
alongside.

## vs. git-lfs / DVC

[git-lfs](https://git-lfs.com/) and [DVC](https://dvc.org/) version
**bytes** — they store large or binary files outside git proper and
content-address them. They don't sign anything; their guarantee is
"the bytes you check out are the bytes someone committed."

| | git-lfs / DVC | aion-context |
|---|---|---|
| What it stores | the historical bytes of every version | latest bytes + hash-chained signatures of every version |
| Signing | none built-in | required, every version |
| Verification | "matches the LFS pointer / DVC hash" | "matches a signed chain rooted in a pinned registry" |
| Tamper evidence | of bytes vs. expected hash | of the whole chain — flipping any byte breaks `verify` |

**When to use which.** git-lfs / DVC for archival of large bodies
of bytes. `aion-context` when you need *cryptographic* tamper-
evidence and provenance — and you're willing to keep historical
bytes in an external store keyed by `rules_hash` (see the
[file-format chapter](./architecture/file-format.md)'s
"Provenance, not archival" section).

## vs. blockchain / public timestamping

A blockchain (or a public timestamping service like
[OpenTimestamps](https://opentimestamps.org/)) gives you global,
public, costly proof that a hash existed before time T. The cost
comes from the consensus / inclusion process; the value comes from
the public-readable nature of the trust root.

| | blockchain / OpenTimestamps | aion-context |
|---|---|---|
| Trust root | global consensus | per-deployment registry |
| Cost per proof | non-trivial (gas / inclusion delay) | local + free |
| Privacy | public on-chain | private; bytes stay local |
| Suitability for evolving policy | poor (every change is a fresh chain entry) | good (chain lives in the file) |

**When to use which.** Blockchain / OpenTimestamps when you need
*public* proof a hash existed at time T against an adversary who
controls every party including yourself. `aion-context` when the
trust boundary is bilateral or multilateral but bounded — a
consortium, a regulated supply chain, a federation of orgs — and
the parties have already agreed on a registry.

## Where they overlap, on purpose

`aion-context` deliberately *plays well* with each of these:

- A sealed release (RFC-0032) emits **SLSA Statements** wrapped in
  **DSSE envelopes** (RFC-0023, RFC-0024) — directly compatible
  with the sigstore / in-toto ingestion paths.
- The **transparency log** (RFC-0025) is RFC 6962-compatible; STHs
  can be cross-witnessed by external services.
- **Content addressing** by `rules_hash` means historical payloads
  can be archived in S3, IPFS, or git-lfs alongside the chain.

The intent is not to replace the existing supply-chain stack. It's
to fill the policy / document gap with a self-contained format
that doesn't force operators to redeploy a registry every time
their policy changes.

## Quick chooser

| If you need… | Reach for… |
|---|---|
| Signed container images | sigstore / cosign |
| CI build provenance | in-toto + sigstore |
| A bar to clear for software supply chain | SLSA + the above |
| Versioning of large data files | git-lfs / DVC |
| Public timestamping of a hash | blockchain / OpenTimestamps |
| **Tamper-evident, hash-chained policy / spec / document files with their own audit log** | **aion-context** |
