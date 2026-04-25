# Corpus → .aion — generic git-history replay tool

> Take any directory with a git history, walk every commit that
> touched a chosen subtree, and bind the entire evolution into a
> single signed `.aion` chain.

The example file is at `examples/corpus_to_aion.rs`. Gated behind
the `corpus-tool` feature so the default build doesn't pull in
`tar` / `flate2`. Shells out to `git` (no libgit2 C dependency).

```bash
cargo run --release --features corpus-tool --example corpus_to_aion -- \
  --repo /path/to/some-repo \
  --subtree relative/policy/dir \
  --filter '**/*.md' \
  --output /tmp/corpus.aion
```

## What it does

For each commit, in chronological order, that touched files
matching `--filter`:

1. `git checkout <sha>`
2. tarball `--subtree` (gzipped) — this becomes the version's
   rules payload
3. **first commit:** `init_file` (genesis); subsequent commits:
   `commit_version` → new VersionEntry, parent_hash chained, signed
4. emit a `tracing::info!(event="corpus_replay_step", …)` event
5. on commits where `--subtree` doesn't yet exist (early history,
   pre-refactor), `tracing::info!(event="corpus_replay_skipped", reason="no_subtree_at_commit")`
   and continue

At the end:

- restore the repo's HEAD to its original ref (unless `--keep-checkout`)
- `verify_file` against the in-process registry — fails the run if
  any guarantee is broken
- print summary: commits considered, versions written, commits
  skipped, total payload, final `.aion` size, sign+write time,
  average per version

## Case study — `isms-core-platform`

Real-world test: the
[isms-core-project/isms-core-platform](https://github.com/isms-core-project/isms-core-platform)
repo, an AGPL-3.0 ISMS framework with the four ISO/IEC 27001:2022
Annex A control families, ran end-to-end through the tool. The
artifact stayed local — only the metrics ship.

```bash
git clone https://github.com/isms-core-project/isms-core-platform /tmp/isms-recon
cargo run --release --features corpus-tool --example corpus_to_aion -- \
  --repo /tmp/isms-recon \
  --subtree isms-core-framework \
  --filter '**/*.md' \
  --output /tmp/isms-corpus.aion
```

| Metric | Value |
|---|---|
| Commits matched by filter | 92 |
| Commits skipped (no subtree) | 29 |
| Versions written | **63** |
| Per-commit payload | 4 MB → 14 MB gzipped tar |
| Final `.aion` size | **14 MB** |
| Total wall time | 67 s (mostly `git checkout` + `tar`) |
| Pure sign + write | 2.6 s |
| **Avg per version** | **41 ms** |
| Verify | ✅ structure, integrity, hash chain, signatures, 63 versions |

The pure cryptographic work — sign-and-write per version — is
~40 ms even on a 14 MB payload. The wall-time bottleneck is
`git checkout` of large trees, which is fundamental to the replay
strategy and not on the format's hot path.

## Provenance, not archival — what the resulting file holds

> **Important.** This deserves its own callout because it surprises
> first-time readers.

| Across 63 versions | Total raw payload | Final file size |
|---|---|---|
| ISMS-framework markdown corpus | 188 MB (sum of all per-version tarballs) | **14 MB** |

The `.aion` file is **not** an archive of all 63 historical payload
bodies. It carries:

- **one** encrypted_rules section (the **latest** commit's payload bytes)
- the **full hash-chained signature history**: every historical
  `rules_hash` is recorded in the version chain and signed

So the file proves *that* a particular byte sequence existed at
version V (because V's `rules_hash` is in the signed chain), but it
cannot reproduce that byte sequence on its own. To reconstruct any
past version's content, the operator pairs the `.aion` with an
external content-addressed store keyed by `rules_hash`:

| Where the bytes live | Where the proof of authenticity lives |
|---|---|
| S3 / IPFS / git-LFS / a transparency-log archive | the `.aion` file |
| addressed by `rules_hash` | which signs every `rules_hash` |

This is **provenance-preserving, not content-archival**. It's the
right shape for most use cases — the file stays small, every
version is cryptographically pinned, and storage is the consumer's
choice — but it's a property to know up front. The
[file-format chapter](../architecture/file-format.md) has the
byte-level statement of this property.

## Output sample

```text
=== corpus_to_aion ===
repo:      /tmp/isms-recon
subtree:   isms-core-framework
filter:    **/*.md
output:    /tmp/isms-corpus.aion
author:    27001

commits to replay: 92
  --   29f6a00a  2026-01-30  skipped (reason=no_subtree_at_commit)
  --   96433d8f  2026-01-30  skipped (reason=no_subtree_at_commit)
  ...
  v01  a312a853  2026-02-07  payload=  4224 KB  elapsed=  12 ms  refactor: split repo into ...
  v02  b27e0526  2026-02-07  payload=  4224 KB  elapsed=  16 ms  fix: update A.7.10 name to ...
  ...
  v63  f66f9643  2026-04-20  payload= 13963 KB  elapsed=  48 ms  feat(platform): NCSC CAF v4.0 ...

=== summary ===
commits considered:      92
versions written:        63
commits skipped:         29
total payload (gzipped): 725047 KB
final .aion file size:   13989 KB
total wall time:         67391 ms
sign + write time:       2598 ms
average per version:     41 ms

=== verifying the resulting .aion ===
is_valid:               true
version_count:          63
```

## Other things you can replay

The tool is intentionally generic — anything stored as files with
git history works:

- **Compliance frameworks** — ISMS, SOC 2 controls, HIPAA policy
  trees (the case study above)
- **Regulatory text** — GDPR / DORA / NIS2 reference material
  living in markdown
- **Internal policies** — security posture, code-of-conduct, AUP
- **Specifications** — RFC drafts, IETF / W3C working group repos
- **Curriculum** — course materials with versioned syllabi

The contract: a directory with `*.md` (or any other byte-stable
content) + a git history that documents how it changed over time.
The tool produces a single tamper-evident artifact you can hand to
any verifier alongside an external blob store keyed by the
`rules_hash` chain.

## License boundary

Whatever you replay carries its source license through into the
encrypted payload. The tool itself ships under MIT/Apache-2.0; the
artifact you produce inherits the upstream's license. For AGPL or
other copyleft sources, do the experiment locally — the resulting
`.aion` cannot be redistributed under MIT/Apache-2.0 without
respecting the upstream's terms.
