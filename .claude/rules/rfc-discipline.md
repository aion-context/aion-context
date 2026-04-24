# RFC Discipline

`aion-context` is RFC-driven. At extraction time, the `rfcs/` tree
holds 20 RFCs covering architecture, file format, crypto primitives,
regulatory compliance, multisig, audit chain, and related subjects.

Non-trivial additions get an RFC **before** the code. This is not
bureaucracy — it's how a crypto-heavy, security-sensitive codebase
stays coherent across contributors and across years.

## What needs an RFC

- A new field in the on-disk file format.
- A new audit-log field or privacy category.
- A new crypto primitive (key type, hash function, cipher).
- A new compliance framework in `src/compliance/`.
- A new export format in `src/export/`.
- Any change to versioning / replay semantics.
- Any change that breaks on-disk compatibility with prior format
  versions.

## What does NOT need an RFC

- Bug fixes with clear scope.
- Performance improvements that preserve the public API.
- Refactors that don't change observable behavior.
- New tests, new benches, new examples.
- Documentation improvements.
- CI / tooling changes (including this `.claude/` tree).

When in doubt, ask in the PR description. "Does this need an RFC?"
is a reasonable question; forcing an RFC for every bug fix is
cargo-cult discipline.

## RFC lifecycle

```
draft → proposed → accepted → implemented → superseded
```

- **draft**: PR adds a new `RFC-NNNN-<slug>.md` marked `status:
  draft`. No implementation yet.
- **proposed**: RFC is ready for review. Open as a PR tagged `rfc`.
- **accepted**: Merged RFC with `status: accepted`. Implementation
  can start on its own branch.
- **implemented**: After the implementation PR merges, update the
  RFC's status field in a small follow-up PR.
- **superseded**: When a later RFC replaces this one, link it and
  mark superseded; do NOT delete historical RFCs.

## Format

Look at `rfcs/RFC-0002-file-format.md` for the canonical
template. Required sections:

1. Frontmatter: `id`, `title`, `status`, `author`, `date`.
2. **Summary** — one-paragraph abstract.
3. **Motivation** — the problem, the cost of not solving it.
4. **Design** — the proposed change in technical detail.
5. **Alternatives** — at least two; "do nothing" is often one.
6. **Unresolved questions** — be honest. A clean "unresolved
   questions" section is a red flag, not a green one.
7. **References** — prior art, related RFCs, source papers.

The `rfc-writer` agent can scaffold an RFC matching this template.
Run `/rfc-new "<title>"` or invoke the agent directly.

## Numbering

- `rfcs/RFC-NNNN-<slug>.md` — four-digit, zero-padded,
  globally unique within the crate's RFC dir.
- Skipping numbers is fine if a draft never merges; leave the gap.
- **Do not renumber** an RFC after it lands, even if numbers are
  non-contiguous.

## RFCs and this `.claude/` tree

Major changes to `.claude/rules/*.md` or to the hook/agent
architecture should reference or produce an RFC. Renaming a rule
file, adding a new agent — not RFC-worthy. Rewriting the crypto
rule, removing a hard block — RFC-worthy.
