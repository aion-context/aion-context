---
description: Scaffold a new RFC under rfcs/ matching the existing aion-context RFC format.
argument-hint: "<title>"
---

Scaffold a new RFC with title `$ARGUMENTS`. Delegates to the
`rfc-writer` agent if the proposal is non-trivial.

Preconditions — fail and report if violated:

- `$ARGUMENTS` is a non-empty title string.
- `rfcs/` exists at the repo root.
- Current branch is NOT `main`/`master` (CLAUDE.md branch policy).

## Steps

1. **Find the next RFC number.** List files matching `rfcs/RFC-*.md`,
   extract the four-digit numbers, take the maximum + 1. Zero-pad to
   four digits.

2. **Read the reference RFC** to match style:
   `rfcs/RFC-0002-file-format.md`.

3. **Confirm RFC-worthiness** per `.claude/rules/rfc-discipline.md`.
   If the proposal is a bug fix, refactor, or doc change, stop and
   suggest a plain PR instead.

4. **Generate the slug** from `$ARGUMENTS`: lowercase, spaces → `-`,
   strip punctuation, trim to 40 chars.

5. **Delegate to the `rfc-writer` agent** with:
   - Target path: `rfcs/RFC-NNNN-<slug>.md`
   - Title: `$ARGUMENTS`
   - Status: `draft`
   - Author: `git config user.name` (fall back to `aion-team`)
   - Date: today (ISO 8601)
   - Reference RFC: `rfcs/RFC-0002-file-format.md`

6. After the agent writes the file, print:
   - The path created.
   - A reminder that the RFC is a draft; reviewers haven't seen it.
   - Next step: `git add <path> && git commit` on an
     `rfc/NNNN-<slug>` branch.

Do NOT start implementation. RFC and implementation are separate PRs.

## Output

```
RFC SCAFFOLD

Number:   RFC-0021
Slug:     canonical-timestamps
Path:     rfcs/RFC-0021-canonical-timestamps.md
Status:   draft (agent invoked)

Next steps:
  1. Review the draft — rfc-writer produces a first-pass skeleton.
  2. Fill in the "Design" and "Alternatives" sections.
  3. git checkout -b rfc/0021-canonical-timestamps
  4. git add rfcs/RFC-0021-canonical-timestamps.md
  5. git commit -m "docs: RFC-0021 canonical timestamps"
```
