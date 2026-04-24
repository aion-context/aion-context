---
description: Report drift between the current working tree and the aion-context masterpiece baseline.
---

Run the masterpiece drift report against `.claude/drift/baseline.json`.

Steps:

1. Run `bash .claude/drift/generate.sh` and capture its JSON output.
2. Read `.claude/drift/baseline.json`. If missing, stop and tell the
   user to run:
   `bash .claude/drift/generate.sh > .claude/drift/baseline.json`
   from a clean `main`.
3. For each crate in the baseline, compare:
   - `panics` — must not increase.
   - `tests` — must not decrease.
   - `max_fn` — allowed +5 lines slop; anything larger is a
     regression.
   - `pub_items` — note additions as "surface growth"
     (informational).
   - `loc` — note delta (informational, not a failure condition).
4. Print a table with one row per crate, columns:
   `crate | loc Δ | panics Δ | tests Δ | max_fn | pub Δ | verdict`.
5. If any verdict is **FAIL**, list the exact file:line or symbol
   causing it (consult `/tiger-audit` output for panic hits).
6. End with one of: `MASTERPIECE HELD`,
   `DRIFT DETECTED (N regressions)`, or
   `BASELINE MISSING — generate from clean main`.

Do not write files. This is a read-only report.
