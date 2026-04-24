---
description: Run every quality gate manually and report pass/fail with citations.
---

Execute all quality gates end-to-end on the current working tree. Use
this before pushing, after a big refactor, or when you suspect drift.

Run these in order. Stop on the first hard failure and report the rest
as "not run". For each step, record exit code and a one-line summary.

1. **Format** — `cargo fmt --check` (hard)
2. **Clippy** — `cargo clippy --all-targets -- -D warnings` (hard)
3. **Panic scan** — grep for
   `\.unwrap\(\)|\.expect\(|panic!\(|todo!\(|unreachable!\(` in `src/`,
   excluding comment lines and `#[cfg(test)]` modules. Compare against
   `.claude/drift/baseline.json` — new hits are hard, existing hits are
   informational. (hard on increase)
4. **Function length** — run `/tiger-audit` logic: flag any function
   body > 60 lines. Compare against baseline's `max_fn`; increase is
   hard. (hard on increase)
5. **Tests** — `cargo test` (hard)
6. **Supply chain** — `cargo deny check` (hard on any error) and
   `cargo audit` (hard on new vulnerabilities not in
   `deny.toml [advisories] ignore`). Skip with WARN if either tool is
   not installed. (hard)
7. **Doc build** — `cargo doc --no-deps --quiet` (soft)
8. **Drift** — compare `bash .claude/drift/generate.sh` output to
   `.claude/drift/baseline.json`. Panic-count regression, test-count
   regression, and `max_fn` regression are hard; anything else is
   soft.
9. **Branch policy** — if on `main`/`master` or a non-conforming
   branch, warn.

Output format:

```
QUALITY GATE — aion-context
[✓] fmt          — clean
[✓] clippy       — no warnings
[✗] panic scan   — +1 hit vs baseline: src/operations.rs:217 expect(
[·] fn length    — not run
...
VERDICT: FAIL (1 hard failure, 2 soft warnings)
```

Verdict strings: `MASTERPIECE`, `FAIL (N hard)`, or
`HOLD (0 hard, N soft)`.

If the baseline is missing, tell the user:
`bash .claude/drift/generate.sh > .claude/drift/baseline.json`
from a clean main before the drift comparison can run.
