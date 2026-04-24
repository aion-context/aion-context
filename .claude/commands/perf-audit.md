---
description: Run the aion-context criterion benches and compare medians against .claude/drift/perf_baseline.json.
argument-hint: [--init]
---

Measure the canonical operations and surface regressions against the
committed perf baseline.

Current scope: `benches/*`.

## `--init` mode

If invoked as `/perf-audit --init`, run `cargo bench`, parse the
medians, and write a new `.claude/drift/perf_baseline.json`.
**Only do this from a clean `main`.** Refuse if `git status --porcelain`
is non-empty or the current branch is not `main`.

## Default mode

Steps:

1. Confirm the baseline exists: `.claude/drift/perf_baseline.json`. If
   missing, stop and tell the user to run `/perf-audit --init` from a
   stable host.

2. Run the benches:

   ```bash
   cargo bench > /tmp/bench.out 2>&1
   ```

3. Extract median latencies. Criterion formats each result as
   `time: [lower median upper]`; take the center value and normalize
   to nanoseconds. The preceding `Benchmarking <NAME>: Analyzing`
   line gives the bench name. Pair them.

4. For every bench present in both the current run and
   `perf_baseline.json`, compute
   `delta_pct = (current - baseline) / baseline * 100`.

5. Classify:
   - `delta_pct ≤ -20`  → **FASTER** (informational)
   - `-20 < delta_pct ≤ 20` → **STABLE**
   - `20 < delta_pct ≤ 50`  → **SOFT** (warning)
   - `delta_pct > 50`       → **HARD** (regression)

6. Print a table sorted by |delta_pct| descending, showing name,
   baseline (ns), current (ns), delta (%), verdict. Also print any
   benches that exist in one side only.

Output format:

```
PERF AUDIT — aion-context (vs baseline)

| bench                               | baseline ns | current ns | Δ       | verdict |
|-------------------------------------|------------:|-----------:|--------:|---------|
| crypto/sign_ed25519                 |      94,120 |     94,350 |  +0.2%  | STABLE  |
| crypto/verify_ed25519               |     210,004 |    211,118 |  +0.5%  | STABLE  |
| parser/parse_header                 |         180 |        205 | +13.9%  | STABLE  |
...

Missing from current run: <name>
New vs baseline: <name>

VERDICT: NO REGRESSIONS | N SOFT | N HARD
```

If any verdict is HARD, list candidate culprit commits:
`git log --oneline -5 -- src/ benches/`.

Machine noise note: criterion measurements vary ~5% between runs on
the same machine, and 10–20% across machines. The ±20% soft threshold
is chosen to absorb that. HARD (>50%) is almost certainly a real
regression regardless of machine.

Do not modify files (except when `--init` is explicitly passed).
