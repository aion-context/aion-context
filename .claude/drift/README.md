# Masterpiece Drift

This directory holds the frozen snapshots that represent "the current
best state of the codebase". Drift checks compare live code against
these snapshots; any regression blocks.

## Files

| File              | Generator                 | What it captures                                      |
|-------------------|---------------------------|-------------------------------------------------------|
| `baseline.json`   | `generate.sh`             | Panics, tests, max function length, public surface, LOC per crate |
| `sbom.json`       | `generate_sbom.sh`        | Dependency closure: name, version, source, license    |
| `perf_baseline.json` | `cargo bench` + jq    | Criterion median per bench                            |

None of these files are committed initially. **You generate them from
a clean `main`** once the crate compiles and tests pass.

## First-time setup

```bash
# from clean main, with a green cargo test:
git checkout main && git pull
cargo test

bash .claude/drift/generate.sh      > .claude/drift/baseline.json
bash .claude/drift/generate_sbom.sh > .claude/drift/sbom.json

git add .claude/drift/baseline.json .claude/drift/sbom.json
git commit -m "chore(drift): establish masterpiece baseline"
```

`perf_baseline.json` comes later — run `/perf-audit --init` to
produce it from a fresh criterion run.

## When to refresh

- **baseline.json** — after a merge that intentionally changes the
  shape: new crate, intentional public API removal, a test cull.
  Refresh from clean `main` and commit in a dedicated chore PR with
  the rationale in the message.
- **sbom.json** — after any dependency add, remove, or version bump.
  See `.claude/rules/supply-chain.md`.
- **perf_baseline.json** — after an intentional perf-affecting
  change. The change itself and the baseline refresh go in the same
  PR so reviewers can see the numbers moved deliberately.

Never refresh a baseline from a dirty working tree. The whole point
is that it captures the state of `main`, not whatever's in progress.

## Drift checks

- **Per-turn** — `stop-drift-check.sh` runs automatically at the end
  of a Claude turn that touched Rust, reports regressions, does not
  block.
- **On demand** — `/drift-check` dumps the comparison.
- **CI** — (once wired) a GitHub Action should run the same
  comparison and fail the build on regressions.

## Regression categories

| Category            | Meaning                                       | Severity   |
|---------------------|-----------------------------------------------|------------|
| `panics`            | `unwrap/expect/panic!/todo!/unreachable!` count increased | HARD block |
| `tests`             | Test count decreased                          | HARD block |
| `max_fn`            | Longest function grew beyond baseline + 5     | HARD block |
| `pub_items`         | Public surface churned without a matching RFC | SOFT flag  |
| `loc`               | Crate size grew > 20% in one diff             | SOFT flag  |

Soft flags are for reviewer attention; hard blocks fail the gate.
