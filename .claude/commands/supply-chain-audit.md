---
description: Run cargo-deny, cargo-audit, and SBOM drift for aion-context.
---

Inventory the dependency graph and flag anything that changed or went
bad. Read-only.

## Steps

1. **cargo-deny**: `cargo deny check` — licenses, bans, advisories,
   sources. If `deny.toml` does not exist, tell the user to create one
   from the template in `.claude/rules/supply-chain.md` and stop. Fail
   summary: count errors in each category. Surface any *new* advisory
   that isn't in `deny.toml [advisories] ignore`.

2. **cargo-audit**: `cargo audit`. Fail summary: count vulnerabilities
   and unmaintained warnings. Distinguish between:
   - **Vulnerability** — actionable, must be addressed.
   - **Unmaintained** — informational; verify it's in the advisory
     ignore list with a dated reason.

3. **SBOM drift**: run `bash .claude/drift/generate_sbom.sh` into a
   temp file, diff against `.claude/drift/sbom.json`. If the baseline
   sbom.json is missing, tell the user to generate it from clean main
   and stop. For each delta:

   - **Added package** (name not in baseline) — investigate: why is
     this new? Is the license on our allowlist? Is the source
     trusted?
   - **Removed package** — usually benign; sanity-check it wasn't a
     dep we meant to keep.
   - **Version bumped** — flag minor bumps for review, major bumps
     for thorough review including tests + benches + audit.
   - **Source changed** — almost always worth investigating.
   - **License changed** — flag for review even if the new license
     is on the allowlist.

4. **Cargo.lock**: `Cargo.lock` is committed at the repo root.
   Confirm it exists; if missing, that's a reproducibility
   regression.

## Output format

```
SUPPLY-CHAIN AUDIT — aion-context

[deny]   advisories ok, bans ok, licenses ok, sources ok
[audit]  2 vulnerabilities, 5 unmaintained (all in ignore list)
[sbom]   baseline 345 packages, current 349 — 4 added, 0 removed, 0 bumped

Added packages:
  - new-crate v1.2.3 (MIT) from crates.io
    pulled in by: aion-context -> some-parent v0.3

Version bumps (baseline -> current):
  - tokio 1.45.0 -> 1.46.0  (patch)

Removed packages:
  (none)

VERDICT: CLEAN | N issues (N actionable, M informational)
```

## Severity

- **Actionable** (fails the gate):
  - cargo-deny error in any category
  - cargo-audit vulnerability NOT listed in `deny.toml` ignore
  - SBOM added package with banned license
  - SBOM source change to an unknown git URL

- **Informational** (warning):
  - cargo-audit unmaintained listings
  - SBOM version bumps
  - SBOM added packages with allowed licenses

## Rules

- Do NOT modify `deny.toml` to silence a finding from inside this
  command. That's a separate, reviewed PR.
- Do NOT update dependencies to fix a vulnerability from inside this
  command. Recommend the `cargo update -p <crate>` and stop.
- Do NOT commit the regenerated SBOM here — that's also a separate,
  reviewed PR via the workflow in `supply-chain.md`.

Read-only audit. Never modify files.
