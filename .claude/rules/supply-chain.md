# Supply Chain

A governance product with questionable dependencies is not a
governance product. Every crate in the aion-context dependency graph is a
party we've chosen to trust — license, maintainership, security
posture. This rule captures how we manage that trust.

## Enforced by

| Tool             | What it catches                                                 | Where                       |
|------------------|-----------------------------------------------------------------|-----------------------------|
| `cargo-deny`     | License violations, banned crates, sketchy sources, advisories  | `deny.toml` at repo root    |
| `cargo-audit`    | RUSTSEC vulnerabilities in the current `Cargo.lock`             | `/quality-gate`             |
| SBOM drift       | New deps / bumped deps / removed deps vs committed baseline     | `.claude/drift/sbom.json`   |

Run all three via `/supply-chain-audit`.

## License allowlist

Apache-2.0, MIT, BSD-2/3-Clause, ISC, Unicode-3.0, Zlib, CC0-1.0,
CDLA-Permissive-2.0, MPL-2.0, BSL-1.0. Anything else needs an
explicit `[[licenses.clarify]]` block in `deny.toml` with a
rationale, or we pick a different crate.

**Forbidden by default**: GPL-family (viral copyleft), AGPL, SSPL
(SaaS restriction), CC-BY-SA, "custom" / unlicensed crates.

## Source allowlist

- `crates.io` — default, fine.
- Anything else — `deny`. Add to `deny.toml [sources] allow-git`
  only with a written rationale. aion-context currently has **zero** git
  dependencies; if you add one, document why it isn't on crates.io
  and what the plan is to get it there.

## Advisory policy

Every entry in `deny.toml [advisories] ignore` is a tax the next
maintainer pays. Format:

```toml
ignore = [
    { id = "RUSTSEC-YYYY-NNNN", reason = "plain-language justification; how/when we plan to remove" },
]
```

Review this list at every dep-bump PR. Entries older than six months
without progress are red flags — either the dep graph has a real
problem or the justification has drifted.

## The SBOM

`.claude/drift/sbom.json` is a committed snapshot of the dependency
closure. It tracks: package name, version, source, license.
Regenerate only from a clean `main`:

```bash
git checkout main && git pull
bash .claude/drift/generate_sbom.sh > .claude/drift/sbom.json
git add .claude/drift/sbom.json
git commit -m "chore(supply-chain): refresh SBOM"
```

Drift concerns, in order of severity:

1. **New package appeared.** A PR is pulling in a new dependency.
   Ask: is it necessary? Is the license allowed? Is the maintainer
   alive? Is there a lighter alternative?
2. **Version bumped.** Major versions especially. Run the full test
   suite + benches + `cargo audit` before approving.
3. **Source changed.** A crate switched from crates.io to a git
   fork. This is almost always worth investigating — it's how
   typosquatting and maintainer-takeover attacks work.
4. **Package removed.** No action required beyond a sanity check.

## When you add a dependency

1. Search existing deps: is someone already pulling in something
   that covers your need? Adding a duplicate-purpose crate is waste.
2. Confirm license is on the allowlist. If not, either pick a
   different crate or open a PR to add the license with
   justification.
3. Check RUSTSEC for known issues. If there are any, handle them
   explicitly (ignore with reason, or choose a different crate).
4. Prefer crates where the maintainer is active in the last 12
   months (check their commit history, not just the version date).
5. Run `cargo deny check` and `cargo audit` locally before pushing.

## Aion-v2-specific posture

The crypto dependencies (`ed25519-dalek`, `blake3`,
`chacha20poly1305`, `rand`, `zerocopy`) are load-bearing. We do not
version-pin them loosely; major version bumps are RFCs and run
through the full `aion-context/fuzz` target suite before merge.

The LLM provider dependencies (`reqwest`) are the network attack
surface. Bumps here get extra scrutiny for TLS posture and redirect
handling.

## Commands

```bash
cargo deny check              # licenses + bans + advisories + sources
cargo deny check advisories   # just RUSTSEC
cargo audit                   # RUSTSEC in Cargo.lock
bash .claude/drift/generate_sbom.sh > .claude/drift/sbom.json
/supply-chain-audit           # run them all and diff against baseline
```

## Cargo.lock

Workspace `Cargo.lock` is committed (it's already present at
`/home/ops/Project/aion-context/Cargo.lock`). This is correct for a
workspace that ships binaries (`aion` CLI, orchestrator) — a
committed lockfile makes `cargo audit` results deterministic across
checkouts. Do not add `Cargo.lock` to `.gitignore`.
