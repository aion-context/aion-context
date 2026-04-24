# aion-context

**Cryptographically-signed, versioned business-context file format.**
A single Rust crate that defines the on-disk `.aion` format and ships
a CLI (`aion`) for creating, signing, verifying, and exporting those
files.

This document is the authoritative guide for agentic work in this
repository. Rules in `.claude/rules/` are additive to this file.

## ABSOLUTE REQUIREMENTS

**These are non-negotiable. Violating any of them is a failure
condition.**

### Tiger Style / NASA Power of 10

Already enforced at the compiler level by `Cargo.toml`
(`unwrap_used = "deny"`, `expect_used = "deny"`, `panic = "deny"`,
`todo = "deny"`, `unreachable = "deny"`, `unimplemented = "deny"`,
`unsafe_code = "forbid"`). Do **not** loosen those lints without a
written rationale and a matching comment in `Cargo.toml`.

- **ZERO panics in production.** No `unwrap()`, `expect()`,
  `panic!()`, `todo!()`, `unreachable!()`.
- Use `Result<T, AionError>` with `thiserror` everywhere. One error
  enum, variants describe *what* failed, not *where*.
- **Maximum 60 lines per function body.** Measured from `fn` to the
  matching close brace. Split long functions; do not hide length in
  macros or generics.
- Every loop must have a termination condition visible at the loop
  site. No unbounded `loop {}` without a break reviewers can point
  at.

```rust
// FORBIDDEN
let value = some_option.unwrap();

// REQUIRED
let value = some_option.ok_or(AionError::MissingValue)?;
```

### No Tutorial Comments

- Code is self-documenting through naming.
- Comments are ONLY for: `/// doc`, `//! crate doc`, `// TODO(name):`,
  `// FIXME(name):`, `// SAFETY:`, or non-obvious **why**.
- Never explain what the code does. If a reader can't tell, rename.

### Crypto is sacred

`aion-context` ships an on-disk cryptographic file format. Changes
to signing, hashing, or hash-chain code are reviewed by the
`crypto-auditor` agent before merge. See `.claude/rules/crypto.md`.

- Do **not** roll your own Ed25519, BLAKE3, ChaCha20, or hash-chain
  linking. Use the existing `aion_context::crypto` primitives.
- Do **not** use `==` on `[u8]` for signatures, MACs, or keys — use
  `subtle::ConstantTimeEq` or the library's verify method.
- Every signed artifact carries `(author_id, version)`. Verifiers
  reject `(author, version)` pairs they have already accepted —
  replay is an attack, not an edge case.

### RFC discipline

Non-trivial additions — a new field in the on-disk file format, a
new audit-log privacy category, a new compliance framework, a new
crypto primitive — get an RFC before code. See
`.claude/rules/rfc-discipline.md` and the `rfc-writer` agent. 20 RFCs
already exist under `rfcs/`.

### Quality Gates

Four enforcement layers. If any blocks, the work does not ship.

| Layer    | Mechanism                                                      | Scope                             |
|----------|----------------------------------------------------------------|-----------------------------------|
| Rules    | `.claude/rules/*.md`                                           | authoritative reference           |
| Hooks    | `.claude/hooks/` wired in `.claude/settings.json`              | PreToolUse, PostToolUse, Stop     |
| Commands | `/tiger-audit`, `/quality-gate`, `/drift-check`, `/crypto-scan`| on-demand inspection              |
| Agents   | `rust-gatekeeper`, `crypto-auditor`, `api-reviewer`, etc.      | deep review, dispatched by scope  |

Hook summary:

- **`pre-edit-rust-gate`** — blocks writes to library `.rs` files
  that introduce `unwrap/expect/panic!/todo!/unreachable!` or a
  function body > 60 lines.
- **`post-edit-fmt-clippy`** — runs `cargo fmt` and `cargo clippy`
  after every Rust edit. Advisory unless `AION_STRICT_POST=1`.
- **`stop-drift-check`** — compares live tree to
  `.claude/drift/baseline.json` (once generated) and reports
  regressions.
- **`pre-commit-branch-name`** — refuses `git commit`/`git push` on
  `main`/`master` or on branch names that don't match the convention
  below.

Bypass (use sparingly, with a written reason in the commit message):

```
AION_SKIP_GATES=1 cargo test
```

### Masterpiece Drift

`.claude/drift/baseline.json` is the frozen snapshot of code quality
(panics, test count, longest function, public surface size). The
baseline is not committed initially — generate it from a clean
`main` with `bash .claude/drift/generate.sh > .claude/drift/baseline.json`
once the crate compiles cleanly. `/drift-check` and
`stop-drift-check` compare live code against it. Any regression in
panics, test count, function-length ceiling, or public surface is a
block.

### Observability (Cantrill)

The library instruments its public surface via `tracing`. Decisions
(accept / reject / verify / tamper) emit structured events at
`info!` or `warn!` with stable `event = "…"` discriminators. Signing
keys, raw signatures, and full payloads never appear in traces —
only sizes, hash prefixes, and bounded reason codes. See
`.claude/rules/observability.md`. The `aion` CLI binary initializes
the subscriber; the library itself must not.

### Supply chain

`deny.toml` at the repo root enforces license allowlist, banned
crates, and RUSTSEC advisories via `cargo-deny`. `cargo audit` runs
on every `/quality-gate`. `.claude/drift/sbom.json` is a committed
snapshot of the dependency closure; new deps, version bumps, and
source changes are diff-able against it. See
`.claude/rules/supply-chain.md` and run `/supply-chain-audit`.

### Branch Management Workflow

**Follow this exactly for every unit of work:**

1. **Start clean**: `git checkout main && git pull origin main`
2. **Create branch**: `git checkout -b <prefix>/<issue>-<short-desc>`
   - `feature/<issue>-<desc>` — new functionality
   - `fix/<issue>-<desc>` — bug fixes
   - `chore/<desc>` — tooling, CI, dep bumps
   - `docs/<desc>` — documentation only
   - `rfc/<number>-<short-title>` — RFC additions/edits
3. **Implement**: work through the issue or RFC acceptance criteria
4. **Verify**: `cargo test && cargo clippy -- -D warnings && cargo fmt --check`
5. **Commit** (Conventional Commits, see `CONTRIBUTING.md`):
   `git commit -m "feat(parser): tolerate trailing padding bytes"`
6. **Push**: `git push -u origin <branch>`
7. **Create PR**: `gh pr create --fill`
8. **Self-review**: read the diff, verify AC compliance
9. **Merge**: `gh pr merge --squash --delete-branch`
10. **Return to main**: `git checkout main && git pull origin main`

The `pre-commit-branch-name` hook blocks commits on `main`/`master`
and on names that don't match these prefixes.

## Architecture

Single crate, single binary target.

### Public modules

`audit`, `compliance`, `conflict`, `crypto`, `error`, `export`,
`keystore`, `multisig`, `operations`, `parser`, `serializer`,
`signature_chain`, `string_table`, `types`. Top-level exports:
`AionError`, `Result`.

### Perf and fuzz

- Criterion benches in `benches/` for crypto, file ops, and parser.
- `cargo-fuzz` targets in `fuzz/` exercise the parser on arbitrary
  bytes.
- Domain examples in `examples/` (enterprise, finance, healthcare,
  legal, manufacturing, retail) demonstrate realistic usage.

### CLI

`src/bin/aion.rs` wraps the library as the `aion` binary: `init`,
`commit`, `verify`, `export`, `inspect`, keystore operations,
multisig quorum checks, compliance reports.

## Commands

```bash
cargo build --release
cargo test
cargo clippy -- -D warnings
cargo fmt --check

# CLI
cargo run --bin aion -- init rules.aion --rules policies.yaml
cargo run --bin aion -- verify rules.aion

# Perf / fuzz
cargo bench
cd fuzz && cargo fuzz list
```

## Code Style

- Rust 2021 edition.
- `thiserror` for library errors, `anyhow` only at the binary
  boundary in `src/bin/`.
- Prefer `&[u8]` over `Vec<u8>` for input data (zero-copy via
  `zerocopy` where possible).
- Import groups: `std`, external crates, crate-local (`crate::`),
  `super::` / `self::`.
- Doc comments on all public items, with at least one example for any
  non-trivial function.

## RFC Workflow

RFCs live under `rfcs/` as `RFC-NNNN-<slug>.md`. Non-trivial changes
need one **before** code.

- Propose: `/rfc-new "<title>"` scaffolds an RFC at `rfcs/`.
- Review: use the `rfc-writer` agent to draft content matching
  existing style (look at `rfcs/RFC-0002-file-format.md` for the
  template).
- Implementation PRs cite the RFC number in the description.

See `.claude/rules/rfc-discipline.md` for the full process.

## DO NOT

- Rewrite `aion_context::crypto::*` — read the source first, then
  wrap or call. Crypto primitives are load-bearing.
- Relax crate-level clippy lints (`unwrap_used`, `expect_used`,
  `panic`, etc.) without a written rationale.
- Add `'static` to silence the borrow checker.
- Use `Rc<RefCell<T>>` / `Arc<Mutex<T>>` as a first resort — see the
  interior-mutability ladder in `.claude/rules/concurrency.md`.
- Clone to avoid ownership issues without understanding why.
- Swallow errors silently. An error that gets `.ok()`-dropped must be
  a provably-safe skip, commented with a reason.
- Add tutorial comments.
- Commit to `main` directly or push without an open PR.
- Add a dependency without checking `deny.toml`, `cargo audit`, and
  the license allowlist in `.claude/rules/supply-chain.md`.
- Change the on-disk binary format without an RFC, a format-version
  bump, and matching fuzz coverage.
