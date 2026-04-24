# Expert Rules

These rules encode the project's non-negotiable standards. Referenced
from `CLAUDE.md` and enforced by hooks in `.claude/hooks/` and agents
in `.claude/agents/`.

| File                     | Enforced by                                               |
|--------------------------|-----------------------------------------------------------|
| `tiger-style.md`         | Crate-level clippy lints; `pre-edit-rust-gate.sh`; `rust-gatekeeper` |
| `crypto.md`              | `crypto-auditor` agent; `/crypto-scan` command            |
| `api-design.md`          | `api-reviewer` agent                                      |
| `concurrency.md`         | `rust-gatekeeper`, `api-reviewer`                         |
| `distributed.md`         | Code review; `crypto-auditor` for replay-defense diffs    |
| `observability.md`       | `/quality-gate`; code review                              |
| `supply-chain.md`        | `cargo-deny`, `cargo-audit`, `/supply-chain-audit`        |
| `property-testing.md`    | Aspirational; no tier floors until a baseline is set      |
| `rfc-discipline.md`      | `rfc-writer` agent; `/rfc-new`                            |

Rules are additive to `CLAUDE.md`; `CLAUDE.md` wins on conflict.
