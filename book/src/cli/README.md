# CLI Reference

The `aion` binary wraps the library as a top-level command with
the following subcommands:

| Subcommand | Purpose | Page |
|---|---|---|
| `init` | Create a new `.aion` file at v1 | [lifecycle](./lifecycle.md) |
| `commit` | Append a new version to an existing file | [lifecycle](./lifecycle.md) |
| `verify` | Validate a single file against a registry | [lifecycle](./lifecycle.md) |
| `show` | Print rules / history / signatures / info | [inspect](./inspect.md) |
| `report` | Generate a compliance report (markdown / text / JSON) | [inspect](./inspect.md) |
| `export` | Export the file's audit data as JSON / YAML / CSV | [inspect](./inspect.md) |
| `key` | Generate / list / export / import / delete keystore keys | [key](./key.md) |
| `registry` | Manage the trusted-key registry: pin, rotate, revoke | [registry](./registry.md) |
| `release` | Seal / verify / inspect RFC-0032 sealed releases | [release](./release.md) |
| `archive` | Bulk-verify a directory of `.aion` files | [archive](./archive.md) |

## Exit-code contract

Every subcommand follows a strict exit-code contract enforced
at the type level (see [issue #23] / RFC-0024 in the rfcs/
directory):

| Outcome | Exit code |
|---|---|
| Success / VALID verdict | `0` |
| Failure / INVALID verdict | `1` |

This is true for `verify`, `archive verify`, `release verify`,
and every other subcommand that produces a verdict. The
typestate refactor in PR #24 moved the verdict-to-exit-code
mapping into a single pure function (`VerificationReport::exit_code`),
so the bug class "INVALID printed but exit 0" is unrepresentable.

## Common flags

Most subcommands that read or write `.aion` files take:

- `--registry <PATH>` — required for verify-side operations and
  for `commit`. Optional for `init` (genesis trust comes from
  the file alone).
- `--format text|json|yaml|markdown` — output format on
  reporting subcommands. `text` is the default.

[issue #23]: https://github.com/copyleftdev/aion-context/issues/23
