# Contributing to aion-context

Thank you for your interest in contributing.

## Quick Start

```bash
git clone https://github.com/aion-context/aion-context.git
cd aion-context

cargo build
cargo test
cargo clippy -- -D warnings
```

## Development Workflow

1. **Create a feature branch**
   ```bash
   git checkout -b feature/<issue-number>-<description>
   ```

2. **Make changes** following [Tiger Style](#tiger-style).

3. **Verify locally**
   ```bash
   cargo test
   cargo clippy -- -D warnings
   cargo fmt --check
   ```

4. **Commit with Conventional Commits**
   ```bash
   git commit -m "feat(parser): tolerate trailing padding bytes"
   ```

5. **Push and open a PR**
   ```bash
   git push -u origin feature/<issue-number>-<description>
   gh pr create --fill
   ```

## Tiger Style (zero panics)

We follow NASA Power of 10 rules adapted for Rust:

- **NO** `unwrap()`, `expect()`, `panic!()`, `todo!()`,
  `unreachable!()` in production code — enforced by clippy at deny
  level.
- **YES** explicit `Result<T, AionError>` error handling.
- **YES** maximum 60 lines per function body.
- **YES** all public items documented.

```rust
// Good
pub fn process(data: &[u8]) -> Result<Output> {
    let parsed = parse(data)?;
    validate(&parsed)?;
    Ok(transform(parsed))
}

// Bad — will fail code review and the pre-edit hook
pub fn process(data: &[u8]) -> Output {
    let parsed = parse(data).unwrap();  // NO
    transform(parsed)
}
```

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix     | Use                                     |
|------------|-----------------------------------------|
| `feat`     | New feature                             |
| `fix`      | Bug fix                                 |
| `docs`     | Documentation                           |
| `test`     | Tests                                   |
| `refactor` | Code change without feature/fix         |
| `perf`     | Performance                             |
| `chore`    | Tooling, CI, dependency bumps           |

Examples:

```
feat(crypto): add batch signature verification
fix(parser): handle empty rules correctly
docs: update API examples
```

## Pull Request Checklist

- [ ] `cargo test` passes
- [ ] `cargo clippy -- -D warnings` is clean
- [ ] `cargo fmt --check` passes
- [ ] Tests added for new functionality
- [ ] Commit messages follow convention
- [ ] PR references issue if applicable (`Closes #NN`)
- [ ] If the change touches the on-disk file format, crypto
      primitives, keystore, or audit chain, an RFC exists and is
      referenced.

## Testing Expectations

- New crypto, parser, or operations code ships with unit tests and,
  where applicable, a property test or fuzz target.
- Run the full suite locally:
  ```bash
  cargo test
  cargo bench        # optional but recommended for perf-touching PRs
  ```

## Documentation

- **User Guide**: [docs/USER_GUIDE.md](docs/USER_GUIDE.md)
- **Developer Guide**: [docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md)
- **API docs**: `cargo doc --open`
- **RFCs**: [rfcs/](rfcs/)

## License

By contributing, you agree that your contributions will be licensed
under the project's dual MIT/Apache-2.0 license.
