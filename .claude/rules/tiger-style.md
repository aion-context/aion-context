# Tiger Style / NASA Power of 10

**Scope:** every `.rs` file under `src/`. Tests, benches, and the
CLI binary are held to the same standard but the pre-edit hook only
hard-blocks library code.

## Already enforced by the compiler

`Cargo.toml` sets, at crate scope:

```toml
[lints.rust]
unsafe_code = "forbid"

[lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
panic       = "deny"
todo        = "deny"
unreachable = "deny"
unimplemented = "deny"
indexing_slicing      = "warn"
arithmetic_side_effects = "warn"
```

## Banned in library code

| Construct                     | Replacement                                     |
|-------------------------------|-------------------------------------------------|
| `.unwrap()`                   | `.ok_or(Error::…)?` / `.map_err(…)?`            |
| `.expect("…")`                | `.ok_or_else(…)?` / `Error::context`            |
| `panic!(…)`                   | return `Err(Error::…)`                          |
| `todo!()`                     | do not merge; land a real implementation        |
| `unreachable!()`              | reshape types so the case cannot be constructed |
| `assert!` / `debug_assert!` in prod hot paths | lift into type invariants       |
| `unsafe { .. }`               | not permitted (`unsafe_code = forbid`)          |

Tests may use `.unwrap()` only when it genuinely documents a test
precondition; prefer `.unwrap_or_else(|_| std::process::abort())` so
the failure mode matches Tiger Style semantics and so a regression in
expected output doesn't hide behind an `unwrap` stack trace.

## Function length

**60 body lines, hard cap.** Counting rule: from the line containing
`fn` to the matching `}`. If the body is reasonable but the signature
spans many lines of generics/where-clauses, extract a type alias
rather than hide length in the signature.

Exceptions: a `match` arm table whose cases are trivially one-line
dispatches can push body length to 80. Document the rationale with a
`// TIGER: table-dispatch exception (N arms)` comment so reviewers
know not to flag it.

## Loops

Every loop must have a **verifiable termination condition** visible at
the loop site — a bounded iterator, a decreasing counter, or a
condition a reviewer can point at. No `loop { … }` without a break
condition a reviewer can point at.

## Return types

Every fallible function returns `Result<T, Error>`. Every infallible
function returns `T`. No `Result<T, ()>`. No `Option<T>` for error
signalling. Errors use `thiserror` and flow through `From` impls.

## Comments

Permitted: `///` doc, `//!` crate doc, `// TODO(name):`,
`// FIXME(name):`, `// SAFETY:`, non-obvious **why** comments. Every
other comment is a smell. If a reader can't tell what the code does
from the names, rename — don't annotate.

## Indexing and arithmetic

`aion-context` sets `indexing_slicing = "warn"` and
`arithmetic_side_effects = "warn"` at the crate level. In
parser/serializer code, prefer:

- `slice.get(i).ok_or(Error::TruncatedInput)?` over `slice[i]`
- `a.checked_add(b).ok_or(Error::Overflow)?` over `a + b` on values
  derived from untrusted input

Panics from out-of-bounds indexing or integer overflow on adversary
input are exploitable. Treat both as Tiger Style violations even
though the lints are only "warn".
