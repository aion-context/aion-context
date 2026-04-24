---
description: Scan aion-context library crates for Tiger Style violations with file:line citations.
---

Audit the library against `.claude/rules/tiger-style.md`. Read-only.

Scope: `src/` (excluding `src/bin/`).

Steps:

1. **Panic scan** — `rg -n '\.unwrap\(\)|\.expect\(|panic!\(|todo!\(|unreachable!\(' <scope>`.
   Filter out lines that are doc comments, `// ` comments, or inside
   `#[cfg(test)]` modules. Report each hit as
   `crate/file.rs:LINE — construct`.

2. **Function length** — for each `fn` in scope, count lines from the
   `fn` keyword to the matching `}`. Any function body > 60 lines is a
   violation. Report as `crate/file.rs:LINE — NAME is N lines`.

3. **Tutorial comments** — flag `//` comments that do NOT start with
   `TODO`, `FIXME`, `SAFETY`, `NOTE(name)`, `TIGER:`, or a symbol
   reference. Skip `///` doc comments. This is advisory, not a hard
   failure.

4. **Loop termination** — report any `loop {` without a visible
   `break` or `return` in the same function.

5. **Error handling** — report any function signature returning
   `Result<_, ()>`, `Option<_>` as an error channel, or
   `Box<dyn std::error::Error>` at a public boundary.

6. **Indexing / arithmetic on untrusted input** — in
   `src/parser.rs` and `src/serializer.rs`, flag
   any raw `slice[i]` or `a + b` / `a - b` / `a * b` on values derived
   from the input. This is the one scope where arithmetic side effects
   are hazardous.

Report format:

```
TIGER AUDIT — aion-context
Panic scan:          [✓ | N violations]
Function length:     [✓ | N violations]
Tutorial comments:   [N suspicious]
Loop termination:    [✓ | N violations]
Error signatures:    [✓ | N violations]
Unsafe arithmetic:   [✓ | N violations]

Violations:
  src/operations.rs:217 — expect(
  src/serializer.rs:89  — write_record is 73 lines
  ...

VERDICT: MASTERPIECE | N violations
```

Do not fix anything. This command reports only.
