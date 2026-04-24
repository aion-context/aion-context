# API Design (Turon)

> "APIs are the interface between you and every future version of
> yourself." — apply this to every `pub` symbol.

## Ownership and borrowing

- **`&self` over `&mut self`** unless the function truly mutates
  observable state visible to every caller. If the only mutation is
  through a `Mutex` / `RwLock`, take `&self` and document that
  concurrent callers are supported.
- **`&[u8]` over `Vec<u8>`** for inputs. Use `Into<Vec<u8>>` only when
  the callee must own the bytes.
- **`impl AsRef<str>` / `&str`** for read-only string inputs. Take
  `String` only when the callee stores it.
- **Return owned types** when the lifetime would force the caller into
  an awkward self-referential struct. Don't leak `'a` for the sake of
  a "zero copy" the caller will just clone around.
- Parser/serializer functions (`src/parser.rs`,
  `src/serializer.rs`) are the one place where zero-copy is
  non-negotiable. Use `zerocopy` and return `&'a` where possible.

## Type design

- **Newtypes over primitives** for anything with units or meaning:
  `FileId`, `AuthorId`, `VersionNumber` (all of which already exist
  in `src/types.rs`). A raw `u64` in a public signature is a
  correctness bug waiting to happen.
- **Phantom state** (`PhantomData<State>`) for protocols with ordering
  — `AionFile<Unsigned> → AionFile<Signed>`, `McpServer<Unstarted> →
  McpServer<Started>`. See the `turon` skill.
- **Enum exhaustiveness**: never mark public enums `#[non_exhaustive]`
  without a reason documented in the doc comment. Callers need to
  match them, and opacity without cause is hostile.
- **`#[must_use]`** on every `Result`, every builder, and every value
  that represents work the caller must act on. `ContextBuilder` and
  `Pipeline` return types already lean on this — keep the pattern.

## Errors

- One error type for the crate, re-exported at the crate root as
  `AionError`. Derived from `thiserror`.
- Variants describe **what failed**, not **where** it failed.
  `BadSignature` not `VerificationError`. File/line context belongs
  in a `context: String` field if at all.
- No `Box<dyn std::error::Error>` at public boundaries. It turns every
  caller's `match` into a string-comparison test.
- No `anyhow::Error` at library boundaries. `anyhow` is a binary-scope
  tool — use it in `src/bin/*.rs`, not in `lib.rs`.
- `From` impls wire internal error sources into `AionError` so
  callers never need to unwrap one error to re-wrap it.

## Naming

- Verbs for actions (`verify_signature`, `inject_context`).
- Nouns for types and constructors (`AionFile`, `GuardrailChain`,
  `ContextBuilder`).
- No `get_` prefix — `version()` not `get_version()`. `take_foo` /
  `into_foo` for ownership-changing, `foo_mut` for mutable borrows.
- Builder methods return `Self`. Terminal methods return
  `Result<Built, Error>` with `#[must_use]`.

## Stability

- Everything `pub` is a promise. Anything not required to be public is
  `pub(crate)` or private.
- Adding a variant to a public enum is a **breaking change** without
  `#[non_exhaustive]`. Adding a field to a public struct is breaking
  without `#[non_exhaustive]` on the struct.
- Never expose a third-party type in a public signature unless you
  are willing to depend on that crate's semver forever. `chrono`,
  `uuid`, and `blake3` are already in the public API and thus already
  pinned. Adding another is a decision that gets an RFC.

## aion-context-specific: file format stability

`aion-context`'s on-disk binary format is a public API. Adding a field,
changing a tag byte, or reordering is a **format break**. Every such
change gets:

1. An RFC (see `rfcs/RFC-0002-file-format.md` for the
   template).
2. A version bump in the file header.
3. A migration path: old readers reject new files with a specific
   `Error::UnsupportedFormat(version)`, never silently misparse.
4. A fuzz target that exercises the parser on old and new versions.

The `api-reviewer` agent hard-blocks format changes that skip any of
those four steps.
