<!--
Thanks for the PR. Please fill in the sections below — they make the
review faster and the merge log readable later.
-->

## Summary

<!-- 1–3 bullets of what changed and why. Link related issue: "Closes #N". -->

-

## Test plan

<!-- How did you verify this works? Local commands you ran, output you checked. -->

- [ ] `cargo test` passes
- [ ] `cargo clippy --all-targets -- -D warnings` clean
- [ ] `cargo fmt --check` clean
- [ ]

## Breaking change

<!--
Yes / No. If yes, describe what breaks and what migration callers need.
Anything that touches the on-disk file format, public API surface, CLI
exit codes, or tracing event names is a breaking change.
-->

- [ ] No breaking change
- [ ] Yes — described below

## Related

<!-- Issues, RFCs, prior PRs. -->

- Closes #
- RFC:

## Reviewer checklist

- [ ] No `unwrap` / `expect` / `panic!` / `todo!` / `unreachable!` in library code
- [ ] No raw `==` on signature, hash, or key bytes (use `subtle::ConstantTimeEq`)
- [ ] If touching crypto / signature / audit chain: `crypto-auditor` agent has reviewed
- [ ] If adding a new `pub` item: doc comment + at least one example
- [ ] If changing on-disk format: an RFC exists, format version is bumped
