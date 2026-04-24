---
description: Run the six expert skills sequentially against the crate and produce a consolidated review.
---

Run a multi-expert review of the `aion-context` crate.

1. Read every `.rs` file under `src/`.
2. For each expert below, produce a section with that expert's lens.
   Keep each section ≤ 10 bullets, file:line citations mandatory.
   - **matsakis** — ownership, lifetimes, borrow-checker fights,
     `'static` bounds
   - **bos** — concurrency, atomics, lock discipline
   - **turon** — public API, `&self` vs `&mut self`, newtypes,
     `#[must_use]`
   - **muratori** — hot paths, unnecessary allocations, cache
     behavior
   - **lamport** — ordering, logical clocks, replay, distributed
     invariants
   - **kleppmann** — data modelling, durability, failure modes
3. Consolidate into a final "Cross-cutting Findings" section that
   lists the top 5 issues at least two experts flagged.
4. End with a **Verdict**: `SHIP IT`, `NEEDS TUNING (N minor)`, or
   `HOLD (N blockers)`.

Do not modify files. This is advisory.
