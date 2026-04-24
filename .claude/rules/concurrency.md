# Concurrency (Bos / Matsakis)

`aion-context` is a synchronous library today — no `tokio`, no
`async fn`, no channels in `src/`. The benches and CLI run single-
threaded or use `rayon` for parallel verification. This rule covers
the shared-state hazards that still apply.

## Lock discipline

- **One lock, one invariant.** If two pieces of state always change
  together, put them under one lock — not two. Mismatched locks
  produce torn reads and bugs that only show up under load.
- **Scope guards tightly.** Bind a guard in the narrowest block that
  needs it. `let _g = lock.read();` at the top of a 40-line function
  is almost always a bug.
- **Poisoning is not panicking.** Every `std::sync::RwLock::read()` /
  `.write()` must be `.map_err(|_| Error::LockPoisoned)?`. The
  `rust-gatekeeper` agent rejects `.unwrap()` on lock results — and so
  do the workspace clippy lints.

## Interior mutability ladder

Pick the weakest tool that works:

1. `&mut T` (easiest to reason about)
2. `Cell<T>` / `RefCell<T>` (single-threaded)
3. `Mutex<T>` (coarse-grained, thread-safe)
4. `RwLock<T>` (read-heavy workloads)
5. Atomics (`AtomicU64`, `AtomicBool`) for single-word state
6. Lock-free structures (`crossbeam`, `dashmap`) — only after proving
   a bottleneck with a `/perf-audit` benchmark

`Rc<RefCell<T>>` and `Arc<Mutex<T>>` are not default tools. If they
appear in a design, the reviewer asks why a simpler ownership model
wasn't enough.

## Rayon

`rayon` is allowed for parallel verification over independent file
lists (e.g. verifying N signatures in a chain). Rules:

- The closure is pure — no shared mutable state, no I/O other than
  the bytes it was given.
- Aggregation uses `reduce` / `collect`, not a shared `Mutex<Vec<_>>`.
- Rayon panics propagate — the Tiger Style ban on panics applies
  inside rayon closures just as it does in synchronous code.

## Data races

Rust's type system prevents data races, but **logical races** still
exist:

- Check-then-act on the same lock is a race. Replace with a single
  atomic transform under one guard.
- Version numbers must be incremented and observed under the same
  lock — not incremented on one lock and read on another.
- In the audit chain, "read current head" + "append new entry with
  prev = head" must happen under one write guard; otherwise two
  concurrent appenders can both chain off the same head and the
  second write silently overwrites the first.

## If async arrives later

An async story for `aion-context` would be an RFC — not a patch. The
file-format operations are fast enough to run on a single thread for
the sizes we target. If a future consumer wants async I/O, they wrap
the sync API in `tokio::task::spawn_blocking`; the library itself
stays sync.
