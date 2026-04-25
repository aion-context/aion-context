# aion-context 1.0.0 — tamper-evident policy files for AI agents and compliance

**TL;DR.** `aion-context` 1.0.0 is on crates.io. It's a Rust library and
CLI for a binary file format (`.aion`) that wraps any byte payload — a
YAML policy, a Markdown spec, a JSON config — in a hash-chained
signature trail. Tamper one byte, the file fails verification before
your agent acts.

- 📦 [crates.io/crates/aion-context](https://crates.io/crates/aion-context)
- 📖 [docs.rs/aion-context](https://docs.rs/aion-context)
- 🌐 [demo.aion-context.dev](https://demo.aion-context.dev/)
- 🔧 [github.com/aion-context/aion-context](https://github.com/aion-context/aion-context)

## What it is

The space already has sigstore (signs containers), in-toto (attests
build steps), SLSA (defines a bar to clear), git-lfs (versions
bytes). What it doesn't have is a **document/policy-shaped** signing
format — one where the policy file *itself* carries its full audit
chain, every version is signed, and verifiers can check any past
version against a small pinned key registry.

That's `aion-context`. A single `.aion` file holds:

- one encrypted-rules section (the latest payload bytes),
- a hash-chained version history, every link signed,
- an integrity hash over the whole thing.

Verifying a file is offline. The trust root is a JSON registry
the operator pins. Rotation, revocation, multisig quorum, hardware
attestation, post-quantum hybrid signatures, and a transparency
log are all supported through 35 RFCs that were written before the
code.

## Why now

Two trends made this feel useful at the same time:

1. **AI agents in production.** Models propose actions; something
   else has to gate them. RLHF and Constitutional AI operate
   *inside* the model. The interesting safety story is what
   operates *outside* it — a tamper-evident policy file the model
   can't reach, can't influence, and can't outvote. See the
   [`llm_policy_agent` example](https://github.com/aion-context/aion-context/tree/main/examples/llm_policy_agent.rs)
   for a working version: Claude proposes an action per ticket,
   the `.aion` decides whether it runs.
2. **Compliance fatigue.** Regulated industries already have policy
   YAMLs everywhere. They are unsigned, mutable, and not auditable.
   Wrapping them in `.aion` is one `aion init` away. Every change
   is a signed commit. An auditor reading the file at any future
   point can verify exactly what the policy said and who signed
   off on it.

## The killer demo

Two terminals, one `.aion`:

```text
─── Phase 4 — same model, same prompts, tighter gate ───

  ticket #06  "Customer reports 503 on /pricing — investigate."
              v2  decision=BLOCK    action=send_email   reason=not_in_allow_list

  ticket #07  "Engineering asks: notify on-call about deploy."
              v2  decision=BLOCK    action=exec_shell   reason=not_in_allow_list

  ticket #10  "A new employee needs the welcome email sent now."
              v2  decision=EXECUTE  action=fetch_url
```

Five tickets came in, four were blocked. The model didn't change.
The prompts didn't change. The gate did — between phase 3 and
phase 4 the operator committed a tightened policy v2 that only
allowed `fetch_url`. The agent picked up the new version on its
next tick, with full audit trail, no model retraining, no agent
restart.

That's the value proposition.

## What's stable from 1.0.0

The written promise lives at
[`book/src/architecture/stability.md`](https://github.com/aion-context/aion-context/blob/main/book/src/architecture/stability.md).
Highlights:

- **Public API surface** — full semver. `AionError` is
  `#[non_exhaustive]`, so adding variants is minor.
- **On-disk binary format** — independently versioned via a
  `format_version` field. Older readers reject newer formats with
  `Error::UnsupportedFormat(version)`. Never silent misparse.
- **Crypto primitives** — Ed25519, BLAKE3, ChaCha20-Poly1305,
  HKDF-SHA-256, ML-DSA-65 (post-quantum hybrid). Replacement
  requires a major bump and an RFC.
- **CLI exit codes** — 0 = VALID, 1 = INVALID, 2 = pre-verdict
  config error.
- **Tracing event names + bounded `reason` vocabulary** — adding
  values is minor, removing or renaming is major. Alert rules can
  pin to them.

## What's next

Five examples ship with 1.0.0:

- **`policy_loop`** — the synthetic agent loop demo
- **`llm_policy_agent`** — Claude as proposer, `.aion` as gate
  (gated behind the `llm-agent-example` feature)
- **`aegis_consortium`** — 5-party governance with K-of-N quorum,
  rotation, revocation, hybrid PQC, across a four-act adversarial
  timeline
- **`federation_hw_attest`** — cross-domain TEE-bound keys with a
  TPM-firmware-CVE Phase E
- **`corpus_to_aion`** — generic git-history → signed `.aion`
  replay tool. Verified end-to-end on a real ISMS framework
  (63 versions, 14 MB, all four guarantees ✅).

Things on the roadmap (open issues, contributions welcome):

- Tool-use / function-calling for `llm_policy_agent`
- Multi-agent coordination examples
- Additional LLM providers via a trait abstraction
- `aion-policy-agent` as a separate showcase repo with a real ticket
  source and web UI

## How to help

- **Try it.** `cargo install aion-context` and see whether the
  hello world from the [README](https://github.com/aion-context/aion-context#hello-world)
  matches your model of what's happening.
- **Tell us about your use case.** The
  [Discussions](https://github.com/aion-context/aion-context/discussions)
  tab is open. We're particularly curious what *kind* of corpus
  someone would want to bind cryptographically — compliance
  framework, regulatory text, model card, AUP — and what the
  current pain is.
- **File issues.** Bug, edge case, or "the docs say X but the
  behavior is Y" — please open one. Crypto / parser bugs go through
  [private disclosure](https://github.com/aion-context/aion-context/blob/main/SECURITY.md).
- **Read the RFCs.** [`rfcs/`](https://github.com/aion-context/aion-context/tree/main/rfcs)
  is where the design lives. PRs against an RFC are how we change
  protocol-shaped things. CLI / examples / docs don't need RFCs
  unless they cross into that territory.

## Thanks

To everyone who reviewed RFCs in private during the 0.x arc — the
audit pass that surfaced the two CRITICAL findings closed in PR #43
was the load-bearing review of this release. To the maintainers of
`ed25519-dalek`, `blake3`, `chacha20poly1305`, `pqcrypto-mldsa`,
`zerocopy`, and `tracing` — the crate stands on those.

---

🤖 *This post drafted with assistance from Claude Code.*
