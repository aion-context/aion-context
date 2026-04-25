# LLM Policy Agent — Claude proposes, .aion gates

> A real LLM-driven sibling of [`policy_loop`](./policy_loop.md).
> Claude proposes an action for each ticket; the signed `.aion`
> policy decides whether the action runs. The model never sees the
> policy file and never gets a vote on the gate.

The example file is at `examples/llm_policy_agent.rs`. Gated behind
the `llm-agent-example` feature so the default build doesn't pull
in an HTTP client. Run it:

```bash
ANTHROPIC_API_KEY=sk-ant-... \
  cargo run --release --features llm-agent-example \
    --example llm_policy_agent
```

For an offline / CI-friendly demo with the same flow but no
network call:

```bash
LLM_POLICY_NO_NETWORK=1 \
  cargo run --release --features llm-agent-example \
    --example llm_policy_agent
```

## What it exercises

| Library surface | RFC | Why it's interesting |
|---|---|---|
| `verify_file(&path, &registry)` | RFC-0034 | The gate every LLM proposal flows through |
| `init_file` / `commit_version` | RFC-0002, RFC-0005 | Operator side of the lifecycle |
| `show_current_rules` | — | The plaintext rules the agent classifies against |
| `KeyRegistry::register_author` | RFC-0028 | Trust root for the policy signature |

## Why this is the load-bearing AI-safety story

The single most important property of an `.aion` policy used as a
gate for an LLM agent is that **the model has no influence over
the gate**. Even a maximally-jailbroken or prompt-injected LLM
that produces `"exec_shell; rm -rf /"` as output cannot bypass
the policy file:

- The gate runs **after** the model produces output, not before.
- The policy is a separate, signed artifact. The model has no
  ability to mutate it (and even if a process the model runs
  could write to the filesystem, the integrity hash + signature
  chain catches the tamper).
- The gate's rules are tamper-evident. A flipped byte means
  refusal of every action — there is no graceful-degradation path
  that would let a corrupted policy quietly accept previously-
  blocked actions.

This is a different shape of AI safety than RLHF / system-prompt
constraints / Constitutional AI. Those operate **inside** the
model. An `.aion` gate operates **outside** it, with cryptographic
authority that the model cannot reach.

## Demo phases (single `cargo run`)

| Phase | What happens |
|---|---|
| 1 | Operator inits `policy.aion` with v1 (lenient: all 5 actions allowed) |
| 2 | 5 tickets → Claude proposes → policy v1 lets each through (`decision=EXECUTE`) |
| 3 | Operator commits v2 (incident response — only `fetch_url`) |
| 4 | Same 5 tickets, same model — most proposals now `decision=BLOCK reason=not_in_allow_list` |

The same model with the same prompts produces different outcomes
across phase 2 and phase 4 — without the model knowing the policy
changed, without an agent restart, without a redeploy.

## The agent's loop body

```rust
fn handle(&mut self, ticket: &str) -> Decision {
    self.tick_seq += 1;
    let proposed = self.llm.propose_action(ticket, self.tick_seq);
    tracing::info!(event = "llm_proposed", action = %proposed, ...);

    let report = verify_file(&self.policy_path, &self.registry)?;
    if !report.is_valid {
        tracing::warn!(event = "agent_refused", reason = classify_invalid(&report));
        return Decision::Refused { ... };
    }

    let rules = show_current_rules(&self.policy_path)?;
    let policy = Policy::parse(&rules);

    if policy.permits(&proposed) {
        tracing::info!(event = "agent_decided", action = %proposed, decision = "execute");
        Decision::Executed { action: proposed, version: report.version_count }
    } else {
        tracing::warn!(event = "agent_refused", reason = "not_in_allow_list");
        Decision::Blocked { action: proposed, reason: "not_in_allow_list", ... }
    }
}
```

Under the 60-line Tiger Style cap. Every ticket re-verifies the
file from scratch — no caching of "I trusted this policy last
tick."

## Bounded reason codes

Every `warn!` rejection carries a `reason` from a fixed
vocabulary:

| `reason=` | When |
|---|---|
| `verify_error` | I/O or library error before reaching a verdict |
| `structure_invalid` | parser couldn't construct an `AionParser` |
| `integrity_hash_mismatch` | trailing BLAKE3 doesn't match file body |
| `hash_chain_broken` | a `parent_hash` link is wrong |
| `signature_invalid` | a signature failed the registry-aware path |
| `not_in_allow_list` | LLM proposed a known action, policy disallowed it |
| `llm_output_invalid` | LLM produced text that didn't match any of the 5 actions |
| `llm_call_failed` | network / decode / shape failure on the API call |

These map to the bounded vocabulary documented in
[Observability](../architecture/observability.md). They are stable
tokens — alert rules can pin to them.

## API key handling

The example reads `ANTHROPIC_API_KEY` from the process environment
at startup and threads it through to the `x-api-key` header on
each request. The key is **never** logged, never appears in any
`tracing` field, and never echoes back in error messages — even
the network-error reason codes are bounded tokens
(`http_error`, `decode_error`, `missing_text`).

If the env var is unset or empty, the example exits with code `2`
(distinct from `1`, which is the policy-rejection exit) and a
clear message pointing the operator at either `ANTHROPIC_API_KEY`
or `LLM_POLICY_NO_NETWORK=1`.

## Sample output (offline mode, abbreviated)

```text
─── Phase 4 — same model, same prompts, tighter gate ─────────

  ticket #06  "Customer reports 503 on /pricing — investigate."
              v2  decision=BLOCK    action=send_email   reason=not_in_allow_list

  ticket #07  "Engineering asks: notify on-call about deploy."
              v2  decision=BLOCK    action=exec_shell   reason=not_in_allow_list

  ticket #10  "A new employee needs the welcome email sent now."
              v2  decision=EXECUTE  action=fetch_url
```

Five tickets came in, four were blocked. The model didn't change.
The prompts didn't change. The gate did.

## Configuration envs

| Env | Default | Effect |
|---|---|---|
| `ANTHROPIC_API_KEY` | (required, unless offline) | Anthropic API key for the live mode |
| `LLM_POLICY_MODEL` | `claude-sonnet-4-6` | Override the Claude model name |
| `LLM_POLICY_NO_NETWORK` | unset | When set non-empty, use the offline proposer (round-robin over the 5 actions) |
| `AION_LOG` | `warn` | Tracing level — set to `info` to see the structured emit stream |

## Command-line flags

| Flag | Effect |
|---|---|
| `--keep-policy` | Don't delete the policy file at exit. Also writes the in-process registry to `<policy>.registry.json` so you can run `aion verify --registry ... <policy>` against it afterwards. |
| `--decision-log <PATH>` | Append one NDJSON line per decision to PATH. Each record carries `tick`, `ticket_hash` (BLAKE3 prefix, stable across phases for the same ticket text), `decision`, `action`, `version`, and `reason`. |
| `-h`, `--help` | Show usage |

Example with both:

```bash
ANTHROPIC_API_KEY=sk-ant-... \
  cargo run --release --features llm-agent-example \
    --example llm_policy_agent -- \
    --decision-log /tmp/llm_decisions.ndjson \
    --keep-policy
```

After the run:

```bash
# the four guarantees on the kept file
aion verify --registry /tmp/aion_llm_policy_demo.registry.json \
            /tmp/aion_llm_policy_demo.aion

# audit trail (CreateGenesis at v1, CommitVersion at v2)
aion show --registry /tmp/aion_llm_policy_demo.registry.json \
          /tmp/aion_llm_policy_demo.aion signatures

# every decision the agent made, one JSON line each
cat /tmp/llm_decisions.ndjson | jq .
```

## Two audit trails

The example has two independent audit surfaces, both verifiable, both bounded:

| Trail | Location | What it captures |
|---|---|---|
| **In-file audit chain** | `audit_trail_count` entries inside the `.aion` file, hash-chained, signed | `CreateGenesis` at v1, `CommitVersion` at v2 — the cryptographic ledger of changes to the policy file itself |
| **Decision log** (`--decision-log`) | NDJSON file the operator chooses | Every per-tick decision the agent made: which ticket, which action Claude proposed, which version of the policy was active, what the verdict was, and why |

The first is a **policy-mutation ledger** (what changed, who signed). The second is a **policy-application ledger** (what the gate decided to do, against what policy version). Together they reconstruct everything an auditor needs: "at time T, the policy was version V (proven by the in-file chain) and the agent classified ticket X as `decision=...` (proven by the decision log)."

Phase 5 of the demo dumps the in-file chain to stdout so you can see it without reaching for the CLI:

```text
─── Phase 5 — in-file audit trail (hash-chained inside the .aion) ───
  audit_trail_count = 2
  #00  ts=1777131731111673740  author=81001  action=CreateGenesis  prev_hash=0000000000000000
  #01  ts=1777131731112170658  author=81001  action=CommitVersion  prev_hash=7014bcee78291585
```

## What you'll learn from running it

- How to wrap an LLM proposer in an `.aion` policy gate without
  giving the model any way to influence the gate.
- How a single signed-policy update flips the agent's allow-list
  in real time, with full audit trail, and no model re-anything.
- How the bounded reason vocabulary makes alert rules cheap: a
  prod alert on `event="agent_refused" AND reason="signature_invalid"`
  fires only on cryptographic tamper, not on routine policy blocks.
