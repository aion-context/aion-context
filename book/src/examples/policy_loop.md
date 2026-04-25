# Policy Loop — agent over a signed policy

> A tight-loop AI agent that re-verifies its own policy file on
> every tick. Demonstrates the value of `.aion` as a substrate for
> agent governance: tamper-evident, versioned, and auditable.

The example file is at `examples/policy_loop.rs`. Run it:

```bash
cargo run --release --example policy_loop
```

## What it exercises

| Library surface | RFC | Why it's interesting |
|---|---|---|
| `verify_file(&path, &registry)` | RFC-0034 | The four guarantees on every tick |
| `init_file` / `commit_version` | RFC-0002, RFC-0005 | Operator side of the lifecycle |
| `show_current_rules` | — | Plaintext rules extraction for the agent |
| `KeyRegistry::register_author` | RFC-0028 | Trust root the agent verifies against |

## Why this is the point

Most agent frameworks ship policies as unsigned YAML or JSON. Anyone
with filesystem access — a misconfigured CI job, a cloud
misconfiguration, a compromised dependency — can mutate the policy,
and there is no audit trail. The agent has no way to tell whether
the policy it just loaded came from its operator or from an
attacker who edited it five minutes ago.

An `.aion` policy file fixes that:

- **Tamper-evident.** Any single-byte change anywhere in the file
  fails the integrity hash. The agent refuses to act and emits a
  structured rejection.
- **Versioned.** Every commit increments the version. The agent
  knows when policy changed and can log the transition.
- **Auditable.** Every signed version is attested by an author the
  agent has pinned in its `KeyRegistry`. A regulator reviewing the
  file later can replay every decision.
- **No ambient authority.** Even with full filesystem access, an
  attacker without the operator's signing key cannot produce a
  policy version the agent will accept.

## The eight phases

The example plays both operator and agent in a single process so
the lifecycle is visible without manual coordination:

| Phase | Side | What happens |
|---|---|---|
| 1 | operator | `init_file` with policy v1 (lenient — all 5 actions allowed) |
| 2 | agent | 5 ticks → all `decision=ALLOW` |
| 3 | operator | `commit_version` with policy v2 (tightened — only `fetch_url`) |
| 4 | agent | 5 ticks → 1 `ALLOW`, 4 `BLOCK` (picks up v2 on first tick) |
| 5 | operator | flip one byte mid-file (`bytes[len/2] ^= 0x01`) |
| 6 | agent | 3 ticks → all `REFUSE` with `reason=integrity_hash_mismatch` |
| 7 | operator | restore by re-init |
| 8 | agent | 2 ticks → back to `ALLOW` under the restored policy |

## The agent's loop body

```rust
fn tick(&mut self) -> Decision {
    let action = ACTIONS[(self.tick_seq as usize) % ACTIONS.len()].to_string();
    self.tick_seq += 1;

    let report = match verify_file(&self.policy_path, &self.registry) {
        Ok(r) => r,
        Err(e) => return Decision::Refused {
            reason: "verify_error", detail: e.to_string()
        },
    };
    if !report.is_valid {
        return Decision::Refused {
            reason: classify_invalid(&report),
            detail: report.errors.join("; "),
        };
    }

    let version = report.version_count;
    if version != self.last_version {
        println!("  ↻ policy update accepted: v{} → v{}",
                 self.last_version, version);
        self.last_version = version;
    }

    let rules = show_current_rules(&self.policy_path)?;
    let policy = Policy::parse(&rules);
    if policy.permits(&action) {
        Decision::Allowed { action, version }
    } else {
        Decision::Blocked { action, version }
    }
}
```

Under the 60-line Tiger Style cap. Every tick performs the full
verification — there is no caching of "I trusted this file last
time." That is deliberate: a long-running agent that caches trust
is one filesystem race away from acting on a tampered policy.

## Bounded reason codes

When a verification fails, the example classifies the failure into
one of five stable reason codes:

| `reason=` | When |
|---|---|
| `structure_invalid` | parser couldn't construct an `AionParser` |
| `integrity_hash_mismatch` | trailing BLAKE3 doesn't match the file body |
| `hash_chain_broken` | any `parent_hash` link in the version chain is wrong |
| `signature_invalid` | a signature failed under the registry-aware verify path |
| `verify_error` / `rules_unreadable` | I/O or library error before a verdict |

These map to the four `bool` fields of [`VerificationReport`]
(plus a couple of pre-verdict cases). They are deliberately a
small, fixed vocabulary — bounded reason codes are how the
[observability rule](https://github.com/aion-context/aion-context/blob/main/.claude/rules/observability.md)
keeps log cardinality tractable.

[`VerificationReport`]: ../architecture/file-format.md

## Sample output (abbreviated)

```text
─── Phase 4 — agent under policy v2 ───────────
  ↻ policy update accepted: v1 → v2
  tick #06  v2  decision=ALLOW   action=fetch_url
  tick #07  v2  decision=BLOCK   action=send_email
  tick #08  v2  decision=BLOCK   action=exec_shell
  tick #09  v2  decision=BLOCK   action=write_file
  tick #10  v2  decision=BLOCK   action=read_secret

─── Phase 6 — agent under tampered file ───────
  tick #11  decision=REFUSE  reason=integrity_hash_mismatch
  tick #12  decision=REFUSE  reason=integrity_hash_mismatch
  tick #13  decision=REFUSE  reason=integrity_hash_mismatch
```

## Split-terminal mode

Although the example drives both sides itself, the same code shape
works as a long-lived daemon you drive with the `aion` CLI from
another terminal. The pattern is:

| Terminal | Action | Expected |
|---|---|---|
| Left | run a forever-loop variant of `tick()` against `agent.aion` | tick … tick … |
| Right | `aion commit agent.aion --rules tighter.yaml ...` | new version signed |
| Left | next tick | picks up new version, decisions change |
| Right | `printf '\x01' \| dd of=agent.aion bs=1 seek=4096 count=1 conv=notrunc` | (no output) |
| Left | next tick | `decision=REFUSE reason=integrity_hash_mismatch` |
| Right | `aion registry rotate ...` | rotation record minted |
| Left | next tick | active epoch resolves through new key, still verifies |

That last row is the load-bearing one: rotation happens out-of-band
in the registry, but the agent picks it up automatically because
`verify_file` resolves the active epoch through the registry on
every call. There is no agent restart, no policy redeploy.

## What you'll learn from running it

- How a signed policy file behaves like git for agent governance:
  every change is a commit, every commit is signed, and the agent's
  view of "current policy" is whatever the latest signed version
  says.
- How the four guarantees compose. A single byte flip simultaneously
  breaks the integrity hash, the parent_hash chain at v2, and the
  head signature — the report shows all three failures, the agent
  classifies on the first one and refuses.
- How the registry-aware verify path (RFC-0034) makes the agent
  silently safe across rotations: the trust root is the registry,
  not any individual key, so rotation is a registry mutation and
  not an agent reconfiguration.
