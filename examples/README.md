# Industry Examples

Six per-industry rules YAMLs that demonstrate how a real organization
might shape its policy content for an `.aion` file. Each directory
ships a `rules.yaml` (or equivalent) — the `.aion` fixtures are
regenerated locally with the script below.

| Industry | Rules file | Generated fixture | Domain |
|----------|------------|-------------------|--------|
| **Enterprise** | `enterprise/ai_governance_policy.yaml` | `enterprise_ai_governance.aion` | AI governance & guardrails |
| **Finance** | `finance/rules.yaml` | `trading_compliance.aion` | SOX-compliant trading desk rules |
| **Healthcare** | `healthcare/rules.yaml` | `patient_data_rules.aion` | HIPAA PHI handling |
| **Legal** | `legal/rules.yaml` | `contract_policy.aion` | Contract review |
| **Manufacturing** | `manufacturing/rules.yaml` | `quality_control.aion` | ISO 9001 quality |
| **Retail** | `retail/rules.yaml` | `pricing_rules.aion` | Dynamic pricing |

## Regenerate the fixtures

```bash
./examples/regenerate_fixtures.sh
```

This script generates a per-fixture key (stored in your OS keyring),
runs `aion init` against each rules file, and writes the resulting
`.aion` next to it. Re-running is idempotent — keys are reused,
fixtures are overwritten via `--force`.

The generated `.aion` files are gitignored (`examples/*/*.aion`) so
they don't end up committed. They are local-only and **must not be
redistributed as authoritative artifacts** — the signing keys are
ephemeral and verifiers other than you cannot establish a chain of
trust to them.

## Why a script and not committed fixtures

The earlier extracted `.aion` fixtures were signed with keys that did
not survive the original aion-v2 → aion-context extraction. External
readers could not verify them, so they were dead data shipping
forever. See issue #65 for the full reasoning.

Replacing them with a one-shot regeneration script means:

- Anyone who clones the repo can produce locally-valid signed
  fixtures in seconds.
- The fixtures are obviously local (gitignored), not pretending to
  be authoritative.
- The script doubles as a working "hello world" for `aion init`.

## Working with the fixtures

```bash
# Regenerate
./examples/regenerate_fixtures.sh

# Verify (you'll need to write or export a registry pinning the
# author IDs the script used — 81001..81006)
aion verify --registry /tmp/fixtures.registry.json \
            examples/finance/trading_compliance.aion

# Show version history
aion show --registry /tmp/fixtures.registry.json \
          examples/finance/trading_compliance.aion history

# Generate a compliance report
aion report --registry /tmp/fixtures.registry.json \
            examples/finance/trading_compliance.aion -f sox
```

## Rules format

Each `rules.yaml` is plain YAML — `aion init` stores its bytes verbatim
inside the encrypted_rules section of the resulting `.aion`. The
format is up to your application; YAML, JSON, plain text, or arbitrary
binary all work. The cryptographic guarantees (signatures, hash chain,
integrity hash) sit on top of whatever bytes you give them.

## Other examples in this directory

The Rust `*.rs` examples (next to these industry directories) are
self-contained, runnable demonstrations of specific subsystems. See
each book chapter under
[`book/src/examples/`](../book/src/examples/) for narrative walkthroughs.
