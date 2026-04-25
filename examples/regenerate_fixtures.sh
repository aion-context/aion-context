#!/usr/bin/env bash
#
# regenerate_fixtures.sh — regenerate the six per-industry demo .aion
# files from their rules.yaml on a fresh clone.
#
# The original extracted fixtures (from aion-v2) were signed with keys
# that did not survive the extraction, so they could not be verified by
# external readers. Issue #65 removed them in favor of this script —
# anyone who clones the repo can produce locally-valid signed fixtures
# in a few seconds.
#
# Usage:
#   ./examples/regenerate_fixtures.sh              # uses cargo-built aion
#   AION_BIN=/path/to/aion ./examples/...          # uses a pre-built binary
#
# Per-fixture metadata is stored in the keystore (OS keyring by default).
# Re-running the script is idempotent: existing keys are reused, .aion
# files are overwritten via --force.
#
# To verify a regenerated fixture:
#   1. Save your registry to disk:
#        aion registry export --output /tmp/fixtures.registry.json
#      (or hand-write a registry JSON pinning these author IDs)
#   2. Run:
#        aion verify --registry /tmp/fixtures.registry.json \
#                    examples/finance/trading_compliance.aion

set -euo pipefail

AION_BIN="${AION_BIN:-cargo run --release --quiet --bin aion --}"
EXAMPLES_DIR="$(cd "$(dirname "$0")" && pwd)"

# industry | output basename | rules YAML | author id | message
FIXTURES=$(cat <<'EOF'
enterprise    | enterprise_ai_governance | ai_governance_policy.yaml | 81001 | Enterprise AI governance policy genesis
finance       | trading_compliance       | rules.yaml                | 81002 | SOX trading compliance rules genesis
healthcare    | patient_data_rules       | rules.yaml                | 81003 | HIPAA patient data handling genesis
legal         | contract_policy          | rules.yaml                | 81004 | Contract review policy genesis
manufacturing | quality_control          | rules.yaml                | 81005 | ISO 9001 quality procedures genesis
retail        | pricing_rules            | rules.yaml                | 81006 | Dynamic pricing rules genesis
EOF
)

echo "regenerating fixtures under: $EXAMPLES_DIR"
echo ""

while IFS='|' read -r industry name rules_yaml author message; do
    industry="$(echo "$industry" | xargs)"
    name="$(echo "$name" | xargs)"
    rules_yaml="$(echo "$rules_yaml" | xargs)"
    author="$(echo "$author" | xargs)"
    message="$(echo "$message" | xargs)"
    [ -z "$industry" ] && continue

    rules="$EXAMPLES_DIR/$industry/$rules_yaml"
    aion_file="$EXAMPLES_DIR/$industry/$name.aion"

    if [ ! -f "$rules" ]; then
        echo "  ⚠ $industry — rules file missing: $rules"
        continue
    fi

    # Generate or reuse the per-fixture key. CLI returns non-zero if the
    # key already exists; that's expected on re-runs and is fine.
    $AION_BIN key generate --id "$author" --description "$industry fixture key" >/dev/null 2>&1 || true

    $AION_BIN init "$aion_file" \
        --author "$author" \
        --key "$author" \
        --rules "$rules" \
        --message "$message" \
        --force >/dev/null

    echo "  ✓ $industry — $aion_file"
done <<<"$FIXTURES"

echo ""
echo "Done. Six .aion fixtures generated."
echo ""
echo "These are signed with ephemeral per-fixture keys stored in your"
echo "OS keyring. They are local-only; do not redistribute them as"
echo "authoritative artifacts."
