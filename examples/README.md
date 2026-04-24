# AION v2 Industry Examples

Real-world examples of AION files for different industries, demonstrating
how versioned, cryptographically-signed business context can be used.

## Examples

| Industry | File | Description |
|----------|------|-------------|
| **Healthcare** | `patient_data_rules.aion` | HIPAA-compliant PHI handling rules |
| **Finance** | `trading_compliance.aion` | SOX-compliant trading desk rules |
| **Legal** | `contract_policy.aion` | Legal document processing rules |
| **Manufacturing** | `quality_control.aion` | ISO 9001 quality procedures |
| **Retail** | `pricing_rules.aion` | Dynamic pricing and promotion rules |

## Creating Examples

```bash
# Initialize a new AION file
./target/release/aion init examples/healthcare/patient_data_rules.aion \
    --author 1001 \
    --key healthcare-admin \
    --rules examples/healthcare/rules.yaml \
    --message "Initial HIPAA compliance rules"

# Commit an update
./target/release/aion commit examples/healthcare/patient_data_rules.aion \
    --author 1001 \
    --key healthcare-admin \
    --rules examples/healthcare/rules_v2.yaml \
    --message "Added breach notification procedures"
```

## Verifying Examples

```bash
# Verify file integrity
./target/release/aion verify examples/finance/trading_compliance.aion

# Show version history
./target/release/aion show history examples/finance/trading_compliance.aion

# Generate compliance report
./target/release/aion report examples/finance/trading_compliance.aion -f sox
```

## Rule File Format

Rules can be any format your AI system understands:
- YAML (recommended for readability)
- JSON (recommended for programmatic access)
- Plain text
- Binary data

The content is stored as-is with cryptographic signatures ensuring integrity.
