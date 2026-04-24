# AION v2 User Guide

**Version**: 1.0  
**Last Updated**: 2024-12-09

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Getting Started](#getting-started)
4. [CLI Reference](#cli-reference)
5. [Use Case Examples](#use-case-examples)
6. [Troubleshooting](#troubleshooting)

---

## Introduction

AION v2 is a versioned truth infrastructure for AI systems. It provides cryptographically-signed, versioned business rules that AI systems can consume and prove they used.

### Key Features

- **Tamper-Evident**: Every version is cryptographically signed
- **Offline-First**: No network or server required
- **Regulatory Compliant**: Meets SOX, HIPAA, GDPR requirements
- **Fast**: Sub-millisecond verification

### Core Concepts

| Concept | Description |
|---------|-------------|
| **AION File** | A binary file containing versioned rules with signatures |
| **Version** | A snapshot of rules at a point in time |
| **Author** | A numeric ID identifying who created a version |
| **Signing Key** | An Ed25519 key pair for cryptographic signatures |
| **Rules** | Business context your AI system consumes |

---

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/copyleftdev/aion-context.git
cd aion-context/aion-context

# Build release binary
cargo build --release

# Binary is at ./target/release/aion
./target/release/aion --version

# Optionally, install to PATH
sudo cp ./target/release/aion /usr/local/bin/
```

### Verify Installation

```bash
aion --version
# Output: aion 0.1.0

aion --help
# Shows all available commands
```

---

## Getting Started

### Step 1: Generate a Signing Key

Every author needs a signing key to create and update AION files.

```bash
# Generate a new key with author ID 1001
aion key generate 1001 --description "Alice - Risk Analyst"

# Verify the key was created
aion key list
```

**Output:**
```
Stored keys:
  1001: Alice - Risk Analyst (created: 2024-12-09T14:30:00Z)
```

### Step 2: Create Your First AION File

Create an AION file with initial business rules:

```bash
# Create a rules file
echo "fraud_threshold: 1000
risk_level: medium
max_transaction: 50000" > rules.txt

# Initialize AION file
aion init policy.aion \
  --author 1001 \
  --key 1001 \
  --rules rules.txt \
  --message "Initial fraud detection policy"
```

**Output:**
```
✓ Created policy.aion
  File ID: 0x7a3f9b2c1d4e5f6a
  Version: 1
  Author: 1001
```

### Step 3: Verify the File

Always verify files before using them:

```bash
aion verify policy.aion
```

**Output:**
```
✓ File verification: PASSED

Summary:
  Versions: 1
  Signatures: 1 (all valid)
  Hash chain: Valid
  Integrity: Valid
```

### Step 4: Update Rules (Commit a New Version)

When rules change, commit a new version:

```bash
# Update rules
echo "fraud_threshold: 800
risk_level: high
max_transaction: 25000" > rules_v2.txt

# Commit new version
aion commit policy.aion \
  --author 1001 \
  --key 1001 \
  --rules rules_v2.txt \
  --message "Tightened fraud thresholds"
```

**Output:**
```
✓ Committed version 2 to policy.aion
  Author: 1001
  Message: Tightened fraud thresholds
```

### Step 5: View History

See all versions and who created them:

```bash
aion show policy.aion history
```

**Output:**
```
Version History:
  v1  2024-12-09T14:30:00Z  Author 1001  "Initial fraud detection policy"
  v2  2024-12-09T14:35:00Z  Author 1001  "Tightened fraud thresholds"
```

### Step 6: Extract Current Rules

Get the current rules for your AI system:

```bash
aion show policy.aion rules
```

**Output:**
```
fraud_threshold: 800
risk_level: high
max_transaction: 25000
```

---

## CLI Reference

### Global Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Print help information |
| `-V, --version` | Print version |

### `aion init` - Create New File

Create a new AION file with initial rules.

```bash
aion init <FILE> --author <ID> --key <KEY_ID> [OPTIONS]
```

| Option | Required | Description |
|--------|----------|-------------|
| `<FILE>` | Yes | Path to create the AION file |
| `-a, --author` | Yes | Author ID (numeric) |
| `-k, --key` | Yes | Signing key ID from keystore |
| `-r, --rules` | No | Rules file (stdin if omitted) |
| `-m, --message` | No | Commit message (default: "Genesis version") |
| `--force` | No | Overwrite existing file |
| `--no-encryption` | No | Disable encryption (not recommended) |

**Examples:**

```bash
# From file
aion init policy.aion -a 1001 -k 1001 -r rules.txt -m "Initial policy"

# From stdin
cat rules.json | aion init policy.aion -a 1001 -k 1001 -m "Initial policy"

# Overwrite existing
aion init policy.aion -a 1001 -k 1001 -r rules.txt --force
```

### `aion commit` - Add New Version

Commit a new version to an existing AION file.

```bash
aion commit <FILE> --author <ID> --key <KEY_ID> --message <MSG> [OPTIONS]
```

| Option | Required | Description |
|--------|----------|-------------|
| `<FILE>` | Yes | Path to the AION file |
| `-a, --author` | Yes | Author ID (numeric) |
| `-k, --key` | Yes | Signing key ID |
| `-m, --message` | Yes | Commit message |
| `-r, --rules` | No | New rules file (stdin if omitted) |

**Examples:**

```bash
# From file
aion commit policy.aion -a 1001 -k 1001 -r new_rules.txt -m "Updated thresholds"

# Different author (requires their key)
aion commit policy.aion -a 2002 -k 2002 -r rules.txt -m "Compliance update"
```

### `aion verify` - Verify Integrity

Verify cryptographic integrity and signatures.

```bash
aion verify <FILE> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-f, --format` | Output format: `text`, `json`, `yaml` |
| `-v, --verbose` | Show detailed check results |

**Examples:**

```bash
# Basic verification
aion verify policy.aion

# Verbose output
aion verify policy.aion --verbose

# JSON output for scripts
aion verify policy.aion --format json
```

**JSON Output:**

```json
{
  "valid": true,
  "version_count": 5,
  "signatures_valid": true,
  "hash_chain_valid": true,
  "integrity_valid": true
}
```

### `aion show` - Display Information

Show file contents and metadata.

#### `aion show rules` - Current Rules

```bash
aion show <FILE> rules [--format text|json|yaml]
```

#### `aion show history` - Version History

```bash
aion show <FILE> history [--format text|json|yaml]
```

#### `aion show signatures` - Signature Details

```bash
aion show <FILE> signatures [--format text|json|yaml]
```

#### `aion show info` - Complete File Info

```bash
aion show <FILE> info [--format text|json|yaml]
```

### `aion key` - Key Management

Manage cryptographic signing keys.

#### `aion key generate` - Create New Key

```bash
aion key generate <KEY_ID> [--description <DESC>]
```

#### `aion key list` - List All Keys

```bash
aion key list
```

#### `aion key export` - Export Key

```bash
aion key export <KEY_ID> --output <FILE>
```

Exports the key encrypted with a password you provide.

#### `aion key import` - Import Key

```bash
aion key import <KEY_ID> --input <FILE>
```

Imports a previously exported key (requires password).

#### `aion key delete` - Delete Key

```bash
aion key delete <KEY_ID> [--force]
```

**Warning**: Deleted keys cannot be recovered!

---

## Use Case Examples

### Healthcare: Drug Interaction Rules

**Scenario**: Hospital AI checks drug interactions. FDA requires audit trail.

```bash
# Chief Pharmacologist creates initial rules
aion key generate 5001 --description "Dr. Smith - Chief Pharmacologist"

aion init drug_interactions.aion \
  -a 5001 -k 5001 \
  -r interactions_v1.json \
  -m "Initial FDA-approved interaction database"

# Monthly update after FDA guidance
aion commit drug_interactions.aion \
  -a 5001 -k 5001 \
  -r interactions_v2.json \
  -m "Updated per FDA guidance 2024-12-01"

# Audit query: What rules were active on Dec 5th?
aion show drug_interactions.aion history --format json
# Returns version active at that timestamp
```

### Financial Services: Fraud Detection

**Scenario**: Real-time fraud detection with hourly rule updates.

```bash
# Risk team has multiple analysts
aion key generate 3001 --description "Alice - Senior Risk Analyst"
aion key generate 3002 --description "Bob - Risk Manager"

# Alice creates initial policy
aion init fraud_policy.aion \
  -a 3001 -k 3001 \
  -r fraud_rules.yaml \
  -m "Q4 2024 fraud detection baseline"

# Bob updates after incident
aion commit fraud_policy.aion \
  -a 3002 -k 3002 \
  -r fraud_rules_v2.yaml \
  -m "Tightened velocity checks after Dec-8 incident"

# Regulator asks: Who authorized the rule change?
aion show fraud_policy.aion signatures
# Shows: v2 signed by Author 3002 (Bob) with valid Ed25519 signature
```

### Legal AI: Contract Review Rules

**Scenario**: AI reviews contracts against compliance rules.

```bash
# Create GDPR compliance rules
aion init gdpr_rules.aion \
  -a 4001 -k 4001 \
  -r gdpr_v1.json \
  -m "GDPR compliance rules 2024"

# Client asks: What rules did AI use for contract #12345?
# Your system logs: contract_12345 -> gdpr_rules.aion v3

# Prove it:
aion verify gdpr_rules.aion
aion show gdpr_rules.aion info --format json > audit_evidence.json
```

### CI/CD Integration

**Scenario**: Automated rule deployment in pipeline.

```bash
#!/bin/bash
# deploy_rules.sh

# Verify before deployment
if ! aion verify production_rules.aion --format json | jq -e '.valid'; then
  echo "ERROR: Rule file verification failed!"
  exit 1
fi

# Extract rules for deployment
aion show production_rules.aion rules > /app/config/rules.yaml

# Log the version deployed
VERSION=$(aion show production_rules.aion info --format json | jq -r '.current_version')
echo "Deployed rules version: $VERSION"
```

---

## Troubleshooting

### Error: "Key not found"

**Symptom:**
```
Error: Key 1001 not found in keystore
```

**Solution:**
```bash
# List available keys
aion key list

# Generate the missing key
aion key generate 1001 --description "Your name"
```

### Error: "File already exists"

**Symptom:**
```
Error: File policy.aion already exists
```

**Solution:**
```bash
# Use --force to overwrite
aion init policy.aion -a 1001 -k 1001 -r rules.txt --force

# Or use commit to add a new version
aion commit policy.aion -a 1001 -k 1001 -r rules.txt -m "Updated rules"
```

### Error: "Verification failed"

**Symptom:**
```
✗ File verification: FAILED
  Hash chain: INVALID
```

**Possible Causes:**
1. File was modified outside of AION
2. File is corrupted
3. File was truncated during transfer

**Solution:**
```bash
# Get detailed error
aion verify policy.aion --verbose

# Check file integrity
sha256sum policy.aion

# Restore from backup if corrupted
```

### Error: "Invalid author ID"

**Symptom:**
```
Error: Invalid author ID 'alice': must be a number
```

**Solution:**
Author IDs must be numeric:
```bash
# Wrong
aion init policy.aion -a alice -k 1001

# Correct
aion init policy.aion -a 1001 -k 1001
```

### Error: "Rules file not found"

**Symptom:**
```
Error: Could not read rules file: rules.txt
```

**Solution:**
```bash
# Check file exists
ls -la rules.txt

# Use absolute path
aion init policy.aion -a 1001 -k 1001 -r /path/to/rules.txt

# Or pipe from stdin
cat rules.txt | aion init policy.aion -a 1001 -k 1001
```

### Keyring Permission Issues (Linux)

**Symptom:**
```
Error: Failed to access keyring
```

**Solution:**
```bash
# Ensure D-Bus session is running
eval $(dbus-launch --sh-syntax)

# Or use environment variable for keyring
export DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u)/bus

# Check Secret Service is installed
sudo apt install gnome-keyring  # Debian/Ubuntu
sudo dnf install gnome-keyring  # Fedora
```

### Large File Performance

**Symptom:** Slow operations on files with many versions.

**Optimization:**
```bash
# For verification, use JSON format and pipe to jq for specific checks
aion verify large_file.aion --format json | jq '.valid'

# For history, limit output
aion show large_file.aion history | tail -20
```

---

## Best Practices

### Key Management

1. **Use descriptive names**: `--description "Jane Doe - Risk Manager"`
2. **Backup exported keys**: Store encrypted exports securely
3. **Rotate keys periodically**: Generate new keys for new team members
4. **Never share private keys**: Each author should have their own key

### File Management

1. **Verify before use**: Always run `aion verify` before consuming rules
2. **Meaningful messages**: Write clear commit messages for audit trail
3. **Regular backups**: Backup AION files with your regular backup process
4. **Version control**: Store AION files in Git for additional history

### CI/CD Integration

1. **Verify in pipeline**: Add verification step before deployment
2. **Log versions**: Record which version was deployed when
3. **Automate commits**: Use CI to commit rule updates with proper attribution

---

## Getting Help

- **Documentation**: `aion --help`, `aion <command> --help`
- **Issues**: https://github.com/copyleftdev/aion-context/issues
- **RFCs**: See `rfcs/` directory for technical specifications

---

*AION v2 - Versioned Truth Infrastructure for AI Systems*
