# AION v2 Developer Guide

**Version**: 1.0  
**Last Updated**: 2024-12-09

Technical documentation for developers contributing to or integrating with AION v2.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Module Structure](#module-structure)
3. [API Reference](#api-reference)
4. [Development Setup](#development-setup)
5. [Contributing Guide](#contributing-guide)
6. [Code Style](#code-style)
7. [Testing](#testing)
8. [RFC Index](#rfc-index)

---

## Architecture Overview

### System Design

AION v2 follows a layered architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────┐
│                     CLI Layer (bin/aion.rs)                 │
│        init, commit, verify, show, key commands             │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│                   Operations Layer                          │
│     init_file, commit_version, verify_file, show_*          │
└────────┬───────────────┬───────────────┬────────────────────┘
         │               │               │
┌────────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
│  Signature    │ │   Parser    │ │  Keystore   │
│    Chain      │ │ (zero-copy) │ │  (OS ring)  │
└────────┬──────┘ └──────┬──────┘ └──────┬──────┘
         │               │               │
┌────────▼───────────────▼───────────────▼────────────────────┐
│                    Crypto Layer                             │
│        Ed25519, ChaCha20-Poly1305, BLAKE3, HKDF             │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│                    Core Types                               │
│           FileId, AuthorId, VersionNumber, AionError        │
└─────────────────────────────────────────────────────────────┘
```

### Key Design Principles

1. **Offline-First**: Zero network dependency for core operations
2. **Cryptographic Integrity**: Ed25519 signatures, BLAKE3 hashing
3. **Zero-Copy Parsing**: Memory-efficient file access via `zerocopy`
4. **Tiger Style**: No panics, explicit error handling
5. **Type Safety**: Newtype pattern prevents ID confusion

### Data Flow

```
User Rules → Encrypt (ChaCha20) → Sign (Ed25519) → Serialize → Write File
     ↓
Read File → Parse (zero-copy) → Verify Signatures → Decrypt → User Rules
```

---

## Module Structure

### Core Modules

| Module | Purpose | Key Types |
|--------|---------|-----------|
| `types` | Domain primitives | `FileId`, `AuthorId`, `VersionNumber` |
| `error` | Error handling | `AionError`, `Result<T>` |
| `crypto` | Cryptographic ops | `SigningKey`, `VerifyingKey`, `encrypt`, `decrypt` |
| `parser` | Zero-copy parsing | `AionParser`, `FileHeader` |
| `serializer` | File construction | `AionSerializer`, `AionFile` |
| `signature_chain` | Version signing | `sign_version`, `verify_signatures_batch` |
| `operations` | High-level API | `init_file`, `commit_version`, `verify_file` |
| `keystore` | Key management | `KeyStore`, `generate_and_store` |
| `audit` | Audit trail | `AuditEntry`, `ActionCode` |
| `string_table` | String storage | `StringTable`, `StringTableBuilder` |

### Module Dependency Graph

```
operations
    ├── crypto
    ├── parser
    ├── serializer
    ├── signature_chain
    │       └── crypto
    ├── keystore
    │       └── crypto
    └── types

error (standalone - used by all)
```

---

## API Reference

### Operations Module (Primary API)

#### `init_file`

Create a new AION file with genesis version.

```rust
use aion_context::operations::{init_file, InitOptions};
use aion_context::crypto::SigningKey;
use aion_context::types::AuthorId;

let signing_key = SigningKey::generate();
let options = InitOptions {
    author_id: AuthorId::new(1001),
    signing_key: &signing_key,
    message: "Initial policy",
    timestamp: None, // Use current time
};

let result = init_file(Path::new("policy.aion"), &rules, &options)?;
println!("Created file with ID: {:?}", result.file_id);
```

#### `commit_version`

Add a new version to an existing file.

```rust
use aion_context::operations::{commit_version, CommitOptions};

let options = CommitOptions {
    author_id: AuthorId::new(1001),
    signing_key: &signing_key,
    message: "Updated thresholds",
    timestamp: None,
};

let result = commit_version(Path::new("policy.aion"), &new_rules, &options)?;
println!("Committed version: {}", result.version_number);
```

#### `verify_file`

Verify cryptographic integrity.

```rust
use aion_context::operations::verify_file;

let report = verify_file(Path::new("policy.aion"))?;

if report.is_valid {
    println!("File is valid");
    println!("Versions: {}", report.version_count);
} else {
    for error in &report.errors {
        eprintln!("Error: {}", error);
    }
}

// Check for temporal warnings (informational only)
for warning in &report.temporal_warnings {
    println!("Warning: {}", warning);
}
```

#### `show_current_rules`

Extract decrypted rules.

```rust
use aion_context::operations::show_current_rules;

let rules = show_current_rules(Path::new("policy.aion"))?;
println!("Rules: {}", String::from_utf8_lossy(&rules));
```

### Crypto Module

#### Key Generation

```rust
use aion_context::crypto::SigningKey;

let signing_key = SigningKey::generate();
let verifying_key = signing_key.verifying_key();
```

#### Signing and Verification

```rust
let message = b"data to sign";
let signature = signing_key.sign(message);

// Verify
verifying_key.verify(message, &signature)?;
```

#### Encryption/Decryption

```rust
use aion_context::crypto::{encrypt, decrypt, generate_nonce};

let key = [0u8; 32]; // 256-bit key
let nonce = generate_nonce();
let aad = b"additional authenticated data";

let ciphertext = encrypt(&key, &nonce, plaintext, aad)?;
let plaintext = decrypt(&key, &nonce, &ciphertext, aad)?;
```

#### Hashing

```rust
use aion_context::crypto::{hash, keyed_hash};

let digest = hash(data);
let keyed_digest = keyed_hash(&key, data);
```

### Types Module

```rust
use aion_context::types::{FileId, AuthorId, VersionNumber};

// Type-safe IDs prevent mixing up different ID types
let file_id = FileId::random();
let author_id = AuthorId::new(1001);
let version = VersionNumber::genesis(); // Always 1

// Version increment with overflow protection
let next = version.next()?; // Returns Result, not panic
```

### Error Handling

```rust
use aion_context::{AionError, Result};

fn example() -> Result<()> {
    // All operations return Result<T, AionError>
    let report = verify_file(path)?;
    
    // Pattern match on specific errors
    match some_operation() {
        Ok(value) => println!("Success: {:?}", value),
        Err(AionError::FileNotFound { path }) => {
            eprintln!("File not found: {}", path.display());
        }
        Err(AionError::SignatureInvalid { version }) => {
            eprintln!("Invalid signature at version {}", version);
        }
        Err(e) => return Err(e),
    }
    
    Ok(())
}
```

---

## Development Setup

### Prerequisites

- Rust 1.70+ (install via [rustup](https://rustup.rs))
- Git

### Clone and Build

```bash
git clone https://github.com/copyleftdev/aion-context.git
cd aion-context/aion-context

# Build
cargo build --release

# Run tests
cargo test --all

# Run clippy
cargo clippy -- -D warnings

# Generate docs
cargo doc --open
```

### Development Tools

```bash
# Install recommended tools
cargo install cargo-audit      # Security audit
cargo install cargo-tarpaulin  # Code coverage
cargo install cargo-fuzz       # Fuzz testing
cargo install cargo-criterion  # Benchmarking
```

### IDE Setup

**VS Code** with rust-analyzer extension recommended.

Settings for consistent formatting:
```json
{
    "rust-analyzer.checkOnSave.command": "clippy",
    "editor.formatOnSave": true
}
```

---

## Contributing Guide

### Branch Workflow

1. **Create feature branch**: `git checkout -b feature/<issue>-<description>`
2. **Make changes**: Follow code style guidelines
3. **Test**: `cargo test --all`
4. **Lint**: `cargo clippy -- -D warnings`
5. **Format**: `cargo fmt`
6. **Commit**: Use conventional commits
7. **Push**: `git push -u origin feature/<issue>-<description>`
8. **PR**: Create pull request, reference issue

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(crypto): Add batch signature verification
fix(parser): Handle zero-length rules correctly
docs(user): Add troubleshooting section
test(operations): Add temporal validation tests
refactor(types): Simplify VersionNumber::next
```

### Pull Request Checklist

- [ ] Tests pass: `cargo test --all`
- [ ] No clippy warnings: `cargo clippy -- -D warnings`
- [ ] Code formatted: `cargo fmt --check`
- [ ] Documentation updated if needed
- [ ] Commit messages follow convention
- [ ] PR description explains changes
- [ ] Issue referenced: `Closes #XX`

### Code Review Standards

- All PRs require review before merge
- Squash merge to main branch
- Delete feature branch after merge

---

## Code Style

### Tiger Style Rules (NASA Power of 10)

1. **No `unwrap()`, `expect()`, `panic!()`** in production code
2. **Explicit error handling** with `Result<T, E>`
3. **Maximum 60 lines** per function
4. **Maximum 15** cyclomatic complexity
5. **All loops must terminate** provably
6. **No raw pointers** without safety proof

### Rust Conventions

```rust
// Types: PascalCase
pub struct FileHeader { }

// Functions: snake_case
pub fn verify_file(path: &Path) -> Result<Report> { }

// Constants: SCREAMING_SNAKE_CASE
pub const MAX_FILE_SIZE: u64 = 1_073_741_824;

// Imports: grouped and sorted
use std::path::Path;

use anyhow::Context;
use thiserror::Error;

use crate::crypto::SigningKey;
use crate::types::FileId;
```

### Documentation

All public items must have doc comments:

```rust
/// Verify the integrity and authenticity of an AION file.
///
/// # Arguments
///
/// * `path` - Path to the AION file
///
/// # Returns
///
/// * `Ok(VerificationReport)` - Detailed verification results
/// * `Err(AionError)` - On critical failure
///
/// # Example
///
/// ```no_run
/// let report = verify_file(Path::new("policy.aion"))?;
/// assert!(report.is_valid);
/// ```
pub fn verify_file(path: &Path) -> Result<VerificationReport> {
    // ...
}
```

---

## Testing

### Test Categories

| Category | Location | Purpose |
|----------|----------|---------|
| Unit tests | `src/*.rs` | Module-level tests |
| Integration tests | `tests/integration_tests.rs` | End-to-end workflows |
| CLI tests | `tests/cli_integration_tests.rs` | Command-line interface |
| Crypto vectors | `tests/crypto_test_vectors.rs` | RFC compliance |
| Doc tests | Inline in source | Example verification |

### Running Tests

```bash
# All tests
cargo test --all

# Specific test
cargo test test_verify_file

# Integration tests only
cargo test --test integration_tests

# With output
cargo test -- --nocapture

# Coverage
cargo tarpaulin --out Html
```

### Writing Tests

```rust
#[test]
fn test_feature_description() {
    // Arrange
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.aion");
    
    // Act
    let result = operation(&file_path);
    
    // Assert
    assert!(result.is_ok());
    assert_eq!(result.unwrap().version_count, 1);
}
```

### Test Coverage Target

- **95%** coverage on critical modules (crypto, operations)
- **90%** coverage overall
- All public APIs must have tests

---

## RFC Index

Technical specifications are in `rfcs/` directory:

| RFC | Title | Status |
|-----|-------|--------|
| [RFC-0000](../rfcs/RFC-0000-index.md) | Index | Published |
| [RFC-0001](../rfcs/RFC-0001-architecture.md) | Architecture | Approved |
| [RFC-0002](../rfcs/RFC-0002-file-format.md) | File Format | Approved |
| [RFC-0003](../rfcs/RFC-0003-cryptography.md) | Cryptography | Approved |
| [RFC-0004](../rfcs/RFC-0004-keystore.md) | Key Store | Approved |
| [RFC-0005](../rfcs/RFC-0005-signature-chain.md) | Signature Chain | Approved |
| [RFC-0006](../rfcs/RFC-0006-threat-model.md) | Threat Model | Approved |
| [RFC-0007](../rfcs/RFC-0007-tiger-style.md) | Tiger Style | Approved |

See [RFC-0000](../rfcs/RFC-0000-index.md) for complete index.

---

## Performance Targets

From RFC-0018:

| Operation | Target | Measured |
|-----------|--------|----------|
| File creation (1MB) | <10ms | ~224µs |
| Version commit (1MB) | <5ms | ~300µs |
| Signature verification | <1ms | ~50µs |
| File parsing (100 versions) | <3ms | ~1ms |

Run benchmarks:
```bash
cargo bench
```

---

## Getting Help

- **API Docs**: `cargo doc --open`
- **User Guide**: [docs/USER_GUIDE.md](USER_GUIDE.md)
- **Security**: [docs/SECURITY_AUDIT_GUIDE.md](SECURITY_AUDIT_GUIDE.md)
- **Issues**: https://github.com/copyleftdev/aion-context/issues

---

*AION v2 - Versioned Truth Infrastructure for AI Systems*
