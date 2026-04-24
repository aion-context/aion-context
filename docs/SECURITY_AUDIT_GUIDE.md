# AION v2 Security Audit Guide

**Version:** 1.0  
**Date:** 2024-11-26  
**Status:** Ready for External Audit

## Executive Summary

AION v2 is a cryptographically-secured versioned truth infrastructure designed for tamper-evident storage of business-critical rules. This guide provides external security auditors with comprehensive information about the system's architecture, threat model, attack surface, and security-critical components.

### Key Security Properties

1. **Tamper-Evidence**: Cryptographic signatures ensure any modification is detectable
2. **Confidentiality**: ChaCha20-Poly1305 encryption protects sensitive rules data
3. **Non-Repudiation**: Ed25519 signatures provide strong author attribution
4. **Offline-First**: Zero server dependency eliminates entire classes of attacks
5. **Memory Safety**: Rust implementation prevents memory corruption vulnerabilities

### Critical Success Factors

- **No signature verification bypasses**
- **No private key extraction from keystore**
- **No file format parser exploits**
- **No cryptographic implementation flaws**
- **No denial of service vectors**

## System Architecture Overview

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                        AION v2 CLI                          │
│  (init, commit, verify, show, key commands)                 │
└────────────────┬────────────────────────────────────────────┘
                 │
    ┌────────────┴────────────┐
    │                         │
┌───▼──────────┐      ┌──────▼──────────┐
│  Operations  │      │   Keystore      │
│  Module      │      │   Module        │
│              │      │                 │
│ - init_file  │      │ - generate_key  │
│ - commit     │      │ - load_key      │
│ - verify     │      │ - store_key     │
└───┬──────────┘      └──────┬──────────┘
    │                        │
    │                        │
┌───▼────────────────────────▼────────┐
│         Crypto Module               │
│                                     │
│ - Ed25519 signing/verification      │
│ - ChaCha20-Poly1305 encryption      │
│ - BLAKE3 hashing                    │
│ - Key derivation (HKDF)             │
└───┬─────────────────────────────────┘
    │
┌───▼─────────────────────────────────┐
│     File Format & Parser            │
│                                     │
│ - Zero-copy parsing                 │
│ - Section management                │
│ - Serialization/deserialization     │
└─────────────────────────────────────┘
```

### Trust Boundaries

1. **User Input → CLI**: Command-line arguments, file paths
2. **File System → Parser**: Binary file data
3. **OS Keyring → Keystore**: Private keys
4. **Crypto Libraries → Crypto Module**: External dependencies

## Attack Surface Analysis

### 1. File Format Parser (HIGH PRIORITY)

**Entry Points:**
- `AionParser::new(data: &[u8])` - Primary parsing entry point
- `parse_file_header()` - Header validation
- Section readers for encrypted rules, versions, signatures

**Attack Vectors:**
- **Malformed Headers**: Invalid magic numbers, version fields, offsets
- **Integer Overflow**: Size calculations in `u64` arithmetic
- **Out-of-Bounds Access**: Section offsets/lengths pointing beyond file
- **Resource Exhaustion**: Extremely large section counts
- **Zip Bomb**: Compressed data expanding to huge sizes

**Security Controls:**
- Zero-copy parsing using `zerocopy` crate
- Comprehensive bounds checking before all array access
- Size limits enforced: `MAX_FILE_SIZE = 1GB`
- Magic number and version validation
- Offset sanity checks against file size

**Test Coverage:**
- Fuzz testing with `cargo-fuzz`
- Malformed file integration tests
- Edge case unit tests (zero-length, max values)

**Files to Audit:**
- `src/parser.rs` (primary parser implementation)
- `src/serializer.rs` (file creation)
- `tests/integration_tests.rs` (file corruption tests)

### 2. Cryptographic Operations (CRITICAL)

**Entry Points:**
- `SigningKey::generate()` - Key generation
- `SigningKey::sign(message)` - Signature creation
- `VerifyingKey::verify(message, signature)` - Signature verification
- `encrypt(key, nonce, plaintext, aad)` - ChaCha20-Poly1305 encryption
- `decrypt(key, nonce, ciphertext, aad)` - Decryption
- `hash(data)` - BLAKE3 hashing
- `derive_file_key(file_id)` - HKDF key derivation

**Attack Vectors:**
- **Weak RNG**: Predictable key generation
- **Nonce Reuse**: ChaCha20 with repeated nonces
- **Signature Malleability**: Modified signatures that still verify
- **Timing Attacks**: Side-channel information leakage
- **Memory Disclosure**: Private keys in memory dumps
- **Parameter Validation**: Invalid key/nonce lengths

**Security Controls:**
- Uses `ed25519-dalek` v2.2.0 (audited library)
- Uses `chacha20poly1305` v0.10.1 (RustCrypto audited)
- Uses `blake3` v1.5.0 (official implementation)
- RNG from OS entropy (`rand::rngs::OsRng`)
- Zeroization of sensitive data with `zeroize` crate
- Constant-time operations in crypto libraries

**Test Coverage (37 tests in `tests/crypto_test_vectors.rs`):**
- RFC 8032 Ed25519 test vectors (5 tests including 1023-byte message)
- RFC 8439 ChaCha20-Poly1305 test vectors (4 tests)
- BLAKE3 official test vectors (6 tests)
- Security tampering detection tests (12 tests):
  - Single-bit signature tampering (512 bit positions)
  - Single-bit message tampering
  - Ciphertext/AAD tampering detection
  - Wrong key/nonce rejection
  - Truncation detection
- Known-answer tests for determinism
- Edge case tests (10 tests)

**Files to Audit:**
- `src/crypto.rs` (cryptographic primitives)
- `tests/crypto_test_vectors.rs` (37 comprehensive test vectors)

### 3. Key Management (CRITICAL)

**Entry Points:**
- `KeyStore::generate_and_store(author_id, description)` - New key creation
- `KeyStore::load_signing_key(author_id)` - Key retrieval
- `KeyStore::export_encrypted(author_id, password)` - Key export
- `KeyStore::import_encrypted(author_id, password, data)` - Key import
- `KeyStore::delete_key(author_id)` - Key deletion

**Attack Vectors:**
- **Keyring Vulnerabilities**: OS-specific security bugs
- **Memory Disclosure**: Private keys in process memory
- **Privilege Escalation**: Unauthorized keyring access
- **Key Extraction Malware**: Targeted key theft
- **Weak Password**: Brute-force of exported keys
- **Backup Exposure**: Unencrypted key backups

**Security Controls:**
- OS keyring integration (`keyring` crate)
- Argon2id for password-based key derivation
- ChaCha20-Poly1305 for encrypted key export
- Memory zeroization after key use
- Key validation before storage
- Per-platform secure storage (macOS Keychain, Windows DPAPI, Linux Secret Service)

**Test Coverage:**
- Key generation and retrieval tests
- Export/import roundtrip tests
- Password strength validation
- Concurrent access tests

**Files to Audit:**
- `src/keystore.rs` (key management implementation)
- `src/bin/aion.rs` (CLI key commands)

### 4. File Operations (HIGH PRIORITY)

**Entry Points:**
- `init_file(path, rules, options)` - File creation
- `commit_version(path, rules, options)` - Version append
- `verify_file(path)` - Integrity verification
- `show_current_rules(path)` - Rules extraction
- `show_version_history(path)` - History inspection

**Attack Vectors:**
- **Path Traversal**: Reading/writing outside intended directory
- **Race Conditions**: TOCTOU attacks on file operations
- **Symlink Attacks**: Following malicious symbolic links
- **Atomic Write Failure**: Partial writes leaving corrupt file
- **File Permission Bypass**: Unauthorized file access

**Security Controls:**
- Path canonicalization before operations
- Atomic file writes with temporary files
- File permission checks
- Comprehensive error handling
- Rollback on operation failure

**Test Coverage:**
- Integration tests for full workflows
- File corruption detection tests
- Concurrent access tests
- Error path coverage

**Files to Audit:**
- `src/operations.rs` (file operation implementations)
- `tests/integration_tests.rs` (workflow tests)

### 5. CLI Interface (MEDIUM PRIORITY)

**Entry Points:**
- Command-line argument parsing (`clap`)
- File path inputs
- Password inputs (for key export/import)
- Standard input for rules data

**Attack Vectors:**
- **Command Injection**: Malicious filenames or arguments
- **Path Traversal**: Relative paths escaping intended directory
- **Buffer Overflow**: Extremely long arguments (mitigated by Rust)
- **Password Interception**: Plaintext password logging

**Security Controls:**
- Input validation and sanitization
- Path canonicalization
- Secure password input (`rpassword` crate)
- No password logging or display
- Argument length limits from OS

**Files to Audit:**
- `src/bin/aion.rs` (CLI implementation)

## Security-Critical Code Locations

### Signature Verification (CRITICAL - MUST NOT BYPASS)

**File**: `src/operations.rs`  
**Functions**:
```rust
// Line ~1800-2100
fn verify_file(file_path: &Path) -> Result<VerificationReport> {
    // CRITICAL: All signatures must be verified
    // CRITICAL: Hash chain must be validated
    // CRITICAL: Version sequence must be monotonic
}
```

**Audit Focus**:
- ✓ All signatures are verified (no early returns)
- ✓ Hash chain integrity is checked
- ✓ Version numbers are monotonically increasing
- ✓ No signature verification bypass paths
- ✓ Error handling doesn't skip verification

### Key Derivation (CRITICAL - MUST BE DETERMINISTIC)

**File**: `src/crypto.rs`  
**Functions**:
```rust
// Line ~200-250
pub fn derive_file_key(file_id: FileId) -> Result<[u8; 32]> {
    // CRITICAL: Must produce same key for same file_id
    // CRITICAL: Must use HKDF properly
    // CRITICAL: Salt must be consistent
}
```

**Audit Focus**:
- ✓ Deterministic key derivation
- ✓ Proper HKDF usage (salt, info)
- ✓ No entropy from non-deterministic sources
- ✓ Key length validation

### Nonce Generation (CRITICAL - MUST NEVER REPEAT)

**File**: `src/crypto.rs`  
**Functions**:
```rust
// Line ~150-170
pub fn generate_nonce() -> [u8; 12] {
    // CRITICAL: Must be cryptographically random
    // CRITICAL: Must never repeat
    // CRITICAL: Must use OS entropy
}
```

**Audit Focus**:
- ✓ Uses `OsRng` (not pseudo-random)
- ✓ 12-byte output (96 bits)
- ✓ No fallback to weak RNG
- ✓ Panic on RNG failure (fail-safe)

### Parser Bounds Checking (HIGH - PREVENT EXPLOITS)

**File**: `src/parser.rs`  
**Functions**:
```rust
// Throughout file, especially:
// Line ~100-300 (section readers)
fn encrypted_rules_bytes(&self) -> Result<&[u8]> {
    // HIGH: Must validate offsets against file size
    // HIGH: Must prevent out-of-bounds access
}
```

**Audit Focus**:
- ✓ All offsets validated before use
- ✓ Lengths validated against file size
- ✓ Integer overflow prevention in arithmetic
- ✓ No unsafe indexing

### Memory Zeroization (HIGH - PREVENT KEY LEAKAGE)

**File**: `src/crypto.rs`, `src/keystore.rs`  
**Locations**:
```rust
// crypto.rs - After key use
// keystore.rs - After password use, key decryption

// Use of `zeroize` trait:
impl Drop for SensitiveData {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
```

**Audit Focus**:
- ✓ All sensitive data zeroized after use
- ✓ Zeroization not optimized away by compiler
- ✓ Memory cleared before deallocation
- ✓ No copies left in temporary buffers

## Cryptographic Implementation Review

### Algorithms Used

| Algorithm | Purpose | Library | Version | Audit Status |
|-----------|---------|---------|---------|--------------|
| Ed25519 | Digital Signatures | `ed25519-dalek` | 2.2.0 | Audited by NCC Group |
| ChaCha20-Poly1305 | AEAD Encryption | `chacha20poly1305` | 0.10.1 | RustCrypto Audited |
| BLAKE3 | Cryptographic Hash | `blake3` | 1.5.0 | Official Implementation |
| HKDF | Key Derivation | `hkdf` | 0.12.3 | RustCrypto Audited |
| Argon2id | Password Hashing | `argon2` | 0.5.2 | RustCrypto Audited |

### Cryptographic Parameters

**Ed25519**:
- Key size: 256 bits (32 bytes)
- Signature size: 512 bits (64 bytes)
- Security level: ~128 bits
- Standard: RFC 8032

**ChaCha20-Poly1305**:
- Key size: 256 bits (32 bytes)
- Nonce size: 96 bits (12 bytes)
- Tag size: 128 bits (16 bytes)
- Security level: 256 bits (confidentiality), 128 bits (authenticity)
- Standard: RFC 8439

**BLAKE3**:
- Output size: 256 bits (32 bytes)
- Security level: 256 bits (collision resistance), 128 bits (preimage resistance)
- Keyed mode: 256-bit keys for MAC

**HKDF-SHA256**:
- Hash: SHA-256
- Key material: 256 bits
- Standard: RFC 5869

**Argon2id**:
- Memory: 64 MB (65536 KB)
- Iterations: 3
- Parallelism: 4 threads
- Salt size: 128 bits (16 bytes)
- Output: 256 bits (32 bytes)

### Random Number Generation

**Source**: `rand::rngs::OsRng`
- Uses OS-provided CSPRNG:
  - Linux: `/dev/urandom` via `getrandom()` syscall
  - macOS: `SecRandomCopyBytes()` from Security framework
  - Windows: `BCryptGenRandom()` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG`

**Usage Locations**:
- `SigningKey::generate()` - Ed25519 key generation
- `generate_nonce()` - ChaCha20-Poly1305 nonces
- `export_encrypted()` - Salt generation for Argon2id

### Known Cryptographic Issues

**None identified** in current implementation. All algorithms are:
- ✓ Industry standard
- ✓ Well-studied and peer-reviewed
- ✓ Implemented in audited libraries
- ✓ Used with secure parameters
- ✓ Properly integrated

## Threat Model Summary

See `rfcs/RFC-0006-threat-model.md` for full details.

### Primary Threats (High Risk)

1. **File Tampering (T1)**: Unauthorized modification bypassing signatures
   - **Mitigation**: Cryptographic signatures, hash chain validation
   - **Test**: Integration tests with tampered files

2. **Private Key Compromise (S1)**: Stolen keys used for forgery
   - **Mitigation**: OS keyring storage, memory zeroization
   - **Test**: Key export encryption, access control tests

3. **Data Disclosure (I1)**: Encryption key compromise exposes rules
   - **Mitigation**: ChaCha20-Poly1305 encryption, secure key derivation
   - **Test**: Encryption/decryption tests, key derivation tests

### Secondary Threats (Medium Risk)

4. **Parser Denial of Service (D1)**: Malformed files crash parser
   - **Mitigation**: Robust input validation, resource limits
   - **Test**: Fuzz testing, malformed file tests

5. **Privilege Escalation (E1)**: OS keyring vulnerability exploitation
   - **Mitigation**: Principle of least privilege, OS security
   - **Test**: Permission tests, error handling

### Tertiary Threats (Low Risk)

6. **Signature Repudiation (R1)**: Author denies creating version
   - **Mitigation**: Ed25519 non-repudiation, timestamp embedding
   - **Test**: Signature uniqueness tests

## Testing & Verification

### Test Coverage Summary

**Total Tests**: 365
- Unit tests: 255
- Cryptographic test vectors: 23
- Integration tests: 14
- Doc tests: 73

**Coverage by Module**:
- `crypto.rs`: 95%+ (critical paths 100%)
- `parser.rs`: 90%+
- `operations.rs`: 92%+
- `keystore.rs`: 88%+

### Security-Specific Tests

**Cryptographic Test Vectors** (`tests/crypto_test_vectors.rs`):
- RFC 8032 Ed25519 official test vectors (4 tests)
- RFC 8439 ChaCha20-Poly1305 official test vectors (3 tests)
- BLAKE3 official test vectors (4 tests)
- Known-answer tests for determinism
- Edge case tests (zero keys, max values)

**Fuzz Testing**:
- File header parser fuzzing
- Section reader fuzzing
- Signature verification fuzzing
- Currently run for 10 minutes in CI (expand for audit)

**Integration Tests** (`tests/integration_tests.rs`):
- File corruption detection
- Tampered signature detection
- Invalid version sequence detection
- Concurrent access safety
- Key export/import encryption

### Code Quality Metrics

**Static Analysis**:
- ✓ Zero Clippy warnings with `-D warnings`
- ✓ Zero unsafe code blocks (except in dependencies)
- ✓ No `unwrap()`, `expect()`, or `panic!()` in production code
- ✓ All `Result` types properly handled

**Dependency Security**:
- ✓ `cargo audit` run in CI
- ✓ All dependencies from crates.io
- ✓ No deprecated dependencies
- ✓ Regular security updates

## Audit Recommendations

### Priority Areas for Focus

**1. Signature Verification Logic (CRITICAL)**
- Verify no bypass paths exist
- Ensure all error cases properly fail
- Validate hash chain integrity checks
- Review version sequence validation

**2. Cryptographic Integration (CRITICAL)**
- Verify proper use of crypto libraries
- Check parameter validation
- Ensure no weak fallbacks
- Review memory handling for keys

**3. File Format Parser (HIGH)**
- Fuzz with malformed inputs
- Test integer overflow scenarios
- Verify bounds checking
- Check resource limits

**4. Key Management (HIGH)**
- Review OS keyring integration
- Test key export encryption
- Verify memory zeroization
- Check access controls

**5. Error Handling (MEDIUM)**
- Ensure no information leakage in errors
- Verify graceful degradation
- Check fail-safe defaults
- Review panic paths

### Recommended Testing Approach

1. **Static Code Review**: Focus on security-critical sections listed above
2. **Fuzz Testing**: Extended fuzzing (24+ hours) of all parsers
3. **Penetration Testing**: Attempt to forge signatures, bypass verification
4. **Side-Channel Analysis**: Basic timing attack assessment
5. **Dependency Review**: Audit all cryptographic dependencies

### Tools Recommended

- **Fuzzing**: `cargo-fuzz`, `AFL++`
- **Static Analysis**: `cargo-clippy`, `cargo-audit`, `semgrep`
- **Memory Safety**: `valgrind`, `AddressSanitizer`, `miri`
- **Timing Analysis**: `dudect`, timing measurement tools

## Known Limitations

1. **No Side-Channel Resistance**: Timing attacks not explicitly defended (relies on constant-time crypto libs)
2. **No Formal Verification**: Cryptographic code not formally verified
3. **OS Trust**: Relies on OS keyring security (platform-dependent)
4. **No Hardware Security**: No HSM/TPM integration
5. **Quantum Vulnerability**: Ed25519 not quantum-resistant (future threat)

## Audit Deliverables

We request the security audit to produce:

1. **Vulnerability Report**: All discovered security issues with severity ratings
2. **Code Review Findings**: Non-exploitable issues and code quality concerns
3. **Cryptographic Review**: Assessment of cryptographic implementation
4. **Penetration Test Results**: Attempted attack outcomes
5. **Recommendations**: Actionable security improvements

## Contact Information

**Project**: AION v2  
**Repository**: https://github.com/copyleftdev/aion-context  
**Documentation**: `docs/` directory  
**RFCs**: `rfcs/` directory  

**For Questions During Audit**:
- Open GitHub issues with `security` label
- Reference specific file/line numbers
- Include reproduction steps for findings

## Appendix A: File Format Specification

See `rfcs/RFC-0001-file-format.md` for complete specification.

**Binary Layout**:
```
[File Header - 256 bytes]
[Encrypted Rules Section - variable]
[Version Chain Section - variable]
[Signatures Section - variable]
[Audit Trail Section - variable]
[String Table Section - variable]
```

**Critical Validation Points**:
1. Magic number: `AION` (0x41494F4E)
2. Version: `0x0002` (version 2)
3. All offsets < file size
4. All lengths < file size
5. Section boundaries don't overlap

## Appendix B: Cryptographic Workflows

### File Creation Workflow

```
1. Generate encryption key: derive_file_key(file_id)
2. Encrypt rules: ChaCha20-Poly1305(key, nonce, rules)
3. Compute content hash: BLAKE3(encrypted_rules)
4. Create version entry with hash
5. Sign version: Ed25519.sign(signing_key, version_bytes)
6. Serialize to binary format
7. Write atomically to file
```

### Version Commit Workflow

```
1. Load and parse existing file
2. Verify all existing signatures
3. Encrypt new rules with same file key
4. Compute new content hash
5. Link to parent via hash chain
6. Increment version number
7. Sign new version
8. Append to file atomically
```

### File Verification Workflow

```
1. Parse file header
2. Load all versions and signatures
3. For each version:
   a. Verify signature with author public key
   b. Check hash chain links to parent
   c. Verify version number increases
4. Return verification report
```

## Appendix C: Security Test Cases

### Critical Test Cases

**T1: Tampered Signature Detection**
- Modify signature bytes
- Verify verification fails
- File: `tests/integration_tests.rs::test_detect_tampered_signature()`

**T2: Modified Content Detection**
- Change encrypted rules
- Verify signature verification fails
- File: `tests/integration_tests.rs::test_detect_file_corruption()`

**T3: Version Rollback Prevention**
- Revert to old version
- Verify sequence validation fails
- File: `tests/integration_tests.rs::test_detect_tampered_signature()`

**T4: Key Export Encryption**
- Export key with password
- Verify encrypted output
- Import and validate match
- File: `src/keystore.rs::tests`

**T5: Nonce Uniqueness**
- Generate multiple nonces
- Verify all unique
- File: `tests/crypto_test_vectors.rs::test_encryption_interoperability()`

## Appendix D: Dependency Tree

**Direct Dependencies** (security-critical):
```
ed25519-dalek = "2.2.0"       # Ed25519 signatures
chacha20poly1305 = "0.10.1"   # AEAD encryption
blake3 = "1.5.0"              # Cryptographic hash
hkdf = "0.12.3"               # Key derivation
argon2 = "0.5.2"              # Password hashing
zeroize = "1.7.0"             # Memory clearing
rand = "0.8.5"                # RNG
keyring = "2.3.2"             # OS keyring
```

**Transitive Dependencies** (review recommended):
- `curve25519-dalek`: Elliptic curve operations (used by ed25519-dalek)
- `aead`: AEAD trait definitions
- `cipher`: Symmetric cipher traits
- `digest`: Hash function traits

All dependencies audited via `cargo audit` in CI.
