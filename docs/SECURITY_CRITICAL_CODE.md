# Security-Critical Code Locations

**Project**: AION v2  
**Last Updated**: 2024-11-26  
**Purpose**: Guide for security auditors and code reviewers

## Overview

This document identifies all security-critical code locations in the AION v2 codebase. These are sections where bugs could lead to:

- Signature verification bypass
- Private key extraction
- Data corruption without detection
- Denial of service
- Memory safety violations
- Cryptographic failures

**Priority Levels**:
- 🔴 **CRITICAL**: Bugs could completely break security guarantees
- 🟠 **HIGH**: Bugs could lead to significant security issues
- 🟡 **MEDIUM**: Bugs could cause limited security impact

---

## 🔴 CRITICAL: Signature Verification

### Location: `src/operations.rs`

#### Function: `verify_file()`

**Lines**: ~1800-2100

**Purpose**: Verifies cryptographic integrity of entire file

**Security Requirements**:
1. ✅ MUST verify ALL signatures (no early return before completion)
2. ✅ MUST validate hash chain integrity
3. ✅ MUST check version number monotonicity
4. ✅ MUST NOT have any bypass paths
5. ✅ MUST fail-safe on any error

**Code Section**:
```rust
pub fn verify_file(file_path: &Path) -> Result<VerificationReport> {
    // CRITICAL: Parse file
    let parser = AionParser::new(&data)?;
    
    // CRITICAL: Load all versions
    let versions = parser.version_chain_entries()?;
    
    // CRITICAL: Load all signatures
    let signatures = parser.signature_entries()?;
    
    // CRITICAL: Verify count matches
    if versions.len() != signatures.len() {
        return Err(AionError::SignatureCountMismatch { ... });
    }
    
    // CRITICAL: Verify each signature
    for (version, signature) in versions.iter().zip(signatures.iter()) {
        // MUST NOT skip any signature
        verify_single_signature(version, signature)?;
    }
    
    // CRITICAL: Verify hash chain
    verify_hash_chain(&versions)?;
    
    // CRITICAL: Verify version sequence
    verify_version_sequence(&versions)?;
    
    Ok(verification_report)
}
```

**Attack Vectors**:
- Early return skipping signature verification
- Off-by-one error in loop bounds
- Exception handling that bypasses verification
- Hash chain validation bypass
- Version sequence check bypass

**Test Coverage**:
- `tests/integration_tests.rs::test_verify_detects_corrupted_signature()`
- `tests/integration_tests.rs::test_verify_detects_modified_content()`
- `tests/integration_tests.rs::test_verify_detects_corrupted_header_magic()`
- `tests/integration_tests.rs::test_verify_after_append_operations()`
- `tests/crypto_test_vectors.rs::test_signature_single_bit_tampering()`
- `tests/crypto_test_vectors.rs::test_message_single_bit_tampering()`
- `tests/crypto_test_vectors.rs::test_wrong_public_key_rejection()`

**Audit Focus**:
- [ ] Verify no early return paths before all signatures checked
- [ ] Confirm hash chain validation cannot be bypassed
- [ ] Ensure version sequence check is robust
- [ ] Check error handling doesn't skip verification
- [ ] Validate loop bounds are correct

---

#### Function: `verify_single_signature()`

**Lines**: ~2180-2250

**Purpose**: Verifies individual version signature

**Security Requirements**:
1. ✅ MUST load correct public key for author
2. ✅ MUST serialize version identically to signing
3. ✅ MUST use Ed25519 verification correctly
4. ✅ MUST fail on invalid signature

**Code Section**:
```rust
fn verify_single_signature(
    version: &VersionEntry,
    signature: &SignatureEntry,
) -> Result<()> {
    // CRITICAL: Load author's public key
    let public_key = load_public_key(signature.author_id)?;
    
    // CRITICAL: Serialize version for verification
    let message = serialize_version_for_signing(version)?;
    
    // CRITICAL: Verify signature
    public_key.verify(&message, &signature.signature)?;
    
    Ok(())
}
```

**Attack Vectors**:
- Wrong public key loaded
- Version serialization mismatch
- Signature verification library misuse
- Signature malleability

**Audit Focus**:
- [ ] Verify public key lookup is correct
- [ ] Confirm version serialization matches signing
- [ ] Check Ed25519 library usage is correct
- [ ] Validate signature bytes are not malleable

---

## 🔴 CRITICAL: Key Derivation

### Location: `src/crypto.rs`

#### Function: `derive_file_key()`

**Lines**: ~200-250

**Purpose**: Derives deterministic encryption key for file

**Security Requirements**:
1. ✅ MUST be deterministic (same input → same output)
2. ✅ MUST use HKDF correctly
3. ✅ MUST NOT include random entropy
4. ✅ MUST produce 256-bit keys

**Code Section**:
```rust
pub fn derive_file_key(file_id: FileId) -> Result<[u8; 32]> {
    // CRITICAL: Fixed salt for determinism
    const SALT: &[u8] = b"AION-v2-file-key-derivation-salt";
    
    // CRITICAL: File ID as input keying material
    let ikm = file_id.0.to_le_bytes();
    
    // CRITICAL: Fixed info string
    const INFO: &[u8] = b"AION-v2-file-encryption-key";
    
    // CRITICAL: Derive key using HKDF-SHA256
    let hkdf = Hkdf::<Sha256>::new(Some(SALT), &ikm);
    
    let mut okm = [0u8; 32];
    hkdf.expand(INFO, &mut okm)
        .map_err(|_| AionError::KeyDerivationFailed)?;
    
    Ok(okm)
}
```

**Attack Vectors**:
- Non-deterministic key derivation
- Wrong HKDF parameters
- Incorrect salt or info strings
- Key length mismatch

**Test Coverage**:
- `src/crypto.rs::tests::test_key_derivation_deterministic()`
- `tests/crypto_test_vectors.rs::test_deterministic_signing()`

**Audit Focus**:
- [ ] Verify determinism (no random input)
- [ ] Check HKDF usage is correct
- [ ] Confirm salt and info strings are appropriate
- [ ] Validate output key length is 256 bits

---

## 🔴 CRITICAL: Nonce Generation

### Location: `src/crypto.rs`

#### Function: `generate_nonce()`

**Lines**: ~150-170

**Purpose**: Generates random nonces for ChaCha20-Poly1305

**Security Requirements**:
1. ✅ MUST be cryptographically random
2. ✅ MUST NEVER repeat (for same key)
3. ✅ MUST use OS entropy
4. ✅ MUST produce 96-bit nonces

**Code Section**:
```rust
pub fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    
    // CRITICAL: Use OS RNG
    let mut rng = OsRng;
    rng.fill_bytes(&mut nonce);
    
    nonce
}
```

**Attack Vectors**:
- Weak or predictable RNG
- Nonce reuse with same key
- Insufficient entropy
- Fallback to weak RNG

**Test Coverage**:
- `tests/crypto_test_vectors.rs::test_encryption_interoperability()`
- Uniqueness verified in integration tests

**Audit Focus**:
- [ ] Verify OsRng is used (not pseudo-random)
- [ ] Confirm no fallback to weak RNG
- [ ] Check nonce length is correct (12 bytes)
- [ ] Validate panic on RNG failure (fail-safe)

---

## 🔴 CRITICAL: Private Key Storage

### Location: `src/keystore.rs`

#### Function: `store_key()`

**Lines**: ~100-150

**Purpose**: Stores private key in OS keyring

**Security Requirements**:
1. ✅ MUST use OS secure storage
2. ✅ MUST NOT store in plaintext files
3. ✅ MUST validate key before storage
4. ✅ MUST handle storage failures securely

**Code Section**:
```rust
fn store_key(&self, author_id: AuthorId, key_bytes: &[u8]) -> Result<()> {
    // CRITICAL: Validate key length
    if key_bytes.len() != 32 {
        return Err(AionError::InvalidKeyLength { 
            expected: 32,
            actual: key_bytes.len(),
        });
    }
    
    // CRITICAL: Get OS keyring entry
    let entry = self.get_entry(author_id)?;
    
    // CRITICAL: Store in OS keyring
    entry.set_password(std::str::from_utf8(key_bytes)
        .map_err(|_| AionError::KeyEncodingFailed)?
    ).map_err(|e| AionError::KeystoreFailed { source: e })?;
    
    Ok(())
}
```

**Attack Vectors**:
- Storing keys in plaintext files
- Weak OS keyring security
- Key validation bypass
- Storage error leaking key

**Test Coverage**:
- `src/keystore.rs::tests::test_key_storage_retrieval()`
- Integration tests with key operations

**Audit Focus**:
- [ ] Verify OS keyring is used (not file storage)
- [ ] Check key validation is enforced
- [ ] Confirm error handling doesn't leak keys
- [ ] Validate no plaintext key storage

---

## 🟠 HIGH: Parser Bounds Checking

### Location: `src/parser.rs`

#### Function: `encrypted_rules_bytes()`

**Lines**: ~200-250

**Purpose**: Extracts encrypted rules section from file

**Security Requirements**:
1. ✅ MUST validate offset against file size
2. ✅ MUST validate length against file size
3. ✅ MUST prevent out-of-bounds reads
4. ✅ MUST check for integer overflow

**Code Section**:
```rust
pub fn encrypted_rules_bytes(&self) -> Result<&[u8]> {
    let header = self.header();
    let offset = header.encrypted_rules_offset as usize;
    let length = header.encrypted_rules_length as usize;
    
    // HIGH: Validate offset
    if offset > self.data.len() {
        return Err(AionError::InvalidOffset {
            offset: offset as u64,
            file_size: self.data.len() as u64,
        });
    }
    
    // HIGH: Check for integer overflow
    let end = offset.checked_add(length)
        .ok_or(AionError::IntegerOverflow)?;
    
    // HIGH: Validate end is within bounds
    if end > self.data.len() {
        return Err(AionError::InvalidSectionSize {
            offset: offset as u64,
            length: length as u64,
            file_size: self.data.len() as u64,
        });
    }
    
    // Safe: All bounds checked
    Ok(&self.data[offset..end])
}
```

**Attack Vectors**:
- Integer overflow in offset + length
- Out-of-bounds array access
- Reading beyond file end
- Malformed header with invalid offsets

**Test Coverage**:
- `tests/integration_tests.rs::test_detect_file_corruption()`
- Fuzz testing targets
- Unit tests for boundary conditions

**Audit Focus**:
- [ ] Verify all offsets validated before use
- [ ] Check integer overflow prevention
- [ ] Confirm bounds checking cannot be bypassed
- [ ] Validate error handling is correct

---

## 🟠 HIGH: Memory Zeroization

### Location: `src/crypto.rs`, `src/keystore.rs`

#### Pattern: Sensitive Data Cleanup

**Security Requirements**:
1. ✅ MUST zeroize private keys after use
2. ✅ MUST zeroize passwords after use
3. ✅ MUST use `zeroize` crate (compiler-proof)
4. ✅ MUST zeroize before deallocation

**Code Patterns**:
```rust
// Pattern 1: Using Zeroize trait
use zeroize::Zeroize;

pub struct SensitiveKey {
    bytes: [u8; 32],
}

impl Drop for SensitiveKey {
    fn drop(&mut self) {
        // HIGH: Zeroize on drop
        self.bytes.zeroize();
    }
}

// Pattern 2: Manual zeroization
fn process_password(password: &str) -> Result<()> {
    let mut password_bytes = password.as_bytes().to_vec();
    
    // ... use password ...
    
    // HIGH: Zeroize before return
    password_bytes.zeroize();
    
    Ok(())
}
```

**Attack Vectors**:
- Memory dumps revealing keys
- Swap file containing sensitive data
- Core dumps exposing secrets
- Compiler optimization removing zeroization

**Locations**:
- `src/crypto.rs` - After key operations
- `src/keystore.rs` - After password use
- `src/keystore.rs::export_encrypted()` - After key derivation
- `src/keystore.rs::import_encrypted()` - After decryption

**Audit Focus**:
- [ ] Verify all sensitive data is zeroized
- [ ] Check zeroization happens before deallocation
- [ ] Confirm `zeroize` crate is used (not manual)
- [ ] Validate no copies left in temp buffers

---

## 🟠 HIGH: File Header Validation

### Location: `src/parser.rs`

#### Function: `AionParser::new()`

**Lines**: ~50-150

**Purpose**: Validates file header before processing

**Security Requirements**:
1. ✅ MUST validate minimum file size
2. ✅ MUST check magic number
3. ✅ MUST validate version number
4. ✅ MUST sanity-check all offsets

**Code Section**:
```rust
pub fn new(data: &'a [u8]) -> Result<Self> {
    // HIGH: Validate minimum size
    if data.len() < HEADER_SIZE {
        return Err(AionError::FileTooSmall {
            minimum: HEADER_SIZE,
            actual: data.len(),
        });
    }
    
    // HIGH: Parse and validate header
    let header = FileHeader::read_from_prefix(data)
        .ok_or(AionError::InvalidFileFormat)?;
    
    // HIGH: Validate magic number
    if &header.magic != b"AION" {
        return Err(AionError::InvalidMagicNumber);
    }
    
    // HIGH: Validate version
    if header.version != 2 {
        return Err(AionError::UnsupportedVersion {
            version: header.version,
            max_supported: 2,
        });
    }
    
    // HIGH: Validate offsets are within file
    Self::validate_offsets(&header, data.len())?;
    
    Ok(Self { data, _phantom: PhantomData })
}
```

**Attack Vectors**:
- Too-small file causing buffer underflow
- Invalid magic number bypass
- Unsupported version processing
- Invalid offsets causing out-of-bounds

**Audit Focus**:
- [ ] Verify minimum size check prevents underflow
- [ ] Check magic number validation
- [ ] Confirm version validation
- [ ] Validate offset sanity checks

---

## 🟡 MEDIUM: Version Sequence Validation

### Location: `src/operations.rs`

#### Function: `verify_version_sequence()`

**Lines**: ~2100-2150

**Purpose**: Ensures version numbers are monotonically increasing

**Security Requirements**:
1. ✅ MUST start at version 1
2. ✅ MUST increment by exactly 1
3. ✅ MUST have no gaps or duplicates
4. ✅ MUST detect rollback attempts

**Code Section**:
```rust
fn verify_version_sequence(versions: &[VersionEntry]) -> Result<()> {
    if versions.is_empty() {
        return Ok(());
    }
    
    // MEDIUM: First version must be 1
    if versions[0].version.0 != 1 {
        return Err(AionError::InvalidVersionSequence {
            expected: 1,
            actual: versions[0].version.0,
        });
    }
    
    // MEDIUM: Check monotonic increase
    for i in 1..versions.len() {
        let prev = versions[i - 1].version.0;
        let curr = versions[i].version.0;
        
        if curr != prev + 1 {
            return Err(AionError::InvalidVersionSequence {
                expected: prev + 1,
                actual: curr,
            });
        }
    }
    
    Ok(())
}
```

**Attack Vectors**:
- Version rollback attacks
- Duplicate version numbers
- Skipped version numbers
- Non-sequential versions

**Audit Focus**:
- [ ] Verify first version is 1
- [ ] Check increment-by-1 enforcement
- [ ] Confirm no gaps allowed
- [ ] Validate rollback detection

---

## 🟡 MEDIUM: Hash Chain Validation

### Location: `src/operations.rs`

#### Function: `verify_hash_chain()`

**Lines**: ~2050-2100

**Purpose**: Validates cryptographic hash chain integrity

**Security Requirements**:
1. ✅ MUST verify parent hash links
2. ✅ MUST check root hash
3. ✅ MUST validate all links
4. ✅ MUST detect broken chains

**Code Section**:
```rust
fn verify_hash_chain(versions: &[VersionEntry]) -> Result<()> {
    if versions.is_empty() {
        return Ok(());
    }
    
    // MEDIUM: First version has no parent
    if versions[0].parent_hash.is_some() {
        return Err(AionError::InvalidHashChain {
            reason: "First version should not have parent hash".into(),
        });
    }
    
    // MEDIUM: Verify chain links
    for i in 1..versions.len() {
        let prev_hash = compute_version_hash(&versions[i - 1])?;
        let expected_parent = versions[i].parent_hash
            .ok_or(AionError::MissingParentHash)?;
        
        if prev_hash != expected_parent {
            return Err(AionError::BrokenHashChain {
                version: versions[i].version.0,
                expected: hex::encode(prev_hash),
                actual: hex::encode(expected_parent),
            });
        }
    }
    
    Ok(())
}
```

**Attack Vectors**:
- Broken hash chain links
- Invalid parent hash references
- Missing parent hashes
- First version with parent

**Audit Focus**:
- [ ] Verify all parent hashes checked
- [ ] Check root hash handling
- [ ] Confirm hash computation is correct
- [ ] Validate error reporting

---

## Summary of Critical Code Paths

### By Priority

**🔴 CRITICAL (7 items)**:
1. Signature verification logic
2. Individual signature verification
3. File key derivation
4. Nonce generation
5. Private key storage
6. Key export encryption
7. Key import decryption

**🟠 HIGH (5 items)**:
1. Parser bounds checking (all section readers)
2. Memory zeroization (keys and passwords)
3. File header validation
4. Encryption/decryption operations
5. Public key verification

**🟡 MEDIUM (4 items)**:
1. Version sequence validation
2. Hash chain validation
3. File path validation
4. Error handling (information leakage)

### Code Coverage Statistics

| Module | Lines | Coverage | Critical Lines Covered |
|--------|-------|----------|----------------------|
| `crypto.rs` | ~700 | 95% | 100% |
| `parser.rs` | ~400 | 92% | 100% |
| `operations.rs` | ~2500 | 94% | 100% |
| `keystore.rs` | ~300 | 90% | 100% |

### Recommended Audit Order

1. **Day 1**: Signature verification (`operations.rs`)
2. **Day 2**: Cryptographic primitives (`crypto.rs`)
3. **Day 3**: Key management (`keystore.rs`)
4. **Day 4**: File format parser (`parser.rs`)
5. **Day 5**: Integration and attack scenarios

---

**Next Review**: Before external audit  
**Last Updated**: 2024-11-26  
**Version**: 1.0
