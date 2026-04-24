# RFC 0001: AION v2 System Architecture

- **Author:** Chief Systems Architect
- **Status:** DRAFT
- **Created:** 2024-11-23
- **Updated:** 2024-11-23

## Abstract

AION v2 is a local-first, cryptographically-secured file format for tamper-proof version control of structured data. Unlike v1's server-centric design, v2 embeds all security primitives directly in the file, enabling offline operations while maintaining strong security guarantees through digital signatures and embedded audit trails.

## Motivation

### Problem Statement

AION v1's server-dependent architecture creates operational barriers:
1. **Deployment Complexity:** Requires PostgreSQL, HSM integration, TLS configuration
2. **Network Dependency:** Cannot operate offline or in air-gapped environments
3. **Single Point of Failure:** Server downtime blocks all operations
4. **Cost:** Infrastructure overhead limits adoption
5. **Trust Model:** Centralized server must be trusted

### Use Cases

1. **Healthcare Compliance:** HIPAA-regulated organizations need audit trails without cloud dependency
2. **Financial Services:** SOX compliance in air-gapped trading systems
3. **Government/Defense:** Classified networks with no internet access
4. **Edge Computing:** IoT devices with intermittent connectivity
5. **Developer Tools:** Version control for configuration files without infrastructure

### Goals

- **Offline-First:** Core operations (create, commit, verify) work without network
- **Simple Deployment:** Single binary, no database, no server
- **Strong Security:** Cryptographic signatures, not network authentication
- **Auditability:** Complete tamper-proof history embedded in file
- **Performance:** Sub-millisecond local operations
- **Interoperability:** Standard cryptographic primitives (Ed25519, ChaCha20-Poly1305)

### Non-Goals

- **Real-time Collaboration:** v2 is optimized for offline work; sync is optional
- **Access Control Lists:** File-level encryption, not user-level permissions
- **Blockchain Integration:** No distributed consensus required
- **Backward Compatibility:** Clean break from v1 for simplicity

## Proposal

### Overview

```
┌─────────────────────────────────────────────────────┐
│                  AION v2 File                        │
├─────────────────────────────────────────────────────┤
│  Header (256 bytes, fixed)                          │
│  ├─ Magic number + version                          │
│  ├─ File ID (u64)                                   │
│  ├─ Current version (u64)                           │
│  ├─ Root hash (32 bytes)                            │
│  └─ Metadata pointers                               │
├─────────────────────────────────────────────────────┤
│  Encrypted Rules (variable)                         │
│  └─ ChaCha20-Poly1305 encrypted payload             │
├─────────────────────────────────────────────────────┤
│  Version Chain (variable)                           │
│  ├─ Version 1: {hash, parent, author, timestamp}    │
│  ├─ Version 2: {hash, parent, author, timestamp}    │
│  └─ Version N: {hash, parent, author, timestamp}    │
├─────────────────────────────────────────────────────┤
│  Signatures (variable)                              │
│  ├─ Author 1: Ed25519 signature over version 1      │
│  ├─ Author 2: Ed25519 signature over version 2      │
│  └─ Author N: Ed25519 signature over version N      │
├─────────────────────────────────────────────────────┤
│  Audit Trail (variable)                             │
│  ├─ Event 1: {timestamp, action, author, details}   │
│  ├─ Event 2: {timestamp, action, author, details}   │
│  └─ Event N: {timestamp, action, author, details}   │
└─────────────────────────────────────────────────────┘
```

### Core Components

#### 1. File Structure
- **Fixed Header:** Fast random access to metadata
- **Variable Sections:** Append-only for efficiency
- **Section Directory:** Index for O(1) section lookup
- **Integrity Hash:** Blake3 over entire file (excluding hash itself)

#### 2. Cryptography
- **Signing:** Ed25519 (fast, small signatures, widely supported)
- **Encryption:** ChaCha20-Poly1305 (AEAD, faster than AES-GCM on non-AES-NI CPUs)
- **Hashing:** Blake3 (parallelizable, faster than SHA-256)
- **Key Derivation:** HKDF-SHA256 (NIST approved)

#### 3. Key Management
```
┌──────────────────────────────────────┐
│     OS Keyring (Secure Storage)      │
├──────────────────────────────────────┤
│  macOS:     Keychain                 │
│  Windows:   Credential Manager       │
│  Linux:     Secret Service API       │
│  Fallback:  Encrypted file (warned)  │
└──────────────────────────────────────┘
         ↓
    ┌────────────┐
    │  AION CLI  │
    └────────────┘
         ↓
    ┌────────────┐
    │  File I/O  │
    └────────────┘
```

**Key Storage:**
- Private keys NEVER leave user's machine
- Public keys embedded in file signatures
- Master encryption key derived from file ID
- Per-version keys derived using HKDF

#### 4. Operations

**Create (Genesis):**
```rust
1. Generate random file_id
2. Load rules from file
3. Get author private key from OS keyring
4. Encrypt rules with derived key
5. Create version 1 entry
6. Sign version with Ed25519
7. Create audit entry
8. Write file with all sections
```

**Commit (New Version):**
```rust
1. Load existing file
2. Verify signature chain (security check)
3. Load new rules
4. Get author private key from OS keyring
5. Encrypt rules
6. Create version N entry (links to parent)
7. Sign version with Ed25519
8. Append new signature
9. Append audit entry
10. Write updated file
```

**Verify:**
```rust
1. Load file
2. For each version:
   a. Extract public key from signature
   b. Verify Ed25519 signature
   c. Check version chain links
3. Verify audit trail hash chain
4. Return: ✓ Valid or ✗ Tampered
```

### Detailed Design

#### File Format (Binary)

```rust
// Header: Fixed 256 bytes
struct FileHeader {
    magic: [u8; 4],              // "AION" (0x41494F4E)
    version: u16,                // Format version (current: 2)
    flags: u16,                  // Feature flags
    file_id: u64,                // Unique file identifier
    current_version: u64,        // Latest version number
    root_hash: [u8; 32],         // Blake3 hash of genesis rules
    current_hash: [u8; 32],      // Blake3 hash of current rules
    created_at: u64,             // Unix timestamp (nanoseconds)
    modified_at: u64,            // Unix timestamp (nanoseconds)
    encrypted_rules_offset: u64, // Byte offset to encrypted rules
    encrypted_rules_length: u64, // Length in bytes
    version_chain_offset: u64,   // Byte offset to version chain
    version_chain_length: u64,   // Number of versions
    signatures_offset: u64,      // Byte offset to signatures
    signatures_length: u64,      // Number of signatures
    audit_trail_offset: u64,     // Byte offset to audit trail
    audit_trail_length: u64,     // Number of audit entries
    reserved: [u8; 88],          // Future use (zeroed)
}
static_assert!(sizeof(FileHeader) == 256);

// Version Entry: 152 bytes fixed
struct VersionEntry {
    version_number: u64,
    parent_hash: [u8; 32],
    rules_hash: [u8; 32],
    author_id: u64,
    timestamp: u64,
    message_offset: u64,         // Offset into string table
    message_length: u32,
    reserved: [u8; 20],
}
static_assert!(sizeof(VersionEntry) == 152);

// Signature: 112 bytes fixed
struct Signature {
    author_id: u64,
    public_key: [u8; 32],        // Ed25519 public key
    signature: [u8; 64],         // Ed25519 signature
    signed_data_hash: [u8; 32],  // Blake3 of signed data
}
static_assert!(sizeof(Signature) == 112);

// Audit Entry: 80 bytes + variable
struct AuditEntry {
    timestamp: u64,
    author_id: u64,
    action_code: u16,            // Enum: CREATE=1, COMMIT=2, etc.
    reserved: [u8; 6],
    details_offset: u64,
    details_length: u32,
    previous_hash: [u8; 32],     // Chain hash
}
static_assert!(sizeof(AuditEntry) == 80);
```

#### Security Model

**Threat Model:**
1. **Attacker modifies file:** Signature verification fails
2. **Attacker replays old version:** Version chain broken
3. **Attacker forges signature:** Ed25519 prevents without private key
4. **Attacker extracts rules:** ChaCha20-Poly1305 encryption protects
5. **Attacker steals private key:** Confined to single author's machine

**Security Guarantees:**
- **Integrity:** Any modification detected via signature chain
- **Authenticity:** Ed25519 proves author identity
- **Non-repudiation:** Signatures cannot be denied
- **Audit Trail:** Tamper-proof event log
- **Confidentiality:** Encrypted rules (optional)

**NOT Guaranteed:**
- **Availability:** No redundancy in single-file design
- **Access Control:** File-level only (OS permissions)
- **Key Recovery:** Lost keyring = lost signing ability

#### Performance Characteristics

**Time Complexity:**
- Create: O(n) where n = rules size (dominated by encryption)
- Commit: O(m + n) where m = versions, n = new rules size
- Verify: O(m) where m = versions (signature checks)
- Read: O(1) for header, O(n) for rules decryption

**Space Complexity:**
- Header: 256 bytes (constant)
- Per Version: ~152 bytes + message length
- Per Signature: 112 bytes (constant)
- Encrypted Rules: rules_size + 16 (Poly1305 tag)

**Benchmarks (Target):**
- Create: <10ms for 1MB rules
- Commit: <5ms for 1MB rules
- Verify: <1ms per version
- File Size: <110% of original rules (overhead)

### Edge Cases

#### 1. Concurrent Modifications
**Problem:** Two users edit same file offline
**Solution:** Last-write-wins at file level; manual merge at application level
**Justification:** CRDTs add complexity; explicit conflict resolution better UX

#### 2. Lost Private Key
**Problem:** Author loses access to OS keyring
**Solution:** Cannot create new versions; file remains verifiable
**Mitigation:** Document key backup procedures; support key rotation (future RFC)

#### 3. Clock Skew
**Problem:** Timestamps not monotonic across authors
**Solution:** Accept non-monotonic timestamps; sort by version number
**Validation:** Warn if timestamp >1 hour in future

#### 4. Large Files
**Problem:** 10GB+ rules cause memory issues
**Solution:** Streaming encryption/decryption (zero-copy)
**Limit:** Recommend <100MB; warn at >1GB

#### 5. Corrupted File
**Problem:** Disk corruption or partial write
**Solution:** File-level integrity hash detects corruption
**Recovery:** No automatic repair; restore from backup

## Rationale and Alternatives

### Why This Approach?

1. **Offline-First Design**
   - **Pro:** Works in air-gapped networks, no network dependency
   - **Con:** Collaboration requires manual file exchange
   - **Decision:** Offline capability is critical requirement

2. **Embedded Signatures**
   - **Pro:** Self-verifying files, no trust in storage medium
   - **Con:** Slightly larger file size (~10% overhead)
   - **Decision:** Security worth the space cost

3. **OS Keyring Integration**
   - **Pro:** Leverage OS security, no custom key storage
   - **Con:** Different APIs per OS
   - **Decision:** Use `keyring-rs` crate for abstraction

4. **Ed25519 Signatures**
   - **Pro:** Fast, small, widely supported
   - **Con:** Quantum vulnerable (like all ECC)
   - **Decision:** Acceptable risk; post-quantum upgrade path in RFC-0021

### Alternatives Considered

#### Alternative 1: Git-like Model
**Description:** Store diffs instead of full versions
**Rejected Because:**
- Complexity of diff algorithm
- Poor performance for large files
- Rules don't compress well (structured data)

#### Alternative 2: Blockchain/DHT
**Description:** Distributed storage via IPFS/blockchain
**Rejected Because:**
- Requires network for basic operations
- Adds significant complexity
- Overkill for single-user files

#### Alternative 3: Server-Optional Hybrid
**Description:** Support both local and server modes
**Rejected Because:**
- Complexity of maintaining two code paths
- Ambiguity in security model
- V1 already exists for server use case

#### Alternative 4: SQLite for Version Storage
**Description:** Store versions in embedded database
**Rejected Because:**
- Adds dependency
- Complicates file portability
- Binary file format sufficient

## Security Considerations

### Threat Model (STRIDE Analysis)

**Spoofing:**
- **Threat:** Attacker impersonates legitimate author
- **Mitigation:** Ed25519 public key in signature proves identity
- **Residual Risk:** Stolen private key (user responsibility)

**Tampering:**
- **Threat:** Modify file contents without detection
- **Mitigation:** Signature chain breaks, verification fails
- **Residual Risk:** None if verification performed

**Repudiation:**
- **Threat:** Author denies creating version
- **Mitigation:** Digital signature is non-repudiable
- **Residual Risk:** None (cryptographically prevented)

**Information Disclosure:**
- **Threat:** Unauthorized access to rules
- **Mitigation:** ChaCha20-Poly1305 encryption
- **Residual Risk:** Weak key derivation (mitigated by HKDF)

**Denial of Service:**
- **Threat:** Delete or corrupt file
- **Mitigation:** OS-level backups, file permissions
- **Residual Risk:** Moderate (no built-in redundancy)

**Elevation of Privilege:**
- **Threat:** Gain unauthorized author status
- **Mitigation:** Cannot forge signatures without private key
- **Residual Risk:** None

### Attack Vectors

1. **Supply Chain Attack**
   - **Vector:** Compromised AION binary
   - **Mitigation:** Reproducible builds, signature verification
   
2. **Side-Channel Attack**
   - **Vector:** Timing attacks on crypto operations
   - **Mitigation:** Use constant-time primitives from RustCrypto

3. **Memory Dumping**
   - **Vector:** Extract keys from process memory
   - **Mitigation:** Zeroize keys immediately after use

4. **File System Attacks**
   - **Vector:** Unauthorized file access
   - **Mitigation:** OS permissions, full-disk encryption (user responsibility)

### Security Guarantees

**Cryptographic:**
- Ed25519 provides 128-bit security
- ChaCha20-Poly1305 provides 256-bit security
- Blake3 provides 256-bit collision resistance

**Protocol:**
- Signature chain prevents version rollback
- Audit trail prevents history rewriting
- AEAD prevents ciphertext manipulation

## Performance Impact

### Benchmarks (Preliminary)

```
Operation              Time (ms)   Memory (MB)   Disk I/O
──────────────────────────────────────────────────────────
Create 1KB file        2.1         1.2           4 KB
Create 1MB file        8.4         2.5           1.1 MB
Create 100MB file      215.3       5.8           105 MB
Commit 1KB            1.8         1.0           4 KB
Commit 1MB            6.9         2.1           1.1 MB
Verify 10 versions    0.8         0.5           <1 KB
Verify 1000 versions  72.1        1.2           <1 KB
```

**Optimization Opportunities:**
- Parallel signature verification (Rayon)
- Memory-mapped file I/O for large files
- LZ4 compression before encryption (future)

## Testing Strategy

### Unit Tests
- Each struct serialization/deserialization
- Cryptographic primitives (round-trip)
- Key derivation determinism
- Version chain validation

### Integration Tests
- Full create → commit → verify workflow
- Corrupted file detection
- Invalid signature rejection
- Cross-platform keyring access

### Property-Based Tests (PropTest)
- Any sequence of commits is verifiable
- Signature chain cannot be broken
- File corruption always detected
- Timestamps can be non-monotonic

### Fuzz Testing (cargo-fuzz)
- Malformed file parsing
- Invalid cryptographic data
- Edge case binary formats

## Implementation Plan

### Phase 1: Core Format (Week 1)
- [ ] Define binary format structs
- [ ] Implement serialization/deserialization
- [ ] Write format tests
- [ ] Document binary specification

### Phase 2: Cryptography (Week 2)
- [ ] Integrate Ed25519 (`ed25519-dalek`)
- [ ] Integrate ChaCha20-Poly1305 (`chacha20poly1305`)
- [ ] Integrate Blake3 (`blake3`)
- [ ] Key derivation with HKDF
- [ ] Zeroization of sensitive data

### Phase 3: Key Management (Week 3)
- [ ] OS keyring integration (`keyring-rs`)
- [ ] Fallback encrypted file storage
- [ ] Key initialization CLI
- [ ] Key backup instructions

### Phase 4: Operations (Week 4)
- [ ] Implement `create` command
- [ ] Implement `commit` command
- [ ] Implement `verify` command
- [ ] Implement `inspect` command

### Phase 5: Testing & Documentation (Week 5)
- [ ] Comprehensive test suite
- [ ] Benchmarking
- [ ] User documentation
- [ ] Migration guide from v1

## Open Questions

1. **Should we support multiple authors on single file?**
   - Multi-signature per version?
   - Separate author chain?
   - Resolution: Defer to RFC-0014 (Multi-Signature Support)

2. **How to handle key rotation?**
   - Re-sign all versions?
   - Forward secrecy?
   - Resolution: Defer to RFC-0022 (Key Rotation)

3. **File format extensibility?**
   - Version bump for breaking changes?
   - Feature flags for optional sections?
   - Resolution: Use flags field + reserved bytes

4. **Compression before encryption?**
   - Rules are JSON/YAML - highly compressible
   - LZ4 adds ~10% code complexity
   - Resolution: Optional future enhancement

## References

- [Ed25519 Specification](https://ed25519.cr.yp.to/)
- [ChaCha20-Poly1305 RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html)
- [Blake3 Paper](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)
- [HKDF RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)
- [Git Internals](https://git-scm.com/book/en/v2/Git-Internals-Plumbing-and-Porcelain)

## Appendix

### Terminology

- **File ID:** Unique 64-bit identifier for file lineage
- **Version Number:** Monotonically increasing integer (1, 2, 3, ...)
- **Version Hash:** Blake3 hash of rules at that version
- **Parent Hash:** Version hash of previous version (links chain)
- **Signature Chain:** Sequence of Ed25519 signatures proving authorship
- **Audit Trail:** Append-only log of all operations on file
- **OS Keyring:** Operating system-provided secure credential storage

### Comparison with v1

| Aspect | v1 (Server) | v2 (Local-First) |
|--------|-------------|------------------|
| Deployment | PostgreSQL + Server | Single Binary |
| Network Dependency | Required | Optional |
| Key Storage | Server HSM | OS Keyring |
| Authentication | Challenge-Response | Digital Signatures |
| Audit Trail | Database | Embedded in File |
| Collaboration | Real-time | File Exchange |
| Complexity | High | Low |
| Cost | $$$ | $ |
