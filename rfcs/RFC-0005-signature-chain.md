# RFC 0005: Signature Chain Verification

- **Author:** Crypto Engineer (PhD Cryptography, 12+ years applied crypto)
- **Status:** DRAFT
- **Created:** 2024-11-23
- **Updated:** 2024-11-23

## Abstract

Specification for cryptographic verification of signature chains in AION v2 files. Defines algorithms for validating version history integrity, detecting tampering, and ensuring cryptographic continuity across the entire file lifecycle.

## Motivation

### Problem Statement

AION v2 files contain a chain of versions, each signed by an author. Critical security requirements:

1. **Chain Integrity:** Every version must link cryptographically to its parent
2. **Signature Validity:** Each signature must be mathematically valid
3. **Temporal Ordering:** Versions must be chronologically consistent
4. **Author Verification:** Each signature must be from a valid author
5. **Tamper Detection:** Any modification must be immediately detectable

### Threat Model

**Adversary Capabilities:**
- Full read/write access to file system
- Knowledge of file format specification
- Computational power: 2^80 operations feasible
- May compromise individual private keys (but not all)

**Attack Scenarios:**
1. **Version Injection:** Insert malicious version in middle of chain
2. **History Rewriting:** Modify past versions retroactively
3. **Signature Forgery:** Generate fake signatures for unauthorized changes
4. **Rollback Attack:** Revert to older version without detection
5. **Split Chain:** Create divergent version histories

## Proposal

### Signature Chain Structure

```rust
/// A single link in the signature chain
#[derive(Debug, Clone)]
pub struct VersionEntry {
    /// Version number (monotonically increasing)
    pub version: VersionNumber,
    
    /// Hash of parent version (None for genesis)
    pub parent_hash: Option<Blake3Hash>,
    
    /// Hash of this version's content
    pub content_hash: Blake3Hash,
    
    /// Author who created this version
    pub author_id: AuthorId,
    
    /// Timestamp (Unix epoch, milliseconds)
    pub timestamp: u64,
    
    /// Additional metadata
    pub metadata: VersionMetadata,
}

/// Cryptographic signature over a version
#[derive(Debug, Clone)]
pub struct VersionSignature {
    /// Version this signature applies to
    pub version: VersionNumber,
    
    /// Author's public key (32 bytes)
    pub public_key: [u8; 32],
    
    /// Ed25519 signature (64 bytes)
    pub signature: [u8; 64],
    
    /// Signature timestamp
    pub signed_at: u64,
}
```

### Hash Chain Construction

Each version's hash includes:

```rust
/// Data that gets hashed for chain linking
#[derive(Debug)]
struct HashableVersion {
    version: u64,
    parent_hash: Option<[u8; 32]>,
    author_id: u64,
    timestamp: u64,
    rules_hash: [u8; 32],  // Hash of encrypted rules at this version
    metadata: Vec<u8>,     // Serialized metadata
}

impl HashableVersion {
    /// Compute Blake3 hash for chain linking
    fn compute_hash(&self) -> Blake3Hash {
        let mut hasher = blake3::Hasher::new();
        
        // Version number (8 bytes, little-endian)
        hasher.update(&self.version.to_le_bytes());
        
        // Parent hash (32 bytes, or 32 zeros if genesis)
        match self.parent_hash {
            Some(parent) => hasher.update(&parent),
            None => hasher.update(&[0u8; 32]),
        }
        
        // Author ID (8 bytes, little-endian)
        hasher.update(&self.author_id.to_le_bytes());
        
        // Timestamp (8 bytes, little-endian)
        hasher.update(&self.timestamp.to_le_bytes());
        
        // Rules hash (32 bytes)
        hasher.update(&self.rules_hash);
        
        // Metadata length + data
        hasher.update(&(self.metadata.len() as u64).to_le_bytes());
        hasher.update(&self.metadata);
        
        Blake3Hash(*hasher.finalize().as_bytes())
    }
}
```

### Signature Verification Algorithm

```rust
use ed25519_dalek::{Verifier, VerifyingKey, Signature};

/// Comprehensive signature chain verification
pub struct SignatureChainVerifier {
    /// Known trusted public keys
    trusted_keys: HashSet<AuthorId>,
    
    /// Maximum allowed clock skew (5 minutes)
    max_clock_skew: Duration,
    
    /// Current system time
    current_time: SystemTime,
}

impl SignatureChainVerifier {
    /// Verify entire signature chain
    pub fn verify_chain(
        &self,
        versions: &[VersionEntry],
        signatures: &[VersionSignature],
    ) -> Result<ChainVerificationResult> {
        // Step 1: Basic structure validation
        self.validate_structure(versions, signatures)?;
        
        // Step 2: Hash chain verification
        self.verify_hash_chain(versions)?;
        
        // Step 3: Cryptographic signature verification
        self.verify_signatures(versions, signatures)?;
        
        // Step 4: Temporal consistency check
        self.verify_temporal_ordering(versions)?;
        
        // Step 5: Author authorization check
        self.verify_author_permissions(signatures)?;
        
        Ok(ChainVerificationResult {
            status: VerificationStatus::Valid,
            verified_versions: versions.len(),
            trusted_authors: self.count_trusted_authors(signatures),
            verification_time: Instant::now(),
        })
    }
    
    /// Validate basic chain structure
    fn validate_structure(
        &self,
        versions: &[VersionEntry],
        signatures: &[VersionSignature],
    ) -> Result<()> {
        // Must have at least genesis version
        if versions.is_empty() {
            return Err(AionError::EmptyVersionChain);
        }
        
        // Must have signature for each version
        if versions.len() != signatures.len() {
            return Err(AionError::SignatureVersionMismatch {
                versions: versions.len(),
                signatures: signatures.len(),
            });
        }
        
        // Genesis version must have no parent
        if versions[0].parent_hash.is_some() {
            return Err(AionError::InvalidGenesisVersion);
        }
        
        // All subsequent versions must have parent
        for version in &versions[1..] {
            if version.parent_hash.is_none() {
                return Err(AionError::MissingParentHash {
                    version: version.version,
                });
            }
        }
        
        // Version numbers must be sequential
        for window in versions.windows(2) {
            let current = window[0].version;
            let next = window[1].version;
            
            if next.as_u64() != current.as_u64() + 1 {
                return Err(AionError::NonSequentialVersions {
                    expected: VersionNumber(current.as_u64() + 1),
                    actual: next,
                });
            }
        }
        
        Ok(())
    }
    
    /// Verify cryptographic hash chain
    fn verify_hash_chain(&self, versions: &[VersionEntry]) -> Result<()> {
        let mut computed_hashes = Vec::new();
        
        for version in versions {
            // Compute hash for this version
            let hashable = HashableVersion {
                version: version.version.as_u64(),
                parent_hash: version.parent_hash.map(|h| h.0),
                author_id: version.author_id.0,
                timestamp: version.timestamp,
                rules_hash: version.content_hash.0,
                metadata: version.metadata.serialize(),
            };
            
            let computed_hash = hashable.compute_hash();
            computed_hashes.push(computed_hash);
            
            // Verify parent hash linkage (skip genesis)
            if let Some(parent_hash) = version.parent_hash {
                if computed_hashes.len() < 2 {
                    return Err(AionError::InvalidChainStructure);
                }
                
                let expected_parent = computed_hashes[computed_hashes.len() - 2];
                if parent_hash != expected_parent {
                    return Err(AionError::BrokenHashChain {
                        version: version.version,
                        expected: expected_parent,
                        actual: parent_hash,
                    });
                }
            }
        }
        
        Ok(())
    }
    
    /// Verify cryptographic signatures
    fn verify_signatures(
        &self,
        versions: &[VersionEntry],
        signatures: &[VersionSignature],
    ) -> Result<()> {
        for (version, signature) in versions.iter().zip(signatures.iter()) {
            // Verify signature version matches
            if version.version != signature.version {
                return Err(AionError::SignatureVersionMismatch {
                    expected: version.version,
                    actual: signature.version,
                });
            }
            
            // Verify author matches
            if version.author_id != signature.author_id {
                return Err(AionError::SignatureAuthorMismatch {
                    version_author: version.author_id,
                    signature_author: signature.author_id,
                });
            }
            
            // Reconstruct signed message
            let signed_message = self.construct_signed_message(version)?;
            
            // Verify Ed25519 signature
            let verifying_key = VerifyingKey::from_bytes(&signature.public_key)
                .map_err(|e| AionError::InvalidPublicKey { 
                    author: signature.author_id,
                    error: e.to_string(),
                })?;
            
            let signature_obj = Signature::from_bytes(&signature.signature)
                .map_err(|e| AionError::InvalidSignature {
                    version: signature.version,
                    error: e.to_string(),
                })?;
            
            verifying_key.verify(&signed_message, &signature_obj)
                .map_err(|e| AionError::SignatureVerificationFailed {
                    version: signature.version,
                    author: signature.author_id,
                    error: e.to_string(),
                })?;
        }
        
        Ok(())
    }
    
    /// Construct the exact message that was signed
    fn construct_signed_message(&self, version: &VersionEntry) -> Result<Vec<u8>> {
        let mut message = Vec::new();
        
        // Domain separator (prevents cross-protocol attacks)
        message.extend_from_slice(b"AION_V2_VERSION_SIGNATURE");
        
        // Version data
        message.extend_from_slice(&version.version.as_u64().to_le_bytes());
        
        if let Some(parent_hash) = version.parent_hash {
            message.extend_from_slice(&parent_hash.0);
        } else {
            message.extend_from_slice(&[0u8; 32]);
        }
        
        message.extend_from_slice(&version.content_hash.0);
        message.extend_from_slice(&version.author_id.0.to_le_bytes());
        message.extend_from_slice(&version.timestamp.to_le_bytes());
        
        let metadata_bytes = version.metadata.serialize();
        message.extend_from_slice(&(metadata_bytes.len() as u64).to_le_bytes());
        message.extend_from_slice(&metadata_bytes);
        
        Ok(message)
    }
}

/// Result of chain verification
#[derive(Debug)]
pub struct ChainVerificationResult {
    pub status: VerificationStatus,
    pub verified_versions: usize,
    pub trusted_authors: usize,
    pub verification_time: Instant,
}

#[derive(Debug, PartialEq)]
pub enum VerificationStatus {
    Valid,
    Invalid(String),
    PartiallyTrusted,
}
```

### Incremental Verification

For performance, support incremental verification when adding new versions:

```rust
impl SignatureChainVerifier {
    /// Verify only new versions since last check
    pub fn verify_incremental(
        &mut self,
        last_verified_version: VersionNumber,
        new_versions: &[VersionEntry],
        new_signatures: &[VersionSignature],
    ) -> Result<ChainVerificationResult> {
        // Verify new versions link correctly to last verified version
        if let Some(first_new) = new_versions.first() {
            // Get expected parent hash from cache
            let expected_parent = self.get_cached_hash(last_verified_version)?;
            
            if first_new.parent_hash != Some(expected_parent) {
                return Err(AionError::IncrementalVerificationFailed {
                    expected_parent,
                    actual_parent: first_new.parent_hash,
                });
            }
        }
        
        // Verify only the new portion
        self.verify_chain(new_versions, new_signatures)
    }
}
```

## Security Analysis

### Attack Resistance

1. **Version Injection:** Prevented by hash chain - any inserted version breaks parent-child links
2. **History Rewriting:** Requires breaking cryptographic hash function (Blake3)
3. **Signature Forgery:** Requires breaking Ed25519 (computationally infeasible)
4. **Rollback Attack:** Version numbers prevent reverting to older versions
5. **Split Chain:** Each version cryptographically commits to single parent

### Security Properties

- **Immutability:** Past versions cannot be modified without detection
- **Non-repudiation:** Authors cannot deny their signatures
- **Integrity:** Any tampering is immediately detectable
- **Authenticity:** Each version provably authored by key holder
- **Ordering:** Temporal sequence is cryptographically enforced

## Performance Considerations

### Time Complexity

- **Full Verification:** O(n) where n = number of versions
- **Incremental Verification:** O(k) where k = new versions only
- **Signature Verification:** ~0.1ms per signature on modern hardware

### Optimizations

1. **Caching:** Store verified hashes to avoid recomputation
2. **Parallel Verification:** Signatures can be verified concurrently
3. **Early Termination:** Stop on first verification failure
4. **Lazy Loading:** Only verify when accessing specific versions

## Testing Strategy

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_valid_chain_verification() {
        // Test complete valid signature chain
    }
    
    #[test]
    fn test_broken_hash_chain_detection() {
        // Test detection of modified parent hash
    }
    
    #[test]
    fn test_invalid_signature_rejection() {
        // Test rejection of forged signatures
    }
    
    #[test]
    fn test_temporal_ordering_enforcement() {
        // Test rejection of out-of-order timestamps
    }
}
```

### Property-Based Tests

- **Invariant:** Valid chain always verifies successfully
- **Invariant:** Any modification breaks verification
- **Invariant:** Incremental verification matches full verification

## Implementation Plan

### Phase 1: Core Verification (Week 1)
- Implement `HashableVersion` and hash computation
- Basic signature verification with Ed25519
- Chain structure validation

### Phase 2: Advanced Features (Week 2)  
- Temporal consistency checking
- Author permission verification
- Comprehensive error messages

### Phase 3: Performance (Week 3)
- Incremental verification
- Hash caching
- Parallel signature verification

### Phase 4: Testing (Week 4)
- Unit test suite
- Property-based testing
- Performance benchmarks

## Open Questions

1. Should we support signature chain branching for merge scenarios?
2. How to handle clock synchronization in distributed scenarios?
3. Should we implement signature aggregation for better performance?

## References

- [RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)](https://tools.ietf.org/html/rfc8032)
- [BLAKE3 Specification](https://github.com/BLAKE3-team/BLAKE3-specs)
- [Ed25519 Security Analysis](https://ed25519.cr.yp.to/ed25519-20110926.pdf)
- [Signature Chain Attacks and Defenses](https://eprint.iacr.org/2019/1444.pdf)

## Appendix

### Terminology

- **Signature Chain:** Cryptographically linked sequence of signed versions
- **Hash Chain:** Parent-child relationships enforced by cryptographic hashes
- **Version Entry:** Single link in the signature chain
- **Chain Verification:** Process of validating entire signature chain
- **Incremental Verification:** Validating only new additions to existing chain