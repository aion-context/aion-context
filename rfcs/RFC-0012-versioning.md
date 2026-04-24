# RFC 0012: Version Chain Semantics

- **Author:** Systems Designer (12+ years distributed systems, version control expert)
- **Status:** DRAFT
- **Created:** 2024-11-23
- **Updated:** 2024-11-23

## Abstract

Specification for version chain semantics in AION v2, defining how versions are linked, ordered, and validated to create a tamper-evident audit trail. Establishes the mathematical properties and operational rules that govern version relationships, conflict resolution, and chain integrity.

## Motivation

### Problem Statement

AION v2's security guarantees depend on a cryptographically-secure version chain that:

1. **Preserves Ordering:** Maintains chronological sequence of changes
2. **Prevents Tampering:** Makes historical modification detectable
3. **Enables Verification:** Allows independent validation of entire history
4. **Supports Concurrency:** Handles multiple authors modifying simultaneously
5. **Resolves Conflicts:** Provides deterministic conflict resolution

### Use Cases

**Single Author Workflow:**
```
Genesis → V2 → V3 → V4 (current)
```

**Multi-Author Collaboration:**
```
        ┌─ V3 (Author B) ─┐
Genesis ├─ V2 (Author A) ─┼─ V5 (merged)
        └─ V4 (Author C) ─┘
```

**Long-Running History:**
```
V1 → V2 → ... → V847 → V848 (thousands of versions)
```

### Design Goals

- **Mathematical Rigor:** Formal definition of version relationships
- **Deterministic Ordering:** Consistent resolution across all implementations
- **Cryptographic Integrity:** Hash-based tamper detection
- **Performance:** O(log n) operations where possible
- **Auditability:** Complete reconstruction of change history

## Proposal

### Version Chain Definition

#### Mathematical Model

A version chain is a directed acyclic graph (DAG) where:
- **Nodes:** Individual versions V₁, V₂, ..., Vₙ
- **Edges:** Parent-child relationships
- **Root:** Genesis version (no parent)
- **Properties:** Acyclic, connected, hash-linked

```rust
/// Mathematical representation of version relationships
pub struct VersionChain {
    /// All versions in the chain
    versions: BTreeMap<VersionNumber, VersionNode>,
    
    /// Current head of the chain
    head: VersionNumber,
    
    /// Genesis version (always version 1)
    genesis: VersionNumber,
}

/// Individual version node in the chain
#[derive(Debug, Clone)]
pub struct VersionNode {
    /// Unique version identifier
    pub version: VersionNumber,
    
    /// Cryptographic hash of parent version
    pub parent_hash: Option<Blake3Hash>,
    
    /// Hash of this version's content
    pub content_hash: Blake3Hash,
    
    /// Author who created this version
    pub author: AuthorId,
    
    /// Creation timestamp (Unix milliseconds)
    pub timestamp: u64,
    
    /// Additional version metadata
    pub metadata: VersionMetadata,
}
```

#### Version Numbering

```rust
/// Strictly monotonic version numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VersionNumber(pub u64);

impl VersionNumber {
    /// Genesis version (always 1)
    pub const GENESIS: Self = Self(1);
    
    /// Maximum version number
    pub const MAX: Self = Self(u64::MAX);
    
    /// Get next version number
    pub fn next(self) -> Result<Self> {
        if self.0 == u64::MAX {
            return Err(AionError::VersionOverflow);
        }
        Ok(Self(self.0 + 1))
    }
    
    /// Check if this is the genesis version
    pub fn is_genesis(self) -> bool {
        self.0 == 1
    }
}
```

### Chain Construction Rules

#### Rule 1: Genesis Constraint

```rust
/// Genesis version must be first and have no parent
pub fn validate_genesis(version: &VersionNode) -> Result<()> {
    if version.version == VersionNumber::GENESIS {
        if version.parent_hash.is_some() {
            return Err(AionError::GenesisHasParent);
        }
    } else {
        if version.parent_hash.is_none() {
            return Err(AionError::NonGenesisWithoutParent {
                version: version.version,
            });
        }
    }
    Ok(())
}
```

#### Rule 2: Hash Chain Integrity

```rust
/// Each version must cryptographically link to its parent
pub fn validate_hash_chain(
    child: &VersionNode,
    parent: &VersionNode,
) -> Result<()> {
    let expected_parent_hash = compute_version_hash(parent);
    
    match child.parent_hash {
        Some(actual_parent_hash) => {
            if actual_parent_hash != expected_parent_hash {
                return Err(AionError::InvalidParentHash {
                    version: child.version,
                    expected: expected_parent_hash,
                    actual: actual_parent_hash,
                });
            }
        }
        None => {
            return Err(AionError::MissingParentHash {
                version: child.version,
            });
        }
    }
    
    Ok(())
}

/// Compute cryptographic hash of a version
pub fn compute_version_hash(version: &VersionNode) -> Blake3Hash {
    let mut hasher = blake3::Hasher::new();
    
    // Domain separator
    hasher.update(b"AION_V2_VERSION_HASH");
    
    // Version data
    hasher.update(&version.version.0.to_le_bytes());
    hasher.update(&version.author.0.to_le_bytes());
    hasher.update(&version.timestamp.to_le_bytes());
    hasher.update(&version.content_hash.0);
    
    // Parent hash (or zeros for genesis)
    match version.parent_hash {
        Some(parent) => hasher.update(&parent.0),
        None => hasher.update(&[0u8; 32]),
    }
    
    // Metadata
    let metadata_bytes = version.metadata.serialize();
    hasher.update(&(metadata_bytes.len() as u64).to_le_bytes());
    hasher.update(&metadata_bytes);
    
    Blake3Hash(*hasher.finalize().as_bytes())
}
```

#### Rule 3: Temporal Ordering

```rust
/// Versions must be temporally ordered (with tolerance for clock skew)
pub fn validate_temporal_ordering(
    child: &VersionNode,
    parent: &VersionNode,
    max_clock_skew: Duration,
) -> Result<()> {
    // Child timestamp must be after parent (with skew tolerance)
    let min_child_time = parent.timestamp + max_clock_skew.as_millis() as u64;
    
    if child.timestamp < min_child_time {
        return Err(AionError::InvalidTimestamp {
            version: child.version,
            timestamp: child.timestamp,
            min_allowed: min_child_time,
        });
    }
    
    // Future timestamps not allowed (with skew tolerance)
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    
    let max_allowed_time = now + max_clock_skew.as_millis() as u64;
    
    if child.timestamp > max_allowed_time {
        return Err(AionError::FutureTimestamp {
            version: child.version,
            timestamp: child.timestamp,
            max_allowed: max_allowed_time,
        });
    }
    
    Ok(())
}
```

#### Rule 4: Version Monotonicity

```rust
/// Version numbers must increase monotonically along any path
pub fn validate_version_monotonicity(chain: &VersionChain) -> Result<()> {
    // Topological sort to validate ordering
    let sorted_versions = topological_sort(chain)?;
    
    for window in sorted_versions.windows(2) {
        let current = &window[0];
        let next = &window[1];
        
        if next.version <= current.version {
            return Err(AionError::NonMonotonicVersions {
                current: current.version,
                next: next.version,
            });
        }
    }
    
    Ok(())
}
```

### Chain Operations

#### Adding New Versions

```rust
impl VersionChain {
    /// Add new version to chain with full validation
    pub fn add_version(
        &mut self,
        new_version: VersionNode,
        parent_version: VersionNumber,
    ) -> Result<()> {
        // Validate version doesn't already exist
        if self.versions.contains_key(&new_version.version) {
            return Err(AionError::VersionAlreadyExists {
                version: new_version.version,
            });
        }
        
        // Validate parent exists
        let parent = self.versions.get(&parent_version)
            .ok_or(AionError::ParentVersionNotFound {
                parent: parent_version,
            })?;
        
        // Validate hash chain
        validate_hash_chain(&new_version, parent)?;
        
        // Validate temporal ordering
        validate_temporal_ordering(&new_version, parent, Duration::from_secs(300))?;
        
        // Validate version number sequence
        if new_version.version != parent_version.next()? {
            return Err(AionError::InvalidVersionSequence {
                expected: parent_version.next()?,
                actual: new_version.version,
            });
        }
        
        // Add to chain
        self.versions.insert(new_version.version, new_version.clone());
        
        // Update head if this is the latest version
        if new_version.version > self.head {
            self.head = new_version.version;
        }
        
        Ok(())
    }
    
    /// Get version by number
    pub fn get_version(&self, version: VersionNumber) -> Option<&VersionNode> {
        self.versions.get(&version)
    }
    
    /// Get current head version
    pub fn current_version(&self) -> &VersionNode {
        self.versions.get(&self.head).unwrap()
    }
    
    /// Get all versions in topological order
    pub fn ordered_versions(&self) -> Result<Vec<&VersionNode>> {
        let sorted = topological_sort(self)?;
        Ok(sorted.iter().collect())
    }
}
```

#### Chain Traversal

```rust
impl VersionChain {
    /// Walk chain from version back to genesis
    pub fn ancestry_path(&self, from: VersionNumber) -> Result<Vec<&VersionNode>> {
        let mut path = Vec::new();
        let mut current = from;
        
        while let Some(version) = self.versions.get(&current) {
            path.push(version);
            
            if version.version.is_genesis() {
                break;
            }
            
            // Find parent
            let parent_hash = version.parent_hash.ok_or(
                AionError::OrphanedVersion { version: current }
            )?;
            
            current = self.find_version_by_hash(parent_hash).ok_or(
                AionError::MissingParent { 
                    version: current,
                    parent_hash,
                }
            )?;
        }
        
        path.reverse(); // Genesis first
        Ok(path)
    }
    
    /// Find version with specific hash
    pub fn find_version_by_hash(&self, hash: Blake3Hash) -> Option<VersionNumber> {
        for (version_num, version_node) in &self.versions {
            if compute_version_hash(version_node) == hash {
                return Some(*version_num);
            }
        }
        None
    }
    
    /// Get all versions by specific author
    pub fn versions_by_author(&self, author: AuthorId) -> Vec<&VersionNode> {
        self.versions.values()
            .filter(|v| v.author == author)
            .collect()
    }
}
```

### Conflict Resolution

#### Last Writer Wins Strategy

```rust
/// Simple conflict resolution: most recent timestamp wins
pub fn resolve_conflicts_lww(
    chain: &mut VersionChain,
    conflicting_versions: &[VersionNode],
) -> Result<VersionNumber> {
    if conflicting_versions.is_empty() {
        return Err(AionError::NoVersionsToResolve);
    }
    
    // Find version with latest timestamp
    let winner = conflicting_versions
        .iter()
        .max_by_key(|v| v.timestamp)
        .unwrap();
    
    // Remove conflicting versions, keep winner
    for version in conflicting_versions {
        if version.version != winner.version {
            chain.versions.remove(&version.version);
        }
    }
    
    // Update head if winner is latest
    if winner.version > chain.head {
        chain.head = winner.version;
    }
    
    Ok(winner.version)
}
```

#### Merge-Based Resolution

```rust
/// Create merge version combining multiple parents
pub fn create_merge_version(
    parents: &[VersionNumber],
    author: AuthorId,
    merged_content: Vec<u8>,
) -> Result<VersionNode> {
    if parents.is_empty() {
        return Err(AionError::NoParentsForMerge);
    }
    
    // Compute merged parent hash
    let merged_parent_hash = compute_merged_parent_hash(parents)?;
    
    // Find next available version number
    let next_version = parents.iter().max().unwrap().next()?;
    
    Ok(VersionNode {
        version: next_version,
        parent_hash: Some(merged_parent_hash),
        content_hash: blake3::hash(&merged_content).into(),
        author,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis() as u64,
        metadata: VersionMetadata::merge_metadata(&parents)?,
    })
}

fn compute_merged_parent_hash(parents: &[VersionNumber]) -> Result<Blake3Hash> {
    let mut hasher = blake3::Hasher::new();
    
    hasher.update(b"AION_V2_MERGE_HASH");
    hasher.update(&(parents.len() as u64).to_le_bytes());
    
    // Hash parents in sorted order for determinism
    let mut sorted_parents = parents.to_vec();
    sorted_parents.sort();
    
    for parent in sorted_parents {
        hasher.update(&parent.0.to_le_bytes());
    }
    
    Ok(Blake3Hash(*hasher.finalize().as_bytes()))
}
```

### Chain Validation

#### Complete Chain Validation

```rust
/// Comprehensive validation of entire version chain
pub fn validate_complete_chain(chain: &VersionChain) -> Result<ValidationReport> {
    let mut report = ValidationReport::new();
    
    // Rule 1: Genesis validation
    let genesis = chain.get_version(VersionNumber::GENESIS)
        .ok_or(AionError::MissingGenesis)?;
    
    validate_genesis(genesis).map_err(|e| {
        report.add_error(ValidationError::Genesis(e));
        e
    })?;
    
    // Rule 2: Hash chain integrity
    for (version_num, version) in &chain.versions {
        if !version.version.is_genesis() {
            let parent_hash = version.parent_hash.unwrap();
            let parent_version = chain.find_version_by_hash(parent_hash)
                .ok_or(AionError::OrphanedVersion { version: *version_num })?;
            let parent = chain.get_version(parent_version).unwrap();
            
            validate_hash_chain(version, parent).map_err(|e| {
                report.add_error(ValidationError::HashChain(*version_num, e));
                e
            })?;
        }
    }
    
    // Rule 3: Version monotonicity
    validate_version_monotonicity(chain).map_err(|e| {
        report.add_error(ValidationError::Monotonicity(e));
        e
    })?;
    
    // Rule 4: Temporal consistency
    for (version_num, version) in &chain.versions {
        if !version.version.is_genesis() {
            let parent_hash = version.parent_hash.unwrap();
            let parent_version = chain.find_version_by_hash(parent_hash).unwrap();
            let parent = chain.get_version(parent_version).unwrap();
            
            validate_temporal_ordering(version, parent, Duration::from_secs(300))
                .map_err(|e| {
                    report.add_warning(ValidationWarning::TemporalInconsistency(*version_num, e));
                    e
                })?;
        }
    }
    
    report.status = if report.errors.is_empty() {
        ValidationStatus::Valid
    } else {
        ValidationStatus::Invalid
    };
    
    Ok(report)
}

#[derive(Debug)]
pub struct ValidationReport {
    pub status: ValidationStatus,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationWarning>,
}

#[derive(Debug)]
pub enum ValidationStatus {
    Valid,
    Invalid,
    Warning,
}
```

### Performance Optimizations

#### Cached Hash Computation

```rust
/// Cache version hashes for performance
pub struct CachedVersionChain {
    chain: VersionChain,
    hash_cache: HashMap<VersionNumber, Blake3Hash>,
}

impl CachedVersionChain {
    pub fn new(chain: VersionChain) -> Self {
        let mut hash_cache = HashMap::new();
        
        // Pre-compute hashes for all versions
        for (version_num, version_node) in &chain.versions {
            hash_cache.insert(*version_num, compute_version_hash(version_node));
        }
        
        Self { chain, hash_cache }
    }
    
    pub fn get_version_hash(&self, version: VersionNumber) -> Option<Blake3Hash> {
        self.hash_cache.get(&version).copied()
    }
    
    pub fn add_version_cached(&mut self, version: VersionNode) -> Result<()> {
        let version_num = version.version;
        let hash = compute_version_hash(&version);
        
        self.chain.add_version(version, version_num)?;
        self.hash_cache.insert(version_num, hash);
        
        Ok(())
    }
}
```

#### Incremental Validation

```rust
/// Validate only new versions since last check
pub fn validate_incremental(
    chain: &VersionChain,
    last_validated: VersionNumber,
) -> Result<ValidationReport> {
    let mut report = ValidationReport::new();
    
    // Find all versions after last validated
    let new_versions: Vec<_> = chain.versions.iter()
        .filter(|(v, _)| **v > last_validated)
        .collect();
    
    // Validate only new versions
    for (version_num, version) in new_versions {
        // Validate against known good parent
        if let Some(parent_hash) = version.parent_hash {
            let parent_version = chain.find_version_by_hash(parent_hash)
                .ok_or(AionError::OrphanedVersion { version: *version_num })?;
            
            if parent_version <= last_validated {
                // Parent is in validated set, check only this version
                let parent = chain.get_version(parent_version).unwrap();
                validate_hash_chain(version, parent)?;
                validate_temporal_ordering(version, parent, Duration::from_secs(300))?;
            }
        }
    }
    
    report.status = ValidationStatus::Valid;
    Ok(report)
}
```

## Security Properties

### Immutability Guarantee

**Theorem:** Once a version is added to a valid chain and signed, any modification to that version or its ancestors will be cryptographically detectable.

**Proof Sketch:** 
1. Each version commits to its parent via cryptographic hash
2. Modifying any version changes its hash
3. This breaks the hash chain for all descendants
4. Digital signatures prevent hash chain repair without private keys

### Ordering Guarantee

**Theorem:** The version chain provides a partial ordering of all versions that is consistent across all implementations.

**Proof Sketch:**
1. Version numbers provide total ordering within single-author sequences
2. Hash chains provide causal ordering across authors
3. Timestamps provide weak temporal ordering
4. Conflict resolution provides deterministic final ordering

### Audit Trail Completeness

**Theorem:** Every change to the file content is recorded in the version chain with cryptographic proof of authorship.

**Proof Sketch:**
1. All modifications require new version creation
2. All versions are digitally signed by their authors
3. Version chain forms complete history from genesis to current
4. Cryptographic signatures provide non-repudiation

## Implementation Plan

### Phase 1: Core Data Structures (Week 1)
- Implement `VersionNode` and `VersionChain` types
- Basic version operations (add, get, traverse)
- Hash computation and validation functions

### Phase 2: Chain Validation (Week 2)
- Complete validation rule implementation
- Chain integrity checking
- Error reporting and diagnostics

### Phase 3: Conflict Resolution (Week 3)
- Last-writer-wins implementation
- Merge-based resolution (future)
- Performance optimizations

### Phase 4: Testing & Documentation (Week 4)
- Comprehensive test suite
- Property-based testing
- Performance benchmarks
- API documentation

## Open Questions

1. Should we support branch/merge semantics like Git?
2. How to handle very long chains (millions of versions)?
3. Should version numbers be globally unique or file-scoped?
4. How to implement efficient chain synchronization?

## References

- [Git Version Control Internals](https://git-scm.com/book/en/v2/Git-Internals-Git-Objects)
- [Merkle Tree Data Structure](https://en.wikipedia.org/wiki/Merkle_tree)
- [Lamport Timestamps](https://en.wikipedia.org/wiki/Lamport_timestamp)
- [Vector Clocks for Distributed Systems](https://en.wikipedia.org/wiki/Vector_clock)
- [Conflict-Free Replicated Data Types](https://en.wikipedia.org/wiki/Conflict-free_replicated_data_type)

## Appendix

### Terminology

- **Version Chain:** Sequence of cryptographically-linked versions
- **Genesis Version:** First version in chain (version 1)
- **Head Version:** Most recent version in chain
- **Hash Chain:** Parent-child relationships enforced by cryptographic hashes
- **Topological Sort:** Ordering that respects parent-child relationships
- **Conflict Resolution:** Process of determining canonical ordering when conflicts occur

### Example Chain Structure

```
Genesis (V1) ← Author A, T=1000
    ↓
Version 2 ← Author A, T=1100, Parent=Hash(V1)
    ↓
Version 3 ← Author B, T=1200, Parent=Hash(V2)  
    ↓
Version 4 ← Author A, T=1300, Parent=Hash(V3)
    ↓
Current (V4)
```

### Mathematical Notation

- `V_i` = Version with number i
- `H(V_i)` = Cryptographic hash of version i  
- `V_i → V_j` = Version j has parent version i
- `chain(V_1, V_n)` = Complete path from V_1 to V_n
- `author(V_i)` = Author who created version i
- `timestamp(V_i)` = Creation timestamp of version i