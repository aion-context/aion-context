# RFC 0015: Conflict Resolution Strategy

- **Author:** CRDT Specialist (PhD Distributed Systems, 8+ years conflict-free data types)
- **Status:** DRAFT
- **Created:** 2024-11-23
- **Updated:** 2024-11-23

## Abstract

Specification for conflict resolution in AION v2 when multiple authors create versions simultaneously or files diverge across devices. Defines deterministic algorithms for merging conflicting changes while preserving all historical data and maintaining cryptographic integrity of the audit trail.

## Motivation

### Problem Statement

AION v2's offline-first design enables concurrent modifications that can create conflicts:

1. **Concurrent Edits:** Two authors modify the same file simultaneously offline
2. **Network Partitions:** Devices work independently, then reconnect with divergent histories
3. **Sync Conflicts:** Cloud sync discovers incompatible version chains
4. **Fork Resolution:** Multiple valid version chains need to be merged
5. **Rollback Scenarios:** Need to revert to earlier state while preserving audit trail

### Use Cases

**Concurrent Development:**
```
Genesis → V2 (Alice) → V4 (Alice)
    └─ V3 (Bob) ──→ V5 (Bob)
    
Resolution: Merge into V6 with both Alice's and Bob's changes
```

**Network Split-Brain:**
```
Site A: V1 → V2 → V3 → V4
Site B: V1 → V2 ──→ V3' → V4'

Resolution: Deterministic merge based on timestamps/content/priority
```

**Sync Divergence:**
```
Device 1: Current=V10, knows V1-V10
Device 2: Current=V8,  knows V1-V8 + V11-V12 (from another device)

Resolution: Merge all versions into consistent chain
```

### Design Goals

- **Deterministic:** Same inputs always produce same resolution
- **Commutative:** Order of merge operations doesn't matter
- **Associative:** (A merge B) merge C = A merge (B merge C)
- **Idempotent:** Merging same data multiple times has no effect
- **Preserves History:** No data loss, complete audit trail maintained
- **Cryptographically Secure:** All resolutions are signed and verifiable

## Proposal

### Conflict Types

#### 1. Version Number Conflicts

```rust
/// Two versions with same number but different content
#[derive(Debug, Clone)]
pub struct VersionNumberConflict {
    pub version_number: VersionNumber,
    pub variants: Vec<VersionVariant>,
    pub conflict_type: ConflictType,
}

#[derive(Debug, Clone)]
pub struct VersionVariant {
    pub version: VersionNode,
    pub signatures: Vec<VersionSignature>,
    pub first_seen: u64,
    pub source_device: Option<DeviceId>,
}

#[derive(Debug, Clone)]
pub enum ConflictType {
    /// Same version number, different content
    ContentConflict,
    /// Same version number, different parent
    ParentConflict,
    /// Same version number, different timestamp
    TimestampConflict,
    /// Complete version duplication
    Duplicate,
}
```

#### 2. Chain Divergence

```rust
/// Multiple valid chains from same parent
#[derive(Debug, Clone)]
pub struct ChainDivergence {
    pub common_ancestor: VersionNumber,
    pub chains: Vec<VersionChain>,
    pub divergence_point: u64,
}

impl ChainDivergence {
    /// Find latest common ancestor of all chains
    pub fn find_common_ancestor(chains: &[VersionChain]) -> Option<VersionNumber> {
        if chains.is_empty() {
            return None;
        }
        
        // Start from genesis and work forward
        let mut candidate = VersionNumber::GENESIS;
        
        loop {
            let next_candidate = candidate.next().ok()?;
            
            // Check if all chains have this version with same hash
            let mut common_hash: Option<Blake3Hash> = None;
            
            for chain in chains {
                match chain.get_version_hash(next_candidate) {
                    Some(hash) => {
                        match common_hash {
                            None => common_hash = Some(hash),
                            Some(expected) if expected == hash => continue,
                            Some(_) => return Some(candidate), // Divergence found
                        }
                    }
                    None => return Some(candidate), // Chain doesn't have this version
                }
            }
            
            candidate = next_candidate;
        }
    }
}
```

### Resolution Algorithms

#### 1. Last Writer Wins (LWW)

```rust
/// Simple conflict resolution using timestamps
pub struct LastWriterWinsResolver {
    /// Clock skew tolerance (5 minutes)
    clock_skew_tolerance: Duration,
    /// Tiebreaker for identical timestamps
    tiebreaker: TiebreakerStrategy,
}

impl ConflictResolver for LastWriterWinsResolver {
    fn resolve_version_conflict(
        &self,
        conflict: &VersionNumberConflict,
    ) -> Result<ResolutionResult> {
        let mut variants = conflict.variants.clone();
        
        // Sort by timestamp (descending)
        variants.sort_by(|a, b| b.version.timestamp.cmp(&a.version.timestamp));
        
        // Handle timestamp ties
        let winner_timestamp = variants[0].version.timestamp;
        let ties: Vec<_> = variants
            .iter()
            .filter(|v| v.version.timestamp == winner_timestamp)
            .collect();
        
        let winner = if ties.len() == 1 {
            &variants[0]
        } else {
            // Use tiebreaker strategy
            self.resolve_timestamp_tie(&ties)?
        };
        
        // Create resolution metadata
        let resolution = ConflictResolution {
            resolution_type: ResolutionType::LastWriterWins,
            winner: winner.version.clone(),
            discarded: variants.iter()
                .filter(|v| v.version != winner.version)
                .map(|v| v.version.clone())
                .collect(),
            resolution_timestamp: unix_timestamp(),
            resolver_metadata: serde_json::json!({
                "strategy": "last_writer_wins",
                "winner_timestamp": winner_timestamp,
                "ties_resolved": ties.len() > 1,
                "tiebreaker": self.tiebreaker,
            }),
        };
        
        Ok(ResolutionResult {
            resolved_version: winner.version.clone(),
            resolution,
        })
    }
    
    fn resolve_timestamp_tie(
        &self,
        ties: &[&VersionVariant],
    ) -> Result<&VersionVariant> {
        match self.tiebreaker {
            TiebreakerStrategy::AuthorId => {
                // Highest author ID wins (deterministic)
                ties.iter()
                    .max_by_key(|v| v.version.author.0)
                    .ok_or(AionError::EmptyTiebreaker)
                    .map(|v| *v)
            }
            TiebreakerStrategy::ContentHash => {
                // Lexicographically largest content hash wins
                ties.iter()
                    .max_by(|a, b| a.version.content_hash.0.cmp(&b.version.content_hash.0))
                    .ok_or(AionError::EmptyTiebreaker)
                    .map(|v| *v)
            }
            TiebreakerStrategy::FirstSeen => {
                // Version first observed wins
                ties.iter()
                    .min_by_key(|v| v.first_seen)
                    .ok_or(AionError::EmptyTiebreaker)
                    .map(|v| *v)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TiebreakerStrategy {
    AuthorId,
    ContentHash,
    FirstSeen,
}
```

#### 2. Three-Way Merge

```rust
/// Advanced conflict resolution using three-way merge
pub struct ThreeWayMergeResolver {
    /// Rules merger for semantic conflict resolution
    rules_merger: Box<dyn RulesMerger>,
    /// Conflict detection sensitivity
    sensitivity: ConflictSensitivity,
}

impl ConflictResolver for ThreeWayMergeResolver {
    fn resolve_chain_divergence(
        &self,
        divergence: &ChainDivergence,
    ) -> Result<ResolutionResult> {
        if divergence.chains.len() != 2 {
            return Err(AionError::UnsupportedMergeScenario {
                chains: divergence.chains.len(),
            });
        }
        
        let base_version = divergence.common_ancestor;
        let left_chain = &divergence.chains[0];
        let right_chain = &divergence.chains[1];
        
        // Get current heads and base version
        let base = left_chain.get_version(base_version)
            .ok_or(AionError::MissingBaseVersion { version: base_version })?;
        let left = left_chain.current_version();
        let right = right_chain.current_version();
        
        // Decrypt and parse rules for three-way merge
        let base_rules = self.decrypt_rules(&base.content_hash)?;
        let left_rules = self.decrypt_rules(&left.content_hash)?;
        let right_rules = self.decrypt_rules(&right.content_hash)?;
        
        // Perform semantic merge
        let merge_result = self.rules_merger.merge_three_way(
            &base_rules,
            &left_rules,
            &right_rules,
        )?;
        
        match merge_result {
            MergeResult::Clean(merged_rules) => {
                // No conflicts, create clean merge version
                let merge_version = self.create_merge_version(
                    merged_rules,
                    vec![left.version, right.version],
                    MergeType::Clean,
                )?;
                
                Ok(ResolutionResult {
                    resolved_version: merge_version,
                    resolution: ConflictResolution::clean_merge(left, right),
                })
            }
            MergeResult::Conflicted(merged_rules, conflicts) => {
                // Conflicts detected, use resolution strategy
                let resolved_rules = self.resolve_rule_conflicts(
                    merged_rules,
                    conflicts,
                    left,
                    right,
                )?;
                
                let merge_version = self.create_merge_version(
                    resolved_rules,
                    vec![left.version, right.version],
                    MergeType::Conflicted,
                )?;
                
                Ok(ResolutionResult {
                    resolved_version: merge_version,
                    resolution: ConflictResolution::conflicted_merge(left, right, conflicts),
                })
            }
        }
    }
}

/// Rules merger for different data formats
pub trait RulesMerger: Send + Sync {
    fn merge_three_way(
        &self,
        base: &RulesData,
        left: &RulesData,
        right: &RulesData,
    ) -> Result<MergeResult>;
}

/// JSON-specific merger with path-based conflict detection
pub struct JsonRulesMerger {
    /// Conflict resolution preferences
    preferences: MergePreferences,
}

impl RulesMerger for JsonRulesMerger {
    fn merge_three_way(
        &self,
        base: &RulesData,
        left: &RulesData,
        right: &RulesData,
    ) -> Result<MergeResult> {
        // Parse JSON structures
        let base_json: serde_json::Value = serde_json::from_slice(base)?;
        let left_json: serde_json::Value = serde_json::from_slice(left)?;
        let right_json: serde_json::Value = serde_json::from_slice(right)?;
        
        // Perform path-based merge
        let mut merged = base_json.clone();
        let mut conflicts = Vec::new();
        
        self.merge_json_recursive(
            &mut merged,
            &base_json,
            &left_json,
            &right_json,
            "",
            &mut conflicts,
        )?;
        
        let merged_bytes = serde_json::to_vec_pretty(&merged)?;
        
        if conflicts.is_empty() {
            Ok(MergeResult::Clean(merged_bytes))
        } else {
            Ok(MergeResult::Conflicted(merged_bytes, conflicts))
        }
    }
}

impl JsonRulesMerger {
    fn merge_json_recursive(
        &self,
        target: &mut serde_json::Value,
        base: &serde_json::Value,
        left: &serde_json::Value,
        right: &serde_json::Value,
        path: &str,
        conflicts: &mut Vec<RuleConflict>,
    ) -> Result<()> {
        use serde_json::Value;
        
        match (base, left, right) {
            // No changes from either side
            (b, l, r) if l == b && r == b => {
                // No changes, keep base
            }
            // Only left changed
            (b, l, r) if r == b && l != b => {
                *target = l.clone();
            }
            // Only right changed
            (b, l, r) if l == b && r != b => {
                *target = r.clone();
            }
            // Both sides changed to same value
            (b, l, r) if l == r && l != b => {
                *target = l.clone();
            }
            // Conflict: both sides changed to different values
            (b, l, r) if l != b && r != b && l != r => {
                // Record conflict
                conflicts.push(RuleConflict {
                    path: path.to_string(),
                    base_value: b.clone(),
                    left_value: l.clone(),
                    right_value: r.clone(),
                    conflict_type: ConflictType::ValueConflict,
                });
                
                // Apply resolution strategy
                *target = self.resolve_value_conflict(b, l, r, path)?;
            }
            // Recursive case: objects
            (Value::Object(base_obj), Value::Object(left_obj), Value::Object(right_obj)) => {
                let target_obj = target.as_object_mut().unwrap();
                
                // Collect all keys
                let mut all_keys = HashSet::new();
                all_keys.extend(base_obj.keys());
                all_keys.extend(left_obj.keys());
                all_keys.extend(right_obj.keys());
                
                for key in all_keys {
                    let child_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{}.{}", path, key)
                    };
                    
                    let base_val = base_obj.get(key).unwrap_or(&Value::Null);
                    let left_val = left_obj.get(key).unwrap_or(&Value::Null);
                    let right_val = right_obj.get(key).unwrap_or(&Value::Null);
                    
                    let mut merged_val = base_val.clone();
                    self.merge_json_recursive(
                        &mut merged_val,
                        base_val,
                        left_val,
                        right_val,
                        &child_path,
                        conflicts,
                    )?;
                    
                    if merged_val != Value::Null {
                        target_obj.insert(key.clone(), merged_val);
                    }
                }
            }
            // Type mismatch or complex conflicts
            _ => {
                conflicts.push(RuleConflict {
                    path: path.to_string(),
                    base_value: base.clone(),
                    left_value: left.clone(),
                    right_value: right.clone(),
                    conflict_type: ConflictType::TypeConflict,
                });
                
                *target = self.resolve_value_conflict(base, left, right, path)?;
            }
        }
        
        Ok(())
    }
    
    fn resolve_value_conflict(
        &self,
        base: &serde_json::Value,
        left: &serde_json::Value,
        right: &serde_json::Value,
        path: &str,
    ) -> Result<serde_json::Value> {
        match self.preferences.get_strategy_for_path(path) {
            ConflictStrategy::LeftWins => Ok(left.clone()),
            ConflictStrategy::RightWins => Ok(right.clone()),
            ConflictStrategy::KeepBase => Ok(base.clone()),
            ConflictStrategy::Union => self.attempt_union(left, right),
            ConflictStrategy::Fail => Err(AionError::UnresolvableConflict {
                path: path.to_string(),
            }),
        }
    }
    
    fn attempt_union(
        &self,
        left: &serde_json::Value,
        right: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        use serde_json::Value;
        
        match (left, right) {
            // Union arrays
            (Value::Array(left_arr), Value::Array(right_arr)) => {
                let mut union = left_arr.clone();
                for item in right_arr {
                    if !union.contains(item) {
                        union.push(item.clone());
                    }
                }
                Ok(Value::Array(union))
            }
            // Union objects
            (Value::Object(left_obj), Value::Object(right_obj)) => {
                let mut union = left_obj.clone();
                for (key, value) in right_obj {
                    union.entry(key.clone()).or_insert(value.clone());
                }
                Ok(Value::Object(union))
            }
            // Cannot union different types
            _ => Err(AionError::IncompatibleUnion),
        }
    }
}
```

#### 3. Operational Transform (OT)

```rust
/// Operational Transform for concurrent edits
pub struct OperationalTransformResolver {
    /// Operation transformation engine
    transform_engine: Box<dyn TransformEngine>,
    /// Maximum operations to replay
    max_operations: usize,
}

impl ConflictResolver for OperationalTransformResolver {
    fn resolve_concurrent_operations(
        &self,
        base_version: &VersionNode,
        operations_a: &[Operation],
        operations_b: &[Operation],
    ) -> Result<ResolutionResult> {
        // Transform operations against each other
        let (transformed_a, transformed_b) = self.transform_engine
            .transform_operations(operations_a, operations_b)?;
        
        // Apply transformed operations to base
        let mut result_data = base_version.decrypt_content()?;
        
        // Apply A's transformed operations
        for op in &transformed_a {
            result_data = op.apply(&result_data)?;
        }
        
        // Apply B's transformed operations
        for op in &transformed_b {
            result_data = op.apply(&result_data)?;
        }
        
        // Create merge version
        let merge_version = VersionNode {
            version: base_version.version.next()?,
            parent_hash: Some(compute_version_hash(base_version)),
            content_hash: blake3::hash(&result_data).into(),
            author: AuthorId(0), // System merge
            timestamp: unix_timestamp(),
            metadata: VersionMetadata::merge_metadata(&[
                base_version.version,
            ])?,
        };
        
        Ok(ResolutionResult {
            resolved_version: merge_version,
            resolution: ConflictResolution {
                resolution_type: ResolutionType::OperationalTransform,
                operations: Some(OperationLog {
                    original_a: operations_a.to_vec(),
                    original_b: operations_b.to_vec(),
                    transformed_a,
                    transformed_b,
                }),
                ..Default::default()
            },
        })
    }
}

/// Abstract operation for transformation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operation {
    /// Insert text at position
    Insert { position: usize, text: String },
    /// Delete text range
    Delete { start: usize, length: usize },
    /// Replace text range
    Replace { start: usize, length: usize, text: String },
    /// JSON path operation
    JsonPath { path: String, operation: JsonOperation },
}

impl Operation {
    /// Apply operation to data
    pub fn apply(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Operation::Insert { position, text } => {
                let mut result = Vec::with_capacity(data.len() + text.len());
                result.extend_from_slice(&data[..*position]);
                result.extend_from_slice(text.as_bytes());
                result.extend_from_slice(&data[*position..]);
                Ok(result)
            }
            Operation::Delete { start, length } => {
                let mut result = Vec::with_capacity(data.len());
                result.extend_from_slice(&data[..*start]);
                result.extend_from_slice(&data[*start + *length..]);
                Ok(result)
            }
            Operation::Replace { start, length, text } => {
                let mut result = Vec::with_capacity(data.len() + text.len());
                result.extend_from_slice(&data[..*start]);
                result.extend_from_slice(text.as_bytes());
                result.extend_from_slice(&data[*start + *length..]);
                Ok(result)
            }
            Operation::JsonPath { path, operation } => {
                // Parse JSON, apply path operation, serialize back
                let mut json: serde_json::Value = serde_json::from_slice(data)?;
                operation.apply_to_json(&mut json, path)?;
                Ok(serde_json::to_vec_pretty(&json)?)
            }
        }
    }
}
```

### Resolution Strategies

#### Configuration-Based Resolution

```rust
/// Configurable conflict resolution strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionConfig {
    /// Default strategy for version conflicts
    pub default_strategy: ConflictStrategy,
    
    /// Path-specific strategies
    pub path_strategies: HashMap<String, ConflictStrategy>,
    
    /// Author priority for tie-breaking
    pub author_priorities: HashMap<AuthorId, u32>,
    
    /// Temporal preferences
    pub temporal_preferences: TemporalPreferences,
    
    /// Safety settings
    pub safety_settings: SafetySettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConflictStrategy {
    /// Use last modification timestamp
    LastWriterWins,
    /// Perform semantic three-way merge
    ThreeWayMerge,
    /// Use operational transform
    OperationalTransform,
    /// Always favor specific author
    AuthorPreference(AuthorId),
    /// Combine non-conflicting changes
    Union,
    /// Require manual resolution
    Manual,
    /// Use custom resolver
    Custom(String),
}

impl ResolutionConfig {
    /// Get strategy for specific rule path
    pub fn get_strategy_for_path(&self, path: &str) -> ConflictStrategy {
        // Check for exact path match
        if let Some(strategy) = self.path_strategies.get(path) {
            return strategy.clone();
        }
        
        // Check for prefix matches (longest first)
        let mut matching_paths: Vec<_> = self.path_strategies
            .iter()
            .filter(|(pattern, _)| path.starts_with(*pattern))
            .collect();
        
        matching_paths.sort_by_key(|(pattern, _)| std::cmp::Reverse(pattern.len()));
        
        if let Some((_, strategy)) = matching_paths.first() {
            strategy.clone()
        } else {
            self.default_strategy.clone()
        }
    }
    
    /// Validate configuration for consistency
    pub fn validate(&self) -> Result<ValidationReport> {
        let mut warnings = Vec::new();
        let mut errors = Vec::new();
        
        // Check for conflicting path strategies
        for (path1, strategy1) in &self.path_strategies {
            for (path2, strategy2) in &self.path_strategies {
                if path1 != path2 && path1.starts_with(path2) && strategy1 != strategy2 {
                    warnings.push(format!(
                        "Path {} conflicts with parent path {} (different strategies)",
                        path1, path2
                    ));
                }
            }
        }
        
        // Validate author priorities
        let priority_values: Vec<_> = self.author_priorities.values().collect();
        let unique_priorities: HashSet<_> = priority_values.iter().collect();
        if priority_values.len() != unique_priorities.len() {
            warnings.push("Duplicate author priorities may cause non-deterministic resolution".to_string());
        }
        
        Ok(ValidationReport { warnings, errors })
    }
}
```

### Merge Metadata

```rust
/// Comprehensive metadata for conflict resolution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictResolution {
    /// Type of resolution performed
    pub resolution_type: ResolutionType,
    
    /// Winning version (if applicable)
    pub winner: Option<VersionNode>,
    
    /// Discarded versions
    pub discarded: Vec<VersionNode>,
    
    /// Merge parents (for merge commits)
    pub merge_parents: Vec<VersionNumber>,
    
    /// Timestamp of resolution
    pub resolution_timestamp: u64,
    
    /// Detailed conflict information
    pub conflicts: Vec<RuleConflict>,
    
    /// Resolution strategy used
    pub strategy: ConflictStrategy,
    
    /// Additional metadata
    pub resolver_metadata: serde_json::Value,
    
    /// Operations applied (for OT)
    pub operations: Option<OperationLog>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConflict {
    /// JSON path or location of conflict
    pub path: String,
    
    /// Base value (common ancestor)
    pub base_value: serde_json::Value,
    
    /// Left side value
    pub left_value: serde_json::Value,
    
    /// Right side value
    pub right_value: serde_json::Value,
    
    /// Type of conflict detected
    pub conflict_type: ConflictType,
    
    /// How conflict was resolved
    pub resolution: ConflictResolutionMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConflictResolutionMethod {
    /// Used left value
    SelectedLeft,
    /// Used right value
    SelectedRight,
    /// Kept base value
    KeptBase,
    /// Merged values (union, etc.)
    Merged(serde_json::Value),
    /// Required manual resolution
    Manual,
}
```

### CLI Integration

```bash
# Detect and show conflicts
$ aion conflicts myapp.aion
Found 3 conflicts requiring resolution:

Conflict 1: Version Number Conflict
  Version: 15
  Variant A: Author 1001, 2024-11-23 10:30:15, Hash: a1b2c3...
  Variant B: Author 1002, 2024-11-23 10:30:22, Hash: d4e5f6...
  
Conflict 2: Chain Divergence  
  Common ancestor: v12
  Chain A: v12 → v13 → v14 (Author 1001)
  Chain B: v12 → v13' → v14' (Author 1002)

Conflict 3: Rule Path Conflict
  Path: security.authentication.method
  Base: "password"
  Left: "mfa"  
  Right: "sso"

# Resolve conflicts automatically
$ aion resolve myapp.aion --strategy last-writer-wins
➤ Resolving conflicts using last-writer-wins...
✓ Resolved version conflict: v15 → Author 1002 wins (later timestamp)
✓ Resolved chain divergence: v14' → Author 1002 wins  
✓ Resolved rule conflict: security.authentication.method = "sso"
✓ Created merge version v16 with resolution metadata

# Interactive conflict resolution
$ aion resolve myapp.aion --interactive
Resolving conflict 1/3: Version Number Conflict (v15)

Variant A (Author 1001, 2024-11-23 10:30:15):
  + Added: validation.required_fields = ["email"]  
  ~ Modified: permissions.admin = ["1001", "1002"]

Variant B (Author 1002, 2024-11-23 10:30:22):  
  + Added: validation.max_length = 1000
  ~ Modified: permissions.admin = ["1001", "1003"]

Choose resolution:
  [A] Use Variant A
  [B] Use Variant B  
  [M] Merge both changes
  [E] Edit manually
  [S] Skip this conflict
Choice: M

➤ Attempting automatic merge...
✓ Merged successfully
  + Added both validation rules
  ! Conflict in permissions.admin: ["1001", "1002"] vs ["1001", "1003"]
  
Resolve permissions.admin conflict:
  [1] ["1001", "1002"] (Variant A)
  [2] ["1001", "1003"] (Variant B)
  [3] ["1001", "1002", "1003"] (Union)
  [4] Custom value
Choice: 3

✓ Resolved using union: ["1001", "1002", "1003"]

# Configure resolution strategies
$ aion config set conflict_resolution.default_strategy three_way_merge
$ aion config set conflict_resolution.path_strategies.'security.*' manual
$ aion config set conflict_resolution.author_priorities.1001 100
$ aion config set conflict_resolution.author_priorities.1002 90
```

### Performance Considerations

```rust
/// Optimized conflict detection
pub struct ConflictDetector {
    /// Hash-based quick conflict detection
    version_hashes: HashMap<VersionNumber, Blake3Hash>,
    /// Bloom filter for fast membership testing
    bloom_filter: BloomFilter,
    /// Conflict cache to avoid recomputation
    conflict_cache: LruCache<ConflictKey, ConflictResult>,
}

impl ConflictDetector {
    /// Fast path: detect conflicts without full comparison
    pub fn quick_conflict_check(
        &self,
        version_a: &VersionNode,
        version_b: &VersionNode,
    ) -> ConflictCheckResult {
        // Same version number is only conflict if different content
        if version_a.version == version_b.version {
            return if version_a.content_hash == version_b.content_hash {
                ConflictCheckResult::Duplicate
            } else {
                ConflictCheckResult::VersionConflict
            };
        }
        
        // Check if versions are in same chain
        if self.are_versions_related(version_a, version_b) {
            ConflictCheckResult::NoConflict
        } else {
            ConflictCheckResult::ChainDivergence
        }
    }
    
    /// Incremental conflict detection for new versions
    pub fn detect_incremental_conflicts(
        &mut self,
        new_versions: &[VersionNode],
        existing_chain: &VersionChain,
    ) -> Vec<Conflict> {
        let mut conflicts = Vec::new();
        
        for new_version in new_versions {
            // Check against existing versions with same number
            if let Some(existing) = existing_chain.get_version(new_version.version) {
                if existing.content_hash != new