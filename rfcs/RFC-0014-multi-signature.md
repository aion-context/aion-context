# RFC 0014: Multi-Signature Support

- **Author:** Crypto Protocol Designer (PhD Cryptography, 10+ years multi-party protocols)
- **Status:** DRAFT
- **Created:** 2024-11-23
- **Updated:** 2024-11-23

## Abstract

Specification for multi-signature support in AION v2, enabling multiple parties to collectively authorize changes to AION files. Provides threshold signature schemes (M-of-N) and sequential approval workflows while maintaining the offline-first design principle and cryptographic security guarantees.

## Motivation

### Problem Statement

Many organizations require multiple approvals for critical configuration changes:

1. **Financial Services:** SOX compliance requires dual approval for trading system changes
2. **Healthcare:** HIPAA-regulated changes need security officer and system administrator approval
3. **Government:** Classified system changes require multiple clearance levels
4. **Enterprise:** Critical infrastructure changes need both technical and business approval
5. **Open Source:** Community projects need maintainer consensus for major changes

### Use Cases

**Dual Approval (2-of-2):**
```
Change Request → Author A Signs → Author B Signs → Change Applied
```

**Threshold Approval (3-of-5):**
```
Change Request → Author A Signs → Author C Signs → Author E Signs → Change Applied
                     ↓              ↓              ↓
               (Any 3 of 5 authors can approve)
```

**Sequential Workflow:**
```
Developer → Technical Lead → Security Officer → Change Applied
  (1001)       (2001)           (3001)
```

### Design Goals

- **Threshold Signatures:** M-of-N approval requirements
- **Flexible Policies:** Per-file or per-change signature requirements
- **Audit Trail:** Complete record of who approved what and when
- **Offline Compatible:** No coordination server required
- **Non-Repudiation:** Cryptographic proof of approval
- **Performance:** Minimal overhead for single-signature workflows

## Proposal

### Multi-Signature Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Multi-Signature Workflow                 │
├─────────────────────────────────────────────────────────────┤
│  1. Author Creates Proposed Version                         │
│     ├─ Version Data + Rules Changes                         │
│     ├─ Initial Signature (Proposer)                         │
│     └─ Multi-Sig Policy Requirements                        │
├─────────────────────────────────────────────────────────────┤
│  2. Approvers Add Signatures                                │
│     ├─ Each Approver Signs Same Version Hash                │
│     ├─ Signatures Accumulated Until Threshold Met           │
│     └─ Order Independence (Commutative)                     │
├─────────────────────────────────────────────────────────────┤
│  3. Version Activation                                       │
│     ├─ Verify Threshold Met (M-of-N)                        │
│     ├─ Validate All Signatures                              │
│     └─ Atomically Commit Version                            │
└─────────────────────────────────────────────────────────────┘
```

### Data Structures

#### Multi-Signature Policy

```rust
/// Multi-signature policy for a file or specific operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiSigPolicy {
    /// Unique policy identifier
    pub policy_id: PolicyId,
    
    /// Policy name for human reference
    pub name: String,
    
    /// Signature requirements
    pub requirements: SignatureRequirement,
    
    /// Authorized signers
    pub authorized_signers: HashSet<AuthorId>,
    
    /// Policy scope
    pub scope: PolicyScope,
    
    /// Expiration time (optional)
    pub expires_at: Option<u64>,
    
    /// Policy metadata
    pub metadata: PolicyMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureRequirement {
    /// Require exactly N signatures from authorized set
    Threshold { required: usize, total: usize },
    
    /// Require ALL specified signers
    All(HashSet<AuthorId>),
    
    /// Require signatures from specific roles in order
    Sequential(Vec<AuthorId>),
    
    /// Complex boolean logic (AND/OR combinations)
    Boolean(BooleanExpression),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyScope {
    /// Apply to all changes
    Global,
    
    /// Apply to specific rule paths
    RulePaths(Vec<String>),
    
    /// Apply to changes above certain size
    ChangeSize { min_bytes: usize },
    
    /// Apply to structural changes only
    StructuralChanges,
}

/// Boolean expression for complex signature requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BooleanExpression {
    /// Single signer requirement
    Signer(AuthorId),
    
    /// Logical AND
    And(Box<BooleanExpression>, Box<BooleanExpression>),
    
    /// Logical OR  
    Or(Box<BooleanExpression>, Box<BooleanExpression>),
    
    /// Threshold within group
    Threshold {
        required: usize,
        signers: HashSet<AuthorId>,
    },
}
```

#### Pending Version

```rust
/// Version awaiting additional signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingVersion {
    /// Version being proposed
    pub version: VersionNode,
    
    /// Required signature policy
    pub policy: MultiSigPolicy,
    
    /// Signatures collected so far
    pub signatures: Vec<VersionSignature>,
    
    /// Signature collection timeout
    pub expires_at: u64,
    
    /// Current signature status
    pub status: SignatureStatus,
    
    /// Proposer information
    pub proposer: AuthorId,
    
    /// Proposal timestamp
    pub proposed_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureStatus {
    /// Awaiting more signatures
    Pending {
        required: usize,
        collected: usize,
        missing: HashSet<AuthorId>,
    },
    
    /// Threshold met, ready to commit
    Ready,
    
    /// Expired or rejected
    Rejected { reason: String },
    
    /// Successfully committed
    Committed { version: VersionNumber },
}
```

#### Multi-Signature Storage

```rust
/// Extended file header for multi-signature support
#[derive(Debug, Clone)]
pub struct MultiSigFileHeader {
    /// Standard AION header
    pub base_header: FileHeader,
    
    /// Multi-sig extension flag
    pub multisig_enabled: bool,
    
    /// Default signature policy
    pub default_policy: Option<PolicyId>,
    
    /// Pending versions section offset
    pub pending_offset: u64,
    
    /// Pending versions count
    pub pending_count: u64,
    
    /// Policies section offset
    pub policies_offset: u64,
    
    /// Policies count
    pub policies_count: u64,
}

/// File section for pending versions
#[derive(Debug, Clone)]
pub struct PendingVersionsSection {
    /// All versions awaiting signatures
    pub pending: Vec<PendingVersion>,
    
    /// Cleanup threshold (auto-remove expired)
    pub cleanup_threshold: Duration,
}
```

### Multi-Signature Operations

#### Creating Multi-Signature Proposals

```rust
impl AionFile {
    /// Propose new version requiring multiple signatures
    pub fn propose_version(
        &mut self,
        rules_data: Vec<u8>,
        proposer: AuthorId,
        policy: MultiSigPolicy,
    ) -> Result<ProposalId> {
        // Create proposed version
        let version_number = self.next_version_number()?;
        let proposed_version = VersionNode {
            version: version_number,
            parent_hash: Some(self.current_head_hash()),
            content_hash: blake3::hash(&rules_data).into(),
            author: proposer,
            timestamp: unix_timestamp(),
            metadata: VersionMetadata::new(),
        };
        
        // Create initial signature from proposer
        let signature_data = self.create_signature_data(&proposed_version)?;
        let proposer_signature = self.sign_with_author(proposer, &signature_data)?;
        
        // Create pending version
        let pending = PendingVersion {
            version: proposed_version,
            policy: policy.clone(),
            signatures: vec![proposer_signature],
            expires_at: unix_timestamp() + policy.signature_timeout(),
            status: self.calculate_signature_status(&policy, &[proposer_signature])?,
            proposer,
            proposed_at: unix_timestamp(),
        };
        
        // Add to pending versions
        let proposal_id = self.add_pending_version(pending)?;
        
        // Record in audit trail
        self.add_audit_entry(AuditEntry {
            timestamp: unix_timestamp(),
            action: AuditAction::VersionProposed,
            author: proposer,
            details: serde_json::json!({
                "proposal_id": proposal_id,
                "version": version_number.0,
                "policy": policy.policy_id,
                "required_signatures": policy.requirements.required_count(),
            }),
        })?;
        
        Ok(proposal_id)
    }
    
    /// Add signature to pending version
    pub fn add_signature(
        &mut self,
        proposal_id: ProposalId,
        signer: AuthorId,
    ) -> Result<SignatureResult> {
        let mut pending = self.get_pending_version_mut(proposal_id)?;
        
        // Validate signer is authorized
        if !pending.policy.authorized_signers.contains(&signer) {
            return Err(AionError::UnauthorizedSigner { 
                signer,
                policy: pending.policy.policy_id,
            });
        }
        
        // Check if already signed
        if pending.signatures.iter().any(|s| s.author_id == signer.0) {
            return Err(AionError::DuplicateSignature { signer });
        }
        
        // Check expiration
        if unix_timestamp() > pending.expires_at {
            pending.status = SignatureStatus::Rejected {
                reason: "Signature collection expired".to_string(),
            };
            return Err(AionError::ProposalExpired { proposal_id });
        }
        
        // Create and validate signature
        let signature_data = self.create_signature_data(&pending.version)?;
        let signature = self.sign_with_author(signer, &signature_data)?;
        
        // Add signature
        pending.signatures.push(signature);
        
        // Update status
        pending.status = self.calculate_signature_status(
            &pending.policy,
            &pending.signatures,
        )?;
        
        // Check if ready to commit
        match pending.status {
            SignatureStatus::Ready => {
                let version = self.commit_pending_version(proposal_id)?;
                Ok(SignatureResult::VersionCommitted { version })
            }
            SignatureStatus::Pending { .. } => {
                Ok(SignatureResult::SignatureAdded { 
                    remaining: pending.status.remaining_signatures(),
                })
            }
            SignatureStatus::Rejected { reason } => {
                Err(AionError::ProposalRejected { 
                    proposal_id,
                    reason,
                })
            }
            _ => unreachable!(),
        }
    }
}
```

#### Signature Validation

```rust
impl MultiSigPolicy {
    /// Check if signature requirements are met
    pub fn validate_signatures(
        &self,
        signatures: &[VersionSignature],
    ) -> Result<ValidationResult> {
        match &self.requirements {
            SignatureRequirement::Threshold { required, total } => {
                self.validate_threshold_signatures(signatures, *required, *total)
            }
            SignatureRequirement::All(required_signers) => {
                self.validate_all_signatures(signatures, required_signers)
            }
            SignatureRequirement::Sequential(ordered_signers) => {
                self.validate_sequential_signatures(signatures, ordered_signers)
            }
            SignatureRequirement::Boolean(expression) => {
                self.validate_boolean_expression(signatures, expression)
            }
        }
    }
    
    fn validate_threshold_signatures(
        &self,
        signatures: &[VersionSignature],
        required: usize,
        _total: usize,
    ) -> Result<ValidationResult> {
        // Count valid signatures from authorized signers
        let mut valid_signatures = 0;
        let mut signer_set = HashSet::new();
        
        for signature in signatures {
            let signer = AuthorId(signature.author_id);
            
            // Check authorization
            if !self.authorized_signers.contains(&signer) {
                continue;
            }
            
            // Prevent double-counting
            if signer_set.contains(&signer) {
                continue;
            }
            
            // Verify signature cryptographically
            if self.verify_signature(signature)? {
                valid_signatures += 1;
                signer_set.insert(signer);
            }
        }
        
        if valid_signatures >= required {
            Ok(ValidationResult::Valid {
                required_signatures: required,
                valid_signatures,
                signers: signer_set,
            })
        } else {
            Ok(ValidationResult::Insufficient {
                required: required,
                collected: valid_signatures,
                missing: required - valid_signatures,
            })
        }
    }
    
    fn validate_boolean_expression(
        &self,
        signatures: &[VersionSignature],
        expression: &BooleanExpression,
    ) -> Result<ValidationResult> {
        let signer_set: HashSet<AuthorId> = signatures
            .iter()
            .map(|s| AuthorId(s.author_id))
            .collect();
        
        let satisfied = self.evaluate_boolean_expression(expression, &signer_set)?;
        
        if satisfied {
            Ok(ValidationResult::Valid {
                required_signatures: expression.required_signature_count(),
                valid_signatures: signatures.len(),
                signers: signer_set,
            })
        } else {
            Ok(ValidationResult::Insufficient {
                required: expression.required_signature_count(),
                collected: signatures.len(),
                missing: expression.missing_signatures(&signer_set),
            })
        }
    }
    
    fn evaluate_boolean_expression(
        &self,
        expression: &BooleanExpression,
        signers: &HashSet<AuthorId>,
    ) -> Result<bool> {
        match expression {
            BooleanExpression::Signer(author_id) => {
                Ok(signers.contains(author_id))
            }
            BooleanExpression::And(left, right) => {
                Ok(self.evaluate_boolean_expression(left, signers)? &&
                   self.evaluate_boolean_expression(right, signers)?)
            }
            BooleanExpression::Or(left, right) => {
                Ok(self.evaluate_boolean_expression(left, signers)? ||
                   self.evaluate_boolean_expression(right, signers)?)
            }
            BooleanExpression::Threshold { required, signers: required_signers } => {
                let valid_signers: HashSet<_> = signers
                    .intersection(required_signers)
                    .count();
                Ok(valid_signers >= *required)
            }
        }
    }
}
```

### Policy Management

#### Dynamic Policy Updates

```rust
impl AionFile {
    /// Update multi-signature policy (requires current policy approval)
    pub fn update_policy(
        &mut self,
        policy_id: PolicyId,
        new_policy: MultiSigPolicy,
        approver_signatures: Vec<VersionSignature>,
    ) -> Result<()> {
        // Get current policy
        let current_policy = self.get_policy(policy_id)?;
        
        // Validate current policy requirements are met for policy change
        let policy_change_result = current_policy.validate_signatures(&approver_signatures)?;
        match policy_change_result {
            ValidationResult::Valid { .. } => {},
            ValidationResult::Insufficient { .. } => {
                return Err(AionError::InsufficientSignatures {
                    required: current_policy.requirements.required_count(),
                    provided: approver_signatures.len(),
                });
            }
        }
        
        // Validate new policy is well-formed
        new_policy.validate()?;
        
        // Update policy
        self.policies.insert(policy_id, new_policy.clone());
        
        // Record policy change in audit trail
        self.add_audit_entry(AuditEntry {
            timestamp: unix_timestamp(),
            action: AuditAction::PolicyUpdated,
            author: AuthorId(0), // System action
            details: serde_json::json!({
                "policy_id": policy_id,
                "policy_name": new_policy.name,
                "approvers": approver_signatures.iter()
                    .map(|s| s.author_id)
                    .collect::<Vec<_>>(),
            }),
        })?;
        
        Ok(())
    }
    
    /// Create policy templates for common scenarios
    pub fn create_standard_policy(
        policy_type: StandardPolicyType,
        signers: Vec<AuthorId>,
    ) -> MultiSigPolicy {
        match policy_type {
            StandardPolicyType::DualApproval => {
                MultiSigPolicy {
                    policy_id: PolicyId::generate(),
                    name: "Dual Approval".to_string(),
                    requirements: SignatureRequirement::Threshold {
                        required: 2,
                        total: signers.len(),
                    },
                    authorized_signers: signers.into_iter().collect(),
                    scope: PolicyScope::Global,
                    expires_at: None,
                    metadata: PolicyMetadata::default(),
                }
            }
            StandardPolicyType::TechnicalAndBusiness => {
                let technical_lead = signers[0];
                let business_owner = signers[1];
                
                MultiSigPolicy {
                    policy_id: PolicyId::generate(),
                    name: "Technical + Business Approval".to_string(),
                    requirements: SignatureRequirement::Boolean(
                        BooleanExpression::And(
                            Box::new(BooleanExpression::Signer(technical_lead)),
                            Box::new(BooleanExpression::Signer(business_owner)),
                        )
                    ),
                    authorized_signers: vec![technical_lead, business_owner].into_iter().collect(),
                    scope: PolicyScope::Global,
                    expires_at: None,
                    metadata: PolicyMetadata::default(),
                }
            }
            StandardPolicyType::MajorityVote => {
                let required = (signers.len() + 1) / 2; // Majority
                
                MultiSigPolicy {
                    policy_id: PolicyId::generate(),
                    name: "Majority Vote".to_string(),
                    requirements: SignatureRequirement::Threshold {
                        required,
                        total: signers.len(),
                    },
                    authorized_signers: signers.into_iter().collect(),
                    scope: PolicyScope::Global,
                    expires_at: None,
                    metadata: PolicyMetadata::default(),
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum StandardPolicyType {
    DualApproval,
    TechnicalAndBusiness,
    MajorityVote,
}
```

### CLI Integration

#### Multi-Signature Commands

```bash
# Propose version requiring multiple signatures
$ aion propose myapp.aion --rules updated_rules.json --policy dual-approval
✓ Version 15 proposed (requires 2-of-3 signatures)
  Proposal ID: prop-a1b2c3d4
  Your signature: ✓ Added
  Remaining signatures needed: 1
  
  Waiting for signatures from:
    • Author 1002 (Technical Lead)
    • Author 1003 (Business Owner)

# List pending proposals
$ aion proposals myapp.aion
Proposal ID      Version  Proposer  Policy        Status        Expires
prop-a1b2c3d4    v15      1001      dual-approval 1/2 sigs     2024-11-24 10:30
prop-x7y8z9w0    v14      1002      majority-vote 2/5 sigs     2024-11-23 18:45

# Add signature to proposal
$ aion approve myapp.aion prop-a1b2c3d4 --author-id 1002
✓ Signature added by author 1002
✓ Threshold met (2/2 signatures)
✓ Version 15 committed successfully

  Signers:
    • 1001 (Proposer) - 2024-11-23 14:30:15
    • 1002 (Approver) - 2024-11-23 14:35:22

# Create multi-signature policy
$ aion policy create myapp.aion --name "Security Team Approval" \
    --threshold 2 --signers 2001,2002,2003 --scope "security.*"
✓ Policy created: policy-sec-001
✓ Applied to rule paths matching 'security.*'

# Show multi-signature status
$ aion status myapp.aion --multisig
Multi-Signature Status:
  Default Policy: dual-approval (2-of-3)
  Active Policies: 3
  Pending Proposals: 1
  
  Authorized Signers:
    • 1001 (Alice - Developer)
    • 1002 (Bob - Technical Lead)  
    • 1003 (Carol - Business Owner)
    
  Recent Activity:
    • v15 committed with 2 signatures (1 hour ago)
    • v14 pending approval (2/5 signatures)
```

### Security Considerations

#### Attack Resistance

```rust
/// Security validations for multi-signature operations
impl MultiSigPolicy {
    /// Validate policy configuration for security issues
    pub fn validate_security(&self) -> Result<SecurityValidation> {
        let mut warnings = Vec::new();
        let mut errors = Vec::new();
        
        // Check for insufficient threshold
        match &self.requirements {
            SignatureRequirement::Threshold { required, total } => {
                if *required == 1 && *total > 1 {
                    warnings.push("Threshold of 1 provides no additional security".to_string());
                }
                if *required as f64 / *total as f64 < 0.5 {
                    warnings.push("Threshold below 50% may be vulnerable to minority attacks".to_string());
                }
            }
            _ => {}
        }
        
        // Check for policy scope conflicts
        if matches!(self.scope, PolicyScope::Global) {
            if self.authorized_signers.len() < 2 {
                errors.push("Global policies must have at least 2 authorized signers".to_string());
            }
        }
        
        // Check for expiration in the past
        if let Some(expires_at) = self.expires_at {
            if expires_at < unix_timestamp() {
                errors.push("Policy expiration time is in the past".to_string());
            }
        }
        
        // Validate boolean expressions for complexity
        if let SignatureRequirement::Boolean(expr) = &self.requirements {
            if expr.complexity() > MAX_EXPRESSION_COMPLEXITY {
                errors.push("Boolean expression too complex (potential DoS risk)".to_string());
            }
        }
        
        if !errors.is_empty() {
            Err(AionError::InvalidPolicy { errors })
        } else {
            Ok(SecurityValidation { warnings })
        }
    }
    
    /// Detect potential signature requirement bypass
    pub fn detect_bypass_attempts(
        &self,
        signatures: &[VersionSignature],
    ) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();
        
        // Check for timestamp manipulation
        let mut timestamps: Vec<u64> = signatures.iter()
            .map(|s| s.signed_at)
            .collect();
        timestamps.sort();
        
        for window in timestamps.windows(2) {
            if window[1] - window[0] < 1000 { // Less than 1 second apart
                warnings.push(SecurityWarning::SuspiciousTimestamps {
                    signatures: signatures.iter()
                        .filter(|s| s.signed_at == window[0] || s.signed_at == window[1])
                        .map(|s| s.author_id)
                        .collect(),
                });
            }
        }
        
        // Check for signature from unauthorized parties
        for signature in signatures {
            let signer = AuthorId(signature.author_id);
            if !self.authorized_signers.contains(&signer) {
                warnings.push(SecurityWarning::UnauthorizedSignature { signer });
            }
        }
        
        warnings
    }
}
```

### Performance Considerations

#### Batch Operations

```rust
/// Optimized batch signature verification
impl MultiSigValidator {
    /// Verify multiple signatures in parallel
    pub async fn verify_signatures_batch(
        &self,
        signatures: &[VersionSignature],
        message: &[u8],
    ) -> Result<Vec<bool>> {
        // Use parallel signature verification for large batches
        if signatures.len() > PARALLEL_VERIFICATION_THRESHOLD {
            self.verify_parallel(signatures, message).await
        } else {
            // Sequential verification for small batches
            signatures.iter()
                .map(|sig| self.verify_single_signature(sig, message))
                .collect()
        }
    }
    
    async fn verify_parallel(
        &self,
        signatures: &[VersionSignature],
        message: &[u8],
    ) -> Result<Vec<bool>> {
        use rayon::prelude::*;
        
        // Parallel signature verification using rayon
        let results: Vec<bool> = signatures
            .par_iter()
            .map(|signature| {
                self.verify_single_signature(signature, message)
                    .unwrap_or(false)
            })
            .collect();
        
        Ok(results)
    }
}
```

## Testing Strategy

### Multi-Signature Test Scenarios

```rust
#[cfg(test)]
mod multisig_tests {
    use super::*;
    
    #[test]
    fn test_threshold_signature_workflow() -> Result<()> {
        // Setup 3-of-5 threshold policy
        let signers = (1001..=1005).map(AuthorId).collect::<Vec<_>>();
        let policy = MultiSigPolicy::create_threshold(3, signers.clone());
        
        let mut file = AionFile::create_with_policy(policy)?;
        
        // Propose version
        let proposal_id = file.propose_version(
            b"updated rules".to_vec(),
            signers[0],
            policy.clone(),
        )?;
        
        // Add signatures until threshold is met
        file.add_signature(proposal_id, signers[1])?; // 2/3
        let result = file.add_signature(proposal_id, signers[2])?; // 3/3 - should commit
        
        match result {
            SignatureResult::VersionCommitted { version } => {
                assert_eq!(version.0, 2); // Second version after genesis
            }
            _ => panic!("Expected version to be committed"),
        }
        
        Ok(())
    }
    
    #[test]
    fn test_boolean_expression_policy() -> Result<()> {
        // (Technical Lead AND Business Owner) OR Security Officer
        let tech_lead = AuthorId(2001);
        let business_owner = AuthorId(2002);  
        let security_officer = AuthorId(3001);
        
        let policy = MultiSigPolicy {
            requirements: SignatureRequirement::Boolean(
                BooleanExpression::Or(
                    Box::new(BooleanExpression::And(
                        Box::new(BooleanExpression::Signer(tech_lead)),
                        Box::new(BooleanExpression::Signer(business_owner)),
                    )),
                    Box::new(BooleanExpression::Signer(security_officer)),
                )
            ),
            // ... other fields
        };
        
        // Test: Security officer alone should be sufficient
        let signatures = vec![create_test_signature(security_officer)];
        let result = policy.validate_signatures(&signatures)?;
        
        assert!(matches!(result, ValidationResult::Valid { .. }));
        
        // Test: Tech lead alone should be insufficient
        let signatures = vec![create_test_signature(tech_lead)];
        let result = policy.validate_signatures(&signatures)?;
        
        assert!(matches!(result, ValidationResult::Insufficient { .. }));
        
        // Test: Tech lead + Business owner should be sufficient
        let signatures = vec![
            create_test_signature(tech_lead),
            create_test_signature(business_owner),
        ];
        let result = policy.validate_signatures(&signatures)?;
        
        assert!(matches!(result, ValidationResult::Valid { .. }));
        
        Ok(())
    }
    
    #[test] 
    fn test_signature_replay_prevention() -> Result<()> {
        let policy = create_test_policy();
        let mut file = AionFile::create_with_policy(policy.clone())?;
        
        let proposal_id = file.propose_version(
            b"test data".to_vec(),
            AuthorId(1001),
            policy,
        )?;
        
        // First signature should succeed
        let result = file.add_signature(proposal_id, AuthorId(1002))?;
        assert!(matches!(result, SignatureResult::SignatureAdded { .. }));
        
        // Duplicate signature should fail
        let result = file.add_signature(proposal_id, AuthorId(1002));
        assert!(matches!(result, Err(AionError::DuplicateSignature { .. })));
        
        Ok(())
    }
}
```

## Implementation Plan

### Phase 1: Core Multi-Signature (Week 1-2)
- Implement basic threshold signature support
- Add pending version management
- Create signature collection workflow
- Basic policy validation

### Phase 2: Advanced Policies (Week 3-4)
- Boolean expression support
- Sequential signature workflows
- Policy update mechanisms
- Security validations

### Phase 3: CLI Integration (Week 5-6)
- Multi-signature CLI commands
- Interactive approval workflows
- Status reporting and monitoring
- Policy management interface

### Phase 4: Performance & Security (Week 7-8)
- Batch signature verification
- Security hardening
- Performance optimization
- Comprehensive testing

## References

- [Multi-Signature Schemes in Cryptography](https://eprint.iacr.org/2018/483.pdf)
- [Threshold Signatures: Definitions and Applications](https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF)  
- [Bitcoin Multi-Signature Implementation](https://github.com/bitcoin/bips/blob/master/bip-0011.mediawiki)
- [Ethereum Multi-Signature Wallets](https://docs.gnosis.io/safe/)
- [NIST Guidelines for Multi-Party Authentication](https://csrc.nist.gov/publications/detail/sp/800-63b/final)

## Appendix

### Policy Examples

#### Financial Services (SOX Compliance)
```json
{
  "policy_id": "sox-trading-changes",
  "name": "SOX Trading System Changes",
  "requirements": {
    "Boolean": {
      "And": [
        {"Signer": 2001}, // Technical Lead
        {"Signer": 3001}  // Compliance Officer
      ]
    }
  },
  "authorized_signers": [2001, 2002