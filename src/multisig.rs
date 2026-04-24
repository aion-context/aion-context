//! Multi-Signature Support Module
//!
//! Provides M-of-N threshold signature verification for scenarios
//! requiring multiple signers to approve a version.
//!
//! # Use Cases
//!
//! - **Dual Control**: 2-of-2 for financial rules requiring two approvers
//! - **Committee Approval**: 3-of-5 for board-level policy changes
//! - **Backup Recovery**: 2-of-3 for key recovery scenarios

use crate::serializer::{SignatureEntry, VersionEntry};
use crate::signature_chain::verify_signature;
use crate::types::AuthorId;
use crate::{AionError, Result};

/// Multi-signature policy defining required signers
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MultiSigPolicy {
    /// Minimum required signatures (M in M-of-N)
    pub threshold: u32,
    /// Total authorized signers (N in M-of-N)
    pub total_signers: u32,
    /// List of authorized signer IDs
    pub authorized_signers: Vec<AuthorId>,
}

impl MultiSigPolicy {
    /// Create a new multi-signature policy
    ///
    /// # Arguments
    ///
    /// * `threshold` - Minimum signatures required (M)
    /// * `authorized_signers` - List of authorized signer IDs
    ///
    /// # Errors
    ///
    /// Returns error if threshold > number of signers or threshold is 0
    ///
    /// # Example
    ///
    /// ```
    /// use aion_context::multisig::MultiSigPolicy;
    /// use aion_context::types::AuthorId;
    ///
    /// // 2-of-3 policy
    /// let signers = vec![
    ///     AuthorId::new(1001),
    ///     AuthorId::new(1002),
    ///     AuthorId::new(1003),
    /// ];
    /// let policy = MultiSigPolicy::new(2, signers).unwrap();
    /// assert_eq!(policy.threshold, 2);
    /// assert_eq!(policy.total_signers, 3);
    /// ```
    pub fn new(threshold: u32, authorized_signers: Vec<AuthorId>) -> Result<Self> {
        if threshold == 0 {
            return Err(AionError::InvalidFormat {
                reason: "Threshold must be at least 1".to_string(),
            });
        }

        let total = authorized_signers.len() as u32;
        if threshold > total {
            return Err(AionError::InvalidFormat {
                reason: format!(
                    "Threshold ({threshold}) cannot exceed number of signers ({total})"
                ),
            });
        }

        Ok(Self {
            threshold,
            total_signers: total,
            authorized_signers,
        })
    }

    /// Create a 1-of-1 single signer policy
    #[must_use]
    pub fn single_signer(signer: AuthorId) -> Self {
        Self {
            threshold: 1,
            total_signers: 1,
            authorized_signers: vec![signer],
        }
    }

    /// Create an M-of-N policy
    pub fn m_of_n(m: u32, signers: Vec<AuthorId>) -> Result<Self> {
        Self::new(m, signers)
    }

    /// Check if an author is an authorized signer
    #[must_use]
    pub fn is_authorized(&self, author: AuthorId) -> bool {
        self.authorized_signers.contains(&author)
    }

    /// Get the M-of-N description
    #[must_use]
    pub fn description(&self) -> String {
        format!("{}-of-{}", self.threshold, self.total_signers)
    }
}

/// Result of multi-signature verification
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MultiSigVerification {
    /// Whether the threshold was met
    pub threshold_met: bool,
    /// Number of valid signatures
    pub valid_count: u32,
    /// Required threshold
    pub required: u32,
    /// List of signers who provided valid signatures
    pub valid_signers: Vec<AuthorId>,
    /// List of signers who provided invalid signatures
    pub invalid_signers: Vec<AuthorId>,
    /// List of authorized signers who did not sign
    pub missing_signers: Vec<AuthorId>,
}

impl MultiSigVerification {
    /// Check if verification passed
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.threshold_met && self.invalid_signers.is_empty()
    }
}

/// Verify multiple signatures against a policy
///
/// # Arguments
///
/// * `version` - The version entry being verified
/// * `signatures` - All signatures for this version
/// * `policy` - The multi-signature policy to enforce
///
/// # Returns
///
/// Detailed verification result including which signers validated
///
/// # Example
///
/// ```ignore
/// let result = verify_multisig(&version, &signatures, &policy)?;
/// if result.threshold_met {
///     println!("Approved by {} signers", result.valid_count);
/// }
/// ```
pub fn verify_multisig(
    version: &VersionEntry,
    signatures: &[SignatureEntry],
    policy: &MultiSigPolicy,
) -> Result<MultiSigVerification> {
    let mut valid_signers = Vec::new();
    let mut invalid_signers = Vec::new();

    // Check each signature
    for sig in signatures {
        let author = AuthorId::new(sig.author_id);

        // Only consider signatures from authorized signers
        if !policy.is_authorized(author) {
            continue;
        }

        // Verify the signature
        match verify_signature(version, sig) {
            Ok(()) => valid_signers.push(author),
            Err(_) => invalid_signers.push(author),
        }
    }

    // Find missing signers (authorized but didn't sign)
    let signed_ids: std::collections::HashSet<_> = signatures
        .iter()
        .map(|s| AuthorId::new(s.author_id))
        .collect();

    let missing_signers: Vec<_> = policy
        .authorized_signers
        .iter()
        .filter(|a| !signed_ids.contains(a))
        .copied()
        .collect();

    let valid_count = valid_signers.len() as u32;
    let threshold_met = valid_count >= policy.threshold;

    Ok(MultiSigVerification {
        threshold_met,
        valid_count,
        required: policy.threshold,
        valid_signers,
        invalid_signers,
        missing_signers,
    })
}

/// Aggregate multiple signatures for a version
///
/// This collects signatures from multiple signers into a single
/// list that can be stored with the version.
#[derive(Debug, Clone)]
pub struct SignatureAggregator {
    signatures: Vec<SignatureEntry>,
}

impl SignatureAggregator {
    /// Create a new aggregator
    #[must_use]
    pub fn new() -> Self {
        Self {
            signatures: Vec::new(),
        }
    }

    /// Add a signature to the aggregation
    pub fn add_signature(&mut self, signature: SignatureEntry) {
        self.signatures.push(signature);
    }

    /// Get the number of signatures collected
    #[must_use]
    pub fn count(&self) -> usize {
        self.signatures.len()
    }

    /// Get the collected signatures
    #[must_use]
    pub fn signatures(&self) -> &[SignatureEntry] {
        &self.signatures
    }

    /// Consume and return the signatures
    #[must_use]
    pub fn into_signatures(self) -> Vec<SignatureEntry> {
        self.signatures
    }
}

impl Default for SignatureAggregator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_creation() {
        let signers = vec![AuthorId::new(1), AuthorId::new(2), AuthorId::new(3)];
        let policy = MultiSigPolicy::new(2, signers).unwrap();

        assert_eq!(policy.threshold, 2);
        assert_eq!(policy.total_signers, 3);
        assert_eq!(policy.description(), "2-of-3");
    }

    #[test]
    fn test_policy_invalid_threshold() {
        let signers = vec![AuthorId::new(1), AuthorId::new(2)];

        // Threshold too high
        let result = MultiSigPolicy::new(3, signers.clone());
        assert!(result.is_err());

        // Zero threshold
        let result = MultiSigPolicy::new(0, signers);
        assert!(result.is_err());
    }

    #[test]
    fn test_single_signer_policy() {
        let policy = MultiSigPolicy::single_signer(AuthorId::new(42));

        assert_eq!(policy.threshold, 1);
        assert_eq!(policy.total_signers, 1);
        assert!(policy.is_authorized(AuthorId::new(42)));
        assert!(!policy.is_authorized(AuthorId::new(99)));
    }

    #[test]
    fn test_signature_aggregator() {
        let mut agg = SignatureAggregator::new();
        assert_eq!(agg.count(), 0);

        let sig = SignatureEntry {
            author_id: 100,
            public_key: [0u8; 32],
            signature: [0u8; 64],
            reserved: [0u8; 8],
        };

        agg.add_signature(sig);
        assert_eq!(agg.count(), 1);
    }
}
