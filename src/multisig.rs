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
#[allow(deprecated)] // RFC-0034 Phase D: verify_multisig wraps raw-key verify_attestation
use crate::signature_chain::{verify_attestation, verify_attestation_with_registry};
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
///
/// # Migration (RFC-0034)
///
/// Prefer [`verify_multisig_with_registry`] when you maintain a
/// pinned [`crate::key_registry::KeyRegistry`]. The registry-aware
/// path rejects signers whose pinned active epoch does not match
/// the signature's embedded `public_key`, closing the
/// substitution gap in the raw-key path.
#[deprecated(
    since = "0.2.0",
    note = "use verify_multisig_with_registry; RFC-0034 — raw-key verify trusts the caller's out-of-band pinning"
)]
#[allow(deprecated)] // wraps raw-key verify_attestation internally
pub fn verify_multisig(
    version: &VersionEntry,
    signatures: &[SignatureEntry],
    policy: &MultiSigPolicy,
) -> Result<MultiSigVerification> {
    let mut valid_signers = Vec::new();
    let mut invalid_signers = Vec::new();
    let mut seen: std::collections::HashSet<AuthorId> = std::collections::HashSet::new();

    // Per RFC-0021: verify each attestation; a signer may contribute at most
    // once toward the threshold. Duplicates from the same signer are skipped
    // (they neither help the threshold nor count as invalid).
    for sig in signatures {
        let author = AuthorId::new(sig.author_id);

        if !policy.is_authorized(author) {
            continue;
        }
        if !seen.insert(author) {
            continue;
        }
        match verify_attestation(version, sig) {
            Ok(()) => valid_signers.push(author),
            Err(_) => invalid_signers.push(author),
        }
    }

    let missing_signers: Vec<_> = policy
        .authorized_signers
        .iter()
        .filter(|a| !seen.contains(a))
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

/// Registry-aware multi-signature verification — RFC-0034 Phase C.
///
/// Like [`verify_multisig`], but each per-signer attestation is
/// checked against `registry` at `version.version_number` via
/// [`verify_attestation_with_registry`]. A signer whose pinned
/// active epoch does not match the signature's embedded
/// `public_key` is classified as `invalid_signers`, not
/// `valid_signers`, regardless of whether the raw Ed25519 bytes
/// would verify on their own.
///
/// # Errors
///
/// Same shape as [`verify_multisig`]; returns `Ok(_)` in the
/// happy path and in every "signer rejected" path. Returns `Err`
/// only for structural issues with the `version`/`signatures`
/// slices themselves.
pub fn verify_multisig_with_registry(
    version: &VersionEntry,
    signatures: &[SignatureEntry],
    policy: &MultiSigPolicy,
    registry: &crate::key_registry::KeyRegistry,
) -> Result<MultiSigVerification> {
    let mut valid_signers = Vec::new();
    let mut invalid_signers = Vec::new();
    let mut seen: std::collections::HashSet<AuthorId> = std::collections::HashSet::new();

    for sig in signatures {
        let author = AuthorId::new(sig.author_id);
        if !policy.is_authorized(author) {
            continue;
        }
        if !seen.insert(author) {
            continue;
        }
        match verify_attestation_with_registry(version, sig, registry) {
            Ok(()) => valid_signers.push(author),
            Err(_) => invalid_signers.push(author),
        }
    }

    let missing_signers: Vec<_> = policy
        .authorized_signers
        .iter()
        .filter(|a| !seen.contains(a))
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
    pub const fn new() -> Self {
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
#[allow(deprecated)] // RFC-0034 Phase D: tests exercise the deprecated raw-key verify_multisig contract
mod tests {
    use super::*;

    #[test]
    fn test_policy_creation() {
        let signers = vec![AuthorId::new(1), AuthorId::new(2), AuthorId::new(3)];
        let policy = MultiSigPolicy::new(2, signers).unwrap_or_else(|_| std::process::abort());

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

    mod properties {
        use super::*;
        use crate::crypto::SigningKey;
        use crate::serializer::VersionEntry;
        use crate::signature_chain::sign_attestation;
        use crate::types::VersionNumber;
        use hegel::generators as gs;

        fn make_version(author: AuthorId) -> VersionEntry {
            VersionEntry::new(
                VersionNumber::GENESIS,
                [0u8; 32],
                [0xAA; 32],
                author,
                1_700_000_000_000_000_000,
                0,
                0,
            )
        }

        /// Build `n` distinct signer identities with fresh keys, none of whom
        /// collide with `exclude` (the version author). Keeps ids monotonic so
        /// we can reason about them in the tests below.
        fn distinct_signers(n: u32, exclude: AuthorId) -> Vec<(AuthorId, SigningKey)> {
            let mut out = Vec::with_capacity(n as usize);
            let mut next_id: u64 = 10_000;
            while (out.len() as u32) < n {
                if next_id != exclude.as_u64() {
                    out.push((AuthorId::new(next_id), SigningKey::generate()));
                }
                next_id = next_id.saturating_add(1);
            }
            out
        }

        #[hegel::test]
        fn prop_multisig_k_distinct_signers_accepts(tc: hegel::TestCase) {
            let n = tc.draw(gs::integers::<u32>().min_value(1).max_value(8));
            let threshold = tc.draw(gs::integers::<u32>().min_value(1).max_value(n));
            let version_author =
                AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1).max_value(u64::MAX)));
            let version = make_version(version_author);
            let signers = distinct_signers(n, version_author);
            let authorized: Vec<AuthorId> = signers.iter().map(|(a, _)| *a).collect();
            let policy = MultiSigPolicy::new(threshold, authorized)
                .unwrap_or_else(|_| std::process::abort());
            let attestations: Vec<SignatureEntry> = signers
                .iter()
                .take(threshold as usize)
                .map(|(who, key)| sign_attestation(&version, *who, key))
                .collect();
            let result = verify_multisig(&version, &attestations, &policy)
                .unwrap_or_else(|_| std::process::abort());
            assert!(result.threshold_met);
            assert_eq!(result.valid_count, threshold);
        }

        #[hegel::test]
        fn prop_multisig_kminus1_distinct_rejects(tc: hegel::TestCase) {
            let n = tc.draw(gs::integers::<u32>().min_value(2).max_value(8));
            let threshold = tc.draw(gs::integers::<u32>().min_value(2).max_value(n));
            let version_author =
                AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1).max_value(u64::MAX)));
            let version = make_version(version_author);
            let signers = distinct_signers(n, version_author);
            let authorized: Vec<AuthorId> = signers.iter().map(|(a, _)| *a).collect();
            let policy = MultiSigPolicy::new(threshold, authorized)
                .unwrap_or_else(|_| std::process::abort());
            let short = threshold.saturating_sub(1) as usize;
            let attestations: Vec<SignatureEntry> = signers
                .iter()
                .take(short)
                .map(|(who, key)| sign_attestation(&version, *who, key))
                .collect();
            let result = verify_multisig(&version, &attestations, &policy)
                .unwrap_or_else(|_| std::process::abort());
            assert!(!result.threshold_met);
        }

        #[hegel::test]
        fn prop_multisig_duplicate_attestations_count_once(tc: hegel::TestCase) {
            let n = tc.draw(gs::integers::<u32>().min_value(2).max_value(8));
            let threshold = tc.draw(gs::integers::<u32>().min_value(2).max_value(n));
            let dups = tc.draw(gs::integers::<u32>().min_value(2).max_value(8));
            let version_author =
                AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1).max_value(u64::MAX)));
            let version = make_version(version_author);
            let signers = distinct_signers(n, version_author);
            let authorized: Vec<AuthorId> = signers.iter().map(|(a, _)| *a).collect();
            let policy = MultiSigPolicy::new(threshold, authorized)
                .unwrap_or_else(|_| std::process::abort());
            // All signatures come from the same signer, repeated `dups` times.
            let first = signers.first().unwrap_or_else(|| std::process::abort());
            let att = sign_attestation(&version, first.0, &first.1);
            let attestations: Vec<SignatureEntry> = (0..dups).map(|_| att).collect();
            let result = verify_multisig(&version, &attestations, &policy)
                .unwrap_or_else(|_| std::process::abort());
            assert_eq!(result.valid_count, 1);
            assert!(!result.threshold_met);
        }

        #[hegel::test]
        fn prop_unauthorized_signers_do_not_count(tc: hegel::TestCase) {
            let author_id = tc.draw(gs::integers::<u64>().min_value(1).max_value(u64::MAX / 2));
            let author = AuthorId::new(author_id);
            let version = make_version(author);
            let impostor = AuthorId::new(author_id.wrapping_add(1).max(2));
            let key = SigningKey::generate();
            let sig = sign_attestation(&version, impostor, &key);
            let policy =
                MultiSigPolicy::new(1, vec![author]).unwrap_or_else(|_| std::process::abort());
            let result = verify_multisig(&version, &[sig], &policy)
                .unwrap_or_else(|_| std::process::abort());
            assert_eq!(result.valid_count, 0);
            assert!(!result.threshold_met);
        }

        #[hegel::test]
        fn prop_forged_author_id_rejects(tc: hegel::TestCase) {
            let version_author =
                AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1).max_value(u64::MAX / 2)));
            let version = make_version(version_author);
            let real_signer = AuthorId::new(version_author.as_u64().saturating_add(1));
            let fake_signer = AuthorId::new(real_signer.as_u64().saturating_add(1));
            let key = SigningKey::generate();
            let mut sig = sign_attestation(&version, real_signer, &key);
            sig.author_id = fake_signer.as_u64();
            let policy =
                MultiSigPolicy::new(1, vec![fake_signer]).unwrap_or_else(|_| std::process::abort());
            let result = verify_multisig(&version, &[sig], &policy)
                .unwrap_or_else(|_| std::process::abort());
            assert_eq!(result.valid_count, 0);
            assert!(!result.threshold_met);
        }
    }
}
