//! Aion-native transparency log — RFC-0025.
//!
//! Append-only Merkle log over BLAKE3, RFC-6962-compatible in
//! structure (split-point MTH, audit-path inclusion proofs) and
//! domain-separated from every other aion signed object.
//!
//! Phase A, this module: in-memory log + inclusion proofs +
//! operator-signed tree heads, all offline. Phase B adds frontier
//! caching, consistency proofs, and persistence. Phase C adds a
//! Rekor adapter for wire interop.
//!
//! # Example
//!
//! ```
//! use aion_context::transparency_log::{TransparencyLog, LogEntryKind, verify_inclusion_proof};
//! use aion_context::crypto::SigningKey;
//!
//! let mut log = TransparencyLog::new();
//! let payload = b"attestation bytes";
//! let seq = log.append(LogEntryKind::VersionAttestation, payload, 42).unwrap();
//!
//! // Self-contained verification: a verifier holding the log and a
//! // pinned root needs no access to the original payload.
//! let proof = log.inclusion_proof(seq).unwrap();
//! let leaf = log.leaf_hash_at(seq).unwrap();
//! verify_inclusion_proof(
//!     leaf,
//!     proof.leaf_index,
//!     proof.tree_size,
//!     &proof.audit_path,
//!     log.root_hash(),
//! ).unwrap();
//!
//! let operator = SigningKey::generate();
//! log.set_operator(operator.verifying_key());
//! let sth = log.sign_tree_head(&operator);
//! assert!(log.verify_tree_head(&sth).is_ok());
//! ```

use crate::crypto::{SigningKey, VerifyingKey};
use crate::{AionError, Result};

/// Domain separator for leaf-data hashing.
pub const LOG_LEAF_DOMAIN: &[u8] = b"AION_V2_LOG_LEAF_V1\0";

/// Domain separator for internal-node hashing.
pub const LOG_NODE_DOMAIN: &[u8] = b"AION_V2_LOG_NODE_V1\0";

/// Domain separator for signed tree heads.
pub const LOG_STH_DOMAIN: &[u8] = b"AION_V2_LOG_STH_V1\0";

/// Domain separator for the empty-tree sentinel root.
pub const LOG_EMPTY_DOMAIN: &[u8] = b"AION_V2_LOG_EMPTY_V1\0";

/// What kind of object is recorded in a log leaf.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogEntryKind {
    /// Multi-party attestation over a version (RFC-0021).
    VersionAttestation = 1,
    /// Signature over an external-artifact manifest (RFC-0022).
    ManifestSignature = 2,
    /// Key rotation record (RFC-0028).
    KeyRotation = 3,
    /// Key revocation record (RFC-0028).
    KeyRevocation = 4,
    /// SLSA v1.1 provenance statement (RFC-0024).
    SlsaStatement = 5,
    /// Generic DSSE envelope (RFC-0023).
    DsseEnvelope = 6,
}

impl LogEntryKind {
    /// Convert a raw `u16` to a known kind.
    ///
    /// # Errors
    ///
    /// Returns `Err` for discriminants not defined by this enum.
    pub fn from_u16(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::VersionAttestation),
            2 => Ok(Self::ManifestSignature),
            3 => Ok(Self::KeyRotation),
            4 => Ok(Self::KeyRevocation),
            5 => Ok(Self::SlsaStatement),
            6 => Ok(Self::DsseEnvelope),
            other => Err(AionError::InvalidFormat {
                reason: format!("Unknown log entry kind: {other}"),
            }),
        }
    }
}

/// One leaf in the transparency log.
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// Which kind of object this leaf carries.
    pub kind: LogEntryKind,
    /// 0-indexed position in the log.
    pub seq: u64,
    /// aion version number at submission time.
    pub timestamp_version: u64,
    /// BLAKE3 hash of the preceding leaf (`[0u8; 32]` for `seq == 0`).
    pub prev_leaf_hash: [u8; 32],
    /// BLAKE3 hash of the raw payload bytes.
    pub payload_hash: [u8; 32],
}

/// An inclusion proof: the siblings along the path from a leaf to
/// the Merkle root, innermost first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// Leaf index the proof refers to.
    pub leaf_index: u64,
    /// Tree size at the time the proof was generated.
    pub tree_size: u64,
    /// Merkle audit path (siblings, innermost first).
    pub audit_path: Vec<[u8; 32]>,
}

/// A tree head signed by the log operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTreeHead {
    /// Number of leaves in the tree at signing time.
    pub tree_size: u64,
    /// Merkle root hash at that tree size.
    pub root_hash: [u8; 32],
    /// Ed25519 signature by the operator master key over the
    /// canonical STH bytes.
    pub operator_signature: [u8; 64],
}

/// Append-only Merkle log.
///
/// Maintains an internal subtree-roots cache keyed by `(level,
/// index)` so [`Self::inclusion_proof`] runs in O(log n) instead of
/// O(n) (issue #36). The cache is in-memory only — no on-disk
/// format change.
///
/// `subtree_roots[level][j]` is the hash of the COMPLETE 2^level
/// subtree covering leaves `[j*2^level, (j+1)*2^level)`. Only
/// fully-populated subtrees are stored; partial right-edge subtrees
/// are recomputed on demand from the cached children (still
/// O(log n) total).
#[derive(Debug, Default)]
pub struct TransparencyLog {
    entries: Vec<LogEntry>,
    leaf_hashes: Vec<[u8; 32]>,
    /// `subtree_roots[level][j]` covers leaves `[j*2^level, (j+1)*2^level)`.
    /// `subtree_roots[0]` mirrors `leaf_hashes`.
    subtree_roots: Vec<Vec<[u8; 32]>>,
    operator_master: Option<VerifyingKey>,
}

/// Compute the canonical leaf-data bytes and return their
/// domain-tagged BLAKE3 hash.
#[must_use]
pub fn leaf_hash(
    kind: LogEntryKind,
    seq: u64,
    timestamp_version: u64,
    prev_leaf_hash: &[u8; 32],
    payload: &[u8],
) -> [u8; 32] {
    let payload_digest = crate::crypto::hash(payload);
    let canonical = canonical_leaf_bytes(
        kind,
        seq,
        timestamp_version,
        prev_leaf_hash,
        &payload_digest,
    );
    let mut hasher = blake3::Hasher::new();
    hasher.update(LOG_LEAF_DOMAIN);
    hasher.update(&canonical);
    *hasher.finalize().as_bytes()
}

fn canonical_leaf_bytes(
    kind: LogEntryKind,
    seq: u64,
    timestamp_version: u64,
    prev_leaf_hash: &[u8; 32],
    payload_hash: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2 + 8 + 8 + 32 + 32);
    buf.extend_from_slice(&(kind as u16).to_le_bytes());
    buf.extend_from_slice(&seq.to_le_bytes());
    buf.extend_from_slice(&timestamp_version.to_le_bytes());
    buf.extend_from_slice(prev_leaf_hash);
    buf.extend_from_slice(payload_hash);
    buf
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LOG_NODE_DOMAIN);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

fn empty_root() -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LOG_EMPTY_DOMAIN);
    *hasher.finalize().as_bytes()
}

/// Largest power of two strictly less than `n` (RFC 6962 split
/// point). Panics would be on `n < 2`; guarded by caller.
const fn split_point(n: usize) -> usize {
    let mut k = 1usize;
    while k.saturating_mul(2) < n {
        k = k.saturating_mul(2);
    }
    k
}

/// Recompute a Merkle root from a leaf + audit path, mirroring the
/// construction used by [`audit_path`]. Returns `Err` if the path
/// is the wrong length for `(leaf_index, tree_size)`.
fn compute_root_from_proof(
    leaf: [u8; 32],
    leaf_index: usize,
    tree_size: usize,
    proof: &[[u8; 32]],
) -> Result<[u8; 32]> {
    if tree_size == 0 {
        return Err(AionError::InvalidFormat {
            reason: "tree_size == 0 in inclusion proof".to_string(),
        });
    }
    if leaf_index >= tree_size {
        return Err(AionError::InvalidFormat {
            reason: "leaf_index >= tree_size".to_string(),
        });
    }
    if tree_size == 1 {
        if !proof.is_empty() {
            return Err(AionError::InvalidFormat {
                reason: "proof is longer than expected for tree_size=1".to_string(),
            });
        }
        return Ok(leaf);
    }
    let k = split_point(tree_size);
    if proof.is_empty() {
        return Err(AionError::InvalidFormat {
            reason: "proof is shorter than expected".to_string(),
        });
    }
    let outer_sibling_index = proof.len().saturating_sub(1);
    let outer_sibling =
        *proof
            .get(outer_sibling_index)
            .ok_or_else(|| AionError::InvalidFormat {
                reason: "proof index underflow".to_string(),
            })?;
    let inner_proof = proof.get(..outer_sibling_index).unwrap_or(&[]);
    if leaf_index < k {
        let left = compute_root_from_proof(leaf, leaf_index, k, inner_proof)?;
        Ok(node_hash(&left, &outer_sibling))
    } else {
        let right_index = leaf_index.saturating_sub(k);
        let right_size = tree_size.saturating_sub(k);
        let right = compute_root_from_proof(leaf, right_index, right_size, inner_proof)?;
        Ok(node_hash(&outer_sibling, &right))
    }
}

/// Verify an inclusion proof: given a leaf hash, the leaf's index,
/// the tree size at proof-generation time, the audit path, and the
/// pinned root hash, check that the leaf is in the tree.
///
/// # Errors
///
/// Returns `Err` if the proof is malformed or the recomputed root
/// differs from `expected_root`.
pub fn verify_inclusion_proof(
    leaf_hash: [u8; 32],
    leaf_index: u64,
    tree_size: u64,
    proof: &[[u8; 32]],
    expected_root: [u8; 32],
) -> Result<()> {
    let leaf_index_usize = usize::try_from(leaf_index).map_err(|_| AionError::InvalidFormat {
        reason: "leaf_index exceeds usize".to_string(),
    })?;
    let tree_size_usize = usize::try_from(tree_size).map_err(|_| AionError::InvalidFormat {
        reason: "tree_size exceeds usize".to_string(),
    })?;
    let computed = compute_root_from_proof(leaf_hash, leaf_index_usize, tree_size_usize, proof)?;
    if computed != expected_root {
        return Err(AionError::InvalidFormat {
            reason: "inclusion proof does not recompute to expected root".to_string(),
        });
    }
    Ok(())
}

impl TransparencyLog {
    /// Construct an empty log with no operator master key set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register the operator master key used to verify STHs.
    pub fn set_operator(&mut self, master_key: VerifyingKey) {
        self.operator_master = Some(master_key);
    }

    /// Number of leaves currently in the log.
    #[must_use]
    pub fn tree_size(&self) -> u64 {
        self.entries.len() as u64
    }

    /// Current Merkle root hash. Returns the empty-tree sentinel
    /// when the log has no entries.
    ///
    /// Uses the subtree-roots cache (issue #36): O(log n) for any
    /// tree size, vs O(n) before the cache.
    #[must_use]
    pub fn root_hash(&self) -> [u8; 32] {
        if self.leaf_hashes.is_empty() {
            return empty_root();
        }
        self.cached_subtree_root(0, self.leaf_hashes.len())
    }

    /// Look up the entry at `index`, if any.
    #[must_use]
    pub fn entry(&self, index: u64) -> Option<&LogEntry> {
        let idx = usize::try_from(index).ok()?;
        self.entries.get(idx)
    }

    /// All entries in log order.
    #[must_use]
    pub fn entries(&self) -> &[LogEntry] {
        &self.entries
    }

    /// Return the stored leaf hash for the entry at `index`, if any.
    ///
    /// Pairs with [`Self::inclusion_proof`] and
    /// [`verify_inclusion_proof`]: a verifier holding only the log
    /// and a pinned root hash can verify any entry's inclusion
    /// without needing the original payload bytes.
    ///
    /// Returns `None` when `index >= tree_size()` or when `index`
    /// does not fit in `usize`.
    #[must_use]
    pub fn leaf_hash_at(&self, index: u64) -> Option<[u8; 32]> {
        let idx = usize::try_from(index).ok()?;
        self.leaf_hashes.get(idx).copied()
    }

    /// Append a new leaf and return its sequence number.
    ///
    /// # Errors
    ///
    /// Returns `Err` on arithmetic overflow of the sequence counter
    /// (unreachable in practice below 2^64 entries).
    pub fn append(
        &mut self,
        kind: LogEntryKind,
        payload: &[u8],
        timestamp_version: u64,
    ) -> Result<u64> {
        let seq = self.entries.len() as u64;
        let prev_leaf_hash = self.leaf_hashes.last().copied().unwrap_or([0u8; 32]);
        let hash = leaf_hash(kind, seq, timestamp_version, &prev_leaf_hash, payload);
        let payload_digest = crate::crypto::hash(payload);
        let entry = LogEntry {
            kind,
            seq,
            timestamp_version,
            prev_leaf_hash,
            payload_hash: payload_digest,
        };
        self.entries.push(entry);
        self.leaf_hashes.push(hash);
        self.cascade_subtree_roots(hash);
        Ok(seq)
    }

    /// Issue #36 — incremental cache update.
    ///
    /// After pushing a new leaf hash, walk up the tree completing
    /// every newly-finished `2^k` subtree. A subtree at level `k`
    /// completes whenever `leaf_hashes.len()` becomes a multiple of
    /// `2^k`. At each level, the new subtree root is
    /// `node_hash(left_sibling, right_just_completed)` where the
    /// right side is the entry we just pushed at level `k-1` and
    /// the left sibling is the previous entry at the same level.
    ///
    /// Total work per append: O(log n) amortized — each leaf rises
    /// at most log2(n) levels over the life of the log.
    #[allow(clippy::arithmetic_side_effects)] // bounded by log2(usize::MAX) iterations
    #[allow(clippy::indexing_slicing)] // indices are bounded by lower_len above
    fn cascade_subtree_roots(&mut self, leaf: [u8; 32]) {
        if self.subtree_roots.is_empty() {
            self.subtree_roots.push(Vec::new());
        }
        self.subtree_roots[0].push(leaf);

        let mut level: usize = 0;
        loop {
            let lower_len = self.subtree_roots[level].len();
            // A pair just completed at `level` iff the lower vec's
            // length is even — the rightmost two entries combine
            // into a new entry one level up.
            if lower_len % 2 != 0 {
                break;
            }
            let right_idx = lower_len - 1;
            let left_idx = lower_len - 2;
            let combined = node_hash(
                &self.subtree_roots[level][left_idx],
                &self.subtree_roots[level][right_idx],
            );
            level += 1;
            if self.subtree_roots.len() <= level {
                self.subtree_roots.push(Vec::new());
            }
            self.subtree_roots[level].push(combined);
        }
    }

    /// Compute the Merkle Tree Hash of `leaves[start..start+len]`
    /// using the subtree cache where possible.
    ///
    /// Falls back to recursive combination of cached sub-peaks for
    /// partial right-edge subtrees. Pure (does not mutate the
    /// cache).
    #[allow(clippy::arithmetic_side_effects)] // bounded by tree depth
    #[allow(clippy::indexing_slicing)] // start < leaf_hashes.len() by debug_assert
    fn cached_subtree_root(&self, start: usize, len: usize) -> [u8; 32] {
        debug_assert!(start + len <= self.leaf_hashes.len());
        if len == 0 {
            return empty_root();
        }
        if len == 1 {
            return self.leaf_hashes[start];
        }
        // If (start, len) is a complete cached subtree, return the
        // cached hash directly.
        if len.is_power_of_two() && start % len == 0 {
            let level = len.trailing_zeros() as usize;
            let j = start / len;
            if let Some(level_vec) = self.subtree_roots.get(level) {
                if let Some(h) = level_vec.get(j) {
                    return *h;
                }
            }
        }
        // Fall back to RFC 6962 recursive split. The cached path
        // gets short-circuited at the first complete sub-peak; the
        // remainder (right-edge partial) recurses but each step
        // halves at most O(log n) times.
        let k = split_point(len);
        let left = self.cached_subtree_root(start, k);
        let right = self.cached_subtree_root(start + k, len - k);
        node_hash(&left, &right)
    }

    /// Cache-aware audit-path construction. RFC 6962 split-and-recurse,
    /// but every sibling subtree is resolved via [`Self::cached_subtree_root`].
    #[allow(clippy::arithmetic_side_effects)] // bounded by tree depth
    fn cached_audit_path(&self, m: usize, range_start: usize, range_len: usize) -> Vec<[u8; 32]> {
        if range_len <= 1 {
            return Vec::new();
        }
        let k = split_point(range_len);
        if m < range_start + k {
            let mut path = self.cached_audit_path(m, range_start, k);
            let sib = self.cached_subtree_root(range_start + k, range_len - k);
            path.push(sib);
            path
        } else {
            let mut path = self.cached_audit_path(m, range_start + k, range_len - k);
            let sib = self.cached_subtree_root(range_start, k);
            path.push(sib);
            path
        }
    }

    /// Generate an inclusion proof for the leaf at `leaf_index`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `leaf_index >= tree_size`.
    pub fn inclusion_proof(&self, leaf_index: u64) -> Result<InclusionProof> {
        let idx = usize::try_from(leaf_index).map_err(|_| AionError::InvalidFormat {
            reason: "leaf_index exceeds usize".to_string(),
        })?;
        if idx >= self.leaf_hashes.len() {
            return Err(AionError::InvalidFormat {
                reason: format!(
                    "leaf_index {idx} out of range (tree_size {})",
                    self.leaf_hashes.len()
                ),
            });
        }
        let path = self.cached_audit_path(idx, 0, self.leaf_hashes.len());
        Ok(InclusionProof {
            leaf_index,
            tree_size: self.tree_size(),
            audit_path: path,
        })
    }

    /// Canonical bytes of the current tree head, used as the
    /// message the operator signs.
    #[must_use]
    pub fn canonical_tree_head(&self) -> Vec<u8> {
        canonical_sth_bytes(self.tree_size(), &self.root_hash())
    }

    /// Produce a [`SignedTreeHead`] for the current state.
    #[must_use]
    pub fn sign_tree_head(&self, operator_key: &SigningKey) -> SignedTreeHead {
        let tree_size = self.tree_size();
        let root_hash = self.root_hash();
        let message = canonical_sth_bytes(tree_size, &root_hash);
        let operator_signature = operator_key.sign(&message);
        SignedTreeHead {
            tree_size,
            root_hash,
            operator_signature,
        }
    }

    /// Verify a [`SignedTreeHead`] against the registered operator
    /// master key **and** against the log's current root.
    ///
    /// # Errors
    ///
    /// Returns `Err` if no operator is registered, if the signature
    /// does not verify, or if the STH's `root_hash` does not match
    /// the log's current root.
    pub fn verify_tree_head(&self, sth: &SignedTreeHead) -> Result<()> {
        let master = self
            .operator_master
            .as_ref()
            .ok_or_else(|| AionError::InvalidFormat {
                reason: "no operator master key registered".to_string(),
            })?;
        let message = canonical_sth_bytes(sth.tree_size, &sth.root_hash);
        master.verify(&message, &sth.operator_signature)?;
        if sth.tree_size != self.tree_size() || sth.root_hash != self.root_hash() {
            return Err(AionError::InvalidFormat {
                reason: "STH does not match current log state".to_string(),
            });
        }
        Ok(())
    }
}

fn canonical_sth_bytes(tree_size: u64, root_hash: &[u8; 32]) -> Vec<u8> {
    let capacity = LOG_STH_DOMAIN.len().saturating_add(8).saturating_add(32);
    let mut buf = Vec::with_capacity(capacity);
    buf.extend_from_slice(LOG_STH_DOMAIN);
    buf.extend_from_slice(&tree_size.to_le_bytes());
    buf.extend_from_slice(root_hash);
    buf
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    #[test]
    fn empty_log_has_empty_root_sentinel() {
        let log = TransparencyLog::new();
        assert_eq!(log.tree_size(), 0);
        assert_eq!(log.root_hash(), empty_root());
    }

    #[test]
    fn append_increments_tree_size() {
        let mut log = TransparencyLog::new();
        log.append(LogEntryKind::VersionAttestation, b"a", 1)
            .unwrap();
        log.append(LogEntryKind::ManifestSignature, b"b", 2)
            .unwrap();
        log.append(LogEntryKind::KeyRotation, b"c", 3).unwrap();
        assert_eq!(log.tree_size(), 3);
        assert_eq!(log.entries().len(), 3);
    }

    #[test]
    fn leaf_chain_links_prev_hashes() {
        let mut log = TransparencyLog::new();
        log.append(LogEntryKind::VersionAttestation, b"a", 1)
            .unwrap();
        log.append(LogEntryKind::ManifestSignature, b"b", 2)
            .unwrap();
        let e0 = log.entry(0).unwrap();
        let e1 = log.entry(1).unwrap();
        let expected_prev = leaf_hash(
            e0.kind,
            e0.seq,
            e0.timestamp_version,
            &e0.prev_leaf_hash,
            b"a",
        );
        assert_eq!(e1.prev_leaf_hash, expected_prev);
        assert_eq!(e0.prev_leaf_hash, [0u8; 32]);
    }

    #[test]
    fn inclusion_proof_verifies_for_every_leaf() {
        let mut log = TransparencyLog::new();
        let payloads: Vec<&[u8]> = vec![b"one", b"two", b"three", b"four", b"five"];
        let kinds = [
            LogEntryKind::VersionAttestation,
            LogEntryKind::ManifestSignature,
            LogEntryKind::KeyRotation,
            LogEntryKind::SlsaStatement,
            LogEntryKind::DsseEnvelope,
        ];
        for (i, p) in payloads.iter().enumerate() {
            log.append(kinds[i], p, (i as u64) + 1).unwrap();
        }
        let root = log.root_hash();
        for (i, p) in payloads.iter().enumerate() {
            let entry = log.entry(i as u64).unwrap();
            let proof = log.inclusion_proof(i as u64).unwrap();
            let leaf = leaf_hash(
                kinds[i],
                entry.seq,
                entry.timestamp_version,
                &entry.prev_leaf_hash,
                p,
            );
            verify_inclusion_proof(
                leaf,
                proof.leaf_index,
                proof.tree_size,
                &proof.audit_path,
                root,
            )
            .unwrap();
        }
    }

    #[test]
    fn inclusion_proof_rejects_out_of_range_index() {
        let mut log = TransparencyLog::new();
        log.append(LogEntryKind::VersionAttestation, b"a", 1)
            .unwrap();
        assert!(log.inclusion_proof(5).is_err());
    }

    #[test]
    fn sth_round_trip_verifies() {
        let mut log = TransparencyLog::new();
        let operator = SigningKey::generate();
        log.set_operator(operator.verifying_key());
        log.append(LogEntryKind::VersionAttestation, b"x", 1)
            .unwrap();
        let sth = log.sign_tree_head(&operator);
        assert!(log.verify_tree_head(&sth).is_ok());
    }

    #[test]
    fn sth_with_tampered_root_rejects() {
        let mut log = TransparencyLog::new();
        let operator = SigningKey::generate();
        log.set_operator(operator.verifying_key());
        log.append(LogEntryKind::VersionAttestation, b"x", 1)
            .unwrap();
        let mut sth = log.sign_tree_head(&operator);
        sth.root_hash[0] ^= 0x01;
        assert!(log.verify_tree_head(&sth).is_err());
    }

    #[test]
    fn sth_without_operator_rejects() {
        let mut log = TransparencyLog::new();
        log.append(LogEntryKind::VersionAttestation, b"x", 1)
            .unwrap();
        let operator = SigningKey::generate();
        let sth = log.sign_tree_head(&operator);
        assert!(log.verify_tree_head(&sth).is_err());
    }

    #[test]
    fn kind_round_trips() {
        for kind in [
            LogEntryKind::VersionAttestation,
            LogEntryKind::ManifestSignature,
            LogEntryKind::KeyRotation,
            LogEntryKind::KeyRevocation,
            LogEntryKind::SlsaStatement,
            LogEntryKind::DsseEnvelope,
        ] {
            let raw = kind as u16;
            assert_eq!(LogEntryKind::from_u16(raw).unwrap(), kind);
        }
        assert!(LogEntryKind::from_u16(999).is_err());
    }

    mod properties {
        use super::*;
        use hegel::generators as gs;

        fn draw_payloads(tc: &hegel::TestCase) -> Vec<Vec<u8>> {
            let n = tc.draw(gs::integers::<usize>().min_value(1).max_value(16));
            let mut out: Vec<Vec<u8>> = Vec::with_capacity(n);
            for _ in 0..n {
                out.push(tc.draw(gs::binary().max_size(256)));
            }
            out
        }

        fn build_log(payloads: &[Vec<u8>]) -> TransparencyLog {
            let mut log = TransparencyLog::new();
            for (i, p) in payloads.iter().enumerate() {
                log.append(LogEntryKind::DsseEnvelope, p, (i as u64) + 1)
                    .unwrap_or_else(|_| std::process::abort());
            }
            log
        }

        #[hegel::test]
        fn prop_tree_size_matches_entries(tc: hegel::TestCase) {
            let payloads = draw_payloads(&tc);
            let log = build_log(&payloads);
            assert_eq!(log.tree_size() as usize, payloads.len());
            assert_eq!(log.entries().len(), payloads.len());
        }

        #[hegel::test]
        fn prop_inclusion_proof_roundtrip_for_any_n(tc: hegel::TestCase) {
            let payloads = draw_payloads(&tc);
            let log = build_log(&payloads);
            let root = log.root_hash();
            for (i, p) in payloads.iter().enumerate() {
                let entry = log.entry(i as u64).unwrap_or_else(|| std::process::abort());
                let proof = log
                    .inclusion_proof(i as u64)
                    .unwrap_or_else(|_| std::process::abort());
                let leaf = leaf_hash(
                    entry.kind,
                    entry.seq,
                    entry.timestamp_version,
                    &entry.prev_leaf_hash,
                    p,
                );
                verify_inclusion_proof(
                    leaf,
                    proof.leaf_index,
                    proof.tree_size,
                    &proof.audit_path,
                    root,
                )
                .unwrap_or_else(|_| std::process::abort());
            }
        }

        #[hegel::test]
        fn prop_tampered_payload_rejects(tc: hegel::TestCase) {
            let payloads = draw_payloads(&tc);
            let log = build_log(&payloads);
            let root = log.root_hash();
            let idx = tc.draw(gs::integers::<usize>().max_value(payloads.len().saturating_sub(1)));
            let entry = log
                .entry(idx as u64)
                .unwrap_or_else(|| std::process::abort());
            let original = payloads
                .get(idx)
                .unwrap_or_else(|| std::process::abort())
                .clone();
            let mut tampered = original;
            tampered.push(0xFF);
            let proof = log
                .inclusion_proof(idx as u64)
                .unwrap_or_else(|_| std::process::abort());
            let leaf = leaf_hash(
                entry.kind,
                entry.seq,
                entry.timestamp_version,
                &entry.prev_leaf_hash,
                &tampered,
            );
            assert!(verify_inclusion_proof(
                leaf,
                proof.leaf_index,
                proof.tree_size,
                &proof.audit_path,
                root
            )
            .is_err());
        }

        #[hegel::test]
        fn prop_wrong_index_rejects(tc: hegel::TestCase) {
            let n = tc.draw(gs::integers::<usize>().min_value(2).max_value(16));
            let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(n);
            for _ in 0..n {
                payloads.push(tc.draw(gs::binary().max_size(128)));
            }
            let log = build_log(&payloads);
            let root = log.root_hash();
            let real = tc.draw(gs::integers::<usize>().max_value(n - 1));
            let wrong_candidate = tc.draw(gs::integers::<usize>().max_value(n - 1));
            // Choose a different index; fall back if the draw collided.
            let wrong = if wrong_candidate == real {
                (real + 1) % n
            } else {
                wrong_candidate
            };
            let entry = log
                .entry(real as u64)
                .unwrap_or_else(|| std::process::abort());
            let payload = payloads.get(real).unwrap_or_else(|| std::process::abort());
            let proof = log
                .inclusion_proof(real as u64)
                .unwrap_or_else(|_| std::process::abort());
            let leaf = leaf_hash(
                entry.kind,
                entry.seq,
                entry.timestamp_version,
                &entry.prev_leaf_hash,
                payload,
            );
            let result = verify_inclusion_proof(
                leaf,
                wrong as u64,
                proof.tree_size,
                &proof.audit_path,
                root,
            );
            assert!(result.is_err());
        }

        #[hegel::test]
        fn prop_tampered_proof_sibling_rejects(tc: hegel::TestCase) {
            // Need at least 2 leaves so audit_path is non-empty.
            let n = tc.draw(gs::integers::<usize>().min_value(2).max_value(16));
            let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(n);
            for _ in 0..n {
                payloads.push(tc.draw(gs::binary().max_size(128)));
            }
            let log = build_log(&payloads);
            let root = log.root_hash();
            let idx = tc.draw(gs::integers::<usize>().max_value(n - 1));
            let entry = log
                .entry(idx as u64)
                .unwrap_or_else(|| std::process::abort());
            let payload = payloads.get(idx).unwrap_or_else(|| std::process::abort());
            let mut proof = log
                .inclusion_proof(idx as u64)
                .unwrap_or_else(|_| std::process::abort());
            if proof.audit_path.is_empty() {
                // Single-leaf tree: nothing to tamper with.
                return;
            }
            let sibling_index =
                tc.draw(gs::integers::<usize>().max_value(proof.audit_path.len() - 1));
            if let Some(sibling) = proof.audit_path.get_mut(sibling_index) {
                sibling[0] ^= 0x01;
            }
            let leaf = leaf_hash(
                entry.kind,
                entry.seq,
                entry.timestamp_version,
                &entry.prev_leaf_hash,
                payload,
            );
            assert!(verify_inclusion_proof(
                leaf,
                proof.leaf_index,
                proof.tree_size,
                &proof.audit_path,
                root
            )
            .is_err());
        }

        #[hegel::test]
        fn prop_leaf_chain_is_monotonic(tc: hegel::TestCase) {
            let payloads = draw_payloads(&tc);
            let log = build_log(&payloads);
            let entries = log.entries();
            for pair in entries.windows(2) {
                let prev = &pair[0];
                let curr = &pair[1];
                assert_eq!(curr.seq, prev.seq.saturating_add(1));
                let expected_prev_hash = leaf_hash(
                    prev.kind,
                    prev.seq,
                    prev.timestamp_version,
                    &prev.prev_leaf_hash,
                    payloads
                        .get(prev.seq as usize)
                        .unwrap_or_else(|| std::process::abort()),
                );
                assert_eq!(curr.prev_leaf_hash, expected_prev_hash);
            }
        }

        #[hegel::test]
        fn prop_sth_sign_verify_roundtrip(tc: hegel::TestCase) {
            let payloads = draw_payloads(&tc);
            let mut log = build_log(&payloads);
            let operator = SigningKey::generate();
            log.set_operator(operator.verifying_key());
            let sth = log.sign_tree_head(&operator);
            assert!(log.verify_tree_head(&sth).is_ok());
        }

        #[hegel::test]
        fn prop_forged_sth_rejects(tc: hegel::TestCase) {
            let payloads = draw_payloads(&tc);
            let mut log = build_log(&payloads);
            let operator = SigningKey::generate();
            log.set_operator(operator.verifying_key());
            let mut sth = log.sign_tree_head(&operator);
            // Mutate one byte of the signed root after signing.
            sth.root_hash[0] ^= 0x01;
            assert!(log.verify_tree_head(&sth).is_err());
        }

        /// Issue #36 — the incremental subtree-roots cache must
        /// agree with from-scratch RFC 6962 MTH for every prefix.
        ///
        /// Builds a log of N appends, then for each prefix [0..i]
        /// computes the root via the cache (incremental) and via a
        /// from-scratch recursion over the leaf slice. They must
        /// agree at every i.
        #[hegel::test]
        fn prop_subtree_cache_matches_from_scratch(tc: hegel::TestCase) {
            let payloads = draw_payloads(&tc);
            // Build the log incrementally, snapshotting root_hash at every step.
            let mut log = TransparencyLog::new();
            let mut incremental_roots = Vec::with_capacity(payloads.len());
            for (i, p) in payloads.iter().enumerate() {
                log.append(LogEntryKind::DsseEnvelope, p, (i as u64) + 1)
                    .unwrap_or_else(|_| std::process::abort());
                incremental_roots.push(log.root_hash());
            }
            // From-scratch: recompute the MTH for every prefix using
            // a fresh recursion over the leaf hashes.
            let leaves: Vec<[u8; 32]> = (0..log.tree_size())
                .map(|i| log.leaf_hash_at(i).unwrap_or_else(|| std::process::abort()))
                .collect();
            for (i, expected) in incremental_roots.iter().enumerate() {
                let from_scratch = mth_from_scratch(&leaves[..=i]);
                if from_scratch != *expected {
                    std::process::abort();
                }
            }
        }

        /// From-scratch RFC 6962 MTH for cross-checking the cache.
        /// Mirrors the recursion the cache replaced.
        fn mth_from_scratch(leaves: &[[u8; 32]]) -> [u8; 32] {
            match leaves.len() {
                0 => empty_root_for_test(),
                1 => leaves[0],
                n => {
                    let k = split_point_for_test(n);
                    let left = mth_from_scratch(&leaves[..k]);
                    let right = mth_from_scratch(&leaves[k..]);
                    node_hash_for_test(&left, &right)
                }
            }
        }

        const fn split_point_for_test(n: usize) -> usize {
            let mut k = 1usize;
            while k.saturating_mul(2) < n {
                k = k.saturating_mul(2);
            }
            k
        }

        fn empty_root_for_test() -> [u8; 32] {
            let mut h = blake3::Hasher::new();
            h.update(LOG_EMPTY_DOMAIN);
            *h.finalize().as_bytes()
        }

        fn node_hash_for_test(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
            let mut h = blake3::Hasher::new();
            h.update(LOG_NODE_DOMAIN);
            h.update(left);
            h.update(right);
            *h.finalize().as_bytes()
        }

        /// Issue #29: a verifier holding only the log + its root can
        /// verify every entry's inclusion without the original payload.
        #[hegel::test]
        fn prop_self_contained_inclusion_proof_verification(tc: hegel::TestCase) {
            let payloads = draw_payloads(&tc);
            let log = build_log(&payloads);
            let root = log.root_hash();

            // Deliberately DROP payloads before verification — the
            // whole point of this property is that the log is
            // self-sufficient for proof verification.
            drop(payloads);

            for i in 0..log.tree_size() {
                let leaf = log.leaf_hash_at(i).unwrap_or_else(|| std::process::abort());
                let proof = log
                    .inclusion_proof(i)
                    .unwrap_or_else(|_| std::process::abort());
                verify_inclusion_proof(
                    leaf,
                    proof.leaf_index,
                    proof.tree_size,
                    &proof.audit_path,
                    root,
                )
                .unwrap_or_else(|_| std::process::abort());
            }
        }
    }

    mod leaf_hash_at_tests {
        use super::*;

        #[test]
        fn leaf_hash_at_matches_leaf_hash_for_every_entry() {
            let mut log = TransparencyLog::new();
            let payloads: Vec<&[u8]> = vec![b"alpha", b"beta", b"gamma", b"delta", b"epsilon"];
            for (i, p) in payloads.iter().enumerate() {
                log.append(LogEntryKind::DsseEnvelope, p, (i as u64) + 1)
                    .unwrap();
            }
            for (i, p) in payloads.iter().enumerate() {
                let entry = log.entry(i as u64).unwrap();
                let expected = leaf_hash(
                    entry.kind,
                    entry.seq,
                    entry.timestamp_version,
                    &entry.prev_leaf_hash,
                    p,
                );
                let stored = log.leaf_hash_at(i as u64).unwrap();
                assert_eq!(stored, expected);
            }
        }

        #[test]
        fn leaf_hash_at_out_of_range_returns_none() {
            let mut log = TransparencyLog::new();
            log.append(LogEntryKind::VersionAttestation, b"only", 1)
                .unwrap();
            assert!(log.leaf_hash_at(0).is_some());
            assert!(log.leaf_hash_at(1).is_none());
            assert!(log.leaf_hash_at(u64::MAX).is_none());
        }

        #[test]
        fn leaf_hash_at_on_empty_log_returns_none() {
            let log = TransparencyLog::new();
            assert!(log.leaf_hash_at(0).is_none());
        }
    }
}
