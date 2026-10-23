// SPDX-License-Identifier: MIT OR Apache-2.0
//! Format-v3 primitives (RFC-0039).
//!
//! This module holds the pieces of the v3 on-disk format that are pure
//! functions of their inputs:
//!
//! - [`FormatVersion`] and [`RulesMode`], the two discriminants a v3
//!   reader needs before it can interpret anything else.
//! - [`rules_commitment`], the BLAKE3 commitment to the *stored* rules
//!   section that a v3 version entry signs. Verifiers check it without
//!   any key.
//! - [`frame_rules`] / [`unframe_rules`], the length-prefixed,
//!   Padmé-padded plaintext framing shared by the public and
//!   confidential modes.
//! - [`FileContext`], the per-file context (`format`, `file_id`) that v3
//!   version signatures and hashes bind, with dispatch to the v2 or v3
//!   canonical message.
//!
//! Nothing here reads or writes files.
//!
//! # Example
//!
//! ```
//! use aion_context::format::{frame_rules, rules_commitment, unframe_rules, RulesMode};
//!
//! let framed = frame_rules(b"allow: read")?;
//! assert_eq!(unframe_rules(&framed)?, b"allow: read");
//!
//! let public = rules_commitment(RulesMode::Public, &framed);
//! let confidential = rules_commitment(RulesMode::Confidential, &framed);
//! assert_ne!(public, confidential);
//! # Ok::<(), aion_context::AionError>(())
//! ```

use crate::crypto::SigningKey;
use crate::key_registry::KeyRegistry;
use crate::serializer::{SignatureEntry, VersionEntry};
use crate::types::{AuthorId, FileId};
use crate::{AionError, Result};

/// Domain separator for the v3 rules commitment.
pub const RULES_COMMIT_DOMAIN: &[u8] = b"AION_V3_RULES_COMMIT_V1\0";

/// Length in bytes of the framing header (plaintext length, `u64` LE).
pub(crate) const FRAME_HEADER_LEN: usize = 8;

/// An on-disk format version this crate understands.
///
/// Not `#[non_exhaustive]`: a new on-disk format is a major-version event
/// with its own RFC, so callers may match exhaustively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FormatVersion {
    /// Format v2: the rules section is obfuscated, not confidential, and
    /// `rules_hash` is BLAKE3 over the plaintext.
    V2,
    /// Format v3 (RFC-0039): per-version rules modes and a signed
    /// commitment to the stored rules section.
    V3,
}

impl FormatVersion {
    /// The header's `version` field value for this format.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::V2 => 2,
            Self::V3 => 3,
        }
    }

    /// Interpret a header `version` field.
    ///
    /// # Errors
    ///
    /// Returns [`AionError::UnsupportedVersion`] for any value other than
    /// 2 or 3.
    pub fn from_u16(version: u16) -> Result<Self> {
        match version {
            2 => Ok(Self::V2),
            3 => Ok(Self::V3),
            _ => Err(AionError::UnsupportedVersion {
                version,
                supported: "2, 3".to_string(),
            }),
        }
    }
}

/// How one version's rules section is stored (RFC-0039).
///
/// Stored per version in `VersionEntry.reserved[0]` and covered by that
/// version's v3 signature, so it can never change without breaking the
/// signature.
///
/// Not `#[non_exhaustive]`: RFC-0039 reserves room for new recipient
/// stanza kinds and suites, not for new modes, so callers may match
/// exhaustively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RulesMode {
    /// The rules section holds the framed plaintext.
    Public,
    /// The rules section holds a confidential envelope.
    Confidential,
}

impl RulesMode {
    /// The on-disk byte for this mode.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Public => 0x00,
            Self::Confidential => 0x01,
        }
    }

    /// Interpret an on-disk mode byte.
    ///
    /// # Errors
    ///
    /// Returns [`AionError::InvalidFormat`] for any byte other than
    /// `0x00` or `0x01`.
    pub fn from_u8(byte: u8) -> Result<Self> {
        match byte {
            0x00 => Ok(Self::Public),
            0x01 => Ok(Self::Confidential),
            _ => Err(AionError::InvalidFormat {
                reason: "unknown rules mode byte".to_string(),
            }),
        }
    }

    /// Read the mode a v3 version entry records.
    ///
    /// The mode lives in `reserved[0]`. The other 51 reserved bytes must
    /// stay zero.
    ///
    /// # Errors
    ///
    /// Returns [`AionError::InvalidFormat`] if the mode byte is unknown or
    /// any other reserved byte is non-zero.
    pub fn of(entry: &VersionEntry) -> Result<Self> {
        Self::from_reserved(&entry.reserved)
    }

    /// Read the mode from a version entry's 52 reserved bytes.
    pub(crate) fn from_reserved(reserved: &[u8; 52]) -> Result<Self> {
        let (mode, rest) = reserved
            .split_first()
            .ok_or_else(|| AionError::InvalidFormat {
                reason: "version entry has no reserved bytes".to_string(),
            })?;
        if rest.iter().any(|b| *b != 0) {
            return Err(AionError::InvalidFormat {
                reason: "VersionEntry reserved bytes after rules_mode must be zero".to_string(),
            });
        }
        Self::from_u8(*mode)
    }
}

/// Commit to a stored rules section (RFC-0039).
///
/// `BLAKE3(RULES_COMMIT_DOMAIN ‖ mode ‖ section)`. The mode byte keeps the
/// public and confidential encodings unambiguous: the same bytes read
/// under the other mode commit differently.
///
/// # Example
///
/// ```
/// use aion_context::format::{rules_commitment, RulesMode};
///
/// let a = rules_commitment(RulesMode::Public, b"section");
/// assert_eq!(a, rules_commitment(RulesMode::Public, b"section"));
/// assert_ne!(a, rules_commitment(RulesMode::Public, b"sectioN"));
/// ```
#[must_use]
pub fn rules_commitment(mode: RulesMode, section: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(RULES_COMMIT_DOMAIN);
    hasher.update(&[mode.as_u8()]);
    hasher.update(section);
    *hasher.finalize().as_bytes()
}

/// The Padmé padded length for `len` bytes.
///
/// Padmé (Nikitin et al., PETS 2019) rounds a length up so that only
/// `O(log log len)` bits of it remain visible, at an overhead of at most
/// about 12%. Lengths below 2 are returned unchanged.
///
/// # Errors
///
/// Returns [`AionError::InvalidFormat`] if the padded length would
/// overflow `u64`.
///
/// # Example
///
/// ```
/// use aion_context::format::padme_len;
///
/// assert_eq!(padme_len(8).ok(), Some(8));
/// assert_eq!(padme_len(33).ok(), Some(36));
/// ```
pub fn padme_len(len: u64) -> Result<u64> {
    if len < 2 {
        return Ok(len);
    }
    let exponent = len.ilog2();
    let exponent_bits = exponent.ilog2().saturating_add(1);
    let last_bits = exponent.saturating_sub(exponent_bits);
    let mask = 1u64
        .checked_shl(last_bits)
        .and_then(|bit| bit.checked_sub(1))
        .ok_or_else(padme_overflow)?;
    len.checked_add(mask)
        .map(|rounded| rounded & !mask)
        .ok_or_else(padme_overflow)
}

fn padme_overflow() -> AionError {
    AionError::InvalidFormat {
        reason: "padded rules length overflows u64".to_string(),
    }
}

/// Frame a rules plaintext: `u64_le(len) ‖ plaintext ‖ zero padding`,
/// padded to [`padme_len`] of `8 + len`.
///
/// # Errors
///
/// Returns [`AionError::InvalidFormat`] if the framed length overflows.
pub fn frame_rules(plaintext: &[u8]) -> Result<Vec<u8>> {
    let plain_len = u64::try_from(plaintext.len()).map_err(|_| padme_overflow())?;
    let unpadded = plain_len
        .checked_add(FRAME_HEADER_LEN as u64)
        .ok_or_else(padme_overflow)?;
    let total = usize::try_from(padme_len(unpadded)?).map_err(|_| padme_overflow())?;
    let mut framed = Vec::with_capacity(total);
    framed.extend_from_slice(&plain_len.to_le_bytes());
    framed.extend_from_slice(plaintext);
    framed.resize(total, 0);
    Ok(framed)
}

/// Recover the plaintext from a framed rules section.
///
/// Accepts only the canonical encoding: the total length must equal
/// [`padme_len`] of `8 + len`, and every padding byte must be zero. This
/// is a parser of adversary-controlled bytes and never panics.
///
/// # Errors
///
/// Returns [`AionError::InvalidFormat`] for a truncated frame, a
/// declared length that exceeds the frame, a non-canonical total
/// length, or non-zero padding.
pub fn unframe_rules(framed: &[u8]) -> Result<&[u8]> {
    let header: [u8; FRAME_HEADER_LEN] = framed
        .get(..FRAME_HEADER_LEN)
        .and_then(|h| h.try_into().ok())
        .ok_or_else(|| frame_error("rules frame shorter than its header"))?;
    let plain_len = u64::from_le_bytes(header);
    let unpadded = plain_len
        .checked_add(FRAME_HEADER_LEN as u64)
        .ok_or_else(|| frame_error("rules frame length overflows"))?;
    let expected = padme_len(unpadded)?;
    if u64::try_from(framed.len()).ok() != Some(expected) {
        return Err(frame_error("rules frame length is not canonical"));
    }
    let body_end =
        usize::try_from(unpadded).map_err(|_| frame_error("rules frame length overflows"))?;
    let body = framed
        .get(FRAME_HEADER_LEN..body_end)
        .ok_or_else(|| frame_error("rules frame body exceeds frame"))?;
    let padding = framed.get(body_end..).unwrap_or_default();
    if padding.iter().any(|b| *b != 0) {
        return Err(frame_error("rules frame padding is not zero"));
    }
    Ok(body)
}

fn frame_error(reason: &str) -> AionError {
    AionError::InvalidFormat {
        reason: reason.to_string(),
    }
}

/// The per-file context that version signatures and version hashes bind.
///
/// v2 messages bind only the version entry. v3 messages also bind the
/// format version, the `file_id`, and the entry's [`RulesMode`], so a
/// signed entry cannot be moved into another file or reinterpreted under
/// another mode (RFC-0039).
///
/// This is the only public entry point for building version messages and
/// hashes, so a caller cannot apply v3 construction to a v2 file by
/// mistake.
///
/// # Example
///
/// ```
/// use aion_context::format::{FileContext, FormatVersion, RulesMode};
/// use aion_context::serializer::VersionEntry;
/// use aion_context::types::{AuthorId, FileId, VersionNumber};
///
/// let entry = VersionEntry::new(VersionNumber::GENESIS, [0; 32], [7; 32], AuthorId::new(1), 0, 0, 0)
///     .with_rules_mode(RulesMode::Public);
/// let context = FileContext::new(FormatVersion::V3, FileId::new(42));
/// let message = context.canonical_version_message(&entry)?;
/// assert!(message.starts_with(aion_context::signature_chain::SIGNATURE_DOMAIN_V3));
/// # Ok::<(), aion_context::AionError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileContext {
    format: FormatVersion,
    file_id: FileId,
}

impl FileContext {
    /// Build the context for a file's format and identifier.
    #[must_use]
    pub const fn new(format: FormatVersion, file_id: FileId) -> Self {
        Self { format, file_id }
    }

    /// The file's on-disk format.
    #[must_use]
    pub const fn format(&self) -> FormatVersion {
        self.format
    }

    /// The file's identifier.
    #[must_use]
    pub const fn file_id(&self) -> FileId {
        self.file_id
    }

    /// The canonical message a version signature covers.
    ///
    /// # Errors
    ///
    /// For v3, returns [`AionError::InvalidFormat`] if the entry's rules
    /// mode or reserved bytes are invalid.
    pub fn canonical_version_message(&self, version: &VersionEntry) -> Result<Vec<u8>> {
        match self.format {
            FormatVersion::V2 => Ok(crate::signature_chain::canonical_version_message(version)),
            FormatVersion::V3 => {
                crate::signature_chain::canonical_version_message_v3(version, self.file_id)
            }
        }
    }

    /// The hash the next version's `parent_hash` links to.
    ///
    /// # Errors
    ///
    /// For v3, returns [`AionError::InvalidFormat`] if the entry's rules
    /// mode or reserved bytes are invalid.
    pub fn version_hash(&self, version: &VersionEntry) -> Result<[u8; 32]> {
        match self.format {
            FormatVersion::V2 => Ok(crate::signature_chain::compute_version_hash(version)),
            FormatVersion::V3 => {
                crate::signature_chain::compute_version_hash_v3(version, self.file_id)
            }
        }
    }

    /// The canonical message an RFC-0021 attestation signature covers.
    ///
    /// # Errors
    ///
    /// For v3, returns [`AionError::InvalidFormat`] if the entry's rules
    /// mode or reserved bytes are invalid.
    pub fn attestation_message(&self, version: &VersionEntry, signer: AuthorId) -> Result<Vec<u8>> {
        match self.format {
            FormatVersion::V2 => Ok(crate::signature_chain::canonical_attestation_message(
                version, signer,
            )),
            FormatVersion::V3 => crate::signature_chain::canonical_attestation_message_v3(
                version,
                self.file_id,
                signer,
            ),
        }
    }

    /// Sign a version entry under this file's format.
    ///
    /// # Errors
    ///
    /// For v3, returns [`AionError::InvalidFormat`] if the entry's rules
    /// mode or reserved bytes are invalid.
    pub fn sign_version(
        &self,
        version: &VersionEntry,
        signing_key: &SigningKey,
    ) -> Result<SignatureEntry> {
        let message = self.canonical_version_message(version)?;
        Ok(SignatureEntry::new(
            AuthorId::new(version.author_id),
            signing_key.verifying_key().to_bytes(),
            signing_key.sign(&message),
        ))
    }

    /// Verify one version signature against a pinned registry, over this
    /// file's canonical message: author binding, active epoch,
    /// constant-time key match, then Ed25519 (RFC-0034).
    ///
    /// # Errors
    ///
    /// Returns an error if the entry is invalid for this format or any
    /// check fails.
    pub fn verify_signature(
        &self,
        version: &VersionEntry,
        signature: &SignatureEntry,
        registry: &KeyRegistry,
    ) -> Result<()> {
        let message = self.canonical_version_message(version)?;
        crate::signature_chain::verify_version_signature_over(
            version, signature, registry, &message,
        )
    }

    /// Verify every version signature in a chain. The format-aware
    /// counterpart of [`crate::signature_chain::verify_signatures_batch`].
    ///
    /// # Errors
    ///
    /// Returns an error on a count mismatch or the first failing pair.
    pub fn verify_signatures(
        &self,
        versions: &[VersionEntry],
        signatures: &[SignatureEntry],
        registry: &KeyRegistry,
    ) -> Result<()> {
        crate::signature_chain::verify_signatures_with(
            versions,
            signatures,
            |version, signature| self.verify_signature(version, signature, registry),
        )
    }

    /// Verify chain structure: genesis is version 1 with a zero parent,
    /// versions increase by one, and each `parent_hash` equals this
    /// format's [`FileContext::version_hash`] of the previous entry.
    ///
    /// # Errors
    ///
    /// Returns an error at the first structural or linkage failure.
    pub fn verify_hash_chain(&self, versions: &[VersionEntry]) -> Result<()> {
        crate::signature_chain::verify_hash_chain_with(versions, |parent| self.version_hash(parent))
    }

    /// Produce an RFC-0021 attestation signature under this file's format.
    ///
    /// # Errors
    ///
    /// For v3, returns [`AionError::InvalidFormat`] if the entry's rules
    /// mode or reserved bytes are invalid.
    pub fn sign_attestation(
        &self,
        version: &VersionEntry,
        signer: AuthorId,
        signing_key: &SigningKey,
    ) -> Result<SignatureEntry> {
        let message = self.attestation_message(version, signer)?;
        Ok(SignatureEntry::new(
            signer,
            signing_key.verifying_key().to_bytes(),
            signing_key.sign(&message),
        ))
    }

    /// Verify an RFC-0021 attestation signature against a pinned registry,
    /// under this file's format.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry is invalid for this format or any
    /// check fails.
    pub fn verify_attestation(
        &self,
        version: &VersionEntry,
        signature: &SignatureEntry,
        registry: &KeyRegistry,
    ) -> Result<()> {
        let message = self.attestation_message(version, AuthorId::new(signature.author_id))?;
        crate::signature_chain::verify_attestation_over(version, signature, registry, &message)
    }

    /// Evaluate an RFC-0021 multi-signature policy over attestations,
    /// each checked against `registry` under this file's format.
    ///
    /// # Errors
    ///
    /// Returns `Err` only for structural problems; rejected signers are
    /// reported in the returned [`crate::multisig::MultiSigVerification`].
    pub fn verify_multisig(
        &self,
        version: &VersionEntry,
        signatures: &[SignatureEntry],
        policy: &crate::multisig::MultiSigPolicy,
        registry: &KeyRegistry,
    ) -> Result<crate::multisig::MultiSigVerification> {
        crate::multisig::verify_multisig_with(version, signatures, policy, |version, signature| {
            self.verify_attestation(version, signature, registry)
        })
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn padme_matches_reference_points() {
        let cases = [
            (0, 0),
            (1, 1),
            (8, 8),
            (9, 10),
            (17, 18),
            (33, 36),
            (100, 104),
            (1000, 1024),
        ];
        for (len, padded) in cases {
            assert_eq!(
                padme_len(len).unwrap_or_else(|_| std::process::abort()),
                padded,
                "padme_len({len})"
            );
        }
    }

    #[test]
    fn padme_rejects_overflow() {
        assert!(padme_len(u64::MAX).is_err());
    }

    #[test]
    fn empty_rules_frame_is_header_only() {
        let framed = frame_rules(b"").unwrap_or_else(|_| std::process::abort());
        assert_eq!(framed, vec![0u8; FRAME_HEADER_LEN]);
        assert_eq!(
            unframe_rules(&framed).unwrap_or_else(|_| std::process::abort()),
            b""
        );
    }

    #[test]
    fn unframe_rejects_frames_shorter_than_canonical() {
        let framed = frame_rules(b"abc").unwrap_or_else(|_| std::process::abort());
        assert_eq!(framed.len(), 12);
        assert!(unframe_rules(&framed[..11]).is_err());
        let mut nine = 9u64.to_le_bytes().to_vec();
        nine.extend_from_slice(&[0x41; 9]);
        assert_eq!(nine.len(), 17);
        assert!(unframe_rules(&nine).is_err());
        nine.push(0);
        assert_eq!(
            unframe_rules(&nine).unwrap_or_else(|_| std::process::abort()),
            &[0x41; 9]
        );
    }

    #[test]
    fn unframe_rejects_truncated_and_overlong_frames() {
        assert!(unframe_rules(&[0u8; 7]).is_err());
        let mut declared_too_long = frame_rules(b"abc").unwrap_or_else(|_| std::process::abort());
        declared_too_long[0] = 200;
        assert!(unframe_rules(&declared_too_long).is_err());
        let mut extra_padding = frame_rules(b"abc").unwrap_or_else(|_| std::process::abort());
        extra_padding.push(0);
        assert!(unframe_rules(&extra_padding).is_err());
    }

    #[test]
    fn domains_are_nul_terminated() {
        for domain in [
            RULES_COMMIT_DOMAIN,
            crate::signature_chain::SIGNATURE_DOMAIN_V3,
            crate::signature_chain::VERSION_HASH_DOMAIN_V3,
            crate::signature_chain::ATTESTATION_DOMAIN_V3,
        ] {
            assert_eq!(domain.last(), Some(&0u8));
            assert_eq!(
                domain.iter().position(|b| *b == 0),
                Some(domain.len().saturating_sub(1))
            );
        }
    }

    #[test]
    fn format_and_mode_round_trip() {
        for format in [FormatVersion::V2, FormatVersion::V3] {
            assert_eq!(
                FormatVersion::from_u16(format.as_u16()).unwrap_or_else(|_| std::process::abort()),
                format
            );
        }
        assert!(FormatVersion::from_u16(1).is_err());
        assert!(FormatVersion::from_u16(4).is_err());
        for mode in [RulesMode::Public, RulesMode::Confidential] {
            assert_eq!(
                RulesMode::from_u8(mode.as_u8()).unwrap_or_else(|_| std::process::abort()),
                mode
            );
        }
    }

    #[test]
    fn file_context_dispatches_by_format() {
        let entry = VersionEntry::new(
            crate::types::VersionNumber::GENESIS,
            [0; 32],
            [9; 32],
            AuthorId::new(3),
            1,
            0,
            0,
        );
        let v2 = FileContext::new(FormatVersion::V2, FileId::new(5));
        let v3 = FileContext::new(FormatVersion::V3, v2.file_id());
        assert_eq!(
            v2.version_hash(&entry)
                .unwrap_or_else(|_| std::process::abort()),
            crate::signature_chain::compute_version_hash(&entry)
        );
        assert_ne!(
            v2.version_hash(&entry)
                .unwrap_or_else(|_| std::process::abort()),
            v3.version_hash(&entry)
                .unwrap_or_else(|_| std::process::abort())
        );
        assert_ne!(
            v2.canonical_version_message(&entry)
                .unwrap_or_else(|_| std::process::abort()),
            v3.canonical_version_message(&entry)
                .unwrap_or_else(|_| std::process::abort())
        );
    }

    mod properties {
        use super::*;
        use hegel::generators as gs;

        #[hegel::test]
        fn prop_padme_bounds_and_idempotence(tc: hegel::TestCase) {
            let len = tc.draw(gs::integers::<u64>().max_value(1u64 << 48));
            let padded = padme_len(len).unwrap_or_else(|_| std::process::abort());
            assert!(padded >= len);
            if len >= 8 {
                assert!(
                    padded.saturating_sub(len) <= len / 8,
                    "overhead above 12.5% at {len}"
                );
            }
            assert_eq!(
                padme_len(padded).unwrap_or_else(|_| std::process::abort()),
                padded
            );
        }

        #[hegel::test]
        fn prop_padme_is_monotonic(tc: hegel::TestCase) {
            let a = tc.draw(gs::integers::<u64>().max_value(1u64 << 48));
            let b = tc.draw(gs::integers::<u64>().max_value(1u64 << 48));
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            let padded_lo = padme_len(lo).unwrap_or_else(|_| std::process::abort());
            let padded_hi = padme_len(hi).unwrap_or_else(|_| std::process::abort());
            assert!(padded_lo <= padded_hi);
        }

        #[hegel::test]
        fn prop_frame_round_trip(tc: hegel::TestCase) {
            let plaintext = tc.draw(gs::binary().max_size(4096));
            let framed = frame_rules(&plaintext).unwrap_or_else(|_| std::process::abort());
            let expected = padme_len(plaintext.len().saturating_add(FRAME_HEADER_LEN) as u64)
                .unwrap_or_else(|_| std::process::abort());
            assert_eq!(framed.len() as u64, expected);
            assert_eq!(
                unframe_rules(&framed).unwrap_or_else(|_| std::process::abort()),
                plaintext.as_slice()
            );
        }

        #[hegel::test]
        fn prop_unframe_never_panics_on_arbitrary_bytes(tc: hegel::TestCase) {
            let bytes = tc.draw(gs::binary().max_size(4096));
            let _ = unframe_rules(&bytes);
        }

        #[hegel::test]
        fn prop_unframe_rejects_nonzero_padding(tc: hegel::TestCase) {
            let mut plaintext = tc.draw(gs::binary().min_size(9).max_size(4096));
            if (plaintext.len() & 1) == 0 {
                plaintext.push(0xAA);
            }
            // 8 + len is now odd and at least 17, so Padmé rounds it up by
            // at least one byte: every run has padding to corrupt.
            let mut framed = frame_rules(&plaintext).unwrap_or_else(|_| std::process::abort());
            let body_end = FRAME_HEADER_LEN.saturating_add(plaintext.len());
            assert!(framed.len() > body_end);
            let index = tc.draw(
                gs::integers::<usize>()
                    .min_value(body_end)
                    .max_value(framed.len().saturating_sub(1)),
            );
            framed[index] = tc.draw(gs::integers::<u8>().min_value(1));
            assert!(unframe_rules(&framed).is_err());
        }

        #[hegel::test]
        fn prop_rules_commitment_separates_modes(tc: hegel::TestCase) {
            let section = tc.draw(gs::binary().max_size(4096));
            assert_ne!(
                rules_commitment(RulesMode::Public, &section),
                rules_commitment(RulesMode::Confidential, &section)
            );
        }

        #[hegel::test]
        fn prop_rules_commitment_detects_any_byte_flip(tc: hegel::TestCase) {
            let section = tc.draw(gs::binary().min_size(1).max_size(4096));
            let mode = if tc.draw(gs::booleans()) {
                RulesMode::Public
            } else {
                RulesMode::Confidential
            };
            let index = tc.draw(gs::integers::<usize>().max_value(section.len().saturating_sub(1)));
            let mut tampered = section.clone();
            tampered[index] ^= tc.draw(gs::integers::<u8>().min_value(1));
            assert_ne!(
                rules_commitment(mode, &section),
                rules_commitment(mode, &tampered)
            );
        }
    }
}
