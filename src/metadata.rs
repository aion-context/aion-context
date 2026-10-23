// SPDX-License-Identifier: MIT OR Apache-2.0
//! Signed version metadata (RFC-0040): format-v4 checks.
//!
//! In format v4 every version signs a metadata commitment over its commit
//! message and its own audit entry, whose v4 hash covers the entry's
//! details text and chains to the entry before it. This module checks all
//! of it key-free:
//!
//! - one audit entry per version, in order, agreeing with its version
//!   (author, timestamp, action);
//! - the v4 audit chain;
//! - the canonical string table: each version's message then NUL, then its
//!   details then NUL when it has any, and nothing else;
//! - each version's stored commitment;
//! - the header copies of signed values.
//!
//! The signatures themselves are checked elsewhere; together they cover
//! the commit messages and the whole audit trail.

use crate::audit::{ActionCode, AuditEntry};
use crate::format::{metadata_commitment, stored_metadata_commitment};
use crate::parser::AionParser;
use crate::serializer::VersionEntry;
use crate::{AionError, Result};

/// One version's verified metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionMetadata {
    /// The commit message.
    pub message: String,
    /// The version's audit entry.
    pub audit: AuditEntry,
    /// The audit entry's details text (empty unless it is `MigratedFrom`).
    pub details: String,
}

fn rejected(reason: &str) -> AionError {
    AionError::InvalidFormat {
        reason: format!("format-v4 metadata rejected: {reason}"),
    }
}

/// Check every format-v4 metadata rule and return each version's message
/// and audit entry, in version order.
///
/// # Errors
///
/// [`AionError::InvalidFormat`] naming the bounded reason:
/// `audit_version_mismatch`, `string_table_noncanonical`,
/// `metadata_commitment_mismatch`, or `header_mismatch`.
pub fn verify_v4_metadata(
    parser: &AionParser<'_>,
    versions: &[VersionEntry],
) -> Result<Vec<VersionMetadata>> {
    let header = parser.header();
    if header.audit_trail_count != header.version_chain_count {
        return Err(rejected(
            "audit_version_mismatch: audit count != version count",
        ));
    }
    check_contiguous_layout(parser)?;
    let table = parser.string_table_bytes()?;
    let mut cursor = TableCursor { table, offset: 0 };
    let mut previous = [0u8; 32];
    let mut verified = Vec::with_capacity(versions.len());
    let audit_section = parser.audit_trail_bytes()?;
    for (index, version) in versions.iter().enumerate() {
        let audit = parser.get_audit_entry(index)?;
        check_canonical_audit(audit_section, index, &audit)?;
        check_agreement(index, version, &audit, &previous)?;
        let message = cursor.take(version.message_offset, version.message_length)?;
        let details = take_details(&mut cursor, &audit)?;
        let audit_hash = audit_hash_v4(&audit, details.as_bytes())?;
        let expected =
            metadata_commitment(version.version_number, message.as_bytes(), &audit_hash)?;
        if stored_metadata_commitment(version) != expected {
            return Err(rejected("metadata_commitment_mismatch"));
        }
        previous = audit_hash;
        verified.push(VersionMetadata {
            message,
            audit,
            details,
        });
    }
    if cursor.offset != table.len() as u64 {
        return Err(rejected("string_table_noncanonical: trailing bytes"));
    }
    check_header_copies(parser, versions)?;
    Ok(verified)
}

/// The v4 audit-entry hash (RFC-0040): the entry's 80 bytes and its
/// details text, under its own domain.
pub fn audit_hash_v4(audit: &AuditEntry, details: &[u8]) -> Result<[u8; 32]> {
    let details_len = u32::try_from(details.len())
        .map_err(|_| rejected("string_table_noncanonical: details longer than u32::MAX"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(crate::audit::AUDIT_ENTRY_DOMAIN_V4);
    hasher.update(audit.as_bytes());
    hasher.update(&details_len.to_le_bytes());
    hasher.update(details);
    Ok(*hasher.finalize().as_bytes())
}

/// The stored 80 bytes of audit entry `index` must be exactly the entry the
/// parser decoded. The parser rebuilds entries from their fields and drops
/// the reserved bytes, so this is what makes those bytes zero and the hash
/// cover what is on disk.
fn check_canonical_audit(section: &[u8], index: usize, audit: &AuditEntry) -> Result<()> {
    let size = crate::serializer::AUDIT_ENTRY_SIZE;
    let start = index
        .checked_mul(size)
        .ok_or_else(|| rejected("audit_version_mismatch: index"))?;
    let stored = section
        .get(start..start.saturating_add(size))
        .ok_or_else(|| rejected("audit_version_mismatch: truncated entry"))?;
    if stored == audit.as_bytes() {
        Ok(())
    } else {
        Err(rejected(
            "audit_version_mismatch: non-canonical audit entry",
        ))
    }
}

/// Audit entry `index` must belong to `version`: same author and timestamp,
/// the action allowed at that position, chained to the previous entry.
fn check_agreement(
    index: usize,
    version: &VersionEntry,
    audit: &AuditEntry,
    previous: &[u8; 32],
) -> Result<()> {
    let action = audit
        .action_code()
        .map_err(|_| rejected("audit_version_mismatch: unknown action"))?;
    let allowed = if index == 0 {
        matches!(action, ActionCode::CreateGenesis | ActionCode::MigratedFrom)
    } else {
        action == ActionCode::CommitVersion
    };
    if !allowed {
        return Err(rejected("audit_version_mismatch: action not allowed here"));
    }
    if audit.author_id().as_u64() != version.author_id || audit.timestamp() != version.timestamp {
        return Err(rejected("audit_version_mismatch: author or timestamp"));
    }
    if audit.previous_hash() != previous {
        return Err(rejected("audit_version_mismatch: broken audit chain"));
    }
    Ok(())
}

/// Details are required for `MigratedFrom` and forbidden otherwise; an
/// absent details range must be `(0, 0)`.
fn take_details(cursor: &mut TableCursor<'_>, audit: &AuditEntry) -> Result<String> {
    let migrated = audit.action_code_raw() == ActionCode::MigratedFrom as u16;
    match (audit.details_length(), migrated) {
        (0, false) if audit.details_offset() == 0 => Ok(String::new()),
        (0, _) => Err(rejected("string_table_noncanonical: details range")),
        (_, false) => Err(rejected("audit_version_mismatch: unexpected details")),
        (length, true) => cursor.take(audit.details_offset(), length),
    }
}

/// Sections must sit back to back in their fixed order, with the integrity
/// hash immediately after the string table, so no byte lies outside a
/// checked section.
fn check_contiguous_layout(parser: &AionParser<'_>) -> Result<()> {
    let h = parser.header();
    let after = |offset: u64, count: u64, size: usize| {
        count
            .checked_mul(size as u64)
            .and_then(|length| offset.checked_add(length))
    };
    let expected = [
        (
            h.encrypted_rules_offset,
            Some(crate::parser::HEADER_SIZE as u64),
        ),
        (
            h.version_chain_offset,
            h.encrypted_rules_offset
                .checked_add(h.encrypted_rules_length),
        ),
        (
            h.signatures_offset,
            after(
                h.version_chain_offset,
                h.version_chain_count,
                crate::parser::VERSION_ENTRY_SIZE,
            ),
        ),
        (
            h.audit_trail_offset,
            after(
                h.signatures_offset,
                h.signatures_count,
                crate::parser::SIGNATURE_ENTRY_SIZE,
            ),
        ),
        (
            h.string_table_offset,
            after(
                h.audit_trail_offset,
                h.audit_trail_count,
                crate::serializer::AUDIT_ENTRY_SIZE,
            ),
        ),
        (
            parser.file_size().saturating_sub(32) as u64,
            h.string_table_offset.checked_add(h.string_table_length),
        ),
    ];
    let contiguous = h.signatures_count == h.version_chain_count
        && expected
            .iter()
            .all(|(actual, wanted)| Some(*actual) == *wanted);
    if contiguous {
        Ok(())
    } else {
        Err(rejected(
            "string_table_noncanonical: sections are not contiguous",
        ))
    }
}

/// The header's copies must equal the values the versions sign.
fn check_header_copies(parser: &AionParser<'_>, versions: &[VersionEntry]) -> Result<()> {
    let header = parser.header();
    let (Some(genesis), Some(head)) = (versions.first(), versions.last()) else {
        return Err(rejected("header_mismatch: no versions"));
    };
    let agrees = header.current_version == head.version_number
        && header.root_hash == genesis.rules_hash
        && header.current_hash == head.rules_hash
        && header.created_at == genesis.timestamp
        && header.modified_at == head.timestamp;
    if agrees {
        Ok(())
    } else {
        Err(rejected("header_mismatch"))
    }
}

/// Walks the string table in canonical order.
struct TableCursor<'a> {
    table: &'a [u8],
    offset: u64,
}

impl TableCursor<'_> {
    /// Take the next string, which must start exactly at the cursor, be
    /// `length` bytes of UTF-8 without NUL, and end in a NUL.
    fn take(&mut self, offset: u64, length: u32) -> Result<String> {
        if offset != self.offset {
            return Err(rejected("string_table_noncanonical: out-of-order offset"));
        }
        let start =
            usize::try_from(offset).map_err(|_| rejected("string_table_noncanonical: offset"))?;
        let end = start
            .checked_add(
                usize::try_from(length)
                    .map_err(|_| rejected("string_table_noncanonical: length"))?,
            )
            .ok_or_else(|| rejected("string_table_noncanonical: length"))?;
        let bytes = self
            .table
            .get(start..end)
            .ok_or_else(|| rejected("string_table_noncanonical: out of range"))?;
        if self.table.get(end) != Some(&0) || bytes.contains(&0) {
            return Err(rejected("string_table_noncanonical: terminator"));
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| rejected("string_table_noncanonical: not UTF-8"))?;
        self.offset = (end as u64).saturating_add(1);
        Ok(text.to_string())
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::crypto::SigningKey;
    use crate::format::RulesProtection;
    use crate::key_registry::KeyRegistry;
    use crate::operations::{
        commit_version, init_file, verify_file, CommitOptions, InitOptions, VerificationReport,
    };
    use crate::types::AuthorId;
    use tempfile::TempDir;

    const APPROVAL: &[u8] = b"Approved by: Alice (CFO)";
    const FORGERY: &[u8] = b"Approved by: Mallory (X)";

    fn ok<T, E>(result: std::result::Result<T, E>) -> T {
        result.unwrap_or_else(|_| std::process::abort())
    }

    struct Fixture {
        _dir: TempDir,
        path: std::path::PathBuf,
        registry: KeyRegistry,
    }

    /// A v4 file with a genesis and one commit, both with approval text.
    fn v4_file() -> Fixture {
        let dir = ok(TempDir::new());
        let path = dir.path().join("policy.aion");
        let key = ok(SigningKey::generate());
        let master = ok(SigningKey::generate());
        let author = AuthorId::new(40_001);
        let mut registry = KeyRegistry::new();
        ok(registry.register_author(author, master.verifying_key(), key.verifying_key(), 0));
        let message = ok(std::str::from_utf8(APPROVAL));
        ok(init_file(
            &path,
            b"refund_limit: 100",
            &InitOptions {
                author_id: author,
                signing_key: &key,
                message,
                timestamp: None,
                protection: RulesProtection::Public,
            },
        ));
        let commit = CommitOptions {
            author_id: author,
            signing_key: &key,
            message: "Raised by: Bob",
            timestamp: None,
            protection: RulesProtection::Public,
        };
        ok(commit_version(
            &path,
            b"refund_limit: 500",
            &commit,
            &registry,
        ));
        Fixture {
            _dir: dir,
            path,
            registry,
        }
    }

    fn recompute_integrity(bytes: &mut [u8]) {
        let body = bytes.len().saturating_sub(32);
        let digest = crate::crypto::hash(&bytes[..body]);
        bytes[body..].copy_from_slice(&digest);
    }

    fn verify_bytes_of(fixture: &Fixture, bytes: &[u8]) -> VerificationReport {
        ok(std::fs::write(&fixture.path, bytes));
        ok(verify_file(&fixture.path, &fixture.registry))
    }

    fn position(bytes: &[u8], needle: &[u8]) -> usize {
        bytes
            .windows(needle.len())
            .position(|window| window == needle)
            .unwrap_or_else(|| std::process::abort())
    }

    #[test]
    fn untouched_v4_files_verify_with_signed_metadata() {
        let fixture = v4_file();
        let report = ok(verify_file(&fixture.path, &fixture.registry));
        assert!(report.is_valid, "{:?}", report.errors);
        assert!(report.metadata_signed);
    }

    /// GHSA-69cp-fwrw-82vh, message half: fixed in v4.
    #[test]
    fn a_forged_commit_message_fails_v4_verification() {
        let fixture = v4_file();
        let mut bytes = ok(std::fs::read(&fixture.path));
        let at = position(&bytes, APPROVAL);
        bytes[at..at + FORGERY.len()].copy_from_slice(FORGERY);
        recompute_integrity(&mut bytes);
        let report = verify_bytes_of(&fixture, &bytes);
        assert!(!report.is_valid);
        assert!(!report.audit_chain_valid);
        assert_eq!(
            crate::operations::classify_verify_failure(&report),
            "metadata_invalid"
        );
    }

    /// The commitment is not secret: a forger who also recomputes it still
    /// fails, because the version signature covers the stored commitment.
    #[test]
    fn recomputing_the_commitment_does_not_help_a_forger() {
        let fixture = v4_file();
        let mut bytes = ok(std::fs::read(&fixture.path));
        let at = position(&bytes, APPROVAL);
        bytes[at..at + FORGERY.len()].copy_from_slice(FORGERY);
        let parser = ok(AionParser::new(&bytes));
        let genesis = ok(parser.get_version_entry(0));
        let audit = ok(parser.get_audit_entry(0));
        let audit_hash = ok(audit_hash_v4(&audit, &[]));
        let forged = ok(metadata_commitment(1, FORGERY, &audit_hash));
        let entry_at = parser.header().version_chain_offset as usize;
        let commitment_at = entry_at + std::mem::size_of::<VersionEntry>() - 52 + 1;
        assert_eq!(genesis.reserved[0], 0);
        bytes[commitment_at..commitment_at + 32].copy_from_slice(&forged);
        recompute_integrity(&mut bytes);
        let report = verify_bytes_of(&fixture, &bytes);
        assert!(!report.is_valid);
        assert!(!report.signatures_valid || !report.hash_chain_valid);
    }

    /// GHSA-69cp-fwrw-82vh, audit half: fixed in v4.
    #[test]
    fn a_forged_audit_author_fails_v4_verification() {
        let fixture = v4_file();
        let mut bytes = ok(std::fs::read(&fixture.path));
        let audit_at = {
            let parser = ok(AionParser::new(&bytes));
            parser.header().audit_trail_offset as usize
        };
        bytes[audit_at + 8..audit_at + 16].copy_from_slice(&999u64.to_le_bytes());
        recompute_integrity(&mut bytes);
        let report = verify_bytes_of(&fixture, &bytes);
        assert!(!report.is_valid);
        assert!(!report.audit_chain_valid);
    }

    #[test]
    fn a_header_copy_change_fails() {
        let fixture = v4_file();
        let original = ok(std::fs::read(&fixture.path));
        let created_at = {
            let parser = ok(AionParser::new(&original));
            parser.header().created_at
        };
        let mut header_edit = original;
        let at = position(&header_edit, &created_at.to_le_bytes());
        header_edit[at..at + 8].copy_from_slice(&(created_at ^ 1).to_le_bytes());
        recompute_integrity(&mut header_edit);
        assert!(!verify_bytes_of(&fixture, &header_edit).is_valid);
    }

    #[test]
    fn the_string_table_walk_accepts_only_the_canonical_layout() {
        let table = b"one\0two\0";
        let mut cursor = TableCursor { table, offset: 0 };
        assert_eq!(ok(cursor.take(0, 3)), "one");
        assert_eq!(ok(cursor.take(4, 3)), "two");
        assert_eq!(cursor.offset, table.len() as u64);

        let out_of_order = TableCursor { table, offset: 0 }.take(4, 3);
        assert!(out_of_order.is_err());
        assert!(
            TableCursor { table, offset: 0 }.take(0, 2).is_err(),
            "no terminator"
        );
        assert!(
            TableCursor { table, offset: 0 }.take(0, 30).is_err(),
            "out of range"
        );
        let inner_nul = b"o\0e\0";
        assert!(TableCursor {
            table: inner_nul,
            offset: 0
        }
        .take(0, 3)
        .is_err());
        let not_utf8 = b"\xff\xfe\0";
        assert!(TableCursor {
            table: not_utf8,
            offset: 0
        }
        .take(0, 2)
        .is_err());
    }

    /// RFC-0040: a v4 file relabelled as v3 must not verify.
    #[test]
    fn a_v4_file_relabelled_v3_is_rejected() {
        let fixture = v4_file();
        let mut bytes = ok(std::fs::read(&fixture.path));
        bytes[4] = 3;
        recompute_integrity(&mut bytes);
        ok(std::fs::write(&fixture.path, &bytes));
        let verdict = verify_file(&fixture.path, &fixture.registry);
        assert!(verdict.map_or(true, |report| !report.is_valid));
    }

    /// Found by the byte-flip property: the parser rebuilds audit entries
    /// and drops their reserved bytes, so v4 checks the stored bytes.
    #[test]
    fn a_nonzero_audit_reserved_byte_fails_v4() {
        let fixture = v4_file();
        let mut bytes = ok(std::fs::read(&fixture.path));
        let audit_at = {
            let parser = ok(AionParser::new(&bytes));
            parser.header().audit_trail_offset as usize
        };
        bytes[audit_at + 18] ^= 1;
        recompute_integrity(&mut bytes);
        assert!(!verify_bytes_of(&fixture, &bytes).is_valid);
    }

    /// RFC-0040: an audit entry with the wrong action for its position fails.
    #[test]
    fn a_wrong_audit_action_fails_v4() {
        let fixture = v4_file();
        let mut bytes = ok(std::fs::read(&fixture.path));
        let audit_at = {
            let parser = ok(AionParser::new(&bytes));
            parser.header().audit_trail_offset as usize
        };
        bytes[audit_at + 16..audit_at + 18]
            .copy_from_slice(&(ActionCode::Verify as u16).to_le_bytes());
        recompute_integrity(&mut bytes);
        assert!(!verify_bytes_of(&fixture, &bytes).is_valid);
    }

    /// Two versions' equal-length messages swapped: each commitment is per
    /// version, so the swap fails.
    #[test]
    fn swapping_equal_length_messages_between_versions_fails() {
        let fixture = v4_file();
        let mut bytes = ok(std::fs::read(&fixture.path));
        let first = position(&bytes, APPROVAL);
        let second = position(&bytes, b"Raised by: Bob");
        let swapped_first: Vec<u8> = b"Raised by: Bob".to_vec();
        bytes[first..first + 14].copy_from_slice(&swapped_first);
        bytes[second..second + 14].copy_from_slice(&APPROVAL[..14]);
        recompute_integrity(&mut bytes);
        assert!(!verify_bytes_of(&fixture, &bytes).is_valid);
    }

    #[test]
    fn writers_refuse_nul_in_v4_messages() {
        let dir = ok(TempDir::new());
        let key = ok(SigningKey::generate());
        let init = InitOptions {
            author_id: AuthorId::new(40_002),
            signing_key: &key,
            message: "approved\0by",
            timestamp: None,
            protection: RulesProtection::Public,
        };
        assert!(init_file(&dir.path().join("nul.aion"), b"r", &init).is_err());
        assert!(!dir.path().join("nul.aion").exists());

        let fixture = v4_file();
        let before = ok(std::fs::read(&fixture.path));
        let signer = ok(SigningKey::generate());
        let commit = CommitOptions {
            author_id: AuthorId::new(40_001),
            signing_key: &signer,
            message: "bad\0message",
            timestamp: None,
            protection: RulesProtection::Public,
        };
        assert!(commit_version(&fixture.path, b"r", &commit, &fixture.registry).is_err());
        assert_eq!(ok(std::fs::read(&fixture.path)), before);
    }

    /// S1: committing on a v4 file whose history was forged is refused
    /// before anything is signed, and the file is left as it was.
    #[test]
    fn committing_on_forged_v4_history_is_refused() {
        let dir = ok(TempDir::new());
        let path = dir.path().join("forged.aion");
        let key = ok(SigningKey::generate());
        let master = ok(SigningKey::generate());
        let author = AuthorId::new(40_003);
        let mut registry = KeyRegistry::new();
        ok(registry.register_author(author, master.verifying_key(), key.verifying_key(), 0));
        let init = InitOptions {
            author_id: author,
            signing_key: &key,
            message: ok(std::str::from_utf8(APPROVAL)),
            timestamp: None,
            protection: RulesProtection::Public,
        };
        ok(init_file(&path, b"r", &init));
        let mut bytes = ok(std::fs::read(&path));
        let at = position(&bytes, APPROVAL);
        bytes[at..at + FORGERY.len()].copy_from_slice(FORGERY);
        recompute_integrity(&mut bytes);
        ok(std::fs::write(&path, &bytes));
        let commit = CommitOptions {
            author_id: author,
            signing_key: &key,
            message: "next",
            timestamp: None,
            protection: RulesProtection::Public,
        };
        assert!(commit_version(&path, b"r2", &commit, &registry).is_err());
        assert_eq!(ok(std::fs::read(&path)), bytes);
    }

    #[test]
    fn audit_hash_v4_matches_golden_layout() {
        let audit = AuditEntry::new(
            0x0102_0304,
            AuthorId::new(9),
            ActionCode::MigratedFrom,
            0,
            0,
            [0x77; 32],
        );
        let mut input = b"AION_V4_AUDIT_ENTRY_V1\0".to_vec();
        input.extend_from_slice(audit.as_bytes());
        input.extend_from_slice(&4u32.to_le_bytes());
        input.extend_from_slice(b"link");
        assert_eq!(
            ok(audit_hash_v4(&audit, b"link")),
            *blake3::hash(&input).as_bytes()
        );
    }

    /// RFC-0021 attestations on a v4 file sign the v4 attestation message
    /// and pass a K-of-N policy.
    #[test]
    fn multisig_attestations_verify_on_v4() {
        let fixture = v4_file();
        let bytes = ok(std::fs::read(&fixture.path));
        let parser = ok(AionParser::new(&bytes));
        let context = ok(parser.header().context());
        let head = ok(parser.get_version_entry(1));
        let mut registry = KeyRegistry::new();
        let mut signatures = Vec::new();
        let mut signers = Vec::new();
        for id in [41_001u64, 41_002] {
            let key = ok(SigningKey::generate());
            let master = ok(SigningKey::generate());
            ok(registry.register_author(
                AuthorId::new(id),
                master.verifying_key(),
                key.verifying_key(),
                0,
            ));
            signatures.push(ok(context.sign_attestation(&head, AuthorId::new(id), &key)));
            signers.push(AuthorId::new(id));
        }
        let policy = ok(crate::multisig::MultiSigPolicy::new(2, signers));
        let verdict = ok(context.verify_multisig(&head, &signatures, &policy, &registry));
        assert!(verdict.threshold_met);
        let message = ok(context.attestation_message(&head, AuthorId::new(41_001)));
        assert!(message.starts_with(crate::signature_chain::ATTESTATION_DOMAIN_V4));
    }

    mod properties {
        use super::*;
        use hegel::generators as gs;

        fn draw_message(tc: &hegel::TestCase) -> String {
            let raw = tc.draw(gs::text().max_size(48));
            raw.replace('\0', "")
        }

        fn grow(tc: &hegel::TestCase) -> (Fixture, Vec<String>) {
            let dir = ok(TempDir::new());
            let path = dir.path().join("p.aion");
            let key = ok(SigningKey::generate());
            let master = ok(SigningKey::generate());
            let author = AuthorId::new(40_100);
            let mut registry = KeyRegistry::new();
            ok(registry.register_author(author, master.verifying_key(), key.verifying_key(), 0));
            let count = tc.draw(gs::integers::<usize>().min_value(1).max_value(4));
            let messages: Vec<String> = (0..count).map(|_| draw_message(tc)).collect();
            for (index, message) in messages.iter().enumerate() {
                if index == 0 {
                    let init = InitOptions {
                        author_id: author,
                        signing_key: &key,
                        message,
                        timestamp: None,
                        protection: RulesProtection::Public,
                    };
                    ok(init_file(&path, b"r", &init));
                } else {
                    let commit = CommitOptions {
                        author_id: author,
                        signing_key: &key,
                        message,
                        timestamp: None,
                        protection: RulesProtection::Public,
                    };
                    ok(commit_version(&path, b"r", &commit, &registry));
                }
            }
            (
                Fixture {
                    _dir: dir,
                    path,
                    registry,
                },
                messages,
            )
        }

        #[hegel::test]
        fn prop_v4_history_round_trips_exactly_the_signed_messages(tc: hegel::TestCase) {
            let (fixture, messages) = grow(&tc);
            let chain = ok(crate::chain::verify_file_chain(
                &fixture.path,
                &fixture.registry,
            ));
            assert!(chain.metadata_signed());
            let shown: Vec<String> = crate::chain::verified_history(&chain)
                .into_iter()
                .map(|v| v.message)
                .collect();
            assert_eq!(shown, messages);
        }

        #[hegel::test]
        fn prop_any_byte_flip_anywhere_in_a_v4_file_fails(tc: hegel::TestCase) {
            let (fixture, _) = grow(&tc);
            let mut bytes = ok(std::fs::read(&fixture.path));
            let body_end = bytes.len().saturating_sub(33);
            let index = tc.draw(gs::integers::<usize>().max_value(body_end));
            let flip = tc.draw(gs::integers::<u8>().min_value(1));
            bytes[index] ^= flip;
            recompute_integrity(&mut bytes);
            ok(std::fs::write(&fixture.path, &bytes));
            let verdict = verify_file(&fixture.path, &fixture.registry);
            assert!(
                verdict.map_or(true, |report| !report.is_valid),
                "byte {index}"
            );
        }

        #[hegel::test]
        fn prop_any_string_table_or_audit_byte_flip_fails_v4(tc: hegel::TestCase) {
            let (fixture, _) = grow(&tc);
            let mut bytes = ok(std::fs::read(&fixture.path));
            let (start, end) = {
                let parser = ok(AionParser::new(&bytes));
                let header = parser.header();
                let start = header.audit_trail_offset as usize;
                let end = header
                    .string_table_offset
                    .saturating_add(header.string_table_length) as usize;
                (start, end)
            };
            if end <= start {
                return;
            }
            let last = end.saturating_sub(1);
            let index = tc.draw(gs::integers::<usize>().min_value(start).max_value(last));
            let flip = tc.draw(gs::integers::<u8>().min_value(1));
            bytes[index] ^= flip;
            recompute_integrity(&mut bytes);
            ok(std::fs::write(&fixture.path, &bytes));
            let verdict = verify_file(&fixture.path, &fixture.registry);
            assert!(verdict.map_or(true, |report| !report.is_valid));
        }
    }
}
