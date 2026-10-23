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
pub(crate) struct VersionMetadata {
    /// The commit message.
    pub(crate) message: String,
    /// The version's audit entry.
    pub(crate) audit: AuditEntry,
    /// The audit entry's details text (empty unless it is `MigratedFrom`).
    pub(crate) details: String,
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
pub(crate) fn verify_v4_metadata(
    parser: &AionParser<'_>,
    versions: &[VersionEntry],
) -> Result<Vec<VersionMetadata>> {
    let header = parser.header();
    if header.audit_trail_count != header.version_chain_count {
        return Err(rejected(
            "audit_version_mismatch: audit count != version count",
        ));
    }
    let table = parser.string_table_bytes()?;
    let mut cursor = TableCursor { table, offset: 0 };
    let mut previous = [0u8; 32];
    let mut verified = Vec::with_capacity(versions.len());
    for (index, version) in versions.iter().enumerate() {
        let audit = parser.get_audit_entry(index)?;
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
pub(crate) fn audit_hash_v4(audit: &AuditEntry, details: &[u8]) -> Result<[u8; 32]> {
    let details_len = u32::try_from(details.len())
        .map_err(|_| rejected("string_table_noncanonical: details longer than u32::MAX"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(crate::audit::AUDIT_ENTRY_DOMAIN_V4);
    hasher.update(audit.as_bytes());
    hasher.update(&details_len.to_le_bytes());
    hasher.update(details);
    Ok(*hasher.finalize().as_bytes())
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
