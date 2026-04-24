//! Deterministic serializer for AION v2 file format
//!
//! This module provides deterministic serialization of AION v2 files as specified
//! in RFC-0002. Key properties:
//!
//! - **Deterministic**: Same data always produces identical bytes (enables signatures)
//! - **Atomic writes**: Files are written to temp location then renamed
//! - **Offset calculation**: Automatic calculation of section offsets
//! - **Roundtrip safe**: Serialize → parse → serialize produces identical output

use crate::audit::AuditEntry;
use crate::crypto::hash;
use crate::parser::{FileHeader, HASH_SIZE, HEADER_SIZE, SIGNATURE_ENTRY_SIZE, VERSION_ENTRY_SIZE};
use crate::types::{AuthorId, FileId, VersionNumber};
use crate::{AionError, Result};
use std::path::Path;
use zerocopy::AsBytes;

/// Size of audit entry in bytes
pub const AUDIT_ENTRY_SIZE: usize = 80;

/// Version chain entry for serialization (152 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy, AsBytes)]
pub struct VersionEntry {
    /// Version number (1, 2, 3, ...)
    pub version_number: u64,
    /// Parent hash (BLAKE3 of previous version rules), all zeros for genesis
    pub parent_hash: [u8; 32],
    /// Rules hash (BLAKE3 of this version's rules)
    pub rules_hash: [u8; 32],
    /// Author ID who created this version
    pub author_id: u64,
    /// Creation timestamp (nanoseconds since Unix epoch)
    pub timestamp: u64,
    /// Commit message offset in string table
    pub message_offset: u64,
    /// Commit message length (bytes)
    pub message_length: u32,
    /// Reserved (must be zero)
    pub reserved: [u8; 52],
}

const _: () = assert!(std::mem::size_of::<VersionEntry>() == VERSION_ENTRY_SIZE);

impl VersionEntry {
    /// Create a new version entry
    #[must_use]
    pub const fn new(
        version_number: VersionNumber,
        parent_hash: [u8; 32],
        rules_hash: [u8; 32],
        author_id: AuthorId,
        timestamp: u64,
        message_offset: u64,
        message_length: u32,
    ) -> Self {
        Self {
            version_number: version_number.as_u64(),
            parent_hash,
            rules_hash,
            author_id: author_id.as_u64(),
            timestamp,
            message_offset,
            message_length,
            reserved: [0; 52],
        }
    }
}

/// Signature entry for serialization (112 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy, AsBytes)]
pub struct SignatureEntry {
    /// Author ID
    pub author_id: u64,
    /// Ed25519 public key (32 bytes)
    pub public_key: [u8; 32],
    /// Ed25519 signature (64 bytes)
    pub signature: [u8; 64],
    /// Reserved (must be zero)
    pub reserved: [u8; 8],
}

const _: () = assert!(std::mem::size_of::<SignatureEntry>() == SIGNATURE_ENTRY_SIZE);

impl SignatureEntry {
    /// Create a new signature entry
    #[must_use]
    pub const fn new(author_id: AuthorId, public_key: [u8; 32], signature: [u8; 64]) -> Self {
        Self {
            author_id: author_id.as_u64(),
            public_key,
            signature,
            reserved: [0; 8],
        }
    }
}

/// AION file data for serialization
#[derive(Debug, Clone)]
pub struct AionFile {
    /// File ID
    pub file_id: FileId,
    /// Current version number
    pub current_version: VersionNumber,
    /// Feature flags (bit 0 = encrypted)
    pub flags: u16,
    /// Root hash (genesis version)
    pub root_hash: [u8; 32],
    /// Current hash (latest version)
    pub current_hash: [u8; 32],
    /// Creation timestamp (nanoseconds)
    pub created_at: u64,
    /// Modification timestamp (nanoseconds)
    pub modified_at: u64,
    /// Encrypted rules data (nonce + ciphertext + tag)
    pub encrypted_rules: Vec<u8>,
    /// Version chain entries
    pub versions: Vec<VersionEntry>,
    /// Signature entries
    pub signatures: Vec<SignatureEntry>,
    /// Audit trail entries
    pub audit_entries: Vec<AuditEntry>,
    /// String table (concatenated null-terminated strings)
    pub string_table: Vec<u8>,
}

impl AionFile {
    /// Create a new file builder
    #[must_use]
    pub fn builder() -> AionFileBuilder {
        AionFileBuilder::new()
    }
}

/// Builder for `AionFile`
#[derive(Debug, Default)]
pub struct AionFileBuilder {
    file_id: Option<FileId>,
    current_version: Option<VersionNumber>,
    flags: u16,
    root_hash: [u8; 32],
    current_hash: [u8; 32],
    created_at: Option<u64>,
    modified_at: Option<u64>,
    encrypted_rules: Vec<u8>,
    versions: Vec<VersionEntry>,
    signatures: Vec<SignatureEntry>,
    audit_entries: Vec<AuditEntry>,
    string_table: Vec<u8>,
}

impl AionFileBuilder {
    /// Create a new builder
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the file ID
    #[must_use]
    pub const fn file_id(mut self, id: FileId) -> Self {
        self.file_id = Some(id);
        self
    }

    /// Set the current version number
    #[must_use]
    pub const fn current_version(mut self, version: VersionNumber) -> Self {
        self.current_version = Some(version);
        self
    }

    /// Set the flags
    #[must_use]
    pub const fn flags(mut self, flags: u16) -> Self {
        self.flags = flags;
        self
    }

    /// Set encrypted flag
    #[must_use]
    pub const fn encrypted(mut self, encrypted: bool) -> Self {
        if encrypted {
            self.flags |= 0x0001;
        } else {
            self.flags &= !0x0001;
        }
        self
    }

    /// Set root hash
    #[must_use]
    pub const fn root_hash(mut self, hash: [u8; 32]) -> Self {
        self.root_hash = hash;
        self
    }

    /// Set current hash
    #[must_use]
    pub const fn current_hash(mut self, hash: [u8; 32]) -> Self {
        self.current_hash = hash;
        self
    }

    /// Set creation timestamp
    #[must_use]
    pub const fn created_at(mut self, timestamp: u64) -> Self {
        self.created_at = Some(timestamp);
        self
    }

    /// Set modification timestamp
    #[must_use]
    pub const fn modified_at(mut self, timestamp: u64) -> Self {
        self.modified_at = Some(timestamp);
        self
    }

    /// Set encrypted rules data
    #[must_use]
    pub fn encrypted_rules(mut self, data: Vec<u8>) -> Self {
        self.encrypted_rules = data;
        self
    }

    /// Add a version entry
    #[must_use]
    pub fn add_version(mut self, version: VersionEntry) -> Self {
        self.versions.push(version);
        self
    }

    /// Set all version entries
    #[must_use]
    pub fn versions(mut self, versions: Vec<VersionEntry>) -> Self {
        self.versions = versions;
        self
    }

    /// Add a signature entry
    #[must_use]
    pub fn add_signature(mut self, signature: SignatureEntry) -> Self {
        self.signatures.push(signature);
        self
    }

    /// Set all signature entries
    #[must_use]
    pub fn signatures(mut self, signatures: Vec<SignatureEntry>) -> Self {
        self.signatures = signatures;
        self
    }

    /// Add an audit entry
    #[must_use]
    pub fn add_audit_entry(mut self, entry: AuditEntry) -> Self {
        self.audit_entries.push(entry);
        self
    }

    /// Set all audit entries
    #[must_use]
    pub fn audit_entries(mut self, entries: Vec<AuditEntry>) -> Self {
        self.audit_entries = entries;
        self
    }

    /// Set string table
    #[must_use]
    pub fn string_table(mut self, table: Vec<u8>) -> Self {
        self.string_table = table;
        self
    }

    /// Build the file
    pub fn build(self) -> Result<AionFile> {
        let file_id = self.file_id.ok_or_else(|| AionError::InvalidFormat {
            reason: "file_id is required".to_string(),
        })?;
        let created_at = self.created_at.ok_or_else(|| AionError::InvalidFormat {
            reason: "created_at is required".to_string(),
        })?;
        let modified_at = self.modified_at.ok_or_else(|| AionError::InvalidFormat {
            reason: "modified_at is required".to_string(),
        })?;
        let current_version = self.current_version.unwrap_or(if self.versions.is_empty() {
            VersionNumber(0)
        } else {
            VersionNumber(self.versions.len() as u64)
        });

        Ok(AionFile {
            file_id,
            current_version,
            flags: self.flags,
            root_hash: self.root_hash,
            current_hash: self.current_hash,
            created_at,
            modified_at,
            encrypted_rules: self.encrypted_rules,
            versions: self.versions,
            signatures: self.signatures,
            audit_entries: self.audit_entries,
            string_table: self.string_table,
        })
    }
}

/// Serializer for AION v2 files
pub struct AionSerializer;

impl AionSerializer {
    /// Serialize an AION file to bytes (deterministic output)
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::arithmetic_side_effects)] // Sizes are bounded by input
    pub fn serialize(file: &AionFile) -> Result<Vec<u8>> {
        let sizes = SectionSizes::from_file(file);
        let offsets = SectionOffsets::from_sizes(&sizes);
        let header = build_header(file, &sizes, &offsets);

        let mut buffer = Vec::with_capacity(sizes.total);
        buffer.extend_from_slice(header.as_bytes());
        write_body_sections(&mut buffer, file);
        let integrity_hash = hash(&buffer);
        buffer.extend_from_slice(&integrity_hash);
        Ok(buffer)
    }

    /// Write an AION file atomically to disk (temp file + rename)
    pub fn write_atomic<P: AsRef<Path>>(file: &AionFile, path: P) -> Result<()> {
        let path = path.as_ref();
        let bytes = Self::serialize(file)?;

        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let temp_path = parent.join(format!(".aion-temp-{}.tmp", std::process::id()));

        std::fs::write(&temp_path, &bytes).map_err(|e| AionError::FileWriteError {
            path: temp_path.clone(),
            source: e,
        })?;

        std::fs::rename(&temp_path, path).map_err(|e| {
            let _ = std::fs::remove_file(&temp_path);
            AionError::FileWriteError {
                path: path.to_path_buf(),
                source: e,
            }
        })?;

        Ok(())
    }

    /// Build a string table from a list of strings
    #[must_use]
    pub fn build_string_table(strings: &[&str]) -> (Vec<u8>, Vec<u64>) {
        let mut table = Vec::new();
        let mut offsets = Vec::with_capacity(strings.len());
        for s in strings {
            offsets.push(table.len() as u64);
            table.extend_from_slice(s.as_bytes());
            table.push(0);
        }
        (table, offsets)
    }
}

#[allow(clippy::arithmetic_side_effects)]
struct SectionSizes {
    encrypted_rules: usize,
    version_chain: usize,
    signatures: usize,
    audit_trail: usize,
    string_table: usize,
    total: usize,
}

impl SectionSizes {
    #[allow(clippy::arithmetic_side_effects)]
    fn from_file(file: &AionFile) -> Self {
        let encrypted_rules = file.encrypted_rules.len();
        let version_chain = file.versions.len() * VERSION_ENTRY_SIZE;
        let signatures = file.signatures.len() * SIGNATURE_ENTRY_SIZE;
        let audit_trail = file.audit_entries.len() * AUDIT_ENTRY_SIZE;
        let string_table = file.string_table.len();
        let total = HEADER_SIZE
            + encrypted_rules
            + version_chain
            + signatures
            + audit_trail
            + string_table
            + HASH_SIZE;
        Self {
            encrypted_rules,
            version_chain,
            signatures,
            audit_trail,
            string_table,
            total,
        }
    }
}

#[allow(clippy::arithmetic_side_effects)]
struct SectionOffsets {
    encrypted_rules: u64,
    version_chain: u64,
    signatures: u64,
    audit_trail: u64,
    string_table: u64,
}

impl SectionOffsets {
    #[allow(clippy::arithmetic_side_effects)]
    const fn from_sizes(sizes: &SectionSizes) -> Self {
        let encrypted_rules = HEADER_SIZE as u64;
        let version_chain = encrypted_rules + sizes.encrypted_rules as u64;
        let signatures = version_chain + sizes.version_chain as u64;
        let audit_trail = signatures + sizes.signatures as u64;
        let string_table = audit_trail + sizes.audit_trail as u64;
        Self {
            encrypted_rules,
            version_chain,
            signatures,
            audit_trail,
            string_table,
        }
    }
}

#[allow(clippy::cast_possible_truncation)]
fn build_header(file: &AionFile, sizes: &SectionSizes, offsets: &SectionOffsets) -> FileHeader {
    FileHeader {
        magic: *b"AION",
        version: 2,
        flags: file.flags,
        file_id: file.file_id.as_u64(),
        current_version: file.current_version.as_u64(),
        root_hash: file.root_hash,
        current_hash: file.current_hash,
        created_at: file.created_at,
        modified_at: file.modified_at,
        encrypted_rules_offset: offsets.encrypted_rules,
        encrypted_rules_length: sizes.encrypted_rules as u64,
        version_chain_offset: offsets.version_chain,
        version_chain_count: file.versions.len() as u64,
        signatures_offset: offsets.signatures,
        signatures_count: file.signatures.len() as u64,
        audit_trail_offset: offsets.audit_trail,
        audit_trail_count: file.audit_entries.len() as u64,
        string_table_offset: offsets.string_table,
        string_table_length: sizes.string_table as u64,
        reserved: [0; 72],
    }
}

fn write_body_sections(buffer: &mut Vec<u8>, file: &AionFile) {
    buffer.extend_from_slice(&file.encrypted_rules);
    for version in &file.versions {
        buffer.extend_from_slice(version.as_bytes());
    }
    for signature in &file.signatures {
        buffer.extend_from_slice(signature.as_bytes());
    }
    for entry in &file.audit_entries {
        buffer.extend_from_slice(entry.as_bytes());
    }
    buffer.extend_from_slice(&file.string_table);
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::inconsistent_digit_grouping)]
mod tests {
    use super::*;
    use crate::audit::ActionCode;
    use crate::parser::AionParser;

    #[test]
    fn version_entry_should_have_correct_size() {
        assert_eq!(std::mem::size_of::<VersionEntry>(), VERSION_ENTRY_SIZE);
    }

    #[test]
    fn signature_entry_should_have_correct_size() {
        assert_eq!(std::mem::size_of::<SignatureEntry>(), SIGNATURE_ENTRY_SIZE);
    }

    #[test]
    fn should_build_minimal_file() {
        let file = AionFile::builder()
            .file_id(FileId::new(1))
            .created_at(1700000000_000_000_000)
            .modified_at(1700000000_000_000_000)
            .build()
            .unwrap();
        assert_eq!(file.file_id, FileId::new(1));
    }

    #[test]
    fn should_serialize_minimal_file() {
        let file = AionFile::builder()
            .file_id(FileId::new(42))
            .created_at(1700000000_000_000_000)
            .modified_at(1700000000_000_000_000)
            .build()
            .unwrap();
        let bytes = AionSerializer::serialize(&file).unwrap();
        assert!(bytes.len() >= HEADER_SIZE + HASH_SIZE);
    }

    #[test]
    fn should_produce_deterministic_output() {
        let file = AionFile::builder()
            .file_id(FileId::new(42))
            .created_at(1700000000_000_000_000)
            .modified_at(1700000000_000_000_000)
            .encrypted_rules(vec![1, 2, 3, 4])
            .build()
            .unwrap();
        let bytes1 = AionSerializer::serialize(&file).unwrap();
        let bytes2 = AionSerializer::serialize(&file).unwrap();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn should_roundtrip_minimal_file() {
        let file = AionFile::builder()
            .file_id(FileId::new(42))
            .current_version(VersionNumber(0))
            .created_at(1700000000_000_000_000)
            .modified_at(1700000000_000_000_000)
            .build()
            .unwrap();

        let bytes = AionSerializer::serialize(&file).unwrap();
        let parser = AionParser::new(&bytes).unwrap();
        let header = parser.header();

        assert_eq!(header.file_id, 42);
        assert_eq!(header.current_version, 0);
    }

    #[test]
    fn should_roundtrip_file_with_versions() {
        let (string_table, offsets) = AionSerializer::build_string_table(&["Genesis version"]);
        let version = VersionEntry::new(
            VersionNumber::GENESIS,
            [0; 32],
            [0xAB; 32],
            AuthorId::new(1001),
            1700000000_000_000_000,
            offsets[0],
            15,
        );
        let signature = SignatureEntry::new(AuthorId::new(1001), [0xCC; 32], [0xDD; 64]);

        let file = AionFile::builder()
            .file_id(FileId::new(100))
            .current_version(VersionNumber::GENESIS)
            .created_at(1700000000_000_000_000)
            .modified_at(1700000001_000_000_000)
            .encrypted_rules(vec![0u8; 64])
            .add_version(version)
            .add_signature(signature)
            .string_table(string_table)
            .encrypted(true)
            .build()
            .unwrap();

        let bytes = AionSerializer::serialize(&file).unwrap();
        let parser = AionParser::new(&bytes).unwrap();
        let header = parser.header();

        assert_eq!(header.file_id, 100);
        assert_eq!(header.current_version, 1);
        assert!(header.is_encrypted());
        assert_eq!(header.version_chain_count, 1);
        assert_eq!(header.signatures_count, 1);
    }

    #[test]
    fn should_roundtrip_with_audit_trail() {
        let audit_entry = AuditEntry::new(
            1700000000_000_000_000,
            AuthorId::new(1001),
            ActionCode::CreateGenesis,
            0,
            10,
            [0u8; 32],
        );

        let file = AionFile::builder()
            .file_id(FileId::new(1))
            .created_at(1700000000_000_000_000)
            .modified_at(1700000000_000_000_000)
            .add_audit_entry(audit_entry)
            .string_table(b"test entry\0".to_vec())
            .build()
            .unwrap();

        let bytes = AionSerializer::serialize(&file).unwrap();
        let parser = AionParser::new(&bytes).unwrap();
        assert_eq!(parser.header().audit_trail_count, 1);
    }

    #[test]
    fn should_verify_integrity_hash() {
        let file = AionFile::builder()
            .file_id(FileId::new(999))
            .created_at(1700000000_000_000_000)
            .modified_at(1700000000_000_000_000)
            .build()
            .unwrap();

        let bytes = AionSerializer::serialize(&file).unwrap();
        let hash_offset = bytes.len() - HASH_SIZE;
        let stored_hash = &bytes[hash_offset..];
        let computed_hash = hash(&bytes[..hash_offset]);
        assert_eq!(stored_hash, computed_hash);
    }

    #[test]
    fn should_calculate_correct_offsets() {
        let file = AionFile::builder()
            .file_id(FileId::new(1))
            .created_at(1700000000_000_000_000)
            .modified_at(1700000000_000_000_000)
            .encrypted_rules(vec![0u8; 100])
            .add_version(VersionEntry::new(
                VersionNumber(1),
                [0; 32],
                [0; 32],
                AuthorId::new(1),
                1700000000_000_000_000,
                0,
                0,
            ))
            .build()
            .unwrap();

        let bytes = AionSerializer::serialize(&file).unwrap();
        let parser = AionParser::new(&bytes).unwrap();
        let header = parser.header();

        assert_eq!(header.encrypted_rules_offset, HEADER_SIZE as u64);
        assert_eq!(header.encrypted_rules_length, 100);
        assert_eq!(header.version_chain_offset, HEADER_SIZE as u64 + 100);
        assert_eq!(header.version_chain_count, 1);
    }

    mod properties {
        use super::*;
        use hegel::generators as gs;

        fn draw_file(tc: &hegel::TestCase) -> AionFile {
            let file_id = tc.draw(gs::integers::<u64>());
            let created_at = tc.draw(gs::integers::<u64>().min_value(1).max_value(1u64 << 62));
            let bump = tc.draw(gs::integers::<u64>().max_value(10_000_000_000));
            let modified_at = created_at.saturating_add(bump);
            AionFile::builder()
                .file_id(FileId::new(file_id))
                .created_at(created_at)
                .modified_at(modified_at)
                .build()
                .unwrap_or_else(|_| std::process::abort())
        }

        #[hegel::test]
        fn prop_serialize_parse_integrity_holds(tc: hegel::TestCase) {
            let file = draw_file(&tc);
            let bytes = AionSerializer::serialize(&file).unwrap_or_else(|_| std::process::abort());
            let parser = AionParser::new(&bytes).unwrap_or_else(|_| std::process::abort());
            parser
                .verify_integrity()
                .unwrap_or_else(|_| std::process::abort());
        }

        #[hegel::test]
        fn prop_serialize_is_deterministic(tc: hegel::TestCase) {
            let file = draw_file(&tc);
            let a = AionSerializer::serialize(&file).unwrap_or_else(|_| std::process::abort());
            let b = AionSerializer::serialize(&file).unwrap_or_else(|_| std::process::abort());
            assert_eq!(a, b);
        }
    }
}
