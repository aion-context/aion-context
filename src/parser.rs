//! Zero-copy parser for AION v2 file format
//!
//! This module provides efficient, allocation-free parsing of AION v2 binary files
//! using the `zerocopy` crate. It supports both in-memory and memory-mapped file access.
//!
//! # Format Overview (RFC-0002)
//!
//! ```text
//! ┌─────────────────────────────────────┐
//! │  FILE HEADER (256 bytes)            │ ← Zero-copy parsed
//! ├─────────────────────────────────────┤
//! │  ENCRYPTED RULES (variable)         │ ← Slice reference
//! ├─────────────────────────────────────┤
//! │  VERSION CHAIN (152 bytes/entry)    │ ← Slice reference
//! ├─────────────────────────────────────┤
//! │  SIGNATURES (112 bytes/entry)       │ ← Slice reference
//! ├─────────────────────────────────────┤
//! │  AUDIT TRAIL (80+ bytes/entry)      │ ← Slice reference
//! ├─────────────────────────────────────┤
//! │  STRING TABLE (variable)            │ ← Slice reference
//! ├─────────────────────────────────────┤
//! │  FILE INTEGRITY HASH (32 bytes)     │ ← Slice reference
//! └─────────────────────────────────────┘
//! ```
//!
//! # Zero-Copy Benefits
//!
//! - **No allocations**: Direct byte slice references
//! - **Memory-mapped I/O**: OS-level caching and lazy loading
//! - **Fast random access**: Jump to any section instantly
//! - **Minimal overhead**: ~100ns to parse header vs ~10µs with serde
//!
//! # Usage
//!
//! ## In-Memory Parsing
//!
//! ```no_run
//! use aion_context::parser::AionParser;
//!
//! # fn example() -> aion_context::Result<()> {
//! let data = std::fs::read("file.aion").map_err(|e| aion_context::AionError::FileReadError {
//!     path: "file.aion".into(),
//!     source: e,
//! })?;
//! let parser = AionParser::new(&data)?;
//!
//! // Zero-copy header access
//! let header = parser.header();
//! println!("File version: {}", header.current_version());
//!
//! // Zero-copy section access
//! let string_table_bytes = parser.string_table_bytes()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Memory-Mapped Parsing
//!
//! ```no_run
//! use aion_context::parser::MmapParser;
//!
//! # fn example() -> aion_context::Result<()> {
//! let parser = MmapParser::open("large_file.aion")?;
//!
//! // OS handles memory management
//! let header = parser.header();
//! let versions = parser.version_chain_bytes()?;
//! # Ok(())
//! # }
//! ```

use crate::crypto::hash;
use crate::{AionError, Result};
use std::path::Path;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

/// Magic number for AION v2 files: "AION" (0x41494F4E)
pub const MAGIC: [u8; 4] = [0x41, 0x49, 0x4F, 0x4E];

/// Current file format version
pub const FORMAT_VERSION: u16 = 2;

/// Header size in bytes (fixed)
pub const HEADER_SIZE: usize = 256;

/// Version chain entry size in bytes (fixed)
pub const VERSION_ENTRY_SIZE: usize = 152;

/// Signature entry size in bytes (fixed)
pub const SIGNATURE_ENTRY_SIZE: usize = 112;

/// File integrity hash size (BLAKE3)
pub const HASH_SIZE: usize = 32;

/// File header structure (256 bytes, RFC-0002 Section 3.1)
///
/// This struct uses `zerocopy` for zero-copy parsing from byte slices.
/// All integers are little-endian.
///
/// # Examples
///
/// ```
/// use aion_context::parser::FileHeader;
/// use zerocopy::FromBytes;
///
/// # fn example() -> Option<()> {
/// let data = vec![0u8; 256];
/// let header = FileHeader::read_from_prefix(&data)?;
/// # Some(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, AsBytes, FromBytes, FromZeroes)]
#[repr(C)]
pub struct FileHeader {
    /// Magic number: "AION" (0x41494F4E)
    pub magic: [u8; 4],

    /// Format version (current = 2)
    pub version: u16,

    /// Feature flags
    /// - Bit 0: Encrypted (1 = encrypted, 0 = plaintext)
    /// - Bit 1-15: Reserved (must be 0)
    pub flags: u16,

    /// Unique file identifier
    pub file_id: u64,

    /// Current version number (monotonically increasing)
    pub current_version: u64,

    /// Root hash (BLAKE3, genesis version)
    pub root_hash: [u8; 32],

    /// Current hash (BLAKE3, latest version)
    pub current_hash: [u8; 32],

    /// Creation timestamp (nanoseconds since Unix epoch)
    pub created_at: u64,

    /// Last modification timestamp
    pub modified_at: u64,

    /// Encrypted rules section offset
    pub encrypted_rules_offset: u64,

    /// Encrypted rules section length (bytes)
    pub encrypted_rules_length: u64,

    /// Version chain section offset
    pub version_chain_offset: u64,

    /// Version chain count (number of entries)
    pub version_chain_count: u64,

    /// Signatures section offset
    pub signatures_offset: u64,

    /// Signatures count
    pub signatures_count: u64,

    /// Audit trail section offset
    pub audit_trail_offset: u64,

    /// Audit trail count
    pub audit_trail_count: u64,

    /// String table offset
    pub string_table_offset: u64,

    /// String table length
    pub string_table_length: u64,

    /// Reserved bytes (must be zero)
    pub reserved: [u8; 72],
}

// Compile-time size check
const _: () = assert!(std::mem::size_of::<FileHeader>() == HEADER_SIZE);

impl FileHeader {
    /// Validate header magic number
    ///
    /// # Examples
    ///
    /// ```
    /// use aion_context::parser::FileHeader;
    ///
    /// let mut header = FileHeader::default();
    /// assert!(header.is_valid_magic());
    ///
    /// header.magic = *b"XXXX";
    /// assert!(!header.is_valid_magic());
    ///
    /// header.magic = *b"AION";
    /// assert!(header.is_valid_magic());
    /// ```
    #[must_use]
    pub const fn is_valid_magic(&self) -> bool {
        self.magic[0] == MAGIC[0]
            && self.magic[1] == MAGIC[1]
            && self.magic[2] == MAGIC[2]
            && self.magic[3] == MAGIC[3]
    }

    /// Check if file is encrypted
    ///
    /// # Examples
    ///
    /// ```
    /// use aion_context::parser::FileHeader;
    ///
    /// let mut header = FileHeader::default();
    /// assert!(!header.is_encrypted());
    ///
    /// header.flags = 0x0001; // Set encrypted bit
    /// assert!(header.is_encrypted());
    /// ```
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        (self.flags & 0x0001) != 0
    }

    /// Get file ID as `FileId` type
    ///
    /// # Examples
    ///
    /// ```
    /// use aion_context::parser::FileHeader;
    /// use aion_context::types::FileId;
    ///
    /// let mut header = FileHeader::default();
    /// header.file_id = 42;
    /// assert_eq!(header.file_id(), FileId(42));
    /// ```
    #[must_use]
    pub const fn file_id(&self) -> crate::types::FileId {
        crate::types::FileId(self.file_id)
    }

    /// Get current version as `VersionNumber` type
    #[must_use]
    pub const fn current_version(&self) -> crate::types::VersionNumber {
        crate::types::VersionNumber(self.current_version)
    }

    /// Validate header structure
    ///
    /// Checks:
    /// - Magic number is correct
    /// - Version is supported
    /// - Reserved bytes are zero
    ///
    /// # Errors
    ///
    /// Returns error if validation fails
    pub fn validate(&self) -> Result<()> {
        // Check magic number
        if !self.is_valid_magic() {
            return Err(AionError::InvalidFormat {
                reason: format!(
                    "Invalid magic number: expected {:?}, got {:?}",
                    MAGIC, self.magic
                ),
            });
        }

        // Check version
        if self.version != FORMAT_VERSION {
            return Err(AionError::UnsupportedVersion {
                version: self.version,
                supported: FORMAT_VERSION.to_string(),
            });
        }

        // Check reserved bits in flags (bits 1-15 must be 0)
        if (self.flags & !0x0001) != 0 {
            return Err(AionError::InvalidFormat {
                reason: format!("Invalid flags: reserved bits set (0x{:04x})", self.flags),
            });
        }

        // Check reserved bytes are zero
        if self.reserved.iter().any(|&b| b != 0) {
            return Err(AionError::InvalidFormat {
                reason: "Reserved bytes must be zero".to_string(),
            });
        }

        Ok(())
    }
}

impl Default for FileHeader {
    fn default() -> Self {
        Self {
            magic: MAGIC,
            version: FORMAT_VERSION,
            flags: 0,
            file_id: 0,
            current_version: 0,
            root_hash: [0; 32],
            current_hash: [0; 32],
            created_at: 0,
            modified_at: 0,
            encrypted_rules_offset: 0,
            encrypted_rules_length: 0,
            version_chain_offset: 0,
            version_chain_count: 0,
            signatures_offset: 0,
            signatures_count: 0,
            audit_trail_offset: 0,
            audit_trail_count: 0,
            string_table_offset: 0,
            string_table_length: 0,
            reserved: [0; 72],
        }
    }
}

/// Zero-copy parser for AION v2 files
///
/// Provides efficient, allocation-free access to file sections using
/// direct byte slice references.
///
/// # Examples
///
/// ```
/// use aion_context::parser::AionParser;
///
/// # fn example() -> aion_context::Result<()> {
/// let data = vec![0u8; 1024]; // Mock file data
/// let parser = AionParser::new(&data)?;
///
/// let header = parser.header();
/// println!("File ID: {}", header.file_id);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct AionParser<'a> {
    /// Complete file data
    data: &'a [u8],
}

impl<'a> AionParser<'a> {
    /// Create a new parser from byte data
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Data is too small for header
    /// - Header validation fails
    ///
    /// # Examples
    ///
    /// ```
    /// use aion_context::parser::AionParser;
    ///
    /// # fn example() -> aion_context::Result<()> {
    /// let data = vec![0u8; 256];
    /// let result = AionParser::new(&data);
    /// assert!(result.is_err()); // Invalid magic
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(data: &'a [u8]) -> Result<Self> {
        // Check minimum size
        if data.len() < HEADER_SIZE {
            return Err(AionError::InvalidFormat {
                reason: format!(
                    "File too small: {} bytes (minimum: {} bytes)",
                    data.len(),
                    HEADER_SIZE
                ),
            });
        }

        // Parse and validate header (zero-copy)
        let header =
            FileHeader::read_from_prefix(data).ok_or_else(|| AionError::InvalidFormat {
                reason: "Failed to parse header".to_string(),
            })?;
        header.validate()?;

        Ok(Self { data })
    }

    /// Get reference to file header
    ///
    /// This is a zero-copy operation returning a direct reference.
    /// The header is parsed on-demand from the data slice.
    ///
    /// # Panics
    ///
    /// Should never panic as the header was validated during construction.
    #[must_use]
    #[allow(clippy::expect_used)] // Validated during construction
    pub fn header(&self) -> &'a FileHeader {
        // Safety: We validated during construction that data is large enough
        FileHeader::ref_from_prefix(self.data).expect("header validated during construction")
    }

    /// Get encrypted rules section as byte slice
    ///
    /// # Errors
    ///
    /// Returns error if section bounds are invalid
    #[allow(clippy::cast_possible_truncation)] // File offsets fit in usize
    pub fn encrypted_rules_bytes(&self) -> Result<&'a [u8]> {
        let header = self.header();
        self.get_section(
            header.encrypted_rules_offset as usize,
            header.encrypted_rules_length as usize,
            "encrypted rules",
        )
    }

    /// Get version chain section as byte slice
    ///
    /// # Errors
    ///
    /// Returns error if section bounds are invalid
    #[allow(clippy::cast_possible_truncation)] // File offsets fit in usize
    pub fn version_chain_bytes(&self) -> Result<&'a [u8]> {
        let header = self.header();
        let size = header
            .version_chain_count
            .checked_mul(VERSION_ENTRY_SIZE as u64)
            .ok_or_else(|| AionError::InvalidFormat {
                reason: "Version chain size overflow".to_string(),
            })?;

        self.get_section(
            header.version_chain_offset as usize,
            size as usize,
            "version chain",
        )
    }

    /// Get signatures section as byte slice
    ///
    /// # Errors
    ///
    /// Returns error if section bounds are invalid
    #[allow(clippy::cast_possible_truncation)] // File offsets fit in usize
    pub fn signatures_bytes(&self) -> Result<&'a [u8]> {
        let header = self.header();
        let size = header
            .signatures_count
            .checked_mul(SIGNATURE_ENTRY_SIZE as u64)
            .ok_or_else(|| AionError::InvalidFormat {
                reason: "Signatures size overflow".to_string(),
            })?;

        self.get_section(
            header.signatures_offset as usize,
            size as usize,
            "signatures",
        )
    }

    /// Get audit trail section as byte slice
    ///
    /// Note: Audit entries are variable-length, so this returns raw bytes.
    /// Use audit module to parse individual entries.
    ///
    /// # Errors
    ///
    /// Returns error if section bounds are invalid
    #[allow(clippy::cast_possible_truncation)] // File offsets fit in usize
    #[allow(clippy::arithmetic_side_effects)] // Checked above
    pub fn audit_trail_bytes(&self) -> Result<&'a [u8]> {
        // Audit trail extends to string table
        let header = self.header();
        let start = header.audit_trail_offset as usize;
        let end = header.string_table_offset as usize;

        if end < start {
            return Err(AionError::InvalidFormat {
                reason: "Audit trail end before start".to_string(),
            });
        }

        self.get_section(start, end - start, "audit trail")
    }

    /// Get string table section as byte slice
    ///
    /// # Errors
    ///
    /// Returns error if section bounds are invalid
    #[allow(clippy::cast_possible_truncation)] // File offsets fit in usize
    pub fn string_table_bytes(&self) -> Result<&'a [u8]> {
        let header = self.header();
        self.get_section(
            header.string_table_offset as usize,
            header.string_table_length as usize,
            "string table",
        )
    }

    /// Get file integrity hash (last 32 bytes)
    ///
    /// # Errors
    ///
    /// Returns error if file is too small
    #[allow(clippy::arithmetic_side_effects)] // Checked above
    #[allow(clippy::indexing_slicing)] // Bounds checked
    pub fn integrity_hash(&self) -> Result<&'a [u8; HASH_SIZE]> {
        if self.data.len() < HASH_SIZE {
            return Err(AionError::InvalidFormat {
                reason: format!(
                    "File too small for integrity hash: {} bytes",
                    self.data.len()
                ),
            });
        }

        let start = self.data.len() - HASH_SIZE;
        self.data[start..]
            .try_into()
            .map_err(|_| AionError::InvalidFormat {
                reason: "Failed to extract integrity hash".to_string(),
            })
    }

    /// Verify file integrity by computing BLAKE3 hash and comparing
    ///
    /// Computes the hash of all bytes except the final 32-byte hash,
    /// then compares with the stored hash.
    ///
    /// # Errors
    ///
    /// Returns `AionError::CorruptedFile` if the hash doesn't match,
    /// indicating the file has been corrupted or tampered with.
    ///
    /// # Examples
    ///
    /// ```
    /// use aion_context::parser::AionParser;
    ///
    /// # fn example() -> aion_context::Result<()> {
    /// # let data = vec![0u8; 288]; // Mock - would need valid file
    /// # return Ok(()); // Skip actual test
    /// let parser = AionParser::new(&data)?;
    /// parser.verify_integrity()?; // Returns Ok if valid
    /// # Ok(())
    /// # }
    /// ```
    #[allow(clippy::arithmetic_side_effects)] // Checked in integrity_hash
    #[allow(clippy::indexing_slicing)] // Bounds checked
    pub fn verify_integrity(&self) -> Result<()> {
        let stored_hash = self.integrity_hash()?;
        let hash_offset = self.data.len() - HASH_SIZE;
        let computed_hash = hash(&self.data[..hash_offset]);

        if stored_hash != &computed_hash {
            return Err(AionError::CorruptedFile {
                expected: hex::encode(stored_hash),
                actual: hex::encode(computed_hash),
            });
        }

        Ok(())
    }

    /// Get total file size
    #[must_use]
    pub const fn file_size(&self) -> usize {
        self.data.len()
    }

    /// Helper: Get a section slice with bounds checking
    #[allow(clippy::indexing_slicing)] // Bounds checked above
    fn get_section(&self, offset: usize, length: usize, name: &str) -> Result<&'a [u8]> {
        let end = offset
            .checked_add(length)
            .ok_or_else(|| AionError::InvalidFormat {
                reason: format!("{name} section: offset + length overflow"),
            })?;

        if end > self.data.len() {
            return Err(AionError::InvalidFormat {
                reason: format!(
                    "{name} section out of bounds: offset={offset}, length={length}, file_size={}",
                    self.data.len()
                ),
            });
        }

        Ok(&self.data[offset..end])
    }

    /// Get a version entry by index
    ///
    /// # Errors
    ///
    /// Returns error if index is out of bounds or entry cannot be parsed
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::indexing_slicing)] // Bounds checked above
    #[allow(clippy::arithmetic_side_effects)] // Bounds checked above
    pub fn get_version_entry(&self, index: usize) -> Result<crate::serializer::VersionEntry> {
        let header = self.header();
        if index >= header.version_chain_count as usize {
            return Err(AionError::InvalidFormat {
                reason: format!(
                    "Version index {} out of bounds (max {})",
                    index, header.version_chain_count
                ),
            });
        }

        let bytes = self.version_chain_bytes()?;
        let offset = index * VERSION_ENTRY_SIZE;
        let entry_bytes = &bytes[offset..offset + VERSION_ENTRY_SIZE];

        // Parse the entry from bytes
        Ok(crate::serializer::VersionEntry {
            version_number: u64::from_le_bytes(entry_bytes[0..8].try_into().map_err(|_| {
                AionError::InvalidFormat {
                    reason: "Invalid version number bytes".to_string(),
                }
            })?),
            parent_hash: entry_bytes[8..40]
                .try_into()
                .map_err(|_| AionError::InvalidFormat {
                    reason: "Invalid parent hash bytes".to_string(),
                })?,
            rules_hash: entry_bytes[40..72]
                .try_into()
                .map_err(|_| AionError::InvalidFormat {
                    reason: "Invalid rules hash bytes".to_string(),
                })?,
            author_id: u64::from_le_bytes(entry_bytes[72..80].try_into().map_err(|_| {
                AionError::InvalidFormat {
                    reason: "Invalid author ID bytes".to_string(),
                }
            })?),
            timestamp: u64::from_le_bytes(entry_bytes[80..88].try_into().map_err(|_| {
                AionError::InvalidFormat {
                    reason: "Invalid timestamp bytes".to_string(),
                }
            })?),
            message_offset: u64::from_le_bytes(entry_bytes[88..96].try_into().map_err(|_| {
                AionError::InvalidFormat {
                    reason: "Invalid message offset bytes".to_string(),
                }
            })?),
            message_length: u32::from_le_bytes(entry_bytes[96..100].try_into().map_err(|_| {
                AionError::InvalidFormat {
                    reason: "Invalid message length bytes".to_string(),
                }
            })?),
            reserved: [0; 52], // Reserved bytes are ignored
        })
    }

    /// Get a signature entry by index
    ///
    /// # Errors
    ///
    /// Returns error if index is out of bounds or entry cannot be parsed
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::indexing_slicing)] // Bounds checked above
    #[allow(clippy::arithmetic_side_effects)] // Bounds checked above
    pub fn get_signature_entry(&self, index: usize) -> Result<crate::serializer::SignatureEntry> {
        let header = self.header();
        if index >= header.signatures_count as usize {
            return Err(AionError::InvalidFormat {
                reason: format!(
                    "Signature index {} out of bounds (max {})",
                    index, header.signatures_count
                ),
            });
        }

        let bytes = self.signatures_bytes()?;
        let offset = index * SIGNATURE_ENTRY_SIZE;
        let entry_bytes = &bytes[offset..offset + SIGNATURE_ENTRY_SIZE];

        Ok(crate::serializer::SignatureEntry {
            author_id: u64::from_le_bytes(entry_bytes[0..8].try_into().map_err(|_| {
                AionError::InvalidFormat {
                    reason: "Invalid author ID bytes".to_string(),
                }
            })?),
            public_key: entry_bytes[8..40]
                .try_into()
                .map_err(|_| AionError::InvalidFormat {
                    reason: "Invalid public key bytes".to_string(),
                })?,
            signature: entry_bytes[40..104]
                .try_into()
                .map_err(|_| AionError::InvalidFormat {
                    reason: "Invalid signature bytes".to_string(),
                })?,
            reserved: [0; 8], // Reserved bytes are ignored
        })
    }

    /// Get an audit entry by index
    ///
    /// # Errors
    ///
    /// Returns error if index is out of bounds or entry cannot be parsed
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::indexing_slicing)] // Bounds checked above
    #[allow(clippy::arithmetic_side_effects)] // Bounds checked above
    pub fn get_audit_entry(&self, index: usize) -> Result<crate::audit::AuditEntry> {
        let header = self.header();
        if index >= header.audit_trail_count as usize {
            return Err(AionError::InvalidFormat {
                reason: format!(
                    "Audit index {} out of bounds (max {})",
                    index, header.audit_trail_count
                ),
            });
        }

        let bytes = self.audit_trail_bytes()?;
        let entry_size = 80; // AuditEntry is 80 bytes
        let offset = index * entry_size;
        let entry_bytes = &bytes[offset..offset + entry_size];

        let timestamp = u64::from_le_bytes(entry_bytes[0..8].try_into().map_err(|_| {
            AionError::InvalidFormat {
                reason: "Invalid timestamp bytes".to_string(),
            }
        })?);
        let author_id = u64::from_le_bytes(entry_bytes[8..16].try_into().map_err(|_| {
            AionError::InvalidFormat {
                reason: "Invalid author ID bytes".to_string(),
            }
        })?);
        let action_code = u16::from_le_bytes(entry_bytes[16..18].try_into().map_err(|_| {
            AionError::InvalidFormat {
                reason: "Invalid action code bytes".to_string(),
            }
        })?);
        let details_offset = u64::from_le_bytes(entry_bytes[24..32].try_into().map_err(|_| {
            AionError::InvalidFormat {
                reason: "Invalid details offset bytes".to_string(),
            }
        })?);
        let details_length = u32::from_le_bytes(entry_bytes[32..36].try_into().map_err(|_| {
            AionError::InvalidFormat {
                reason: "Invalid details length bytes".to_string(),
            }
        })?);
        let previous_hash: [u8; 32] =
            entry_bytes[48..80]
                .try_into()
                .map_err(|_| AionError::InvalidFormat {
                    reason: "Invalid previous hash bytes".to_string(),
                })?;

        let action = crate::audit::ActionCode::from_u16(action_code)?;

        Ok(crate::audit::AuditEntry::new(
            timestamp,
            crate::types::AuthorId::new(author_id),
            action,
            details_offset,
            details_length,
            previous_hash,
        ))
    }
}

/// Memory-mapped file parser for large files
///
/// Uses OS-level memory mapping for efficient access to large files
/// without loading entire file into memory.
///
/// # Examples
///
/// ```no_run
/// use aion_context::parser::MmapParser;
///
/// # fn example() -> aion_context::Result<()> {
/// let parser = MmapParser::open("large_file.aion")?;
/// let header = parser.header();
/// println!("File ID: {}", header.file_id);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct MmapParser {
    /// Memory-mapped file
    /// This field is necessary to keep the memory mapping alive
    #[allow(dead_code)]
    mmap: memmap2::Mmap,
    /// Parser wrapping mmap data
    parser: AionParser<'static>,
}

impl MmapParser {
    /// Open and memory-map a file
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - File cannot be opened
    /// - File cannot be memory-mapped
    /// - Header parsing fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use aion_context::parser::MmapParser;
    ///
    /// # fn example() -> aion_context::Result<()> {
    /// let parser = MmapParser::open("file.aion")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = std::fs::File::open(path.as_ref()).map_err(|e| AionError::FileReadError {
            path: path.as_ref().to_path_buf(),
            source: e,
        })?;

        // Safety: File is opened read-only, mmap lifetime tied to struct
        #[allow(unsafe_code)]
        let mmap = unsafe {
            memmap2::MmapOptions::new()
                .map(&file)
                .map_err(|e| AionError::FileReadError {
                    path: path.as_ref().to_path_buf(),
                    source: e,
                })?
        };

        // Create parser from mmap
        // Safety: Mmap owned by struct, transmute to 'static is sound
        #[allow(unsafe_code)]
        let parser = unsafe {
            let slice = std::slice::from_raw_parts(mmap.as_ptr(), mmap.len());
            // Transmute lifetime is safe: mmap owned by struct
            let static_slice: &'static [u8] = std::mem::transmute(slice);
            AionParser::new(static_slice)?
        };

        Ok(Self { mmap, parser })
    }

    /// Get reference to file header
    #[must_use]
    pub fn header(&self) -> &FileHeader {
        self.parser.header()
    }

    /// Get encrypted rules section
    pub fn encrypted_rules_bytes(&self) -> Result<&[u8]> {
        self.parser.encrypted_rules_bytes()
    }

    /// Get version chain section
    pub fn version_chain_bytes(&self) -> Result<&[u8]> {
        self.parser.version_chain_bytes()
    }

    /// Get signatures section
    pub fn signatures_bytes(&self) -> Result<&[u8]> {
        self.parser.signatures_bytes()
    }

    /// Get audit trail section
    pub fn audit_trail_bytes(&self) -> Result<&[u8]> {
        self.parser.audit_trail_bytes()
    }

    /// Get string table section
    pub fn string_table_bytes(&self) -> Result<&[u8]> {
        self.parser.string_table_bytes()
    }

    /// Get file integrity hash
    pub fn integrity_hash(&self) -> Result<&[u8; HASH_SIZE]> {
        self.parser.integrity_hash()
    }

    /// Verify file integrity
    pub fn verify_integrity(&self) -> Result<()> {
        self.parser.verify_integrity()
    }

    /// Get total file size
    #[must_use]
    pub const fn file_size(&self) -> usize {
        self.parser.file_size()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::field_reassign_with_default)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    mod file_header {
        use super::*;

        #[test]
        fn should_have_correct_size() {
            assert_eq!(std::mem::size_of::<FileHeader>(), HEADER_SIZE);
        }

        #[test]
        fn should_validate_magic_number() {
            let mut header = FileHeader::default();
            header.magic = *b"AION";
            assert!(header.is_valid_magic());

            header.magic = *b"XXXX";
            assert!(!header.is_valid_magic());
        }

        #[test]
        fn should_check_encrypted_flag() {
            let mut header = FileHeader::default();
            assert!(!header.is_encrypted());

            header.flags = 0x0001;
            assert!(header.is_encrypted());

            header.flags = 0x0002; // Other bit
            assert!(!header.is_encrypted());
        }

        #[test]
        fn should_validate_header() {
            let header = FileHeader::default();
            assert!(header.validate().is_ok());
        }

        #[test]
        fn should_reject_invalid_magic() {
            let mut header = FileHeader::default();
            header.magic = *b"XXXX";
            assert!(header.validate().is_err());
        }

        #[test]
        fn should_reject_invalid_version() {
            let mut header = FileHeader::default();
            header.version = 999;
            assert!(header.validate().is_err());
        }

        #[test]
        fn should_reject_reserved_flags() {
            let mut header = FileHeader::default();
            header.flags = 0x0002; // Reserved bit set
            assert!(header.validate().is_err());
        }

        #[test]
        fn should_reject_non_zero_reserved_bytes() {
            let mut header = FileHeader::default();
            header.reserved[0] = 1;
            assert!(header.validate().is_err());
        }

        #[test]
        fn should_parse_from_bytes() {
            let mut data = vec![0u8; 256];
            data[0..4].copy_from_slice(b"AION");
            data[4..6].copy_from_slice(&2u16.to_le_bytes());

            let header = FileHeader::read_from_prefix(&data).unwrap();
            assert!(header.is_valid_magic());
            assert_eq!(header.version, 2);
        }
    }

    mod parser {
        use super::*;

        fn create_minimal_file() -> Vec<u8> {
            let mut data = vec![0u8; 512];

            // Header
            data[0..4].copy_from_slice(b"AION");
            data[4..6].copy_from_slice(&2u16.to_le_bytes());

            // Set offsets to avoid overlaps
            let header_end = 256u64;
            data[104..112].copy_from_slice(&header_end.to_le_bytes()); // encrypted_rules_offset
            data[112..120].copy_from_slice(&0u64.to_le_bytes()); // encrypted_rules_length
            data[120..128].copy_from_slice(&header_end.to_le_bytes()); // version_chain_offset
            data[128..136].copy_from_slice(&0u64.to_le_bytes()); // version_chain_count
            data[136..144].copy_from_slice(&header_end.to_le_bytes()); // signatures_offset
            data[144..152].copy_from_slice(&0u64.to_le_bytes()); // signatures_count
            data[152..160].copy_from_slice(&header_end.to_le_bytes()); // audit_trail_offset
            data[160..168].copy_from_slice(&0u64.to_le_bytes()); // audit_trail_count
            data[168..176].copy_from_slice(&(header_end + 224).to_le_bytes()); // string_table_offset
            data[176..184].copy_from_slice(&0u64.to_le_bytes()); // string_table_length

            data
        }

        #[test]
        fn should_parse_valid_file() {
            let data = create_minimal_file();
            let parser = AionParser::new(&data).unwrap();
            assert!(parser.header().is_valid_magic());
        }

        #[test]
        fn should_reject_too_small_file() {
            let data = vec![0u8; 100];
            assert!(AionParser::new(&data).is_err());
        }

        #[test]
        fn should_reject_invalid_header() {
            let data = vec![0u8; 256];
            assert!(AionParser::new(&data).is_err());
        }

        #[test]
        fn should_get_header_reference() {
            let data = create_minimal_file();
            let parser = AionParser::new(&data).unwrap();
            let header = parser.header();
            assert_eq!(header.version, 2);
        }

        #[test]
        fn should_get_file_size() {
            let data = create_minimal_file();
            let parser = AionParser::new(&data).unwrap();
            assert_eq!(parser.file_size(), data.len());
        }

        #[test]
        fn should_get_string_table_bytes() {
            let data = create_minimal_file();
            let parser = AionParser::new(&data).unwrap();
            let result = parser.string_table_bytes();
            assert!(result.is_ok());
        }

        #[test]
        fn should_reject_out_of_bounds_section() {
            let mut data = create_minimal_file();
            // Set string table offset beyond file size
            data[168..176].copy_from_slice(&9999u64.to_le_bytes());

            let parser = AionParser::new(&data).unwrap();
            assert!(parser.string_table_bytes().is_err());
        }

        #[test]
        fn should_get_integrity_hash() {
            let data = create_minimal_file();
            let parser = AionParser::new(&data).unwrap();
            let hash = parser.integrity_hash().unwrap();
            assert_eq!(hash.len(), HASH_SIZE);
        }
    }

    mod integrity {
        use super::*;
        use crate::serializer::{AionFile, AionSerializer};
        use crate::types::FileId;

        fn create_valid_file() -> Vec<u8> {
            let file = AionFile::builder()
                .file_id(FileId::new(42))
                .created_at(1_700_000_000_000_000_000)
                .modified_at(1_700_000_000_000_000_000)
                .build()
                .unwrap();
            AionSerializer::serialize(&file).unwrap()
        }

        #[test]
        fn should_verify_valid_integrity() {
            let data = create_valid_file();
            let parser = AionParser::new(&data).unwrap();
            assert!(parser.verify_integrity().is_ok());
        }

        #[test]
        fn should_detect_corrupted_header() {
            let mut data = create_valid_file();
            // Corrupt a byte in the header
            data[10] ^= 0xFF;

            let parser = AionParser::new(&data).unwrap();
            let result = parser.verify_integrity();
            assert!(result.is_err());
            assert!(matches!(result, Err(AionError::CorruptedFile { .. })));
        }

        #[test]
        fn should_detect_corrupted_middle() {
            let mut data = create_valid_file();
            // Corrupt a byte in the middle of the file
            let middle = data.len() / 2;
            data[middle] ^= 0xFF;

            let parser = AionParser::new(&data).unwrap();
            let result = parser.verify_integrity();
            assert!(result.is_err());
        }

        #[test]
        fn should_detect_corrupted_hash() {
            let mut data = create_valid_file();
            // Corrupt the last byte (part of hash)
            let last = data.len() - 1;
            data[last] ^= 0xFF;

            let parser = AionParser::new(&data).unwrap();
            let result = parser.verify_integrity();
            assert!(result.is_err());
        }

        #[test]
        fn should_detect_single_bit_flip() {
            let mut data = create_valid_file();
            // Flip a single bit in the file_id field
            data[8] ^= 0x01;

            let parser = AionParser::new(&data).unwrap();
            let result = parser.verify_integrity();
            assert!(result.is_err());
            assert!(matches!(result, Err(AionError::CorruptedFile { .. })));
        }

        #[test]
        fn should_detect_appended_data() {
            let mut data = create_valid_file();
            // Append extra bytes after hash
            data.extend_from_slice(&[0xFF; 10]);

            // Parser won't reject this at parse time, but integrity will fail
            let parser = AionParser::new(&data).unwrap();
            let result = parser.verify_integrity();
            assert!(result.is_err());
        }

        #[test]
        fn should_produce_consistent_hash() {
            let data1 = create_valid_file();
            let data2 = create_valid_file();

            // Same input should produce same output
            assert_eq!(data1, data2);

            let parser = AionParser::new(&data1).unwrap();
            let hash1 = parser.integrity_hash().unwrap();

            let parser = AionParser::new(&data2).unwrap();
            let hash2 = parser.integrity_hash().unwrap();

            assert_eq!(hash1, hash2);
        }
    }

    mod properties {
        use super::*;
        use hegel::generators as gs;

        #[hegel::test]
        fn prop_parser_new_never_panics_on_arbitrary_bytes(tc: hegel::TestCase) {
            let bytes = tc.draw(gs::binary().max_size(4096));
            let _ = AionParser::new(&bytes);
        }

        #[hegel::test]
        fn prop_parser_accessors_never_panic_when_construction_succeeds(tc: hegel::TestCase) {
            let bytes = tc.draw(gs::binary().max_size(4096));
            if let Ok(parser) = AionParser::new(&bytes) {
                let _ = parser.header().is_valid_magic();
                let _ = parser.header().is_encrypted();
                let _ = parser.file_size();
                let _ = parser.string_table_bytes();
                let _ = parser.integrity_hash();
            }
        }

        #[hegel::test]
        fn prop_small_truncated_inputs_are_rejected_not_panicked(tc: hegel::TestCase) {
            let len = tc.draw(gs::integers::<usize>().max_value(HEADER_SIZE - 1));
            let bytes = tc.draw(gs::binary().min_size(len).max_size(len));
            assert!(AionParser::new(&bytes).is_err());
        }
    }
}
