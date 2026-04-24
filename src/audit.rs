//! Audit trail structures for AION v2
//!
//! This module implements the embedded audit trail as specified in RFC-0002 and RFC-0019.
//! All audit operations are logged with cryptographic hash chaining to prevent tampering.
//!
//! # Structure
//!
//! The audit trail is a hash-chained sequence of 80-byte entries. Each entry records:
//! - **Timestamp** - Nanosecond-precision Unix timestamp
//! - **Author** - Who performed the action
//! - **Action** - What operation was performed
//! - **Details** - Human-readable description (stored in string table)
//! - **Chain Link** - BLAKE3 hash of previous entry
//!
//! # Hash Chain Integrity
//!
//! Each audit entry contains the BLAKE3 hash of the previous entry, forming an
//! immutable chain. The genesis entry (first entry) has an all-zero previous hash.
//! Any modification to an entry breaks the chain, making tampering evident.
//!
//! # Compliance
//!
//! The audit trail satisfies requirements for:
//! - **SOX**: Comprehensive change tracking with non-repudiation
//! - **HIPAA**: Access control and information system activity logging
//! - **GDPR Article 30**: Records of processing activities
//!
//! # Usage Example
//!
//! ```
//! use aion_context::audit::{AuditEntry, ActionCode};
//! use aion_context::types::AuthorId;
//!
//! // Create genesis audit entry
//! let entry = AuditEntry::new(
//!     1_700_000_000_000_000_000, // timestamp in nanoseconds
//!     AuthorId(1001),
//!     ActionCode::CreateGenesis,
//!     42,  // details_offset in string table
//!     15,  // details_length
//!     [0u8; 32], // previous_hash (all zeros for genesis)
//! );
//!
//! // Entry is exactly 80 bytes
//! assert_eq!(std::mem::size_of_val(&entry), 80);
//! ```
//!
//! # Serialization
//!
//! Audit entries use deterministic binary serialization with `#[repr(C)]` layout.
//! All multi-byte integers are little-endian. The format is zero-copy compatible
//! for efficient parsing.

use crate::crypto::hash;
use crate::types::AuthorId;
use crate::{AionError, Result};

/// Audit trail entry with hash chain integrity
///
/// Fixed 80-byte structure as specified in RFC-0002 Section 5.4.
/// All integers are little-endian. Layout is `#[repr(C)]` for deterministic serialization.
///
/// # Memory Layout
///
/// ```text
/// Offset  Size  Field
/// ------  ----  -----
/// 0       8     timestamp
/// 8       8     author_id
/// 16      2     action_code
/// 18      6     reserved1
/// 24      8     details_offset
/// 32      4     details_length
/// 36      4     reserved2
/// 40      32    previous_hash
/// 72      8     reserved3
/// ------  ----
/// Total:  80 bytes
/// ```
///
/// # Examples
///
/// ```
/// use aion_context::audit::{AuditEntry, ActionCode};
/// use aion_context::types::AuthorId;
///
/// let entry = AuditEntry::new(
///     1_700_000_000_000_000_000,
///     AuthorId(1001),
///     ActionCode::CommitVersion,
///     100,
///     27,
///     [0u8; 32],
/// );
///
/// // Verify size
/// assert_eq!(std::mem::size_of_val(&entry), 80);
///
/// // Access fields
/// assert_eq!(entry.action_code().unwrap(), ActionCode::CommitVersion);
/// assert_eq!(entry.author_id(), AuthorId(1001));
/// ```
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditEntry {
    /// Timestamp in nanoseconds since Unix epoch
    timestamp: u64,

    /// Author who performed the action
    author_id: u64,

    /// Action code (see [`ActionCode`])
    action_code: u16,

    /// Reserved for future use (must be zero)
    reserved1: [u8; 6],

    /// Offset of details string in string table
    details_offset: u64,

    /// Length of details string (bytes, excluding null terminator)
    details_length: u32,

    /// Reserved for future use (must be zero)
    reserved2: [u8; 4],

    /// BLAKE3 hash of previous audit entry (all zeros for genesis)
    previous_hash: [u8; 32],

    /// Reserved for future use (must be zero)
    reserved3: [u8; 8],
}

// Compile-time size verification
const _: () = assert!(std::mem::size_of::<AuditEntry>() == 80);

impl AuditEntry {
    /// Create a new audit entry
    ///
    /// # Arguments
    ///
    /// * `timestamp` - Nanoseconds since Unix epoch (use `SystemTime::now()`)
    /// * `author_id` - Author performing the action
    /// * `action_code` - Type of operation (see [`ActionCode`])
    /// * `details_offset` - Byte offset in string table
    /// * `details_length` - Length of details string (excluding null)
    /// * `previous_hash` - BLAKE3 hash of previous entry (all zeros for genesis)
    ///
    /// # Examples
    ///
    /// ```
    /// use aion_context::audit::{AuditEntry, ActionCode};
    /// use aion_context::types::AuthorId;
    ///
    /// let entry = AuditEntry::new(
    ///     1_700_000_000_000_000_000,
    ///     AuthorId(1001),
    ///     ActionCode::Verify,
    ///     200,
    ///     42,
    ///     [0xAB; 32],
    /// );
    /// ```
    #[must_use]
    pub const fn new(
        timestamp: u64,
        author_id: AuthorId,
        action_code: ActionCode,
        details_offset: u64,
        details_length: u32,
        previous_hash: [u8; 32],
    ) -> Self {
        Self {
            timestamp,
            author_id: author_id.0,
            action_code: action_code as u16,
            reserved1: [0; 6],
            details_offset,
            details_length,
            reserved2: [0; 4],
            previous_hash,
            reserved3: [0; 8],
        }
    }

    /// Get the timestamp in nanoseconds
    #[must_use]
    pub const fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Get the author ID
    #[must_use]
    pub const fn author_id(&self) -> AuthorId {
        AuthorId(self.author_id)
    }

    /// Get the action code
    ///
    /// # Errors
    ///
    /// Returns an error if the action code is not a valid enum variant
    pub const fn action_code(&self) -> Result<ActionCode> {
        ActionCode::from_u16(self.action_code)
    }

    /// Get the action code as raw u16 (no validation)
    #[must_use]
    pub const fn action_code_raw(&self) -> u16 {
        self.action_code
    }

    /// Get the details offset in string table
    #[must_use]
    pub const fn details_offset(&self) -> u64 {
        self.details_offset
    }

    /// Get the details string length (bytes, excluding null terminator)
    #[must_use]
    pub const fn details_length(&self) -> u32 {
        self.details_length
    }

    /// Get the previous entry hash
    #[must_use]
    pub const fn previous_hash(&self) -> &[u8; 32] {
        &self.previous_hash
    }

    /// Check if this is a genesis entry (first in chain)
    ///
    /// Genesis entries have an all-zero previous hash.
    #[must_use]
    pub fn is_genesis(&self) -> bool {
        self.previous_hash == [0u8; 32]
    }

    /// Compute BLAKE3 hash of this entry
    ///
    /// The hash includes all 80 bytes of the entry. This hash becomes the
    /// `previous_hash` value for the next entry in the chain.
    ///
    /// # Examples
    ///
    /// ```
    /// use aion_context::audit::{AuditEntry, ActionCode};
    /// use aion_context::types::AuthorId;
    ///
    /// let entry = AuditEntry::new(
    ///     1_700_000_000_000_000_000,
    ///     AuthorId(1001),
    ///     ActionCode::CreateGenesis,
    ///     0,
    ///     10,
    ///     [0u8; 32],
    /// );
    ///
    /// let entry_hash = entry.compute_hash();
    /// assert_eq!(entry_hash.len(), 32);
    /// ```
    #[must_use]
    pub fn compute_hash(&self) -> [u8; 32] {
        hash(self.as_bytes())
    }

    /// Serialize entry to bytes (little-endian)
    ///
    /// Returns exactly 80 bytes in RFC-0002 specified format.
    ///
    /// # Safety
    ///
    /// This function is safe because:
    /// 1. `AuditEntry` has `#[repr(C)]` for deterministic layout
    /// 2. All fields are plain-old-data (POD) types
    /// 3. The lifetime of the returned slice is tied to `self`
    /// 4. The size is compile-time verified to be 80 bytes
    #[must_use]
    #[allow(unsafe_code)] // Necessary for zero-copy serialization
    pub const fn as_bytes(&self) -> &[u8] {
        // SAFETY: AuditEntry is repr(C) with POD fields, properly aligned
        unsafe {
            std::slice::from_raw_parts(
                (self as *const Self).cast::<u8>(),
                std::mem::size_of::<Self>(),
            )
        }
    }

    /// Deserialize entry from bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the input is not exactly 80 bytes.
    ///
    /// # Safety
    ///
    /// This function is safe because:
    /// 1. Length is validated to be exactly 80 bytes
    /// 2. `AuditEntry` is `#[repr(C)]` with POD fields
    /// 3. All bit patterns are valid for the field types
    /// 4. No references or complex types that need initialization
    ///
    /// Note: Callers should validate field values (e.g., `action_code`) after deserialization.
    #[allow(unsafe_code)] // Necessary for zero-copy deserialization
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 80 {
            return Err(AionError::InvalidFormat {
                reason: format!("AuditEntry must be exactly 80 bytes, got {}", bytes.len()),
            });
        }

        // SAFETY: Length validated, repr(C) layout, all bit patterns valid for POD types
        // Cast is safe: input slice is 80 bytes (verified above), struct size is 80 bytes
        #[allow(clippy::cast_ptr_alignment)]
        let entry = unsafe { std::ptr::read(bytes.as_ptr().cast::<Self>()) };

        Ok(entry)
    }

    /// Validate this entry against the previous entry
    ///
    /// Checks that:
    /// 1. The `previous_hash` matches the hash of `previous_entry`
    /// 2. The timestamp is not before the previous entry
    /// 3. Reserved fields are zero
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use aion_context::audit::{AuditEntry, ActionCode};
    /// use aion_context::types::AuthorId;
    ///
    /// let genesis = AuditEntry::new(
    ///     1_700_000_000_000_000_000,
    ///     AuthorId(1001),
    ///     ActionCode::CreateGenesis,
    ///     0,
    ///     10,
    ///     [0u8; 32],
    /// );
    ///
    /// let genesis_hash = genesis.compute_hash();
    ///
    /// let entry2 = AuditEntry::new(
    ///     1_700_000_001_000_000_000,
    ///     AuthorId(1002),
    ///     ActionCode::CommitVersion,
    ///     10,
    ///     15,
    ///     genesis_hash,
    /// );
    ///
    /// assert!(entry2.validate_chain(&genesis).is_ok());
    /// ```
    pub fn validate_chain(&self, previous_entry: &Self) -> Result<()> {
        // Check hash chain
        let expected_hash = previous_entry.compute_hash();
        if self.previous_hash != expected_hash {
            return Err(AionError::BrokenAuditChain {
                expected: expected_hash,
                actual: self.previous_hash,
            });
        }

        // Check timestamp ordering (allow equal for concurrent operations)
        if self.timestamp < previous_entry.timestamp {
            return Err(AionError::InvalidTimestamp {
                reason: format!(
                    "Entry timestamp {} is before previous entry {}",
                    self.timestamp, previous_entry.timestamp
                ),
            });
        }

        // Validate reserved fields are zero
        if self.reserved1 != [0; 6] || self.reserved2 != [0; 4] || self.reserved3 != [0; 8] {
            return Err(AionError::InvalidFormat {
                reason: "Reserved fields must be zero".to_string(),
            });
        }

        Ok(())
    }
}

/// Action codes for audit trail entries
///
/// As specified in RFC-0002, action codes indicate the type of operation
/// being audited. Codes 1-4 are currently defined, 5-99 are reserved for
/// future standard actions, and 100+ are available for custom extensions.
///
/// # Examples
///
/// ```
/// use aion_context::audit::ActionCode;
///
/// // Standard actions
/// let action = ActionCode::CommitVersion;
/// assert_eq!(action as u16, 2);
///
/// // Round-trip through u16
/// let code = ActionCode::from_u16(3).unwrap();
/// assert_eq!(code, ActionCode::Verify);
/// ```
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionCode {
    /// File creation with genesis version
    CreateGenesis = 1,

    /// New version committed to file
    CommitVersion = 2,

    /// Signature verification performed
    Verify = 3,

    /// File inspection/audit operation
    Inspect = 4,
}

impl ActionCode {
    /// Convert from raw u16 value
    ///
    /// # Errors
    ///
    /// Returns an error if the value is not a valid action code.
    ///
    /// # Examples
    ///
    /// ```
    /// use aion_context::audit::ActionCode;
    ///
    /// assert_eq!(ActionCode::from_u16(1).unwrap(), ActionCode::CreateGenesis);
    /// assert_eq!(ActionCode::from_u16(2).unwrap(), ActionCode::CommitVersion);
    /// assert!(ActionCode::from_u16(99).is_err());
    /// ```
    pub const fn from_u16(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::CreateGenesis),
            2 => Ok(Self::CommitVersion),
            3 => Ok(Self::Verify),
            4 => Ok(Self::Inspect),
            _ => Err(AionError::InvalidActionCode { code: value }),
        }
    }

    /// Get human-readable description
    ///
    /// # Examples
    ///
    /// ```
    /// use aion_context::audit::ActionCode;
    ///
    /// assert_eq!(ActionCode::CreateGenesis.description(), "Create genesis version");
    /// assert_eq!(ActionCode::CommitVersion.description(), "Commit new version");
    /// ```
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::CreateGenesis => "Create genesis version",
            Self::CommitVersion => "Commit new version",
            Self::Verify => "Verify signatures",
            Self::Inspect => "Inspect file",
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Allow unwrap in test code
mod tests {
    use super::*;

    mod audit_entry {
        use super::*;

        #[test]
        fn should_have_correct_size() {
            assert_eq!(std::mem::size_of::<AuditEntry>(), 80);
        }

        #[test]
        fn should_create_new_entry() {
            let entry = AuditEntry::new(
                1_700_000_000_000_000_000,
                AuthorId(1001),
                ActionCode::CreateGenesis,
                0,
                10,
                [0u8; 32],
            );

            assert_eq!(entry.timestamp(), 1_700_000_000_000_000_000);
            assert_eq!(entry.author_id(), AuthorId(1001));
            assert_eq!(entry.action_code().unwrap(), ActionCode::CreateGenesis);
            assert_eq!(entry.details_offset(), 0);
            assert_eq!(entry.details_length(), 10);
            assert_eq!(entry.previous_hash(), &[0u8; 32]);
        }

        #[test]
        fn should_identify_genesis_entry() {
            let genesis = AuditEntry::new(
                1_700_000_000_000_000_000,
                AuthorId(1001),
                ActionCode::CreateGenesis,
                0,
                10,
                [0u8; 32],
            );

            assert!(genesis.is_genesis());

            let non_genesis = AuditEntry::new(
                1_700_000_001_000_000_000,
                AuthorId(1002),
                ActionCode::CommitVersion,
                10,
                15,
                [0xAB; 32],
            );

            assert!(!non_genesis.is_genesis());
        }

        #[test]
        fn should_compute_hash() {
            let entry = AuditEntry::new(
                1_700_000_000_000_000_000,
                AuthorId(1001),
                ActionCode::CreateGenesis,
                0,
                10,
                [0u8; 32],
            );

            let hash = entry.compute_hash();
            assert_eq!(hash.len(), 32);

            // Same entry should produce same hash
            let hash2 = entry.compute_hash();
            assert_eq!(hash, hash2);
        }

        #[test]
        fn should_serialize_and_deserialize() {
            let original = AuditEntry::new(
                1_700_000_000_000_000_000,
                AuthorId(1001),
                ActionCode::CommitVersion,
                42,
                27,
                [0xCD; 32],
            );

            let bytes = original.as_bytes();
            assert_eq!(bytes.len(), 80);

            let deserialized = AuditEntry::from_bytes(bytes).unwrap();
            assert_eq!(deserialized, original);
        }

        #[test]
        fn should_reject_invalid_size() {
            let bytes = [0u8; 79];
            let result = AuditEntry::from_bytes(&bytes);
            assert!(result.is_err());

            let bytes = [0u8; 81];
            let result = AuditEntry::from_bytes(&bytes);
            assert!(result.is_err());
        }

        #[test]
        fn should_validate_chain() {
            let genesis = AuditEntry::new(
                1_700_000_000_000_000_000,
                AuthorId(1001),
                ActionCode::CreateGenesis,
                0,
                10,
                [0u8; 32],
            );

            let genesis_hash = genesis.compute_hash();

            let entry2 = AuditEntry::new(
                1_700_000_001_000_000_000,
                AuthorId(1002),
                ActionCode::CommitVersion,
                10,
                15,
                genesis_hash,
            );

            assert!(entry2.validate_chain(&genesis).is_ok());
        }

        #[test]
        fn should_reject_broken_chain() {
            let genesis = AuditEntry::new(
                1_700_000_000_000_000_000,
                AuthorId(1001),
                ActionCode::CreateGenesis,
                0,
                10,
                [0u8; 32],
            );

            let wrong_hash = [0xFF; 32];
            let entry2 = AuditEntry::new(
                1_700_000_001_000_000_000,
                AuthorId(1002),
                ActionCode::CommitVersion,
                10,
                15,
                wrong_hash,
            );

            assert!(entry2.validate_chain(&genesis).is_err());
        }

        #[test]
        fn should_reject_timestamp_regression() {
            let entry1 = AuditEntry::new(
                1_700_000_001_000_000_000,
                AuthorId(1001),
                ActionCode::CreateGenesis,
                0,
                10,
                [0u8; 32],
            );

            let entry1_hash = entry1.compute_hash();

            let entry2 = AuditEntry::new(
                1_700_000_000_000_000_000, // Earlier timestamp
                AuthorId(1002),
                ActionCode::CommitVersion,
                10,
                15,
                entry1_hash,
            );

            assert!(entry2.validate_chain(&entry1).is_err());
        }

        #[test]
        fn should_allow_equal_timestamps() {
            let timestamp = 1_700_000_000_000_000_000;
            let entry1 = AuditEntry::new(
                timestamp,
                AuthorId(1001),
                ActionCode::CreateGenesis,
                0,
                10,
                [0u8; 32],
            );

            let entry1_hash = entry1.compute_hash();

            let entry2 = AuditEntry::new(
                timestamp, // Same timestamp (concurrent operations)
                AuthorId(1002),
                ActionCode::Verify,
                10,
                15,
                entry1_hash,
            );

            assert!(entry2.validate_chain(&entry1).is_ok());
        }
    }

    mod action_code {
        use super::*;

        #[test]
        fn should_convert_from_u16() {
            assert_eq!(ActionCode::from_u16(1).unwrap(), ActionCode::CreateGenesis);
            assert_eq!(ActionCode::from_u16(2).unwrap(), ActionCode::CommitVersion);
            assert_eq!(ActionCode::from_u16(3).unwrap(), ActionCode::Verify);
            assert_eq!(ActionCode::from_u16(4).unwrap(), ActionCode::Inspect);
        }

        #[test]
        fn should_reject_invalid_codes() {
            assert!(ActionCode::from_u16(0).is_err());
            assert!(ActionCode::from_u16(5).is_err());
            assert!(ActionCode::from_u16(99).is_err());
            assert!(ActionCode::from_u16(100).is_err());
        }

        #[test]
        fn should_have_descriptions() {
            assert_eq!(
                ActionCode::CreateGenesis.description(),
                "Create genesis version"
            );
            assert_eq!(
                ActionCode::CommitVersion.description(),
                "Commit new version"
            );
            assert_eq!(ActionCode::Verify.description(), "Verify signatures");
            assert_eq!(ActionCode::Inspect.description(), "Inspect file");
        }

        #[test]
        fn should_roundtrip_through_u16() {
            let codes = [
                ActionCode::CreateGenesis,
                ActionCode::CommitVersion,
                ActionCode::Verify,
                ActionCode::Inspect,
            ];

            for code in codes {
                let value = code as u16;
                let recovered = ActionCode::from_u16(value).unwrap();
                assert_eq!(recovered, code);
            }
        }
    }

    mod hash_chain {
        use super::*;

        #[test]
        fn should_build_valid_chain() {
            // Genesis entry
            let entry1 = AuditEntry::new(
                1_700_000_000_000_000_000,
                AuthorId(1001),
                ActionCode::CreateGenesis,
                0,
                10,
                [0u8; 32],
            );

            // Chain to entry 2
            let hash1 = entry1.compute_hash();
            let entry2 = AuditEntry::new(
                1_700_000_001_000_000_000,
                AuthorId(1002),
                ActionCode::CommitVersion,
                10,
                15,
                hash1,
            );

            // Chain to entry 3
            let hash2 = entry2.compute_hash();
            let entry3 = AuditEntry::new(
                1_700_000_002_000_000_000,
                AuthorId(1003),
                ActionCode::Verify,
                25,
                20,
                hash2,
            );

            // Validate chain
            assert!(entry2.validate_chain(&entry1).is_ok());
            assert!(entry3.validate_chain(&entry2).is_ok());
        }

        #[test]
        fn should_detect_missing_entry() {
            let entry1 = AuditEntry::new(
                1_700_000_000_000_000_000,
                AuthorId(1001),
                ActionCode::CreateGenesis,
                0,
                10,
                [0u8; 32],
            );

            let hash1 = entry1.compute_hash();
            let _entry2 = AuditEntry::new(
                1_700_000_001_000_000_000,
                AuthorId(1002),
                ActionCode::CommitVersion,
                10,
                15,
                hash1,
            );

            // Entry 3 claims to follow entry 2, but we try to validate against entry 1
            let hash2 = [0xAB; 32]; // Wrong hash
            let entry3 = AuditEntry::new(
                1_700_000_002_000_000_000,
                AuthorId(1003),
                ActionCode::Verify,
                25,
                20,
                hash2,
            );

            assert!(entry3.validate_chain(&entry1).is_err());
        }
    }
}
