//! Type-safe domain identifiers for AION v2
//!
//! This module provides newtype wrappers around primitive types to prevent
//! parameter confusion and provide compile-time type safety. Following Tiger Style,
//! all types avoid panics and provide comprehensive error handling.
//!
//! # Type Safety Benefits
//!
//! Using newtypes prevents common errors:
//!
//! ```compile_fail
//! # use aion_context::types::{FileId, AuthorId};
//! fn process_file(file_id: FileId, author_id: AuthorId) { }
//!
//! let file = FileId::new(1);
//! let author = AuthorId::new(1);
//!
//! // This won't compile - parameters are in wrong order!
//! process_file(author, file);
//! ```
//!
//! # Core Types
//!
//! - [`FileId`] - Unique identifier for AION files (64-bit)
//! - [`AuthorId`] - Identifier for file authors (64-bit)
//! - [`VersionNumber`] - Monotonically increasing version counter (64-bit)
//!
//! # Usage Example
//!
//! ```
//! use aion_context::types::{FileId, AuthorId, VersionNumber};
//!
//! // Create identifiers
//! let file_id = FileId::new(42);
//! let author_id = AuthorId::new(1001);
//! let version = VersionNumber(1);  // Version 1 is genesis
//!
//! // All types are serializable
//! let json = serde_json::to_string(&file_id).unwrap();
//! let deserialized: FileId = serde_json::from_str(&json).unwrap();
//! assert_eq!(file_id, deserialized);
//!
//! // Version arithmetic is safe
//! let next = version.next().unwrap();
//! assert_eq!(next, VersionNumber(2));
//! ```

use std::fmt;

/// Unique file identifier (64-bit)
///
/// Each AION file has a unique ID that remains constant across all versions.
///
/// # Examples
///
/// ```
/// use aion_context::types::FileId;
///
/// let id = FileId::new(42);
/// assert_eq!(id.as_u64(), 42);
///
/// let random_id = FileId::random();
/// assert!(random_id.as_u64() > 0);
/// ```
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct FileId(pub u64);

impl FileId {
    /// Create a new `FileId` from a u64
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Generate a random `FileId`
    #[must_use]
    pub fn random() -> Self {
        Self(rand::random())
    }

    /// Extract the inner u64 value
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for FileId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{:016x}", self.0)
    }
}

/// Author identifier
///
/// Identifies the author of a version entry.
///
/// # Examples
///
/// ```
/// use aion_context::types::AuthorId;
///
/// let author = AuthorId::new(1);
/// assert_eq!(author.as_u64(), 1);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct AuthorId(pub u64);

impl AuthorId {
    /// Create a new `AuthorId` from a u64
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Extract the inner u64 value
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for AuthorId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Version number (monotonically increasing)
///
/// Version numbers start at 1 (GENESIS) and increment sequentially.
/// Overflow protection is built-in via `checked_add`.
///
/// # Examples
///
/// ```
/// use aion_context::types::VersionNumber;
///
/// let v1 = VersionNumber::GENESIS;
/// assert_eq!(v1.as_u64(), 1);
///
/// let v2 = v1.next().unwrap();
/// assert_eq!(v2.as_u64(), 2);
/// ```
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct VersionNumber(pub u64);

impl VersionNumber {
    /// Genesis version (version 1)
    pub const GENESIS: Self = Self(1);

    /// Get the next version number
    ///
    /// # Errors
    ///
    /// Returns `Err` if incrementing would overflow `u64::MAX`
    pub fn next(self) -> crate::Result<Self> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(crate::AionError::VersionOverflow { max: self.0 })
    }

    /// Extract the inner u64 value
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for VersionNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// 256-bit hash (BLAKE3)
pub type Hash = [u8; 32];

/// Ed25519 public key
pub type PublicKey = [u8; 32];

/// Ed25519 signature
pub type Signature = [u8; 64];

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests are allowed to panic
mod tests {
    use super::*;

    mod file_id {
        use super::*;

        #[test]
        fn should_create_file_id_from_u64() {
            let id = FileId::new(42);
            assert_eq!(id.as_u64(), 42);
        }

        #[test]
        fn should_generate_random_file_id() {
            let id1 = FileId::random();
            let id2 = FileId::random();
            // Very unlikely to be equal
            assert_ne!(id1, id2);
        }

        #[test]
        fn should_display_as_hex() {
            let id = FileId::new(255);
            assert_eq!(format!("{id}"), "0x00000000000000ff");
        }

        #[test]
        fn should_serialize_deserialize() {
            let id = FileId::new(12345);
            // Test serialization - test can panic if this fails
            let json = serde_json::to_string(&id).unwrap();
            let deserialized: FileId = serde_json::from_str(&json).unwrap();
            assert_eq!(id, deserialized);
        }

        #[test]
        fn should_be_comparable() {
            let id1 = FileId::new(1);
            let id2 = FileId::new(2);
            assert!(id1 < id2);
            assert!(id2 > id1);
        }

        #[test]
        fn should_be_hashable() {
            use std::collections::HashSet;
            let mut set = HashSet::new();
            set.insert(FileId::new(1));
            set.insert(FileId::new(2));
            set.insert(FileId::new(1)); // Duplicate
            assert_eq!(set.len(), 2);
        }
    }

    mod author_id {
        use super::*;

        #[test]
        fn should_create_author_id_from_u64() {
            let id = AuthorId::new(100);
            assert_eq!(id.as_u64(), 100);
        }

        #[test]
        fn should_display_as_decimal() {
            let id = AuthorId::new(42);
            assert_eq!(format!("{id}"), "42");
        }

        #[test]
        fn should_serialize_deserialize() {
            let id = AuthorId::new(999);
            // Test serialization - test can panic if this fails
            let json = serde_json::to_string(&id).unwrap();
            let deserialized: AuthorId = serde_json::from_str(&json).unwrap();
            assert_eq!(id, deserialized);
        }

        #[test]
        fn should_be_comparable() {
            let id1 = AuthorId::new(1);
            let id2 = AuthorId::new(1);
            assert_eq!(id1, id2);
        }
    }

    mod version_number {
        use super::*;

        #[test]
        fn should_have_genesis_constant() {
            assert_eq!(VersionNumber::GENESIS.as_u64(), 1);
        }

        #[test]
        fn should_increment_version() {
            let v1 = VersionNumber::GENESIS;
            let v2 = v1.next().unwrap();
            assert_eq!(v2.as_u64(), 2);

            let v3 = v2.next().unwrap();
            assert_eq!(v3.as_u64(), 3);
        }

        #[test]
        fn should_handle_overflow() {
            let v_max = VersionNumber(u64::MAX);
            let result = v_max.next();
            assert!(result.is_err());
        }

        #[test]
        fn should_display_as_decimal() {
            let v = VersionNumber(42);
            assert_eq!(format!("{v}"), "42");
        }

        #[test]
        fn should_serialize_deserialize() {
            let v = VersionNumber(123);
            // Test serialization - test can panic if this fails
            let json = serde_json::to_string(&v).unwrap();
            let deserialized: VersionNumber = serde_json::from_str(&json).unwrap();
            assert_eq!(v, deserialized);
        }

        #[test]
        fn should_be_ordered() {
            let v1 = VersionNumber(1);
            let v2 = VersionNumber(2);
            let v3 = VersionNumber(3);

            assert!(v1 < v2);
            assert!(v2 < v3);
            assert!(v1 < v3);
        }

        #[test]
        fn should_sort_correctly() {
            let mut versions = [VersionNumber(3), VersionNumber(1), VersionNumber(2)];
            versions.sort();
            assert_eq!(versions.first().unwrap().as_u64(), 1);
            assert_eq!(versions.get(1).unwrap().as_u64(), 2);
            assert_eq!(versions.get(2).unwrap().as_u64(), 3);
        }
    }

    mod type_aliases {
        use super::*;

        #[test]
        fn hash_should_be_32_bytes() {
            let hash: Hash = [0u8; 32];
            assert_eq!(hash.len(), 32);
        }

        #[test]
        fn public_key_should_be_32_bytes() {
            let pk: PublicKey = [0u8; 32];
            assert_eq!(pk.len(), 32);
        }

        #[test]
        fn signature_should_be_64_bytes() {
            let sig: Signature = [0u8; 64];
            assert_eq!(sig.len(), 64);
        }
    }
}
