// SPDX-License-Identifier: MIT OR Apache-2.0
//! Error types for AION v2
//!
//! This module defines the error types used throughout AION v2. Following Tiger Style,
//! all errors are explicit, provide actionable messages, and implement `std::error::Error`.
//!
//! # Error Categories
//!
//! Errors are organized into logical categories for clarity:
//!
//! - **I/O Errors** - File system operations
//! - **Cryptographic Errors** - Signature and encryption failures
//! - **Format Errors** - File parsing and validation
//! - **Version Errors** - Version chain and history issues
//! - **Key Management Errors** - Keyring and key storage
//! - **Validation Errors** - Input validation failures
//! - **Operational Errors** - Runtime operation failures
//!
//! # Usage Example
//!
//! ```
//! use aion_context::{AionError, Result};
//! use std::path::PathBuf;
//!
//! fn load_file(path: &str) -> Result<Vec<u8>> {
//!     std::fs::read(path).map_err(|e| AionError::FileReadError {
//!         path: PathBuf::from(path),
//!         source: e,
//!     })
//! }
//!
//! // Errors provide contextual information
//! match load_file("nonexistent.aion") {
//!     Ok(data) => println!("Loaded {} bytes", data.len()),
//!     Err(e) => eprintln!("Error: {e}"),
//! }
//! ```
//!
//! # Error Handling Best Practices
//!
//! 1. **Always use `?` operator** for error propagation
//! 2. **Add context** to errors when re-wrapping
//! 3. **Match on error types** for specific handling
//! 4. **Display errors to users** with helpful messages
//!
//! ```
//! use aion_context::Result;
//!
//! fn process_file() -> Result<()> {
//!     let data = load_file("file.aion")?;  // ✓ Propagate errors
//!     verify_signatures(&data)?;            // ✓ Chain operations
//!     Ok(())
//! }
//! # fn load_file(path: &str) -> Result<Vec<u8>> { Ok(vec![]) }
//! # fn verify_signatures(data: &[u8]) -> Result<()> { Ok(()) }
//! ```

use std::path::PathBuf;
use thiserror::Error;

use crate::types::AuthorId;

/// Top-level error type for AION v2
///
/// All errors provide contextual information to aid debugging and suggest
/// solutions to users. Errors are organized by category for clarity.
///
/// `#[non_exhaustive]` because the crate is under active development —
/// new error categories will land for crypto rotations, hardware
/// attestation, transparency-log proofs, and additional compliance
/// frameworks. Adding a variant should not force every downstream
/// consumer's exhaustive `match` to update on a minor release.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum AionError {
    // ============================================================================
    // I/O Errors
    // ============================================================================
    /// Failed to read a file
    #[error("Failed to read file: {path}")]
    FileReadError {
        /// Path to the file that couldn't be read
        path: PathBuf,
        /// Underlying I/O error
        #[source]
        source: std::io::Error,
    },

    /// Failed to write a file
    #[error("Failed to write file: {path}")]
    FileWriteError {
        /// Path to the file that couldn't be written
        path: PathBuf,
        /// Underlying I/O error
        #[source]
        source: std::io::Error,
    },

    /// File already exists
    #[error("File already exists: {path}")]
    FileExists {
        /// Path to the existing file
        path: PathBuf,
    },

    /// File not found
    #[error("File not found: {path}")]
    FileNotFound {
        /// Path to the missing file
        path: PathBuf,
    },

    /// Permission denied
    #[error("Permission denied: {path}")]
    PermissionDenied {
        /// Path to the file with permission issues
        path: PathBuf,
    },

    // ============================================================================
    // Format Errors
    // ============================================================================
    /// Invalid file format
    #[error("Invalid file format: {reason}")]
    InvalidFormat {
        /// Description of the format issue
        reason: String,
    },

    /// Corrupted file detected via checksum mismatch
    #[error("Corrupted file: checksum mismatch (expected: {expected}, got: {actual})")]
    CorruptedFile {
        /// Expected checksum
        expected: String,
        /// Actual checksum
        actual: String,
    },

    /// Unsupported file version
    #[error("Unsupported file version: {version} (supported: {supported})")]
    UnsupportedVersion {
        /// Version found in the file
        version: u16,
        /// Supported versions
        supported: String,
    },

    /// Invalid file header
    #[error("Invalid header: {reason}")]
    InvalidHeader {
        /// Description of header issue
        reason: String,
    },

    // ============================================================================
    // Cryptographic Errors
    // ============================================================================
    /// Signature verification failed
    #[error("Signature verification failed for version {version} by author {author}")]
    SignatureVerificationFailed {
        /// Version number that failed verification
        version: u64,
        /// Author ID
        author: AuthorId,
    },

    /// Invalid signature
    #[error("Invalid signature: {reason}")]
    InvalidSignature {
        /// Description of signature issue
        reason: String,
    },

    /// A commit was attempted by a signer the registry has no active
    /// epoch for at the target version (issue #25). The write was
    /// refused before any bytes were emitted.
    #[error(
        "Unauthorized signer: author {author} has no active registry epoch at version {version}"
    )]
    UnauthorizedSigner {
        /// The author that attempted to sign.
        author: AuthorId,
        /// The version number the commit would have produced.
        version: u64,
    },

    /// The supplied signing key's public half does not match the
    /// operational key pinned in the registry for this author's active
    /// epoch (issue #25). Most often means the caller used a rotated-
    /// out key.
    #[error(
        "Key mismatch: author {author} signing key does not match registry epoch {epoch} operational key"
    )]
    KeyMismatch {
        /// The author that attempted to sign.
        author: AuthorId,
        /// The registry epoch number that pinned a different public key.
        epoch: u32,
    },

    /// Decryption failed
    #[error("Decryption failed: {reason}")]
    DecryptionFailed {
        /// Description of decryption failure
        reason: String,
    },

    /// Encryption failed
    #[error("Encryption failed: {reason}")]
    EncryptionFailed {
        /// Description of encryption failure
        reason: String,
    },

    /// Hash mismatch after decryption
    #[error("Hash mismatch: expected {expected:x?}, got {actual:x?}")]
    HashMismatch {
        /// Expected hash value
        expected: [u8; 32],
        /// Actual hash value
        actual: [u8; 32],
    },

    /// Invalid private key
    #[error("Invalid private key: {reason}")]
    InvalidPrivateKey {
        /// Description of key issue
        reason: String,
    },

    /// Invalid public key
    #[error("Invalid public key: {reason}")]
    InvalidPublicKey {
        /// Description of key issue
        reason: String,
    },

    // ============================================================================
    // Version Chain Errors
    // ============================================================================
    /// Version chain integrity broken
    #[error("Version chain broken at version {version}: parent hash mismatch")]
    BrokenVersionChain {
        /// Version where the chain breaks
        version: u64,
    },

    /// Invalid version number
    #[error("Invalid version number: {version} (current: {current})")]
    InvalidVersionNumber {
        /// Invalid version number
        version: u64,
        /// Current version
        current: u64,
    },

    /// Version number overflow
    #[error("Version overflow: cannot increment beyond {max}")]
    VersionOverflow {
        /// Maximum version reached
        max: u64,
    },

    /// Missing version in chain
    #[error("Missing version: {version}")]
    MissingVersion {
        /// Missing version number
        version: u64,
    },

    // ============================================================================
    // Key Management Errors
    // ============================================================================
    /// Key not found in keyring
    #[error("Key not found for author {author_id}: {reason}")]
    KeyNotFound {
        /// Author identifier
        author_id: crate::types::AuthorId,
        /// Description of the error
        reason: String,
    },

    /// Keyring access denied
    #[error("Keyring access denied: {reason}")]
    KeyringAccessDenied {
        /// Description of access issue
        reason: String,
    },

    /// Failed to store key
    #[error("Failed to store key: {reason}")]
    KeyStoreFailed {
        /// Description of storage failure
        reason: String,
    },

    /// Keyring operation error
    #[error("Keyring {operation} failed: {reason}")]
    KeyringError {
        /// Operation that failed
        operation: String,
        /// Description of the error
        reason: String,
    },

    // ============================================================================
    // Validation Errors
    // ============================================================================
    /// Invalid file ID
    #[error("Invalid file ID: {file_id}")]
    InvalidFileId {
        /// Invalid file ID value
        file_id: u64,
    },

    /// Invalid author ID
    #[error("Invalid author ID: {author_id}")]
    InvalidAuthorId {
        /// Invalid author ID value
        author_id: u64,
    },

    /// Invalid timestamp
    #[error("Invalid timestamp: {reason}")]
    InvalidTimestamp {
        /// Description of timestamp issue
        reason: String,
    },

    /// Invalid action code
    #[error("Invalid action code: {code}")]
    InvalidActionCode {
        /// Invalid action code value
        code: u16,
    },

    /// Broken audit chain
    #[error("Broken audit chain: expected hash {expected:?}, got {actual:?}")]
    BrokenAuditChain {
        /// Expected previous hash
        expected: [u8; 32],
        /// Actual previous hash
        actual: [u8; 32],
    },

    /// Invalid UTF-8 encoding
    #[error("Invalid UTF-8: {reason}")]
    InvalidUtf8 {
        /// Description of UTF-8 validation failure
        reason: String,
    },

    /// Rules too large
    #[error("Rules too large: {size} bytes (max: {max} bytes)")]
    RulesTooLarge {
        /// Actual size
        size: usize,
        /// Maximum allowed size
        max: usize,
    },

    // ============================================================================
    // Operational Errors
    // ============================================================================
    /// Operation not permitted
    #[error("Operation not permitted: {operation} requires {required}")]
    OperationNotPermitted {
        /// Operation attempted
        operation: String,
        /// Required permission/state
        required: String,
    },

    /// Conflicting operation
    #[error("Conflicting operation: {reason}")]
    Conflict {
        /// Description of conflict
        reason: String,
    },

    /// Resource exhausted
    #[error("Resource exhausted: {resource}")]
    ResourceExhausted {
        /// Resource that was exhausted
        resource: String,
    },
}

/// Result type alias for AION operations
///
/// # Examples
///
/// ```
/// use aion_context::error::{AionError, Result};
///
/// fn read_version(version: u64) -> Result<String> {
///     if version == 0 {
///         return Err(AionError::InvalidVersionNumber { version, current: 1 });
///     }
///     Ok("version data".to_string())
/// }
/// ```
pub type Result<T> = std::result::Result<T, AionError>;

// Implement Send + Sync for async compatibility
// (thiserror derives these automatically when possible)

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests are allowed to panic
mod tests {
    use super::*;

    #[test]
    fn error_should_implement_error_trait() {
        let err = AionError::InvalidFormat {
            reason: "test".to_string(),
        };
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn error_should_be_send_and_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<AionError>();
        assert_sync::<AionError>();
    }

    mod file_errors {
        use super::*;

        #[test]
        fn file_read_error_should_display_path_and_source() {
            let err = AionError::FileReadError {
                path: PathBuf::from("/test/file.aion"),
                source: std::io::Error::from(std::io::ErrorKind::NotFound),
            };
            let msg = format!("{err}");
            assert!(msg.contains("/test/file.aion"));
            assert!(msg.contains("Failed to read file"));
        }

        #[test]
        fn file_not_found_should_display_path() {
            let err = AionError::FileNotFound {
                path: PathBuf::from("/missing.aion"),
            };
            assert_eq!(format!("{err}"), "File not found: /missing.aion");
        }

        #[test]
        fn permission_denied_should_display_path() {
            let err = AionError::PermissionDenied {
                path: PathBuf::from("/protected.aion"),
            };
            assert_eq!(format!("{err}"), "Permission denied: /protected.aion");
        }
    }

    mod format_errors {
        use super::*;

        #[test]
        fn invalid_format_should_display_reason() {
            let err = AionError::InvalidFormat {
                reason: "missing magic number".to_string(),
            };
            assert_eq!(
                format!("{err}"),
                "Invalid file format: missing magic number"
            );
        }

        #[test]
        fn corrupted_file_should_display_checksums() {
            let err = AionError::CorruptedFile {
                expected: "abc123".to_string(),
                actual: "def456".to_string(),
            };
            let msg = format!("{err}");
            assert!(msg.contains("abc123"));
            assert!(msg.contains("def456"));
        }

        #[test]
        fn unsupported_version_should_display_versions() {
            let err = AionError::UnsupportedVersion {
                version: 99,
                supported: "1-2".to_string(),
            };
            assert_eq!(
                format!("{err}"),
                "Unsupported file version: 99 (supported: 1-2)"
            );
        }
    }

    mod crypto_errors {
        use super::*;

        #[test]
        fn signature_verification_failed_should_display_details() {
            let err = AionError::SignatureVerificationFailed {
                version: 42,
                author: AuthorId::new(1),
            };
            let msg = format!("{err}");
            assert!(msg.contains("42"));
            assert!(msg.contains('1'));
        }

        #[test]
        fn invalid_signature_should_display_reason() {
            let err = AionError::InvalidSignature {
                reason: "wrong length".to_string(),
            };
            assert_eq!(format!("{err}"), "Invalid signature: wrong length");
        }

        #[test]
        fn decryption_failed_should_display_reason() {
            let err = AionError::DecryptionFailed {
                reason: "wrong key".to_string(),
            };
            assert_eq!(format!("{err}"), "Decryption failed: wrong key");
        }
    }

    mod version_errors {
        use super::*;

        #[test]
        fn broken_version_chain_should_display_version() {
            let err = AionError::BrokenVersionChain { version: 5 };
            assert_eq!(
                format!("{err}"),
                "Version chain broken at version 5: parent hash mismatch"
            );
        }

        #[test]
        fn invalid_version_number_should_display_versions() {
            let err = AionError::InvalidVersionNumber {
                version: 10,
                current: 5,
            };
            assert_eq!(format!("{err}"), "Invalid version number: 10 (current: 5)");
        }

        #[test]
        fn version_overflow_should_display_max() {
            let err = AionError::VersionOverflow { max: u64::MAX };
            let msg = format!("{err}");
            assert!(msg.contains("overflow"));
            assert!(msg.contains(&u64::MAX.to_string()));
        }

        #[test]
        fn missing_version_should_display_version() {
            let err = AionError::MissingVersion { version: 3 };
            assert_eq!(format!("{err}"), "Missing version: 3");
        }
    }

    mod key_management_errors {
        use super::*;
        use crate::types::AuthorId;

        #[test]
        fn key_not_found_should_display_author_id() {
            let err = AionError::KeyNotFound {
                author_id: AuthorId::new(50001),
                reason: "not found".to_string(),
            };
            assert_eq!(
                format!("{err}"),
                "Key not found for author 50001: not found"
            );
        }

        #[test]
        fn keyring_access_denied_should_display_reason() {
            let err = AionError::KeyringAccessDenied {
                reason: "locked".to_string(),
            };
            assert_eq!(format!("{err}"), "Keyring access denied: locked");
        }

        #[test]
        fn keyring_error_should_display_operation() {
            let err = AionError::KeyringError {
                operation: "store".to_string(),
                reason: "permission denied".to_string(),
            };
            assert_eq!(format!("{err}"), "Keyring store failed: permission denied");
        }
    }

    mod validation_errors {
        use super::*;

        #[test]
        fn invalid_file_id_should_display_id() {
            let err = AionError::InvalidFileId { file_id: 0 };
            assert_eq!(format!("{err}"), "Invalid file ID: 0");
        }

        #[test]
        fn rules_too_large_should_display_sizes() {
            let err = AionError::RulesTooLarge {
                size: 2_000_000,
                max: 1_000_000,
            };
            let msg = format!("{err}");
            assert!(msg.contains("2000000"));
            assert!(msg.contains("1000000"));
        }

        #[test]
        fn invalid_action_code_should_display_code() {
            let err = AionError::InvalidActionCode { code: 99 };
            assert_eq!(format!("{err}"), "Invalid action code: 99");
        }

        #[test]
        fn broken_audit_chain_should_display_hashes() {
            let expected = [0xAB; 32];
            let actual = [0xCD; 32];
            let err = AionError::BrokenAuditChain { expected, actual };
            let msg = format!("{err}");
            assert!(msg.contains("Broken audit chain"));
        }

        #[test]
        fn invalid_timestamp_should_display_reason() {
            let err = AionError::InvalidTimestamp {
                reason: "timestamp is in the future".to_string(),
            };
            assert_eq!(
                format!("{err}"),
                "Invalid timestamp: timestamp is in the future"
            );
        }

        #[test]
        fn invalid_utf8_should_display_reason() {
            let err = AionError::InvalidUtf8 {
                reason: "invalid byte sequence at offset 10".to_string(),
            };
            assert_eq!(
                format!("{err}"),
                "Invalid UTF-8: invalid byte sequence at offset 10"
            );
        }
    }

    mod operational_errors {
        use super::*;

        #[test]
        fn operation_not_permitted_should_display_details() {
            let err = AionError::OperationNotPermitted {
                operation: "commit".to_string(),
                required: "write access".to_string(),
            };
            let msg = format!("{err}");
            assert!(msg.contains("commit"));
            assert!(msg.contains("write access"));
        }

        #[test]
        fn conflict_should_display_reason() {
            let err = AionError::Conflict {
                reason: "version already exists".to_string(),
            };
            assert_eq!(
                format!("{err}"),
                "Conflicting operation: version already exists"
            );
        }

        #[test]
        fn resource_exhausted_should_display_resource() {
            let err = AionError::ResourceExhausted {
                resource: "memory".to_string(),
            };
            assert_eq!(format!("{err}"), "Resource exhausted: memory");
        }
    }

    mod result_type {
        use super::*;

        #[test]
        fn result_should_work_with_ok() {
            let result: Result<i32> = Ok(42);
            assert!(result.is_ok());
            if let Ok(value) = result {
                assert_eq!(value, 42);
            }
        }

        #[test]
        fn result_should_work_with_err() {
            let result: Result<i32> = Err(AionError::InvalidFormat {
                reason: "test".to_string(),
            });
            assert!(result.is_err());
        }
    }
}
