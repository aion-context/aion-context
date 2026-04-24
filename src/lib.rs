//! AION v2: Versioned Truth Infrastructure for AI Systems
//!
//! AION v2 provides cryptographically-signed, versioned business context that AI systems
//! can consume and prove they used. This solves the AI compliance crisis by providing
//! mathematical proof instead of expensive retraining.
//!
//! # Features
//!
//! - **Local-first**: Zero server dependency, works offline
//! - **Cryptographically-signed**: Ed25519 signatures for tamper-proof versioning
//! - **Embedded audit trails**: Complete history of all changes
//! - **OS keyring integration**: Secure key storage using platform keychains
//! - **Zero panics**: Tiger Style implementation with explicit error handling
//!
//! # Architecture
//!
//! - **Core Types**: Type-safe domain identifiers (`FileId`, `AuthorId`, `VersionNumber`)
//! - **Cryptography**: Ed25519, ChaCha20-Poly1305, Blake3, HKDF
//! - **File Format**: Binary format with zero-copy parsing
//! - **Operations**: init, commit, verify, show
//! - **CLI**: Command-line interface for all operations
//!
//! # Example
//!
//! ```rust,no_run
//! # use aion_context::Result;
//! # fn example() -> Result<()> {
//! // Future API example - not yet implemented
//! // let file_id = aion_context::init_file("policy.aion", &rules)?;
//! // let version = aion_context::commit_version("policy.aion", &updated_rules)?;
//! // let verification = aion_context::verify_file("policy.aion")?;
//! # Ok(())
//! # }
//! ```
//!
//! # Safety and Security
//!
//! This library follows NASA Power of 10 rules and Tiger Style:
//! - No `unwrap()`, `expect()`, or `panic!()` in production code
//! - All errors explicit with context
//! - Constant-time cryptographic operations
//! - Zeroization of sensitive data
//! - Maximum function size: 60 lines
//! - Maximum cyclomatic complexity: 15
//!
//! # Performance Targets
//!
//! - File creation: <10ms for 1MB rules
//! - Version commit: <5ms for 1MB rules
//! - Signature verification: <1ms per version
//! - File parsing: <3ms for 100-version file

// Enforce Tiger Style at the crate level
// Note: unwrap_used, expect_used, panic, etc. are enforced via Cargo.toml clippy lints
#![warn(missing_docs, unsafe_code, unused_must_use)]

// Module structure (to be implemented in future issues)
pub mod audit; // Issue #7: Audit trail
pub mod compliance; // Issue #33: Compliance reporting
pub mod conflict; // Issue #30: Conflict resolution
pub mod crypto; // Issue #4: Cryptography
pub mod dsse; // RFC-0023: DSSE envelope support
pub mod error; // Issue #3: Error handling
pub mod export; // Issue #31: Export/Import formats
pub mod keystore; // Issue #12: Key generation and storage
pub mod manifest; // RFC-0022: External artifact manifest
pub mod multisig; // Issue #29: Multi-signature support
pub mod operations; // Issue #15: Version commit operation
pub mod parser; // Issue #9: Zero-copy parser
pub mod serializer; // Issue #10: Deterministic Serializer
pub mod signature_chain; // Issue #14: Version signing protocol
pub mod string_table; // Issue #8: String table
pub mod types; // Issue #2: Core types
               // pub mod cli;          // CLI interface

// Test helpers (only available during testing)
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers; // Issue #5: Testing Infrastructure

// Public exports
pub use error::{AionError, Result};

#[cfg(test)]
mod tests {
    #[test]
    fn test_crate_compiles() {
        // Basic smoke test to ensure crate structure is valid
        // This test passes if the crate compiles successfully
    }
}
