// SPDX-License-Identifier: MIT OR Apache-2.0
//! Tamper-evident policy files with hash-chained signatures.
//!
//! `aion-context` wraps any byte payload — a YAML policy, a Markdown spec, a JSON config —
//! in a cryptographically-signed, version-chained integrity trail. Every change is signed
//! by a named author, every byte is bound into a BLAKE3 hash chain. Verifying any past
//! version is an O(log n) operation against a pinned [`key_registry::KeyRegistry`].
//!
//! Built for two audiences: **AI agent operators** who need policy files the model cannot
//! bypass, and **compliance teams** who need an auditor-ready record of exactly what a
//! policy said and who signed it — at any past version, without trusting any external
//! service.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use aion_context::crypto::SigningKey;
//! use aion_context::key_registry::KeyRegistry;
//! use aion_context::operations::{init_file, verify_file, InitOptions};
//! use aion_context::types::AuthorId;
//! use std::path::Path;
//!
//! fn main() -> anyhow::Result<()> {
//!     let key = SigningKey::generate();
//!     let author = AuthorId::new(1);
//!     let mut registry = KeyRegistry::new();
//!     registry.register_author(author, key.verifying_key(), key.verifying_key(), 0)?;
//!     init_file(
//!         Path::new("/tmp/policy.aion"),
//!         b"allow: read\nallow: write",
//!         &InitOptions { author_id: author, signing_key: &key, message: "v1", timestamp: None },
//!     )?;
//!     let report = verify_file(Path::new("/tmp/policy.aion"), &registry)?;
//!     assert!(report.is_valid);
//!     Ok(())
//! }
//! ```
//!
//! Flip one byte of the file on disk and `report.is_valid` is `false` — no further
//! configuration needed.
//!
//! # Key properties
//!
//! - **Tamper-evident** — BLAKE3 hash chain binds every version; any mutation is detectable
//! - **Signed** — Ed25519 per-version signatures; optional ML-DSA-65 hybrid (FIPS 204)
//! - **Replay-resistant** — `(author_id, version)` pairs are rejected if already seen
//! - **Offline-first** — zero network dependency; single static binary
//! - **Zero panics** — Tiger Style: all fallible paths return `Result<T, AionError>`
//! - **Zero-copy parsing** — `zerocopy`-backed parser for hot verification paths
//!
//! # Standards
//!
//! Sealed releases speak the supply-chain ecosystem: DSSE envelopes, SLSA v1.1
//! Statements, OCI Image Manifest v1.1, RFC 8785 canonical JSON, RFC 6962-compatible
//! transparency log, and Ed25519 + ML-DSA-65 hybrid signatures.
//!
//! # Performance
//!
//! - File creation: <10 ms for 1 MB payload
//! - Signature verification: <1 ms per version
//! - File parsing: <3 ms for a 100-version chain

// Enforce Tiger Style at the crate level
// Note: unwrap_used, expect_used, panic, etc. are enforced via Cargo.toml clippy lints
#![warn(missing_docs, unsafe_code, unused_must_use)]

// Module structure (to be implemented in future issues)
pub mod aibom; // RFC-0029: AI Bill of Materials
pub mod audit; // Issue #7: Audit trail
pub mod compliance; // Issue #33: Compliance reporting
pub mod conflict; // Issue #30: Conflict resolution
pub mod crypto; // Issue #4: Cryptography
pub mod dsse; // RFC-0023: DSSE envelope support
pub mod error; // Issue #3: Error handling
pub mod export; // Issue #31: Export/Import formats
pub mod hw_attestation; // RFC-0026: Hardware attestation binding
pub mod hybrid_sig; // RFC-0027: Post-quantum hybrid signatures
pub mod jcs; // RFC-0031: RFC 8785 JSON canonicalization
pub mod key_registry; // RFC-0028: Key rotation and revocation
pub mod keystore; // Issue #12: Key generation and storage
pub mod manifest; // RFC-0022: External artifact manifest
pub mod multisig; // Issue #29: Multi-signature support
pub mod oci; // RFC-0030: OCI artifact packaging
pub mod operations; // Issue #15: Version commit operation
pub mod parser; // Issue #9: Zero-copy parser
pub mod release; // RFC-0032: Release orchestration
pub mod serializer; // Issue #10: Deterministic Serializer
pub mod signature_chain; // Issue #14: Version signing protocol
pub mod slsa; // RFC-0024: SLSA v1.1 provenance emitter
pub mod string_table; // Issue #8: String table
pub mod transparency_log; // RFC-0025: Aion-native transparency log
pub mod types; // Issue #2: Core types

// Internal helpers for tracing field formatting (issue #57). Not part
// of the public API — see `.claude/rules/observability.md` for the
// field-naming and cardinality discipline these helpers enforce.
mod obs;
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
