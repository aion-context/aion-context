// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test helpers and utilities for AION v2
//!
//! This module provides reusable test utilities, data generators, and fixtures
//! for testing across the AION v2 codebase. All helpers follow Tiger Style principles
//! and are only available during testing or with the `test-helpers` feature.
//!
//! # Module Organization
//!
//! - **Test Keys**: [`TestKeyPair`] for Ed25519 signature testing
//! - **Test IDs**: Functions for creating [`FileId`], [`AuthorId`], [`VersionNumber`]
//! - **Test Data**: Deterministic and random data generation
//! - **Test Time**: Fixed timestamps for reproducible tests
//!
//! # Usage Examples
//!
//! ## Basic Test Helper Usage
//!
//! ```rust,ignore
//! use aion_context::test_helpers::*;
//!
//! #[test]
//! fn test_signature_verification() {
//!     // Generate test keypair
//!     let key = TestKeyPair::generate();
//!     let message = b"test data";
//!     
//!     // Sign and verify
//!     let signature = key.sign(message);
//!     assert!(key.verify(message, &signature).is_ok());
//! }
//! ```
//!
//! ## Deterministic Testing
//!
//! ```rust,ignore
//! use aion_context::test_helpers::*;
//!
//! #[test]
//! fn test_reproducible_behavior() {
//!     // Same seed produces same results
//!     let key1 = TestKeyPair::from_seed(12345)?;
//!     let key2 = TestKeyPair::from_seed(12345)?;
//!     
//!     let data1 = test_data(12345, 1024);
//!     let data2 = test_data(12345, 1024);
//!     
//!     assert_eq!(data1, data2);
//! }
//! ```
//!
//! ## Test Data Builder
//!
//! ```rust,ignore
//! use aion_context::test_helpers::TestDataBuilder;
//!
//! #[test]
//! fn test_with_custom_data() {
//!     // Build test data with specific properties
//!     let zeros = TestDataBuilder::new()
//!         .size(1000)
//!         .pattern(0x00)
//!         .build();
//!     
//!     let random = TestDataBuilder::new()
//!         .size(500)
//!         .build();
//!     
//!     let deterministic = TestDataBuilder::new()
//!         .size(256)
//!         .seed(42)
//!         .build();
//! }
//! ```
//!
//! # Availability
//!
//! This module is only available during testing or when the `test-helpers` feature
//! is enabled. This prevents test utilities from being used in production code.
//!
//! ```toml
//! [dev-dependencies]
//! aion-context = { path = ".", features = ["test-helpers"] }
//! ```

use crate::crypto::{SigningKey, VerifyingKey};
use crate::key_registry::{
    sign_revocation_record, sign_rotation_record, KeyRegistry, RevocationReason,
};
use crate::types::{AuthorId, FileId, VersionNumber};
use crate::Result;
use rand::SeedableRng;

/// Test keypair with both signing and verifying keys
///
/// Provides a convenient wrapper for testing signature operations.
#[derive(Clone)]
pub struct TestKeyPair {
    /// Signing key (private)
    pub signing: SigningKey,
    /// Verifying key (public)
    pub verifying: VerifyingKey,
}

impl TestKeyPair {
    /// Generate a random test keypair
    #[must_use]
    pub fn generate() -> Self {
        let signing = SigningKey::generate();
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    /// Generate a deterministic keypair from a seed.
    ///
    /// Useful for reproducible tests.
    ///
    /// # Errors
    ///
    /// Returns an error if `SigningKey::from_bytes` rejects the
    /// derived 32 bytes. Ed25519 accepts any 32-byte input as a
    /// seed, so in normal operation this branch is unreachable;
    /// the fallible signature exists so downstream callers
    /// compiling with `feature = "test-helpers"` do not inherit
    /// a library-level panic (RFC-0033 C1).
    pub fn from_seed(seed: u64) -> crate::Result<Self> {
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let mut key_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut key_bytes);

        let signing = SigningKey::from_bytes(&key_bytes)?;
        let verifying = signing.verifying_key();
        Ok(Self { signing, verifying })
    }

    /// Sign a message with this keypair
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message)
    }

    /// Verify a signature with this keypair
    ///
    /// # Errors
    ///
    /// Returns an error if signature verification fails
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> crate::Result<()> {
        self.verifying.verify(message, signature)
    }
}

/// Generate a test `FileId`
#[must_use]
pub const fn test_file_id() -> FileId {
    FileId(42)
}

/// Generate a test `FileId` with specific value
#[must_use]
pub const fn test_file_id_with_value(value: u64) -> FileId {
    FileId(value)
}

/// Generate a test `AuthorId`
#[must_use]
pub const fn test_author_id() -> AuthorId {
    AuthorId(1001)
}

/// Generate a test `AuthorId` with specific value
#[must_use]
pub const fn test_author_id_with_value(value: u64) -> AuthorId {
    AuthorId(value)
}

/// Generate a test `VersionNumber`
#[must_use]
pub const fn test_version() -> VersionNumber {
    VersionNumber(1)
}

/// Generate a test `VersionNumber` with specific value
#[must_use]
pub const fn test_version_with_value(value: u64) -> VersionNumber {
    VersionNumber(value)
}

/// Generate deterministic test data
///
/// Creates repeatable test data for a given seed and size.
#[must_use]
pub fn test_data(seed: u64, size: usize) -> Vec<u8> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut data = vec![0u8; size];
    rand::RngCore::fill_bytes(&mut rng, &mut data);
    data
}

/// Generate random test data
#[must_use]
pub fn random_test_data(size: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut data = vec![0u8; size];
    rand::rngs::OsRng.fill_bytes(&mut data);
    data
}

/// Test data builder for creating structured test data
///
/// Provides a fluent interface for building test data with specific characteristics.
///
/// # Examples
///
/// ```rust,ignore
/// use aion_context::test_helpers::TestDataBuilder;
///
/// let data = TestDataBuilder::new()
///     .size(1024)
///     .seed(12345)
///     .build();
/// ```
pub struct TestDataBuilder {
    size: usize,
    seed: Option<u64>,
    pattern: Option<u8>,
}

impl TestDataBuilder {
    /// Create a new test data builder with default values
    #[must_use]
    pub const fn new() -> Self {
        Self {
            size: 1024,
            seed: None,
            pattern: None,
        }
    }

    /// Set the size of the test data
    #[must_use]
    pub const fn size(mut self, size: usize) -> Self {
        self.size = size;
        self
    }

    /// Set the seed for deterministic generation
    #[must_use]
    pub const fn seed(mut self, seed: u64) -> Self {
        self.seed = Some(seed);
        self
    }

    /// Set a repeating pattern byte
    #[must_use]
    pub const fn pattern(mut self, pattern: u8) -> Self {
        self.pattern = Some(pattern);
        self
    }

    /// Build the test data
    #[must_use]
    pub fn build(self) -> Vec<u8> {
        self.pattern.map_or_else(
            || {
                self.seed.map_or_else(
                    || random_test_data(self.size),
                    |seed| test_data(seed, self.size),
                )
            },
            |pattern| vec![pattern; self.size],
        )
    }
}

impl Default for TestDataBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Test timestamp generator
///
/// Returns a fixed timestamp for deterministic tests.
#[must_use]
pub const fn test_timestamp() -> u64 {
    1_700_000_000_000 // 2023-11-14 22:13:20 UTC
}

/// Test timestamp with offset
///
/// # Panics
///
/// Panics if the offset would cause an overflow (test code only)
#[must_use]
#[allow(clippy::arithmetic_side_effects)] // Acceptable in test helpers
pub const fn test_timestamp_with_offset(offset_ms: u64) -> u64 {
    test_timestamp() + offset_ms
}

/// Convenience wrapper around [`KeyRegistry`] for test and
/// downstream-test-helpers use — issue #18 / RFC-0034 Open Q1.
///
/// Every method is a small composition over the public
/// [`KeyRegistry`] API (sign → apply) so test code can pin an
/// author, rotate, and revoke without re-implementing the
/// 5-line ceremony each time. `TestRegistry` is intentionally a
/// newtype rather than a `&KeyRegistry` typedef — it is for
/// tests only and must not leak into production code paths.
///
/// Gated behind `#[cfg(any(test, feature = "test-helpers"))]` via
/// this module's top-level attribute.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "test-helpers")] {
/// use aion_context::crypto::SigningKey;
/// use aion_context::test_helpers::TestRegistry;
///
/// let master = SigningKey::generate();
/// let op = SigningKey::generate();
/// let mut reg = TestRegistry::new();
/// let author = reg.pin(&master, &op).unwrap();
/// // `reg.as_registry()` is the same `&KeyRegistry` every
/// // `verify_*_with_registry` call on the crate expects.
/// assert!(reg.as_registry().active_epoch_at(author, 1).is_some());
/// # }
/// ```
#[derive(Debug, Default)]
pub struct TestRegistry {
    inner: KeyRegistry,
    next_author_id: u64,
}

impl TestRegistry {
    /// Construct an empty test registry. Author ids start at 1.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: KeyRegistry::new(),
            next_author_id: 1,
        }
    }

    /// Pin a fresh author whose master and operational keys are
    /// `master` and `operational`. A new sequential `AuthorId` is
    /// allocated and returned.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the registry rejects the registration
    /// (should never happen under normal use since the id is
    /// freshly allocated).
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "test-helpers")] {
    /// # use aion_context::crypto::SigningKey;
    /// # use aion_context::test_helpers::TestRegistry;
    /// let (m, op) = (SigningKey::generate(), SigningKey::generate());
    /// let mut reg = TestRegistry::new();
    /// let author = reg.pin(&m, &op).unwrap();
    /// assert_ne!(author.as_u64(), 0);
    /// # }
    /// ```
    pub fn pin(&mut self, master: &SigningKey, operational: &SigningKey) -> Result<AuthorId> {
        let author = AuthorId::new(self.next_author_id);
        self.next_author_id = self.next_author_id.saturating_add(1);
        self.inner.register_author(
            author,
            master.verifying_key(),
            operational.verifying_key(),
            0,
        )?;
        Ok(author)
    }

    /// Pin an author with an explicit `id` (useful when the test
    /// already has a fixed author id from a file header or test
    /// vector).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the id is already registered.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "test-helpers")] {
    /// # use aion_context::crypto::SigningKey;
    /// # use aion_context::test_helpers::TestRegistry;
    /// # use aion_context::types::AuthorId;
    /// let (m, op) = (SigningKey::generate(), SigningKey::generate());
    /// let mut reg = TestRegistry::new();
    /// reg.pin_with_id(AuthorId::new(50001), &m, &op).unwrap();
    /// # }
    /// ```
    pub fn pin_with_id(
        &mut self,
        author: AuthorId,
        master: &SigningKey,
        operational: &SigningKey,
    ) -> Result<()> {
        self.inner.register_author(
            author,
            master.verifying_key(),
            operational.verifying_key(),
            0,
        )
    }

    /// Rotate `author`'s currently-active epoch to a new one
    /// whose operational key is `new_op`, effective at
    /// `effective_version`. Returns the new epoch number.
    ///
    /// Internally signs a rotation record with `master` and
    /// applies it. Fails if the rotation preconditions don't hold
    /// (e.g. non-monotonic version, wrong current epoch).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the author is unknown, no currently-active
    /// epoch exists, or the master signature does not verify
    /// (which can only happen if `master` is different from the
    /// key the author was pinned with).
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "test-helpers")] {
    /// # use aion_context::crypto::SigningKey;
    /// # use aion_context::test_helpers::TestRegistry;
    /// let (master, op0, op1) = (
    ///     SigningKey::generate(),
    ///     SigningKey::generate(),
    ///     SigningKey::generate(),
    /// );
    /// let mut reg = TestRegistry::new();
    /// let author = reg.pin(&master, &op0).unwrap();
    /// let new_epoch = reg.rotate(author, &master, &op1, 100).unwrap();
    /// assert_eq!(new_epoch, 1);
    /// # }
    /// ```
    pub fn rotate(
        &mut self,
        author: AuthorId,
        master: &SigningKey,
        new_op: &SigningKey,
        effective_version: u64,
    ) -> Result<u32> {
        let current_epoch = self
            .inner
            .epochs_for(author)
            .iter()
            .filter(|e| e.is_valid_for(effective_version.saturating_sub(1)))
            .map(|e| e.epoch)
            .next_back()
            .or_else(|| self.inner.epochs_for(author).iter().map(|e| e.epoch).max())
            .unwrap_or(0);
        let new_epoch = current_epoch.saturating_add(1);
        let record = sign_rotation_record(
            author,
            current_epoch,
            new_epoch,
            new_op.verifying_key().to_bytes(),
            effective_version,
            master,
        );
        self.inner.apply_rotation(&record)?;
        Ok(new_epoch)
    }

    /// Revoke `author`'s currently-active epoch as of
    /// `effective_version`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the author is unknown, no currently-active
    /// epoch exists, or the master signature does not verify.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "test-helpers")] {
    /// # use aion_context::crypto::SigningKey;
    /// # use aion_context::test_helpers::TestRegistry;
    /// # use aion_context::key_registry::RevocationReason;
    /// let (master, op) = (SigningKey::generate(), SigningKey::generate());
    /// let mut reg = TestRegistry::new();
    /// let author = reg.pin(&master, &op).unwrap();
    /// reg.revoke(author, &master, RevocationReason::Compromised, 50).unwrap();
    /// assert!(reg.as_registry().active_epoch_at(author, 100).is_none());
    /// # }
    /// ```
    pub fn revoke(
        &mut self,
        author: AuthorId,
        master: &SigningKey,
        reason: RevocationReason,
        effective_version: u64,
    ) -> Result<()> {
        let active_epoch = self
            .inner
            .epochs_for(author)
            .iter()
            .find(|e| e.is_valid_for(effective_version.saturating_sub(1)))
            .map(|e| e.epoch)
            .or_else(|| self.inner.epochs_for(author).iter().map(|e| e.epoch).max())
            .unwrap_or(0);
        let record =
            sign_revocation_record(author, active_epoch, reason, effective_version, master);
        self.inner.apply_revocation(&record)
    }

    /// View the underlying [`KeyRegistry`] — pass this to any
    /// `verify_*_with_registry` function.
    #[must_use]
    pub const fn as_registry(&self) -> &KeyRegistry {
        &self.inner
    }
}

impl AsRef<KeyRegistry> for TestRegistry {
    fn as_ref(&self) -> &KeyRegistry {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod keypair {
        use super::*;

        #[test]
        fn should_generate_random_keypair() {
            let kp1 = TestKeyPair::generate();
            let kp2 = TestKeyPair::generate();

            // Different keypairs should have different keys
            assert_ne!(kp1.signing.to_bytes(), kp2.signing.to_bytes());
        }

        #[test]
        fn should_generate_deterministic_keypair_from_seed() {
            let kp1 = TestKeyPair::from_seed(12345).unwrap_or_else(|_| std::process::abort());
            let kp2 = TestKeyPair::from_seed(12345).unwrap_or_else(|_| std::process::abort());

            // Same seed should produce same keypair
            assert_eq!(kp1.signing.to_bytes(), kp2.signing.to_bytes());
        }

        #[test]
        fn should_sign_and_verify() {
            let kp = TestKeyPair::generate();
            let message = b"test message";
            let signature = kp.sign(message);

            assert!(kp.verify(message, &signature).is_ok());
        }

        #[test]
        fn should_reject_invalid_signature() {
            let kp = TestKeyPair::generate();
            let message = b"test message";
            let mut signature = kp.sign(message);

            // Tamper with signature
            signature[0] ^= 1;

            assert!(kp.verify(message, &signature).is_err());
        }
    }

    mod identifiers {
        use super::*;

        #[test]
        fn should_create_test_file_id() {
            let id = test_file_id();
            assert_eq!(id.as_u64(), 42);
        }

        #[test]
        fn should_create_test_file_id_with_value() {
            let id = test_file_id_with_value(12345);
            assert_eq!(id.as_u64(), 12345);
        }

        #[test]
        fn should_create_test_author_id() {
            let id = test_author_id();
            assert_eq!(id.as_u64(), 1001);
        }

        #[test]
        fn should_create_test_version() {
            let version = test_version();
            assert_eq!(version.as_u64(), 1);
        }
    }

    mod test_data_generation {
        use super::*;

        #[test]
        fn should_generate_deterministic_test_data() {
            let data1 = test_data(12345, 100);
            let data2 = test_data(12345, 100);

            assert_eq!(data1, data2);
            assert_eq!(data1.len(), 100);
        }

        #[test]
        fn should_generate_different_data_for_different_seeds() {
            let data1 = test_data(12345, 100);
            let data2 = test_data(54321, 100);

            assert_ne!(data1, data2);
        }

        #[test]
        fn should_generate_random_test_data() {
            let data1 = random_test_data(100);
            let data2 = random_test_data(100);

            assert_eq!(data1.len(), 100);
            assert_eq!(data2.len(), 100);
            // Very unlikely to be equal
            assert_ne!(data1, data2);
        }

        #[test]
        fn should_build_test_data_with_size() {
            let data = TestDataBuilder::new().size(500).build();
            assert_eq!(data.len(), 500);
        }

        #[test]
        fn should_build_test_data_with_seed() {
            let data1 = TestDataBuilder::new().seed(12345).build();
            let data2 = TestDataBuilder::new().seed(12345).build();
            assert_eq!(data1, data2);
        }

        #[test]
        fn should_build_test_data_with_pattern() {
            let data = TestDataBuilder::new().size(100).pattern(0xAB).build();
            assert_eq!(data.len(), 100);
            assert!(data.iter().all(|&b| b == 0xAB));
        }
    }

    mod timestamps {
        use super::*;

        #[test]
        fn should_generate_test_timestamp() {
            let ts = test_timestamp();
            assert_eq!(ts, 1_700_000_000_000);
        }

        #[test]
        fn should_generate_timestamp_with_offset() {
            let ts = test_timestamp_with_offset(1000);
            assert_eq!(ts, 1_700_000_001_000);
        }
    }

    #[allow(clippy::unwrap_used)]
    mod test_registry {
        use super::*;
        use crate::signature_chain::{sign_version, verify_signature};
        use crate::types::VersionNumber;

        fn make_version(author: AuthorId, version: u64) -> crate::serializer::VersionEntry {
            crate::serializer::VersionEntry::new(
                VersionNumber(version),
                [0u8; 32],
                [0xAB; 32],
                author,
                1_700_000_000_000_000_000,
                0,
                0,
            )
        }

        #[test]
        fn pin_returns_registry_with_active_epoch_for_new_author() {
            let (master, op) = (SigningKey::generate(), SigningKey::generate());
            let mut reg = TestRegistry::new();
            let author = reg.pin(&master, &op).unwrap();
            assert!(reg.as_registry().active_epoch_at(author, 1).is_some());
        }

        #[test]
        fn pin_allocates_sequential_ids() {
            let mut reg = TestRegistry::new();
            let (ma, opa) = (SigningKey::generate(), SigningKey::generate());
            let (mb, opb) = (SigningKey::generate(), SigningKey::generate());
            let a = reg.pin(&ma, &opa).unwrap();
            let b = reg.pin(&mb, &opb).unwrap();
            assert_ne!(a, b);
            assert_eq!(b.as_u64(), a.as_u64().saturating_add(1));
        }

        #[test]
        fn pin_with_id_uses_the_supplied_id() {
            let (m, op) = (SigningKey::generate(), SigningKey::generate());
            let mut reg = TestRegistry::new();
            let chosen = AuthorId::new(50_001);
            reg.pin_with_id(chosen, &m, &op).unwrap();
            assert!(reg.as_registry().active_epoch_at(chosen, 1).is_some());
        }

        #[test]
        fn pinned_registry_accepts_signature_made_with_the_pinned_key() {
            let (master, op) = (SigningKey::generate(), SigningKey::generate());
            let mut reg = TestRegistry::new();
            let author = reg.pin(&master, &op).unwrap();
            let version = make_version(author, 7);
            let sig = sign_version(&version, &op);
            verify_signature(&version, &sig, reg.as_registry()).unwrap();
        }

        #[test]
        fn rotate_rejects_signatures_made_with_the_rotated_out_key() {
            let (master, op0, op1) = (
                SigningKey::generate(),
                SigningKey::generate(),
                SigningKey::generate(),
            );
            let mut reg = TestRegistry::new();
            let author = reg.pin(&master, &op0).unwrap();
            let new_epoch = reg.rotate(author, &master, &op1, 100).unwrap();
            assert_eq!(new_epoch, 1);
            // A signature at version 200 signed by the rotated-out op0 must be rejected.
            let version = make_version(author, 200);
            let sig = sign_version(&version, &op0);
            assert!(verify_signature(&version, &sig, reg.as_registry()).is_err());
        }

        #[test]
        fn rotate_accepts_signatures_made_with_the_new_key_after_effective_version() {
            let (master, op0, op1) = (
                SigningKey::generate(),
                SigningKey::generate(),
                SigningKey::generate(),
            );
            let mut reg = TestRegistry::new();
            let author = reg.pin(&master, &op0).unwrap();
            reg.rotate(author, &master, &op1, 100).unwrap();
            let version = make_version(author, 150);
            let sig = sign_version(&version, &op1);
            verify_signature(&version, &sig, reg.as_registry()).unwrap();
        }

        #[test]
        fn revoke_rejects_signatures_after_effective_version() {
            let (master, op) = (SigningKey::generate(), SigningKey::generate());
            let mut reg = TestRegistry::new();
            let author = reg.pin(&master, &op).unwrap();
            reg.revoke(author, &master, RevocationReason::Compromised, 50)
                .unwrap();
            let version = make_version(author, 100);
            let sig = sign_version(&version, &op);
            assert!(verify_signature(&version, &sig, reg.as_registry()).is_err());
        }

        #[test]
        fn revoke_preserves_signatures_before_effective_version() {
            let (master, op) = (SigningKey::generate(), SigningKey::generate());
            let mut reg = TestRegistry::new();
            let author = reg.pin(&master, &op).unwrap();
            reg.revoke(author, &master, RevocationReason::Superseded, 100)
                .unwrap();
            // A signature at version 50 (before revocation) is still valid.
            let version = make_version(author, 50);
            let sig = sign_version(&version, &op);
            verify_signature(&version, &sig, reg.as_registry()).unwrap();
        }

        #[test]
        fn as_ref_matches_as_registry() {
            let (m, op) = (SigningKey::generate(), SigningKey::generate());
            let mut reg = TestRegistry::new();
            reg.pin(&m, &op).unwrap();
            let via_method = reg.as_registry() as *const KeyRegistry;
            let via_asref: *const KeyRegistry = reg.as_ref();
            assert_eq!(via_method, via_asref);
        }
    }
}
