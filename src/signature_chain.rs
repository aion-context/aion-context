// SPDX-License-Identifier: MIT OR Apache-2.0
//! Signature chain protocol for AION v2
//!
//! This module implements the version signing protocol as specified in RFC-0005.
//! It provides cryptographic signing and verification of version entries to ensure
//! chain integrity, authenticity, and non-repudiation.
//!
//! # Protocol Overview
//!
//! Each version in an AION file is signed using Ed25519. The signing process:
//!
//! 1. **Canonical serialization**: Version data is serialized in a deterministic format
//! 2. **Domain separation**: A prefix prevents cross-protocol signature reuse
//! 3. **Hash computation**: Blake3 hash for chain linking
//! 4. **Ed25519 signing**: Cryptographic signature over the canonical message
//!
//! # Security Properties
//!
//! - **Immutability**: Signed versions cannot be modified without detection
//! - **Non-repudiation**: Authors cannot deny their signatures
//! - **Chain integrity**: Hash chain prevents version injection attacks
//! - **Authenticity**: Each version is provably authored by key holder
//!
//! # Usage Example
//!
//! ```
//! use aion_context::signature_chain::{sign_version, compute_version_hash};
//! use aion_context::serializer::VersionEntry;
//! use aion_context::crypto::SigningKey;
//! use aion_context::types::{AuthorId, VersionNumber};
//!
//! // Create a version entry
//! let version = VersionEntry::new(
//!     VersionNumber::GENESIS,
//!     [0u8; 32],  // No parent for genesis
//!     [0xAB; 32], // Rules hash
//!     AuthorId::new(50001),
//!     1700000000_000_000_000,
//!     0,
//!     0,
//! );
//!
//! // Compute the hash for chain linking
//! let version_hash = compute_version_hash(&version);
//!
//! // Sign the version
//! let signing_key = SigningKey::generate().unwrap();
//! let signature_entry = sign_version(&version, &signing_key);
//! ```

use crate::crypto::{hash, SigningKey, VerifyingKey};
use crate::format::{FormatVersion, RulesMode};
use crate::serializer::{SignatureEntry, VersionEntry};
use crate::types::{AuthorId, FileId};
use crate::Result;
use subtle::ConstantTimeEq;

/// Domain separator for version signatures
///
/// This prefix is prepended to all signed messages to prevent cross-protocol
/// signature reuse attacks. An attacker cannot repurpose signatures from
/// other applications that use Ed25519.
const SIGNATURE_DOMAIN: &[u8] = b"AION_V2_VERSION_SIGNATURE_V1";

/// Domain separator for multi-party attestation messages (RFC-0021).
///
/// Distinct from [`SIGNATURE_DOMAIN`] so that a single-signer version
/// signature cannot be replayed as a multi-party attestation nor vice versa.
const ATTESTATION_DOMAIN: &[u8] = b"AION_V2_ATTESTATION_V1";

/// Domain separator for format-v3 version signatures (RFC-0039).
pub const SIGNATURE_DOMAIN_V3: &[u8] = b"AION_V3_VERSION_SIGNATURE_V1\0";

/// Domain separator for format-v3 version hashes (RFC-0039).
///
/// Distinct from [`SIGNATURE_DOMAIN_V3`] so the hash that `parent_hash`
/// links to is never the same BLAKE3 input as a signed message.
pub const VERSION_HASH_DOMAIN_V3: &[u8] = b"AION_V3_VERSION_HASH_V1\0";

/// Domain separator for format-v3 attestations (RFC-0021, RFC-0039).
pub const ATTESTATION_DOMAIN_V3: &[u8] = b"AION_V3_ATTESTATION_V1\0";

/// Length of the fields a v3 message binds, after its domain:
/// format version (2), `file_id` (8), mode (1), and the 100 bytes of
/// version fields that v2 also signs.
const V3_BOUND_FIELDS_LEN: usize = 2 + 8 + 1 + 100;

/// Compute the canonical message to be signed for a version entry
///
/// The canonical format ensures deterministic serialization:
/// - Domain separator (28 bytes)
/// - Version number (8 bytes, little-endian)
/// - Parent hash (32 bytes, zeros for genesis)
/// - Rules hash (32 bytes)
/// - Author ID (8 bytes, little-endian)
/// - Timestamp (8 bytes, little-endian)
/// - Message offset (8 bytes, little-endian)
/// - Message length (4 bytes, little-endian)
///
/// Total: 128 bytes + domain separator
#[must_use]
#[allow(clippy::arithmetic_side_effects)] // Fixed capacity calculation
pub fn canonical_version_message(version: &VersionEntry) -> Vec<u8> {
    // Capacity: domain(28) + version(8) + parent(32) + rules(32) + author(8) + ts(8) + offset(8) + len(4) = 128
    let mut message = Vec::with_capacity(128 + SIGNATURE_DOMAIN.len());

    // Domain separator (prevents cross-protocol attacks)
    message.extend_from_slice(SIGNATURE_DOMAIN);

    // Version number (8 bytes LE)
    message.extend_from_slice(&version.version_number.to_le_bytes());

    // Parent hash (32 bytes, zeros for genesis)
    message.extend_from_slice(&version.parent_hash);

    // Rules hash (32 bytes)
    message.extend_from_slice(&version.rules_hash);

    // Author ID (8 bytes LE)
    message.extend_from_slice(&version.author_id.to_le_bytes());

    // Timestamp (8 bytes LE)
    message.extend_from_slice(&version.timestamp.to_le_bytes());

    // Message offset (8 bytes LE)
    message.extend_from_slice(&version.message_offset.to_le_bytes());

    // Message length (4 bytes LE)
    message.extend_from_slice(&version.message_length.to_le_bytes());

    message
}

/// Compute the Blake3 hash of a version entry for chain linking
///
/// This hash is used as the `parent_hash` in the next version, creating
/// the cryptographic chain that ensures tamper detection.
///
/// # Example
///
/// ```
/// use aion_context::signature_chain::compute_version_hash;
/// use aion_context::serializer::VersionEntry;
/// use aion_context::types::{AuthorId, VersionNumber};
///
/// let version = VersionEntry::new(
///     VersionNumber::GENESIS,
///     [0u8; 32],
///     [0xAB; 32],
///     AuthorId::new(1),
///     1700000000_000_000_000,
///     0,
///     0,
/// );
///
/// let hash = compute_version_hash(&version);
/// assert_eq!(hash.len(), 32);
/// ```
#[must_use]
pub fn compute_version_hash(version: &VersionEntry) -> [u8; 32] {
    // Hash the canonical message (without domain separator for chain linking)
    let mut data = Vec::with_capacity(100);

    data.extend_from_slice(&version.version_number.to_le_bytes());
    data.extend_from_slice(&version.parent_hash);
    data.extend_from_slice(&version.rules_hash);
    data.extend_from_slice(&version.author_id.to_le_bytes());
    data.extend_from_slice(&version.timestamp.to_le_bytes());
    data.extend_from_slice(&version.message_offset.to_le_bytes());
    data.extend_from_slice(&version.message_length.to_le_bytes());

    hash(&data)
}

/// Sign a version entry and create a signature entry
///
/// This function:
/// 1. Constructs the canonical message from the version entry
/// 2. Signs it with the provided Ed25519 signing key
/// 3. Returns a `SignatureEntry` containing the public key and signature
///
/// # Example
///
/// ```
/// use aion_context::signature_chain::sign_version;
/// use aion_context::serializer::VersionEntry;
/// use aion_context::crypto::SigningKey;
/// use aion_context::types::{AuthorId, VersionNumber};
///
/// let version = VersionEntry::new(
///     VersionNumber::GENESIS,
///     [0u8; 32],
///     [0xAB; 32],
///     AuthorId::new(50001),
///     1700000000_000_000_000,
///     0,
///     0,
/// );
///
/// let signing_key = SigningKey::generate().unwrap();
/// let signature_entry = sign_version(&version, &signing_key);
///
/// assert_eq!(signature_entry.author_id, 50001);
/// ```
#[must_use]
pub fn sign_version(version: &VersionEntry, signing_key: &SigningKey) -> SignatureEntry {
    let message = canonical_version_message(version);
    let signature = signing_key.sign(&message);
    let public_key = signing_key.verifying_key().to_bytes();

    SignatureEntry::new(AuthorId::new(version.author_id), public_key, signature)
}

/// Verify a single-signer version signature against a pinned
/// [`KeyRegistry`](crate::key_registry::KeyRegistry) — RFC-0034.
///
/// This is the canonical verifier. It cross-checks
/// `signature.public_key` against the active epoch for
/// `(version.author_id, version.version_number)` in `registry`
/// before running the Ed25519 check, closing the
/// `public_key`-substitution gap that the Phase A raw-key path
/// left open.
///
/// # Errors
///
/// Returns [`crate::AionError::SignatureVerificationFailed`] if:
/// - `version.author_id != signature.author_id`,
/// - `registry` has no active epoch for the signer at
///   `version.version_number`,
/// - the signature's embedded public key does not match that
///   epoch's public key,
/// - the Ed25519 signature does not verify.
///
/// # Example
///
/// ```
/// use aion_context::signature_chain::{sign_version, verify_signature};
/// use aion_context::serializer::VersionEntry;
/// use aion_context::crypto::SigningKey;
/// use aion_context::key_registry::KeyRegistry;
/// use aion_context::types::{AuthorId, VersionNumber};
///
/// let author = AuthorId::new(50001);
/// let master = SigningKey::generate().unwrap();
/// let signing_key = SigningKey::generate().unwrap();
/// let mut registry = KeyRegistry::new();
/// registry
///     .register_author(author, master.verifying_key(), signing_key.verifying_key(), 0)
///     .unwrap();
///
/// let version = VersionEntry::new(
///     VersionNumber::GENESIS,
///     [0u8; 32],
///     [0xAB; 32],
///     author,
///     1700000000_000_000_000,
///     0,
///     0,
/// );
/// let signature_entry = sign_version(&version, &signing_key);
/// assert!(verify_signature(&version, &signature_entry, &registry).is_ok());
/// ```
pub fn verify_signature(
    version: &VersionEntry,
    signature: &SignatureEntry,
    registry: &crate::key_registry::KeyRegistry,
) -> Result<()> {
    if version.author_id != signature.author_id {
        emit_sig_rejected(
            version.version_number,
            AuthorId::new(signature.author_id),
            "author_mismatch",
        );
        return Err(crate::AionError::SignatureVerificationFailed {
            version: version.version_number,
            author: AuthorId::new(signature.author_id),
        });
    }
    let signer = AuthorId::new(version.author_id);
    let epoch = registry
        .active_epoch_at(signer, version.version_number)
        .ok_or_else(|| {
            emit_sig_rejected(version.version_number, signer, "no_active_epoch");
            crate::AionError::SignatureVerificationFailed {
                version: version.version_number,
                author: signer,
            }
        })?;
    if !bool::from(signature.public_key.ct_eq(&epoch.public_key)) {
        emit_sig_rejected(version.version_number, signer, "pubkey_substitution");
        return Err(crate::AionError::SignatureVerificationFailed {
            version: version.version_number,
            author: signer,
        });
    }
    let message = canonical_version_message(version);
    let verifying_key = VerifyingKey::from_bytes(&signature.public_key)?;
    verifying_key
        .verify(&message, &signature.signature)
        .inspect_err(|_| {
            emit_sig_rejected(version.version_number, signer, "bad_signature");
        })
}

fn emit_sig_rejected(version: u64, author: AuthorId, reason: &'static str) {
    tracing::warn!(
        event = "signature_rejected",
        version,
        author = %crate::obs::author_short(author),
        reason,
    );
}

/// Build the canonical attestation message binding `(version, signer)` — RFC-0021.
///
/// Each signer in a multi-party attestation signs a message that embeds
/// the full version identity **and** the signer's own `AuthorId`. This
/// prevents signature replay across signers and across protocols.
#[must_use]
#[allow(clippy::arithmetic_side_effects)] // capacity calculation over consts
pub fn canonical_attestation_message(version: &VersionEntry, signer: AuthorId) -> Vec<u8> {
    let mut message = Vec::with_capacity(128 + 8 + ATTESTATION_DOMAIN.len());
    message.extend_from_slice(ATTESTATION_DOMAIN);
    message.extend_from_slice(&version.version_number.to_le_bytes());
    message.extend_from_slice(&version.parent_hash);
    message.extend_from_slice(&version.rules_hash);
    message.extend_from_slice(&version.author_id.to_le_bytes());
    message.extend_from_slice(&version.timestamp.to_le_bytes());
    message.extend_from_slice(&version.message_offset.to_le_bytes());
    message.extend_from_slice(&version.message_length.to_le_bytes());
    message.extend_from_slice(&signer.as_u64().to_le_bytes());
    message
}

/// The fields every v3 version message binds, in order:
/// `format_version u16 ‖ file_id u64 ‖ rules_mode u8 ‖ version u64 ‖
/// parent_hash[32] ‖ rules_commitment[32] ‖ author u64 ‖ timestamp u64 ‖
/// message_offset u64 ‖ message_length u32`, all little-endian.
fn v3_bound_fields(version: &VersionEntry, file_id: FileId) -> Result<Vec<u8>> {
    let mode = RulesMode::of(version)?;
    let mut fields = Vec::with_capacity(V3_BOUND_FIELDS_LEN);
    fields.extend_from_slice(&FormatVersion::V3.as_u16().to_le_bytes());
    fields.extend_from_slice(&file_id.as_u64().to_le_bytes());
    fields.push(mode.as_u8());
    fields.extend_from_slice(&version.version_number.to_le_bytes());
    fields.extend_from_slice(&version.parent_hash);
    fields.extend_from_slice(&version.rules_hash);
    fields.extend_from_slice(&version.author_id.to_le_bytes());
    fields.extend_from_slice(&version.timestamp.to_le_bytes());
    fields.extend_from_slice(&version.message_offset.to_le_bytes());
    fields.extend_from_slice(&version.message_length.to_le_bytes());
    Ok(fields)
}

/// Canonical message a format-v3 version signature covers (RFC-0039).
///
/// `SIGNATURE_DOMAIN_V3 ‖ format_version ‖ file_id ‖ rules_mode ‖` the
/// v2 version fields. Binding `file_id` and the mode means a signed entry
/// cannot be moved into another file or reinterpreted under another mode.
/// In v3, `rules_hash` holds the rules commitment.
///
/// # Errors
///
/// Returns [`crate::AionError::InvalidFormat`] if the entry's rules mode
/// byte is unknown or another reserved byte is non-zero.
///
/// Crate-internal: callers go through [`crate::format::FileContext`], so
/// v3 construction cannot be applied to a v2 file by mistake.
pub(crate) fn canonical_version_message_v3(
    version: &VersionEntry,
    file_id: FileId,
) -> Result<Vec<u8>> {
    let fields = v3_bound_fields(version, file_id)?;
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN_V3.len().saturating_add(fields.len()));
    message.extend_from_slice(SIGNATURE_DOMAIN_V3);
    message.extend_from_slice(&fields);
    Ok(message)
}

/// Hash of a format-v3 version entry, the value the next version's
/// `parent_hash` links to (RFC-0039).
///
/// Covers the same fields as [`canonical_version_message_v3`], including
/// the rules mode, under [`VERSION_HASH_DOMAIN_V3`]. So the same version
/// number re-signed with a different mode is a different version.
///
/// # Errors
///
/// Returns [`crate::AionError::InvalidFormat`] if the entry's rules mode
/// byte is unknown or another reserved byte is non-zero.
pub(crate) fn compute_version_hash_v3(version: &VersionEntry, file_id: FileId) -> Result<[u8; 32]> {
    let fields = v3_bound_fields(version, file_id)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(VERSION_HASH_DOMAIN_V3);
    hasher.update(&fields);
    Ok(*hasher.finalize().as_bytes())
}

/// Canonical message a format-v3 attestation signature covers
/// (RFC-0021, RFC-0039): `ATTESTATION_DOMAIN_V3 ‖` the v3 bound fields
/// `‖ signer u64`.
///
/// # Errors
///
/// Returns [`crate::AionError::InvalidFormat`] if the entry's rules mode
/// byte is unknown or another reserved byte is non-zero.
pub(crate) fn canonical_attestation_message_v3(
    version: &VersionEntry,
    file_id: FileId,
    signer: AuthorId,
) -> Result<Vec<u8>> {
    let fields = v3_bound_fields(version, file_id)?;
    let capacity = ATTESTATION_DOMAIN_V3
        .len()
        .saturating_add(fields.len())
        .saturating_add(8);
    let mut message = Vec::with_capacity(capacity);
    message.extend_from_slice(ATTESTATION_DOMAIN_V3);
    message.extend_from_slice(&fields);
    message.extend_from_slice(&signer.as_u64().to_le_bytes());
    Ok(message)
}

/// Produce an attestation signature over a version — RFC-0021.
///
/// Unlike [`sign_version`], the signer need not equal `version.author_id`:
/// attestations are multi-party by design. Returns a `SignatureEntry` whose
/// `author_id` is the attesting signer's id.
#[must_use]
pub fn sign_attestation(
    version: &VersionEntry,
    signer: AuthorId,
    signing_key: &SigningKey,
) -> SignatureEntry {
    let message = canonical_attestation_message(version, signer);
    let signature = signing_key.sign(&message);
    let public_key = signing_key.verifying_key().to_bytes();
    SignatureEntry::new(signer, public_key, signature)
}

/// Verify a multi-party attestation signature against a pinned
/// [`KeyRegistry`](crate::key_registry::KeyRegistry) — RFC-0021 / RFC-0034.
///
/// The signer identity is taken from `signature.author_id`; there
/// is no equality constraint against `version.author_id`
/// (attestations are multi-party by design).
///
/// # Errors
///
/// Returns `Err` if the registry has no active epoch for the
/// attester at `version.version_number`, if the signature's
/// embedded public key does not match that epoch, or if the
/// Ed25519 signature does not verify.
pub fn verify_attestation(
    version: &VersionEntry,
    signature: &SignatureEntry,
    registry: &crate::key_registry::KeyRegistry,
) -> Result<()> {
    let signer = AuthorId::new(signature.author_id);
    let epoch = registry
        .active_epoch_at(signer, version.version_number)
        .ok_or_else(|| {
            emit_sig_rejected(version.version_number, signer, "no_active_epoch");
            crate::AionError::SignatureVerificationFailed {
                version: version.version_number,
                author: signer,
            }
        })?;
    if !bool::from(signature.public_key.ct_eq(&epoch.public_key)) {
        emit_sig_rejected(version.version_number, signer, "pubkey_substitution");
        return Err(crate::AionError::SignatureVerificationFailed {
            version: version.version_number,
            author: signer,
        });
    }
    let message = canonical_attestation_message(version, signer);
    let verifying_key = VerifyingKey::from_bytes(&signature.public_key)?;
    verifying_key
        .verify(&message, &signature.signature)
        .inspect_err(|_| {
            emit_sig_rejected(version.version_number, signer, "bad_attestation");
        })
}

/// Verify signatures for multiple versions in batch, registry-pinned.
///
/// Applies [`verify_signature`] to every `(version, signature)`
/// pair: each must have a matching active epoch in `registry` at
/// the signed version number AND the Ed25519 signature must
/// verify under the pinned public key. Uses rayon in parallel
/// for batches of more than 10 pairs; sequential otherwise.
///
/// # Errors
///
/// - `AionError::InvalidFormat` if the two slices differ in length.
/// - `AionError::SignatureVerificationFailed` on the first pair
///   where registry lookup or the Ed25519 verify fails.
/// - `AionError::InvalidPublicKey` if any embedded public key is malformed.
pub fn verify_signatures_batch(
    versions: &[VersionEntry],
    signatures: &[SignatureEntry],
    registry: &crate::key_registry::KeyRegistry,
) -> Result<()> {
    if versions.len() != signatures.len() {
        return Err(crate::AionError::InvalidFormat {
            reason: format!(
                "Version and signature count mismatch: {} versions vs {} signatures",
                versions.len(),
                signatures.len()
            ),
        });
    }
    if versions.len() > 10 {
        use rayon::prelude::*;
        versions
            .par_iter()
            .zip(signatures.par_iter())
            .try_for_each(|(version, signature)| verify_signature(version, signature, registry))
    } else {
        for (version, signature) in versions.iter().zip(signatures.iter()) {
            verify_signature(version, signature, registry)?;
        }
        Ok(())
    }
}

/// Create a genesis version entry (version 1 with no parent)
///
/// # Arguments
///
/// * `rules_hash` - Blake3 hash of the initial rules content
/// * `author_id` - ID of the author creating the genesis version
/// * `timestamp` - Creation timestamp in nanoseconds since Unix epoch
/// * `message_offset` - Offset of commit message in string table
/// * `message_length` - Length of commit message in bytes
///
/// # Example
///
/// ```
/// use aion_context::signature_chain::create_genesis_version;
/// use aion_context::types::AuthorId;
///
/// let rules_hash = [0xAB; 32];
/// let version = create_genesis_version(
///     rules_hash,
///     AuthorId::new(50001),
///     1700000000_000_000_000,
///     0,
///     15,
/// );
///
/// assert_eq!(version.version_number, 1);
/// assert_eq!(version.parent_hash, [0u8; 32]); // No parent
/// ```
#[must_use]
pub const fn create_genesis_version(
    rules_hash: [u8; 32],
    author_id: AuthorId,
    timestamp: u64,
    message_offset: u64,
    message_length: u32,
) -> VersionEntry {
    VersionEntry::new(
        crate::types::VersionNumber::GENESIS,
        [0u8; 32], // No parent for genesis
        rules_hash,
        author_id,
        timestamp,
        message_offset,
        message_length,
    )
}

/// Create a new version entry linked to a parent
///
/// # Arguments
///
/// * `parent` - The parent version entry
/// * `rules_hash` - Blake3 hash of the new rules content
/// * `author_id` - ID of the author creating this version
/// * `timestamp` - Creation timestamp in nanoseconds since Unix epoch
/// * `message_offset` - Offset of commit message in string table
/// * `message_length` - Length of commit message in bytes
///
/// # Example
///
/// ```
/// use aion_context::signature_chain::{create_genesis_version, create_child_version, compute_version_hash};
/// use aion_context::types::AuthorId;
///
/// let genesis = create_genesis_version(
///     [0xAB; 32],
///     AuthorId::new(50001),
///     1700000000_000_000_000,
///     0,
///     15,
/// );
///
/// let child = create_child_version(
///     &genesis,
///     [0xCD; 32],
///     AuthorId::new(50001),
///     1700000001_000_000_000,
///     16,
///     12,
/// );
///
/// assert_eq!(child.version_number, 2);
/// assert_eq!(child.parent_hash, compute_version_hash(&genesis));
/// ```
#[must_use]
pub fn create_child_version(
    parent: &VersionEntry,
    rules_hash: [u8; 32],
    author_id: AuthorId,
    timestamp: u64,
    message_offset: u64,
    message_length: u32,
) -> VersionEntry {
    let parent_hash = compute_version_hash(parent);

    // Safe: version_number is u64, overflow is handled by VersionNumber::next() elsewhere
    #[allow(clippy::arithmetic_side_effects)]
    let next_version = parent.version_number + 1;

    VersionEntry::new(
        crate::types::VersionNumber(next_version),
        parent_hash,
        rules_hash,
        author_id,
        timestamp,
        message_offset,
        message_length,
    )
}

/// Verify the integrity of a hash chain across multiple versions
///
/// This function performs comprehensive verification of the version chain according
/// to RFC-0005. It validates:
///
/// 1. **Genesis validation**: First version must be version 1 with zero parent hash
/// 2. **Parent hash linking**: Each version's `parent_hash` must match the hash of the previous version
/// 3. **Version monotonicity**: Version numbers must increase by exactly 1
/// 4. **Chain continuity**: No gaps or breaks in the chain
///
/// # Arguments
///
/// * `versions` - Slice of version entries to verify (must be in order)
///
/// # Returns
///
/// * `Ok(())` - All checks passed
/// * `Err(AionError)` - Verification failed with specific error
///
/// # Errors
///
/// - `AionError::InvalidFormat` if versions slice is empty
/// - `AionError::InvalidVersionNumber` if genesis is not version 1
/// - `AionError::InvalidFormat` if genesis parent hash is not zero
/// - `AionError::BrokenVersionChain` if parent hash doesn't match
/// - `AionError::InvalidVersionNumber` if versions don't increment by 1
///
/// # Example
///
/// ```
/// use aion_context::signature_chain::{create_genesis_version, create_child_version, verify_hash_chain};
/// use aion_context::types::AuthorId;
///
/// let genesis = create_genesis_version(
///     [0xAB; 32],
///     AuthorId::new(50001),
///     1700000000_000_000_000,
///     0,
///     15,
/// );
///
/// let v2 = create_child_version(
///     &genesis,
///     [0xCD; 32],
///     AuthorId::new(50001),
///     1700000001_000_000_000,
///     16,
///     12,
/// );
///
/// // Verify the chain
/// let versions = vec![genesis, v2];
/// assert!(verify_hash_chain(&versions).is_ok());
/// ```
pub fn verify_hash_chain(versions: &[VersionEntry]) -> Result<()> {
    let genesis = versions
        .first()
        .ok_or_else(|| crate::AionError::InvalidFormat {
            reason: "Version chain is empty".to_string(),
        })?;
    verify_genesis_version(genesis)?;
    verify_chain_links(versions)
}

fn verify_genesis_version(genesis: &VersionEntry) -> Result<()> {
    if genesis.version_number != 1 {
        return Err(crate::AionError::InvalidVersionNumber {
            version: genesis.version_number,
            current: 1,
        });
    }
    if genesis.parent_hash != [0u8; 32] {
        return Err(crate::AionError::InvalidFormat {
            reason: format!(
                "Genesis version has non-zero parent hash: {:?}",
                genesis.parent_hash
            ),
        });
    }
    Ok(())
}

fn verify_chain_links(versions: &[VersionEntry]) -> Result<()> {
    for pair in versions.windows(2) {
        let [parent, current] = pair else { continue };
        let expected_version =
            parent
                .version_number
                .checked_add(1)
                .ok_or(crate::AionError::VersionOverflow {
                    max: parent.version_number,
                })?;
        if current.version_number != expected_version {
            return Err(crate::AionError::InvalidVersionNumber {
                version: current.version_number,
                current: expected_version,
            });
        }
        if current.parent_hash != compute_version_hash(parent) {
            return Err(crate::AionError::BrokenVersionChain {
                version: current.version_number,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::inconsistent_digit_grouping)]
mod tests {
    use super::*;
    use crate::crypto::SigningKey;
    use crate::key_registry::KeyRegistry;
    use crate::types::VersionNumber;

    /// Minimal test fixture: pin `signing_key` as the active operational
    /// key for `author_id` in a fresh [`KeyRegistry`]. Master key is a
    /// throwaway since these tests don't exercise rotation.
    fn reg_pinning(author_id: u64, signing_key: &SigningKey) -> KeyRegistry {
        let mut reg = KeyRegistry::new();
        let master = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
        reg.register_author(
            AuthorId::new(author_id),
            master.verifying_key(),
            signing_key.verifying_key(),
            0,
        )
        .unwrap_or_else(|_| std::process::abort());
        reg
    }

    mod canonical_serialization {
        use super::*;

        #[test]
        fn should_produce_deterministic_output() {
            let version = VersionEntry::new(
                VersionNumber::GENESIS,
                [0u8; 32],
                [0xAB; 32],
                AuthorId::new(50001),
                1700000000_000_000_000,
                0,
                15,
            );

            let msg1 = canonical_version_message(&version);
            let msg2 = canonical_version_message(&version);
            assert_eq!(msg1, msg2);
        }

        /// RFC-0039 golden vectors. The expected bytes are written out
        /// literally rather than rebuilt with `to_le_bytes`, so a swapped,
        /// resized, or reordered field fails here even when every
        /// round-trip property still passes.
        fn golden_v3_entry() -> VersionEntry {
            VersionEntry::new(
                crate::types::VersionNumber(0x0102_0304_0506_0708),
                [0x11; 32],
                [0x22; 32],
                AuthorId::new(0x0A0B_0C0D_0E0F_1011),
                0x2122_2324_2526_2728,
                0x3132_3334_3536_3738,
                0x4142_4344,
            )
            .with_rules_mode(crate::format::RulesMode::Confidential)
        }

        fn golden_v3_fields() -> Vec<u8> {
            let mut fields = vec![0x03, 0x00];
            fields.extend_from_slice(&[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]);
            fields.push(0x01);
            fields.extend_from_slice(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
            fields.extend_from_slice(&[0x11; 32]);
            fields.extend_from_slice(&[0x22; 32]);
            fields.extend_from_slice(&[0x11, 0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A]);
            fields.extend_from_slice(&[0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21]);
            fields.extend_from_slice(&[0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31]);
            fields.extend_from_slice(&[0x44, 0x43, 0x42, 0x41]);
            fields
        }

        const GOLDEN_FILE_ID: u64 = 0x1122_3344_5566_7788;

        #[test]
        fn v3_version_message_matches_golden_layout() {
            let mut expected = b"AION_V3_VERSION_SIGNATURE_V1\0".to_vec();
            expected.extend_from_slice(&golden_v3_fields());
            assert_eq!(expected.len(), 29 + 111);
            let actual =
                canonical_version_message_v3(&golden_v3_entry(), FileId::new(GOLDEN_FILE_ID))
                    .unwrap_or_else(|_| std::process::abort());
            assert_eq!(actual, expected);
        }

        #[test]
        fn v3_version_hash_matches_golden_layout() {
            let mut input = b"AION_V3_VERSION_HASH_V1\0".to_vec();
            input.extend_from_slice(&golden_v3_fields());
            let expected = *blake3::hash(&input).as_bytes();
            let actual = compute_version_hash_v3(&golden_v3_entry(), FileId::new(GOLDEN_FILE_ID))
                .unwrap_or_else(|_| std::process::abort());
            assert_eq!(actual, expected);
        }

        #[test]
        fn v3_attestation_message_matches_golden_layout() {
            let mut expected = b"AION_V3_ATTESTATION_V1\0".to_vec();
            expected.extend_from_slice(&golden_v3_fields());
            expected.extend_from_slice(&[0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01]);
            let actual = canonical_attestation_message_v3(
                &golden_v3_entry(),
                FileId::new(GOLDEN_FILE_ID),
                AuthorId::new(0x0123_4567_89AB_CDEF),
            )
            .unwrap_or_else(|_| std::process::abort());
            assert_eq!(actual, expected);
        }

        #[test]
        fn should_include_domain_separator() {
            let version = VersionEntry::new(
                VersionNumber::GENESIS,
                [0u8; 32],
                [0xAB; 32],
                AuthorId::new(1),
                1700000000_000_000_000,
                0,
                0,
            );

            let msg = canonical_version_message(&version);
            assert!(msg.starts_with(SIGNATURE_DOMAIN));
        }

        #[test]
        fn should_differ_for_different_versions() {
            let v1 = VersionEntry::new(
                VersionNumber(1),
                [0u8; 32],
                [0xAB; 32],
                AuthorId::new(1),
                1700000000_000_000_000,
                0,
                0,
            );

            let v2 = VersionEntry::new(
                VersionNumber(2),
                [0u8; 32],
                [0xAB; 32],
                AuthorId::new(1),
                1700000000_000_000_000,
                0,
                0,
            );

            assert_ne!(
                canonical_version_message(&v1),
                canonical_version_message(&v2)
            );
        }

        #[test]
        fn should_differ_for_different_parent_hashes() {
            let v1 = VersionEntry::new(
                VersionNumber(2),
                [0xAA; 32],
                [0xBB; 32],
                AuthorId::new(1),
                1700000000_000_000_000,
                0,
                0,
            );

            let v2 = VersionEntry::new(
                VersionNumber(2),
                [0xCC; 32],
                [0xBB; 32],
                AuthorId::new(1),
                1700000000_000_000_000,
                0,
                0,
            );

            assert_ne!(
                canonical_version_message(&v1),
                canonical_version_message(&v2)
            );
        }
    }

    mod version_hashing {
        use super::*;

        #[test]
        fn should_produce_32_byte_hash() {
            let version = VersionEntry::new(
                VersionNumber::GENESIS,
                [0u8; 32],
                [0xAB; 32],
                AuthorId::new(1),
                1700000000_000_000_000,
                0,
                0,
            );

            let hash = compute_version_hash(&version);
            assert_eq!(hash.len(), 32);
        }

        #[test]
        fn should_produce_deterministic_hash() {
            let version = VersionEntry::new(
                VersionNumber::GENESIS,
                [0u8; 32],
                [0xAB; 32],
                AuthorId::new(1),
                1700000000_000_000_000,
                0,
                0,
            );

            let hash1 = compute_version_hash(&version);
            let hash2 = compute_version_hash(&version);
            assert_eq!(hash1, hash2);
        }

        #[test]
        fn should_differ_for_different_content() {
            let v1 = VersionEntry::new(
                VersionNumber::GENESIS,
                [0u8; 32],
                [0xAA; 32],
                AuthorId::new(1),
                1700000000_000_000_000,
                0,
                0,
            );

            let v2 = VersionEntry::new(
                VersionNumber::GENESIS,
                [0u8; 32],
                [0xBB; 32],
                AuthorId::new(1),
                1700000000_000_000_000,
                0,
                0,
            );

            assert_ne!(compute_version_hash(&v1), compute_version_hash(&v2));
        }
    }

    mod hash_chain_verification {
        use super::*;

        #[test]
        fn should_verify_valid_single_version_chain() {
            let genesis = create_genesis_version(
                [0xAB; 32],
                AuthorId::new(50001),
                1700000000_000_000_000,
                0,
                15,
            );

            let versions = vec![genesis];
            assert!(verify_hash_chain(&versions).is_ok());
        }

        #[test]
        fn should_verify_valid_multi_version_chain() {
            let genesis = create_genesis_version(
                [0xAB; 32],
                AuthorId::new(50001),
                1700000000_000_000_000,
                0,
                15,
            );

            let v2 = create_child_version(
                &genesis,
                [0xCD; 32],
                AuthorId::new(50001),
                1700000001_000_000_000,
                16,
                12,
            );

            let v3 = create_child_version(
                &v2,
                [0xEF; 32],
                AuthorId::new(50001),
                1700000002_000_000_000,
                28,
                10,
            );

            let versions = vec![genesis, v2, v3];
            assert!(verify_hash_chain(&versions).is_ok());
        }

        #[test]
        fn should_reject_empty_chain() {
            let versions: Vec<VersionEntry> = vec![];
            let result = verify_hash_chain(&versions);

            assert!(result.is_err());
            assert!(matches!(
                result,
                Err(crate::AionError::InvalidFormat { .. })
            ));
        }

        #[test]
        fn should_reject_non_genesis_first_version() {
            // Create a version with version number 2
            let non_genesis = VersionEntry::new(
                VersionNumber(2),
                [0u8; 32],
                [0xAB; 32],
                AuthorId::new(50001),
                1700000000_000_000_000,
                0,
                15,
            );

            let versions = vec![non_genesis];
            let result = verify_hash_chain(&versions);

            assert!(result.is_err());
            assert!(matches!(
                result,
                Err(crate::AionError::InvalidVersionNumber { .. })
            ));
        }

        #[test]
        fn should_reject_genesis_with_non_zero_parent() {
            // Create a genesis version with non-zero parent hash
            let bad_genesis = VersionEntry::new(
                VersionNumber::GENESIS,
                [0xFF; 32], // Non-zero parent
                [0xAB; 32],
                AuthorId::new(50001),
                1700000000_000_000_000,
                0,
                15,
            );

            let versions = vec![bad_genesis];
            let result = verify_hash_chain(&versions);

            assert!(result.is_err());
            assert!(matches!(
                result,
                Err(crate::AionError::InvalidFormat { .. })
            ));
        }

        #[test]
        fn should_reject_broken_hash_chain() {
            let genesis = create_genesis_version(
                [0xAB; 32],
                AuthorId::new(50001),
                1700000000_000_000_000,
                0,
                15,
            );

            // Create v2 with wrong parent hash
            let mut v2 = create_child_version(
                &genesis,
                [0xCD; 32],
                AuthorId::new(50001),
                1700000001_000_000_000,
                16,
                12,
            );
            v2.parent_hash = [0xFF; 32]; // Tamper with parent hash

            let versions = vec![genesis, v2];
            let result = verify_hash_chain(&versions);

            assert!(result.is_err());
            assert!(matches!(
                result,
                Err(crate::AionError::BrokenVersionChain { .. })
            ));
        }

        #[test]
        fn should_reject_version_gap() {
            let genesis = create_genesis_version(
                [0xAB; 32],
                AuthorId::new(50001),
                1700000000_000_000_000,
                0,
                15,
            );

            // Create version 3 (skipping version 2)
            let v3 = VersionEntry::new(
                VersionNumber(3),
                compute_version_hash(&genesis),
                [0xCD; 32],
                AuthorId::new(50001),
                1700000001_000_000_000,
                16,
                12,
            );

            let versions = vec![genesis, v3];
            let result = verify_hash_chain(&versions);

            assert!(result.is_err());
            assert!(matches!(
                result,
                Err(crate::AionError::InvalidVersionNumber { .. })
            ));
        }

        #[test]
        fn should_reject_duplicate_version_numbers() {
            let genesis = create_genesis_version(
                [0xAB; 32],
                AuthorId::new(50001),
                1700000000_000_000_000,
                0,
                15,
            );

            // Create another version 1 (duplicate)
            let duplicate_genesis = VersionEntry::new(
                VersionNumber::GENESIS,
                compute_version_hash(&genesis),
                [0xCD; 32],
                AuthorId::new(50001),
                1700000001_000_000_000,
                16,
                12,
            );

            let versions = vec![genesis, duplicate_genesis];
            let result = verify_hash_chain(&versions);

            assert!(result.is_err());
            assert!(matches!(
                result,
                Err(crate::AionError::InvalidVersionNumber { .. })
            ));
        }

        #[test]
        fn should_verify_long_chain() {
            // Create a chain with 100 versions
            let mut versions = Vec::with_capacity(100);

            let genesis = create_genesis_version(
                [0xAB; 32],
                AuthorId::new(50001),
                1700000000_000_000_000,
                0,
                15,
            );
            versions.push(genesis);

            #[allow(clippy::indexing_slicing)] // Test code: loop bounds guarantee valid index
            #[allow(clippy::cast_possible_truncation)]
            // Test code: intentional wrapping for test data
            for i in 2..=100 {
                let parent = &versions[i - 2];
                let child = create_child_version(
                    parent,
                    [i as u8; 32],
                    AuthorId::new(50001),
                    1700000000_000_000_000 + (i as u64) * 1_000_000_000,
                    (i as u64) * 16,
                    12,
                );
                versions.push(child);
            }

            assert!(verify_hash_chain(&versions).is_ok());
            assert_eq!(versions.len(), 100);
            assert_eq!(versions.last().unwrap().version_number, 100);
        }

        #[test]
        fn should_detect_break_in_middle_of_long_chain() {
            // Create a chain with 50 versions, break at version 25
            let mut versions = Vec::with_capacity(50);

            let genesis = create_genesis_version(
                [0xAB; 32],
                AuthorId::new(50001),
                1700000000_000_000_000,
                0,
                15,
            );
            versions.push(genesis);

            #[allow(clippy::indexing_slicing)] // Test code: loop bounds guarantee valid index
            #[allow(clippy::cast_possible_truncation)]
            // Test code: intentional wrapping for test data
            for i in 2..=50 {
                let parent = &versions[i - 2];
                let mut child = create_child_version(
                    parent,
                    [i as u8; 32],
                    AuthorId::new(50001),
                    1700000000_000_000_000 + (i as u64) * 1_000_000_000,
                    (i as u64) * 16,
                    12,
                );

                // Tamper with version 25's parent hash
                if i == 25 {
                    child.parent_hash = [0xFF; 32];
                }

                versions.push(child);
            }

            let result = verify_hash_chain(&versions);
            assert!(result.is_err());
            assert!(matches!(
                result,
                Err(crate::AionError::BrokenVersionChain { version: 25 })
            ));
        }

        #[test]
        fn should_validate_chain_with_different_authors() {
            let genesis = create_genesis_version(
                [0xAB; 32],
                AuthorId::new(50001),
                1700000000_000_000_000,
                0,
                15,
            );

            let v2 = create_child_version(
                &genesis,
                [0xCD; 32],
                AuthorId::new(50002), // Different author
                1700000001_000_000_000,
                16,
                12,
            );

            let v3 = create_child_version(
                &v2,
                [0xEF; 32],
                AuthorId::new(50003), // Another different author
                1700000002_000_000_000,
                28,
                10,
            );

            let versions = vec![genesis, v2, v3];
            assert!(verify_hash_chain(&versions).is_ok());
        }
    }

    mod version_creation {
        use super::*;

        #[test]
        fn should_create_genesis_version() {
            let genesis = create_genesis_version(
                [0xAB; 32],
                AuthorId::new(50001),
                1700000000_000_000_000,
                0,
                15,
            );

            assert_eq!(genesis.version_number, 1);
            assert_eq!(genesis.parent_hash, [0u8; 32]);
            assert_eq!(genesis.rules_hash, [0xAB; 32]);
            assert_eq!(genesis.author_id, 50001);
        }

        #[test]
        fn should_create_child_version_with_correct_parent_hash() {
            let genesis = create_genesis_version(
                [0xAB; 32],
                AuthorId::new(50001),
                1700000000_000_000_000,
                0,
                15,
            );

            let child = create_child_version(
                &genesis,
                [0xCD; 32],
                AuthorId::new(50001),
                1700000001_000_000_000,
                16,
                12,
            );

            assert_eq!(child.version_number, 2);
            assert_eq!(child.parent_hash, compute_version_hash(&genesis));
        }

        #[test]
        fn should_build_valid_chain() {
            let v1 =
                create_genesis_version([0xAA; 32], AuthorId::new(1), 1700000000_000_000_000, 0, 10);

            let v2 = create_child_version(
                &v1,
                [0xBB; 32],
                AuthorId::new(1),
                1700000001_000_000_000,
                11,
                10,
            );

            let v3 = create_child_version(
                &v2,
                [0xCC; 32],
                AuthorId::new(2),
                1700000002_000_000_000,
                22,
                10,
            );

            // Verify chain linkage
            assert_eq!(v1.version_number, 1);
            assert_eq!(v2.version_number, 2);
            assert_eq!(v3.version_number, 3);
            assert_eq!(v2.parent_hash, compute_version_hash(&v1));
            assert_eq!(v3.parent_hash, compute_version_hash(&v2));
        }
    }

    mod chain_integrity {
        use super::*;

        #[test]
        fn should_detect_modified_chain_link() {
            let v1 =
                create_genesis_version([0xAA; 32], AuthorId::new(1), 1700000000_000_000_000, 0, 10);
            let expected_hash = compute_version_hash(&v1);

            let v2 = create_child_version(
                &v1,
                [0xBB; 32],
                AuthorId::new(1),
                1700000001_000_000_000,
                11,
                10,
            );

            // v2's parent_hash should match v1's hash
            assert_eq!(v2.parent_hash, expected_hash);

            // If v1 is modified, the hash changes
            let modified_v1 = VersionEntry::new(
                VersionNumber(1),
                [0u8; 32],
                [0xFF; 32], // Different content
                AuthorId::new(1),
                1700000000_000_000_000,
                0,
                10,
            );

            assert_ne!(compute_version_hash(&modified_v1), expected_hash);
            assert_ne!(compute_version_hash(&modified_v1), v2.parent_hash);
        }
    }

    mod properties {
        use super::*;
        use hegel::generators as gs;

        fn draw_hash(tc: &hegel::TestCase) -> [u8; 32] {
            let bytes = tc.draw(gs::binary().min_size(32).max_size(32));
            let mut h = [0u8; 32];
            h.copy_from_slice(&bytes);
            h
        }

        fn build_chain(tc: &hegel::TestCase, n: usize) -> Vec<VersionEntry> {
            let author = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let ts_base = tc.draw(gs::integers::<u64>().min_value(1).max_value(1u64 << 60));
            let mut chain = Vec::with_capacity(n);
            chain.push(create_genesis_version(draw_hash(tc), author, ts_base, 0, 0));
            for _ in 1..n {
                let parent = chain
                    .last()
                    .copied()
                    .unwrap_or_else(|| std::process::abort());
                let child = create_child_version(&parent, draw_hash(tc), author, ts_base, 0, 0);
                chain.push(child);
            }
            chain
        }

        #[hegel::test]
        fn prop_append_verify_ok_for_any_n(tc: hegel::TestCase) {
            let n = tc.draw(gs::integers::<usize>().min_value(1).max_value(20));
            let chain = build_chain(&tc, n);
            assert!(verify_hash_chain(&chain).is_ok());
        }

        #[hegel::test]
        fn prop_tamper_non_terminal_entry_fails(tc: hegel::TestCase) {
            let n = tc.draw(gs::integers::<usize>().min_value(2).max_value(20));
            let mut chain = build_chain(&tc, n);
            let max_idx = n.saturating_sub(2);
            let idx = tc.draw(gs::integers::<usize>().max_value(max_idx));
            if let Some(entry) = chain.get_mut(idx) {
                if let Some(b) = entry.rules_hash.get_mut(0) {
                    *b ^= 0x01;
                }
            }
            assert!(verify_hash_chain(&chain).is_err());
        }

        #[hegel::test]
        fn prop_sign_verify_roundtrip_for_any_version(tc: hegel::TestCase) {
            let author = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let rules_hash = draw_hash(&tc);
            let version =
                create_genesis_version(rules_hash, author, 1_700_000_000_000_000_000, 0, 0);
            let key = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let mut sig = sign_version(&version, &key);
            sig.author_id = author.as_u64();
            let reg = reg_pinning(author.as_u64(), &key);
            assert!(verify_signature(&version, &sig, &reg).is_ok());
        }

        #[hegel::test]
        fn prop_attestation_roundtrip(tc: hegel::TestCase) {
            let version_author = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let signer =
                AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1).max_value(u64::MAX / 2)));
            // Avoid collision between version_author and signer
            let signer = if signer == version_author {
                AuthorId::new(signer.as_u64().saturating_add(1))
            } else {
                signer
            };
            let version = create_genesis_version(
                draw_hash(&tc),
                version_author,
                1_700_000_000_000_000_000,
                0,
                0,
            );
            let key = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let att = sign_attestation(&version, signer, &key);
            let reg = reg_pinning(signer.as_u64(), &key);
            assert!(verify_attestation(&version, &att, &reg).is_ok());
        }

        #[hegel::test]
        fn prop_attestation_rejects_wrong_signer(tc: hegel::TestCase) {
            let version_author = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let real_signer =
                AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1).max_value(u64::MAX / 2)));
            let fake_signer = AuthorId::new(real_signer.as_u64().saturating_add(1));
            let version = create_genesis_version(
                draw_hash(&tc),
                version_author,
                1_700_000_000_000_000_000,
                0,
                0,
            );
            let key = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let mut att = sign_attestation(&version, real_signer, &key);
            // Tamper with signer identity after signing.
            att.author_id = fake_signer.as_u64();
            // Registry pins the real_signer — the tampered att claims to be fake_signer,
            // which isn't in the registry; verify must reject.
            let reg = reg_pinning(real_signer.as_u64(), &key);
            assert!(verify_attestation(&version, &att, &reg).is_err());
        }

        #[hegel::test]
        fn prop_attestation_rejects_wrong_version(tc: hegel::TestCase) {
            let author = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let signer = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let v1 =
                create_genesis_version(draw_hash(&tc), author, 1_700_000_000_000_000_000, 0, 0);
            let mut v2 = v1;
            // Different rules content -> different canonical message.
            v2.rules_hash[0] ^= 0x01;
            let key = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let att = sign_attestation(&v1, signer, &key);
            let reg = reg_pinning(signer.as_u64(), &key);
            assert!(verify_attestation(&v2, &att, &reg).is_err());
        }

        #[hegel::test]
        fn prop_attestation_and_version_signature_are_domain_separated(tc: hegel::TestCase) {
            // A signature produced by sign_version should NOT verify as an
            // attestation under verify_attestation, even when every byte
            // except the domain tag matches. This guards the RFC-0021 domain
            // separator `AION_V2_ATTESTATION_V1`.
            let author = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let version =
                create_genesis_version(draw_hash(&tc), author, 1_700_000_000_000_000_000, 0, 0);
            let key = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let mut version_sig = sign_version(&version, &key);
            version_sig.author_id = author.as_u64();
            let reg = reg_pinning(author.as_u64(), &key);
            // verify_signature should pass; verify_attestation must not.
            assert!(verify_signature(&version, &version_sig, &reg).is_ok());
            assert!(verify_attestation(&version, &version_sig, &reg).is_err());
        }

        // ------------------------------------------------------------------
        // RFC-0028 registry-aware verification properties.
        // ------------------------------------------------------------------

        use crate::key_registry::{sign_rotation_record, KeyRegistry};

        fn make_version_at(author: AuthorId, version_number: u64) -> VersionEntry {
            VersionEntry::new(
                crate::types::VersionNumber(version_number),
                [0u8; 32],
                [0xAAu8; 32],
                author,
                1_700_000_000_000_000_000,
                0,
                0,
            )
        }

        #[hegel::test]
        fn prop_registry_verify_accepts_active_epoch_signature(tc: hegel::TestCase) {
            let author_id = tc.draw(gs::integers::<u64>().min_value(1));
            let author = AuthorId::new(author_id);
            let master = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let op0 = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let mut reg = KeyRegistry::new();
            reg.register_author(author, master.verifying_key(), op0.verifying_key(), 0)
                .unwrap_or_else(|_| std::process::abort());

            let version_number = tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 20));
            let version = make_version_at(author, version_number);
            let mut sig = sign_version(&version, &op0);
            sig.author_id = author.as_u64();
            assert!(verify_signature(&version, &sig, &reg).is_ok());
        }

        #[hegel::test]
        fn prop_registry_verify_rejects_sig_after_rotation_with_old_key(tc: hegel::TestCase) {
            let author_id = tc.draw(gs::integers::<u64>().min_value(1));
            let author = AuthorId::new(author_id);
            let master = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let op0 = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let op1 = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let mut reg = KeyRegistry::new();
            reg.register_author(author, master.verifying_key(), op0.verifying_key(), 0)
                .unwrap_or_else(|_| std::process::abort());
            let effective = tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 20));
            let rotation = sign_rotation_record(
                author,
                0,
                1,
                op1.verifying_key().to_bytes(),
                effective,
                &master,
            );
            reg.apply_rotation(&rotation)
                .unwrap_or_else(|_| std::process::abort());

            let v_after = tc.draw(
                gs::integers::<u64>()
                    .min_value(effective)
                    .max_value(effective.saturating_add(1 << 20)),
            );
            let version = make_version_at(author, v_after);
            // Sign with the ROTATED-OUT op0 key — this should now fail.
            let mut sig = sign_version(&version, &op0);
            sig.author_id = author.as_u64();
            assert!(verify_signature(&version, &sig, &reg).is_err());
        }

        #[hegel::test]
        fn prop_registry_verify_rejects_revoked_key(tc: hegel::TestCase) {
            let author_id = tc.draw(gs::integers::<u64>().min_value(1));
            let author = AuthorId::new(author_id);
            let master = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let op0 = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let mut reg = KeyRegistry::new();
            reg.register_author(author, master.verifying_key(), op0.verifying_key(), 0)
                .unwrap_or_else(|_| std::process::abort());
            let effective = tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 20));
            let revocation = crate::key_registry::sign_revocation_record(
                author,
                0,
                crate::key_registry::RevocationReason::Compromised,
                effective,
                &master,
            );
            reg.apply_revocation(&revocation)
                .unwrap_or_else(|_| std::process::abort());

            let v_after = tc.draw(
                gs::integers::<u64>()
                    .min_value(effective)
                    .max_value(effective.saturating_add(1 << 20)),
            );
            let version = make_version_at(author, v_after);
            let mut sig = sign_version(&version, &op0);
            sig.author_id = author.as_u64();
            assert!(verify_signature(&version, &sig, &reg).is_err());
        }

        #[hegel::test]
        fn prop_registry_verify_rejects_pubkey_substitution(tc: hegel::TestCase) {
            let author_id = tc.draw(gs::integers::<u64>().min_value(1));
            let author = AuthorId::new(author_id);
            let master = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let op0 = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let attacker = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let mut reg = KeyRegistry::new();
            reg.register_author(author, master.verifying_key(), op0.verifying_key(), 0)
                .unwrap_or_else(|_| std::process::abort());
            let version = make_version_at(author, 1);
            let mut sig = sign_version(&version, &op0);
            sig.author_id = author.as_u64();
            // Attacker swaps the embedded public_key to a key they control.
            sig.public_key = attacker.verifying_key().to_bytes();
            assert!(verify_signature(&version, &sig, &reg).is_err());
        }

        // ------------------------------------------------------------------
        // RFC-0039 format-v3 message and hash properties.
        // ------------------------------------------------------------------

        use crate::format::RulesMode;

        fn draw_mode(tc: &hegel::TestCase) -> RulesMode {
            if tc.draw(gs::booleans()) {
                RulesMode::Confidential
            } else {
                RulesMode::Public
            }
        }

        fn draw_v3_entry(tc: &hegel::TestCase, mode: RulesMode) -> VersionEntry {
            VersionEntry::new(
                crate::types::VersionNumber(tc.draw(gs::integers::<u64>())),
                draw_hash(tc),
                draw_hash(tc),
                AuthorId::new(tc.draw(gs::integers::<u64>())),
                tc.draw(gs::integers::<u64>()),
                tc.draw(gs::integers::<u64>()),
                tc.draw(gs::integers::<u32>()),
            )
            .with_rules_mode(mode)
        }

        fn v3_message(entry: &VersionEntry, file_id: u64) -> Vec<u8> {
            canonical_version_message_v3(entry, FileId::new(file_id))
                .unwrap_or_else(|_| std::process::abort())
        }

        fn v3_hash(entry: &VersionEntry, file_id: u64) -> [u8; 32] {
            compute_version_hash_v3(entry, FileId::new(file_id))
                .unwrap_or_else(|_| std::process::abort())
        }

        #[hegel::test]
        fn prop_v3_message_and_hash_bind_file_id(tc: hegel::TestCase) {
            let entry = draw_v3_entry(&tc, draw_mode(&tc));
            let file_a = tc.draw(gs::integers::<u64>());
            let file_b = file_a ^ tc.draw(gs::integers::<u64>().min_value(1));
            assert_ne!(v3_message(&entry, file_a), v3_message(&entry, file_b));
            assert_ne!(v3_hash(&entry, file_a), v3_hash(&entry, file_b));
        }

        #[hegel::test]
        fn prop_v3_message_and_hash_bind_rules_mode(tc: hegel::TestCase) {
            let entry = draw_v3_entry(&tc, RulesMode::Public);
            let flipped = entry.with_rules_mode(RulesMode::Confidential);
            let file_id = tc.draw(gs::integers::<u64>());
            assert_ne!(v3_message(&entry, file_id), v3_message(&flipped, file_id));
            assert_ne!(v3_hash(&entry, file_id), v3_hash(&flipped, file_id));
        }

        #[hegel::test]
        fn prop_v3_version_hash_differs_from_v2(tc: hegel::TestCase) {
            let entry = draw_v3_entry(&tc, RulesMode::Public);
            let file_id = tc.draw(gs::integers::<u64>());
            assert_ne!(v3_hash(&entry, file_id), compute_version_hash(&entry));
        }

        #[hegel::test]
        fn prop_v3_signature_round_trip_and_file_binding(tc: hegel::TestCase) {
            let entry = draw_v3_entry(&tc, draw_mode(&tc));
            let file_id = tc.draw(gs::integers::<u64>());
            let other_file = file_id ^ tc.draw(gs::integers::<u64>().min_value(1));
            let key = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let signature = key.sign(&v3_message(&entry, file_id));
            let verifying = key.verifying_key();
            assert!(verifying
                .verify(&v3_message(&entry, file_id), &signature)
                .is_ok());
            assert!(verifying
                .verify(&v3_message(&entry, other_file), &signature)
                .is_err());
        }

        #[hegel::test]
        fn prop_v3_version_and_attestation_are_domain_separated(tc: hegel::TestCase) {
            let entry = draw_v3_entry(&tc, draw_mode(&tc));
            let file_id = FileId::new(tc.draw(gs::integers::<u64>()));
            let signer = AuthorId::new(tc.draw(gs::integers::<u64>()));
            let key = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let version_message = canonical_version_message_v3(&entry, file_id)
                .unwrap_or_else(|_| std::process::abort());
            let attestation_message = canonical_attestation_message_v3(&entry, file_id, signer)
                .unwrap_or_else(|_| std::process::abort());
            let signature = key.sign(&version_message);
            assert!(key
                .verifying_key()
                .verify(&attestation_message, &signature)
                .is_err());
        }

        #[hegel::test]
        fn prop_v3_rejects_invalid_mode_and_reserved_bytes(tc: hegel::TestCase) {
            let mut bad_mode = draw_v3_entry(&tc, RulesMode::Public);
            bad_mode.reserved[0] = tc.draw(gs::integers::<u8>().min_value(2));
            let mut bad_reserved = draw_v3_entry(&tc, draw_mode(&tc));
            let index = tc.draw(gs::integers::<usize>().min_value(1).max_value(51));
            let flipped = tc.draw(gs::integers::<u8>().min_value(1));
            if let Some(byte) = bad_reserved.reserved.get_mut(index) {
                *byte = flipped;
            }
            let file_id = FileId::new(tc.draw(gs::integers::<u64>()));
            assert!(canonical_version_message_v3(&bad_mode, file_id).is_err());
            assert!(compute_version_hash_v3(&bad_mode, file_id).is_err());
            assert!(canonical_version_message_v3(&bad_reserved, file_id).is_err());
            assert!(compute_version_hash_v3(&bad_reserved, file_id).is_err());
        }
    }
}
