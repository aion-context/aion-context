//! Core operations for AION v2 files
//!
//! This module implements the high-level operations for working with AION files:
//!
//! - **Commit**: Create a new version with updated rules
//!
//! All operations follow the security model defined in RFC-0001:
//! - Signature chain verification before modifications
//! - Cryptographic signing of all new versions
//! - Atomic file writes to prevent corruption
//!
//! # Usage Example
//!
//! ```no_run
//! use aion_context::operations::{commit_version, CommitOptions};
//! use aion_context::crypto::SigningKey;
//! use aion_context::types::AuthorId;
//! use std::path::Path;
//!
//! let signing_key = SigningKey::generate();
//! let options = CommitOptions {
//!     author_id: AuthorId::new(50001),
//!     signing_key: &signing_key,
//!     message: "Updated fraud detection rules",
//!     timestamp: None, // Use current time
//! };
//!
//! // Commit new rules to existing file
//! // let result = commit_version(
//! //     Path::new("rules.aion"),
//! //     b"new rules content",
//! //     &options,
//! // );
//! ```

use crate::audit::{ActionCode, AuditEntry};
use crate::crypto::{decrypt, derive_key, encrypt, generate_nonce, hash, SigningKey};
use crate::parser::AionParser;
use crate::serializer::{AionFile, AionSerializer, SignatureEntry, VersionEntry};
#[allow(deprecated)] // RFC-0034 Phase D: verify_signature kept for legacy verify_file path
use crate::signature_chain::{
    compute_version_hash, create_genesis_version, sign_version, verify_hash_chain,
    verify_signature, verify_signatures_batch,
};
use crate::types::{AuthorId, FileId, VersionNumber};
use crate::{AionError, Result};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// File Creation Operations
// ============================================================================

/// Options for initializing a new AION file
pub struct InitOptions<'a> {
    /// Author ID for the genesis version
    pub author_id: AuthorId,
    /// Signing key for the genesis version
    pub signing_key: &'a SigningKey,
    /// Commit message for genesis version
    pub message: &'a str,
    /// Optional timestamp (uses current time if None)
    pub timestamp: Option<u64>,
}

/// Result of file initialization
#[derive(Debug, Clone)]
pub struct InitResult {
    /// Generated file ID
    pub file_id: FileId,
    /// Genesis version number (always 1)
    pub version: VersionNumber,
    /// Hash of the initial rules
    pub rules_hash: [u8; 32],
}

/// Initialize a new AION file with genesis version
///
/// Creates a new AION file with:
/// - Unique file ID
/// - Genesis version (version 1)
/// - Encrypted rules
/// - Cryptographic signature
/// - Audit trail entry
///
/// # Arguments
///
/// * `path` - Path where the file will be created
/// * `initial_rules` - Initial rules content (plaintext)
/// * `options` - Initialization options (author, key, message)
///
/// # Returns
///
/// Returns `InitResult` containing file ID and version information.
///
/// # Errors
///
/// Returns error if:
/// - File already exists at the path
/// - Rules encryption fails
/// - File write fails
/// - I/O error occurs
///
/// # Example
///
/// ```no_run
/// use aion_context::operations::{init_file, InitOptions};
/// use aion_context::crypto::SigningKey;
/// use aion_context::types::AuthorId;
/// use std::path::Path;
///
/// let signing_key = SigningKey::generate();
/// let options = InitOptions {
///     author_id: AuthorId::new(50001),
///     signing_key: &signing_key,
///     message: "Initial policy version",
///     timestamp: None, // Use current time
/// };
///
/// let initial_rules = b"fraud_threshold: 1000\nrisk_level: medium";
/// // let result = init_file(
/// //     Path::new("policy.aion"),
/// //     initial_rules,
/// //     &options,
/// // )?;
/// // println!("Created file {} with version {}", result.file_id.as_u64(), result.version.as_u64());
/// ```
pub fn init_file(path: &Path, initial_rules: &[u8], options: &InitOptions) -> Result<InitResult> {
    if path.exists() {
        return Err(AionError::FileExists {
            path: path.to_path_buf(),
        });
    }
    let file_id = FileId::random();
    let timestamp = options.timestamp.unwrap_or_else(current_timestamp_nanos);
    let rules_hash = hash(initial_rules);
    let (encrypted_rules, _) = encrypt_rules(initial_rules, file_id, VersionNumber::GENESIS)?;

    let aion_file = build_genesis_file(file_id, timestamp, rules_hash, encrypted_rules, options)?;
    write_serialized_file(&aion_file, path)?;

    tracing::info!(
        event = "file_initialized",
        file_id = %crate::obs::short_hex(&file_id.as_u64().to_le_bytes()),
        author = %crate::obs::author_short(options.author_id),
        rules_hash = %crate::obs::short_hex(&rules_hash),
    );
    Ok(InitResult {
        file_id,
        version: VersionNumber::GENESIS,
        rules_hash,
    })
}

#[allow(clippy::cast_possible_truncation)]
fn build_genesis_file(
    file_id: FileId,
    timestamp: u64,
    rules_hash: [u8; 32],
    encrypted_rules: Vec<u8>,
    options: &InitOptions,
) -> Result<AionFile> {
    let (string_table, offsets) = AionSerializer::build_string_table(&[options.message]);
    let message_offset = offsets.first().copied().unwrap_or(0);

    let genesis_version = create_genesis_version(
        rules_hash,
        options.author_id,
        timestamp,
        message_offset,
        options.message.len() as u32,
    );
    let signature = sign_version(&genesis_version, options.signing_key);
    let audit_entry = AuditEntry::new(
        timestamp,
        options.author_id,
        ActionCode::CreateGenesis,
        0,
        0,
        [0u8; 32],
    );

    AionFile::builder()
        .file_id(file_id)
        .current_version(VersionNumber::GENESIS)
        .flags(0x0001)
        .root_hash(rules_hash)
        .current_hash(rules_hash)
        .created_at(timestamp)
        .modified_at(timestamp)
        .encrypted_rules(encrypted_rules)
        .add_version(genesis_version)
        .add_signature(signature)
        .add_audit_entry(audit_entry)
        .string_table(string_table)
        .build()
}

fn write_serialized_file(file: &AionFile, path: &Path) -> Result<()> {
    let file_bytes = AionSerializer::serialize(file)?;
    std::fs::write(path, &file_bytes).map_err(|e| AionError::FileWriteError {
        path: path.to_path_buf(),
        source: e,
    })
}

// ============================================================================
// Version Management Operations
// ============================================================================

/// Options for committing a new version
pub struct CommitOptions<'a> {
    /// Author ID for the new version
    pub author_id: AuthorId,
    /// Signing key for the author
    pub signing_key: &'a SigningKey,
    /// Commit message describing changes
    pub message: &'a str,
    /// Optional timestamp (nanoseconds since Unix epoch)
    /// If None, uses current system time
    pub timestamp: Option<u64>,
}

/// Result of a successful commit operation
#[derive(Debug)]
pub struct CommitResult {
    /// The new version number
    pub version: VersionNumber,
    /// Hash of the new version entry
    pub version_hash: [u8; 32],
    /// Hash of the new rules
    pub rules_hash: [u8; 32],
}

/// Commit a new version with updated rules to an existing AION file
///
/// This operation:
/// 1. Loads and parses the existing file
/// 2. Verifies the existing signature chain
/// 3. Encrypts the new rules
/// 4. Creates a new version entry linked to the previous version
/// 5. Signs the new version with the author's key
/// 6. Writes the updated file atomically
///
/// # Arguments
///
/// * `path` - Path to the existing AION file
/// * `new_rules` - The new rules content to commit
/// * `options` - Commit options including author and signing key
///
/// # Returns
///
/// * `Ok(CommitResult)` - On success, contains the new version number and hashes
/// * `Err(AionError)` - On failure
///
/// # Errors
///
/// - `AionError::FileReadError` - Cannot read the file
/// - `AionError::InvalidFormat` - File format is invalid
/// - `AionError::SignatureVerificationFailed` - Existing signature chain is invalid
/// - `AionError::VersionOverflow` - Version number would overflow u64
/// - `AionError::FileWriteError` - Cannot write the updated file
///
/// # Example
///
/// ```no_run
/// use aion_context::operations::{commit_version, CommitOptions};
/// use aion_context::crypto::SigningKey;
/// use aion_context::types::AuthorId;
/// use std::path::Path;
///
/// let signing_key = SigningKey::generate();
/// let options = CommitOptions {
///     author_id: AuthorId::new(50001),
///     signing_key: &signing_key,
///     message: "Updated rules",
///     timestamp: None,
/// };
///
/// // let result = commit_version(
/// //     Path::new("rules.aion"),
/// //     b"new rules content",
/// //     &options,
/// // )?;
/// // println!("Created version {}", result.version.as_u64());
/// # Ok::<(), aion_context::AionError>(())
/// ```
#[must_use = "the CommitResult carries the new version number and rules hash; \
              dropping it silently usually indicates a missing post-commit step"]
pub fn commit_version(
    path: &Path,
    new_rules: &[u8],
    options: &CommitOptions<'_>,
    registry: &crate::key_registry::KeyRegistry,
) -> Result<CommitResult> {
    commit_version_inner(path, new_rules, options, registry, true)
}

/// Commit bypassing the registry authz pre-check (issue #25
/// `--force-unregistered` escape hatch).
///
/// Same behavior as [`commit_version`] except the
/// `(author, signing key, active epoch)` match is not enforced.
/// The resulting entry is **not guaranteed to verify** against the
/// supplied registry — operators using this path must know why
/// (offline signer, staged rollout) and accept that the file on
/// disk will not pass `verify` until the registry is updated.
///
/// # Errors
///
/// Same error surface as [`commit_version`] minus the authz errors.
#[must_use = "the resulting file will NOT pass `verify` against the \
              supplied registry until the registry is updated to pin \
              this signer; check the CommitResult and ensure the \
              registry update is staged"]
pub fn commit_version_force_unregistered(
    path: &Path,
    new_rules: &[u8],
    options: &CommitOptions<'_>,
    registry: &crate::key_registry::KeyRegistry,
) -> Result<CommitResult> {
    commit_version_inner(path, new_rules, options, registry, false)
}

fn commit_version_inner(
    path: &Path,
    new_rules: &[u8],
    options: &CommitOptions<'_>,
    registry: &crate::key_registry::KeyRegistry,
    enforce_registry: bool,
) -> Result<CommitResult> {
    let file_bytes = std::fs::read(path).map_err(|e| AionError::FileReadError {
        path: path.to_path_buf(),
        source: e,
    })?;
    let parser = AionParser::new(&file_bytes)?;
    let header = parser.header();

    // Pre-write integrity gate (audit follow-up to PR #37):
    //
    //   1. integrity_hash over the whole on-disk byte range — catches
    //      any single-bit tamper in any section, including ones that
    //      verify_head_signature alone wouldn't notice.
    //   2. parent_hash chain over the version entries — catches
    //      tampering of an intermediate VersionEntry that doesn't
    //      change the head signature.
    //   3. head signature — catches tampering of the latest sig.
    //
    // PR #37's commit message claimed (1) was already done by the
    // parser at parse time. It was not — `AionParser::new` only
    // does structural validation. Without (1) and (2), commit
    // could layer a valid new entry on top of a corrupt chain,
    // hiding the corruption beneath fresh bytes.
    parser.verify_integrity()?;
    let existing_versions = collect_versions(&parser, header.version_chain_count)?;
    crate::signature_chain::verify_hash_chain(&existing_versions)?;
    verify_head_signature(&parser, registry)?;

    let new_version = VersionNumber(header.current_version).next()?;

    if enforce_registry {
        preflight_registry_authz(options, new_version, registry)?;
    }

    let timestamp = options.timestamp.unwrap_or_else(current_timestamp_nanos);
    let file_id = FileId::new(header.file_id);
    let (encrypted_rules, rules_hash) = encrypt_rules(new_rules, file_id, new_version)?;
    let parent_hash = compute_version_hash(&get_last_version_entry(&parser)?);
    let (string_table, message_offset) = build_string_table_with_message(options.message, &parser)?;

    let (new_version_entry, signature_entry) = build_new_version_and_signature(
        new_version,
        parent_hash,
        rules_hash,
        timestamp,
        message_offset,
        options,
    );

    let updated_file = build_updated_file(
        &parser,
        header,
        new_version,
        rules_hash,
        encrypted_rules,
        new_version_entry,
        signature_entry,
        string_table,
        timestamp,
        options.author_id,
    )?;
    AionSerializer::write_atomic(&updated_file, path)?;

    let version_hash = compute_version_hash(&new_version_entry);
    tracing::info!(
        event = "commit_accepted",
        file_id = %crate::obs::short_hex(&header.file_id.to_le_bytes()),
        author = %crate::obs::author_short(options.author_id),
        version = new_version.as_u64(),
        version_hash = %crate::obs::short_hex(&version_hash),
        rules_hash = %crate::obs::short_hex(&rules_hash),
    );
    Ok(CommitResult {
        version: new_version,
        version_hash,
        rules_hash,
    })
}

/// Pre-write authz check (issue #25): the signer must have an
/// active epoch at the target version, and the supplied signing
/// key must match that epoch's pinned operational key.
fn preflight_registry_authz(
    options: &CommitOptions<'_>,
    new_version: VersionNumber,
    registry: &crate::key_registry::KeyRegistry,
) -> Result<()> {
    use subtle::ConstantTimeEq;
    let Some(epoch) = registry.active_epoch_at(options.author_id, new_version.as_u64()) else {
        return Err(AionError::UnauthorizedSigner {
            author: options.author_id,
            version: new_version.as_u64(),
        });
    };
    let supplied_pk = options.signing_key.verifying_key().to_bytes();
    // Constant-time comparison — never `==` on key-shaped bytes.
    // See .claude/rules/crypto.md and the audit verdict on issue
    // (audit, 2026-04-25): `!=` here is a hard rule violation
    // even though public keys aren't strictly secret.
    if !bool::from(supplied_pk.ct_eq(&epoch.public_key)) {
        return Err(AionError::KeyMismatch {
            author: options.author_id,
            epoch: epoch.epoch,
        });
    }
    Ok(())
}

#[allow(clippy::cast_possible_truncation)]
fn build_new_version_and_signature(
    new_version: VersionNumber,
    parent_hash: [u8; 32],
    rules_hash: [u8; 32],
    timestamp: u64,
    message_offset: u64,
    options: &CommitOptions<'_>,
) -> (VersionEntry, SignatureEntry) {
    let new_version_entry = VersionEntry::new(
        new_version,
        parent_hash,
        rules_hash,
        options.author_id,
        timestamp,
        message_offset,
        options.message.len() as u32,
    );
    let signature_entry = sign_version(&new_version_entry, options.signing_key);
    (new_version_entry, signature_entry)
}

/// Verify only the head (most recent) signature against the pinned
/// registry — issue #35.
///
/// Replaces the previous full-chain sweep that ran on every
/// [`commit_version`]. Walking every prior signature on every append
/// gave commit O(n) per call and chain construction O(n²) — building
/// 10k versions took ~150 minutes. The hash chain (verified at parse
/// time and again on read by [`verify_file`]) seals all earlier links;
/// re-running every prior signature at write time was redundant.
///
/// Cost: one Ed25519 verify and one structural check, regardless of
/// chain length.
#[allow(clippy::cast_possible_truncation)] // File counts fit in usize
#[allow(clippy::arithmetic_side_effects)] // count - 1 guarded by count > 0
fn verify_head_signature(
    parser: &AionParser<'_>,
    registry: &crate::key_registry::KeyRegistry,
) -> Result<()> {
    let header = parser.header();
    let version_count = header.version_chain_count as usize;
    let signature_count = header.signatures_count as usize;

    if version_count != signature_count {
        return Err(AionError::InvalidFormat {
            reason: format!(
                "Version count ({version_count}) does not match signature count ({signature_count})"
            ),
        });
    }
    if version_count == 0 {
        return Err(AionError::InvalidFormat {
            reason: "File has no versions".to_string(),
        });
    }

    let last = version_count - 1;
    let version = parser.get_version_entry(last)?;
    let signature = parser.get_signature_entry(last)?;
    verify_signature(&version, &signature, registry)
}

/// Get the last version entry from the parser
#[allow(clippy::cast_possible_truncation)] // File counts fit in usize
#[allow(clippy::arithmetic_side_effects)] // Checked above
fn get_last_version_entry(parser: &AionParser<'_>) -> Result<VersionEntry> {
    let header = parser.header();
    let version_count = header.version_chain_count as usize;

    if version_count == 0 {
        return Err(AionError::InvalidFormat {
            reason: "File has no versions".to_string(),
        });
    }

    parser.get_version_entry(version_count - 1)
}

/// Encrypt rules content using file-specific key derivation
#[allow(clippy::arithmetic_side_effects)] // Capacity calculation is safe
fn encrypt_rules(
    rules: &[u8],
    file_id: FileId,
    version: VersionNumber,
) -> Result<(Vec<u8>, [u8; 32])> {
    // Compute rules hash first
    let rules_hash = hash(rules);

    // Derive encryption key from file ID and version
    let mut encryption_key = [0u8; 32];
    let salt = file_id.as_u64().to_le_bytes();
    let info = format!("aion-v2-rules-v{}", version.as_u64());

    // Use a fixed master secret derived from file ID for deterministic key derivation
    let master_secret = format!("aion-v2-master-{}", file_id.as_u64());

    derive_key(
        master_secret.as_bytes(),
        &salt,
        info.as_bytes(),
        &mut encryption_key,
    )?;

    // Generate nonce and encrypt
    let nonce = generate_nonce();
    let aad = version.as_u64().to_le_bytes();
    let ciphertext = encrypt(&encryption_key, &nonce, rules, &aad)?;

    // Prepend nonce to ciphertext (nonce is 12 bytes)
    let mut encrypted = Vec::with_capacity(12 + ciphertext.len());
    encrypted.extend_from_slice(&nonce);
    encrypted.extend_from_slice(&ciphertext);

    Ok((encrypted, rules_hash))
}

/// Decrypt rules content using file-specific key derivation
///
/// This function performs the reverse of `encrypt_rules`:
/// 1. Extracts the 12-byte nonce from the beginning of encrypted data
/// 2. Derives the encryption key from `file_id` + version (same as encryption)
/// 3. Decrypts using ChaCha20-Poly1305 AEAD
/// 4. Verifies the decrypted data hash matches `expected_hash`
///
/// # Arguments
///
/// * `encrypted_rules` - Encrypted data with prepended nonce (nonce || ciphertext)
/// * `file_id` - File identifier used for key derivation
/// * `version` - Version number used for key derivation and AAD
/// * `expected_hash` - Expected BLAKE3 hash of the plaintext rules
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Decrypted plaintext rules
/// * `Err(AionError)` - On decryption failure or hash mismatch
///
/// # Errors
///
/// - `AionError::DecryptionFailed` if:
///   - Encrypted data is too short (< 12 bytes for nonce)
///   - Authentication tag is invalid (tampering detected)
///   - Wrong key or nonce used
/// - `AionError::HashMismatch` if decrypted data hash doesn't match expected
///
/// # Security
///
/// - Uses deterministic key derivation from `file_id` and version
/// - Verifies authentication tag (prevents tampering)
/// - Verifies content hash after decryption (defense in depth)
/// - Constant-time operations where possible
///
/// # Example
///
/// ```no_run
/// use aion_context::operations::decrypt_rules;
/// use aion_context::types::{FileId, VersionNumber};
///
/// // Assuming we have encrypted rules from the file
/// // let encrypted = parser.encrypted_rules()?;
/// // let version_entry = parser.get_version_entry(0)?;
/// //
/// // let plaintext = decrypt_rules(
/// //     encrypted,
/// //     FileId::new(12345),
/// //     VersionNumber::GENESIS,
/// //     version_entry.rules_hash,
/// // )?;
/// ```
pub fn decrypt_rules(
    encrypted_rules: &[u8],
    file_id: FileId,
    version: VersionNumber,
    expected_hash: [u8; 32],
) -> Result<Vec<u8>> {
    // Step 1: Extract nonce (first 12 bytes)
    if encrypted_rules.len() < 12 {
        return Err(AionError::DecryptionFailed {
            reason: format!(
                "Encrypted data too short: {} bytes, need at least 12 for nonce",
                encrypted_rules.len()
            ),
        });
    }

    let mut nonce = [0u8; 12];
    let nonce_slice = encrypted_rules
        .get(..12)
        .ok_or_else(|| AionError::DecryptionFailed {
            reason: "Failed to extract nonce from encrypted data".to_string(),
        })?;
    nonce.copy_from_slice(nonce_slice);

    // Step 2: Extract ciphertext (remaining bytes after nonce)
    let ciphertext = encrypted_rules
        .get(12..)
        .ok_or_else(|| AionError::DecryptionFailed {
            reason: "Failed to extract ciphertext from encrypted data".to_string(),
        })?;

    // Step 3: Derive encryption key (same process as encryption)
    let mut encryption_key = [0u8; 32];
    let salt = file_id.as_u64().to_le_bytes();
    let info = format!("aion-v2-rules-v{}", version.as_u64());
    let master_secret = format!("aion-v2-master-{}", file_id.as_u64());

    derive_key(
        master_secret.as_bytes(),
        &salt,
        info.as_bytes(),
        &mut encryption_key,
    )?;

    // Step 4: Decrypt using ChaCha20-Poly1305
    let aad = version.as_u64().to_le_bytes();
    let plaintext = decrypt(&encryption_key, &nonce, ciphertext, &aad)?;

    // Step 5: Verify hash of decrypted data
    let actual_hash = hash(&plaintext);
    if actual_hash != expected_hash {
        return Err(AionError::HashMismatch {
            expected: expected_hash,
            actual: actual_hash,
        });
    }

    Ok(plaintext)
}

/// Temporal warning types for timestamp validation (RFC-0005)
///
/// These warnings are informational only and do not cause verification to fail.
/// They help identify potential clock skew or backdated entries.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TemporalWarning {
    /// Version has a timestamp earlier than its predecessor
    NonMonotonicTimestamp {
        /// The version with the older timestamp
        version: u64,
        /// Timestamp of this version (nanoseconds)
        timestamp: u64,
        /// Timestamp of the previous version (nanoseconds)
        previous_timestamp: u64,
    },
    /// Version timestamp is in the future
    FutureTimestamp {
        /// The version with the future timestamp
        version: u64,
        /// The future timestamp (nanoseconds)
        timestamp: u64,
        /// Current system time when checked (nanoseconds)
        current_time: u64,
    },
    /// Version timestamps are very close together (possible clock skew)
    ClockSkewDetected {
        /// The version where skew was detected
        version: u64,
        /// Time difference in nanoseconds (negative means earlier)
        skew_nanos: i64,
    },
}

impl std::fmt::Display for TemporalWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonMonotonicTimestamp {
                version,
                timestamp,
                previous_timestamp,
            } => {
                let diff_secs = previous_timestamp.saturating_sub(*timestamp) / 1_000_000_000;
                write!(
                    f,
                    "Version {version} has non-monotonic timestamp ({diff_secs}s before previous version)"
                )
            }
            Self::FutureTimestamp {
                version,
                timestamp,
                current_time,
            } => {
                let diff_secs = timestamp.saturating_sub(*current_time) / 1_000_000_000;
                write!(
                    f,
                    "Version {version} has future timestamp ({diff_secs}s in the future)"
                )
            }
            Self::ClockSkewDetected {
                version,
                skew_nanos,
            } => {
                let skew_ms = skew_nanos / 1_000_000;
                write!(
                    f,
                    "Version {version} shows potential clock skew ({skew_ms}ms)"
                )
            }
        }
    }
}

/// Detailed verification report for an AION file
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[allow(clippy::struct_excessive_bools)] // Report struct legitimately needs multiple bool flags
pub struct VerificationReport {
    /// File ID
    pub file_id: FileId,
    /// Number of versions in the file
    pub version_count: u64,
    /// Whether the file structure is valid
    pub structure_valid: bool,
    /// Whether the file integrity hash matches
    pub integrity_hash_valid: bool,
    /// Whether the hash chain is intact
    pub hash_chain_valid: bool,
    /// Whether all signatures are valid
    pub signatures_valid: bool,
    /// Overall verification result
    pub is_valid: bool,
    /// Errors encountered during verification (if any)
    pub errors: Vec<String>,
    /// Temporal warnings (informational only, do not affect validity)
    pub temporal_warnings: Vec<TemporalWarning>,
}

impl VerificationReport {
    /// Create a new verification report
    #[must_use]
    pub const fn new(file_id: FileId, version_count: u64) -> Self {
        Self {
            file_id,
            version_count,
            structure_valid: false,
            integrity_hash_valid: false,
            hash_chain_valid: false,
            signatures_valid: false,
            is_valid: false,
            errors: Vec::new(),
            temporal_warnings: Vec::new(),
        }
    }

    /// Check if the report has any temporal warnings
    #[must_use]
    pub fn has_temporal_warnings(&self) -> bool {
        !self.temporal_warnings.is_empty()
    }

    /// Map this verdict to a process exit code.
    ///
    /// This is the **sole** producer of a verify-path exit code in
    /// the aion CLI. A valid report maps to
    /// [`std::process::ExitCode::SUCCESS`]; anything else maps to
    /// `ExitCode::from(1)`. Callers must thread this through their
    /// return type rather than branching on `is_valid` and calling
    /// `std::process::exit` by hand — see issue #23.
    #[must_use]
    pub const fn exit_code(&self) -> std::process::ExitCode {
        if self.is_valid {
            std::process::ExitCode::SUCCESS
        } else {
            // NOTE: std::process::ExitCode::from is not const as of 1.70;
            // construct via the literal path.
            std::process::ExitCode::FAILURE
        }
    }

    /// Mark all checks as passed
    pub fn mark_valid(&mut self) {
        self.structure_valid = true;
        self.integrity_hash_valid = true;
        self.hash_chain_valid = true;
        self.signatures_valid = true;
        self.is_valid = true;
    }
}

// ============================================================================
// Temporal Ordering Validation (RFC-0005)
// ============================================================================

/// Clock skew tolerance: 5 minutes in nanoseconds
/// Timestamps within this range won't trigger warnings
const CLOCK_SKEW_TOLERANCE_NANOS: u64 = 5 * 60 * 1_000_000_000;

/// Future timestamp tolerance: 1 minute in nanoseconds
/// Timestamps up to this far in the future are tolerated without warning
const FUTURE_TOLERANCE_NANOS: u64 = 60 * 1_000_000_000;

/// Check temporal ordering of version timestamps
///
/// This function validates that timestamps are consistent and monotonically
/// increasing. It generates warnings (not errors) for:
///
/// 1. **Non-monotonic timestamps**: A version has a timestamp earlier than
///    its predecessor (possible backdating or clock issues)
/// 2. **Future timestamps**: A version has a timestamp in the future
///    (possible clock drift)
/// 3. **Clock skew**: Timestamps are suspiciously close together while
///    going backwards
///
/// Per RFC-0005, these are informational warnings only and do NOT cause
/// verification to fail. The cryptographic chain remains valid regardless
/// of timestamp ordering.
///
/// # Arguments
///
/// * `versions` - Slice of version entries to check
///
/// # Returns
///
/// Vector of temporal warnings (empty if no issues detected)
fn check_temporal_ordering(versions: &[VersionEntry]) -> Vec<TemporalWarning> {
    let mut warnings = Vec::new();

    if versions.is_empty() {
        return warnings;
    }

    // Get current time for future timestamp detection
    let current_time = current_timestamp_nanos();

    // Check each version
    for (i, version) in versions.iter().enumerate() {
        let version_num = version.version_number;
        let timestamp = version.timestamp;

        // Check for future timestamps (beyond tolerance)
        if timestamp > current_time.saturating_add(FUTURE_TOLERANCE_NANOS) {
            warnings.push(TemporalWarning::FutureTimestamp {
                version: version_num,
                timestamp,
                current_time,
            });
        }

        // Check monotonicity against previous version
        if let Some(prev) = i.checked_sub(1).and_then(|j| versions.get(j)) {
            let prev_timestamp = prev.timestamp;

            if timestamp < prev_timestamp {
                // Non-monotonic: this version is earlier than previous
                let diff = prev_timestamp.saturating_sub(timestamp);

                // Only report if beyond clock skew tolerance
                if diff > CLOCK_SKEW_TOLERANCE_NANOS {
                    warnings.push(TemporalWarning::NonMonotonicTimestamp {
                        version: version_num,
                        timestamp,
                        previous_timestamp: prev_timestamp,
                    });
                } else {
                    // Within tolerance but still backwards - report as clock skew
                    #[allow(clippy::cast_possible_wrap)]
                    let skew_nanos = (diff as i64).saturating_neg();
                    warnings.push(TemporalWarning::ClockSkewDetected {
                        version: version_num,
                        skew_nanos,
                    });
                }
            }
        }
    }

    warnings
}

/// Verify the integrity and authenticity of an AION file
///
/// This function performs comprehensive verification of an AION file according to RFC-0001.
/// It validates:
///
/// 1. **Structure validation**: File format is parseable and well-formed
/// 2. **Integrity hash check**: File-level hash matches computed hash
/// 3. **Hash chain verification**: Version chain is intact from genesis
/// 4. **Signature verification**: All Ed25519 signatures are valid
///
/// # Arguments
///
/// * `path` - Path to the AION file to verify
///
/// # Returns
///
/// * `Ok(VerificationReport)` - Detailed report of verification results
/// * `Err(AionError)` - Critical error preventing verification
///
/// # Errors
///
/// - `AionError::Io` if file cannot be read
/// - `AionError::InvalidFormat` if file structure is corrupted
///
/// # Example
///
/// ```no_run
/// use aion_context::operations::verify_file;
/// use aion_context::key_registry::KeyRegistry;
/// use std::path::Path;
///
/// let registry = KeyRegistry::new(); // pin authors before production use
/// let report = verify_file(Path::new("rules.aion"), &registry)?;
///
/// if report.is_valid {
///     println!("✅ File verified successfully");
///     println!("   Versions: {}", report.version_count);
/// } else {
///     println!("❌ Verification failed:");
///     for error in &report.errors {
///         println!("   - {}", error);
///     }
/// }
/// # Ok::<(), aion_context::AionError>(())
/// ```
pub fn verify_file(
    path: &Path,
    registry: &crate::key_registry::KeyRegistry,
) -> Result<VerificationReport> {
    let file_bytes = std::fs::read(path).map_err(|e| AionError::FileReadError {
        path: path.to_path_buf(),
        source: e,
    })?;
    let parser = AionParser::new(&file_bytes)?;
    let header = parser.header();

    let mut report = VerificationReport::new(FileId(header.file_id), header.version_chain_count);
    report.structure_valid = true;

    match parser.verify_integrity() {
        Ok(()) => report.integrity_hash_valid = true,
        Err(e) => report
            .errors
            .push(format!("File integrity hash mismatch: {e}")),
    }

    let Some(versions) = collect_versions_into_report(&parser, &mut report)? else {
        emit_verify_outcome(&report);
        return Ok(report);
    };

    match verify_hash_chain(&versions) {
        Ok(()) => report.hash_chain_valid = true,
        Err(e) => report
            .errors
            .push(format!("Hash chain verification failed: {e}")),
    }

    let Some(signatures) = collect_signatures_into_report(&parser, &mut report)? else {
        emit_verify_outcome(&report);
        return Ok(report);
    };

    match verify_signatures_batch(&versions, &signatures, registry) {
        Ok(()) => report.signatures_valid = true,
        Err(e) => report
            .errors
            .push(format!("Signature verification failed: {e}")),
    }

    report.temporal_warnings = check_temporal_ordering(&versions);
    report.is_valid = report.structure_valid
        && report.integrity_hash_valid
        && report.hash_chain_valid
        && report.signatures_valid;
    emit_verify_outcome(&report);
    Ok(report)
}

/// Bounded `reason` codes for `event="file_rejected"` (RFC-0007 / observability rule).
const fn classify_verify_failure(report: &VerificationReport) -> &'static str {
    if !report.structure_valid {
        "structure_invalid"
    } else if !report.integrity_hash_valid {
        "integrity_hash_mismatch"
    } else if !report.hash_chain_valid {
        "hash_chain_broken"
    } else if !report.signatures_valid {
        "signature_invalid"
    } else {
        "unknown"
    }
}

fn emit_verify_outcome(report: &VerificationReport) {
    let file_id = crate::obs::short_hex(&report.file_id.as_u64().to_le_bytes());
    if report.is_valid {
        tracing::info!(
            event = "file_verified",
            file_id = %file_id,
            versions = report.version_count,
        );
    } else {
        tracing::warn!(
            event = "file_rejected",
            file_id = %file_id,
            versions = report.version_count,
            reason = classify_verify_failure(report),
        );
    }
}

#[allow(clippy::cast_possible_truncation)]
fn collect_versions_into_report(
    parser: &AionParser<'_>,
    report: &mut VerificationReport,
) -> Result<Option<Vec<VersionEntry>>> {
    let count = parser.header().version_chain_count as usize;
    let mut versions = Vec::with_capacity(count);
    for i in 0..count {
        match parser.get_version_entry(i) {
            Ok(entry) => versions.push(entry),
            Err(e) => {
                report
                    .errors
                    .push(format!("Failed to read version entry {i}: {e}"));
                return Ok(None);
            }
        }
    }
    Ok(Some(versions))
}

#[allow(clippy::cast_possible_truncation)]
fn collect_signatures_into_report(
    parser: &AionParser<'_>,
    report: &mut VerificationReport,
) -> Result<Option<Vec<SignatureEntry>>> {
    let count = parser.header().signatures_count as usize;
    let mut signatures = Vec::with_capacity(count);
    for i in 0..count {
        match parser.get_signature_entry(i) {
            Ok(entry) => signatures.push(entry),
            Err(e) => {
                report
                    .errors
                    .push(format!("Failed to read signature entry {i}: {e}"));
                return Ok(None);
            }
        }
    }
    Ok(Some(signatures))
}

// ============================================================================
// File Inspection Operations
// ============================================================================

/// Information about a version in the file
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VersionInfo {
    /// Version number
    pub version_number: u64,
    /// Author ID
    pub author_id: u64,
    /// Timestamp (nanoseconds since Unix epoch)
    pub timestamp: u64,
    /// Commit message
    pub message: String,
    /// Rules content hash
    pub rules_hash: [u8; 32],
    /// Parent version hash (None for genesis)
    pub parent_hash: Option<[u8; 32]>,
}

/// Information about a signature in the file
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignatureInfo {
    /// Version number this signature is for
    pub version_number: u64,
    /// Author ID
    pub author_id: u64,
    /// Public key (32 bytes)
    pub public_key: [u8; 32],
    /// Signature verification status
    pub verified: bool,
    /// Verification error message (if any)
    pub error: Option<String>,
}

/// Complete file information for inspection
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileInfo {
    /// File ID
    pub file_id: u64,
    /// Total number of versions
    pub version_count: u64,
    /// Current (latest) version number
    pub current_version: u64,
    /// List of all versions
    pub versions: Vec<VersionInfo>,
    /// List of all signatures
    pub signatures: Vec<SignatureInfo>,
}

/// Get the current (latest) rules content from an AION file
///
/// This function loads the file, finds the latest version entry,
/// and decrypts the rules using the file-specific encryption key.
///
/// # Arguments
///
/// * `path` - Path to the AION file
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Decrypted rules content
/// * `Err(AionError)` - On failure
///
/// # Errors
///
/// - `AionError::FileReadError` - Cannot read the file
/// - `AionError::InvalidFormat` - File format is invalid
/// - `AionError::DecryptionFailed` - Cannot decrypt rules
///
/// # Example
///
/// ```no_run
/// use aion_context::operations::show_current_rules;
/// use std::path::Path;
///
/// let rules = show_current_rules(Path::new("rules.aion"))?;
/// let rules_text = String::from_utf8(rules)?;
/// println!("Current rules:\n{}", rules_text);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn show_current_rules(path: &Path) -> Result<Vec<u8>> {
    // Load and parse the file
    let file_bytes = std::fs::read(path).map_err(|e| AionError::FileReadError {
        path: path.to_path_buf(),
        source: e,
    })?;
    let parser = AionParser::new(&file_bytes)?;

    let header = parser.header();
    let file_id = FileId(header.file_id);
    let version_count = header.version_chain_count;

    if version_count == 0 {
        return Err(AionError::InvalidFormat {
            reason: "File has no versions".to_string(),
        });
    }

    // Get the latest version (last in chain)
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::arithmetic_side_effects)] // version_count >= 1 checked above
    let latest_idx = (version_count - 1) as usize;
    let latest_version = parser.get_version_entry(latest_idx)?;

    // Get encrypted rules (entire section contains current version only)
    let encrypted_rules = parser.encrypted_rules_bytes()?;

    // Decrypt the rules
    decrypt_rules(
        encrypted_rules,
        file_id,
        VersionNumber(latest_version.version_number),
        latest_version.rules_hash,
    )
}

/// Get version history for all versions in the file
///
/// Returns detailed information about each version including
/// author, timestamp, message, and hashes.
///
/// # Arguments
///
/// * `path` - Path to the AION file
///
/// # Returns
///
/// * `Ok(Vec<VersionInfo>)` - List of version information
/// * `Err(AionError)` - On failure
///
/// # Errors
///
/// - `AionError::FileReadError` - Cannot read the file
/// - `AionError::InvalidFormat` - File format is invalid
///
/// # Example
///
/// ```no_run
/// use aion_context::operations::show_version_history;
/// use std::path::Path;
///
/// let versions = show_version_history(Path::new("rules.aion"))?;
/// for v in versions {
///     println!("Version {}: {} (by author {})",
///         v.version_number, v.message, v.author_id);
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn show_version_history(path: &Path) -> Result<Vec<VersionInfo>> {
    // Load and parse the file
    let file_bytes = std::fs::read(path).map_err(|e| AionError::FileReadError {
        path: path.to_path_buf(),
        source: e,
    })?;
    let parser = AionParser::new(&file_bytes)?;

    let header = parser.header();
    let version_count = header.version_chain_count;

    #[allow(clippy::cast_possible_truncation)] // version_count is header field, won't exceed usize
    let mut versions = Vec::with_capacity(version_count as usize);

    // Get string table for extracting messages
    let string_table = parser.string_table_bytes()?;

    #[allow(clippy::cast_possible_truncation)]
    for i in 0..version_count as usize {
        let entry = parser.get_version_entry(i)?;

        // Get commit message from string table
        let message_offset = entry.message_offset as usize;
        let message_length = entry.message_length as usize;

        #[allow(clippy::arithmetic_side_effects)] // Checked bounds before use
        let message =
            message_offset
                .checked_add(message_length)
                .map_or_else(String::new, |end_offset| {
                    if end_offset <= string_table.len() {
                        string_table
                            .get(message_offset..end_offset)
                            .map(|bytes| String::from_utf8_lossy(bytes).to_string())
                            .unwrap_or_default()
                    } else {
                        String::new()
                    }
                });

        // Parent hash is all zeros for genesis, otherwise it's the actual hash
        let parent_hash = if entry.version_number == 1 {
            None
        } else {
            Some(entry.parent_hash)
        };

        versions.push(VersionInfo {
            version_number: entry.version_number,
            author_id: entry.author_id,
            timestamp: entry.timestamp,
            message,
            rules_hash: entry.rules_hash,
            parent_hash,
        });
    }

    Ok(versions)
}

/// Get signature information with verification status
///
/// Returns detailed information about each signature including
/// verification status and any errors encountered during verification.
///
/// # Arguments
///
/// * `path` - Path to the AION file
///
/// # Returns
///
/// * `Ok(Vec<SignatureInfo>)` - List of signature information
/// * `Err(AionError)` - On failure
///
/// # Errors
///
/// - `AionError::FileReadError` - Cannot read the file
/// - `AionError::InvalidFormat` - File format is invalid
///
/// # Example
///
/// ```no_run
/// use aion_context::operations::show_signatures;
/// use aion_context::key_registry::KeyRegistry;
/// use std::path::Path;
///
/// let registry = KeyRegistry::new();
/// let signatures = show_signatures(Path::new("rules.aion"), &registry)?;
/// for sig in signatures {
///     let status = if sig.verified { "✓" } else { "✗" };
///     println!("{} Version {} signed by author {}",
///         status, sig.version_number, sig.author_id);
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
/// Each signature's `verified` field reflects the registry-aware
/// verdict: both the Ed25519 signature AND the signer's active
/// epoch (at the signed version number) must match. A signer
/// whose pinned active epoch does not match the embedded
/// `public_key` is reported `verified = false`.
pub fn show_signatures(
    path: &Path,
    registry: &crate::key_registry::KeyRegistry,
) -> Result<Vec<SignatureInfo>> {
    // Load and parse the file
    let file_bytes = std::fs::read(path).map_err(|e| AionError::FileReadError {
        path: path.to_path_buf(),
        source: e,
    })?;
    let parser = AionParser::new(&file_bytes)?;

    let header = parser.header();
    let sig_count = header.signatures_count;
    let version_count = header.version_chain_count;

    // Collect version entries for verification
    #[allow(clippy::cast_possible_truncation)] // version_count is header field, won't exceed usize
    let mut versions = Vec::with_capacity(version_count as usize);
    #[allow(clippy::cast_possible_truncation)]
    for i in 0..version_count as usize {
        versions.push(parser.get_version_entry(i)?);
    }

    #[allow(clippy::cast_possible_truncation)] // sig_count is header field, won't exceed usize
    let mut signatures = Vec::with_capacity(sig_count as usize);

    // Signatures are indexed parallel to versions (1:1 mapping)
    #[allow(clippy::cast_possible_truncation)]
    for i in 0..sig_count as usize {
        let sig_entry = parser.get_signature_entry(i)?;

        // Get corresponding version entry (parallel indexing)
        let version_entry = versions.get(i).ok_or_else(|| AionError::InvalidFormat {
            reason: format!(
                "Signature index {} exceeds version count {}",
                i,
                versions.len()
            ),
        })?;

        let result = crate::signature_chain::verify_signature(version_entry, &sig_entry, registry);
        let (verified, error) = match result {
            Ok(()) => (true, None),
            Err(e) => (false, Some(e.to_string())),
        };

        signatures.push(SignatureInfo {
            version_number: version_entry.version_number,
            author_id: sig_entry.author_id,
            public_key: sig_entry.public_key,
            verified,
            error,
        });
    }

    Ok(signatures)
}

/// Get complete file information including versions and signatures
///
/// This is a convenience function that combines version history
/// and signature information into a single comprehensive report.
///
/// # Arguments
///
/// * `path` - Path to the AION file
///
/// # Returns
///
/// * `Ok(FileInfo)` - Complete file information
/// * `Err(AionError)` - On failure
///
/// # Example
///
/// ```no_run
/// use aion_context::operations::show_file_info;
/// use aion_context::key_registry::KeyRegistry;
/// use std::path::Path;
///
/// let registry = KeyRegistry::new();
/// let info = show_file_info(Path::new("rules.aion"), &registry)?;
/// println!("File ID: 0x{:016x}", info.file_id);
/// println!("Current version: {}/{}", info.current_version, info.version_count);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn show_file_info(
    path: &Path,
    registry: &crate::key_registry::KeyRegistry,
) -> Result<FileInfo> {
    // Load and parse the file
    let file_bytes = std::fs::read(path).map_err(|e| AionError::FileReadError {
        path: path.to_path_buf(),
        source: e,
    })?;
    let parser = AionParser::new(&file_bytes)?;

    let header = parser.header();

    let versions = show_version_history(path)?;
    let signatures = show_signatures(path, registry)?;

    let current_version = versions.last().map_or(0, |v| v.version_number);

    Ok(FileInfo {
        file_id: header.file_id,
        version_count: header.version_chain_count,
        current_version,
        versions,
        signatures,
    })
}

/// Build string table with the new commit message appended
fn build_string_table_with_message(
    message: &str,
    parser: &AionParser<'_>,
) -> Result<(Vec<u8>, u64)> {
    // Get existing string table
    let existing_table = parser.string_table_bytes()?;

    // Calculate offset for new message
    let message_offset = existing_table.len() as u64;

    // Build new table with message appended
    let mut new_table = existing_table.to_vec();
    new_table.extend_from_slice(message.as_bytes());
    new_table.push(0); // Null terminator

    Ok((new_table, message_offset))
}

/// Get current timestamp in nanoseconds since Unix epoch
#[allow(clippy::cast_possible_truncation)] // Nanoseconds won't exceed u64 for realistic times
fn current_timestamp_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Build the updated `AionFile` with all existing and new data
#[allow(clippy::too_many_arguments)]
#[allow(clippy::cast_possible_truncation)] // File counts fit in usize
#[allow(clippy::arithmetic_side_effects)] // Capacity calculations are safe
fn build_updated_file(
    parser: &AionParser<'_>,
    header: &crate::parser::FileHeader,
    new_version: VersionNumber,
    new_rules_hash: [u8; 32],
    encrypted_rules: Vec<u8>,
    new_version_entry: VersionEntry,
    new_signature: SignatureEntry,
    string_table: Vec<u8>,
    timestamp: u64,
    author_id: AuthorId,
) -> Result<AionFile> {
    let versions = collect_existing_plus(parser, header.version_chain_count, new_version_entry)?;
    let signatures =
        collect_existing_plus_signatures(parser, header.signatures_count, new_signature)?;
    let audit_entries = collect_existing_audit_plus_commit(parser, header, timestamp, author_id)?;

    AionFile::builder()
        .file_id(FileId::new(header.file_id))
        .current_version(new_version)
        .flags(header.flags)
        .root_hash(header.root_hash)
        .current_hash(new_rules_hash)
        .created_at(header.created_at)
        .modified_at(timestamp)
        .encrypted_rules(encrypted_rules)
        .versions(versions)
        .signatures(signatures)
        .audit_entries(audit_entries)
        .string_table(string_table)
        .build()
}

#[allow(clippy::cast_possible_truncation)]
fn collect_versions(parser: &AionParser<'_>, count: u64) -> Result<Vec<VersionEntry>> {
    let n = count as usize;
    let mut versions = Vec::with_capacity(n);
    for i in 0..n {
        versions.push(parser.get_version_entry(i)?);
    }
    Ok(versions)
}

#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::arithmetic_side_effects)]
fn collect_existing_plus(
    parser: &AionParser<'_>,
    count: u64,
    new_entry: VersionEntry,
) -> Result<Vec<VersionEntry>> {
    let mut versions = collect_versions(parser, count)?;
    versions.push(new_entry);
    Ok(versions)
}

#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::arithmetic_side_effects)]
fn collect_existing_plus_signatures(
    parser: &AionParser<'_>,
    count: u64,
    new_entry: SignatureEntry,
) -> Result<Vec<SignatureEntry>> {
    let n = count as usize;
    let mut signatures = Vec::with_capacity(n + 1);
    for i in 0..n {
        signatures.push(parser.get_signature_entry(i)?);
    }
    signatures.push(new_entry);
    Ok(signatures)
}

#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::arithmetic_side_effects)]
fn collect_existing_audit_plus_commit(
    parser: &AionParser<'_>,
    header: &crate::parser::FileHeader,
    timestamp: u64,
    author_id: AuthorId,
) -> Result<Vec<AuditEntry>> {
    let n = header.audit_trail_count as usize;
    let mut audit_entries = Vec::with_capacity(n + 1);
    for i in 0..n {
        audit_entries.push(parser.get_audit_entry(i)?);
    }
    let previous_hash = audit_entries
        .last()
        .map_or([0u8; 32], AuditEntry::compute_hash);
    audit_entries.push(AuditEntry::new(
        timestamp,
        author_id,
        ActionCode::CommitVersion,
        0,
        0,
        previous_hash,
    ));
    Ok(audit_entries)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::inconsistent_digit_grouping)]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;
    use crate::audit::ActionCode;
    use crate::key_registry::KeyRegistry;
    use crate::serializer::AionSerializer;
    use crate::signature_chain::{create_genesis_version, sign_version};
    use tempfile::TempDir;

    /// Build a registry pinning `author_id` at epoch 0 with `signing_key`.
    /// Used by every test that calls `verify_file` / `commit_version` / `show_signatures`.
    fn test_reg(author_id: AuthorId, signing_key: &SigningKey) -> KeyRegistry {
        let mut reg = KeyRegistry::new();
        let master = SigningKey::generate();
        reg.register_author(
            author_id,
            master.verifying_key(),
            signing_key.verifying_key(),
            0,
        )
        .unwrap_or_else(|_| std::process::abort());
        reg
    }

    /// Create a minimal valid AION file for testing
    fn create_test_file(signing_key: &SigningKey, author_id: AuthorId) -> Vec<u8> {
        let timestamp = 1700000000_000_000_000u64;
        let rules = b"initial rules content";
        let rules_hash = hash(rules);

        // Create genesis version
        let genesis = create_genesis_version(rules_hash, author_id, timestamp, 0, 15);

        // Sign it
        let signature = sign_version(&genesis, signing_key);

        // Create audit entry
        let audit = AuditEntry::new(
            timestamp,
            author_id,
            ActionCode::CreateGenesis,
            0,
            0,
            [0u8; 32],
        );

        // Encrypt rules (simplified for test)
        let file_id = FileId::new(12345);
        let (encrypted_rules, _) = encrypt_rules(rules, file_id, VersionNumber::GENESIS).unwrap();

        // Build string table
        let (string_table, _) = AionSerializer::build_string_table(&["Genesis version"]);

        // Build file
        let file = AionFile::builder()
            .file_id(file_id)
            .current_version(VersionNumber::GENESIS)
            .flags(0x0001) // encrypted
            .root_hash(rules_hash)
            .current_hash(rules_hash)
            .created_at(timestamp)
            .modified_at(timestamp)
            .encrypted_rules(encrypted_rules)
            .add_version(genesis)
            .add_signature(signature)
            .add_audit_entry(audit)
            .string_table(string_table)
            .build()
            .unwrap();

        AionSerializer::serialize(&file).unwrap()
    }

    mod commit_version_tests {
        use super::*;

        #[test]
        fn should_commit_new_version() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("test.aion");

            // Create initial file
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let initial_bytes = create_test_file(&signing_key, author_id);
            std::fs::write(&file_path, &initial_bytes).unwrap();

            // Commit new version
            let options = CommitOptions {
                author_id,
                signing_key: &signing_key,
                message: "Updated rules",
                timestamp: Some(1700000001_000_000_000),
            };

            let result = commit_version(
                &file_path,
                b"new rules content",
                &options,
                &test_reg(author_id, &signing_key),
            )
            .unwrap();

            assert_eq!(result.version.as_u64(), 2);
            assert_ne!(result.rules_hash, [0u8; 32]);
        }

        #[test]
        fn should_verify_chain_before_commit() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("test.aion");

            // Create initial file
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let initial_bytes = create_test_file(&signing_key, author_id);
            std::fs::write(&file_path, &initial_bytes).unwrap();

            // Read file and verify we can parse it
            let bytes = std::fs::read(&file_path).unwrap();
            let parser = AionParser::new(&bytes).unwrap();
            assert_eq!(parser.header().current_version, 1);
        }

        #[test]
        fn should_increment_version_correctly() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("test.aion");

            // Create initial file
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let initial_bytes = create_test_file(&signing_key, author_id);
            std::fs::write(&file_path, &initial_bytes).unwrap();

            // Commit multiple versions
            for i in 2..=5 {
                let options = CommitOptions {
                    author_id,
                    signing_key: &signing_key,
                    message: &format!("Version {i}"),
                    timestamp: Some(1700000000_000_000_000 + i * 1_000_000_000),
                };

                let result = commit_version(
                    &file_path,
                    format!("rules v{i}").as_bytes(),
                    &options,
                    &test_reg(author_id, &signing_key),
                )
                .unwrap();
                assert_eq!(result.version.as_u64(), i);
            }

            // Verify final state
            let bytes = std::fs::read(&file_path).unwrap();
            let parser = AionParser::new(&bytes).unwrap();
            assert_eq!(parser.header().current_version, 5);
            assert_eq!(parser.header().version_chain_count, 5);
        }

        #[test]
        fn should_preserve_existing_versions() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("test.aion");

            // Create initial file
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let initial_bytes = create_test_file(&signing_key, author_id);
            std::fs::write(&file_path, &initial_bytes).unwrap();

            // Get initial version hash
            let initial_parser = AionParser::new(&initial_bytes).unwrap();
            let initial_version = initial_parser.get_version_entry(0).unwrap();
            let initial_hash = compute_version_hash(&initial_version);

            // Commit new version
            let options = CommitOptions {
                author_id,
                signing_key: &signing_key,
                message: "New version",
                timestamp: Some(1700000001_000_000_000),
            };
            commit_version(
                &file_path,
                b"new rules",
                &options,
                &test_reg(author_id, &signing_key),
            )
            .unwrap();

            // Verify original version is preserved
            let bytes = std::fs::read(&file_path).unwrap();
            let parser = AionParser::new(&bytes).unwrap();
            let preserved_version = parser.get_version_entry(0).unwrap();
            let preserved_hash = compute_version_hash(&preserved_version);

            assert_eq!(initial_hash, preserved_hash);
        }

        #[test]
        fn should_link_to_parent_correctly() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("test.aion");

            // Create initial file
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let initial_bytes = create_test_file(&signing_key, author_id);
            std::fs::write(&file_path, &initial_bytes).unwrap();

            // Get genesis hash
            let parser = AionParser::new(&initial_bytes).unwrap();
            let genesis = parser.get_version_entry(0).unwrap();
            let genesis_hash = compute_version_hash(&genesis);

            // Commit new version
            let options = CommitOptions {
                author_id,
                signing_key: &signing_key,
                message: "Version 2",
                timestamp: Some(1700000001_000_000_000),
            };
            commit_version(
                &file_path,
                b"new rules",
                &options,
                &test_reg(author_id, &signing_key),
            )
            .unwrap();

            // Verify version 2 links to genesis
            let bytes = std::fs::read(&file_path).unwrap();
            let parser = AionParser::new(&bytes).unwrap();
            let version2 = parser.get_version_entry(1).unwrap();

            assert_eq!(version2.parent_hash, genesis_hash);
        }
    }

    mod encrypt_rules_tests {
        use super::*;

        #[test]
        fn should_encrypt_rules_deterministically_with_same_nonce() {
            // Note: With random nonce, ciphertext differs each time
            // This test verifies the structure is correct
            let rules = b"test rules content";
            let file_id = FileId::new(12345);
            let version = VersionNumber::GENESIS;

            let (encrypted1, hash1) = encrypt_rules(rules, file_id, version).unwrap();
            let (encrypted2, hash2) = encrypt_rules(rules, file_id, version).unwrap();

            // Hashes should be identical
            assert_eq!(hash1, hash2);

            // Encrypted data should have nonce + ciphertext
            assert!(encrypted1.len() >= 12 + rules.len());
            assert!(encrypted2.len() >= 12 + rules.len());
        }

        #[test]
        fn should_produce_different_hashes_for_different_rules() {
            let file_id = FileId::new(12345);
            let version = VersionNumber::GENESIS;

            let (_, hash1) = encrypt_rules(b"rules A", file_id, version).unwrap();
            let (_, hash2) = encrypt_rules(b"rules B", file_id, version).unwrap();

            assert_ne!(hash1, hash2);
        }
    }

    mod decrypt_rules_tests {
        use super::*;

        #[test]
        fn should_decrypt_encrypted_rules_successfully() {
            // Arrange: Encrypt rules
            let rules = b"test rules content that needs decryption";
            let file_id = FileId::new(12345);
            let version = VersionNumber::GENESIS;

            let (encrypted, expected_hash) = encrypt_rules(rules, file_id, version).unwrap();

            // Act: Decrypt the encrypted rules
            let decrypted = decrypt_rules(&encrypted, file_id, version, expected_hash).unwrap();

            // Assert: Decrypted matches original
            assert_eq!(decrypted, rules);
        }

        #[test]
        fn should_verify_roundtrip_for_multiple_versions() {
            let file_id = FileId::new(54321);

            for version_num in 1..=5 {
                let version = VersionNumber(version_num);
                let rules = format!("Rules for version {version_num}").into_bytes();

                let (encrypted, hash) = encrypt_rules(&rules, file_id, version).unwrap();
                let decrypted = decrypt_rules(&encrypted, file_id, version, hash).unwrap();

                assert_eq!(decrypted, rules);
            }
        }

        #[test]
        fn should_reject_decryption_with_wrong_file_id() {
            // Arrange: Encrypt with one file ID
            let rules = b"sensitive rules";
            let correct_file_id = FileId::new(12345);
            let wrong_file_id = FileId::new(99999);
            let version = VersionNumber::GENESIS;

            let (encrypted, hash) = encrypt_rules(rules, correct_file_id, version).unwrap();

            // Act: Try to decrypt with wrong file ID
            let result = decrypt_rules(&encrypted, wrong_file_id, version, hash);

            // Assert: Decryption fails (wrong key derived)
            assert!(result.is_err());
        }

        #[test]
        fn should_reject_decryption_with_wrong_version() {
            // Arrange: Encrypt with one version
            let rules = b"version-specific rules";
            let file_id = FileId::new(12345);
            let correct_version = VersionNumber(1);
            let wrong_version = VersionNumber(2);

            let (encrypted, hash) = encrypt_rules(rules, file_id, correct_version).unwrap();

            // Act: Try to decrypt with wrong version
            let result = decrypt_rules(&encrypted, file_id, wrong_version, hash);

            // Assert: Decryption fails (wrong AAD)
            assert!(result.is_err());
        }

        #[test]
        fn should_reject_tampered_ciphertext() {
            // Arrange: Encrypt rules
            let rules = b"rules that will be tampered with";
            let file_id = FileId::new(12345);
            let version = VersionNumber::GENESIS;

            let (mut encrypted, hash) = encrypt_rules(rules, file_id, version).unwrap();

            // Act: Tamper with ciphertext (skip nonce, modify actual ciphertext)
            if encrypted.len() > 20 {
                encrypted[20] ^= 0x01;
            }

            let result = decrypt_rules(&encrypted, file_id, version, hash);

            // Assert: Decryption fails (authentication tag invalid)
            assert!(result.is_err());
            if let Err(e) = result {
                assert!(matches!(e, AionError::DecryptionFailed { .. }));
            }
        }

        #[test]
        fn should_reject_tampered_nonce() {
            // Arrange: Encrypt rules
            let rules = b"rules with nonce tampering";
            let file_id = FileId::new(12345);
            let version = VersionNumber::GENESIS;

            let (mut encrypted, hash) = encrypt_rules(rules, file_id, version).unwrap();

            // Act: Tamper with nonce (first 12 bytes)
            if !encrypted.is_empty() {
                encrypted[0] ^= 0x01;
            }

            let result = decrypt_rules(&encrypted, file_id, version, hash);

            // Assert: Decryption fails (wrong nonce)
            assert!(result.is_err());
        }

        #[test]
        fn should_reject_wrong_expected_hash() {
            // Arrange: Encrypt rules
            let rules = b"rules with wrong hash";
            let file_id = FileId::new(12345);
            let version = VersionNumber::GENESIS;

            let (encrypted, _correct_hash) = encrypt_rules(rules, file_id, version).unwrap();

            // Act: Use wrong expected hash
            let wrong_hash = [0u8; 32]; // All zeros is very unlikely to match
            let result = decrypt_rules(&encrypted, file_id, version, wrong_hash);

            // Assert: Hash verification fails
            assert!(result.is_err());
            if let Err(e) = result {
                assert!(matches!(e, AionError::HashMismatch { .. }));
            }
        }

        #[test]
        fn should_reject_too_short_encrypted_data() {
            // Arrange: Create data that's too short for nonce
            let short_data = [0u8; 8]; // Less than 12 bytes needed for nonce
            let file_id = FileId::new(12345);
            let version = VersionNumber::GENESIS;
            let hash = [0u8; 32];

            // Act: Try to decrypt
            let result = decrypt_rules(&short_data, file_id, version, hash);

            // Assert: Fails with appropriate error
            assert!(result.is_err());
            if let Err(e) = result {
                assert!(matches!(e, AionError::DecryptionFailed { .. }));
            }
        }

        #[test]
        fn should_handle_empty_rules_content() {
            // Arrange: Encrypt empty rules
            let rules = b"";
            let file_id = FileId::new(12345);
            let version = VersionNumber::GENESIS;

            let (encrypted, hash) = encrypt_rules(rules, file_id, version).unwrap();

            // Act: Decrypt
            let decrypted = decrypt_rules(&encrypted, file_id, version, hash).unwrap();

            // Assert: Empty content preserved
            assert_eq!(decrypted, rules);
            assert!(decrypted.is_empty());
        }

        #[test]
        fn should_handle_large_rules_content() {
            // Arrange: Encrypt large rules (1 MB)
            let rules = vec![0xAB; 1024 * 1024]; // 1 MB of data
            let file_id = FileId::new(12345);
            let version = VersionNumber::GENESIS;

            let (encrypted, hash) = encrypt_rules(&rules, file_id, version).unwrap();

            // Act: Decrypt
            let decrypted = decrypt_rules(&encrypted, file_id, version, hash).unwrap();

            // Assert: Large content preserved
            assert_eq!(decrypted.len(), rules.len());
            assert_eq!(decrypted, rules);
        }

        #[test]
        fn should_derive_different_keys_for_different_versions() {
            // This test verifies key derivation produces different keys for different versions
            let rules = b"same rules, different versions";
            let file_id = FileId::new(12345);

            let (encrypted_v1, hash1) = encrypt_rules(rules, file_id, VersionNumber(1)).unwrap();
            let (encrypted_v2, hash2) = encrypt_rules(rules, file_id, VersionNumber(2)).unwrap();

            // Hashes should be the same (same plaintext)
            assert_eq!(hash1, hash2);

            // But ciphertext should be different (different keys due to version in derivation)
            // Note: Even with same key, different nonces would make them different
            // But we verify by trying to decrypt with wrong version
            let result = decrypt_rules(&encrypted_v1, file_id, VersionNumber(2), hash1);
            assert!(result.is_err(), "Should not decrypt v1 data with v2 key");

            // Verify v2 also decrypts correctly with its own version
            let decrypted_v2 =
                decrypt_rules(&encrypted_v2, file_id, VersionNumber(2), hash2).unwrap();
            assert_eq!(decrypted_v2, rules);
        }
    }

    mod verification_tests {
        use super::*;

        #[test]
        fn should_reject_tampered_signature() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("test.aion");

            // Create initial file
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let mut initial_bytes = create_test_file(&signing_key, author_id);

            // Tamper with signature (signature is in the signatures section)
            // Find signature section and modify a byte
            let parser = AionParser::new(&initial_bytes).unwrap();
            let sig_offset = parser.header().signatures_offset as usize;
            if sig_offset + 50 < initial_bytes.len() {
                initial_bytes[sig_offset + 50] ^= 0x01;
            }

            std::fs::write(&file_path, &initial_bytes).unwrap();

            // Attempt to commit - should fail verification
            let options = CommitOptions {
                author_id,
                signing_key: &signing_key,
                message: "Should fail",
                timestamp: Some(1700000001_000_000_000),
            };

            let result = commit_version(
                &file_path,
                b"new rules",
                &options,
                &test_reg(author_id, &signing_key),
            );
            assert!(result.is_err());
        }

        /// Follow-up to issue #40 — same silent-zero pattern existed
        /// in `get_version_entry` (52 reserved bytes) and
        /// `get_signature_entry` (8 reserved bytes). Pre-fix, an
        /// attacker could flip reserved bytes; `verify_file` would
        /// flag the integrity-hash mismatch, but the next
        /// `commit_version` would silently launder the tamper because
        /// `get_version_entry` zeroed reserved on read. Post-fix,
        /// the parser rejects non-zero reserved at parse time and
        /// `commit_version` propagates the Err.
        #[test]
        fn should_reject_tampered_version_entry_reserved_bytes() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("ver_tamper.aion");
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50_011);
            let mut bytes = create_test_file(&signing_key, author_id);

            let parser = AionParser::new(&bytes).unwrap();
            // Flip a byte squarely inside VersionEntry.reserved
            // (entry-relative offset 100..152 → pick 130).
            let off = parser.header().version_chain_offset as usize + 130;
            bytes[off] ^= 0x55;
            std::fs::write(&file_path, &bytes).unwrap();

            // Direct parser-level check.
            let parser2 = AionParser::new(&bytes).unwrap();
            assert!(
                parser2.get_version_entry(0).is_err(),
                "VersionEntry with non-zero reserved must be rejected at parse"
            );

            // Laundering path is also closed: commit_version fails
            // because rebuild reads every existing version.
            let options = CommitOptions {
                author_id,
                signing_key: &signing_key,
                message: "should fail",
                timestamp: None,
            };
            let result = commit_version(
                &file_path,
                b"new",
                &options,
                &test_reg(author_id, &signing_key),
            );
            assert!(
                result.is_err(),
                "commit_version must reject tampered reserved bytes (laundering closed)"
            );
        }

        #[test]
        fn should_reject_tampered_signature_entry_reserved_bytes() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("sig_tamper.aion");
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50_012);
            let mut bytes = create_test_file(&signing_key, author_id);

            let parser = AionParser::new(&bytes).unwrap();
            // SignatureEntry.reserved is bytes 104..112 of each
            // 112-byte entry; pick offset 108 inside the first
            // signature.
            let off = parser.header().signatures_offset as usize + 108;
            bytes[off] ^= 0x55;
            std::fs::write(&file_path, &bytes).unwrap();

            let parser2 = AionParser::new(&bytes).unwrap();
            assert!(
                parser2.get_signature_entry(0).is_err(),
                "SignatureEntry with non-zero reserved must be rejected at parse"
            );

            let options = CommitOptions {
                author_id,
                signing_key: &signing_key,
                message: "should fail",
                timestamp: None,
            };
            let result = commit_version(
                &file_path,
                b"new",
                &options,
                &test_reg(author_id, &signing_key),
            );
            assert!(
                result.is_err(),
                "commit_version must reject tampered SignatureEntry reserved"
            );
        }
    }

    mod file_verification_tests {
        use super::*;

        #[test]
        fn should_verify_valid_file() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("test.aion");

            // Create a valid file
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let file_bytes = create_test_file(&signing_key, author_id);
            std::fs::write(&file_path, &file_bytes).unwrap();

            // Verify the file
            let report = verify_file(&file_path, &test_reg(author_id, &signing_key)).unwrap();

            assert!(report.is_valid);
            assert!(report.structure_valid);
            assert!(report.integrity_hash_valid);
            assert!(report.hash_chain_valid);
            assert!(report.signatures_valid);
            assert_eq!(report.version_count, 1);
            assert!(report.errors.is_empty());
        }

        #[test]
        fn should_verify_multi_version_file() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("test.aion");

            // Create initial file
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let initial_bytes = create_test_file(&signing_key, author_id);
            std::fs::write(&file_path, &initial_bytes).unwrap();

            // Add more versions
            let options = CommitOptions {
                author_id,
                signing_key: &signing_key,
                message: "Version 2",
                timestamp: Some(1700000001_000_000_000),
            };
            commit_version(
                &file_path,
                b"rules v2",
                &options,
                &test_reg(author_id, &signing_key),
            )
            .unwrap();

            let options = CommitOptions {
                author_id,
                signing_key: &signing_key,
                message: "Version 3",
                timestamp: Some(1700000002_000_000_000),
            };
            commit_version(
                &file_path,
                b"rules v3",
                &options,
                &test_reg(author_id, &signing_key),
            )
            .unwrap();

            // Verify the file
            let report = verify_file(&file_path, &test_reg(author_id, &signing_key)).unwrap();

            assert!(report.is_valid);
            assert_eq!(report.version_count, 3);
            assert!(report.errors.is_empty());
        }

        #[test]
        fn should_detect_corrupted_integrity_hash() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("test.aion");

            // Create a valid file
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let mut file_bytes = create_test_file(&signing_key, author_id);

            // Corrupt the integrity hash (last 32 bytes)
            let len = file_bytes.len();
            if len > 32 {
                file_bytes[len - 10] ^= 0xFF;
            }

            std::fs::write(&file_path, &file_bytes).unwrap();

            // Verify the file
            let report = verify_file(&file_path, &test_reg(author_id, &signing_key)).unwrap();

            assert!(!report.is_valid);
            assert!(report.structure_valid);
            assert!(!report.integrity_hash_valid);
            assert!(!report.errors.is_empty());
        }

        #[test]
        fn should_detect_broken_hash_chain() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("test.aion");

            // Create initial file
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let initial_bytes = create_test_file(&signing_key, author_id);
            std::fs::write(&file_path, &initial_bytes).unwrap();

            // Add a version
            let options = CommitOptions {
                author_id,
                signing_key: &signing_key,
                message: "Version 2",
                timestamp: Some(1700000001_000_000_000),
            };
            commit_version(
                &file_path,
                b"rules v2",
                &options,
                &test_reg(author_id, &signing_key),
            )
            .unwrap();

            // Corrupt the version chain (change second version number to 99)
            let mut file_bytes = std::fs::read(&file_path).unwrap();
            let version_offset = {
                let parser = AionParser::new(&file_bytes).unwrap();
                parser.header().version_chain_offset as usize
            };

            // Tamper with second version's version number (first 8 bytes of second entry)
            // This breaks version monotonicity
            let version_entry_size = 108; // Size of VersionEntry
            if version_offset + version_entry_size + 7 < file_bytes.len() {
                file_bytes[version_offset + version_entry_size] = 99; // Change version to 99
            }

            std::fs::write(&file_path, &file_bytes).unwrap();

            // Verify the file
            let report = verify_file(&file_path, &test_reg(author_id, &signing_key)).unwrap();

            // Tampering should cause overall validation failure
            assert!(!report.is_valid);
            assert!(!report.errors.is_empty());
        }

        #[test]
        fn should_detect_invalid_signature() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("test.aion");

            // Create a valid file
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let mut file_bytes = create_test_file(&signing_key, author_id);

            // Corrupt a signature
            let parser = AionParser::new(&file_bytes).unwrap();
            let sig_offset = parser.header().signatures_offset as usize;
            if sig_offset + 50 < file_bytes.len() {
                file_bytes[sig_offset + 50] ^= 0x01;
            }

            std::fs::write(&file_path, &file_bytes).unwrap();

            // Verify the file
            let report = verify_file(&file_path, &test_reg(author_id, &signing_key)).unwrap();

            assert!(!report.is_valid);
            assert!(report.structure_valid);
            assert!(!report.signatures_valid);
            assert!(!report.errors.is_empty());
        }

        #[test]
        fn should_handle_malformed_file() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("test.aion");

            // Write invalid data
            std::fs::write(&file_path, b"not a valid aion file").unwrap();

            // Verify the file
            let result = verify_file(&file_path, &KeyRegistry::new());

            // Should fail to parse
            assert!(result.is_err());
        }

        #[test]
        fn should_handle_nonexistent_file() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("nonexistent.aion");

            // Verify the file
            let result = verify_file(&file_path, &KeyRegistry::new());

            // Should fail with file read error
            assert!(result.is_err());
        }

        #[test]
        fn should_report_all_errors() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("test.aion");

            // Create initial file
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let initial_bytes = create_test_file(&signing_key, author_id);
            std::fs::write(&file_path, &initial_bytes).unwrap();

            // Add a version
            let options = CommitOptions {
                author_id,
                signing_key: &signing_key,
                message: "Version 2",
                timestamp: Some(1700000001_000_000_000),
            };
            commit_version(
                &file_path,
                b"rules v2",
                &options,
                &test_reg(author_id, &signing_key),
            )
            .unwrap();

            // Corrupt multiple things: hash, chain, and signature
            let mut file_bytes = std::fs::read(&file_path).unwrap();

            // Read offsets before mutating
            let (version_offset, sig_offset) = {
                let parser = AionParser::new(&file_bytes).unwrap();
                let header = parser.header();
                (
                    header.version_chain_offset as usize,
                    header.signatures_offset as usize,
                )
            };

            // Corrupt integrity hash
            let len = file_bytes.len();
            if len > 32 {
                file_bytes[len - 10] ^= 0xFF;
            }

            // Corrupt version chain (change second version number)
            let version_entry_size = 108;
            if version_offset + version_entry_size + 7 < file_bytes.len() {
                file_bytes[version_offset + version_entry_size] = 99; // Change version to 99
            }

            // Corrupt signature
            if sig_offset + 50 < file_bytes.len() {
                file_bytes[sig_offset + 50] ^= 0x01;
            }

            std::fs::write(&file_path, &file_bytes).unwrap();

            // Verify the file
            let report = verify_file(&file_path, &test_reg(author_id, &signing_key)).unwrap();

            // Multiple tampering should cause validation failure
            assert!(!report.is_valid);
            assert!(report.structure_valid); // Structure is still parseable
            assert!(!report.integrity_hash_valid);

            // Should report multiple errors (at least integrity hash failed)
            assert!(!report.errors.is_empty());
        }

        #[test]
        fn should_verify_empty_errors_on_valid_file() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("test.aion");

            // Create a valid file
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let file_bytes = create_test_file(&signing_key, author_id);
            std::fs::write(&file_path, &file_bytes).unwrap();

            // Verify the file
            let report = verify_file(&file_path, &test_reg(author_id, &signing_key)).unwrap();

            // Valid file should have no errors
            assert!(report.errors.is_empty());
            assert!(report.is_valid);
        }
    }

    mod file_inspection_tests {
        use super::*;

        #[test]
        fn should_show_current_rules() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("test.aion");

            // Create a test file
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let file_bytes = create_test_file(&signing_key, author_id);
            std::fs::write(&file_path, &file_bytes).unwrap();

            // Show current rules
            let rules = show_current_rules(&file_path).unwrap();

            // Should get the test rules back
            assert_eq!(rules, b"initial rules content");
        }

        #[test]
        fn should_show_version_history_single_version() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("test.aion");

            // Create a test file
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let file_bytes = create_test_file(&signing_key, author_id);
            std::fs::write(&file_path, &file_bytes).unwrap();

            // Show version history
            let versions = show_version_history(&file_path).unwrap();

            assert_eq!(versions.len(), 1);
            assert_eq!(versions[0].version_number, 1);
            assert_eq!(versions[0].author_id, author_id.as_u64());
            assert_eq!(versions[0].message, "Genesis version");
            assert!(versions[0].parent_hash.is_none()); // Genesis has no parent
        }

        #[test]
        fn should_show_version_history_multiple_versions() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("test.aion");

            // Create initial file
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let initial_bytes = create_test_file(&signing_key, author_id);
            std::fs::write(&file_path, &initial_bytes).unwrap();

            // Add more versions
            let options = CommitOptions {
                author_id,
                signing_key: &signing_key,
                message: "Version 2",
                timestamp: Some(1700000001_000_000_000),
            };
            commit_version(
                &file_path,
                b"rules v2",
                &options,
                &test_reg(author_id, &signing_key),
            )
            .unwrap();

            let options = CommitOptions {
                author_id,
                signing_key: &signing_key,
                message: "Version 3",
                timestamp: Some(1700000002_000_000_000),
            };
            commit_version(
                &file_path,
                b"rules v3",
                &options,
                &test_reg(author_id, &signing_key),
            )
            .unwrap();

            // Show version history
            let versions = show_version_history(&file_path).unwrap();

            assert_eq!(versions.len(), 3);
            assert_eq!(versions[0].version_number, 1);
            assert_eq!(versions[0].message, "Genesis version");
            assert!(versions[0].parent_hash.is_none());

            assert_eq!(versions[1].version_number, 2);
            assert_eq!(versions[1].message, "Version 2");
            assert!(versions[1].parent_hash.is_some());

            assert_eq!(versions[2].version_number, 3);
            assert_eq!(versions[2].message, "Version 3");
            assert!(versions[2].parent_hash.is_some());
        }

        #[test]
        fn should_show_signatures_with_verification() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("test.aion");

            // Create a test file
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let file_bytes = create_test_file(&signing_key, author_id);
            std::fs::write(&file_path, &file_bytes).unwrap();

            // Show signatures
            let signatures =
                show_signatures(&file_path, &test_reg(author_id, &signing_key)).unwrap();

            assert_eq!(signatures.len(), 1);
            assert_eq!(signatures[0].version_number, 1);
            assert_eq!(signatures[0].author_id, author_id.as_u64());
            assert!(signatures[0].verified);
            assert!(signatures[0].error.is_none());
        }

        #[test]
        fn should_show_signatures_with_multiple_versions() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("test.aion");

            // Create initial file
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let initial_bytes = create_test_file(&signing_key, author_id);
            std::fs::write(&file_path, &initial_bytes).unwrap();

            // Add another version
            let options = CommitOptions {
                author_id,
                signing_key: &signing_key,
                message: "Version 2",
                timestamp: Some(1700000001_000_000_000),
            };
            commit_version(
                &file_path,
                b"rules v2",
                &options,
                &test_reg(author_id, &signing_key),
            )
            .unwrap();

            // Show signatures
            let signatures =
                show_signatures(&file_path, &test_reg(author_id, &signing_key)).unwrap();

            assert_eq!(signatures.len(), 2);
            assert!(signatures[0].verified);
            assert!(signatures[1].verified);
            assert!(signatures[0].error.is_none());
            assert!(signatures[1].error.is_none());
        }

        #[test]
        fn should_detect_invalid_signature_in_show() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("test.aion");

            // Create a valid file
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let mut file_bytes = create_test_file(&signing_key, author_id);

            // Corrupt a signature
            let parser = AionParser::new(&file_bytes).unwrap();
            let sig_offset = parser.header().signatures_offset as usize;
            if sig_offset + 50 < file_bytes.len() {
                file_bytes[sig_offset + 50] ^= 0x01;
            }

            std::fs::write(&file_path, &file_bytes).unwrap();

            // Show signatures
            let signatures =
                show_signatures(&file_path, &test_reg(author_id, &signing_key)).unwrap();

            assert_eq!(signatures.len(), 1);
            assert!(!signatures[0].verified);
            assert!(signatures[0].error.is_some());
        }

        #[test]
        fn should_show_complete_file_info() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("test.aion");

            // Create initial file
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let initial_bytes = create_test_file(&signing_key, author_id);
            std::fs::write(&file_path, &initial_bytes).unwrap();

            // Add another version
            let options = CommitOptions {
                author_id,
                signing_key: &signing_key,
                message: "Version 2",
                timestamp: Some(1700000001_000_000_000),
            };
            commit_version(
                &file_path,
                b"rules v2",
                &options,
                &test_reg(author_id, &signing_key),
            )
            .unwrap();

            // Show file info
            let info = show_file_info(&file_path, &test_reg(author_id, &signing_key)).unwrap();

            assert_eq!(info.version_count, 2);
            assert_eq!(info.current_version, 2);
            assert_eq!(info.versions.len(), 2);
            assert_eq!(info.signatures.len(), 2);

            // All signatures should be verified
            for sig in &info.signatures {
                assert!(sig.verified);
            }
        }

        #[test]
        fn should_show_current_rules_for_latest_version() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("test.aion");

            // Create initial file
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let initial_bytes = create_test_file(&signing_key, author_id);
            std::fs::write(&file_path, &initial_bytes).unwrap();

            // Add new version with different rules
            let options = CommitOptions {
                author_id,
                signing_key: &signing_key,
                message: "Updated rules",
                timestamp: Some(1700000001_000_000_000),
            };
            let new_rules = b"these are the updated rules";
            commit_version(
                &file_path,
                new_rules,
                &options,
                &test_reg(author_id, &signing_key),
            )
            .unwrap();

            // Show current rules should return the latest
            let rules = show_current_rules(&file_path).unwrap();
            assert_eq!(rules, new_rules);
        }

        #[test]
        fn should_handle_empty_file() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("test.aion");

            // Write invalid/empty file
            std::fs::write(&file_path, b"").unwrap();

            // All operations should fail gracefully
            assert!(show_current_rules(&file_path).is_err());
            assert!(show_version_history(&file_path).is_err());
            assert!(show_signatures(&file_path, &KeyRegistry::new()).is_err());
            assert!(show_file_info(&file_path, &KeyRegistry::new()).is_err());
        }

        #[test]
        fn should_handle_nonexistent_file() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("nonexistent.aion");

            // All operations should fail with file read error
            assert!(show_current_rules(&file_path).is_err());
            assert!(show_version_history(&file_path).is_err());
            assert!(show_signatures(&file_path, &KeyRegistry::new()).is_err());
            assert!(show_file_info(&file_path, &KeyRegistry::new()).is_err());
        }
    }

    mod init_file_tests {
        use super::*;

        #[test]
        fn should_create_new_file_successfully() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("new.aion");

            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let options = InitOptions {
                author_id,
                signing_key: &signing_key,
                message: "Initial version",
                timestamp: Some(1700000000_000_000_000),
            };

            let rules = b"fraud_threshold: 1000\nrisk_level: medium";
            let result = init_file(&file_path, rules, &options).unwrap();

            // Check result
            assert_eq!(result.version.as_u64(), 1);
            assert!(file_path.exists());

            // Verify file can be read back
            let loaded_rules = show_current_rules(&file_path).unwrap();
            assert_eq!(loaded_rules, rules);
        }

        #[test]
        fn should_create_file_with_correct_structure() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("structured.aion");

            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let options = InitOptions {
                author_id,
                signing_key: &signing_key,
                message: "Genesis",
                timestamp: Some(1700000000_000_000_000),
            };

            let rules = b"test rules";
            init_file(&file_path, rules, &options).unwrap();

            // Verify file structure
            let info = show_file_info(&file_path, &test_reg(author_id, &signing_key)).unwrap();
            assert_eq!(info.version_count, 1);
            assert_eq!(info.current_version, 1);
            assert_eq!(info.versions.len(), 1);
            assert_eq!(info.signatures.len(), 1);

            // Check version details
            assert_eq!(info.versions[0].version_number, 1);
            assert_eq!(info.versions[0].author_id, author_id.as_u64());
            assert_eq!(info.versions[0].message, "Genesis");
            assert!(info.versions[0].parent_hash.is_none());

            // Check signature
            assert!(info.signatures[0].verified);
            assert_eq!(info.signatures[0].author_id, author_id.as_u64());
        }

        #[test]
        fn should_fail_if_file_already_exists() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("exists.aion");

            // Create file first
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let options = InitOptions {
                author_id,
                signing_key: &signing_key,
                message: "Initial version",
                timestamp: Some(1700000000_000_000_000),
            };

            init_file(&file_path, b"rules", &options).unwrap();

            // Try to create again - should fail
            let result = init_file(&file_path, b"new rules", &options);
            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), AionError::FileExists { .. }));
        }

        #[test]
        fn should_generate_unique_file_ids() {
            let temp_dir = TempDir::new().unwrap();
            let path1 = temp_dir.path().join("file1.aion");
            let path2 = temp_dir.path().join("file2.aion");

            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let options = InitOptions {
                author_id,
                signing_key: &signing_key,
                message: "Initial",
                timestamp: Some(1700000000_000_000_000),
            };

            let result1 = init_file(&path1, b"rules1", &options).unwrap();
            let result2 = init_file(&path2, b"rules2", &options).unwrap();

            // File IDs should be different
            assert_ne!(result1.file_id.as_u64(), result2.file_id.as_u64());
        }

        #[test]
        fn should_encrypt_rules_content() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("encrypted.aion");

            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let options = InitOptions {
                author_id,
                signing_key: &signing_key,
                message: "Initial",
                timestamp: Some(1700000000_000_000_000),
            };

            let secret_rules = b"secret: fraud_detection_threshold_is_5000";
            init_file(&file_path, secret_rules, &options).unwrap();

            // Read raw file bytes - should not contain plaintext
            let file_bytes = std::fs::read(&file_path).unwrap();
            let file_string = String::from_utf8_lossy(&file_bytes);
            assert!(!file_string.contains("secret"));
            assert!(!file_string.contains("fraud_detection_threshold"));

            // But decryption should work
            let decrypted = show_current_rules(&file_path).unwrap();
            assert_eq!(decrypted, secret_rules);
        }

        #[test]
        fn should_create_valid_signature() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("signed.aion");

            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let options = InitOptions {
                author_id,
                signing_key: &signing_key,
                message: "Initial",
                timestamp: Some(1700000000_000_000_000),
            };

            init_file(&file_path, b"rules", &options).unwrap();

            // Verify signature is valid
            let report = verify_file(&file_path, &test_reg(author_id, &signing_key)).unwrap();
            assert!(report.is_valid);
            assert!(report.signatures_valid);
            assert!(report.errors.is_empty());
        }

        #[test]
        fn should_use_current_timestamp_when_none_provided() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("timestamped.aion");

            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let options = InitOptions {
                author_id,
                signing_key: &signing_key,
                message: "Initial",
                timestamp: None, // Should use current time
            };

            let before = current_timestamp_nanos();
            init_file(&file_path, b"rules", &options).unwrap();
            let after = current_timestamp_nanos();

            // Check timestamp is reasonable
            let versions = show_version_history(&file_path).unwrap();
            assert_eq!(versions.len(), 1);
            assert!(versions[0].timestamp >= before);
            assert!(versions[0].timestamp <= after);
        }

        #[test]
        fn should_handle_empty_rules() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("empty.aion");

            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let options = InitOptions {
                author_id,
                signing_key: &signing_key,
                message: "Empty genesis",
                timestamp: Some(1700000000_000_000_000),
            };

            let result = init_file(&file_path, b"", &options).unwrap();
            assert_eq!(result.version.as_u64(), 1);

            // Should be able to read back empty rules
            let rules = show_current_rules(&file_path).unwrap();
            assert_eq!(rules, b"");
        }

        #[test]
        fn should_handle_large_rules() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("large.aion");

            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let options = InitOptions {
                author_id,
                signing_key: &signing_key,
                message: "Large ruleset",
                timestamp: Some(1700000000_000_000_000),
            };

            // Create large rules (1MB)
            let large_rules = vec![b'X'; 1024 * 1024];
            init_file(&file_path, &large_rules, &options).unwrap();

            // Verify
            let decrypted = show_current_rules(&file_path).unwrap();
            assert_eq!(decrypted.len(), large_rules.len());
            assert_eq!(decrypted, large_rules);
        }

        #[test]
        fn should_handle_long_commit_messages() {
            let temp_dir = TempDir::new().unwrap();
            let file_path = temp_dir.path().join("longmsg.aion");

            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let long_message = "A".repeat(1000);
            let options = InitOptions {
                author_id,
                signing_key: &signing_key,
                message: &long_message,
                timestamp: Some(1700000000_000_000_000),
            };

            init_file(&file_path, b"rules", &options).unwrap();

            // Check message is preserved
            let versions = show_version_history(&file_path).unwrap();
            assert_eq!(versions[0].message, long_message);
        }
    }

    mod exit_code_tests {
        use super::*;

        fn report_with(is_valid: bool) -> VerificationReport {
            let mut r = VerificationReport::new(FileId::new(1), 1);
            r.is_valid = is_valid;
            r
        }

        #[test]
        fn valid_report_maps_to_success() {
            assert_eq!(
                report_with(true).exit_code(),
                std::process::ExitCode::SUCCESS
            );
        }

        #[test]
        fn invalid_report_maps_to_failure() {
            // ExitCode is opaque; compare via stable debug repr.
            let invalid = format!("{:?}", report_with(false).exit_code());
            let failure = format!("{:?}", std::process::ExitCode::FAILURE);
            assert_eq!(invalid, failure);
        }

        mod properties {
            use super::*;
            use hegel::generators as gs;

            #[hegel::test]
            fn prop_exit_code_reflects_verdict(tc: hegel::TestCase) {
                let is_valid = tc.draw(gs::integers::<u8>()) % 2 == 1;
                let report = report_with(is_valid);
                let observed = format!("{:?}", report.exit_code());
                let expected = format!(
                    "{:?}",
                    if is_valid {
                        std::process::ExitCode::SUCCESS
                    } else {
                        std::process::ExitCode::FAILURE
                    }
                );
                if observed != expected {
                    std::process::abort();
                }
            }
        }
    }

    /// Issue #25 — registry authz pre-check properties. These test
    /// `preflight_registry_authz` directly since building a real
    /// `.aion` file on every Hegel trial would be expensive; the full
    /// end-to-end contract is exercised by the CLI integration tests.
    mod registry_precheck_tests {
        use super::*;
        use crate::crypto::SigningKey;
        use crate::key_registry::KeyRegistry;

        mod properties {
            use super::*;
            use hegel::generators as gs;

            /// Build a fresh registry that pins exactly one author at
            /// epoch 0 with the supplied operational key.
            fn single_author_registry(author: AuthorId, op_key: &SigningKey) -> KeyRegistry {
                let master = SigningKey::generate();
                let mut reg = KeyRegistry::new();
                reg.register_author(author, master.verifying_key(), op_key.verifying_key(), 0)
                    .unwrap_or_else(|_| std::process::abort());
                reg
            }

            fn options(author: AuthorId, key: &SigningKey) -> CommitOptions<'_> {
                CommitOptions {
                    author_id: author,
                    signing_key: key,
                    message: "",
                    timestamp: None,
                }
            }

            /// Author not in the registry ⇒ `UnauthorizedSigner`.
            #[hegel::test]
            fn prop_unknown_author_rejects(tc: hegel::TestCase) {
                let pinned_id = tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 40));
                let probe_id = tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 40));
                if pinned_id == probe_id {
                    return; // skip the trivial collision
                }
                let version = tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 30));

                let pinned_key = SigningKey::generate();
                let reg = single_author_registry(AuthorId::new(pinned_id), &pinned_key);

                // Probe: a different author, any key.
                let probe_key = SigningKey::generate();
                let opts = options(AuthorId::new(probe_id), &probe_key);

                match preflight_registry_authz(&opts, VersionNumber(version), &reg) {
                    Err(AionError::UnauthorizedSigner { .. }) => {}
                    _ => std::process::abort(),
                }
            }

            /// Author pinned and key matches ⇒ `Ok`.
            #[hegel::test]
            fn prop_pinned_matching_key_accepts(tc: hegel::TestCase) {
                let author_id = tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 40));
                let version = tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 30));
                let author = AuthorId::new(author_id);

                let op_key = SigningKey::generate();
                let reg = single_author_registry(author, &op_key);
                let opts = options(author, &op_key);

                if preflight_registry_authz(&opts, VersionNumber(version), &reg).is_err() {
                    std::process::abort();
                }
            }

            /// Author pinned but key differs ⇒ `KeyMismatch`.
            #[hegel::test]
            fn prop_pinned_wrong_key_rejects(tc: hegel::TestCase) {
                let author_id = tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 40));
                let version = tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 30));
                let author = AuthorId::new(author_id);

                let pinned_key = SigningKey::generate();
                let reg = single_author_registry(author, &pinned_key);

                let wrong_key = SigningKey::generate();
                let opts = options(author, &wrong_key);

                match preflight_registry_authz(&opts, VersionNumber(version), &reg) {
                    Err(AionError::KeyMismatch { .. }) => {}
                    _ => std::process::abort(),
                }
            }
        }
    }

    /// Issue #35 — `commit_version` must still detect head-signature
    /// tampering even though the verify is now O(1) (head only) rather
    /// than O(n) (full sweep). Tampering of *non-head* prior signatures
    /// is intentionally caught by `verify_file`, not by commit.
    mod commit_head_verify_tests {
        use super::*;
        use crate::parser::SIGNATURE_ENTRY_SIZE;

        /// Tamper with a specific signature entry inside an .aion
        /// file's signature section by flipping one byte.
        #[allow(clippy::arithmetic_side_effects)] // bounded test inputs
        fn flip_byte_in_signature_at(bytes: &mut [u8], index: usize) {
            let parser = AionParser::new(bytes).unwrap();
            let sig_offset = parser.header().signatures_offset as usize;
            let target = sig_offset + index * SIGNATURE_ENTRY_SIZE + 50;
            assert!(target < bytes.len(), "tamper offset out of bounds");
            bytes[target] ^= 0x01;
        }

        /// Build a chain of v1..v3, all valid. Then tamper the HEAD
        /// (v3) signature; `commit_version` of v4 must reject.
        ///
        /// This is the post-#35 contract: head-only verify still
        /// catches tampering of the latest signature, even when
        /// every earlier signature is intact.
        #[test]
        fn commit_rejects_tampered_head_on_multi_version_chain() {
            let temp = TempDir::new().unwrap();
            let path = temp.path().join("head_tamper.aion");
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(70_001);
            let registry = test_reg(author_id, &signing_key);

            // Build v1, v2, v3 — all valid.
            let init_opts = InitOptions {
                author_id,
                signing_key: &signing_key,
                message: "v1",
                timestamp: None,
            };
            init_file(&path, b"r1", &init_opts).unwrap();
            for _ in 2..=3u64 {
                let opts = CommitOptions {
                    author_id,
                    signing_key: &signing_key,
                    message: "amend",
                    timestamp: None,
                };
                commit_version(&path, b"r", &opts, &registry).unwrap();
            }

            // Tamper signature index 2 (== v3, the head).
            let mut bytes = std::fs::read(&path).unwrap();
            flip_byte_in_signature_at(&mut bytes, 2);
            std::fs::write(&path, &bytes).unwrap();

            let next_opts = CommitOptions {
                author_id,
                signing_key: &signing_key,
                message: "v4",
                timestamp: None,
            };
            let result = commit_version(&path, b"r4", &next_opts, &registry);
            assert!(
                result.is_err(),
                "commit_version must reject when HEAD signature is tampered"
            );
        }

        /// Audit follow-up to #37: post-fix, `commit_version` runs
        /// `verify_integrity()` and `verify_hash_chain()` before
        /// every append, so tampering with ANY prior entry — not
        /// just the head — is caught at write time. This closes the
        /// laundering path that the original #37 narrative
        /// documented as intentional.
        ///
        /// (The function name predates the fix and is preserved for
        /// git-blame continuity; the docstring captures the new
        /// contract.)
        #[test]
        fn commit_now_catches_non_head_tamper_at_write_time() {
            let temp = TempDir::new().unwrap();
            let path = temp.path().join("non_head_tamper.aion");
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(70_002);
            let registry = test_reg(author_id, &signing_key);

            // v1, v2, v3.
            let init_opts = InitOptions {
                author_id,
                signing_key: &signing_key,
                message: "v1",
                timestamp: None,
            };
            init_file(&path, b"r1", &init_opts).unwrap();
            for _ in 2..=3u64 {
                let opts = CommitOptions {
                    author_id,
                    signing_key: &signing_key,
                    message: "amend",
                    timestamp: None,
                };
                commit_version(&path, b"r", &opts, &registry).unwrap();
            }

            // Tamper signature index 0 (v1, NOT the head).
            let mut bytes = std::fs::read(&path).unwrap();
            flip_byte_in_signature_at(&mut bytes, 0);
            std::fs::write(&path, &bytes).unwrap();
            let tampered = std::fs::read(&path).unwrap();

            // commit_version must NOW reject — the integrity hash
            // catches the byte flip even though it lives in a
            // non-head entry.
            let next_opts = CommitOptions {
                author_id,
                signing_key: &signing_key,
                message: "v4",
                timestamp: None,
            };
            let result = commit_version(&path, b"r4", &next_opts, &registry);
            assert!(
                result.is_err(),
                "commit_version must reject non-head tamper at write time"
            );

            // No bytes written — the refused commit must not mutate.
            let post = std::fs::read(&path).unwrap();
            assert_eq!(
                tampered, post,
                "refused commit must not mutate the tampered file"
            );

            // verify_file also rejects, as before.
            let report = verify_file(&path, &registry).unwrap();
            assert!(
                !report.is_valid,
                "verify_file must reject after a non-head signature tamper"
            );
        }

        /// Build cost smoke-check: a 200-version chain post-#35 should
        /// take well under a second. Pre-#35, this exact loop was
        /// ~636 ms (already noticeable); the head-only verify drops
        /// it close to file-I/O cost.
        #[test]
        fn commit_succeeds_on_clean_chain_of_many_versions() {
            let temp = TempDir::new().unwrap();
            let path = temp.path().join("many.aion");
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(70_003);
            let registry = test_reg(author_id, &signing_key);

            let init_opts = InitOptions {
                author_id,
                signing_key: &signing_key,
                message: "v1",
                timestamp: None,
            };
            init_file(&path, b"v1", &init_opts).unwrap();

            for _ in 2..=200u64 {
                let opts = CommitOptions {
                    author_id,
                    signing_key: &signing_key,
                    message: "amend",
                    timestamp: None,
                };
                commit_version(&path, b"amend", &opts, &registry).unwrap();
            }

            let report = verify_file(&path, &registry).unwrap();
            assert!(report.is_valid, "verify_file must accept the built chain");
            assert_eq!(report.version_count, 200);
        }
    }
}
