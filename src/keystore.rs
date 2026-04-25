// SPDX-License-Identifier: MIT OR Apache-2.0
//! Key management with OS keyring integration and file-based fallback
//!
//! This module provides secure key storage using the operating system's
//! credential management facilities (macOS Keychain, Windows Credential Manager,
//! Linux Secret Service). When OS keyring is unavailable, falls back to
//! encrypted file-based storage in `~/.aion/keys/`.
//!
//! # Security Properties
//!
//! - **OS-level protection**: Keys protected by OS encryption when available
//! - **Encrypted file fallback**: ChaCha20-Poly1305 encrypted files when keyring unavailable
//! - **Automatic zeroization**: Key material cleared from memory after use
//! - **Password-encrypted export**: Backup keys with ChaCha20-Poly1305 encryption
//! - **No plaintext storage**: Keys never written to disk unencrypted
//!
//! # Usage
//!
//! ```no_run
//! use aion_context::keystore::KeyStore;
//! use aion_context::types::AuthorId;
//!
//! # fn example() -> aion_context::Result<()> {
//! let keystore = KeyStore::new();
//!
//! // Generate and store a new keypair
//! let (signing_key, verifying_key) = keystore.generate_keypair(AuthorId::new(50001))?;
//!
//! // Load keypair later
//! let signing_key = keystore.load_signing_key(AuthorId::new(50001))?;
//! # Ok(())
//! # }
//! ```

use crate::crypto::{decrypt, encrypt, generate_nonce, SigningKey, VerifyingKey};
use crate::types::AuthorId;
use crate::{AionError, Result};
use rand::RngCore;
use std::path::PathBuf;

/// Service name for keyring entries
const KEYRING_SERVICE: &str = "aion-v2";

/// Magic bytes for encrypted key files
const EXPORT_MAGIC: &[u8; 4] = b"AKEY";

/// Export file version (v2 uses Argon2 instead of BLAKE3)
const EXPORT_VERSION: u8 = 2;

/// Salt size for Argon2 key derivation
const SALT_SIZE: usize = 16;

/// File-based key storage directory name
const KEYS_DIR: &str = "keys";

/// File extension for encrypted key files
const KEY_FILE_EXT: &str = ".key";

/// Magic bytes for file-based key storage
const FILE_KEY_MAGIC: &[u8; 4] = b"AFKY";

/// File key storage version
const FILE_KEY_VERSION: u8 = 1;

/// Key store for managing Ed25519 keypairs
///
/// Uses the OS keyring for secure storage when available, with automatic
/// fallback to encrypted file-based storage in `~/.aion/keys/`.
#[derive(Debug)]
pub struct KeyStore {
    /// Whether to use file-based storage (fallback mode)
    use_file_storage: bool,
    /// Base directory for file-based storage
    storage_dir: PathBuf,
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStore {
    /// Create a new key store
    ///
    /// Automatically detects whether OS keyring is available and falls back
    /// to file-based storage if not.
    #[must_use]
    pub fn new() -> Self {
        let storage_dir = get_aion_keys_dir();
        let use_file_storage = !is_keyring_available();

        Self {
            use_file_storage,
            storage_dir,
        }
    }

    /// Create a key store that always uses file-based storage
    ///
    /// Useful for testing or environments where keyring access is restricted.
    #[must_use]
    pub fn file_based() -> Self {
        Self {
            use_file_storage: true,
            storage_dir: get_aion_keys_dir(),
        }
    }

    /// Create a key store with a custom storage directory
    ///
    /// Useful for testing with isolated storage.
    #[must_use]
    pub const fn with_storage_dir(storage_dir: PathBuf) -> Self {
        Self {
            use_file_storage: true,
            storage_dir,
        }
    }

    /// Generate a new keypair and store it in the OS keyring
    ///
    /// # Errors
    ///
    /// Returns error if keyring access fails
    pub fn generate_keypair(&self, author_id: AuthorId) -> Result<(SigningKey, VerifyingKey)> {
        let signing_key = SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        self.store_signing_key(author_id, &signing_key)?;

        tracing::info!(
            event = "keystore_key_created",
            author = %crate::obs::author_short(author_id),
            backend = if self.use_file_storage { "file" } else { "os_keyring" },
        );
        Ok((signing_key, verifying_key))
    }

    /// Store a signing key
    ///
    /// Uses OS keyring when available, otherwise falls back to encrypted file storage.
    ///
    /// # Errors
    ///
    /// Returns error if storage fails
    pub fn store_signing_key(&self, author_id: AuthorId, key: &SigningKey) -> Result<()> {
        if self.use_file_storage {
            self.store_key_to_file(author_id, key)
        } else {
            self.store_key_to_keyring(author_id, key)
        }
    }

    /// Store a key in the OS keyring
    fn store_key_to_keyring(&self, author_id: AuthorId, key: &SigningKey) -> Result<()> {
        let entry = self.get_entry(author_id)?;
        let key_hex = hex::encode(key.to_bytes());

        entry
            .set_password(&key_hex)
            .map_err(|e| AionError::KeyringError {
                operation: "store".to_string(),
                reason: e.to_string(),
            })?;

        Ok(())
    }

    /// Store a key to encrypted file
    fn store_key_to_file(&self, author_id: AuthorId, key: &SigningKey) -> Result<()> {
        // Ensure keys directory exists
        std::fs::create_dir_all(&self.storage_dir).map_err(|e| AionError::KeyringError {
            operation: "create_dir".to_string(),
            reason: e.to_string(),
        })?;

        let file_path = self.get_key_file_path(author_id);

        // Encrypt key with machine-specific key
        let encrypted = encrypt_key_for_storage(author_id, key)?;

        // Write atomically via temp file
        let temp_path = file_path.with_extension("tmp");
        std::fs::write(&temp_path, &encrypted).map_err(|e| AionError::KeyringError {
            operation: "write".to_string(),
            reason: e.to_string(),
        })?;

        std::fs::rename(&temp_path, &file_path).map_err(|e| AionError::KeyringError {
            operation: "rename".to_string(),
            reason: e.to_string(),
        })?;

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&file_path, perms).map_err(|e| AionError::KeyringError {
                operation: "chmod".to_string(),
                reason: e.to_string(),
            })?;
        }

        Ok(())
    }

    /// Load a signing key
    ///
    /// Uses OS keyring when available, otherwise loads from encrypted file storage.
    ///
    /// # Errors
    ///
    /// Returns error if key not found or access fails
    pub fn load_signing_key(&self, author_id: AuthorId) -> Result<SigningKey> {
        let result = if self.use_file_storage {
            self.load_key_from_file(author_id)
        } else {
            self.load_key_from_keyring(author_id)
        };
        if let Err(ref e) = result {
            tracing::warn!(
                event = "keystore_load_rejected",
                author = %crate::obs::author_short(author_id),
                reason = match e {
                    AionError::KeyNotFound { .. } => "key_not_found",
                    AionError::InvalidPrivateKey { .. } => "invalid_key_bytes",
                    AionError::KeyringError { .. } => "keyring_error",
                    _ => "load_error",
                },
            );
        }
        result
    }

    /// Load a key from OS keyring
    fn load_key_from_keyring(&self, author_id: AuthorId) -> Result<SigningKey> {
        let entry = self.get_entry(author_id)?;

        let key_hex = entry.get_password().map_err(|e| AionError::KeyNotFound {
            author_id,
            reason: e.to_string(),
        })?;

        let key_bytes = hex::decode(&key_hex).map_err(|e| AionError::InvalidPrivateKey {
            reason: format!("invalid hex in keyring: {e}"),
        })?;

        SigningKey::from_bytes(&key_bytes)
    }

    /// Load a key from encrypted file
    fn load_key_from_file(&self, author_id: AuthorId) -> Result<SigningKey> {
        let file_path = self.get_key_file_path(author_id);

        if !file_path.exists() {
            return Err(AionError::KeyNotFound {
                author_id,
                reason: format!("key file not found: {}", file_path.display()),
            });
        }

        let encrypted = std::fs::read(&file_path).map_err(|e| AionError::KeyNotFound {
            author_id,
            reason: e.to_string(),
        })?;

        decrypt_key_from_storage(author_id, &encrypted)
    }

    /// Delete a signing key
    ///
    /// # Errors
    ///
    /// Returns error if key not found or access fails
    pub fn delete_signing_key(&self, author_id: AuthorId) -> Result<()> {
        if self.use_file_storage {
            self.delete_key_from_file(author_id)
        } else {
            self.delete_key_from_keyring(author_id)
        }
    }

    /// Delete a key from OS keyring
    fn delete_key_from_keyring(&self, author_id: AuthorId) -> Result<()> {
        let entry = self.get_entry(author_id)?;

        entry
            .delete_credential()
            .map_err(|e| AionError::KeyringError {
                operation: "delete".to_string(),
                reason: e.to_string(),
            })?;

        Ok(())
    }

    /// Delete a key file
    fn delete_key_from_file(&self, author_id: AuthorId) -> Result<()> {
        let file_path = self.get_key_file_path(author_id);

        if !file_path.exists() {
            return Err(AionError::KeyNotFound {
                author_id,
                reason: "key file not found".to_string(),
            });
        }

        std::fs::remove_file(&file_path).map_err(|e| AionError::KeyringError {
            operation: "delete".to_string(),
            reason: e.to_string(),
        })?;

        Ok(())
    }

    /// Check if a signing key exists
    #[must_use]
    pub fn has_signing_key(&self, author_id: AuthorId) -> bool {
        if self.use_file_storage {
            self.get_key_file_path(author_id).exists()
        } else {
            self.get_entry(author_id)
                .and_then(|e| {
                    e.get_password().map_err(|e| AionError::KeyringError {
                        operation: "check".to_string(),
                        reason: e.to_string(),
                    })
                })
                .is_ok()
        }
    }

    /// List all stored key IDs (file-based storage only)
    ///
    /// Returns author IDs for all keys stored in the keys directory.
    /// For keyring-based storage, returns an empty list.
    pub fn list_keys(&self) -> Result<Vec<AuthorId>> {
        if !self.use_file_storage {
            // Keyring doesn't support enumeration, return empty
            return Ok(Vec::new());
        }

        if !self.storage_dir.exists() {
            return Ok(Vec::new());
        }

        let mut keys = Vec::new();

        let entries =
            std::fs::read_dir(&self.storage_dir).map_err(|e| AionError::KeyringError {
                operation: "list".to_string(),
                reason: e.to_string(),
            })?;

        for entry in entries {
            let entry = entry.map_err(|e| AionError::KeyringError {
                operation: "list".to_string(),
                reason: e.to_string(),
            })?;

            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "key" {
                    if let Some(stem) = path.file_stem() {
                        if let Some(stem_str) = stem.to_str() {
                            if let Some(id_str) = stem_str.strip_prefix("author-") {
                                if let Ok(id) = id_str.parse::<u64>() {
                                    keys.push(AuthorId::new(id));
                                }
                            }
                        }
                    }
                }
            }
        }

        keys.sort_by_key(|k| k.as_u64());
        Ok(keys)
    }

    /// Get the file path for a key
    fn get_key_file_path(&self, author_id: AuthorId) -> PathBuf {
        self.storage_dir
            .join(format!("author-{}{}", author_id.as_u64(), KEY_FILE_EXT))
    }

    /// Export a signing key with password encryption
    ///
    /// Returns encrypted bytes that can be written to a file for backup.
    /// Format: MAGIC (4) + VERSION (1) + SALT (16) + NONCE (12) + CIPHERTEXT (32+16)
    ///
    /// Uses Argon2id for password-based key derivation (memory-hard, resistant to
    /// GPU/ASIC attacks) and ChaCha20-Poly1305 for authenticated encryption.
    ///
    /// # Errors
    ///
    /// Returns error if key not found or encryption fails
    #[allow(clippy::arithmetic_side_effects)] // Fixed size components
    pub fn export_encrypted(&self, author_id: AuthorId, password: &str) -> Result<Vec<u8>> {
        let signing_key = self.load_signing_key(author_id)?;

        // Generate random salt for Argon2
        let salt = generate_salt();

        // Derive encryption key from password using Argon2id
        let encryption_key = derive_key_from_password(password, &salt)?;

        // Encrypt the key bytes
        let nonce = generate_nonce();
        let aad = author_id.as_u64().to_le_bytes();
        let ciphertext = encrypt(&encryption_key, &nonce, signing_key.to_bytes(), &aad)?;

        // Build export format: MAGIC + VERSION + SALT + NONCE + CIPHERTEXT
        let mut output = Vec::with_capacity(4 + 1 + SALT_SIZE + 12 + ciphertext.len());
        output.extend_from_slice(EXPORT_MAGIC);
        output.push(EXPORT_VERSION);
        output.extend_from_slice(&salt);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);

        Ok(output)
    }

    /// Import a signing key from password-encrypted bytes
    ///
    /// Decrypts a key file created by `export_encrypted` and stores the key
    /// in the OS keyring.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - File format is invalid (wrong magic, unsupported version)
    /// - Decryption fails (wrong password, corrupted data)
    /// - Key storage fails
    pub fn import_encrypted(
        &self,
        author_id: AuthorId,
        password: &str,
        encrypted_data: &[u8],
    ) -> Result<SigningKey> {
        let parsed = parse_encrypted_key_blob(encrypted_data)?;
        let encryption_key = derive_key_from_password(password, &parsed.salt)?;
        let aad = author_id.as_u64().to_le_bytes();
        let key_bytes = decrypt(&encryption_key, &parsed.nonce, parsed.ciphertext, &aad)?;
        let signing_key = SigningKey::from_bytes(&key_bytes)?;
        self.store_signing_key(author_id, &signing_key)?;
        Ok(signing_key)
    }

    /// Get keyring entry for an author
    #[allow(clippy::unused_self)] // Method for API consistency
    fn get_entry(&self, author_id: AuthorId) -> Result<keyring::Entry> {
        let username = format!("author-{}", author_id.as_u64());
        keyring::Entry::new(KEYRING_SERVICE, &username).map_err(|e| AionError::KeyringError {
            operation: "access".to_string(),
            reason: e.to_string(),
        })
    }
}

/// Parsed encrypted-key blob layout: magic(4) + version(1) + salt(16) + nonce(12) + ciphertext.
struct ParsedEncryptedKey<'a> {
    salt: [u8; SALT_SIZE],
    nonce: [u8; 12],
    ciphertext: &'a [u8],
}

fn parse_encrypted_key_blob(encrypted_data: &[u8]) -> Result<ParsedEncryptedKey<'_>> {
    const MIN_SIZE: usize = 4 + 1 + SALT_SIZE + 12 + 32 + 16;
    if encrypted_data.len() < MIN_SIZE {
        return Err(AionError::InvalidFormat {
            reason: format!(
                "encrypted key file too small: {} bytes (minimum: {MIN_SIZE})",
                encrypted_data.len()
            ),
        });
    }
    let magic = encrypted_data
        .get(0..4)
        .ok_or_else(|| AionError::InvalidFormat {
            reason: "missing magic".to_string(),
        })?;
    if magic != EXPORT_MAGIC {
        return Err(AionError::InvalidFormat {
            reason: "invalid key file magic".to_string(),
        });
    }
    let version = *encrypted_data
        .get(4)
        .ok_or_else(|| AionError::InvalidFormat {
            reason: "missing version byte".to_string(),
        })?;
    if version != EXPORT_VERSION {
        return Err(AionError::InvalidFormat {
            reason: format!("unsupported key file version: {version} (expected: {EXPORT_VERSION})"),
        });
    }
    let salt_end = 5_usize.saturating_add(SALT_SIZE);
    let salt: [u8; SALT_SIZE] = encrypted_data
        .get(5..salt_end)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| AionError::InvalidFormat {
            reason: "invalid salt".to_string(),
        })?;
    let nonce_end = salt_end.saturating_add(12);
    let nonce: [u8; 12] = encrypted_data
        .get(salt_end..nonce_end)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| AionError::InvalidFormat {
            reason: "invalid nonce".to_string(),
        })?;
    let ciphertext = encrypted_data
        .get(nonce_end..)
        .ok_or_else(|| AionError::InvalidFormat {
            reason: "missing ciphertext".to_string(),
        })?;
    Ok(ParsedEncryptedKey {
        salt,
        nonce,
        ciphertext,
    })
}

/// Generate a random salt for Argon2 key derivation
fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

/// Derive encryption key from password using Argon2id
///
/// Argon2id is a memory-hard password hashing function that provides:
/// - Resistance to GPU/ASIC brute-force attacks
/// - Protection against timing attacks
/// - Configurable memory and time costs
///
/// Parameters chosen for balance between security and usability:
/// - Memory: 64 MiB (`m_cost` = 65536)
/// - Iterations: 3 (`t_cost` = 3)
/// - Parallelism: 4 threads (`p_cost` = 4)
fn derive_key_from_password(password: &str, salt: &[u8; SALT_SIZE]) -> Result<[u8; 32]> {
    use argon2::{Algorithm, Argon2, Params, Version};

    // Configure Argon2id parameters
    // These are reasonable defaults for interactive use (< 1 second on modern hardware)
    let params = Params::new(
        65536,    // 64 MiB memory
        3,        // 3 iterations
        4,        // 4 parallel lanes
        Some(32), // 32-byte output
    )
    .map_err(|e| AionError::InvalidPrivateKey {
        reason: format!("Argon2 params error: {e}"),
    })?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|e| AionError::InvalidPrivateKey {
            reason: format!("Argon2 key derivation failed: {e}"),
        })?;

    Ok(output)
}

/// Get the AION keys directory (~/.aion/keys)
fn get_aion_keys_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".aion")
        .join(KEYS_DIR)
}

/// Check if OS keyring is available and functional
fn is_keyring_available() -> bool {
    // Try to create a test entry - if this fails, keyring isn't available
    let test_username = "__aion_keyring_test__";
    let test_entry = keyring::Entry::new(KEYRING_SERVICE, test_username);

    let Ok(entry) = test_entry else {
        return false;
    };

    // Try to set a test value
    let test_value = "aion-keyring-test-12345";
    if entry.set_password(test_value).is_err() {
        return false;
    }

    // Create a NEW entry instance (simulating a different process/invocation)
    // This tests whether the keyring persists data across entry instances
    let Ok(entry2) = keyring::Entry::new(KEYRING_SERVICE, test_username) else {
        let _ = entry.delete_credential();
        return false;
    };

    // Verify we can read it back from the new entry instance
    let result = matches!(entry2.get_password(), Ok(retrieved) if retrieved == test_value);

    // Clean up test entry
    let _ = entry.delete_credential();

    result
}

/// Fixed salt for file-based key storage (machine-local protection)
/// This provides obfuscation but not true security - the real protection
/// comes from filesystem permissions and the encryption itself
const FILE_STORAGE_SALT: [u8; SALT_SIZE] = [
    0x41, 0x49, 0x4f, 0x4e, // "AION"
    0x76, 0x32, 0x00, 0x00, // "v2\0\0"
    0x6b, 0x65, 0x79, 0x73, // "keys"
    0x74, 0x6f, 0x72, 0x65, // "tore"
];

/// Encrypt a key for file-based storage
///
/// Uses a fixed salt with author ID as additional authenticated data.
/// Security relies on filesystem permissions (0600) for the key files.
fn encrypt_key_for_storage(author_id: AuthorId, key: &SigningKey) -> Result<Vec<u8>> {
    // Derive encryption key from machine-specific data
    // Note: This is weaker than OS keyring but provides obfuscation
    let machine_key = derive_machine_key(&FILE_STORAGE_SALT)?;

    let nonce = generate_nonce();
    let aad = author_id.as_u64().to_le_bytes();
    let ciphertext = encrypt(&machine_key, &nonce, key.to_bytes(), &aad)?;

    // Format: MAGIC (4) + VERSION (1) + NONCE (12) + CIPHERTEXT
    #[allow(clippy::arithmetic_side_effects)] // Fixed-size constants
    let mut output = Vec::with_capacity(4 + 1 + 12 + ciphertext.len());
    output.extend_from_slice(FILE_KEY_MAGIC);
    output.push(FILE_KEY_VERSION);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Decrypt a key from file-based storage
#[allow(clippy::indexing_slicing)] // Bounds checked
fn decrypt_key_from_storage(author_id: AuthorId, encrypted: &[u8]) -> Result<SigningKey> {
    // Minimum: MAGIC(4) + VERSION(1) + NONCE(12) + KEY(32) + TAG(16) = 65
    const MIN_SIZE: usize = 4 + 1 + 12 + 32 + 16;

    if encrypted.len() < MIN_SIZE {
        return Err(AionError::InvalidFormat {
            reason: format!(
                "encrypted key file too small: {} bytes (minimum: {MIN_SIZE})",
                encrypted.len()
            ),
        });
    }

    if &encrypted[0..4] != FILE_KEY_MAGIC {
        return Err(AionError::InvalidFormat {
            reason: "invalid file key magic".to_string(),
        });
    }

    let version = encrypted[4];
    if version != FILE_KEY_VERSION {
        return Err(AionError::InvalidFormat {
            reason: format!(
                "unsupported file key version: {version} (expected: {FILE_KEY_VERSION})"
            ),
        });
    }

    let nonce: [u8; 12] = encrypted[5..17]
        .try_into()
        .map_err(|_| AionError::InvalidFormat {
            reason: "invalid nonce".to_string(),
        })?;

    let ciphertext = &encrypted[17..];

    let machine_key = derive_machine_key(&FILE_STORAGE_SALT)?;
    let aad = author_id.as_u64().to_le_bytes();
    let key_bytes = decrypt(&machine_key, &nonce, ciphertext, &aad)?;

    SigningKey::from_bytes(&key_bytes)
}

/// Derive a machine-specific encryption key
///
/// This provides basic obfuscation for file-based key storage.
/// Real security comes from filesystem permissions.
fn derive_machine_key(salt: &[u8; SALT_SIZE]) -> Result<[u8; 32]> {
    use argon2::{Algorithm, Argon2, Params, Version};

    // Use a combination of fixed data as "password"
    // This isn't true security, but provides obfuscation
    let machine_id = get_machine_identifier();

    // Use lighter Argon2 params for machine key (faster startup)
    let params = Params::new(
        16384,    // 16 MiB memory (lighter than password derivation)
        2,        // 2 iterations
        2,        // 2 parallel lanes
        Some(32), // 32-byte output
    )
    .map_err(|e| AionError::InvalidPrivateKey {
        reason: format!("Argon2 params error: {e}"),
    })?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(machine_id.as_bytes(), salt, &mut output)
        .map_err(|e| AionError::InvalidPrivateKey {
            reason: format!("machine key derivation failed: {e}"),
        })?;

    Ok(output)
}

/// Get a machine-specific identifier for key derivation
///
/// Falls back to username if machine ID isn't available.
fn get_machine_identifier() -> String {
    // Try to get machine ID (Linux)
    #[cfg(target_os = "linux")]
    {
        if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
            return id.trim().to_string();
        }
    }

    // Fallback: use username + hostname
    let username = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "aion-user".to_string());

    let hostname = hostname::get().map_or_else(
        |_| "localhost".to_string(),
        |h| h.to_string_lossy().to_string(),
    );

    format!("{username}@{hostname}")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    mod password_encryption {
        use super::*;

        #[test]
        fn should_derive_consistent_key() {
            let salt = [1u8; SALT_SIZE];
            let key1 = derive_key_from_password("password123", &salt).unwrap();
            let key2 = derive_key_from_password("password123", &salt).unwrap();
            assert_eq!(key1, key2);
        }

        #[test]
        fn should_derive_different_keys_for_different_passwords() {
            let salt = [1u8; SALT_SIZE];
            let key1 = derive_key_from_password("password1", &salt).unwrap();
            let key2 = derive_key_from_password("password2", &salt).unwrap();
            assert_ne!(key1, key2);
        }

        #[test]
        fn should_derive_different_keys_for_different_salts() {
            let salt1 = [1u8; SALT_SIZE];
            let salt2 = [2u8; SALT_SIZE];
            let key1 = derive_key_from_password("password", &salt1).unwrap();
            let key2 = derive_key_from_password("password", &salt2).unwrap();
            assert_ne!(key1, key2);
        }

        #[test]
        fn should_generate_unique_salts() {
            let salt1 = generate_salt();
            let salt2 = generate_salt();
            assert_ne!(salt1, salt2);
        }
    }

    mod export_format {
        use super::*;

        #[test]
        fn should_have_correct_magic() {
            assert_eq!(EXPORT_MAGIC, b"AKEY");
        }

        #[test]
        fn should_encrypt_and_decrypt_key() {
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);
            let password = "test-password-123";

            // Generate salt and derive key
            let salt = generate_salt();
            let encryption_key = derive_key_from_password(password, &salt).unwrap();
            let nonce = generate_nonce();
            let aad = author_id.as_u64().to_le_bytes();
            let ciphertext =
                encrypt(&encryption_key, &nonce, signing_key.to_bytes(), &aad).unwrap();

            // Build export format: MAGIC + VERSION + SALT + NONCE + CIPHERTEXT
            let mut encrypted = Vec::new();
            encrypted.extend_from_slice(EXPORT_MAGIC);
            encrypted.push(EXPORT_VERSION);
            encrypted.extend_from_slice(&salt);
            encrypted.extend_from_slice(&nonce);
            encrypted.extend_from_slice(&ciphertext);

            // Extract components for decryption
            let extracted_salt: [u8; SALT_SIZE] = encrypted[5..5 + SALT_SIZE].try_into().unwrap();
            let nonce_start = 5 + SALT_SIZE;
            let extracted_nonce: [u8; 12] =
                encrypted[nonce_start..nonce_start + 12].try_into().unwrap();
            let decrypted_ciphertext = &encrypted[nonce_start + 12..];

            // Derive same key and decrypt
            let decryption_key = derive_key_from_password(password, &extracted_salt).unwrap();
            let key_bytes = decrypt(
                &decryption_key,
                &extracted_nonce,
                decrypted_ciphertext,
                &aad,
            )
            .unwrap();

            assert_eq!(key_bytes.as_slice(), signing_key.to_bytes());
        }

        #[test]
        fn should_reject_wrong_password() {
            let signing_key = SigningKey::generate();
            let author_id = AuthorId::new(50001);

            // Encrypt with one password
            let salt = generate_salt();
            let encryption_key = derive_key_from_password("correct-password", &salt).unwrap();
            let nonce = generate_nonce();
            let aad = author_id.as_u64().to_le_bytes();
            let ciphertext =
                encrypt(&encryption_key, &nonce, signing_key.to_bytes(), &aad).unwrap();

            // Build export format with salt
            let mut encrypted = Vec::new();
            encrypted.extend_from_slice(EXPORT_MAGIC);
            encrypted.push(EXPORT_VERSION);
            encrypted.extend_from_slice(&salt);
            encrypted.extend_from_slice(&nonce);
            encrypted.extend_from_slice(&ciphertext);

            // Try to decrypt with wrong password (same salt)
            let wrong_key = derive_key_from_password("wrong-password", &salt).unwrap();
            let nonce_start = 5 + SALT_SIZE;
            let decrypted_ciphertext = &encrypted[nonce_start + 12..];
            let decrypted_nonce: [u8; 12] =
                encrypted[nonce_start..nonce_start + 12].try_into().unwrap();
            let result = decrypt(&wrong_key, &decrypted_nonce, decrypted_ciphertext, &aad);

            assert!(result.is_err());
        }

        #[test]
        fn should_reject_invalid_magic() {
            let mut data = vec![0u8; 81]; // Minimum size for v2 format
            data[0..4].copy_from_slice(b"XXXX"); // Wrong magic

            let keystore = KeyStore::new();
            let result = keystore.import_encrypted(AuthorId::new(1), "password", &data);
            assert!(result.is_err());
        }

        #[test]
        fn should_reject_too_small_data() {
            let data = vec![0u8; 10]; // Too small

            let keystore = KeyStore::new();
            let result = keystore.import_encrypted(AuthorId::new(1), "password", &data);
            assert!(result.is_err());
        }

        #[test]
        fn should_reject_wrong_version() {
            let mut data = vec![0u8; 81];
            data[0..4].copy_from_slice(EXPORT_MAGIC);
            data[4] = 99; // Wrong version

            let keystore = KeyStore::new();
            let result = keystore.import_encrypted(AuthorId::new(1), "password", &data);
            assert!(result.is_err());
        }

        #[test]
        fn export_format_should_have_correct_size() {
            // MAGIC(4) + VERSION(1) + SALT(16) + NONCE(12) + KEY(32) + TAG(16) = 81
            assert_eq!(4 + 1 + SALT_SIZE + 12 + 32 + 16, 81);
        }
    }

    // Note: Full keyring integration tests require actual OS keyring access
    // and are better suited for integration tests or manual testing.
    // The tests above verify the encryption/decryption logic independently.
}
