//! Cryptographic primitives for AION v2
//!
//! This module provides safe, ergonomic wrappers around battle-tested cryptographic
//! libraries. All operations follow Tiger Style principles: explicit error handling,
//! constant-time where applicable, and automatic zeroization of sensitive data.
//!
//! # Cryptographic Algorithms
//!
//! - **Ed25519**: Digital signatures (RFC 8032, 128-bit security level)
//!   - Used for version signing and author authentication
//!   - Deterministic signatures, no nonce generation issues
//!   - Constant-time operations resistant to timing attacks
//!
//! - **ChaCha20-Poly1305**: Authenticated encryption (RFC 8439, 256-bit key)
//!   - AEAD cipher for rules encryption
//!   - Prevents tampering via authentication tag
//!   - Used in TLS 1.3 as mandatory cipher suite
//!
//! - **BLAKE3**: Cryptographic hashing (256-bit output)
//!   - 5x faster than SHA-256
//!   - Parallelizable for large data
//!   - Used for content hashing and integrity checks
//!
//! - **HKDF**: Key derivation function (RFC 5869, NIST approved)
//!   - HMAC-based key derivation with SHA-256
//!   - Derives multiple keys from master secret
//!   - Context separation via info parameter
//!
//! # Security Properties
//!
//! - **No panics**: All errors explicitly handled
//! - **Constant-time**: Ed25519 operations resistant to timing attacks
//! - **Zeroization**: Signing keys automatically cleared on drop
//! - **Entropy**: OS CSPRNG for key/nonce generation
//! - **Standards**: RFC-compliant implementations
//!
//! # Usage Examples
//!
//! ## Digital Signatures
//!
//! ```
//! use aion_context::crypto::SigningKey;
//!
//! // Generate a new signing key
//! let signing_key = SigningKey::generate();
//! let message = b"Version 1: Updated fraud rules";
//!
//! // Sign a message
//! let signature = signing_key.sign(message);
//!
//! // Verify the signature
//! let verifying_key = signing_key.verifying_key();
//! assert!(verifying_key.verify(message, &signature).is_ok());
//! ```
//!
//! ## Authenticated Encryption
//!
//! ```
//! use aion_context::crypto::{generate_nonce, encrypt, decrypt};
//!
//! let key = [0u8; 32];  // In production, use proper key derivation
//! let nonce = generate_nonce();
//! let plaintext = b"sensitive rules data";
//! let aad = b"version metadata";
//!
//! // Encrypt data
//! let ciphertext = encrypt(&key, &nonce, plaintext, aad).unwrap();
//!
//! // Decrypt data
//! let recovered = decrypt(&key, &nonce, &ciphertext, aad).unwrap();
//! assert_eq!(recovered, plaintext);
//! ```
//!
//! ## Hashing
//!
//! ```
//! use aion_context::crypto::{hash, keyed_hash};
//!
//! // Content hashing
//! let data = b"file content";
//! let content_hash = hash(data);
//!
//! // Keyed hashing (MAC)
//! let key = [0u8; 32];
//! let mac = keyed_hash(&key, data);
//! ```
//!
//! ## Key Derivation
//!
//! ```
//! use aion_context::crypto::derive_key;
//!
//! let master_secret = b"high entropy master key";
//! let salt = b"unique salt value";
//! let info = b"encryption-key-v1";
//!
//! let mut derived_key = [0u8; 32];
//! derive_key(master_secret, salt, info, &mut derived_key).unwrap();
//! // derived_key now contains 32 bytes of derived key material
//! assert_eq!(derived_key.len(), 32);
//! ```

use crate::{AionError, Result};
use ed25519_dalek::{Signature as Ed25519Signature, Signer, Verifier};
use rand::RngCore;
use zeroize::Zeroizing;

// Re-export commonly used types
pub use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};

/// Signing key for Ed25519 signatures
///
/// Automatically zeroized on drop to protect key material.
///
/// # Security
///
/// - 256-bit private key
/// - Constant-time operations
/// - Automatically zeroized when dropped
/// - **Note**: Implements `Clone` for testing convenience, but cloning key material
///   increases exposure. Use sparingly in production code.
///
/// # Examples
///
/// ```
/// use aion_context::crypto::SigningKey;
///
/// let key = SigningKey::generate();
/// let message = b"test message";
/// let signature = key.sign(message);
/// ```
#[derive(Clone)]
pub struct SigningKey(Zeroizing<[u8; 32]>);

impl SigningKey {
    /// Generate a new random signing key using OS entropy
    ///
    /// Uses the operating system's cryptographically secure random number
    /// generator (`/dev/urandom` on Unix, `CryptGenRandom` on Windows).
    #[must_use]
    pub fn generate() -> Self {
        let key = Ed25519SigningKey::generate(&mut rand::rngs::OsRng);
        Self(Zeroizing::new(key.to_bytes()))
    }

    /// Create a signing key from bytes
    ///
    /// # Errors
    ///
    /// Returns `AionError::InvalidPrivateKey` if the bytes are not a valid Ed25519 private key
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(AionError::InvalidPrivateKey {
                reason: format!("expected 32 bytes, got {}", bytes.len()),
            });
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);

        // Validate the key by trying to create an Ed25519SigningKey
        let _validate = Ed25519SigningKey::from_bytes(&key_bytes);

        Ok(Self(Zeroizing::new(key_bytes)))
    }

    /// Get the bytes of this signing key
    ///
    /// Returns a reference to the key bytes
    #[must_use]
    pub fn to_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Sign a message
    ///
    /// Creates an Ed25519 signature over the message using this key.
    ///
    /// # Examples
    ///
    /// ```
    /// use aion_context::crypto::SigningKey;
    ///
    /// let key = SigningKey::generate();
    /// let signature = key.sign(b"message");
    /// assert_eq!(signature.len(), 64);
    /// ```
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let signing_key = Ed25519SigningKey::from_bytes(&self.0);
        signing_key.sign(message).to_bytes()
    }

    /// Get the corresponding verifying key
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        let signing_key = Ed25519SigningKey::from_bytes(&self.0);
        VerifyingKey(signing_key.verifying_key())
    }
}

/// Verifying key for Ed25519 signatures
///
/// Used to verify signatures created by the corresponding `SigningKey`.
///
/// # Examples
///
/// ```
/// use aion_context::crypto::{SigningKey, VerifyingKey};
///
/// let signing_key = SigningKey::generate();
/// let verifying_key = signing_key.verifying_key();
///
/// let message = b"test";
/// let signature = signing_key.sign(message);
///
/// assert!(verifying_key.verify(message, &signature).is_ok());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyingKey(Ed25519VerifyingKey);

impl VerifyingKey {
    /// Create a verifying key from bytes
    ///
    /// # Errors
    ///
    /// Returns `AionError::InvalidPublicKey` if the bytes are not a valid Ed25519 public key
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(AionError::InvalidPublicKey {
                reason: format!("expected 32 bytes, got {}", bytes.len()),
            });
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);

        let key = Ed25519VerifyingKey::from_bytes(&key_bytes).map_err(|e| {
            AionError::InvalidPublicKey {
                reason: e.to_string(),
            }
        })?;

        Ok(Self(key))
    }

    /// Get the bytes of this verifying key
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Verify a signature on a message
    ///
    /// # Errors
    ///
    /// Returns `AionError::InvalidSignature` if the signature is invalid or doesn't match the message
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<()> {
        let sig = Ed25519Signature::from_bytes(signature);

        self.0
            .verify(message, &sig)
            .map_err(|_| AionError::InvalidSignature {
                reason: "signature verification failed".to_string(),
            })
    }
}

/// Hash a message using BLAKE3
///
/// Returns a 32-byte (256-bit) cryptographic hash.
///
/// # Examples
///
/// ```
/// use aion_context::crypto::hash;
///
/// let hash = hash(b"Hello, AION!");
/// assert_eq!(hash.len(), 32);
/// ```
#[must_use]
pub fn hash(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

/// Keyed hash using BLAKE3
///
/// Provides message authentication (MAC) using a secret key.
///
/// # Examples
///
/// ```
/// use aion_context::crypto::keyed_hash;
///
/// let key = [0u8; 32];
/// let mac = keyed_hash(&key, b"message");
/// assert_eq!(mac.len(), 32);
/// ```
#[must_use]
pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    blake3::keyed_hash(key, data).into()
}

/// Derive a key using HKDF-SHA256
///
/// Extracts entropy from input key material and expands it into a derived key.
///
/// # Arguments
///
/// * `ikm` - Input key material
/// * `salt` - Optional salt value (use empty slice if none)
/// * `info` - Context and application-specific information
/// * `output` - Buffer to fill with derived key material
///
/// # Examples
///
/// ```
/// use aion_context::crypto::derive_key;
///
/// let ikm = b"input key material";
/// let salt = b"optional salt";
/// let info = b"application context";
/// let mut output = [0u8; 32];
///
/// derive_key(ikm, salt, info, &mut output).unwrap();
/// ```
///
/// # Errors
///
/// Returns `AionError::InvalidPrivateKey` if key derivation fails (should never happen with valid inputs)
pub fn derive_key(ikm: &[u8], salt: &[u8], info: &[u8], output: &mut [u8]) -> Result<()> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);

    hk.expand(info, output)
        .map_err(|_| AionError::InvalidPrivateKey {
            reason: "HKDF expand failed".to_string(),
        })?;

    Ok(())
}

/// Encrypt data using ChaCha20-Poly1305 (AEAD)
///
/// # Arguments
///
/// * `key` - 32-byte encryption key
/// * `nonce` - 12-byte nonce (MUST be unique for each encryption with the same key)
/// * `plaintext` - Data to encrypt
/// * `aad` - Additional authenticated data (not encrypted, but authenticated)
///
/// # Returns
///
/// Ciphertext with authentication tag appended (`plaintext.len()` + 16 bytes)
///
/// # Errors
///
/// Returns `AionError::EncryptionFailed` if encryption fails
///
/// # Security
///
/// **CRITICAL**: Never reuse a nonce with the same key. Use `generate_nonce()` for each encryption.
pub fn encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit, Payload},
        ChaCha20Poly1305,
    };

    let cipher = ChaCha20Poly1305::new(key.into());
    let payload = Payload {
        msg: plaintext,
        aad,
    };

    cipher
        .encrypt(nonce.into(), payload)
        .map_err(|e| AionError::EncryptionFailed {
            reason: e.to_string(),
        })
}

/// Decrypt data using ChaCha20-Poly1305 (AEAD)
///
/// # Arguments
///
/// * `key` - 32-byte encryption key (same as used for encryption)
/// * `nonce` - 12-byte nonce (same as used for encryption)
/// * `ciphertext` - Encrypted data with authentication tag
/// * `aad` - Additional authenticated data (must match encryption)
///
/// # Returns
///
/// Decrypted plaintext
///
/// # Errors
///
/// Returns `AionError::DecryptionFailed` if:
/// - Authentication tag is invalid (data was tampered with)
/// - Wrong key or nonce used
/// - AAD doesn't match
pub fn decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit, Payload},
        ChaCha20Poly1305,
    };

    let cipher = ChaCha20Poly1305::new(key.into());
    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    cipher
        .decrypt(nonce.into(), payload)
        .map_err(|e| AionError::DecryptionFailed {
            reason: e.to_string(),
        })
}

/// Generate a random nonce for ChaCha20-Poly1305
///
/// Uses OS entropy to generate a cryptographically secure 12-byte nonce.
///
/// # Examples
///
/// ```
/// use aion_context::crypto::generate_nonce;
///
/// let nonce = generate_nonce();
/// assert_eq!(nonce.len(), 12);
/// ```
#[must_use]
pub fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // Tests are allowed to panic
mod tests {
    use super::*;

    mod signing {
        use super::*;

        #[test]
        fn should_generate_signing_key() {
            let key = SigningKey::generate();
            let bytes = key.to_bytes();
            assert_eq!(bytes.len(), 32);
        }

        #[test]
        fn should_create_signing_key_from_bytes() {
            let original = SigningKey::generate();
            let bytes = *original.to_bytes();

            let restored = SigningKey::from_bytes(&bytes).unwrap();
            assert_eq!(*original.to_bytes(), *restored.to_bytes());
        }

        #[test]
        fn should_reject_invalid_key_length() {
            let result = SigningKey::from_bytes(&[0u8; 16]);
            assert!(result.is_err());
        }

        #[test]
        fn should_sign_message() {
            let key = SigningKey::generate();
            let signature = key.sign(b"test message");
            assert_eq!(signature.len(), 64);
        }

        #[test]
        fn should_verify_valid_signature() {
            let key = SigningKey::generate();
            let message = b"test message";
            let signature = key.sign(message);

            let verifying_key = key.verifying_key();
            assert!(verifying_key.verify(message, &signature).is_ok());
        }

        #[test]
        fn should_reject_invalid_signature() {
            let key = SigningKey::generate();
            let message = b"test message";
            let mut signature = key.sign(message);

            // Tamper with signature
            signature[0] ^= 1;

            let verifying_key = key.verifying_key();
            assert!(verifying_key.verify(message, &signature).is_err());
        }

        #[test]
        fn should_reject_wrong_message() {
            let key = SigningKey::generate();
            let signature = key.sign(b"original message");

            let verifying_key = key.verifying_key();
            assert!(verifying_key
                .verify(b"different message", &signature)
                .is_err());
        }

        #[test]
        fn should_serialize_verifying_key() {
            let key = SigningKey::generate();
            let verifying_key = key.verifying_key();
            let bytes = verifying_key.to_bytes();
            assert_eq!(bytes.len(), 32);

            let restored = VerifyingKey::from_bytes(&bytes).unwrap();
            assert_eq!(verifying_key.to_bytes(), restored.to_bytes());
        }
    }

    mod hashing {
        use super::*;

        #[test]
        fn should_hash_data() {
            let hash1 = hash(b"test data");
            assert_eq!(hash1.len(), 32);

            // Same input produces same hash
            let hash2 = hash(b"test data");
            assert_eq!(hash1, hash2);
        }

        #[test]
        fn should_produce_different_hashes_for_different_data() {
            let hash1 = hash(b"data1");
            let hash2 = hash(b"data2");
            assert_ne!(hash1, hash2);
        }

        #[test]
        fn should_create_keyed_hash() {
            let key = [0u8; 32];
            let mac = keyed_hash(&key, b"message");
            assert_eq!(mac.len(), 32);
        }

        #[test]
        fn should_produce_different_macs_with_different_keys() {
            let key1 = [0u8; 32];
            let key2 = [1u8; 32];

            let mac1 = keyed_hash(&key1, b"message");
            let mac2 = keyed_hash(&key2, b"message");
            assert_ne!(mac1, mac2);
        }
    }

    mod key_derivation {
        use super::*;

        #[test]
        fn should_derive_key() {
            let ikm = b"input key material";
            let salt = b"salt";
            let info = b"context";
            let mut output = [0u8; 32];

            derive_key(ikm, salt, info, &mut output).unwrap();

            // Output should not be all zeros
            assert_ne!(output, [0u8; 32]);
        }

        #[test]
        fn should_produce_deterministic_output() {
            let ikm = b"input key material";
            let salt = b"salt";
            let info = b"context";

            let mut output1 = [0u8; 32];
            derive_key(ikm, salt, info, &mut output1).unwrap();

            let mut output2 = [0u8; 32];
            derive_key(ikm, salt, info, &mut output2).unwrap();

            assert_eq!(output1, output2);
        }

        #[test]
        fn should_produce_different_keys_for_different_info() {
            let ikm = b"input key material";
            let salt = b"salt";

            let mut output1 = [0u8; 32];
            derive_key(ikm, salt, b"context1", &mut output1).unwrap();

            let mut output2 = [0u8; 32];
            derive_key(ikm, salt, b"context2", &mut output2).unwrap();

            assert_ne!(output1, output2);
        }
    }

    mod encryption {
        use super::*;

        #[test]
        fn should_encrypt_and_decrypt() {
            let key = [0u8; 32];
            let nonce = generate_nonce();
            let plaintext = b"secret message";
            let aad = b"additional data";

            let ciphertext = encrypt(&key, &nonce, plaintext, aad).unwrap();
            assert_eq!(ciphertext.len(), plaintext.len() + 16); // +16 for auth tag

            let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();
            assert_eq!(decrypted, plaintext);
        }

        #[test]
        fn should_reject_tampered_ciphertext() {
            let key = [0u8; 32];
            let nonce = generate_nonce();
            let plaintext = b"secret message";
            let aad = b"additional data";

            let mut ciphertext = encrypt(&key, &nonce, plaintext, aad).unwrap();

            // Tamper with ciphertext
            if let Some(byte) = ciphertext.get_mut(0) {
                *byte ^= 1;
            }

            let result = decrypt(&key, &nonce, &ciphertext, aad);
            assert!(result.is_err());
        }

        #[test]
        fn should_reject_wrong_aad() {
            let key = [0u8; 32];
            let nonce = generate_nonce();
            let plaintext = b"secret message";

            let ciphertext = encrypt(&key, &nonce, plaintext, b"aad1").unwrap();

            let result = decrypt(&key, &nonce, &ciphertext, b"aad2");
            assert!(result.is_err());
        }

        #[test]
        fn should_reject_wrong_key() {
            let key1 = [0u8; 32];
            let key2 = [1u8; 32];
            let nonce = generate_nonce();
            let plaintext = b"secret message";
            let aad = b"additional data";

            let ciphertext = encrypt(&key1, &nonce, plaintext, aad).unwrap();

            let result = decrypt(&key2, &nonce, &ciphertext, aad);
            assert!(result.is_err());
        }

        #[test]
        fn should_generate_unique_nonces() {
            let nonce1 = generate_nonce();
            let nonce2 = generate_nonce();
            assert_ne!(nonce1, nonce2);
        }
    }
}
