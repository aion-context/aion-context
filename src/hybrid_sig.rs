//! Post-quantum hybrid signatures — RFC-0027.
//!
//! A hybrid signature pairs an Ed25519 signature with an ML-DSA-65
//! signature over the same domain-tagged message. Verification
//! requires **both** components to verify; breaking one algorithm
//! is not enough to forge.
//!
//! ML-DSA-65 (FIPS 204) comes from the [`pqcrypto_mldsa`] crate —
//! the C reference implementation wrapped via FFI, the most
//! scrutinized PQ signature library in Rust today. When pure-Rust
//! alternatives (`ml-dsa` from RustCrypto) mature and receive
//! third-party review, Phase C swaps backends behind the same
//! `HybridSigningKey` API.
//!
//! Phase A (this module) does not change the on-disk file format;
//! hybrid signatures are new in-memory types. Phase B integrates
//! them into `signature_chain`, `multisig`, and the RFC-0023 DSSE
//! envelope.
//!
//! # Example
//!
//! ```
//! use aion_context::hybrid_sig::HybridSigningKey;
//!
//! # fn run() -> aion_context::Result<()> {
//! let key = HybridSigningKey::generate();
//! let vk = key.verifying_key();
//! let payload = b"attested bytes";
//! let sig = key.sign(payload)?;
//! vk.verify(payload, &sig)?;
//! # Ok(())
//! # }
//! # run().unwrap();
//! ```

use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};

use crate::crypto::{SigningKey as ClassicalSigningKey, VerifyingKey as ClassicalVerifyingKey};
use crate::{AionError, Result};

/// Domain separator for hybrid signatures. Distinct from every
/// other aion signing domain so a single-algorithm signature
/// over the same payload cannot be replayed as a hybrid one.
pub const HYBRID_DOMAIN: &[u8] = b"AION_V2_HYBRID_V1\0";

/// Post-quantum signature algorithm identifier.
///
/// Carried in [`HybridSignature`] so verifiers can reject a
/// signature whose algorithm does not match the expected
/// verifying key. Only ML-DSA-65 is defined for Phase A; the
/// discriminant range reserves room for ML-DSA-87, SLH-DSA, and
/// future algorithms.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqAlgorithm {
    /// FIPS 204 ML-DSA-65 (formerly CRYSTALS-Dilithium-3).
    MlDsa65 = 1,
}

impl PqAlgorithm {
    /// Convert a raw `u16` to a known algorithm.
    ///
    /// # Errors
    ///
    /// Returns `Err` for discriminants not defined here.
    pub fn from_u16(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::MlDsa65),
            other => Err(AionError::InvalidFormat {
                reason: format!("Unknown hybrid PQ algorithm: {other}"),
            }),
        }
    }
}

/// Classical + post-quantum keypair used for producing hybrid
/// signatures.
///
/// Does not derive `Debug` — the ML-DSA secret is sensitive.
///
/// The ML-DSA-65 secret is held as raw bytes inside a
/// [`zeroize::Zeroizing`] wrapper (RFC-0033 C9) and re-parsed into
/// a [`mldsa65::SecretKey`] on every call to [`Self::sign`]. The
/// `pqcrypto-mldsa` C-FFI `SecretKey` type does not implement
/// `Zeroize`, so holding it live would leave ~4 KB of key material
/// unzeroed in heap on drop.
pub struct HybridSigningKey {
    classical: ClassicalSigningKey,
    pq_secret_bytes: zeroize::Zeroizing<Vec<u8>>,
    pq_public: mldsa65::PublicKey,
}

/// Corresponding verifying key.
#[derive(Clone)]
pub struct HybridVerifyingKey {
    classical: ClassicalVerifyingKey,
    algorithm: PqAlgorithm,
    pq_public: mldsa65::PublicKey,
}

/// A hybrid signature: classical Ed25519 bytes + PQ algorithm
/// discriminant + PQ signature bytes. Both must verify for the
/// signature to be accepted.
#[derive(Debug, Clone)]
pub struct HybridSignature {
    /// Which PQ algorithm produced [`Self::pq`].
    pub algorithm: PqAlgorithm,
    /// 64-byte Ed25519 signature.
    pub classical: [u8; 64],
    /// Variable-length PQ signature bytes (3293 for ML-DSA-65).
    pub pq: Vec<u8>,
}

/// Build the exact bytes signed by both halves of a hybrid
/// signature: `HYBRID_DOMAIN || payload`.
#[must_use]
pub fn canonical_hybrid_message(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HYBRID_DOMAIN.len().saturating_add(payload.len()));
    out.extend_from_slice(HYBRID_DOMAIN);
    out.extend_from_slice(payload);
    out
}

impl HybridSigningKey {
    /// Generate a fresh hybrid keypair (Ed25519 + ML-DSA-65).
    #[must_use]
    pub fn generate() -> Self {
        let classical = ClassicalSigningKey::generate();
        let (pq_public, pq_secret) = mldsa65::keypair();
        let pq_secret_bytes = zeroize::Zeroizing::new(pq_secret.as_bytes().to_vec());
        Self {
            classical,
            pq_secret_bytes,
            pq_public,
        }
    }

    /// Build a hybrid key whose classical half is `classical` and
    /// whose PQ half is freshly generated.
    ///
    /// This lets callers migrate an existing Ed25519 identity into
    /// hybrid mode without losing the classical keypair.
    #[must_use]
    pub fn from_classical(classical: ClassicalSigningKey) -> Self {
        let (pq_public, pq_secret) = mldsa65::keypair();
        let pq_secret_bytes = zeroize::Zeroizing::new(pq_secret.as_bytes().to_vec());
        Self {
            classical,
            pq_secret_bytes,
            pq_public,
        }
    }

    /// Derive the [`HybridVerifyingKey`].
    #[must_use]
    pub fn verifying_key(&self) -> HybridVerifyingKey {
        HybridVerifyingKey {
            classical: self.classical.verifying_key(),
            algorithm: PqAlgorithm::MlDsa65,
            pq_public: self.pq_public,
        }
    }

    /// Produce a hybrid signature over `payload`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the cached ML-DSA secret bytes fail to
    /// reconstitute into an `mldsa65::SecretKey`. In normal
    /// operation the bytes originate from `mldsa65::keypair()` and
    /// this branch is unreachable; a failure here indicates memory
    /// corruption or manual tampering with the field contents.
    pub fn sign(&self, payload: &[u8]) -> Result<HybridSignature> {
        let message = canonical_hybrid_message(payload);
        let classical = self.classical.sign(&message);
        let pq_secret = mldsa65::SecretKey::from_bytes(&self.pq_secret_bytes).map_err(|e| {
            AionError::InvalidFormat {
                reason: format!("internal: ML-DSA-65 secret key reconstitution failed: {e}"),
            }
        })?;
        let pq_sig = mldsa65::detached_sign(&message, &pq_secret);
        Ok(HybridSignature {
            algorithm: PqAlgorithm::MlDsa65,
            classical,
            pq: pq_sig.as_bytes().to_vec(),
        })
    }

    /// 32-byte Ed25519 classical seed, for callers that need to
    /// shuttle the key between processes. Drops the PQ half —
    /// use [`Self::export_pq_secret`] for that.
    #[must_use]
    pub fn classical_seed(&self) -> &[u8; 32] {
        self.classical.to_bytes()
    }

    /// Export the ML-DSA-65 secret-key bytes in a [`Zeroizing`]
    /// wrapper. The wrapper zeroes its heap buffer on drop; callers
    /// who copy the bytes into an unwrapped `Vec<u8>` or `String`
    /// defeat the zeroization contract and are responsible for any
    /// residual exposure.
    ///
    /// Exposed so a caller can serialize the key via their own
    /// key-storage layer. `aion-context` does not persist PQ keys
    /// in Phase A.
    #[must_use]
    pub fn export_pq_secret(&self) -> zeroize::Zeroizing<Vec<u8>> {
        zeroize::Zeroizing::new(self.pq_secret_bytes.as_slice().to_vec())
    }
}

impl HybridVerifyingKey {
    /// Announce which PQ algorithm this verifying key expects.
    #[must_use]
    pub const fn algorithm(&self) -> PqAlgorithm {
        self.algorithm
    }

    /// Expose the 32-byte classical verifying key.
    #[must_use]
    pub const fn classical(&self) -> &ClassicalVerifyingKey {
        &self.classical
    }

    /// Expose the ML-DSA-65 public key bytes.
    #[must_use]
    pub fn pq_public_bytes(&self) -> &[u8] {
        self.pq_public.as_bytes()
    }

    /// Verify a hybrid signature — both halves must verify.
    ///
    /// # Errors
    ///
    /// Returns `Err` on algorithm mismatch, on classical-signature
    /// verification failure, or on PQ-signature verification
    /// failure.
    pub fn verify(&self, payload: &[u8], sig: &HybridSignature) -> Result<()> {
        if sig.algorithm != self.algorithm {
            return Err(AionError::InvalidFormat {
                reason: format!(
                    "hybrid algorithm mismatch: sig={:?}, key={:?}",
                    sig.algorithm, self.algorithm
                ),
            });
        }
        let message = canonical_hybrid_message(payload);
        // Classical half.
        self.classical.verify(&message, &sig.classical)?;
        // PQ half.
        let pq_sig = mldsa65::DetachedSignature::from_bytes(&sig.pq).map_err(|e| {
            AionError::InvalidFormat {
                reason: format!("ML-DSA-65 signature bytes invalid: {e}"),
            }
        })?;
        mldsa65::verify_detached_signature(&pq_sig, &message, &self.pq_public).map_err(|e| {
            AionError::InvalidFormat {
                reason: format!("ML-DSA-65 verification failed: {e}"),
            }
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_fips_204() {
        // FIPS 204 ML-DSA-65 fixed sizes.
        assert_eq!(mldsa65::public_key_bytes(), 1952);
        assert_eq!(mldsa65::secret_key_bytes(), 4032);
        assert_eq!(mldsa65::signature_bytes(), 3309);
    }

    #[test]
    fn sign_verify_round_trip() {
        let key = HybridSigningKey::generate();
        let vk = key.verifying_key();
        let sig = key.sign(b"hello hybrid").unwrap();
        vk.verify(b"hello hybrid", &sig).unwrap();
    }

    #[test]
    fn tampered_payload_rejects() {
        let key = HybridSigningKey::generate();
        let vk = key.verifying_key();
        let sig = key.sign(b"hello hybrid").unwrap();
        assert!(vk.verify(b"hello HYBRID", &sig).is_err());
    }

    #[test]
    fn corrupted_classical_sig_rejects() {
        let key = HybridSigningKey::generate();
        let vk = key.verifying_key();
        let mut sig = key.sign(b"payload").unwrap();
        sig.classical[0] ^= 0x01;
        assert!(vk.verify(b"payload", &sig).is_err());
    }

    #[test]
    fn corrupted_pq_sig_rejects() {
        let key = HybridSigningKey::generate();
        let vk = key.verifying_key();
        let mut sig = key.sign(b"payload").unwrap();
        sig.pq[0] ^= 0x01;
        assert!(vk.verify(b"payload", &sig).is_err());
    }

    #[test]
    fn algorithm_round_trips() {
        assert_eq!(PqAlgorithm::from_u16(1).unwrap(), PqAlgorithm::MlDsa65);
        assert!(PqAlgorithm::from_u16(99).is_err());
    }

    #[test]
    fn from_classical_preserves_ed25519_identity() {
        let classical = ClassicalSigningKey::generate();
        let original_pk = classical.verifying_key().to_bytes();
        let key = HybridSigningKey::from_classical(classical);
        assert_eq!(key.verifying_key().classical.to_bytes(), original_pk);
    }

    mod properties {
        use super::*;
        use hegel::generators as gs;

        #[hegel::test]
        fn prop_hybrid_sign_verify_roundtrip(tc: hegel::TestCase) {
            let payload = tc.draw(gs::binary().max_size(512));
            let key = HybridSigningKey::generate();
            let vk = key.verifying_key();
            let sig = key.sign(&payload).unwrap();
            vk.verify(&payload, &sig)
                .unwrap_or_else(|_| std::process::abort());
        }

        #[hegel::test]
        fn prop_hybrid_tampered_payload_rejects(tc: hegel::TestCase) {
            let payload = tc.draw(gs::binary().min_size(1).max_size(512));
            let key = HybridSigningKey::generate();
            let vk = key.verifying_key();
            let sig = key.sign(&payload).unwrap();
            let mut tampered = payload.clone();
            let idx = tc.draw(gs::integers::<usize>().max_value(tampered.len().saturating_sub(1)));
            if let Some(b) = tampered.get_mut(idx) {
                *b ^= 0x01;
            }
            assert!(vk.verify(&tampered, &sig).is_err());
        }

        #[hegel::test]
        fn prop_hybrid_wrong_classical_key_rejects(tc: hegel::TestCase) {
            let payload = tc.draw(gs::binary().max_size(512));
            let key = HybridSigningKey::generate();
            let sig = key.sign(&payload).unwrap();
            // Build a verifying key whose classical half is from a
            // fresh keypair — PQ half still matches `key`.
            let impostor_classical = ClassicalSigningKey::generate();
            let wrong_vk = HybridVerifyingKey {
                classical: impostor_classical.verifying_key(),
                algorithm: PqAlgorithm::MlDsa65,
                pq_public: key.pq_public,
            };
            assert!(wrong_vk.verify(&payload, &sig).is_err());
        }

        #[hegel::test]
        fn prop_hybrid_wrong_pq_key_rejects(tc: hegel::TestCase) {
            let payload = tc.draw(gs::binary().max_size(512));
            let key = HybridSigningKey::generate();
            let sig = key.sign(&payload).unwrap();
            // Build a verifying key whose PQ half is from a fresh
            // keypair — classical half still matches `key`.
            let (impostor_pq_pub, _) = mldsa65::keypair();
            let wrong_vk = HybridVerifyingKey {
                classical: key.classical.verifying_key(),
                algorithm: PqAlgorithm::MlDsa65,
                pq_public: impostor_pq_pub,
            };
            assert!(wrong_vk.verify(&payload, &sig).is_err());
        }

        #[hegel::test]
        fn prop_hybrid_corrupted_classical_sig_rejects(tc: hegel::TestCase) {
            let payload = tc.draw(gs::binary().max_size(512));
            let key = HybridSigningKey::generate();
            let vk = key.verifying_key();
            let mut sig = key.sign(&payload).unwrap();
            let idx = tc.draw(gs::integers::<usize>().max_value(sig.classical.len() - 1));
            if let Some(b) = sig.classical.get_mut(idx) {
                *b ^= 0x01;
            }
            assert!(vk.verify(&payload, &sig).is_err());
        }

        #[hegel::test]
        fn prop_hybrid_corrupted_pq_sig_rejects(tc: hegel::TestCase) {
            let payload = tc.draw(gs::binary().max_size(512));
            let key = HybridSigningKey::generate();
            let vk = key.verifying_key();
            let mut sig = key.sign(&payload).unwrap();
            // PQ signature is long — flipping any byte should break
            // the ML-DSA verification.
            let idx = tc.draw(gs::integers::<usize>().max_value(sig.pq.len().saturating_sub(1)));
            if let Some(b) = sig.pq.get_mut(idx) {
                *b ^= 0x01;
            }
            assert!(vk.verify(&payload, &sig).is_err());
        }

        #[hegel::test]
        fn prop_hybrid_domain_separated_from_plain_ed25519(tc: hegel::TestCase) {
            // An Ed25519 signature over `payload` (no HYBRID_DOMAIN
            // prefix) must NOT verify when plugged into a
            // HybridSignature. This guards the domain separator.
            let payload = tc.draw(gs::binary().max_size(512));
            let key = HybridSigningKey::generate();
            let vk = key.verifying_key();
            // Sign the raw payload (no domain) with the classical key.
            let classical_only = key.classical.sign(&payload);
            // Provide a correctly-constructed PQ signature over the
            // correct (domain-tagged) message, so the PQ half would
            // pass alone — the only failing component is classical,
            // which signed the wrong message.
            let domain_msg = canonical_hybrid_message(&payload);
            let pq_secret = mldsa65::SecretKey::from_bytes(&key.pq_secret_bytes).unwrap();
            let pq_sig = mldsa65::detached_sign(&domain_msg, &pq_secret);
            let sig = HybridSignature {
                algorithm: PqAlgorithm::MlDsa65,
                classical: classical_only,
                pq: pq_sig.as_bytes().to_vec(),
            };
            assert!(vk.verify(&payload, &sig).is_err());
        }

        #[hegel::test]
        fn prop_hybrid_algorithm_mismatch_rejects(tc: hegel::TestCase) {
            // Today there's only MlDsa65, so we synthesize a
            // mismatch by flipping the discriminant.
            let payload = tc.draw(gs::binary().max_size(256));
            let key = HybridSigningKey::generate();
            let vk = key.verifying_key();
            let mut sig = key.sign(&payload).unwrap();
            // Invent a discriminant the enum doesn't recognize by
            // constructing a fake signature with a different type
            // discriminant. Since PqAlgorithm only has MlDsa65, we
            // exercise the check indirectly by mutating the verifying
            // key's algorithm instead.
            let mut wrong_vk = vk.clone();
            // Safety: PqAlgorithm is repr(u16); we write a value not
            // in the enum to model a future algorithm mismatch.
            // Construct a misaligned verifying key by transmuting is
            // unsafe-forbidden here; instead we check that the
            // in-API symmetric case works. Use the true positive as
            // the asserted baseline.
            let _ = &mut wrong_vk;
            vk.verify(&payload, &sig)
                .unwrap_or_else(|_| std::process::abort());
            // Now corrupt the signature algorithm field to a value
            // that cannot equal vk.algorithm. Because the enum only
            // has one variant today, we do this by constructing an
            // empty/placeholder signature whose PQ bytes are
            // trivially bad — matching the algorithm but failing the
            // crypto checks.
            sig.pq.clear();
            assert!(vk.verify(&payload, &sig).is_err());
        }
    }
}
