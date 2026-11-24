// SPDX-License-Identifier: MIT OR Apache-2.0
//! Post-quantum hybrid signatures — RFC-0027.
//!
//! A hybrid signature pairs an Ed25519 signature with an ML-DSA-65
//! signature over the same domain-tagged message. Verification
//! requires **both** components to verify; breaking one algorithm
//! is not enough to forge.
//!
//! ML-DSA-65 (FIPS 204) comes from the pure-Rust `RustCrypto`
//! [`ml_dsa`] crate (RFC-0041). It replaced the `pqcrypto-mldsa`
//! C/FFI backend, whose AVX2 verifier skipped a FIPS 204 norm check
//! (RUSTSEC-2026-0586). Public keys and signatures keep the standard
//! FIPS 204 encodings, so signatures made with either backend verify
//! under the other.
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
//! let key = HybridSigningKey::generate()?;
//! let vk = key.verifying_key();
//! let payload = b"attested bytes";
//! let sig = key.sign(payload)?;
//! vk.verify(payload, &sig)?;
//! # Ok(())
//! # }
//! # run().unwrap();
//! ```

use ml_dsa::{
    ExpandedSigningKey, MlDsa65, Signature as MlDsaSignature, VerifyingKey as MlDsaVerifyingKey,
    B32,
};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{
    fill_os_entropy, SigningKey as ClassicalSigningKey, VerifyingKey as ClassicalVerifyingKey,
};
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

/// An ML-DSA-65 public key together with its 1952-byte encoding,
/// cached so [`HybridVerifyingKey::pq_public_bytes`] can lend it.
#[derive(Clone)]
struct PqPublicKey {
    key: MlDsaVerifyingKey<MlDsa65>,
    encoded: Vec<u8>,
}

impl PqPublicKey {
    fn from_key(key: MlDsaVerifyingKey<MlDsa65>) -> Self {
        let encoded = key.encode().to_vec();
        Self { key, encoded }
    }

    /// Decode a 1952-byte FIPS 204 public key. Any other length is
    /// rejected; every 1952-byte string decodes (FIPS 204 defines no
    /// further validity check on `t1`).
    #[cfg(test)]
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        use ml_dsa::EncodedVerifyingKey;
        let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(bytes).map_err(|_| {
            AionError::InvalidFormat {
                reason: format!(
                    "ML-DSA-65 public key must be 1952 bytes, got {}",
                    bytes.len()
                ),
            }
        })?;
        Ok(Self::from_key(MlDsaVerifyingKey::decode(&encoded)))
    }
}

/// Classical + post-quantum keypair used for producing hybrid
/// signatures.
///
/// Does not derive `Debug` — the ML-DSA secret is sensitive.
///
/// The ML-DSA-65 half is held as its 32-byte FIPS 204 seed and the
/// expanded signing key derived from it. Both are wiped on drop: the
/// seed by [`Zeroizing`], the expanded key by `ml-dsa`'s `zeroize`
/// feature (RFC-0041; previously RFC-0033 C9 had to re-parse the
/// secret on every signature).
pub struct HybridSigningKey {
    classical: ClassicalSigningKey,
    pq_seed: Zeroizing<[u8; 32]>,
    pq_expanded: ExpandedSigningKey<MlDsa65>,
    pq_public: PqPublicKey,
}

/// Corresponding verifying key.
#[derive(Clone)]
pub struct HybridVerifyingKey {
    classical: ClassicalVerifyingKey,
    algorithm: PqAlgorithm,
    pq_public: PqPublicKey,
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
    /// Variable-length PQ signature bytes (3309 for ML-DSA-65).
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

/// Draw a fresh 32-byte ML-DSA seed from the OS RNG (RFC-0037).
fn fresh_pq_seed() -> Result<Zeroizing<[u8; 32]>> {
    let mut seed = Zeroizing::new([0u8; 32]);
    fill_os_entropy(seed.as_mut_slice())?;
    Ok(seed)
}

impl HybridSigningKey {
    /// Generate a fresh hybrid keypair (Ed25519 + ML-DSA-65).
    ///
    /// # Errors
    ///
    /// Returns [`AionError::EntropyUnavailable`](crate::AionError::EntropyUnavailable)
    /// if the OS RNG fails (RFC-0037).
    pub fn generate() -> Result<Self> {
        let classical = ClassicalSigningKey::generate()?;
        Self::from_classical(classical)
    }

    /// Build a hybrid key whose classical half is `classical` and
    /// whose PQ half is freshly generated.
    ///
    /// This lets callers migrate an existing Ed25519 identity into
    /// hybrid mode without losing the classical keypair.
    ///
    /// # Errors
    ///
    /// Returns [`AionError::EntropyUnavailable`](crate::AionError::EntropyUnavailable)
    /// if the OS RNG fails while drawing the ML-DSA seed (RFC-0041).
    pub fn from_classical(classical: ClassicalSigningKey) -> Result<Self> {
        let seed = fresh_pq_seed()?;
        Ok(Self::from_seeds(classical, &seed))
    }

    /// Rebuild a hybrid key from a classical key and a 32-byte
    /// ML-DSA-65 seed, as returned by [`Self::export_pq_seed`].
    ///
    /// Key generation from a seed is deterministic (FIPS 204
    /// `ML-DSA.KeyGen_internal`), so the same seed always yields the
    /// same ML-DSA-65 key pair.
    #[must_use]
    pub fn from_seeds(classical: ClassicalSigningKey, pq_seed: &[u8; 32]) -> Self {
        let mut xi = B32::from(*pq_seed);
        let pq_expanded = ExpandedSigningKey::<MlDsa65>::from_seed(&xi);
        xi.zeroize();
        let pq_public = PqPublicKey::from_key(pq_expanded.verifying_key());
        Self {
            classical,
            pq_seed: Zeroizing::new(*pq_seed),
            pq_expanded,
            pq_public,
        }
    }

    /// Derive the [`HybridVerifyingKey`].
    #[must_use]
    pub fn verifying_key(&self) -> HybridVerifyingKey {
        HybridVerifyingKey {
            classical: self.classical.verifying_key(),
            algorithm: PqAlgorithm::MlDsa65,
            pq_public: self.pq_public.clone(),
        }
    }

    /// Produce a hybrid signature over `payload`.
    ///
    /// The ML-DSA half uses hedged (randomized) signing with an empty
    /// context, drawing its per-signature randomness from the OS RNG.
    ///
    /// # Errors
    ///
    /// Returns [`AionError::SigningFailed`](crate::AionError::SigningFailed)
    /// if ML-DSA signing fails: the OS RNG is unavailable, or rejection
    /// sampling exhausts its bound (`ml-dsa` reports both as one opaque
    /// error).
    pub fn sign(&self, payload: &[u8]) -> Result<HybridSignature> {
        let message = canonical_hybrid_message(payload);
        let classical = self.classical.sign(&message);
        let pq_sig = self
            .pq_expanded
            .sign_randomized(&message, &[], &mut rand::rngs::SysRng)
            .map_err(|_| AionError::SigningFailed {
                reason: "ML-DSA-65 signing failed".to_string(),
            })?;
        Ok(HybridSignature {
            algorithm: PqAlgorithm::MlDsa65,
            classical,
            pq: pq_sig.encode().to_vec(),
        })
    }

    /// 32-byte Ed25519 classical seed, for callers that need to
    /// shuttle the key between processes. Drops the PQ half —
    /// use [`Self::export_pq_seed`] for that.
    #[must_use]
    pub fn classical_seed(&self) -> &[u8; 32] {
        self.classical.to_bytes()
    }

    /// Export the 32-byte FIPS 204 ML-DSA-65 seed, the only supported
    /// persistence form for the PQ half (RFC-0041). Restore with
    /// [`Self::from_seeds`].
    ///
    /// The [`Zeroizing`] wrapper wipes the copy on drop; callers who
    /// copy the bytes elsewhere are responsible for that copy.
    #[must_use]
    pub fn export_pq_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.pq_seed)
    }

    /// Export the 4032-byte FIPS 204 `skEncode` ML-DSA-65 secret key.
    ///
    /// There is no import for this form: `ml-dsa`'s expanded-key
    /// decoder can panic on malformed input. Persist
    /// [`Self::export_pq_seed`] instead.
    #[deprecated(
        since = "3.1.0",
        note = "use export_pq_seed; expanded ML-DSA keys cannot be imported (RFC-0041)"
    )]
    #[must_use]
    pub fn export_pq_secret(&self) -> Zeroizing<Vec<u8>> {
        #[allow(deprecated)]
        let mut expanded = self.pq_expanded.to_expanded();
        let out = Zeroizing::new(expanded.to_vec());
        expanded.zeroize();
        out
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

    /// Expose the 1952-byte ML-DSA-65 public key encoding.
    #[must_use]
    pub fn pq_public_bytes(&self) -> &[u8] {
        &self.pq_public.encoded
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
        verify_mldsa65(&self.pq_public.key, &message, &sig.pq)
    }
}

/// Verify the ML-DSA-65 half of a hybrid signature over `message`,
/// FIPS 204 pure mode with an empty context.
///
/// Malformed signature bytes and a failed verification return the
/// same error, so the result reveals nothing about which check failed.
/// `hybrid_sig::tests::wycheproof_mldsa65_verify_vectors` runs the full
/// Wycheproof verify set through this function.
fn verify_mldsa65(public: &MlDsaVerifyingKey<MlDsa65>, message: &[u8], sig: &[u8]) -> Result<()> {
    let accepted = MlDsaSignature::<MlDsa65>::try_from(sig)
        .is_ok_and(|sig| public.verify_with_context(message, &[], &sig));
    if accepted {
        Ok(())
    } else {
        Err(AionError::InvalidFormat {
            reason: "ML-DSA-65 signature rejected".to_string(),
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    fn unhex(v: &serde_json::Value) -> Vec<u8> {
        hex::decode(v.as_str().unwrap_or_default()).unwrap_or_else(|_| std::process::abort())
    }

    fn fixture(json: &str) -> serde_json::Value {
        serde_json::from_str(json).unwrap_or_else(|_| std::process::abort())
    }

    fn groups(v: &serde_json::Value) -> &Vec<serde_json::Value> {
        v["testGroups"]
            .as_array()
            .unwrap_or_else(|| std::process::abort())
    }

    fn cases(g: &serde_json::Value) -> &Vec<serde_json::Value> {
        g["tests"]
            .as_array()
            .unwrap_or_else(|| std::process::abort())
    }

    fn has_flag(t: &serde_json::Value, flag: &str) -> bool {
        t["flags"]
            .as_array()
            .is_some_and(|f| f.iter().any(|x| x == flag))
    }

    /// RFC-0041 verification plan item 1: every Wycheproof ML-DSA-65
    /// verify vector. Empty-context vectors go through
    /// `verify_mldsa65`, the function `HybridVerifyingKey::verify`
    /// uses; vectors with a context call the backend directly.
    #[test]
    fn wycheproof_mldsa65_verify_vectors() {
        let v = fixture(include_str!(
            "../tests/fixtures/mldsa/wycheproof-mldsa65-verify.json"
        ));
        let (mut no_ctx, mut with_ctx) = (0, 0);
        for g in groups(&v) {
            let public = PqPublicKey::from_bytes(&unhex(&g["publicKey"]));
            for t in cases(g) {
                let (msg, sig) = (unhex(&t["msg"]), unhex(&t["sig"]));
                let accepted = match (&public, t.get("ctx")) {
                    (Err(_), _) => false,
                    (Ok(pk), None) => {
                        no_ctx += 1;
                        verify_mldsa65(&pk.key, &msg, &sig).is_ok()
                    }
                    (Ok(pk), Some(ctx)) => {
                        with_ctx += 1;
                        MlDsaSignature::<MlDsa65>::try_from(sig.as_slice())
                            .is_ok_and(|s| pk.key.verify_with_context(&msg, &unhex(ctx), &s))
                    }
                };
                assert_eq!(accepted, t["result"] == "valid", "tcId {}", t["tcId"]);
            }
        }
        assert_eq!((no_ctx, with_ctx), (199, 7));
    }

    /// RFC-0041 verification plan item 2: every Wycheproof ML-DSA-65
    /// sign-with-seed vector. The seed must yield the exact public
    /// key, deterministic signing must reproduce the exact signature,
    /// and that signature must verify.
    #[test]
    fn wycheproof_mldsa65_sign_seed_vectors() {
        let v = fixture(include_str!(
            "../tests/fixtures/mldsa/wycheproof-mldsa65-sign-seed.json"
        ));
        let mut counts = [0usize; 5];
        for g in groups(&v) {
            let Ok(seed) = <[u8; 32]>::try_from(unhex(&g["privateSeed"]).as_slice()) else {
                assert!(cases(g).iter().all(|t| t["result"] == "invalid"));
                counts[4] += cases(g).len();
                continue;
            };
            let classical =
                ClassicalSigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let key = HybridSigningKey::from_seeds(classical, &seed);
            assert_eq!(key.pq_public.encoded, unhex(&g["publicKey"]));
            for t in cases(g) {
                counts[check_sign_vector(&key, t)] += 1;
            }
        }
        assert_eq!(counts, [80, 17, 4, 1, 3]);
    }

    /// Returns the bucket the vector was counted in: 0 pure mode,
    /// 1 internal (precomputed mu, `Sign_internal`), 2 with context,
    /// 3 hedged with a fixed `rnd` (verified only: `ml-dsa` takes
    /// signing randomness from an RNG, not as bytes).
    fn check_sign_vector(key: &HybridSigningKey, t: &serde_json::Value) -> usize {
        let want = unhex(&t["sig"]);
        let pk = &key.pq_public.key;
        if has_flag(t, "Internal") {
            let mu_bytes = unhex(&t["mu"]);
            let mu = mu_bytes
                .as_slice()
                .try_into()
                .unwrap_or_else(|_| std::process::abort());
            let sig = key.pq_expanded.sign_mu_deterministic(&mu);
            assert_eq!(sig.encode().to_vec(), want, "tcId {}", t["tcId"]);
            assert!(pk.verify_mu(&mu, &sig));
            return 1;
        }
        let msg = unhex(&t["msg"]);
        if has_flag(t, "Randomized") {
            verify_mldsa65(pk, &msg, &want).unwrap_or_else(|_| std::process::abort());
            return 3;
        }
        let ctx = t.get("ctx").map(unhex).unwrap_or_default();
        let signed = key.pq_expanded.sign_deterministic(&msg, &ctx);
        if t["result"] == "invalid" {
            assert!(signed.is_err(), "tcId {}", t["tcId"]);
            return 2;
        }
        let sig = signed.unwrap_or_else(|_| std::process::abort());
        assert_eq!(sig.encode().to_vec(), want, "tcId {}", t["tcId"]);
        assert!(pk.verify_with_context(&msg, &ctx, &sig));
        if ctx.is_empty() {
            verify_mldsa65(pk, &msg, &want).unwrap_or_else(|_| std::process::abort());
            0
        } else {
            2
        }
    }

    #[test]
    fn sizes_match_fips_204() {
        let key = HybridSigningKey::generate().unwrap_or_else(|_| std::process::abort());
        assert_eq!(key.verifying_key().pq_public_bytes().len(), 1952);
        let sig = key.sign(b"x").unwrap_or_else(|_| std::process::abort());
        assert_eq!(sig.pq.len(), 3309);
        assert_eq!(key.export_pq_seed().len(), 32);
        #[allow(deprecated)]
        let expanded = key.export_pq_secret();
        assert_eq!(expanded.len(), 4032);
    }

    #[test]
    fn public_key_of_the_wrong_length_is_rejected() {
        assert!(PqPublicKey::from_bytes(&[0u8; 1951]).is_err());
        assert!(PqPublicKey::from_bytes(&[0u8; 1953]).is_err());
    }

    #[test]
    fn sign_verify_round_trip() {
        let key = HybridSigningKey::generate().unwrap_or_else(|_| std::process::abort());
        let vk = key.verifying_key();
        let sig = key.sign(b"hello hybrid").unwrap();
        vk.verify(b"hello hybrid", &sig).unwrap();
    }

    #[test]
    fn signing_is_hedged() {
        let key = HybridSigningKey::generate().unwrap_or_else(|_| std::process::abort());
        let a = key
            .sign(b"same payload")
            .unwrap_or_else(|_| std::process::abort());
        let b = key
            .sign(b"same payload")
            .unwrap_or_else(|_| std::process::abort());
        assert_ne!(a.pq, b.pq);
    }

    #[test]
    fn tampered_payload_rejects() {
        let key = HybridSigningKey::generate().unwrap_or_else(|_| std::process::abort());
        let vk = key.verifying_key();
        let sig = key.sign(b"hello hybrid").unwrap();
        assert!(vk.verify(b"hello HYBRID", &sig).is_err());
    }

    #[test]
    fn corrupted_classical_sig_rejects() {
        let key = HybridSigningKey::generate().unwrap_or_else(|_| std::process::abort());
        let vk = key.verifying_key();
        let mut sig = key.sign(b"payload").unwrap();
        sig.classical[0] ^= 0x01;
        assert!(vk.verify(b"payload", &sig).is_err());
    }

    #[test]
    fn corrupted_pq_sig_rejects() {
        let key = HybridSigningKey::generate().unwrap_or_else(|_| std::process::abort());
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
        let classical = ClassicalSigningKey::generate().unwrap_or_else(|_| std::process::abort());
        let original_pk = classical.verifying_key().to_bytes();
        let key =
            HybridSigningKey::from_classical(classical).unwrap_or_else(|_| std::process::abort());
        assert_eq!(key.verifying_key().classical.to_bytes(), original_pk);
    }

    /// RFC-0041 verification plan item 4, removed with the
    /// `pqcrypto-mldsa` dev-dependency after one release.
    mod interop {
        use super::*;
        use pqcrypto_mldsa::mldsa65 as pqclean;
        use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};

        /// A key exported through the deprecated expanded form signs
        /// under `pqcrypto-mldsa`, and `ml-dsa` verifies the result.
        pub(super) fn pqclean_signs_ml_dsa_verifies(payload: &[u8]) {
            let key = HybridSigningKey::generate().unwrap_or_else(|_| std::process::abort());
            #[allow(deprecated)]
            let expanded = key.export_pq_secret();
            let sk =
                pqclean::SecretKey::from_bytes(&expanded).unwrap_or_else(|_| std::process::abort());
            let message = canonical_hybrid_message(payload);
            let sig = HybridSignature {
                algorithm: PqAlgorithm::MlDsa65,
                classical: key.classical.sign(&message),
                pq: pqclean::detached_sign(&message, &sk).as_bytes().to_vec(),
            };
            key.verifying_key()
                .verify(payload, &sig)
                .unwrap_or_else(|_| std::process::abort());
        }

        /// `pqcrypto-mldsa` verifies `ml-dsa` signatures, and a
        /// `pqcrypto-mldsa` key pair's public key decodes in `ml-dsa` and
        /// verifies that backend's signatures.
        pub(super) fn ml_dsa_signs_pqclean_verifies(payload: &[u8]) {
            let key = HybridSigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let sig = key.sign(payload).unwrap_or_else(|_| std::process::abort());
            let message = canonical_hybrid_message(payload);
            let pk = pqclean::PublicKey::from_bytes(key.verifying_key().pq_public_bytes())
                .unwrap_or_else(|_| std::process::abort());
            let pq_sig = pqclean::DetachedSignature::from_bytes(&sig.pq)
                .unwrap_or_else(|_| std::process::abort());
            assert!(pqclean::verify_detached_signature(&pq_sig, &message, &pk).is_ok());

            let (their_public, their_secret) = pqclean::keypair();
            let theirs = pqclean::detached_sign(&message, &their_secret);
            let ours = PqPublicKey::from_bytes(their_public.as_bytes())
                .unwrap_or_else(|_| std::process::abort());
            verify_mldsa65(&ours.key, &message, theirs.as_bytes())
                .unwrap_or_else(|_| std::process::abort());
        }

        #[test]
        fn backends_interoperate_on_fixed_payloads() {
            for payload in [&b""[..], b"x", &[0xA5; 4096]] {
                pqclean_signs_ml_dsa_verifies(payload);
                ml_dsa_signs_pqclean_verifies(payload);
            }
        }
    }

    mod properties {
        use super::*;
        use hegel::generators as gs;

        #[hegel::test]
        fn prop_hybrid_sign_verify_roundtrip(tc: hegel::TestCase) {
            let payload = tc.draw(gs::binary().max_size(512));
            let key = HybridSigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let vk = key.verifying_key();
            let sig = key.sign(&payload).unwrap();
            vk.verify(&payload, &sig)
                .unwrap_or_else(|_| std::process::abort());
        }

        #[hegel::test]
        fn prop_hybrid_tampered_payload_rejects(tc: hegel::TestCase) {
            let payload = tc.draw(gs::binary().min_size(1).max_size(512));
            let key = HybridSigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let vk = key.verifying_key();
            let sig = key.sign(&payload).unwrap();
            let mut tampered = payload;
            let idx = tc.draw(gs::integers::<usize>().max_value(tampered.len().saturating_sub(1)));
            if let Some(b) = tampered.get_mut(idx) {
                *b ^= 0x01;
            }
            assert!(vk.verify(&tampered, &sig).is_err());
        }

        #[hegel::test]
        fn prop_hybrid_wrong_classical_key_rejects(tc: hegel::TestCase) {
            let payload = tc.draw(gs::binary().max_size(512));
            let key = HybridSigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let sig = key.sign(&payload).unwrap();
            // Build a verifying key whose classical half is from a
            // fresh keypair — PQ half still matches `key`.
            let impostor_classical =
                ClassicalSigningKey::generate().unwrap_or_else(|_| std::process::abort());
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
            let key = HybridSigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let sig = key.sign(&payload).unwrap();
            // Build a verifying key whose PQ half is from a fresh
            // keypair — classical half still matches `key`.
            let impostor = HybridSigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let wrong_vk = HybridVerifyingKey {
                classical: key.classical.verifying_key(),
                algorithm: PqAlgorithm::MlDsa65,
                pq_public: impostor.pq_public,
            };
            assert!(wrong_vk.verify(&payload, &sig).is_err());
        }

        #[hegel::test]
        fn prop_hybrid_corrupted_classical_sig_rejects(tc: hegel::TestCase) {
            let payload = tc.draw(gs::binary().max_size(512));
            let key = HybridSigningKey::generate().unwrap_or_else(|_| std::process::abort());
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
            let key = HybridSigningKey::generate().unwrap_or_else(|_| std::process::abort());
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
            let key = HybridSigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let vk = key.verifying_key();
            // Sign the raw payload (no domain) with the classical key.
            let classical_only = key.classical.sign(&payload);
            // Provide a correctly-constructed PQ signature over the
            // correct (domain-tagged) message, so the PQ half would
            // pass alone — the only failing component is classical,
            // which signed the wrong message.
            let domain_msg = canonical_hybrid_message(&payload);
            let pq_sig = key
                .pq_expanded
                .sign_randomized(&domain_msg, &[], &mut rand::rngs::SysRng)
                .unwrap_or_else(|_| std::process::abort());
            verify_mldsa65(&key.pq_public.key, &domain_msg, &pq_sig.encode())
                .unwrap_or_else(|_| std::process::abort());
            let sig = HybridSignature {
                algorithm: PqAlgorithm::MlDsa65,
                classical: classical_only,
                pq: pq_sig.encode().to_vec(),
            };
            assert!(vk.verify(&payload, &sig).is_err());
        }

        #[hegel::test]
        fn prop_hybrid_algorithm_mismatch_rejects(tc: hegel::TestCase) {
            // PqAlgorithm has one variant, so a discriminant mismatch
            // cannot be built through the API. Assert the matching
            // case verifies, then that a structurally invalid PQ half
            // under the same algorithm still rejects.
            let payload = tc.draw(gs::binary().max_size(256));
            let key = HybridSigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let vk = key.verifying_key();
            let mut sig = key.sign(&payload).unwrap();
            vk.verify(&payload, &sig)
                .unwrap_or_else(|_| std::process::abort());
            sig.pq.clear();
            assert!(vk.verify(&payload, &sig).is_err());
        }

        /// RFC-0041: `export_pq_seed` → `from_seeds` rebuilds the same
        /// key pair, and the rebuilt key's signatures verify under the
        /// original verifying key.
        #[hegel::test]
        fn prop_hybrid_seed_export_round_trips(tc: hegel::TestCase) {
            let payload = tc.draw(gs::binary().max_size(512));
            let key = HybridSigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let classical = ClassicalSigningKey::from_bytes(key.classical_seed())
                .unwrap_or_else(|_| std::process::abort());
            let rebuilt = HybridSigningKey::from_seeds(classical, &key.export_pq_seed());
            assert_eq!(
                rebuilt.verifying_key().pq_public_bytes(),
                key.verifying_key().pq_public_bytes()
            );
            let sig = rebuilt
                .sign(&payload)
                .unwrap_or_else(|_| std::process::abort());
            key.verifying_key()
                .verify(&payload, &sig)
                .unwrap_or_else(|_| std::process::abort());
        }

        /// RFC-0041 verification plan item 4 over generated payloads.
        #[hegel::test]
        fn prop_hybrid_backends_interoperate(tc: hegel::TestCase) {
            let payload = tc.draw(gs::binary().max_size(1024));
            super::interop::pqclean_signs_ml_dsa_verifies(&payload);
            super::interop::ml_dsa_signs_pqclean_verifies(&payload);
        }
    }
}
