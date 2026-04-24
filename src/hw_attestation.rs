//! Hardware attestation binding — RFC-0026.
//!
//! Ties an aion operational-key epoch to a TEE attestation quote
//! (TPM2, NVIDIA NRAS, Intel TDX, AMD SEV-SNP, AWS Nitro, Arm CCA,
//! Azure Attestation, …) via a record signed by the author's
//! master key.
//!
//! The aion-context crate does **not** verify TEE quotes itself —
//! every platform has a mature library already, and wiring one in
//! as a hard dependency would bloat every consumer. Instead, this
//! module exposes an [`EvidenceVerifier`] trait that callers
//! implement with the platform-specific library of their choice.
//!
//! # Example
//!
//! ```
//! use aion_context::crypto::SigningKey;
//! use aion_context::hw_attestation::{
//!     sign_binding, verify_binding_signature,
//!     AttestationEvidence, AttestationKind,
//! };
//! use aion_context::types::AuthorId;
//!
//! let master = SigningKey::generate();
//! let op = SigningKey::generate();
//! let evidence = AttestationEvidence {
//!     kind: AttestationKind::Tpm2Quote,
//!     nonce: [0u8; 32],
//!     evidence: b"opaque-tpm-quote-bytes".to_vec(),
//! };
//! let binding = sign_binding(
//!     AuthorId::new(1),
//!     0,
//!     op.verifying_key().to_bytes(),
//!     evidence,
//!     &master,
//! );
//! // Full `verify_binding` with a platform verifier requires the
//! // `test-helpers` feature for the built-in test doubles; here we
//! // verify just the master signature, which works without any
//! // platform-specific library.
//! verify_binding_signature(&binding, &master.verifying_key()).unwrap();
//! ```

use crate::crypto::{hash, SigningKey, VerifyingKey};
use crate::types::AuthorId;
use crate::{AionError, Result};

/// Domain separator for hardware-attestation binding messages.
pub const HW_ATTESTATION_DOMAIN: &[u8] = b"AION_V2_KEY_ATTESTATION_V1";

/// Platform whose quote format the evidence bytes carry.
///
/// The crate treats evidence bytes as opaque; this discriminant
/// exists so consumers can dispatch to the right platform
/// verifier.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationKind {
    /// TCG TPM 2.0 `TPMS_ATTEST` quote.
    Tpm2Quote = 1,
    /// NVIDIA Remote Attestation Service token (H100 Confidential
    /// Compute).
    NvidiaNras = 2,
    /// AMD SEV-SNP attestation report.
    AmdSevSnp = 3,
    /// Intel TDX quote.
    IntelTdxReport = 4,
    /// Intel SGX quote.
    IntelSgxReport = 5,
    /// AWS Nitro Enclaves attestation document.
    AwsNitroEnclave = 6,
    /// Arm Confidential Compute Architecture quote.
    ArmCca = 7,
    /// Microsoft Azure Attestation JWT.
    AzureAttestation = 8,
    /// Reserved for consumer-specific evidence formats.
    Custom = 0xFFFF,
}

impl AttestationKind {
    /// Convert a raw `u16` back to a known kind.
    ///
    /// # Errors
    ///
    /// Returns `Err` for discriminants not defined here.
    pub fn from_u16(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::Tpm2Quote),
            2 => Ok(Self::NvidiaNras),
            3 => Ok(Self::AmdSevSnp),
            4 => Ok(Self::IntelTdxReport),
            5 => Ok(Self::IntelSgxReport),
            6 => Ok(Self::AwsNitroEnclave),
            7 => Ok(Self::ArmCca),
            8 => Ok(Self::AzureAttestation),
            0xFFFF => Ok(Self::Custom),
            other => Err(AionError::InvalidFormat {
                reason: format!("Unknown attestation kind: {other}"),
            }),
        }
    }
}

/// Opaque evidence blob plus discriminant and freshness nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationEvidence {
    /// Which platform's format `evidence` carries.
    pub kind: AttestationKind,
    /// Freshness nonce — typically the one the TEE embedded in the
    /// quote (so platform verifiers can confirm the quote isn't
    /// replayed).
    pub nonce: [u8; 32],
    /// Platform-specific quote bytes.
    pub evidence: Vec<u8>,
}

/// A [`KeyAttestationBinding`] pairs an aion key epoch with a TEE
/// quote; the master signature commits to `(author_id, epoch,
/// public_key, kind, nonce, BLAKE3(evidence))`.
#[derive(Debug, Clone)]
pub struct KeyAttestationBinding {
    /// Author whose operational key is being attested.
    pub author_id: AuthorId,
    /// Epoch number for that key (matches `KeyEpoch::epoch`).
    pub epoch: u32,
    /// 32-byte operational public key.
    pub public_key: [u8; 32],
    /// TEE evidence.
    pub evidence: AttestationEvidence,
    /// Ed25519 signature by the author's master key over the
    /// canonical binding message.
    pub master_signature: [u8; 64],
}

/// Canonical bytes the master key signs when producing a binding.
#[must_use]
#[allow(clippy::arithmetic_side_effects)] // Fixed-size const arithmetic.
pub fn canonical_binding_message(binding: &KeyAttestationBinding) -> Vec<u8> {
    let evidence_hash = hash(&binding.evidence.evidence);
    let mut msg = Vec::with_capacity(HW_ATTESTATION_DOMAIN.len() + 8 + 4 + 32 + 2 + 32 + 32);
    msg.extend_from_slice(HW_ATTESTATION_DOMAIN);
    msg.extend_from_slice(&binding.author_id.as_u64().to_le_bytes());
    msg.extend_from_slice(&binding.epoch.to_le_bytes());
    msg.extend_from_slice(&binding.public_key);
    msg.extend_from_slice(&(binding.evidence.kind as u16).to_le_bytes());
    msg.extend_from_slice(&binding.evidence.nonce);
    msg.extend_from_slice(&evidence_hash);
    msg
}

/// Produce a signed binding. The caller is responsible for
/// ensuring `public_key` matches the registered `epoch` — this
/// module does not talk to [`crate::key_registry`] directly.
#[must_use]
pub fn sign_binding(
    author: AuthorId,
    epoch: u32,
    public_key: [u8; 32],
    evidence: AttestationEvidence,
    master_key: &SigningKey,
) -> KeyAttestationBinding {
    let mut binding = KeyAttestationBinding {
        author_id: author,
        epoch,
        public_key,
        evidence,
        master_signature: [0u8; 64],
    };
    let message = canonical_binding_message(&binding);
    binding.master_signature = master_key.sign(&message);
    binding
}

/// Verify only the master signature on `binding` — the signed
/// commitment is intact.
///
/// This does **not** run a platform evidence check; callers that
/// need the full story use [`verify_binding`] with an
/// [`EvidenceVerifier`].
///
/// # Errors
///
/// Returns `Err` if the master signature does not verify.
pub fn verify_binding_signature(
    binding: &KeyAttestationBinding,
    master_verifying_key: &VerifyingKey,
) -> Result<()> {
    let message = canonical_binding_message(binding);
    master_verifying_key.verify(&message, &binding.master_signature)
}

/// Trait for platform-specific TEE quote verification.
///
/// Implementations check:
///
/// 1. The TEE quote's internal signatures (vendor root-of-trust).
/// 2. The enclave measurement against an approved policy.
/// 3. That `expected_pubkey` matches the key material baked into
///    the quote.
///
/// aion-context ships three test doubles:
/// [`AcceptAllEvidenceVerifier`], [`RejectAllEvidenceVerifier`],
/// and [`PubkeyPrefixEvidenceVerifier`]. Real platform
/// implementations live in separate crates.
pub trait EvidenceVerifier {
    /// Verify `evidence` and confirm the TEE-attested public key
    /// equals `expected_pubkey`.
    ///
    /// # Errors
    ///
    /// Implementations return `Err` for any failure. Error
    /// content is implementation-defined.
    fn verify(&self, evidence: &AttestationEvidence, expected_pubkey: &[u8; 32]) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Test-double verifiers.
//
// These exist so property tests can exercise the platform-verification branch
// without a real TEE. Gated behind `#[cfg(any(test, feature = "test-helpers"))]`
// so production binaries cannot accidentally depend on `AcceptAllEvidenceVerifier`,
// which would silently accept any quote.
// ---------------------------------------------------------------------------

/// Testing verifier that unconditionally accepts. Useful for
/// exercising the signature path without a real TEE.
#[cfg(any(test, feature = "test-helpers"))]
#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptAllEvidenceVerifier;

#[cfg(any(test, feature = "test-helpers"))]
impl EvidenceVerifier for AcceptAllEvidenceVerifier {
    fn verify(&self, _evidence: &AttestationEvidence, _expected_pubkey: &[u8; 32]) -> Result<()> {
        Ok(())
    }
}

/// Testing verifier that unconditionally rejects.
#[cfg(any(test, feature = "test-helpers"))]
#[derive(Debug, Clone, Copy, Default)]
pub struct RejectAllEvidenceVerifier;

#[cfg(any(test, feature = "test-helpers"))]
impl EvidenceVerifier for RejectAllEvidenceVerifier {
    fn verify(&self, _evidence: &AttestationEvidence, _expected_pubkey: &[u8; 32]) -> Result<()> {
        Err(AionError::InvalidFormat {
            reason: "RejectAllEvidenceVerifier".to_string(),
        })
    }
}

/// Testing verifier that accepts iff `expected_pubkey` appears as
/// a byte-prefix of `evidence.evidence`. A minimal model of
/// "the TEE quote contains the public key" suitable for property
/// tests.
#[cfg(any(test, feature = "test-helpers"))]
#[derive(Debug, Clone, Copy, Default)]
pub struct PubkeyPrefixEvidenceVerifier;

#[cfg(any(test, feature = "test-helpers"))]
impl EvidenceVerifier for PubkeyPrefixEvidenceVerifier {
    fn verify(&self, evidence: &AttestationEvidence, expected_pubkey: &[u8; 32]) -> Result<()> {
        let prefix = evidence
            .evidence
            .get(..32)
            .ok_or_else(|| AionError::InvalidFormat {
                reason: "evidence shorter than 32 bytes".to_string(),
            })?;
        if prefix == expected_pubkey.as_slice() {
            Ok(())
        } else {
            Err(AionError::InvalidFormat {
                reason: "evidence prefix does not match expected pubkey".to_string(),
            })
        }
    }
}

/// Full verification: master signature **and** platform evidence.
///
/// # Errors
///
/// Returns `Err` if the master signature fails or if the platform
/// verifier rejects.
pub fn verify_binding<V: EvidenceVerifier>(
    binding: &KeyAttestationBinding,
    master_verifying_key: &VerifyingKey,
    verifier: &V,
) -> Result<()> {
    verify_binding_signature(binding, master_verifying_key)?;
    verifier.verify(&binding.evidence, &binding.public_key)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn sample_evidence() -> AttestationEvidence {
        AttestationEvidence {
            kind: AttestationKind::Tpm2Quote,
            nonce: [0x42u8; 32],
            evidence: b"opaque-tpm-quote-bytes".to_vec(),
        }
    }

    #[test]
    fn signature_round_trip() {
        let master = SigningKey::generate();
        let binding = sign_binding(
            AuthorId::new(1),
            0,
            [0xAAu8; 32],
            sample_evidence(),
            &master,
        );
        verify_binding_signature(&binding, &master.verifying_key()).unwrap();
    }

    #[test]
    fn wrong_master_rejects() {
        let master = SigningKey::generate();
        let other = SigningKey::generate();
        let binding = sign_binding(
            AuthorId::new(1),
            0,
            [0xAAu8; 32],
            sample_evidence(),
            &master,
        );
        assert!(verify_binding_signature(&binding, &other.verifying_key()).is_err());
    }

    #[test]
    fn tampered_evidence_rejects() {
        let master = SigningKey::generate();
        let mut binding = sign_binding(
            AuthorId::new(1),
            0,
            [0xAAu8; 32],
            sample_evidence(),
            &master,
        );
        binding.evidence.evidence[0] ^= 0x01;
        assert!(verify_binding_signature(&binding, &master.verifying_key()).is_err());
    }

    #[test]
    fn tampered_pubkey_rejects() {
        let master = SigningKey::generate();
        let mut binding = sign_binding(
            AuthorId::new(1),
            0,
            [0xAAu8; 32],
            sample_evidence(),
            &master,
        );
        binding.public_key[0] ^= 0x01;
        assert!(verify_binding_signature(&binding, &master.verifying_key()).is_err());
    }

    #[test]
    fn accept_all_verifier_accepts() {
        let master = SigningKey::generate();
        let binding = sign_binding(
            AuthorId::new(1),
            0,
            [0xAAu8; 32],
            sample_evidence(),
            &master,
        );
        assert!(verify_binding(
            &binding,
            &master.verifying_key(),
            &AcceptAllEvidenceVerifier,
        )
        .is_ok());
    }

    #[test]
    fn reject_all_verifier_rejects_even_valid_signature() {
        let master = SigningKey::generate();
        let binding = sign_binding(
            AuthorId::new(1),
            0,
            [0xAAu8; 32],
            sample_evidence(),
            &master,
        );
        assert!(verify_binding(
            &binding,
            &master.verifying_key(),
            &RejectAllEvidenceVerifier,
        )
        .is_err());
    }

    #[test]
    fn pubkey_prefix_verifier_matches_prefix_only() {
        let master = SigningKey::generate();
        let pk = [0xAAu8; 32];
        // Evidence that starts with the pubkey — prefix matches.
        let mut good_evidence = pk.to_vec();
        good_evidence.extend_from_slice(b"tail");
        let good = AttestationEvidence {
            kind: AttestationKind::Tpm2Quote,
            nonce: [0u8; 32],
            evidence: good_evidence,
        };
        let binding_good = sign_binding(AuthorId::new(1), 0, pk, good, &master);
        assert!(verify_binding(
            &binding_good,
            &master.verifying_key(),
            &PubkeyPrefixEvidenceVerifier,
        )
        .is_ok());

        // Evidence that does not start with the pubkey.
        let bad = AttestationEvidence {
            kind: AttestationKind::Tpm2Quote,
            nonce: [0u8; 32],
            evidence: vec![0u8; 64],
        };
        let binding_bad = sign_binding(AuthorId::new(1), 0, pk, bad, &master);
        assert!(verify_binding(
            &binding_bad,
            &master.verifying_key(),
            &PubkeyPrefixEvidenceVerifier,
        )
        .is_err());
    }

    #[test]
    fn attestation_kind_round_trips() {
        for kind in [
            AttestationKind::Tpm2Quote,
            AttestationKind::NvidiaNras,
            AttestationKind::AmdSevSnp,
            AttestationKind::IntelTdxReport,
            AttestationKind::IntelSgxReport,
            AttestationKind::AwsNitroEnclave,
            AttestationKind::ArmCca,
            AttestationKind::AzureAttestation,
            AttestationKind::Custom,
        ] {
            let raw = kind as u16;
            assert_eq!(AttestationKind::from_u16(raw).unwrap(), kind);
        }
        assert!(AttestationKind::from_u16(999).is_err());
    }

    mod properties {
        use super::*;
        use hegel::generators as gs;

        fn draw_evidence(tc: &hegel::TestCase) -> AttestationEvidence {
            let bytes = tc.draw(gs::binary().max_size(1024));
            let nonce_vec = tc.draw(gs::binary().min_size(32).max_size(32));
            let mut nonce = [0u8; 32];
            nonce.copy_from_slice(&nonce_vec);
            AttestationEvidence {
                kind: AttestationKind::Tpm2Quote,
                nonce,
                evidence: bytes,
            }
        }

        fn draw_pubkey(tc: &hegel::TestCase) -> [u8; 32] {
            let v = tc.draw(gs::binary().min_size(32).max_size(32));
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&v);
            pk
        }

        #[hegel::test]
        fn prop_binding_signature_roundtrip(tc: hegel::TestCase) {
            let master = SigningKey::generate();
            let author = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let epoch = tc.draw(gs::integers::<u32>());
            let pubkey = draw_pubkey(&tc);
            let evidence = draw_evidence(&tc);
            let binding = sign_binding(author, epoch, pubkey, evidence, &master);
            verify_binding_signature(&binding, &master.verifying_key())
                .unwrap_or_else(|_| std::process::abort());
        }

        #[hegel::test]
        fn prop_binding_rejects_wrong_master(tc: hegel::TestCase) {
            let master = SigningKey::generate();
            let other = SigningKey::generate();
            let author = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let epoch = tc.draw(gs::integers::<u32>());
            let pubkey = draw_pubkey(&tc);
            let evidence = draw_evidence(&tc);
            let binding = sign_binding(author, epoch, pubkey, evidence, &master);
            assert!(verify_binding_signature(&binding, &other.verifying_key()).is_err());
        }

        #[hegel::test]
        fn prop_binding_rejects_tampered_evidence(tc: hegel::TestCase) {
            let master = SigningKey::generate();
            let author = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let epoch = tc.draw(gs::integers::<u32>());
            let pubkey = draw_pubkey(&tc);
            let mut evidence = draw_evidence(&tc);
            // Need at least one byte to tamper.
            if evidence.evidence.is_empty() {
                evidence.evidence.push(0);
            }
            let mut binding = sign_binding(author, epoch, pubkey, evidence, &master);
            let idx = tc.draw(
                gs::integers::<usize>()
                    .max_value(binding.evidence.evidence.len().saturating_sub(1)),
            );
            if let Some(b) = binding.evidence.evidence.get_mut(idx) {
                *b ^= 0x01;
            }
            assert!(verify_binding_signature(&binding, &master.verifying_key()).is_err());
        }

        #[hegel::test]
        fn prop_binding_rejects_tampered_pubkey(tc: hegel::TestCase) {
            let master = SigningKey::generate();
            let author = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let epoch = tc.draw(gs::integers::<u32>());
            let pubkey = draw_pubkey(&tc);
            let evidence = draw_evidence(&tc);
            let mut binding = sign_binding(author, epoch, pubkey, evidence, &master);
            binding.public_key[0] ^= 0x01;
            assert!(verify_binding_signature(&binding, &master.verifying_key()).is_err());
        }

        #[hegel::test]
        fn prop_binding_rejects_tampered_nonce(tc: hegel::TestCase) {
            let master = SigningKey::generate();
            let author = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let epoch = tc.draw(gs::integers::<u32>());
            let pubkey = draw_pubkey(&tc);
            let evidence = draw_evidence(&tc);
            let mut binding = sign_binding(author, epoch, pubkey, evidence, &master);
            binding.evidence.nonce[0] ^= 0x01;
            assert!(verify_binding_signature(&binding, &master.verifying_key()).is_err());
        }

        #[hegel::test]
        fn prop_binding_rejects_tampered_author_or_epoch(tc: hegel::TestCase) {
            let master = SigningKey::generate();
            let author_raw = tc.draw(gs::integers::<u64>().min_value(1).max_value(u64::MAX / 2));
            let epoch = tc.draw(gs::integers::<u32>().max_value(u32::MAX - 1));
            let pubkey = draw_pubkey(&tc);
            let evidence = draw_evidence(&tc);
            let author = AuthorId::new(author_raw);
            let binding = sign_binding(author, epoch, pubkey, evidence, &master);

            // Tamper author.
            let mut b1 = binding.clone();
            b1.author_id = AuthorId::new(author_raw.saturating_add(1));
            assert!(verify_binding_signature(&b1, &master.verifying_key()).is_err());

            // Tamper epoch.
            let mut b2 = binding.clone();
            b2.epoch = epoch.saturating_add(1);
            assert!(verify_binding_signature(&b2, &master.verifying_key()).is_err());
        }

        #[hegel::test]
        fn prop_verify_binding_accept_all_ok(tc: hegel::TestCase) {
            let master = SigningKey::generate();
            let author = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let epoch = tc.draw(gs::integers::<u32>());
            let pubkey = draw_pubkey(&tc);
            let evidence = draw_evidence(&tc);
            let binding = sign_binding(author, epoch, pubkey, evidence, &master);
            verify_binding(
                &binding,
                &master.verifying_key(),
                &AcceptAllEvidenceVerifier,
            )
            .unwrap_or_else(|_| std::process::abort());
        }

        #[hegel::test]
        fn prop_verify_binding_reject_all_err(tc: hegel::TestCase) {
            let master = SigningKey::generate();
            let author = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let epoch = tc.draw(gs::integers::<u32>());
            let pubkey = draw_pubkey(&tc);
            let evidence = draw_evidence(&tc);
            let binding = sign_binding(author, epoch, pubkey, evidence, &master);
            assert!(verify_binding(
                &binding,
                &master.verifying_key(),
                &RejectAllEvidenceVerifier,
            )
            .is_err());
        }

        #[hegel::test]
        fn prop_pubkey_prefix_verifier_matches_prefix(tc: hegel::TestCase) {
            let master = SigningKey::generate();
            let author = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let epoch = tc.draw(gs::integers::<u32>());
            let pubkey = draw_pubkey(&tc);
            let tail = tc.draw(gs::binary().max_size(128));
            let mut good_evidence_bytes = pubkey.to_vec();
            good_evidence_bytes.extend_from_slice(&tail);
            let good = AttestationEvidence {
                kind: AttestationKind::Tpm2Quote,
                nonce: [0u8; 32],
                evidence: good_evidence_bytes,
            };
            let binding_good = sign_binding(author, epoch, pubkey, good, &master);
            verify_binding(
                &binding_good,
                &master.verifying_key(),
                &PubkeyPrefixEvidenceVerifier,
            )
            .unwrap_or_else(|_| std::process::abort());

            // Build a distinct pubkey-shaped prefix and inject it.
            let mut bad_prefix = pubkey;
            bad_prefix[0] ^= 0x01;
            let mut bad_bytes = bad_prefix.to_vec();
            bad_bytes.extend_from_slice(&tail);
            let bad = AttestationEvidence {
                kind: AttestationKind::Tpm2Quote,
                nonce: [0u8; 32],
                evidence: bad_bytes,
            };
            let binding_bad = sign_binding(author, epoch, pubkey, bad, &master);
            assert!(verify_binding(
                &binding_bad,
                &master.verifying_key(),
                &PubkeyPrefixEvidenceVerifier,
            )
            .is_err());
        }
    }
}
