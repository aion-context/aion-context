// SPDX-License-Identifier: MIT OR Apache-2.0
//! Enforcement receipts — RFC-0036.
//!
//! An [`EnforcementReceipt`] attests that a runtime **applied** a
//! policy to a real decision — the claim the provenance chain
//! ([`crate::dsse`], [`crate::slsa`], [`crate::transparency_log`])
//! does not make. It is a DSSE-wrapped in-toto Statement whose
//! predicate binds policy identity, the pinned key-registry epoch, the
//! enforcement decision, references to gating approvals, and the
//! enforcing runtime's identity.
//!
//! The load-bearing security property is **author binding**: the
//! runtime signs with its *own* registry-tracked key, distinct from
//! the policy author's, and [`EnforcementReceipt::verify_with_registry`]
//! rejects any receipt whose runtime signature is absent — a
//! validly-registered but different signer cannot produce a receipt
//! attributed to another runtime. Witnesses resolve under their own
//! version space, never the runtime's `receipt_version`.
//!
//! # Example
//!
//! ```
//! use aion_context::enforcement_receipt::{
//!     EnforcementReceiptBuilder, EnforcementDecision, PolicyIdentity, RegistryEpochRef,
//! };
//! use aion_context::crypto::SigningKey;
//! use aion_context::key_registry::KeyRegistry;
//! use aion_context::types::AuthorId;
//!
//! let runtime = AuthorId::new(60_001);
//! let master = SigningKey::generate().unwrap();
//! let key = SigningKey::generate().unwrap();
//! let mut registry = KeyRegistry::new();
//! registry
//!     .register_author(runtime, master.verifying_key(), key.verifying_key(), 0)
//!     .unwrap();
//!
//! let mut builder = EnforcementReceiptBuilder::new(
//!     PolicyIdentity { file_id: 7001, policy_version: 42, policy_author_id: AuthorId::new(50_001) },
//!     RegistryEpochRef { author_id: AuthorId::new(50_001), epoch: 3 },
//! );
//! builder
//!     .decision(EnforcementDecision::Deny)
//!     .add_input_digest("request", [0xAB; 32])
//!     .runtime(runtime, 118)
//!     .nonce([0x11; 16]);
//! let receipt = builder.seal(&key).unwrap();
//! receipt.verify_with_registry(&registry).unwrap();
//! ```

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::crypto::{SigningKey, VerifyingKey};
use crate::dsse::{self, author_from_keyid, keyid_for, DsseEnvelope};
use crate::key_registry::KeyRegistry;
use crate::slsa::{Subject, BLAKE3_DIGEST_KEY, IN_TOTO_PAYLOAD_TYPE, IN_TOTO_STATEMENT_TYPE};
use crate::transparency_log::{LogEntryKind, TransparencyLog};
use crate::types::AuthorId;
use crate::{AionError, Result};

/// `predicateType` for RFC-0036 enforcement receipts.
pub const ENFORCEMENT_RECEIPT_PREDICATE_TYPE: &str =
    "https://aion-context.dev/enforcement-receipt/v1";

/// The decision a runtime rendered against a policy. Closed, bounded
/// enum — never a freeform string (`.claude/rules/observability.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementDecision {
    /// The action was permitted.
    Allow,
    /// The action was blocked.
    Deny,
    /// The action proceeded in a reduced-capability mode.
    Degraded,
    /// The runtime could not evaluate and blocked by default.
    FailClosed,
}

/// Identity of the policy a decision was rendered against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyIdentity {
    /// The `.aion` file id.
    pub file_id: u64,
    /// The policy version enforced.
    pub policy_version: u64,
    /// The policy author.
    pub policy_author_id: AuthorId,
}

/// The registry epoch a runtime pinned for the policy author at
/// decision time — the datum that lets an auditor reproduce the
/// trust context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryEpochRef {
    /// The author whose epoch was pinned (the policy author).
    pub author_id: AuthorId,
    /// The epoch number that was active.
    pub epoch: u32,
}

/// The trust context block of the predicate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustContext {
    /// The pinned registry epoch.
    pub registry_epoch: RegistryEpochRef,
}

/// A reference to a gating approval attestation (RFC-0021), by digest.
///
/// The digest is carried on the wire as `blake3:<hex>`. Base
/// verification binds the reference; independent verification of the
/// referenced attestation is opt-in via
/// [`EnforcementReceipt::verify_with_registry_and_approvals`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRef {
    /// The author whose approval gated the decision.
    pub approver_author_id: AuthorId,
    /// BLAKE3 digest of the referenced attestation, `blake3:<hex>`.
    #[serde(rename = "attestation_ref", with = "blake3_ref")]
    pub attestation_digest: [u8; 32],
}

/// The runtime-identity block of the predicate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeBlock {
    /// The enforcing runtime's author id (distinct from the policy author).
    pub runtime_author_id: AuthorId,
    /// Per-runtime monotonic version for `(author, version)` replay defense.
    pub receipt_version: u64,
    /// 16-byte anti-fabrication nonce, hex on the wire.
    #[serde(with = "hex_nonce")]
    pub nonce: [u8; 16],
}

/// The enforcement-receipt predicate body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementPredicate {
    /// The policy the decision was rendered against.
    pub policy: PolicyIdentity,
    /// The pinned trust context.
    pub trust_context: TrustContext,
    /// The enforcement decision.
    pub decision: EnforcementDecision,
    /// References to gating approvals (may be empty).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approvals: Vec<ApprovalRef>,
    /// The enforcing runtime's identity.
    pub runtime: RuntimeBlock,
}

/// An in-toto Statement carrying an enforcement-receipt predicate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementStatement {
    /// Always [`IN_TOTO_STATEMENT_TYPE`].
    #[serde(rename = "_type")]
    pub type_uri: String,
    /// BLAKE3 digests of the decision inputs the runtime committed to.
    pub subject: Vec<Subject>,
    /// Always [`ENFORCEMENT_RECEIPT_PREDICATE_TYPE`].
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    /// The enforcement predicate.
    pub predicate: EnforcementPredicate,
}

impl EnforcementStatement {
    /// Signature-stable canonical bytes (matches the `slsa` module's
    /// `canonical_bytes` convention).
    ///
    /// # Errors
    ///
    /// Propagates `serde_json` serialization errors.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| AionError::InvalidFormat {
            reason: format!("enforcement statement serialization failed: {e}"),
        })
    }

    /// Parse from JSON.
    ///
    /// # Errors
    ///
    /// Returns `Err` for malformed JSON or a schema mismatch.
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|e| AionError::InvalidFormat {
            reason: format!("enforcement statement parse failed: {e}"),
        })
    }
}

/// Resolves and independently verifies referenced approval
/// attestations (RFC-0021) for the opt-in approval-gated verify path.
pub trait AttestationStore {
    /// Return `Ok(())` iff an attestation matching `digest` exists, is
    /// valid, and was produced by `approver`; otherwise `Err`.
    ///
    /// # Errors
    ///
    /// Returns `Err` when the attestation is absent, malformed, or
    /// signed by a different author.
    fn verify_approval(&self, digest: &[u8; 32], approver: AuthorId) -> Result<()>;
}

/// Binds a witness signature's keyid to the witness's own version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessBinding {
    /// The witness signature's keyid (`aion:author:<id>`).
    pub keyid: String,
    /// The witness author's own version, used to resolve its epoch.
    pub witness_version: u64,
}

/// Fluent builder for an [`EnforcementReceipt`].
#[derive(Debug)]
pub struct EnforcementReceiptBuilder {
    policy: PolicyIdentity,
    registry_epoch: RegistryEpochRef,
    decision: Option<EnforcementDecision>,
    approvals: Vec<ApprovalRef>,
    subjects: Vec<Subject>,
    runtime: Option<(AuthorId, u64)>,
    nonce: Option<[u8; 16]>,
}

impl EnforcementReceiptBuilder {
    /// Start a receipt for `policy` verified under `registry_epoch`.
    #[must_use]
    pub const fn new(policy: PolicyIdentity, registry_epoch: RegistryEpochRef) -> Self {
        Self {
            policy,
            registry_epoch,
            decision: None,
            approvals: Vec::new(),
            subjects: Vec::new(),
            runtime: None,
            nonce: None,
        }
    }

    /// Record the enforcement decision.
    pub fn decision(&mut self, decision: EnforcementDecision) -> &mut Self {
        self.decision = Some(decision);
        self
    }

    /// Append a gating-approval reference.
    pub fn add_approval(&mut self, approval: ApprovalRef) -> &mut Self {
        self.approvals.push(approval);
        self
    }

    /// Commit to one decision input by name and BLAKE3 digest.
    pub fn add_input_digest(&mut self, name: impl Into<String>, digest: [u8; 32]) -> &mut Self {
        let mut map = std::collections::BTreeMap::new();
        map.insert(BLAKE3_DIGEST_KEY.to_string(), hex::encode(digest));
        self.subjects.push(Subject {
            name: name.into(),
            digest: map,
        });
        self
    }

    /// Set the enforcing runtime identity and its receipt version.
    pub fn runtime(&mut self, runtime_author_id: AuthorId, receipt_version: u64) -> &mut Self {
        self.runtime = Some((runtime_author_id, receipt_version));
        self
    }

    /// Set the 16-byte anti-fabrication nonce.
    pub fn nonce(&mut self, nonce: [u8; 16]) -> &mut Self {
        self.nonce = Some(nonce);
        self
    }

    /// Build the statement and sign it via DSSE with the runtime's own key.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the decision, runtime identity, or nonce were
    /// not set, or if no decision-input digests were committed.
    pub fn seal(self, runtime_key: &SigningKey) -> Result<EnforcementReceipt> {
        let decision = self.decision.ok_or_else(|| AionError::InvalidFormat {
            reason: "enforcement receipt requires a decision".to_string(),
        })?;
        let (runtime_author_id, receipt_version) =
            self.runtime.ok_or_else(|| AionError::InvalidFormat {
                reason: "enforcement receipt requires a runtime identity".to_string(),
            })?;
        let nonce = self.nonce.ok_or_else(|| AionError::InvalidFormat {
            reason: "enforcement receipt requires a nonce".to_string(),
        })?;
        if self.subjects.is_empty() {
            return Err(AionError::InvalidFormat {
                reason: "enforcement receipt requires at least one decision-input digest"
                    .to_string(),
            });
        }
        let statement = EnforcementStatement {
            type_uri: IN_TOTO_STATEMENT_TYPE.to_string(),
            subject: self.subjects,
            predicate_type: ENFORCEMENT_RECEIPT_PREDICATE_TYPE.to_string(),
            predicate: EnforcementPredicate {
                policy: self.policy,
                trust_context: TrustContext {
                    registry_epoch: self.registry_epoch,
                },
                decision,
                approvals: self.approvals,
                runtime: RuntimeBlock {
                    runtime_author_id,
                    receipt_version,
                    nonce,
                },
            },
        };
        let payload = statement.canonical_bytes()?;
        let envelope = dsse::sign_envelope(
            &payload,
            IN_TOTO_PAYLOAD_TYPE,
            runtime_author_id,
            runtime_key,
        );
        Ok(EnforcementReceipt {
            envelope,
            witnesses: Vec::new(),
        })
    }
}

/// A sealed, verifiable enforcement receipt.
#[derive(Debug, Clone)]
pub struct EnforcementReceipt {
    /// The DSSE envelope carrying the signed enforcement statement.
    pub envelope: DsseEnvelope,
    /// Per-witness version bindings for signatures beyond the runtime's.
    witnesses: Vec<WitnessBinding>,
}

impl EnforcementReceipt {
    /// Parse and structurally validate the carried statement.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the envelope `payloadType` is not in-toto, the
    /// payload is not valid UTF-8/JSON, the `predicateType` is wrong,
    /// or the subject list is empty.
    pub fn statement(&self) -> Result<EnforcementStatement> {
        if self.envelope.payload_type != IN_TOTO_PAYLOAD_TYPE {
            return Err(AionError::InvalidFormat {
                reason: format!(
                    "envelope payloadType is '{}', expected '{IN_TOTO_PAYLOAD_TYPE}'",
                    self.envelope.payload_type
                ),
            });
        }
        let text =
            std::str::from_utf8(&self.envelope.payload).map_err(|e| AionError::InvalidFormat {
                reason: format!("enforcement payload is not UTF-8: {e}"),
            })?;
        let statement = EnforcementStatement::from_json(text)?;
        if statement.predicate_type != ENFORCEMENT_RECEIPT_PREDICATE_TYPE {
            return Err(AionError::InvalidFormat {
                reason: format!(
                    "predicateType is '{}', expected enforcement receipt",
                    statement.predicate_type
                ),
            });
        }
        if statement.subject.is_empty() {
            return Err(AionError::InvalidFormat {
                reason: "enforcement receipt has empty subject".to_string(),
            });
        }
        Ok(statement)
    }

    /// The carried predicate.
    ///
    /// # Errors
    ///
    /// Propagates parse/structure errors from [`Self::statement`].
    pub fn predicate(&self) -> Result<EnforcementPredicate> {
        Ok(self.statement()?.predicate)
    }

    /// Reconstruct a receipt from a DSSE envelope and its witness
    /// sidecar — the cross-process verification entry point.
    ///
    /// Witness version bindings travel out-of-band (unsigned; a wrong
    /// binding only mis-selects an epoch and fails the Ed25519 check,
    /// per RFC-0036), so the caller supplies them explicitly.
    #[must_use]
    pub const fn from_envelope(envelope: DsseEnvelope, witnesses: Vec<WitnessBinding>) -> Self {
        Self {
            envelope,
            witnesses,
        }
    }

    /// Reconstruct from the envelope's canonical JSON plus its witness
    /// sidecar.
    ///
    /// # Errors
    ///
    /// Propagates DSSE JSON parse errors.
    pub fn from_json(envelope_json: &str, witnesses: Vec<WitnessBinding>) -> Result<Self> {
        let envelope = DsseEnvelope::from_json(envelope_json)?;
        Ok(Self {
            envelope,
            witnesses,
        })
    }

    /// The witness version bindings a holder must ship alongside the
    /// envelope for a reconstructed receipt to re-verify.
    #[must_use]
    pub fn witnesses(&self) -> &[WitnessBinding] {
        &self.witnesses
    }

    /// Verify the receipt against the pinned registry — RFC-0036.
    ///
    /// Fails unless the runtime's own key
    /// (`keyid_for(runtime_author_id)`) is present in the envelope AND
    /// verifies at `receipt_version`. Witness signatures resolve at
    /// their own bound version. Does not resolve approvals (see
    /// [`Self::verify_with_registry_and_approvals`]) or check the
    /// caller's `(author, version)`/nonce replay ledger.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the statement is malformed, the runtime
    /// signature is absent or invalid, any present signature fails, or
    /// a non-runtime signature has no bound witness version.
    pub fn verify_with_registry(&self, registry: &KeyRegistry) -> Result<()> {
        let predicate = self.predicate()?;
        let runtime_author = predicate.runtime.runtime_author_id;
        let expected = keyid_for(runtime_author);
        if self.envelope.signatures.is_empty() {
            return Err(AionError::InvalidFormat {
                reason: "enforcement receipt has zero signatures".to_string(),
            });
        }
        let message = dsse::pae(&self.envelope.payload_type, &self.envelope.payload);
        let mut runtime_verified = false;
        let mut seen: HashSet<&str> = HashSet::new();
        for entry in &self.envelope.signatures {
            if !seen.insert(entry.keyid.as_str()) {
                continue;
            }
            let is_runtime = entry.keyid == expected;
            let at_version = if is_runtime {
                predicate.runtime.receipt_version
            } else {
                self.witness_version_for(&entry.keyid)?
            };
            verify_signature_at(registry, &entry.keyid, at_version, &message, &entry.sig)?;
            if is_runtime {
                runtime_verified = true;
            }
        }
        if !runtime_verified {
            return Err(AionError::SignatureVerificationFailed {
                version: predicate.runtime.receipt_version,
                author: runtime_author,
            });
        }
        Ok(())
    }

    /// As [`Self::verify_with_registry`], additionally resolving and
    /// verifying every referenced approval against `store`.
    ///
    /// # Errors
    ///
    /// Returns the base-verification error, or
    /// [`AionError::UnresolvedApproval`] if any referenced approval
    /// cannot be resolved and independently verified.
    pub fn verify_with_registry_and_approvals(
        &self,
        registry: &KeyRegistry,
        store: &dyn AttestationStore,
    ) -> Result<()> {
        self.verify_with_registry(registry)?;
        let predicate = self.predicate()?;
        for approval in &predicate.approvals {
            store
                .verify_approval(&approval.attestation_digest, approval.approver_author_id)
                .map_err(|_| AionError::UnresolvedApproval {
                    approver: approval.approver_author_id,
                    reason: "not_found_or_invalid".to_string(),
                })?;
        }
        Ok(())
    }

    /// Add an independent witness co-signature, bound to the witness's
    /// own version space (never the runtime's `receipt_version`).
    ///
    /// # Errors
    ///
    /// Currently infallible for well-formed inputs; returns `Result`
    /// for forward compatibility with witness-policy checks.
    pub fn add_witness_signature(
        &mut self,
        witness_author_id: AuthorId,
        witness_version: u64,
        witness_key: &SigningKey,
    ) -> Result<()> {
        dsse::add_signature(&mut self.envelope, witness_author_id, witness_key);
        self.witnesses.push(WitnessBinding {
            keyid: keyid_for(witness_author_id),
            witness_version,
        });
        Ok(())
    }

    /// Resolve the bound version for a non-runtime (witness) keyid.
    fn witness_version_for(&self, keyid: &str) -> Result<u64> {
        self.witnesses
            .iter()
            .find(|w| w.keyid == keyid)
            .map(|w| w.witness_version)
            .ok_or_else(|| AionError::InvalidFormat {
                reason: format!("signature keyid has no bound witness version: {keyid}"),
            })
    }
}

/// Append the receipt's envelope to a transparency log as
/// [`LogEntryKind::EnforcementReceipt`].
///
/// # Errors
///
/// Propagates envelope serialization and log-append errors.
pub fn log_receipt(
    receipt: &EnforcementReceipt,
    log: &mut TransparencyLog,
    timestamp_version: u64,
) -> Result<u64> {
    let bytes = receipt.envelope.to_json()?;
    log.append(
        LogEntryKind::EnforcementReceipt,
        bytes.as_bytes(),
        timestamp_version,
    )
}

/// Verify one DSSE signature at a specific registry version.
fn verify_signature_at(
    registry: &KeyRegistry,
    keyid: &str,
    at_version: u64,
    message: &[u8],
    sig: &[u8],
) -> Result<()> {
    let author = author_from_keyid(keyid)?;
    let epoch = registry.active_epoch_at(author, at_version).ok_or(
        AionError::SignatureVerificationFailed {
            version: at_version,
            author,
        },
    )?;
    let verifying_key = VerifyingKey::from_bytes(&epoch.public_key)?;
    let sig_bytes: &[u8; 64] = sig.try_into().map_err(|_| AionError::InvalidSignature {
        reason: format!(
            "signature for {keyid} has length {} (expected 64)",
            sig.len()
        ),
    })?;
    verifying_key.verify(message, sig_bytes)
}

/// Serde adapter: `[u8; 16]` ⇄ lowercase hex string.
mod hex_nonce {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 16], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 16], D::Error> {
        let raw = String::deserialize(deserializer)?;
        let bytes = hex::decode(&raw).map_err(serde::de::Error::custom)?;
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::custom("nonce must be 16 bytes"))
    }
}

/// Serde adapter: `[u8; 32]` ⇄ `blake3:<hex>` string.
mod blake3_ref {
    use serde::{Deserialize, Deserializer, Serializer};

    const PREFIX: &str = "blake3:";

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{PREFIX}{}", hex::encode(bytes)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let raw = String::deserialize(deserializer)?;
        let hexpart = raw
            .strip_prefix(PREFIX)
            .ok_or_else(|| serde::de::Error::custom("attestation_ref must start with 'blake3:'"))?;
        let bytes = hex::decode(hexpart).map_err(serde::de::Error::custom)?;
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::custom("attestation digest must be 32 bytes"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A trivial in-memory approval store keyed by digest → approver.
    struct MapStore {
        entries: HashMap<[u8; 32], AuthorId>,
    }

    impl AttestationStore for MapStore {
        fn verify_approval(&self, digest: &[u8; 32], approver: AuthorId) -> Result<()> {
            match self.entries.get(digest) {
                Some(a) if *a == approver => Ok(()),
                _ => Err(AionError::InvalidFormat {
                    reason: "no matching approval".to_string(),
                }),
            }
        }
    }

    fn reg_pinning(pairs: &[(AuthorId, &SigningKey)]) -> KeyRegistry {
        let mut reg = KeyRegistry::new();
        for (author, key) in pairs {
            let master = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
            reg.register_author(*author, master.verifying_key(), key.verifying_key(), 0)
                .unwrap();
        }
        reg
    }

    fn sample_builder(policy_author: AuthorId, runtime: AuthorId) -> EnforcementReceiptBuilder {
        let mut b = EnforcementReceiptBuilder::new(
            PolicyIdentity {
                file_id: 7001,
                policy_version: 42,
                policy_author_id: policy_author,
            },
            RegistryEpochRef {
                author_id: policy_author,
                epoch: 0,
            },
        );
        b.decision(EnforcementDecision::Deny)
            .add_input_digest("request", [0xAB; 32])
            .runtime(runtime, 118)
            .nonce([0x11; 16]);
        b
    }

    #[test]
    fn seal_then_verify_roundtrip() {
        let runtime = AuthorId::new(60_001);
        let key = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
        let reg = reg_pinning(&[(runtime, &key)]);
        let receipt = sample_builder(AuthorId::new(50_001), runtime)
            .seal(&key)
            .unwrap();
        receipt.verify_with_registry(&reg).unwrap();
        let predicate = receipt.predicate().unwrap();
        assert_eq!(predicate.decision, EnforcementDecision::Deny);
        assert_eq!(predicate.runtime.receipt_version, 118);
    }

    #[test]
    fn seal_requires_decision_runtime_nonce_subject() {
        let policy = PolicyIdentity {
            file_id: 1,
            policy_version: 1,
            policy_author_id: AuthorId::new(50_001),
        };
        let epoch = RegistryEpochRef {
            author_id: AuthorId::new(50_001),
            epoch: 0,
        };
        let key = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
        assert!(
            EnforcementReceiptBuilder::new(policy.clone(), epoch.clone())
                .seal(&key)
                .is_err()
        );
        let mut only_decision = EnforcementReceiptBuilder::new(policy, epoch);
        only_decision.decision(EnforcementDecision::Allow);
        assert!(only_decision.seal(&key).is_err());
    }

    #[test]
    fn tampered_decision_rejects() {
        let runtime = AuthorId::new(60_001);
        let key = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
        let reg = reg_pinning(&[(runtime, &key)]);
        let mut receipt = sample_builder(AuthorId::new(50_001), runtime)
            .seal(&key)
            .unwrap();
        let flipped = receipt.envelope.payload.iter().position(|&b| b == b'y'); // "deny"
        if let Some(i) = flipped {
            receipt.envelope.payload[i] ^= 0x01;
        }
        assert!(receipt.verify_with_registry(&reg).is_err());
    }

    #[test]
    fn distinct_signer_substitution_rejects() {
        // CRITICAL-1: author Y signs a predicate naming victim X as the
        // runtime, with Y's own valid key. Must reject — no X signature.
        let victim = AuthorId::new(60_001);
        let attacker = AuthorId::new(60_002);
        let attacker_key = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
        // Predicate names the victim as runtime, but attacker seals it.
        let receipt = sample_builder(AuthorId::new(50_001), victim)
            .seal(&attacker_key)
            .unwrap();
        // Registry pins BOTH authors with real keys (attacker is valid).
        let reg = reg_pinning(&[
            (
                victim,
                &SigningKey::generate().unwrap_or_else(|_| std::process::abort()),
            ),
            (attacker, &attacker_key),
        ]);
        // The envelope carries attacker's keyid, predicate claims victim.
        assert!(receipt.verify_with_registry(&reg).is_err());
    }

    #[test]
    fn runtime_signature_must_be_present() {
        let runtime = AuthorId::new(60_001);
        let witness = AuthorId::new(70_001);
        let runtime_key = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
        let witness_key = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
        let mut receipt = sample_builder(AuthorId::new(50_001), runtime)
            .seal(&runtime_key)
            .unwrap();
        // Drop the runtime signature, leaving only a witness co-sign.
        receipt
            .add_witness_signature(witness, 5, &witness_key)
            .unwrap();
        receipt
            .envelope
            .signatures
            .retain(|s| s.keyid != keyid_for(runtime));
        let reg = reg_pinning(&[(runtime, &runtime_key), (witness, &witness_key)]);
        assert!(receipt.verify_with_registry(&reg).is_err());
    }

    #[test]
    fn witness_cosignature_roundtrip() {
        let runtime = AuthorId::new(60_001);
        let witness = AuthorId::new(70_001);
        let runtime_key = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
        let witness_key = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
        let mut receipt = sample_builder(AuthorId::new(50_001), runtime)
            .seal(&runtime_key)
            .unwrap();
        receipt
            .add_witness_signature(witness, 5, &witness_key)
            .unwrap();
        let reg = reg_pinning(&[(runtime, &runtime_key), (witness, &witness_key)]);
        receipt.verify_with_registry(&reg).unwrap();
        assert_eq!(receipt.envelope.signatures.len(), 2);
    }

    #[test]
    fn unresolvable_approval_hard_fails_but_base_passes() {
        let runtime = AuthorId::new(60_001);
        let approver = AuthorId::new(50_010);
        let key = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
        let mut b = sample_builder(AuthorId::new(50_001), runtime);
        b.add_approval(ApprovalRef {
            approver_author_id: approver,
            attestation_digest: [0x077; 32],
        });
        let receipt = b.seal(&key).unwrap();
        let reg = reg_pinning(&[(runtime, &key)]);
        // Base path passes (references are bound, not resolved).
        receipt.verify_with_registry(&reg).unwrap();
        // Approval path fails — the store has no matching attestation.
        let empty = MapStore {
            entries: HashMap::new(),
        };
        assert!(receipt
            .verify_with_registry_and_approvals(&reg, &empty)
            .is_err());
        // With a matching attestation it passes.
        let mut entries = HashMap::new();
        entries.insert([0x077; 32], approver);
        let store = MapStore { entries };
        receipt
            .verify_with_registry_and_approvals(&reg, &store)
            .unwrap();
    }

    #[test]
    fn from_json_reconstruct_and_verify() {
        // Cross-process shape: serialize the envelope, capture the
        // witness sidecar, reconstruct elsewhere, and re-verify.
        let runtime = AuthorId::new(60_001);
        let witness = AuthorId::new(70_001);
        let runtime_key = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
        let witness_key = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
        let mut receipt = sample_builder(AuthorId::new(50_001), runtime)
            .seal(&runtime_key)
            .unwrap();
        receipt
            .add_witness_signature(witness, 5, &witness_key)
            .unwrap();
        let json = receipt.envelope.to_json().unwrap();
        let sidecar = receipt.witnesses().to_vec();
        let rebuilt = EnforcementReceipt::from_json(&json, sidecar).unwrap();
        let reg = reg_pinning(&[(runtime, &runtime_key), (witness, &witness_key)]);
        rebuilt.verify_with_registry(&reg).unwrap();
        assert_eq!(rebuilt.predicate().unwrap(), receipt.predicate().unwrap());
    }

    #[test]
    fn reconstruct_without_witness_sidecar_rejects_witness_sig() {
        // A witness signature with no bound version fails closed.
        let runtime = AuthorId::new(60_001);
        let witness = AuthorId::new(70_001);
        let runtime_key = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
        let witness_key = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
        let mut receipt = sample_builder(AuthorId::new(50_001), runtime)
            .seal(&runtime_key)
            .unwrap();
        receipt
            .add_witness_signature(witness, 5, &witness_key)
            .unwrap();
        let json = receipt.envelope.to_json().unwrap();
        let rebuilt = EnforcementReceipt::from_json(&json, Vec::new()).unwrap();
        let reg = reg_pinning(&[(runtime, &runtime_key), (witness, &witness_key)]);
        assert!(rebuilt.verify_with_registry(&reg).is_err());
    }

    #[test]
    fn log_entry_kind_is_enforcement_receipt() {
        let runtime = AuthorId::new(60_001);
        let key = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
        let receipt = sample_builder(AuthorId::new(50_001), runtime)
            .seal(&key)
            .unwrap();
        let mut log = TransparencyLog::new();
        let seq = log_receipt(&receipt, &mut log, 1).unwrap();
        assert_eq!(seq, 0);
        assert_eq!(
            log.entries().first().map(|e| e.kind),
            Some(LogEntryKind::EnforcementReceipt)
        );
    }

    #[test]
    fn json_predicate_shape_is_nested() {
        let runtime = AuthorId::new(60_001);
        let key = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
        let receipt = sample_builder(AuthorId::new(50_001), runtime)
            .seal(&key)
            .unwrap();
        let json = std::str::from_utf8(&receipt.envelope.payload).unwrap();
        assert!(
            json.contains("\"predicateType\":\"https://aion-context.dev/enforcement-receipt/v1\"")
        );
        assert!(json.contains("\"decision\":\"deny\""));
        assert!(json.contains("\"trust_context\""));
    }

    mod properties {
        use super::*;
        use hegel::generators as gs;

        fn draw_ids(tc: &hegel::TestCase) -> (AuthorId, AuthorId) {
            let policy =
                AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 20)));
            let runtime = AuthorId::new(
                tc.draw(
                    gs::integers::<u64>()
                        .min_value((1 << 20) + 1)
                        .max_value(1 << 30),
                ),
            );
            (policy, runtime)
        }

        #[hegel::test]
        fn prop_enforcement_receipt_seal_verify_roundtrip(tc: hegel::TestCase) {
            let (policy, runtime) = draw_ids(&tc);
            let version = tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 30));
            let key = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let mut b = EnforcementReceiptBuilder::new(
                PolicyIdentity {
                    file_id: tc.draw(gs::integers::<u64>()),
                    policy_version: tc.draw(gs::integers::<u64>()),
                    policy_author_id: policy,
                },
                RegistryEpochRef {
                    author_id: policy,
                    epoch: 0,
                },
            );
            b.decision(EnforcementDecision::Allow)
                .add_input_digest("input", [0x01; 32])
                .runtime(runtime, version)
                .nonce([0x22; 16]);
            let receipt = b.seal(&key).unwrap_or_else(|_| std::process::abort());
            let reg = reg_pinning(&[(runtime, &key)]);
            receipt
                .verify_with_registry(&reg)
                .unwrap_or_else(|_| std::process::abort());
        }

        #[hegel::test]
        fn prop_enforcement_receipt_tampered_payload_rejects(tc: hegel::TestCase) {
            let (policy, runtime) = draw_ids(&tc);
            let key = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let mut receipt = sample_builder(policy, runtime)
                .seal(&key)
                .unwrap_or_else(|_| std::process::abort());
            let max = receipt.envelope.payload.len().saturating_sub(1);
            let idx = tc.draw(gs::integers::<usize>().max_value(max));
            if let Some(byte) = receipt.envelope.payload.get_mut(idx) {
                *byte ^= 0x01;
            }
            let reg = reg_pinning(&[(runtime, &key)]);
            assert!(receipt.verify_with_registry(&reg).is_err());
        }

        #[hegel::test]
        fn prop_enforcement_receipt_wrong_runtime_key_rejects(tc: hegel::TestCase) {
            let (policy, runtime) = draw_ids(&tc);
            let real = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let wrong = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let receipt = sample_builder(policy, runtime)
                .seal(&real)
                .unwrap_or_else(|_| std::process::abort());
            // Registry pins the WRONG key for the runtime.
            let reg = reg_pinning(&[(runtime, &wrong)]);
            assert!(receipt.verify_with_registry(&reg).is_err());
        }

        #[hegel::test]
        fn prop_enforcement_receipt_distinct_signer_substitution_rejects(tc: hegel::TestCase) {
            let (policy, victim) = draw_ids(&tc);
            let attacker = AuthorId::new(victim.as_u64().saturating_add(1));
            let attacker_key = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let receipt = sample_builder(policy, victim)
                .seal(&attacker_key)
                .unwrap_or_else(|_| std::process::abort());
            let reg = reg_pinning(&[
                (
                    victim,
                    &SigningKey::generate().unwrap_or_else(|_| std::process::abort()),
                ),
                (attacker, &attacker_key),
            ]);
            assert!(receipt.verify_with_registry(&reg).is_err());
        }

        #[hegel::test]
        fn prop_enforcement_receipt_json_roundtrip(tc: hegel::TestCase) {
            let (policy, runtime) = draw_ids(&tc);
            let key = SigningKey::generate().unwrap_or_else(|_| std::process::abort());
            let receipt = sample_builder(policy, runtime)
                .seal(&key)
                .unwrap_or_else(|_| std::process::abort());
            let statement = receipt
                .statement()
                .unwrap_or_else(|_| std::process::abort());
            let json = statement
                .canonical_bytes()
                .unwrap_or_else(|_| std::process::abort());
            let text = std::str::from_utf8(&json).unwrap_or_else(|_| std::process::abort());
            let parsed =
                EnforcementStatement::from_json(text).unwrap_or_else(|_| std::process::abort());
            assert_eq!(parsed, statement);
        }
    }
}
