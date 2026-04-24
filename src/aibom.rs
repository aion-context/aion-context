//! AI Bill of Materials (AIBOM) — RFC-0029.
//!
//! [`AiBom`] captures the ingredients of a trained model: the
//! artifact reference, frameworks, datasets, licenses,
//! hyperparameters, safety attestations, export controls, and
//! external references (model card, paper, changelog). Serializes
//! to byte-stable JSON and rides over DSSE (RFC-0023) as
//! `application/vnd.aion.aibom.v1+json`.
//!
//! Phase A: aion-native schema. Phase B: bi-directional
//! translation to/from SPDX 3.0 AI profile and `CycloneDX` 1.6 ML.
//!
//! # Example
//!
//! ```
//! use aion_context::aibom::{AiBom, ModelRef, FrameworkRef};
//! use aion_context::crypto::SigningKey;
//! use aion_context::types::AuthorId;
//!
//! let model = ModelRef {
//!     name: "acme-7b-chat".into(),
//!     version: "0.3.1".into(),
//!     hash_algorithm: "BLAKE3-256".into(),
//!     hash: [0xAB; 32],
//!     size: 1_000,
//!     format: "safetensors".into(),
//! };
//! let mut b = AiBom::builder(model, 42);
//! b.add_framework(FrameworkRef {
//!     name: "pytorch".into(),
//!     version: "2.3.1".into(),
//!     cpe: None,
//! });
//! let aibom = b.build();
//!
//! let signer = AuthorId::new(1001);
//! let key = SigningKey::generate();
//! let env = aion_context::aibom::wrap_aibom_dsse(&aibom, signer, &key).unwrap();
//! let back = aion_context::aibom::unwrap_aibom_dsse(&env).unwrap();
//! assert_eq!(back, aibom);
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::crypto::SigningKey;
use crate::dsse::{self, DsseEnvelope};
use crate::types::AuthorId;
use crate::{AionError, Result};

/// DSSE `payloadType` for aion AIBOM envelopes.
pub const AIBOM_PAYLOAD_TYPE: &str = "application/vnd.aion.aibom.v1+json";

/// Value carried in `schema_version` on every emitted AIBOM.
pub const AIBOM_SCHEMA_VERSION: &str = "aion.aibom.v1";

/// Reference to the model artifact the AIBOM describes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelRef {
    /// Model name (site-local or upstream identifier).
    pub name: String,
    /// Model version string.
    pub version: String,
    /// Hash algorithm used for `hash`. Usually `"BLAKE3-256"`.
    pub hash_algorithm: String,
    /// 32-byte content hash, emitted as lowercase hex.
    #[serde(with = "hex_bytes32")]
    pub hash: [u8; 32],
    /// Size of the artifact in bytes.
    pub size: u64,
    /// Serialization format — `safetensors`, `gguf`, `onnx`, …
    pub format: String,
}

/// A framework required to run or train the model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameworkRef {
    /// Framework name: `pytorch`, `tensorflow`, `jax`, …
    pub name: String,
    /// Framework version.
    pub version: String,
    /// Optional CPE 2.3 URI for CVE correlation.
    pub cpe: Option<String>,
}

/// A dataset used in training, fine-tuning, or evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetRef {
    /// Dataset name.
    pub name: String,
    /// Hash algorithm used for `hash`, if any.
    pub hash_algorithm: Option<String>,
    /// Optional 32-byte content hash.
    #[serde(with = "hex_bytes32_opt")]
    pub hash: Option<[u8; 32]>,
    /// Optional size in bytes.
    pub size: Option<u64>,
    /// Optional URI — pointer to the dataset location.
    pub uri: Option<String>,
    /// Optional SPDX license identifier for the dataset.
    pub license_spdx_id: Option<String>,
}

/// Scope a license applies to within the AIBOM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LicenseScope {
    /// Just the trained weights.
    Weights,
    /// Source code only.
    SourceCode,
    /// Training data only.
    TrainingData,
    /// Documentation / model card.
    Documentation,
    /// The whole release (weights + code + data + docs).
    Combined,
}

/// A license that applies to some part of the release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct License {
    /// SPDX license ID (`Apache-2.0`, `LLAMA3-COMMUNITY`, …).
    pub spdx_id: String,
    /// What the license covers.
    pub scope: LicenseScope,
    /// Optional URI to the full license text.
    pub text_uri: Option<String>,
}

/// A safety / red-team / evaluation attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyAttestation {
    /// Attestation name or identifier.
    pub name: String,
    /// Result string — site-specific. `"PASS"` / `"REVIEW"` etc.
    pub result: String,
    /// Optional hash algorithm for `report_hash`.
    pub report_hash_algorithm: Option<String>,
    /// Optional 32-byte content hash of the attestation report.
    #[serde(with = "hex_bytes32_opt")]
    pub report_hash: Option<[u8; 32]>,
    /// Optional URI for the report.
    pub report_uri: Option<String>,
}

/// An export-control classification under some regime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportControl {
    /// Regime name — `"US-ECCN"`, `"EU-dual-use"`, …
    pub regime: String,
    /// Classification within the regime — `"EAR99"`,
    /// `"5D002.c.1"`, …
    pub classification: String,
    /// Optional human-readable notes.
    pub notes: Option<String>,
}

/// An external reference (model card, paper, changelog, …).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalReference {
    /// Kind: `"model_card"`, `"paper"`, `"changelog"`, …
    pub kind: String,
    /// URI.
    pub uri: String,
}

/// The full AIBOM record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AiBom {
    /// Schema-version discriminator. Always
    /// [`AIBOM_SCHEMA_VERSION`] for Phase A.
    pub schema_version: String,
    /// The model this AIBOM describes.
    pub model: ModelRef,
    /// Frameworks required at train/infer time.
    pub frameworks: Vec<FrameworkRef>,
    /// Datasets used in training/tuning.
    pub datasets: Vec<DatasetRef>,
    /// Licenses that apply to the release.
    pub licenses: Vec<License>,
    /// Hyperparameters — opaque JSON values keyed by string.
    pub hyperparameters: BTreeMap<String, serde_json::Value>,
    /// Safety / red-team attestations.
    pub safety_attestations: Vec<SafetyAttestation>,
    /// Export-control classifications.
    pub export_controls: Vec<ExportControl>,
    /// External references (model card, paper, …).
    pub references: Vec<ExternalReference>,
    /// aion version number at AIBOM creation time — orders
    /// the AIBOM alongside other aion artifacts per
    /// `.claude/rules/distributed.md`.
    pub created_at_version: u64,
}

impl AiBom {
    /// Start building a new AIBOM for `model` at
    /// `created_at_version`.
    #[must_use]
    pub const fn builder(model: ModelRef, created_at_version: u64) -> AiBomBuilder {
        AiBomBuilder {
            model,
            frameworks: Vec::new(),
            datasets: Vec::new(),
            licenses: Vec::new(),
            hyperparameters: BTreeMap::new(),
            safety_attestations: Vec::new(),
            export_controls: Vec::new(),
            references: Vec::new(),
            created_at_version,
        }
    }

    /// Serialize to pretty-printed JSON. For byte-stable output
    /// use [`Self::canonical_bytes`].
    ///
    /// # Errors
    ///
    /// Propagates `serde_json` errors.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| AionError::InvalidFormat {
            reason: format!("AIBOM JSON serialize failed: {e}"),
        })
    }

    /// Parse from JSON.
    ///
    /// # Errors
    ///
    /// Returns `Err` for malformed JSON or schema mismatch.
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|e| AionError::InvalidFormat {
            reason: format!("AIBOM JSON parse failed: {e}"),
        })
    }

    /// Canonical serialized bytes — stable across runs because
    /// all user-keyed maps use `BTreeMap` and struct fields are
    /// emitted in declaration order.
    ///
    /// # Errors
    ///
    /// Propagates `serde_json` errors.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| AionError::InvalidFormat {
            reason: format!("AIBOM canonical bytes failed: {e}"),
        })
    }

    /// RFC 8785 (JCS) canonical bytes — use when cross-implementation
    /// byte stability matters (Phase B of RFC-0031). Opt-in;
    /// `canonical_bytes()` remains the signature-stable form for
    /// historical DSSE envelopes.
    ///
    /// # Errors
    ///
    /// Propagates serialization errors from [`crate::jcs`].
    pub fn to_jcs_bytes(&self) -> Result<Vec<u8>> {
        crate::jcs::to_jcs_bytes(self)
    }
}

/// Fluent builder for an [`AiBom`].
#[derive(Debug)]
pub struct AiBomBuilder {
    model: ModelRef,
    frameworks: Vec<FrameworkRef>,
    datasets: Vec<DatasetRef>,
    licenses: Vec<License>,
    hyperparameters: BTreeMap<String, serde_json::Value>,
    safety_attestations: Vec<SafetyAttestation>,
    export_controls: Vec<ExportControl>,
    references: Vec<ExternalReference>,
    created_at_version: u64,
}

impl AiBomBuilder {
    /// Append a framework reference.
    pub fn add_framework(&mut self, f: FrameworkRef) -> &mut Self {
        self.frameworks.push(f);
        self
    }

    /// Append a dataset reference.
    pub fn add_dataset(&mut self, d: DatasetRef) -> &mut Self {
        self.datasets.push(d);
        self
    }

    /// Append a license.
    pub fn add_license(&mut self, l: License) -> &mut Self {
        self.licenses.push(l);
        self
    }

    /// Set a hyperparameter; overwrites any prior value for the
    /// same key.
    pub fn hyperparameter(&mut self, k: impl Into<String>, v: serde_json::Value) -> &mut Self {
        self.hyperparameters.insert(k.into(), v);
        self
    }

    /// Append a safety attestation.
    pub fn add_safety_attestation(&mut self, s: SafetyAttestation) -> &mut Self {
        self.safety_attestations.push(s);
        self
    }

    /// Append an export-control entry.
    pub fn add_export_control(&mut self, e: ExportControl) -> &mut Self {
        self.export_controls.push(e);
        self
    }

    /// Append an external reference.
    pub fn add_reference(&mut self, r: ExternalReference) -> &mut Self {
        self.references.push(r);
        self
    }

    /// Finalize.
    #[must_use]
    pub fn build(self) -> AiBom {
        AiBom {
            schema_version: AIBOM_SCHEMA_VERSION.to_string(),
            model: self.model,
            frameworks: self.frameworks,
            datasets: self.datasets,
            licenses: self.licenses,
            hyperparameters: self.hyperparameters,
            safety_attestations: self.safety_attestations,
            export_controls: self.export_controls,
            references: self.references,
            created_at_version: self.created_at_version,
        }
    }
}

/// Wrap `aibom` in a DSSE envelope signed by `signer`.
///
/// # Errors
///
/// Propagates canonical-bytes serialization errors.
pub fn wrap_aibom_dsse(aibom: &AiBom, signer: AuthorId, key: &SigningKey) -> Result<DsseEnvelope> {
    let payload = aibom.canonical_bytes()?;
    Ok(dsse::sign_envelope(
        &payload,
        AIBOM_PAYLOAD_TYPE,
        signer,
        key,
    ))
}

/// Pull an [`AiBom`] out of a DSSE envelope. The caller is
/// responsible for verifying the envelope's signature(s) via
/// [`crate::dsse::verify_envelope`] before trusting the result.
///
/// # Errors
///
/// Returns `Err` if the envelope's `payloadType` is not
/// [`AIBOM_PAYLOAD_TYPE`] or if the payload fails to parse.
pub fn unwrap_aibom_dsse(envelope: &DsseEnvelope) -> Result<AiBom> {
    if envelope.payload_type != AIBOM_PAYLOAD_TYPE {
        return Err(AionError::InvalidFormat {
            reason: format!(
                "envelope payloadType is '{}', expected '{}'",
                envelope.payload_type, AIBOM_PAYLOAD_TYPE
            ),
        });
    }
    let payload_str =
        std::str::from_utf8(&envelope.payload).map_err(|e| AionError::InvalidFormat {
            reason: format!("AIBOM DSSE payload is not valid UTF-8: {e}"),
        })?;
    AiBom::from_json(payload_str)
}

/// Serde adapter for 32-byte hashes → lowercase hex and back.
mod hex_bytes32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(deserializer)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if v.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "hash hex length is {} (expected 64 chars = 32 bytes)",
                v.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

/// Serde adapter for `Option<[u8; 32]>` → hex / null.
mod hex_bytes32_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        bytes: &Option<[u8; 32]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(b) => serializer.serialize_str(&hex::encode(b)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<[u8; 32]>, D::Error> {
        let maybe: Option<String> = Option::deserialize(deserializer)?;
        match maybe {
            None => Ok(None),
            Some(s) => {
                let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
                if v.len() != 32 {
                    return Err(serde::de::Error::custom(format!(
                        "hash hex length is {} (expected 64 chars = 32 bytes)",
                        v.len()
                    )));
                }
                let mut out = [0u8; 32];
                out.copy_from_slice(&v);
                Ok(Some(out))
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dsse::verify_envelope;
    use crate::key_registry::KeyRegistry;
    use serde_json::json;

    /// Pin `signer` with `key` as the active op pubkey at epoch 0.
    fn reg_pinning(signer: AuthorId, key: &SigningKey) -> KeyRegistry {
        let mut reg = KeyRegistry::new();
        let master = SigningKey::generate();
        reg.register_author(signer, master.verifying_key(), key.verifying_key(), 0)
            .unwrap();
        reg
    }

    fn sample_model() -> ModelRef {
        ModelRef {
            name: "acme-7b-chat".to_string(),
            version: "0.3.1".to_string(),
            hash_algorithm: "BLAKE3-256".to_string(),
            hash: [0xABu8; 32],
            size: 1_000,
            format: "safetensors".to_string(),
        }
    }

    fn sample_aibom() -> AiBom {
        let mut b = AiBom::builder(sample_model(), 42);
        b.add_framework(FrameworkRef {
            name: "pytorch".to_string(),
            version: "2.3.1".to_string(),
            cpe: None,
        });
        b.add_dataset(DatasetRef {
            name: "c4-en-v2".to_string(),
            hash_algorithm: Some("BLAKE3-256".to_string()),
            hash: Some([0xCDu8; 32]),
            size: None,
            uri: Some("s3://acme-datasets/c4-en-v2/".to_string()),
            license_spdx_id: Some("ODC-By-1.0".to_string()),
        });
        b.add_license(License {
            spdx_id: "Apache-2.0".to_string(),
            scope: LicenseScope::Weights,
            text_uri: None,
        });
        b.hyperparameter("context_length", json!(8192));
        b.add_export_control(ExportControl {
            regime: "US-ECCN".to_string(),
            classification: "EAR99".to_string(),
            notes: None,
        });
        b.build()
    }

    #[test]
    fn builds_with_schema_version() {
        let aibom = sample_aibom();
        assert_eq!(aibom.schema_version, AIBOM_SCHEMA_VERSION);
    }

    #[test]
    fn json_round_trip_preserves_fields() {
        let aibom = sample_aibom();
        let json = aibom.to_json().unwrap();
        let parsed = AiBom::from_json(&json).unwrap();
        assert_eq!(parsed, aibom);
    }

    #[test]
    fn canonical_bytes_are_deterministic() {
        let aibom = sample_aibom();
        let a = aibom.canonical_bytes().unwrap();
        let b = aibom.canonical_bytes().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn dsse_wrap_and_verify_round_trip() {
        let aibom = sample_aibom();
        let signer = AuthorId::new(1001);
        let key = SigningKey::generate();
        let env = wrap_aibom_dsse(&aibom, signer, &key).unwrap();
        assert_eq!(env.payload_type, AIBOM_PAYLOAD_TYPE);
        let reg = reg_pinning(signer, &key);
        let verified = verify_envelope(&env, &reg, 1).unwrap();
        assert_eq!(verified.len(), 1);
        let back = unwrap_aibom_dsse(&env).unwrap();
        assert_eq!(back, aibom);
    }

    #[test]
    fn unwrap_rejects_wrong_payload_type() {
        let key = SigningKey::generate();
        let env = dsse::sign_envelope(b"not aibom", "text/plain", AuthorId::new(1), &key);
        assert!(unwrap_aibom_dsse(&env).is_err());
    }

    #[test]
    fn hash_field_survives_hex_round_trip() {
        let aibom = sample_aibom();
        let json = aibom.to_json().unwrap();
        let parsed = AiBom::from_json(&json).unwrap();
        assert_eq!(parsed.model.hash, [0xABu8; 32]);
    }

    mod properties {
        use super::*;
        use hegel::generators as gs;

        fn draw_model(tc: &hegel::TestCase) -> ModelRef {
            let hash_v = tc.draw(gs::binary().min_size(32).max_size(32));
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&hash_v);
            ModelRef {
                name: tc.draw(gs::text().max_size(32)),
                version: tc.draw(gs::text().max_size(16)),
                hash_algorithm: "BLAKE3-256".to_string(),
                hash,
                size: tc.draw(gs::integers::<u64>()),
                format: tc.draw(gs::text().max_size(16)),
            }
        }

        fn draw_aibom(tc: &hegel::TestCase) -> AiBom {
            let mut b = AiBom::builder(draw_model(tc), tc.draw(gs::integers::<u64>()));
            let n_frameworks = tc.draw(gs::integers::<usize>().max_value(3));
            for _ in 0..n_frameworks {
                b.add_framework(FrameworkRef {
                    name: tc.draw(gs::text().max_size(16)),
                    version: tc.draw(gs::text().max_size(8)),
                    cpe: None,
                });
            }
            let n_datasets = tc.draw(gs::integers::<usize>().max_value(3));
            for _ in 0..n_datasets {
                b.add_dataset(DatasetRef {
                    name: tc.draw(gs::text().max_size(16)),
                    hash_algorithm: None,
                    hash: None,
                    size: None,
                    uri: None,
                    license_spdx_id: None,
                });
            }
            b.build()
        }

        #[hegel::test]
        fn prop_aibom_json_roundtrip(tc: hegel::TestCase) {
            let aibom = draw_aibom(&tc);
            let json = aibom.to_json().unwrap_or_else(|_| std::process::abort());
            let parsed = AiBom::from_json(&json).unwrap_or_else(|_| std::process::abort());
            assert_eq!(parsed, aibom);
        }

        #[hegel::test]
        fn prop_aibom_canonical_bytes_deterministic(tc: hegel::TestCase) {
            let aibom = draw_aibom(&tc);
            let a = aibom
                .canonical_bytes()
                .unwrap_or_else(|_| std::process::abort());
            let b = aibom
                .canonical_bytes()
                .unwrap_or_else(|_| std::process::abort());
            assert_eq!(a, b);
        }

        #[hegel::test]
        fn prop_aibom_model_hash_survives_json(tc: hegel::TestCase) {
            let aibom = draw_aibom(&tc);
            let expected = aibom.model.hash;
            let json = aibom.to_json().unwrap_or_else(|_| std::process::abort());
            let parsed = AiBom::from_json(&json).unwrap_or_else(|_| std::process::abort());
            assert_eq!(parsed.model.hash, expected);
        }

        #[hegel::test]
        fn prop_aibom_dsse_roundtrip(tc: hegel::TestCase) {
            let aibom = draw_aibom(&tc);
            let signer = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let key = SigningKey::generate();
            let env =
                wrap_aibom_dsse(&aibom, signer, &key).unwrap_or_else(|_| std::process::abort());
            let reg = reg_pinning(signer, &key);
            let verified = verify_envelope(&env, &reg, 1).unwrap_or_else(|_| std::process::abort());
            assert_eq!(verified.len(), 1);
            let back = unwrap_aibom_dsse(&env).unwrap_or_else(|_| std::process::abort());
            assert_eq!(back, aibom);
        }

        #[hegel::test]
        fn prop_aibom_tampered_json_rejects(tc: hegel::TestCase) {
            let aibom = draw_aibom(&tc);
            let signer = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let key = SigningKey::generate();
            let mut env =
                wrap_aibom_dsse(&aibom, signer, &key).unwrap_or_else(|_| std::process::abort());
            let max_idx = env.payload.len().saturating_sub(1);
            let idx = tc.draw(gs::integers::<usize>().max_value(max_idx));
            if let Some(b) = env.payload.get_mut(idx) {
                *b ^= 0x01;
            }
            let reg = reg_pinning(signer, &key);
            assert!(verify_envelope(&env, &reg, 1).is_err());
        }

        #[hegel::test]
        fn prop_aibom_multi_signer_envelope(tc: hegel::TestCase) {
            let aibom = draw_aibom(&tc);
            let s1 = (
                AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 20))),
                SigningKey::generate(),
            );
            let s2 = (
                AuthorId::new(s1.0.as_u64().saturating_add(1)),
                SigningKey::generate(),
            );
            let mut env =
                wrap_aibom_dsse(&aibom, s1.0, &s1.1).unwrap_or_else(|_| std::process::abort());
            dsse::add_signature(&mut env, s2.0, &s2.1);
            let mut reg = KeyRegistry::new();
            for (signer, key) in [(s1.0, &s1.1), (s2.0, &s2.1)] {
                let master = SigningKey::generate();
                reg.register_author(signer, master.verifying_key(), key.verifying_key(), 0)
                    .unwrap_or_else(|_| std::process::abort());
            }
            let verified = verify_envelope(&env, &reg, 1).unwrap_or_else(|_| std::process::abort());
            assert_eq!(verified.len(), 2);
        }

        #[hegel::test]
        fn prop_aibom_payload_type_is_aion_aibom(tc: hegel::TestCase) {
            let aibom = draw_aibom(&tc);
            let signer = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let key = SigningKey::generate();
            let env =
                wrap_aibom_dsse(&aibom, signer, &key).unwrap_or_else(|_| std::process::abort());
            assert_eq!(env.payload_type, AIBOM_PAYLOAD_TYPE);
        }

        #[hegel::test]
        fn prop_aibom_to_jcs_bytes_matches_helper(tc: hegel::TestCase) {
            let aibom = draw_aibom(&tc);
            let from_method = aibom
                .to_jcs_bytes()
                .unwrap_or_else(|_| std::process::abort());
            let from_helper =
                crate::jcs::to_jcs_bytes(&aibom).unwrap_or_else(|_| std::process::abort());
            assert_eq!(from_method, from_helper);
        }
    }
}
