// SPDX-License-Identifier: MIT OR Apache-2.0
//! SLSA v1.1 provenance emitter — RFC-0024.
//!
//! Builds an in-toto Statement carrying a SLSA v1.1 provenance
//! predicate and wraps it in a DSSE envelope ([`crate::dsse`]) so
//! it can be consumed by `slsa-verifier`, cosign, Kyverno, and
//! every other DSSE-aware supply-chain tool.
//!
//! This module does **not** claim any specific SLSA Build level —
//! that's an organizational claim the caller asserts via the
//! `builder.id` and build-type URIs. We emit valid provenance; the
//! level is declared by the consumer's policy.
//!
//! # Example
//!
//! ```
//! use aion_context::manifest::ArtifactManifestBuilder;
//! use aion_context::slsa::SlsaStatementBuilder;
//! use aion_context::dsse::verify_envelope;
//! use aion_context::crypto::SigningKey;
//! use aion_context::key_registry::KeyRegistry;
//! use aion_context::types::AuthorId;
//! use serde_json::json;
//!
//! let mut m = ArtifactManifestBuilder::new();
//! let _ = m.add("model.bin", &vec![0xAA; 32]);
//! let manifest = m.build();
//!
//! let mut b = SlsaStatementBuilder::new("https://example.com/ci/run/1");
//! b.add_all_subjects_from_manifest(&manifest).unwrap();
//! b.external_parameters(json!({"source": "git@example.com/org/repo"}));
//! let statement = b.build().unwrap();
//!
//! let signer = AuthorId::new(42);
//! let master = SigningKey::generate();
//! let key = SigningKey::generate();
//! let mut registry = KeyRegistry::new();
//! registry
//!     .register_author(signer, master.verifying_key(), key.verifying_key(), 0)
//!     .unwrap();
//!
//! let env = aion_context::slsa::wrap_statement_dsse(&statement, signer, &key).unwrap();
//! let verified = verify_envelope(&env, &registry, 1).unwrap();
//! assert_eq!(verified.len(), 1);
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::crypto::SigningKey;
use crate::dsse::{self, DsseEnvelope};
use crate::manifest::{ArtifactEntry, ArtifactManifest};
use crate::types::AuthorId;
use crate::{AionError, Result};

/// `_type` for in-toto Statements v1.
pub const IN_TOTO_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// `predicateType` for SLSA v1.1 provenance predicates.
pub const SLSA_V1_PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";

/// DSSE `payloadType` for in-toto Statements (any version).
pub const IN_TOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// Default build-type URI for generic aion-produced provenance.
pub const AION_DEFAULT_BUILD_TYPE: &str = "https://aion-context.dev/buildtypes/generic/v1";

/// Digest algorithm label used in subjects and resource descriptors.
pub const BLAKE3_DIGEST_KEY: &str = "blake3-256";

/// An in-toto Subject: an artifact identified by name + digest map.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Subject {
    /// Artifact name (file-path-like).
    pub name: String,
    /// Map of digest algorithm → lowercase hex digest.
    pub digest: BTreeMap<String, String>,
}

/// in-toto v1 `ResourceDescriptor` — used for resolvedDependencies,
/// byproducts, and related lists. All fields optional per spec.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceDescriptor {
    /// Optional name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// Optional digest map.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<BTreeMap<String, String>>,
    /// Optional media type.
    #[serde(rename = "mediaType", skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
}

/// SLSA v1.1 Builder identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Builder {
    /// URI identifying the builder (e.g. CI workflow URL).
    pub id: String,
}

/// SLSA v1.1 `BuildDefinition` block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildDefinition {
    /// URI for the build type schema.
    #[serde(rename = "buildType")]
    pub build_type: String,
    /// Caller-provided parameters the build was invoked with.
    #[serde(rename = "externalParameters")]
    pub external_parameters: serde_json::Value,
    /// Internal parameters (private to the builder).
    #[serde(
        rename = "internalParameters",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub internal_parameters: Option<serde_json::Value>,
    /// Resolved dependencies (source, tools, containers, ...).
    #[serde(rename = "resolvedDependencies", default)]
    pub resolved_dependencies: Vec<ResourceDescriptor>,
}

/// SLSA v1.1 metadata about the build invocation.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildMetadata {
    /// Invocation identifier (CI run id, etc.).
    #[serde(rename = "invocationId", skip_serializing_if = "Option::is_none")]
    pub invocation_id: Option<String>,
    /// RFC 3339 start timestamp.
    #[serde(rename = "startedOn", skip_serializing_if = "Option::is_none")]
    pub started_on: Option<String>,
    /// RFC 3339 finish timestamp.
    #[serde(rename = "finishedOn", skip_serializing_if = "Option::is_none")]
    pub finished_on: Option<String>,
}

/// SLSA v1.1 `RunDetails` block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunDetails {
    /// Identity of the builder that produced this provenance.
    pub builder: Builder,
    /// Optional invocation metadata.
    #[serde(default, skip_serializing_if = "is_default_metadata")]
    pub metadata: BuildMetadata,
    /// Optional byproducts (logs, intermediate artifacts).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub byproducts: Vec<ResourceDescriptor>,
}

const fn is_default_metadata(m: &BuildMetadata) -> bool {
    m.invocation_id.is_none() && m.started_on.is_none() && m.finished_on.is_none()
}

/// SLSA v1.1 provenance predicate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlsaProvenancePredicate {
    /// The build definition.
    #[serde(rename = "buildDefinition")]
    pub build_definition: BuildDefinition,
    /// Details about the invocation.
    #[serde(rename = "runDetails")]
    pub run_details: RunDetails,
}

/// in-toto v1 Statement wrapping a SLSA provenance predicate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InTotoStatement {
    /// Always [`IN_TOTO_STATEMENT_TYPE`].
    #[serde(rename = "_type")]
    pub type_uri: String,
    /// The artifacts this statement attests to.
    pub subject: Vec<Subject>,
    /// Predicate type URI.
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    /// The predicate body.
    pub predicate: SlsaProvenancePredicate,
}

impl InTotoStatement {
    /// Serialise to JSON.
    ///
    /// # Errors
    ///
    /// Propagates `serde_json` errors.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| AionError::InvalidFormat {
            reason: format!("in-toto Statement JSON serialization failed: {e}"),
        })
    }

    /// Canonical bytes used for DSSE PAE.
    ///
    /// # Errors
    ///
    /// Propagates `serde_json` errors.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| AionError::InvalidFormat {
            reason: format!("in-toto Statement canonical serialization failed: {e}"),
        })
    }

    /// RFC 8785 (JCS) canonical bytes — use when cross-implementation
    /// byte stability matters (Phase B of RFC-0031). Opt-in;
    /// [`Self::canonical_bytes`] remains the signature-stable form
    /// for historical DSSE envelopes.
    ///
    /// # Errors
    ///
    /// Propagates serialization errors from [`crate::jcs`].
    pub fn to_jcs_bytes(&self) -> Result<Vec<u8>> {
        crate::jcs::to_jcs_bytes(self)
    }

    /// Parse from JSON.
    ///
    /// # Errors
    ///
    /// Returns `Err` for malformed JSON or schema mismatches.
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|e| AionError::InvalidFormat {
            reason: format!("in-toto Statement JSON parse failed: {e}"),
        })
    }
}

/// Fluent builder for [`InTotoStatement`].
#[derive(Debug)]
pub struct SlsaStatementBuilder {
    subjects: Vec<Subject>,
    build_type: String,
    builder_id: String,
    external_parameters: serde_json::Value,
    internal_parameters: Option<serde_json::Value>,
    resolved_dependencies: Vec<ResourceDescriptor>,
    metadata: BuildMetadata,
    byproducts: Vec<ResourceDescriptor>,
}

impl SlsaStatementBuilder {
    /// Start a new builder. `builder_id` is the URI identifying the
    /// build system and is mandatory per SLSA v1.1.
    #[must_use]
    pub fn new(builder_id: impl Into<String>) -> Self {
        Self {
            subjects: Vec::new(),
            build_type: AION_DEFAULT_BUILD_TYPE.to_string(),
            builder_id: builder_id.into(),
            external_parameters: serde_json::json!({}),
            internal_parameters: None,
            resolved_dependencies: Vec::new(),
            metadata: BuildMetadata::default(),
            byproducts: Vec::new(),
        }
    }

    /// Override the default buildType URI.
    pub fn build_type(&mut self, uri: impl Into<String>) -> &mut Self {
        self.build_type = uri.into();
        self
    }

    /// Set the build's externalParameters.
    pub fn external_parameters(&mut self, params: serde_json::Value) -> &mut Self {
        self.external_parameters = params;
        self
    }

    /// Set the build's internalParameters.
    pub fn internal_parameters(&mut self, params: serde_json::Value) -> &mut Self {
        self.internal_parameters = Some(params);
        self
    }

    /// Append a resolved dependency.
    pub fn add_resolved_dependency(&mut self, descriptor: ResourceDescriptor) -> &mut Self {
        self.resolved_dependencies.push(descriptor);
        self
    }

    /// Append a byproduct.
    pub fn add_byproduct(&mut self, descriptor: ResourceDescriptor) -> &mut Self {
        self.byproducts.push(descriptor);
        self
    }

    /// Set the invocation id.
    pub fn invocation_id(&mut self, id: impl Into<String>) -> &mut Self {
        self.metadata.invocation_id = Some(id.into());
        self
    }

    /// Set the start timestamp (RFC 3339).
    pub fn started_on(&mut self, ts: impl Into<String>) -> &mut Self {
        self.metadata.started_on = Some(ts.into());
        self
    }

    /// Set the finish timestamp (RFC 3339).
    pub fn finished_on(&mut self, ts: impl Into<String>) -> &mut Self {
        self.metadata.finished_on = Some(ts.into());
        self
    }

    /// Append a subject derived from one manifest entry.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the entry's name cannot be decoded from the
    /// manifest name table.
    pub fn add_subject_from_entry(
        &mut self,
        manifest: &ArtifactManifest,
        entry: &ArtifactEntry,
    ) -> Result<&mut Self> {
        let name = manifest.name_of(entry)?.to_string();
        let mut digest = BTreeMap::new();
        digest.insert(BLAKE3_DIGEST_KEY.to_string(), hex::encode(entry.hash));
        self.subjects.push(Subject { name, digest });
        Ok(self)
    }

    /// Append subjects for every entry in `manifest`.
    ///
    /// # Errors
    ///
    /// Propagates any name-table decoding error from
    /// [`Self::add_subject_from_entry`].
    pub fn add_all_subjects_from_manifest(
        &mut self,
        manifest: &ArtifactManifest,
    ) -> Result<&mut Self> {
        // Collect names first to avoid holding a borrow of `manifest`
        // across the mutable self.subjects.push inside the loop.
        let mut entries: Vec<(String, [u8; 32])> = Vec::with_capacity(manifest.entries().len());
        for entry in manifest.entries() {
            entries.push((manifest.name_of(entry)?.to_string(), entry.hash));
        }
        for (name, digest_bytes) in entries {
            let mut digest = BTreeMap::new();
            digest.insert(BLAKE3_DIGEST_KEY.to_string(), hex::encode(digest_bytes));
            self.subjects.push(Subject { name, digest });
        }
        Ok(self)
    }

    /// Finalize into a validated [`InTotoStatement`].
    ///
    /// # Errors
    ///
    /// Returns `Err` if no subjects were registered or if `builder_id`
    /// is empty — both are required by SLSA v1.1.
    pub fn build(self) -> Result<InTotoStatement> {
        if self.subjects.is_empty() {
            return Err(AionError::InvalidFormat {
                reason: "SLSA Statement must have at least one subject".to_string(),
            });
        }
        if self.builder_id.is_empty() {
            return Err(AionError::InvalidFormat {
                reason: "SLSA Statement requires a non-empty builder.id".to_string(),
            });
        }
        Ok(InTotoStatement {
            type_uri: IN_TOTO_STATEMENT_TYPE.to_string(),
            subject: self.subjects,
            predicate_type: SLSA_V1_PREDICATE_TYPE.to_string(),
            predicate: SlsaProvenancePredicate {
                build_definition: BuildDefinition {
                    build_type: self.build_type,
                    external_parameters: self.external_parameters,
                    internal_parameters: self.internal_parameters,
                    resolved_dependencies: self.resolved_dependencies,
                },
                run_details: RunDetails {
                    builder: Builder {
                        id: self.builder_id,
                    },
                    metadata: self.metadata,
                    byproducts: self.byproducts,
                },
            },
        })
    }
}

/// Wrap a statement in a DSSE envelope signed by `signer`.
///
/// The payload type is always [`IN_TOTO_PAYLOAD_TYPE`], matching
/// what every DSSE-aware SLSA verifier expects.
///
/// # Errors
///
/// Propagates JSON serialization errors.
pub fn wrap_statement_dsse(
    statement: &InTotoStatement,
    signer: AuthorId,
    key: &SigningKey,
) -> Result<DsseEnvelope> {
    let payload = statement.canonical_bytes()?;
    Ok(dsse::sign_envelope(
        &payload,
        IN_TOTO_PAYLOAD_TYPE,
        signer,
        key,
    ))
}

/// Unwrap a DSSE envelope that is known to carry an in-toto Statement.
///
/// The caller is expected to separately verify the DSSE signature via
/// [`crate::dsse::verify_envelope`] before trusting the statement
/// contents.
///
/// # Errors
///
/// Returns `Err` if the envelope's `payloadType` is not
/// [`IN_TOTO_PAYLOAD_TYPE`] or if the payload bytes fail to parse as
/// an in-toto Statement.
pub fn unwrap_statement_dsse(envelope: &DsseEnvelope) -> Result<InTotoStatement> {
    if envelope.payload_type != IN_TOTO_PAYLOAD_TYPE {
        return Err(AionError::InvalidFormat {
            reason: format!(
                "envelope payloadType is '{}', expected '{}'",
                envelope.payload_type, IN_TOTO_PAYLOAD_TYPE
            ),
        });
    }
    let payload_str =
        std::str::from_utf8(&envelope.payload).map_err(|e| AionError::InvalidFormat {
            reason: format!("envelope payload is not valid UTF-8: {e}"),
        })?;
    InTotoStatement::from_json(payload_str)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dsse::verify_envelope;
    use crate::key_registry::KeyRegistry;
    use crate::manifest::ArtifactManifestBuilder;
    use serde_json::json;

    /// Pin `signer` with `key` as the active op pubkey at epoch 0.
    fn reg_pinning(signer: AuthorId, key: &SigningKey) -> KeyRegistry {
        let mut reg = KeyRegistry::new();
        let master = SigningKey::generate();
        reg.register_author(signer, master.verifying_key(), key.verifying_key(), 0)
            .unwrap();
        reg
    }

    fn build_sample_manifest() -> ArtifactManifest {
        let mut m = ArtifactManifestBuilder::new();
        let _ = m.add("model.bin", &[0xAAu8; 32]);
        let _ = m.add("tokenizer.json", b"{}");
        m.build()
    }

    #[test]
    fn should_build_minimal_statement() {
        let manifest = build_sample_manifest();
        let mut b = SlsaStatementBuilder::new("https://example.com/ci/1");
        b.add_all_subjects_from_manifest(&manifest).unwrap();
        let statement = b.build().unwrap();
        assert_eq!(statement.type_uri, IN_TOTO_STATEMENT_TYPE);
        assert_eq!(statement.predicate_type, SLSA_V1_PREDICATE_TYPE);
        assert_eq!(statement.subject.len(), 2);
        assert_eq!(
            statement.predicate.build_definition.build_type,
            AION_DEFAULT_BUILD_TYPE
        );
    }

    #[test]
    fn should_reject_empty_subjects() {
        let b = SlsaStatementBuilder::new("https://example.com/ci/1");
        assert!(b.build().is_err());
    }

    #[test]
    fn should_reject_empty_builder_id() {
        let manifest = build_sample_manifest();
        let mut b = SlsaStatementBuilder::new("");
        b.add_all_subjects_from_manifest(&manifest).unwrap();
        assert!(b.build().is_err());
    }

    #[test]
    fn should_round_trip_through_json() {
        let manifest = build_sample_manifest();
        let mut b = SlsaStatementBuilder::new("https://example.com/ci/1");
        b.add_all_subjects_from_manifest(&manifest).unwrap();
        b.external_parameters(json!({"source": "git@example.com/org/repo"}));
        b.invocation_id("run-42");
        let statement = b.build().unwrap();
        let json = statement.to_json().unwrap();
        let parsed = InTotoStatement::from_json(&json).unwrap();
        assert_eq!(parsed, statement);
    }

    #[test]
    fn should_wrap_and_verify_via_dsse() {
        let manifest = build_sample_manifest();
        let mut b = SlsaStatementBuilder::new("https://example.com/ci/1");
        b.add_all_subjects_from_manifest(&manifest).unwrap();
        let statement = b.build().unwrap();
        let signer = AuthorId::new(42);
        let key = SigningKey::generate();
        let env = wrap_statement_dsse(&statement, signer, &key).unwrap();
        assert_eq!(env.payload_type, IN_TOTO_PAYLOAD_TYPE);
        let reg = reg_pinning(signer, &key);
        let verified = verify_envelope(&env, &reg, 1).unwrap();
        assert_eq!(verified.len(), 1);
        let back = unwrap_statement_dsse(&env).unwrap();
        assert_eq!(back, statement);
    }

    #[test]
    fn should_reject_unwrap_with_wrong_payload_type() {
        let key = SigningKey::generate();
        let signer = AuthorId::new(1);
        let env = dsse::sign_envelope(b"not a statement", "text/plain", signer, &key);
        assert!(unwrap_statement_dsse(&env).is_err());
    }

    #[test]
    fn subject_digest_uses_blake3_label() {
        let manifest = build_sample_manifest();
        let entry = manifest.entries().first().unwrap();
        let mut b = SlsaStatementBuilder::new("https://example.com/ci/1");
        b.add_subject_from_entry(&manifest, entry).unwrap();
        let statement = b.build().unwrap();
        let subject = statement.subject.first().unwrap();
        assert!(subject.digest.contains_key(BLAKE3_DIGEST_KEY));
        assert_eq!(
            subject.digest.get(BLAKE3_DIGEST_KEY).unwrap(),
            &hex::encode(entry.hash)
        );
    }

    mod properties {
        use super::*;
        use crate::crypto::VerifyingKey;
        use hegel::generators as gs;

        fn draw_manifest(tc: &hegel::TestCase) -> ArtifactManifest {
            let n = tc.draw(gs::integers::<usize>().min_value(1).max_value(4));
            let mut b = ArtifactManifestBuilder::new();
            let mut counter: u64 = 0;
            for _ in 0..n {
                let bytes = tc.draw(gs::binary().max_size(256));
                let name = format!("artifact_{counter}");
                counter = counter.saturating_add(1);
                let _ = b.add(&name, &bytes);
            }
            b.build()
        }

        #[hegel::test]
        fn prop_slsa_dsse_roundtrip(tc: hegel::TestCase) {
            let manifest = draw_manifest(&tc);
            let mut builder = SlsaStatementBuilder::new("https://example.com/ci/1");
            builder
                .add_all_subjects_from_manifest(&manifest)
                .unwrap_or_else(|_| std::process::abort());
            let statement = builder.build().unwrap_or_else(|_| std::process::abort());
            let signer = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let key = SigningKey::generate();
            let env = wrap_statement_dsse(&statement, signer, &key)
                .unwrap_or_else(|_| std::process::abort());
            let reg = reg_pinning(signer, &key);
            let verified = verify_envelope(&env, &reg, 1).unwrap_or_else(|_| std::process::abort());
            assert_eq!(verified.len(), 1);
            let roundtripped =
                unwrap_statement_dsse(&env).unwrap_or_else(|_| std::process::abort());
            assert_eq!(roundtripped, statement);
        }

        #[hegel::test]
        fn prop_slsa_manifest_binding_survives_json(tc: hegel::TestCase) {
            let manifest = draw_manifest(&tc);
            let mut builder = SlsaStatementBuilder::new("https://example.com/ci/1");
            builder
                .add_all_subjects_from_manifest(&manifest)
                .unwrap_or_else(|_| std::process::abort());
            let statement = builder.build().unwrap_or_else(|_| std::process::abort());
            let json = statement
                .to_json()
                .unwrap_or_else(|_| std::process::abort());
            let parsed =
                InTotoStatement::from_json(&json).unwrap_or_else(|_| std::process::abort());
            assert_eq!(parsed.subject.len(), manifest.entries().len());
            for (subject, entry) in parsed.subject.iter().zip(manifest.entries().iter()) {
                let expected = hex::encode(entry.hash);
                let got = subject
                    .digest
                    .get(BLAKE3_DIGEST_KEY)
                    .unwrap_or_else(|| std::process::abort());
                assert_eq!(got, &expected);
            }
        }

        #[hegel::test]
        fn prop_slsa_tampered_subject_digest_rejects(tc: hegel::TestCase) {
            let manifest = draw_manifest(&tc);
            let mut builder = SlsaStatementBuilder::new("https://example.com/ci/1");
            builder
                .add_all_subjects_from_manifest(&manifest)
                .unwrap_or_else(|_| std::process::abort());
            let statement = builder.build().unwrap_or_else(|_| std::process::abort());
            let signer = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let key = SigningKey::generate();
            let mut env = wrap_statement_dsse(&statement, signer, &key)
                .unwrap_or_else(|_| std::process::abort());
            // Flip a byte in the payload (the JSON body) → verification fails.
            let max = env.payload.len().saturating_sub(1);
            let idx = tc.draw(gs::integers::<usize>().max_value(max));
            if let Some(b) = env.payload.get_mut(idx) {
                *b ^= 0x01;
            }
            let reg = reg_pinning(signer, &key);
            let result: Result<Vec<String>> = verify_envelope(&env, &reg, 1);
            assert!(result.is_err());
        }

        #[hegel::test]
        fn prop_slsa_envelope_payload_type_is_in_toto(tc: hegel::TestCase) {
            let manifest = draw_manifest(&tc);
            let mut builder = SlsaStatementBuilder::new("https://example.com/ci/1");
            builder
                .add_all_subjects_from_manifest(&manifest)
                .unwrap_or_else(|_| std::process::abort());
            let statement = builder.build().unwrap_or_else(|_| std::process::abort());
            let signer = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let key = SigningKey::generate();
            let env = wrap_statement_dsse(&statement, signer, &key)
                .unwrap_or_else(|_| std::process::abort());
            assert_eq!(env.payload_type, IN_TOTO_PAYLOAD_TYPE);
            // Suppress `unused` for the signer variable path and keep
            // the VerifyingKey import live in test builds.
            let _ = signer;
            let _: fn() -> Option<VerifyingKey> = || None;
        }

        #[hegel::test]
        fn prop_slsa_statement_to_jcs_bytes_matches_helper(tc: hegel::TestCase) {
            let manifest = draw_manifest(&tc);
            let mut builder = SlsaStatementBuilder::new("https://example.com/ci/1");
            builder
                .add_all_subjects_from_manifest(&manifest)
                .unwrap_or_else(|_| std::process::abort());
            let statement = builder.build().unwrap_or_else(|_| std::process::abort());
            let from_method = statement
                .to_jcs_bytes()
                .unwrap_or_else(|_| std::process::abort());
            let from_helper =
                crate::jcs::to_jcs_bytes(&statement).unwrap_or_else(|_| std::process::abort());
            assert_eq!(from_method, from_helper);
        }
    }
}
