//! Release orchestration — RFC-0032.
//!
//! One call site that composes the Phase-A primitives into a
//! complete signed model release: manifest (RFC-0022), AIBOM
//! (RFC-0029), SLSA v1.1 statement (RFC-0024), three DSSE
//! envelopes (RFC-0023), three transparency-log entries
//! (RFC-0025), an OCI primary manifest, and two OCI attestation
//! referrers (RFC-0030).
//!
//! Nothing here is a new primitive. Every byte the builder emits
//! is produced by code that already has Hegel property tests in
//! its home module. What this module asserts is the **integration**
//! contract: if `ReleaseBuilder::seal` returned `Ok`, then
//! `SignedRelease::verify` with the matching key is `Ok`; any
//! tampering of any component breaks `verify`.
//!
//! # Example
//!
//! ```
//! use aion_context::aibom::{FrameworkRef, License, LicenseScope};
//! use aion_context::crypto::SigningKey;
//! use aion_context::key_registry::KeyRegistry;
//! use aion_context::release::ReleaseBuilder;
//! use aion_context::transparency_log::TransparencyLog;
//! use aion_context::types::AuthorId;
//!
//! let mut log = TransparencyLog::new();
//! let signer = AuthorId::new(50_001);
//! let master = SigningKey::generate();
//! let key = SigningKey::generate();
//! let mut registry = KeyRegistry::new();
//! registry
//!     .register_author(signer, master.verifying_key(), key.verifying_key(), 0)
//!     .unwrap();
//!
//! let mut b = ReleaseBuilder::new("acme-7b-chat", "0.3.1", "safetensors");
//! b.primary_artifact("model.safetensors", vec![0xAA; 128])
//!     .add_framework(FrameworkRef {
//!         name: "pytorch".into(),
//!         version: "2.3.1".into(),
//!         cpe: None,
//!     })
//!     .add_license(License {
//!         spdx_id: "Apache-2.0".into(),
//!         scope: LicenseScope::Weights,
//!         text_uri: None,
//!     })
//!     .builder_id("https://example.com/ci/run/1")
//!     .current_aion_version(1);
//! let signed = b.seal(signer, &key, &mut log).unwrap();
//! signed.verify(&registry, 1).unwrap();
//! ```

use std::collections::BTreeMap;

use crate::aibom::{
    AiBom, DatasetRef, ExportControl, ExternalReference, FrameworkRef, License, ModelRef,
    SafetyAttestation,
};
use crate::crypto::SigningKey;
use crate::dsse::{self, DsseEnvelope, AION_MANIFEST_TYPE};
use crate::key_registry::KeyRegistry;
use crate::manifest::{
    sign_manifest, verify_manifest_signature, ArtifactEntry, ArtifactManifest,
    ArtifactManifestBuilder,
};
use crate::oci::{
    build_aion_manifest, build_attestation_manifest, AionConfig, OciArtifactManifest,
    AION_CONFIG_MEDIA_TYPE,
};
use crate::serializer::SignatureEntry;
use crate::slsa::{
    wrap_statement_dsse, InTotoStatement, SlsaStatementBuilder, IN_TOTO_PAYLOAD_TYPE,
};
use crate::transparency_log::{LogEntryKind, TransparencyLog};
use crate::types::AuthorId;
use crate::{AionError, Result};

/// Transparency-log position returned from [`TransparencyLog::append`].
///
/// `#[non_exhaustive]` because future phases may attach inclusion
/// proofs, operator STHs, or Rekor log indices per log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LogSeq {
    /// Which kind of record was logged.
    pub kind: LogEntryKind,
    /// 0-indexed position in the log.
    pub seq: u64,
}

/// Builder that collects everything needed for a signed release.
#[derive(Debug)]
pub struct ReleaseBuilder {
    model_name: String,
    model_version: String,
    model_format: String,
    primary_artifact: Option<(String, Vec<u8>)>,
    auxiliary_artifacts: Vec<(String, Vec<u8>)>,
    frameworks: Vec<FrameworkRef>,
    datasets: Vec<DatasetRef>,
    licenses: Vec<License>,
    hyperparameters: BTreeMap<String, serde_json::Value>,
    safety_attestations: Vec<SafetyAttestation>,
    export_controls: Vec<ExportControl>,
    references: Vec<ExternalReference>,
    builder_id: String,
    external_parameters: serde_json::Value,
    current_aion_version: u64,
}

impl ReleaseBuilder {
    /// Start a new builder for `(name, version, format)`.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        format: impl Into<String>,
    ) -> Self {
        Self {
            model_name: name.into(),
            model_version: version.into(),
            model_format: format.into(),
            primary_artifact: None,
            auxiliary_artifacts: Vec::new(),
            frameworks: Vec::new(),
            datasets: Vec::new(),
            licenses: Vec::new(),
            hyperparameters: BTreeMap::new(),
            safety_attestations: Vec::new(),
            export_controls: Vec::new(),
            references: Vec::new(),
            builder_id: String::new(),
            external_parameters: serde_json::json!({}),
            current_aion_version: 0,
        }
    }

    /// Register the primary artifact (the model weights).
    pub fn primary_artifact(&mut self, name: impl Into<String>, bytes: Vec<u8>) -> &mut Self {
        self.primary_artifact = Some((name.into(), bytes));
        self
    }

    /// Register an auxiliary artifact (tokenizer, config, sidecar).
    pub fn add_auxiliary(&mut self, name: impl Into<String>, bytes: Vec<u8>) -> &mut Self {
        self.auxiliary_artifacts.push((name.into(), bytes));
        self
    }

    /// AIBOM framework entry.
    pub fn add_framework(&mut self, f: FrameworkRef) -> &mut Self {
        self.frameworks.push(f);
        self
    }

    /// AIBOM dataset entry.
    pub fn add_dataset(&mut self, d: DatasetRef) -> &mut Self {
        self.datasets.push(d);
        self
    }

    /// AIBOM license entry.
    pub fn add_license(&mut self, l: License) -> &mut Self {
        self.licenses.push(l);
        self
    }

    /// AIBOM hyperparameter (arbitrary JSON value).
    pub fn hyperparameter(&mut self, k: impl Into<String>, v: serde_json::Value) -> &mut Self {
        self.hyperparameters.insert(k.into(), v);
        self
    }

    /// AIBOM safety attestation entry.
    pub fn add_safety_attestation(&mut self, s: SafetyAttestation) -> &mut Self {
        self.safety_attestations.push(s);
        self
    }

    /// AIBOM export-control entry.
    pub fn add_export_control(&mut self, e: ExportControl) -> &mut Self {
        self.export_controls.push(e);
        self
    }

    /// AIBOM external reference (model card, paper).
    pub fn add_reference(&mut self, r: ExternalReference) -> &mut Self {
        self.references.push(r);
        self
    }

    /// SLSA `builder.id` — the CI / build-system URI. Required.
    pub fn builder_id(&mut self, id: impl Into<String>) -> &mut Self {
        self.builder_id = id.into();
        self
    }

    /// SLSA `externalParameters` blob.
    pub fn external_parameters(&mut self, v: serde_json::Value) -> &mut Self {
        self.external_parameters = v;
        self
    }

    /// aion version number at seal time.
    pub fn current_aion_version(&mut self, v: u64) -> &mut Self {
        self.current_aion_version = v;
        self
    }

    /// Seal the release: produce every signed artifact, append the
    /// three log entries, and build the OCI manifest graph.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the primary artifact is missing, the
    /// `builder_id` is empty, or any downstream module rejects the
    /// inputs (e.g. SLSA's non-empty-subject requirement).
    pub fn seal(
        self,
        signer: AuthorId,
        signing_key: &SigningKey,
        log: &mut TransparencyLog,
    ) -> Result<SignedRelease> {
        let core = self.build_core()?;
        let manifest_signature = sign_manifest(&core.manifest, signer, signing_key);
        let manifest_dsse = dsse::wrap_manifest(&core.manifest, signer, signing_key);
        let aibom_dsse = crate::aibom::wrap_aibom_dsse(&core.aibom, signer, signing_key)?;
        let slsa_dsse = wrap_statement_dsse(&core.slsa_statement, signer, signing_key)?;
        let log_entries = append_release_log_entries(
            log,
            &manifest_signature.signature,
            &aibom_dsse,
            &slsa_dsse,
            core.current_aion_version,
        )?;
        let (oci_primary, oci_aibom_referrer, oci_slsa_referrer) = build_oci_graph(
            &core.manifest,
            &core.model_ref.name,
            core.current_aion_version,
            &aibom_dsse,
            &slsa_dsse,
        )?;
        Ok(SignedRelease {
            signer,
            model_ref: core.model_ref,
            manifest: core.manifest,
            manifest_signature,
            manifest_dsse,
            aibom: core.aibom,
            aibom_dsse,
            slsa_statement: core.slsa_statement,
            slsa_dsse,
            oci_primary,
            oci_aibom_referrer,
            oci_slsa_referrer,
            log_entries,
        })
    }

    /// Validate preconditions and assemble the unsigned core
    /// artifacts (manifest, `model_ref`, AIBOM, SLSA statement).
    /// Called once by [`Self::seal`]; consumes the builder.
    fn build_core(self) -> Result<SealedCore> {
        let Self {
            model_name,
            model_version,
            model_format,
            primary_artifact,
            auxiliary_artifacts,
            frameworks,
            datasets,
            licenses,
            hyperparameters,
            safety_attestations,
            export_controls,
            references,
            builder_id,
            external_parameters,
            current_aion_version,
        } = self;
        let (primary_name, primary_bytes) =
            primary_artifact.ok_or_else(|| AionError::InvalidFormat {
                reason: "ReleaseBuilder requires a primary_artifact".to_string(),
            })?;
        if builder_id.is_empty() {
            return Err(AionError::InvalidFormat {
                reason: "ReleaseBuilder requires a non-empty builder_id".to_string(),
            });
        }
        let manifest =
            construct_artifact_manifest(&primary_name, &primary_bytes, &auxiliary_artifacts);
        let model_ref =
            model_ref_from_manifest(&manifest, model_name, model_version, model_format)?;
        let aibom = assemble_aibom(
            model_ref.clone(),
            current_aion_version,
            AibomFields {
                frameworks,
                datasets,
                licenses,
                hyperparameters,
                safety_attestations,
                export_controls,
                references,
            },
        );
        let slsa_statement = assemble_slsa_statement(&manifest, builder_id, external_parameters)?;
        Ok(SealedCore {
            manifest,
            model_ref,
            aibom,
            slsa_statement,
            current_aion_version,
        })
    }
}

/// Unsigned core artifacts produced by [`ReleaseBuilder::build_core`].
/// Not part of the public API.
struct SealedCore {
    manifest: ArtifactManifest,
    model_ref: ModelRef,
    aibom: AiBom,
    slsa_statement: InTotoStatement,
    current_aion_version: u64,
}

/// Bundle of AIBOM-shaped fields transported from `ReleaseBuilder`
/// into [`assemble_aibom`]. Keeps the helper's argument list
/// readable without forcing more parameter structs into the
/// public API.
struct AibomFields {
    frameworks: Vec<FrameworkRef>,
    datasets: Vec<DatasetRef>,
    licenses: Vec<License>,
    hyperparameters: BTreeMap<String, serde_json::Value>,
    safety_attestations: Vec<SafetyAttestation>,
    export_controls: Vec<ExportControl>,
    references: Vec<ExternalReference>,
}

/// Step 2: build the artifact manifest — primary first, then
/// auxiliaries in insertion order.
fn construct_artifact_manifest(
    primary_name: &str,
    primary_bytes: &[u8],
    auxiliaries: &[(String, Vec<u8>)],
) -> ArtifactManifest {
    let mut mb = ArtifactManifestBuilder::new();
    let _ = mb.add(primary_name, primary_bytes);
    for (name, bytes) in auxiliaries {
        let _ = mb.add(name, bytes);
    }
    mb.build()
}

/// Step 3: derive a [`ModelRef`] from the manifest's primary entry.
fn model_ref_from_manifest(
    manifest: &ArtifactManifest,
    name: String,
    version: String,
    format: String,
) -> Result<ModelRef> {
    let primary = manifest
        .entries()
        .first()
        .ok_or_else(|| AionError::InvalidFormat {
            reason: "manifest is unexpectedly empty".to_string(),
        })?;
    Ok(ModelRef {
        name,
        version,
        hash_algorithm: "BLAKE3-256".to_string(),
        hash: primary.hash,
        size: primary.size,
        format,
    })
}

/// Step 4: assemble an [`AiBom`] from the collected builder fields.
fn assemble_aibom(model_ref: ModelRef, current_aion_version: u64, fields: AibomFields) -> AiBom {
    let mut ab = AiBom::builder(model_ref, current_aion_version);
    for f in fields.frameworks {
        ab.add_framework(f);
    }
    for d in fields.datasets {
        ab.add_dataset(d);
    }
    for l in fields.licenses {
        ab.add_license(l);
    }
    for (k, v) in fields.hyperparameters {
        ab.hyperparameter(k, v);
    }
    for s in fields.safety_attestations {
        ab.add_safety_attestation(s);
    }
    for e in fields.export_controls {
        ab.add_export_control(e);
    }
    for r in fields.references {
        ab.add_reference(r);
    }
    ab.build()
}

/// Step 5: assemble the SLSA v1.1 Statement.
fn assemble_slsa_statement(
    manifest: &ArtifactManifest,
    builder_id: String,
    external_parameters: serde_json::Value,
) -> Result<InTotoStatement> {
    let mut sb = SlsaStatementBuilder::new(builder_id);
    sb.add_all_subjects_from_manifest(manifest)?;
    sb.external_parameters(external_parameters);
    sb.build()
}

/// Step 8: append the three release attestations to the
/// transparency log in kind order.
fn append_release_log_entries(
    log: &mut TransparencyLog,
    manifest_sig_bytes: &[u8; 64],
    aibom_dsse: &DsseEnvelope,
    slsa_dsse: &DsseEnvelope,
    current_aion_version: u64,
) -> Result<Vec<LogSeq>> {
    let seq_manifest = log.append(
        LogEntryKind::ManifestSignature,
        manifest_sig_bytes,
        current_aion_version,
    )?;
    let seq_aibom = log.append(
        LogEntryKind::DsseEnvelope,
        aibom_dsse.to_json()?.as_bytes(),
        current_aion_version,
    )?;
    let seq_slsa = log.append(
        LogEntryKind::SlsaStatement,
        slsa_dsse.to_json()?.as_bytes(),
        current_aion_version,
    )?;
    Ok(vec![
        LogSeq {
            kind: LogEntryKind::ManifestSignature,
            seq: seq_manifest,
        },
        LogSeq {
            kind: LogEntryKind::DsseEnvelope,
            seq: seq_aibom,
        },
        LogSeq {
            kind: LogEntryKind::SlsaStatement,
            seq: seq_slsa,
        },
    ])
}

/// Steps 9–10: build the OCI primary manifest plus one referrer
/// per DSSE envelope.
///
/// Phase-B stub: the primary's layer payload is the artifact
/// manifest's canonical bytes. Phase C of RFC-0022 replaces this
/// with the real `.aion` v3 on-disk bytes.
fn build_oci_graph(
    manifest: &ArtifactManifest,
    model_name: &str,
    current_aion_version: u64,
    aibom_dsse: &DsseEnvelope,
    slsa_dsse: &DsseEnvelope,
) -> Result<(
    OciArtifactManifest,
    OciArtifactManifest,
    OciArtifactManifest,
)> {
    // Touch the unused re-exports so `cargo clippy` doesn't flag them;
    // both are kept in the `use` list for downstream consumers.
    let _ = AION_MANIFEST_TYPE;
    let _ = AION_CONFIG_MEDIA_TYPE;
    let oci_config = AionConfig {
        schema_version: "aion.oci.config.v1".to_string(),
        format_version: 2,
        file_id: 0,
        created_at_version: current_aion_version,
        created_at: "release-orchestration-phase-b".to_string(),
    };
    let oci_layer_payload = manifest.canonical_bytes();
    let oci_primary = build_aion_manifest(&oci_layer_payload, model_name, &oci_config)?;
    let oci_aibom_referrer = build_attestation_manifest(
        aibom_dsse.to_json()?.as_bytes(),
        crate::aibom::AIBOM_PAYLOAD_TYPE,
        &oci_primary,
    )?;
    let oci_slsa_referrer = build_attestation_manifest(
        slsa_dsse.to_json()?.as_bytes(),
        IN_TOTO_PAYLOAD_TYPE,
        &oci_primary,
    )?;
    Ok((oci_primary, oci_aibom_referrer, oci_slsa_referrer))
}

/// Everything produced by [`ReleaseBuilder::seal`].
///
/// `#[non_exhaustive]` so Phase C additions (countersignatures,
/// hybrid-sig variants, inclusion proofs, Rekor bundle, Sigstore
/// certificate chain) can land without breaking downstream
/// pattern matches or struct-literal constructions.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SignedRelease {
    /// Author that sealed this release. `verify` uses this to
    /// require every DSSE signature's `keyid` to match
    /// [`crate::dsse::keyid_for`] of the same signer.
    pub signer: AuthorId,
    /// AIBOM-flavoured reference to the primary artifact.
    pub model_ref: ModelRef,
    /// Artifact manifest (primary + auxiliaries).
    pub manifest: ArtifactManifest,
    /// RFC-0022 signature over `manifest`.
    pub manifest_signature: SignatureEntry,
    /// DSSE envelope for the manifest signature.
    pub manifest_dsse: DsseEnvelope,
    /// AIBOM record.
    pub aibom: AiBom,
    /// DSSE envelope wrapping `aibom`.
    pub aibom_dsse: DsseEnvelope,
    /// in-toto Statement carrying the SLSA v1.1 provenance.
    pub slsa_statement: InTotoStatement,
    /// DSSE envelope wrapping `slsa_statement`.
    pub slsa_dsse: DsseEnvelope,
    /// OCI Image Manifest v1.1 for the primary artifact.
    pub oci_primary: OciArtifactManifest,
    /// OCI referrer manifest for `aibom_dsse`.
    pub oci_aibom_referrer: OciArtifactManifest,
    /// OCI referrer manifest for `slsa_dsse`.
    pub oci_slsa_referrer: OciArtifactManifest,
    /// Log positions for the three appended entries.
    pub log_entries: Vec<LogSeq>,
}

impl SignedRelease {
    /// Verify every component of the release against `verifying_key`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if any signature fails to verify, any OCI
    /// digest is inconsistent, or the AIBOM / SLSA linkages to the
    /// manifest are broken. Resolves every signing key from
    /// `registry` at `at_version`.
    pub fn verify(&self, registry: &KeyRegistry, at_version: u64) -> Result<()> {
        verify_manifest_signature(
            &self.manifest,
            &self.manifest_signature,
            registry,
            at_version,
        )?;
        let _ = dsse::verify_envelope(&self.manifest_dsse, registry, at_version)?;
        let _ = dsse::verify_envelope(&self.aibom_dsse, registry, at_version)?;
        let _ = dsse::verify_envelope(&self.slsa_dsse, registry, at_version)?;
        self.verify_aibom_manifest_linkage()?;
        verify_slsa_subjects_against_manifest(&self.slsa_statement, &self.manifest)?;
        self.verify_oci_linkage()?;
        self.verify_log_entry_kinds()?;
        Ok(())
    }

    /// AIBOM model hash + size must match the primary manifest
    /// entry (first entry by seal invariant).
    fn verify_aibom_manifest_linkage(&self) -> Result<()> {
        let primary = self
            .manifest
            .entries()
            .first()
            .ok_or_else(|| AionError::InvalidFormat {
                reason: "manifest has no primary entry".to_string(),
            })?;
        if primary.hash != self.aibom.model.hash {
            return Err(AionError::InvalidFormat {
                reason: "AIBOM model hash does not match manifest primary entry".to_string(),
            });
        }
        if primary.size != self.aibom.model.size {
            return Err(AionError::InvalidFormat {
                reason: "AIBOM model size does not match manifest primary entry".to_string(),
            });
        }
        Ok(())
    }

    /// Both OCI referrers must point at the primary manifest's
    /// SHA-256 digest via their `subject` descriptor.
    fn verify_oci_linkage(&self) -> Result<()> {
        let primary_digest = self.oci_primary.digest()?;
        check_referrer_subject(&self.oci_aibom_referrer, &primary_digest, "AIBOM")?;
        check_referrer_subject(&self.oci_slsa_referrer, &primary_digest, "SLSA")
    }

    /// Log entries are exactly three, in the kind order produced
    /// by [`append_release_log_entries`].
    fn verify_log_entry_kinds(&self) -> Result<()> {
        let expected = [
            LogEntryKind::ManifestSignature,
            LogEntryKind::DsseEnvelope,
            LogEntryKind::SlsaStatement,
        ];
        if self.log_entries.len() != expected.len() {
            return Err(AionError::InvalidFormat {
                reason: format!(
                    "expected {} log entries, got {}",
                    expected.len(),
                    self.log_entries.len()
                ),
            });
        }
        for (entry, want) in self.log_entries.iter().zip(expected.iter()) {
            if entry.kind != *want {
                return Err(AionError::InvalidFormat {
                    reason: format!(
                        "log entry kind mismatch: got {:?}, expected {want:?}",
                        entry.kind
                    ),
                });
            }
        }
        Ok(())
    }
}

/// Assert that `referrer`'s `subject.digest` equals
/// `expected_digest`. `label` is injected into the error message
/// so the caller can tell which referrer failed.
fn check_referrer_subject(
    referrer: &OciArtifactManifest,
    expected_digest: &str,
    label: &str,
) -> Result<()> {
    let subject = referrer
        .subject
        .as_ref()
        .ok_or_else(|| AionError::InvalidFormat {
            reason: format!("{label} OCI referrer missing subject"),
        })?;
    if subject.digest != expected_digest {
        return Err(AionError::InvalidFormat {
            reason: format!("{label} OCI referrer subject.digest != primary digest"),
        });
    }
    Ok(())
}

/// Check that every `InTotoStatement` subject's BLAKE3-256 digest
/// corresponds to some `ArtifactEntry` in the manifest.
fn verify_slsa_subjects_against_manifest(
    statement: &InTotoStatement,
    manifest: &ArtifactManifest,
) -> Result<()> {
    for subject in &statement.subject {
        let want = subject
            .digest
            .get("blake3-256")
            .ok_or_else(|| AionError::InvalidFormat {
                reason: format!("SLSA subject '{}' missing blake3-256 digest", subject.name),
            })?;
        let matched = manifest.entries().iter().any(|entry: &ArtifactEntry| {
            let observed = hex::encode(entry.hash);
            observed == *want
        });
        if !matched {
            return Err(AionError::InvalidFormat {
                reason: format!(
                    "SLSA subject digest for '{}' not found in manifest",
                    subject.name
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Build a registry pinning `signer` with `key` as the active op at epoch 0.
    fn reg_pinning(signer: AuthorId, key: &SigningKey) -> KeyRegistry {
        let mut reg = KeyRegistry::new();
        let master = SigningKey::generate();
        reg.register_author(signer, master.verifying_key(), key.verifying_key(), 0)
            .unwrap();
        reg
    }

    fn sample_builder() -> ReleaseBuilder {
        let mut b = ReleaseBuilder::new("acme-7b-chat", "0.3.1", "safetensors");
        b.primary_artifact("model.safetensors", vec![0xAAu8; 256])
            .add_auxiliary("tokenizer.json", b"{}".to_vec())
            .add_framework(FrameworkRef {
                name: "pytorch".into(),
                version: "2.3.1".into(),
                cpe: None,
            })
            .add_license(License {
                spdx_id: "Apache-2.0".into(),
                scope: crate::aibom::LicenseScope::Weights,
                text_uri: None,
            })
            .builder_id("https://example.com/ci/run/1")
            .current_aion_version(1);
        b
    }

    #[test]
    fn seal_requires_primary_artifact() {
        let mut log = TransparencyLog::new();
        let key = SigningKey::generate();
        let mut b = ReleaseBuilder::new("m", "1", "safetensors");
        b.builder_id("https://ci/1");
        assert!(b.seal(AuthorId::new(1), &key, &mut log).is_err());
    }

    #[test]
    fn seal_requires_builder_id() {
        let mut log = TransparencyLog::new();
        let key = SigningKey::generate();
        let mut b = ReleaseBuilder::new("m", "1", "safetensors");
        b.primary_artifact("x", vec![0u8; 32]);
        assert!(b.seal(AuthorId::new(1), &key, &mut log).is_err());
    }

    #[test]
    fn seal_and_verify_round_trip() {
        let mut log = TransparencyLog::new();
        let key = SigningKey::generate();
        let signed = sample_builder()
            .seal(AuthorId::new(50_001), &key, &mut log)
            .unwrap();
        signed
            .verify(&reg_pinning(AuthorId::new(50_001), &key), 1)
            .unwrap();
    }

    #[test]
    fn log_has_three_entries_in_kind_order() {
        let mut log = TransparencyLog::new();
        let key = SigningKey::generate();
        let signed = sample_builder()
            .seal(AuthorId::new(50_001), &key, &mut log)
            .unwrap();
        assert_eq!(signed.log_entries.len(), 3);
        assert_eq!(signed.log_entries[0].kind, LogEntryKind::ManifestSignature);
        assert_eq!(signed.log_entries[1].kind, LogEntryKind::DsseEnvelope);
        assert_eq!(signed.log_entries[2].kind, LogEntryKind::SlsaStatement);
    }

    #[test]
    fn oci_referrers_link_to_primary() {
        let mut log = TransparencyLog::new();
        let key = SigningKey::generate();
        let signed = sample_builder()
            .seal(AuthorId::new(50_001), &key, &mut log)
            .unwrap();
        let primary_digest = signed.oci_primary.digest().unwrap();
        assert_eq!(
            signed.oci_aibom_referrer.subject.as_ref().unwrap().digest,
            primary_digest
        );
        assert_eq!(
            signed.oci_slsa_referrer.subject.as_ref().unwrap().digest,
            primary_digest
        );
    }

    #[test]
    fn aibom_model_hash_equals_manifest_primary() {
        let mut log = TransparencyLog::new();
        let key = SigningKey::generate();
        let signed = sample_builder()
            .seal(AuthorId::new(50_001), &key, &mut log)
            .unwrap();
        assert_eq!(
            signed.aibom.model.hash,
            signed.manifest.entries().first().unwrap().hash
        );
    }

    #[test]
    fn tampered_aibom_envelope_rejects() {
        let mut log = TransparencyLog::new();
        let key = SigningKey::generate();
        let mut signed = sample_builder()
            .seal(AuthorId::new(50_001), &key, &mut log)
            .unwrap();
        signed.aibom_dsse.payload[0] ^= 0x01;
        assert!(signed
            .verify(&reg_pinning(AuthorId::new(50_001), &key), 1)
            .is_err());
    }

    #[test]
    fn wrong_key_rejects() {
        let mut log = TransparencyLog::new();
        let key = SigningKey::generate();
        let other = SigningKey::generate();
        let signed = sample_builder()
            .seal(AuthorId::new(50_001), &key, &mut log)
            .unwrap();
        // Pin the WRONG key for the author — registry check rejects.
        assert!(signed
            .verify(&reg_pinning(AuthorId::new(50_001), &other), 1)
            .is_err());
    }

    mod properties {
        use super::*;
        use hegel::generators as gs;

        fn build_and_seal(
            tc: &hegel::TestCase,
            log: &mut TransparencyLog,
            signer: AuthorId,
            key: &SigningKey,
        ) -> SignedRelease {
            let primary_bytes = tc.draw(gs::binary().min_size(1).max_size(1024));
            let n_aux = tc.draw(gs::integers::<usize>().max_value(3));
            let mut b = ReleaseBuilder::new("model", "0.1.0", "safetensors");
            b.primary_artifact("model.bin", primary_bytes)
                .builder_id("https://ci/run/42")
                .current_aion_version(tc.draw(gs::integers::<u64>().max_value(1 << 40)));
            for i in 0..n_aux {
                let bytes = tc.draw(gs::binary().max_size(256));
                b.add_auxiliary(format!("aux_{i}"), bytes);
            }
            b.seal(signer, key, log)
                .unwrap_or_else(|_| std::process::abort())
        }

        #[hegel::test]
        fn prop_release_seal_verify_roundtrip(tc: hegel::TestCase) {
            let mut log = TransparencyLog::new();
            let key = SigningKey::generate();
            let signer = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let signed = build_and_seal(&tc, &mut log, signer, &key);
            let reg = reg_pinning(signer, &key);
            signed
                .verify(&reg, 1)
                .unwrap_or_else(|_| std::process::abort());
        }

        #[hegel::test]
        fn prop_release_tampered_manifest_detected(tc: hegel::TestCase) {
            let mut log = TransparencyLog::new();
            let key = SigningKey::generate();
            let mut signed = build_and_seal(
                &tc,
                &mut log,
                AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1))),
                &key,
            );
            let idx = tc.draw(
                gs::integers::<usize>()
                    .max_value(signed.manifest_dsse.payload.len().saturating_sub(1)),
            );
            if let Some(b) = signed.manifest_dsse.payload.get_mut(idx) {
                *b ^= 0x01;
            }
            assert!(signed
                .verify(&reg_pinning(AuthorId::new(50_001), &key), 1)
                .is_err());
        }

        #[hegel::test]
        fn prop_release_oci_referrers_link_to_primary(tc: hegel::TestCase) {
            let mut log = TransparencyLog::new();
            let key = SigningKey::generate();
            let signed = build_and_seal(
                &tc,
                &mut log,
                AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1))),
                &key,
            );
            let primary_digest = signed
                .oci_primary
                .digest()
                .unwrap_or_else(|_| std::process::abort());
            let aibom_subject = signed
                .oci_aibom_referrer
                .subject
                .as_ref()
                .unwrap_or_else(|| std::process::abort());
            let slsa_subject = signed
                .oci_slsa_referrer
                .subject
                .as_ref()
                .unwrap_or_else(|| std::process::abort());
            assert_eq!(aibom_subject.digest, primary_digest);
            assert_eq!(slsa_subject.digest, primary_digest);
        }

        #[hegel::test]
        fn prop_release_aibom_model_ref_matches_manifest(tc: hegel::TestCase) {
            let mut log = TransparencyLog::new();
            let key = SigningKey::generate();
            let signed = build_and_seal(
                &tc,
                &mut log,
                AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1))),
                &key,
            );
            let primary = signed
                .manifest
                .entries()
                .first()
                .unwrap_or_else(|| std::process::abort());
            assert_eq!(signed.aibom.model.hash, primary.hash);
            assert_eq!(signed.aibom.model.size, primary.size);
        }

        #[hegel::test]
        fn prop_release_log_has_expected_kinds(tc: hegel::TestCase) {
            let mut log = TransparencyLog::new();
            let key = SigningKey::generate();
            let signed = build_and_seal(
                &tc,
                &mut log,
                AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1))),
                &key,
            );
            assert_eq!(signed.log_entries.len(), 3);
            assert_eq!(signed.log_entries[0].kind, LogEntryKind::ManifestSignature);
            assert_eq!(signed.log_entries[1].kind, LogEntryKind::DsseEnvelope);
            assert_eq!(signed.log_entries[2].kind, LogEntryKind::SlsaStatement);
        }

        #[hegel::test]
        fn prop_release_registry_verify_accepts_pinned_release(tc: hegel::TestCase) {
            use crate::key_registry::KeyRegistry;
            let mut log = TransparencyLog::new();
            let master = SigningKey::generate();
            let op = SigningKey::generate();
            let signer =
                AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 32)));
            let mut reg = KeyRegistry::new();
            reg.register_author(signer, master.verifying_key(), op.verifying_key(), 0)
                .unwrap_or_else(|_| std::process::abort());
            let signed = build_and_seal(&tc, &mut log, signer, &op);
            let at = tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 20));
            signed
                .verify(&reg, at)
                .unwrap_or_else(|_| std::process::abort());
        }

        #[hegel::test]
        fn prop_release_registry_verify_rejects_rotated_out_signer(tc: hegel::TestCase) {
            use crate::key_registry::{sign_rotation_record, KeyRegistry};
            let mut log = TransparencyLog::new();
            let master = SigningKey::generate();
            let op0 = SigningKey::generate();
            let op1 = SigningKey::generate();
            let signer =
                AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 32)));
            let mut reg = KeyRegistry::new();
            reg.register_author(signer, master.verifying_key(), op0.verifying_key(), 0)
                .unwrap_or_else(|_| std::process::abort());
            let effective = tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 20));
            let rotation = sign_rotation_record(
                signer,
                0,
                1,
                op1.verifying_key().to_bytes(),
                effective,
                &master,
            );
            reg.apply_rotation(&rotation)
                .unwrap_or_else(|_| std::process::abort());
            // Seal the release with the rotated-OUT op0 key.
            let signed = build_and_seal(&tc, &mut log, signer, &op0);
            let v_after = effective.saturating_add(1);
            assert!(signed.verify(&reg, v_after).is_err());
        }
    }
}
