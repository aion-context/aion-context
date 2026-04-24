//! OCI artifact packaging — RFC-0030.
//!
//! Emits OCI Image Manifest v1.1 JSON so `.aion` files and their
//! attached attestations (RFC-0023 DSSE, RFC-0024 SLSA, RFC-0029
//! AIBOM) can ride through the standard container-registry supply
//! chain. Phase A is pure data model — push/pull is the caller's
//! job using ORAS, cosign, `oras push`, or plain HTTP.
//!
//! OCI mandates SHA-256 for layer and config digests, distinct
//! from aion's internal BLAKE3 content hashing (RFC-0002). They
//! coexist: BLAKE3 for content addressing inside `.aion` files,
//! SHA-256 for OCI transport.
//!
//! # Example
//!
//! ```
//! use aion_context::oci::{AionConfig, build_aion_manifest};
//!
//! let aion_bytes: Vec<u8> = vec![0u8; 256];
//! let config = AionConfig {
//!     schema_version: "aion.oci.config.v1".into(),
//!     format_version: 2,
//!     file_id: 42,
//!     created_at_version: 1,
//!     created_at: "2026-04-23T12:00:00Z".into(),
//! };
//! let manifest = build_aion_manifest(&aion_bytes, "rules.aion", &config).unwrap();
//! assert_eq!(
//!     manifest.artifact_type.as_deref(),
//!     Some("application/vnd.aion.context.v2")
//! );
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AionError, Result};

/// OCI Image Manifest v1.1 media type.
pub const OCI_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

/// Discriminator advertised on the manifest `artifactType` field
/// for aion-context primary artifacts.
pub const AION_CONTEXT_ARTIFACT_TYPE: &str = "application/vnd.aion.context.v2";

/// Media type for the `.aion` file payload layer.
pub const AION_CONTEXT_LAYER_MEDIA_TYPE: &str = "application/vnd.aion.context.v2+binary";

/// Media type for the aion-specific JSON config blob.
pub const AION_CONFIG_MEDIA_TYPE: &str = "application/vnd.aion.context.config.v1+json";

/// OCI's sentinel empty-config media type. Used for referrer
/// manifests that carry their payload in `layers` and need no
/// per-artifact config.
pub const OCI_EMPTY_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.empty.v1+json";

/// Pre-computed SHA-256 digest of the 2-byte `{}` empty-config
/// payload, per the OCI spec.
pub const OCI_EMPTY_CONFIG_DIGEST: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

/// Pre-computed size of `{}`.
pub const OCI_EMPTY_CONFIG_SIZE: u64 = 2;

/// Compute an OCI digest string (`sha256:<lowercase-hex>`) over
/// `bytes`.
#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    format!("sha256:{}", hex::encode(digest))
}

/// An OCI content descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciDescriptor {
    /// IANA media type of the referenced content.
    #[serde(rename = "mediaType")]
    pub media_type: String,
    /// `sha256:<hex>` digest of the referenced content.
    pub digest: String,
    /// Size of the referenced content in bytes.
    pub size: u64,
    /// Annotations on this descriptor — omitted when empty.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

impl OciDescriptor {
    /// Build a descriptor for `bytes` with the given `media_type`.
    /// The SHA-256 digest is computed here.
    #[must_use]
    pub fn of(bytes: &[u8], media_type: impl Into<String>) -> Self {
        Self {
            media_type: media_type.into(),
            digest: sha256_digest(bytes),
            size: bytes.len() as u64,
            annotations: BTreeMap::new(),
        }
    }
}

/// An OCI Image Manifest v1.1 shaped for use as an artifact or
/// attestation referrer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciArtifactManifest {
    /// Always `2` for OCI Image Manifest v1.1.
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    /// Always [`OCI_MANIFEST_MEDIA_TYPE`].
    #[serde(rename = "mediaType")]
    pub media_type: String,
    /// Artifact-type discriminator — missing for pure image
    /// manifests, set for aion artifacts and referrers.
    #[serde(
        rename = "artifactType",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub artifact_type: Option<String>,
    /// Config-blob descriptor.
    pub config: OciDescriptor,
    /// Layer descriptors. aion manifests always have exactly one.
    pub layers: Vec<OciDescriptor>,
    /// When present, this artifact is a referrer for the
    /// subject — enumerable via the OCI Referrers API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<OciDescriptor>,
    /// Manifest-level annotations.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

/// Aion-specific config blob, embedded as a layer-style object
/// whose JSON bytes become the manifest's `config` descriptor
/// target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AionConfig {
    /// Discriminator — always `"aion.oci.config.v1"`.
    pub schema_version: String,
    /// The `.aion` binary format version (currently 2).
    pub format_version: u32,
    /// Mirrors `AionFile.file_id`.
    pub file_id: u64,
    /// aion version at artifact creation time.
    pub created_at_version: u64,
    /// Informational RFC 3339 timestamp.
    pub created_at: String,
}

impl AionConfig {
    /// Serialize to canonical JSON bytes.
    ///
    /// # Errors
    ///
    /// Propagates `serde_json` errors.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| AionError::InvalidFormat {
            reason: format!("AionConfig serialize failed: {e}"),
        })
    }
}

impl OciArtifactManifest {
    /// Serialize to JSON string.
    ///
    /// # Errors
    ///
    /// Propagates `serde_json` errors.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| AionError::InvalidFormat {
            reason: format!("OCI manifest serialize failed: {e}"),
        })
    }

    /// Canonical bytes used to compute the manifest digest.
    ///
    /// # Errors
    ///
    /// Propagates `serde_json` errors.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| AionError::InvalidFormat {
            reason: format!("OCI manifest canonical bytes failed: {e}"),
        })
    }

    /// RFC 8785 (JCS) canonical bytes — use when cross-implementation
    /// byte stability matters (Phase B of RFC-0031). Opt-in;
    /// [`Self::canonical_bytes`] remains the hash-stable form used
    /// by [`Self::digest`].
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
    /// Returns `Err` on malformed JSON or schema mismatch.
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|e| AionError::InvalidFormat {
            reason: format!("OCI manifest parse failed: {e}"),
        })
    }

    /// SHA-256 digest of the canonical manifest bytes — what
    /// referrers point at via `subject.digest`.
    ///
    /// # Errors
    ///
    /// Propagates canonical-bytes errors.
    pub fn digest(&self) -> Result<String> {
        Ok(sha256_digest(&self.canonical_bytes()?))
    }

    /// Descriptor suitable for use as another manifest's
    /// `subject`.
    ///
    /// # Errors
    ///
    /// Propagates canonical-bytes errors.
    pub fn as_subject(&self) -> Result<OciDescriptor> {
        let bytes = self.canonical_bytes()?;
        Ok(OciDescriptor {
            media_type: OCI_MANIFEST_MEDIA_TYPE.to_string(),
            digest: sha256_digest(&bytes),
            size: bytes.len() as u64,
            annotations: BTreeMap::new(),
        })
    }
}

/// Build a primary aion OCI artifact manifest carrying `aion_bytes`
/// as its one layer plus `config` as the config blob.
///
/// # Errors
///
/// Propagates config-serialization errors.
pub fn build_aion_manifest(
    aion_bytes: &[u8],
    file_title: &str,
    config: &AionConfig,
) -> Result<OciArtifactManifest> {
    let config_bytes = config.canonical_bytes()?;
    let config_desc = OciDescriptor {
        media_type: AION_CONFIG_MEDIA_TYPE.to_string(),
        digest: sha256_digest(&config_bytes),
        size: config_bytes.len() as u64,
        annotations: BTreeMap::new(),
    };
    let mut layer = OciDescriptor::of(aion_bytes, AION_CONTEXT_LAYER_MEDIA_TYPE);
    layer.annotations.insert(
        "org.opencontainers.image.title".to_string(),
        file_title.to_string(),
    );
    let mut annotations = BTreeMap::new();
    annotations.insert(
        "dev.aion.format.version".to_string(),
        config.format_version.to_string(),
    );
    annotations.insert("dev.aion.file.id".to_string(), config.file_id.to_string());
    Ok(OciArtifactManifest {
        schema_version: 2,
        media_type: OCI_MANIFEST_MEDIA_TYPE.to_string(),
        artifact_type: Some(AION_CONTEXT_ARTIFACT_TYPE.to_string()),
        config: config_desc,
        layers: vec![layer],
        subject: None,
        annotations,
    })
}

/// Build a referrer manifest that attaches `envelope_json` bytes
/// (typically a DSSE envelope) as an attestation for
/// `subject_manifest`.
///
/// The caller passes the attestation's media type — for instance
/// [`crate::aibom::AIBOM_PAYLOAD_TYPE`] or the in-toto payload
/// type constant from RFC-0024.
///
/// # Errors
///
/// Propagates canonical-bytes errors from the subject manifest.
pub fn build_attestation_manifest(
    envelope_json: &[u8],
    attestation_media_type: &str,
    subject_manifest: &OciArtifactManifest,
) -> Result<OciArtifactManifest> {
    let layer = OciDescriptor::of(envelope_json, attestation_media_type);
    let config_desc = OciDescriptor {
        media_type: OCI_EMPTY_CONFIG_MEDIA_TYPE.to_string(),
        digest: OCI_EMPTY_CONFIG_DIGEST.to_string(),
        size: OCI_EMPTY_CONFIG_SIZE,
        annotations: BTreeMap::new(),
    };
    let subject = subject_manifest.as_subject()?;
    Ok(OciArtifactManifest {
        schema_version: 2,
        media_type: OCI_MANIFEST_MEDIA_TYPE.to_string(),
        artifact_type: Some(attestation_media_type.to_string()),
        config: config_desc,
        layers: vec![layer],
        subject: Some(subject),
        annotations: BTreeMap::new(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample_config() -> AionConfig {
        AionConfig {
            schema_version: "aion.oci.config.v1".to_string(),
            format_version: 2,
            file_id: 42,
            created_at_version: 1,
            created_at: "2026-04-23T12:00:00Z".to_string(),
        }
    }

    #[test]
    fn sha256_digest_known_vector() {
        // SHA-256 of empty string is the well-known constant.
        assert_eq!(
            sha256_digest(b""),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn empty_config_constants_consistent() {
        assert_eq!(sha256_digest(b"{}"), OCI_EMPTY_CONFIG_DIGEST);
    }

    #[test]
    fn aion_manifest_has_expected_shape() {
        let bytes = vec![0xABu8; 128];
        let m = build_aion_manifest(&bytes, "rules.aion", &sample_config()).unwrap();
        assert_eq!(m.schema_version, 2);
        assert_eq!(m.media_type, OCI_MANIFEST_MEDIA_TYPE);
        assert_eq!(m.artifact_type.as_deref(), Some(AION_CONTEXT_ARTIFACT_TYPE));
        assert_eq!(m.layers.len(), 1);
        assert_eq!(m.layers[0].media_type, AION_CONTEXT_LAYER_MEDIA_TYPE);
        assert_eq!(m.layers[0].size, 128);
        assert_eq!(
            m.layers[0]
                .annotations
                .get("org.opencontainers.image.title"),
            Some(&"rules.aion".to_string())
        );
        assert!(m.subject.is_none());
    }

    #[test]
    fn attestation_manifest_links_subject() {
        let aion_bytes = vec![0u8; 64];
        let primary = build_aion_manifest(&aion_bytes, "rules.aion", &sample_config()).unwrap();
        let envelope = br#"{"payloadType":"application/vnd.aion.aibom.v1+json"}"#;
        let referrer =
            build_attestation_manifest(envelope, "application/vnd.aion.aibom.v1+json", &primary)
                .unwrap();
        let subject = referrer.subject.as_ref().unwrap();
        assert_eq!(subject.media_type, OCI_MANIFEST_MEDIA_TYPE);
        assert_eq!(subject.digest, primary.digest().unwrap());
    }

    #[test]
    fn manifest_json_round_trip() {
        let bytes = vec![1u8, 2, 3, 4];
        let m = build_aion_manifest(&bytes, "rules.aion", &sample_config()).unwrap();
        let json = m.to_json().unwrap();
        let parsed = OciArtifactManifest::from_json(&json).unwrap();
        assert_eq!(parsed, m);
    }

    #[test]
    fn manifest_digest_is_deterministic() {
        let bytes = vec![0xCCu8; 16];
        let m = build_aion_manifest(&bytes, "rules.aion", &sample_config()).unwrap();
        let d1 = m.digest().unwrap();
        let d2 = m.digest().unwrap();
        assert_eq!(d1, d2);
    }

    #[test]
    fn tampering_json_changes_digest() {
        let bytes = vec![0u8; 8];
        let mut m = build_aion_manifest(&bytes, "rules.aion", &sample_config()).unwrap();
        let d1 = m.digest().unwrap();
        m.annotations.insert("foo".to_string(), "bar".to_string());
        let d2 = m.digest().unwrap();
        assert_ne!(d1, d2);
    }

    mod properties {
        use super::*;
        use hegel::generators as gs;

        fn draw_config(tc: &hegel::TestCase) -> AionConfig {
            AionConfig {
                schema_version: "aion.oci.config.v1".to_string(),
                format_version: 2,
                file_id: tc.draw(gs::integers::<u64>()),
                created_at_version: tc.draw(gs::integers::<u64>()),
                created_at: "2026-04-23T12:00:00Z".to_string(),
            }
        }

        #[hegel::test]
        fn prop_oci_manifest_json_roundtrip(tc: hegel::TestCase) {
            let aion_bytes = tc.draw(gs::binary().max_size(512));
            let config = draw_config(&tc);
            let m = build_aion_manifest(&aion_bytes, "rules.aion", &config)
                .unwrap_or_else(|_| std::process::abort());
            let json = m.to_json().unwrap_or_else(|_| std::process::abort());
            let parsed =
                OciArtifactManifest::from_json(&json).unwrap_or_else(|_| std::process::abort());
            assert_eq!(parsed, m);
        }

        #[hegel::test]
        fn prop_oci_manifest_digest_deterministic(tc: hegel::TestCase) {
            let aion_bytes = tc.draw(gs::binary().max_size(512));
            let config = draw_config(&tc);
            let m = build_aion_manifest(&aion_bytes, "rules.aion", &config)
                .unwrap_or_else(|_| std::process::abort());
            let a = m.digest().unwrap_or_else(|_| std::process::abort());
            let b = m.digest().unwrap_or_else(|_| std::process::abort());
            assert_eq!(a, b);
        }

        #[hegel::test]
        fn prop_aion_primary_has_expected_media_types(tc: hegel::TestCase) {
            let aion_bytes = tc.draw(gs::binary().max_size(256));
            let config = draw_config(&tc);
            let m = build_aion_manifest(&aion_bytes, "rules.aion", &config)
                .unwrap_or_else(|_| std::process::abort());
            assert_eq!(m.artifact_type.as_deref(), Some(AION_CONTEXT_ARTIFACT_TYPE));
            let layer = m.layers.first().unwrap_or_else(|| std::process::abort());
            assert_eq!(layer.media_type, AION_CONTEXT_LAYER_MEDIA_TYPE);
            assert_eq!(m.config.media_type, AION_CONFIG_MEDIA_TYPE);
        }

        #[hegel::test]
        fn prop_aion_layer_size_matches_payload(tc: hegel::TestCase) {
            let aion_bytes = tc.draw(gs::binary().max_size(1024));
            let config = draw_config(&tc);
            let m = build_aion_manifest(&aion_bytes, "rules.aion", &config)
                .unwrap_or_else(|_| std::process::abort());
            let layer = m.layers.first().unwrap_or_else(|| std::process::abort());
            assert_eq!(layer.size as usize, aion_bytes.len());
        }

        #[hegel::test]
        fn prop_aion_layer_digest_matches_payload_sha256(tc: hegel::TestCase) {
            let aion_bytes = tc.draw(gs::binary().max_size(1024));
            let config = draw_config(&tc);
            let m = build_aion_manifest(&aion_bytes, "rules.aion", &config)
                .unwrap_or_else(|_| std::process::abort());
            let layer = m.layers.first().unwrap_or_else(|| std::process::abort());
            assert_eq!(layer.digest, sha256_digest(&aion_bytes));
        }

        #[hegel::test]
        fn prop_attestation_manifest_subject_links_to_primary(tc: hegel::TestCase) {
            let aion_bytes = tc.draw(gs::binary().max_size(256));
            let config = draw_config(&tc);
            let primary = build_aion_manifest(&aion_bytes, "rules.aion", &config)
                .unwrap_or_else(|_| std::process::abort());
            let envelope = tc.draw(gs::binary().min_size(1).max_size(512));
            let referrer = build_attestation_manifest(
                &envelope,
                "application/vnd.aion.aibom.v1+json",
                &primary,
            )
            .unwrap_or_else(|_| std::process::abort());
            let subject = referrer
                .subject
                .as_ref()
                .unwrap_or_else(|| std::process::abort());
            let primary_digest = primary.digest().unwrap_or_else(|_| std::process::abort());
            assert_eq!(subject.digest, primary_digest);
            assert_eq!(subject.media_type, OCI_MANIFEST_MEDIA_TYPE);
        }

        #[hegel::test]
        fn prop_oci_manifest_tamper_rejects_digest(tc: hegel::TestCase) {
            let aion_bytes = tc.draw(gs::binary().max_size(256));
            let config = draw_config(&tc);
            let m = build_aion_manifest(&aion_bytes, "rules.aion", &config)
                .unwrap_or_else(|_| std::process::abort());
            let original_digest = m.digest().unwrap_or_else(|_| std::process::abort());
            let mut tampered = m.clone();
            tampered
                .annotations
                .insert("dev.aion.mutation".to_string(), "yes".to_string());
            let tampered_digest = tampered.digest().unwrap_or_else(|_| std::process::abort());
            assert_ne!(original_digest, tampered_digest);
        }

        #[hegel::test]
        fn prop_oci_manifest_to_jcs_bytes_matches_helper(tc: hegel::TestCase) {
            let aion_bytes = tc.draw(gs::binary().max_size(256));
            let config = draw_config(&tc);
            let m = build_aion_manifest(&aion_bytes, "rules.aion", &config)
                .unwrap_or_else(|_| std::process::abort());
            let from_method = m.to_jcs_bytes().unwrap_or_else(|_| std::process::abort());
            let from_helper =
                crate::jcs::to_jcs_bytes(&m).unwrap_or_else(|_| std::process::abort());
            assert_eq!(from_method, from_helper);
        }
    }
}
