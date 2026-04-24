//! DSSE envelope support — RFC-0023.
//!
//! DSSE (Dead Simple Signing Envelope) is the universal envelope format
//! used across Sigstore, in-toto, SLSA, Kyverno, and every major
//! supply-chain verifier in 2026. This module emits and verifies DSSE
//! envelopes wrapping aion signatures, giving `aion-context` interop
//! with those ecosystems.
//!
//! Signatures are still produced by [`crate::crypto::SigningKey`] —
//! only the wire format changes. DSSE's native multi-signature support
//! maps onto RFC-0021 multi-party attestations.
//!
//! # Example
//!
//! ```
//! use aion_context::dsse::{sign_envelope, verify_envelope, AION_ATTESTATION_TYPE};
//! use aion_context::crypto::SigningKey;
//! use aion_context::key_registry::KeyRegistry;
//! use aion_context::types::AuthorId;
//!
//! let payload = br#"{"_type":"https://aion-context.dev/attestation/v1"}"#;
//! let signer = AuthorId::new(50001);
//! let master = SigningKey::generate();
//! let key = SigningKey::generate();
//! let mut registry = KeyRegistry::new();
//! registry
//!     .register_author(signer, master.verifying_key(), key.verifying_key(), 0)
//!     .unwrap();
//!
//! let envelope = sign_envelope(payload, AION_ATTESTATION_TYPE, signer, &key);
//! let verified = verify_envelope(&envelope, &registry, 1).unwrap();
//! assert_eq!(verified, vec!["aion:author:50001".to_string()]);
//! ```

use base64::engine::general_purpose::STANDARD_NO_PAD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::crypto::{SigningKey, VerifyingKey};
use crate::manifest::ArtifactManifest;
use crate::serializer::VersionEntry;
use crate::types::AuthorId;
use crate::{AionError, Result};

/// DSSE protocol preamble — signed into every PAE.
pub const DSSE_PREAMBLE: &str = "DSSEv1";

/// `payloadType` for aion version attestations (RFC-0021 carried via DSSE).
pub const AION_ATTESTATION_TYPE: &str = "application/vnd.aion.attestation.v1+json";

/// `payloadType` for aion external-artifact manifests (RFC-0022).
pub const AION_MANIFEST_TYPE: &str = "application/vnd.aion.manifest.v1+json";

/// Keyid prefix for aion signatures. Full form: `aion:author:<decimal_id>`.
pub const AION_KEYID_PREFIX: &str = "aion:author:";

/// Build the canonical keyid string for an [`AuthorId`].
#[must_use]
pub fn keyid_for(author: AuthorId) -> String {
    format!("{AION_KEYID_PREFIX}{}", author.as_u64())
}

/// Parse a keyid back to an [`AuthorId`].
///
/// # Errors
///
/// Returns `Err` for keyids that do not start with [`AION_KEYID_PREFIX`]
/// or whose suffix is not a valid `u64`.
pub fn author_from_keyid(keyid: &str) -> Result<AuthorId> {
    let suffix = keyid
        .strip_prefix(AION_KEYID_PREFIX)
        .ok_or_else(|| AionError::InvalidFormat {
            reason: format!("keyid does not start with '{AION_KEYID_PREFIX}': {keyid}"),
        })?;
    let id = suffix
        .parse::<u64>()
        .map_err(|_| AionError::InvalidFormat {
            reason: format!("keyid suffix is not a u64: {suffix}"),
        })?;
    Ok(AuthorId::new(id))
}

/// Pre-Authentication Encoding — the exact bytes signed/verified.
///
/// ```text
/// PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
/// ```
#[must_use]
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let type_len = payload_type.len().to_string();
    let body_len = payload.len().to_string();
    let mut out = Vec::with_capacity(
        DSSE_PREAMBLE
            .len()
            .saturating_add(3)
            .saturating_add(type_len.len())
            .saturating_add(payload_type.len())
            .saturating_add(body_len.len())
            .saturating_add(payload.len()),
    );
    out.extend_from_slice(DSSE_PREAMBLE.as_bytes());
    out.push(b' ');
    out.extend_from_slice(type_len.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(body_len.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// A DSSE envelope. Serialises to the canonical DSSE JSON form on the wire:
/// `payload` and `sig` fields are base64-standard-no-padding when encoded,
/// raw bytes when in memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsseEnvelope {
    /// Media type URI describing `payload`.
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    /// Raw payload bytes; JSON encodes/decodes as base64.
    #[serde(with = "base64_bytes")]
    pub payload: Vec<u8>,
    /// All signatures bound to the (`payload_type`, payload) tuple.
    pub signatures: Vec<DsseSignature>,
}

/// One signature entry inside a [`DsseEnvelope`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsseSignature {
    /// Opaque key identifier. aion uses `aion:author:<decimal>`.
    pub keyid: String,
    /// Raw 64-byte Ed25519 signature; JSON encodes/decodes as base64.
    #[serde(with = "base64_bytes")]
    pub sig: Vec<u8>,
}

/// Serde adapter: `Vec<u8>` ⇄ base64-standard-no-padding string.
mod base64_bytes {
    use super::{Deserializer, Serializer, STANDARD_NO_PAD};
    use base64::Engine;
    use serde::{Deserialize, Serialize};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        let encoded = STANDARD_NO_PAD.encode(bytes);
        encoded.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let raw = String::deserialize(deserializer)?;
        STANDARD_NO_PAD
            .decode(raw.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// Produce a single-signature envelope for `payload` under `payload_type`.
#[must_use]
pub fn sign_envelope(
    payload: &[u8],
    payload_type: &str,
    signer: AuthorId,
    key: &SigningKey,
) -> DsseEnvelope {
    let message = pae(payload_type, payload);
    let signature_bytes = key.sign(&message);
    DsseEnvelope {
        payload_type: payload_type.to_string(),
        payload: payload.to_vec(),
        signatures: vec![DsseSignature {
            keyid: keyid_for(signer),
            sig: signature_bytes.to_vec(),
        }],
    }
}

/// Append an additional signature to an existing envelope.
///
/// Used to build up a multi-signature envelope for RFC-0021
/// multi-party attestations. Infallible — Ed25519 signing over
/// fixed-size inputs cannot fail.
pub fn add_signature(envelope: &mut DsseEnvelope, signer: AuthorId, key: &SigningKey) {
    let message = pae(&envelope.payload_type, &envelope.payload);
    let signature_bytes = key.sign(&message);
    envelope.signatures.push(DsseSignature {
        keyid: keyid_for(signer),
        sig: signature_bytes.to_vec(),
    });
}

/// Verify every envelope signature against the pinned registry — RFC-0023 / RFC-0034.
///
/// Each signature is checked against its signer's active epoch in
/// [`KeyRegistry`](crate::key_registry::KeyRegistry) at
/// `at_version`. Returns the distinct keyids of verified signatures
/// in envelope order.
///
/// For each distinct keyid the signer is resolved via
/// [`author_from_keyid`] and cross-checked against the active
/// epoch in `registry`. A signer whose keyid does not parse as a
/// well-formed aion keyid, or who has no active epoch at
/// `at_version`, causes the whole envelope to fail.
///
/// A given `keyid` contributes to the returned vector **at most
/// once** even if the envelope carries multiple signature entries
/// under the same keyid (RFC-0033 C6).
///
/// # Errors
///
/// Returns `Err` if the envelope has zero signatures, if any keyid
/// parses as a non-aion form, if any signer has no active epoch
/// at `at_version`, or if any signature fails Ed25519 verification
/// under the pinned key.
pub fn verify_envelope(
    envelope: &DsseEnvelope,
    registry: &crate::key_registry::KeyRegistry,
    at_version: u64,
) -> Result<Vec<String>> {
    if envelope.signatures.is_empty() {
        return Err(AionError::InvalidFormat {
            reason: "DSSE envelope has zero signatures".to_string(),
        });
    }
    let message = pae(&envelope.payload_type, &envelope.payload);
    let mut verified = Vec::with_capacity(envelope.signatures.len());
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for sig_entry in &envelope.signatures {
        if !seen.insert(sig_entry.keyid.as_str()) {
            continue;
        }
        let author = author_from_keyid(&sig_entry.keyid).map_err(|_| AionError::InvalidFormat {
            reason: format!("non-aion keyid cannot be resolved: {}", sig_entry.keyid),
        })?;
        let epoch = registry
            .active_epoch_at(author, at_version)
            .ok_or_else(|| AionError::InvalidFormat {
                reason: format!(
                    "no active epoch at version {at_version} for keyid: {}",
                    sig_entry.keyid
                ),
            })?;
        let verifying_key = VerifyingKey::from_bytes(&epoch.public_key)?;
        let sig_bytes =
            sig_entry
                .sig
                .as_slice()
                .try_into()
                .map_err(|_| AionError::InvalidFormat {
                    reason: format!(
                        "DSSE signature for {} has length {} (expected 64)",
                        sig_entry.keyid,
                        sig_entry.sig.len()
                    ),
                })?;
        verifying_key.verify(&message, sig_bytes)?;
        verified.push(sig_entry.keyid.clone());
    }
    Ok(verified)
}

impl DsseEnvelope {
    /// Serialise to canonical DSSE JSON.
    ///
    /// # Errors
    ///
    /// Propagates `serde_json` errors (should not occur for
    /// well-constructed envelopes).
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| AionError::InvalidFormat {
            reason: format!("DSSE JSON serialization failed: {e}"),
        })
    }

    /// Parse a DSSE envelope from JSON.
    ///
    /// # Errors
    ///
    /// Returns `Err` for malformed JSON or invalid base64 in the
    /// `payload` / `sig` fields.
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|e| AionError::InvalidFormat {
            reason: format!("DSSE JSON deserialization failed: {e}"),
        })
    }
}

// ---------------------------------------------------------------------------
// Aion-native payload builders.
// ---------------------------------------------------------------------------

/// Hex-encode a fixed-size hash to lowercase.
fn hex32(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

/// Build the canonical JSON body for an aion version attestation.
///
/// Shape matches the RFC-0023 §"Aion payload types" table.
#[must_use]
pub fn version_attestation_payload(version: &VersionEntry, signer: AuthorId) -> Vec<u8> {
    let json = serde_json::json!({
        "_type": "https://aion-context.dev/attestation/v1",
        "version": {
            "version_number": version.version_number,
            "parent_hash": hex32(&version.parent_hash),
            "rules_hash": hex32(&version.rules_hash),
            "author_id": version.author_id,
            "timestamp": version.timestamp,
            "message_offset": version.message_offset,
            "message_length": version.message_length,
        },
        "signer": signer.as_u64(),
    });
    // Safety: serde_json::to_vec on a Value cannot fail for finite data.
    serde_json::to_vec(&json).unwrap_or_else(|_| std::process::abort())
}

/// Build the canonical JSON body for an aion artifact manifest.
#[must_use]
pub fn manifest_payload(manifest: &ArtifactManifest) -> Vec<u8> {
    let entries: Vec<serde_json::Value> = manifest
        .entries()
        .iter()
        .map(|entry| {
            let name = manifest
                .name_of(entry)
                .unwrap_or("<invalid-utf8>")
                .to_string();
            serde_json::json!({
                "name": name,
                "size": entry.size,
                "hash_algorithm": "BLAKE3-256",
                "hash": hex32(&entry.hash),
            })
        })
        .collect();
    let json = serde_json::json!({
        "_type": "https://aion-context.dev/manifest/v1",
        "manifest_id": hex32(manifest.manifest_id()),
        "entries": entries,
    });
    serde_json::to_vec(&json).unwrap_or_else(|_| std::process::abort())
}

/// Wrap a version attestation into a DSSE envelope signed by `signer`.
#[must_use]
pub fn wrap_version_attestation(
    version: &VersionEntry,
    signer: AuthorId,
    key: &SigningKey,
) -> DsseEnvelope {
    let payload = version_attestation_payload(version, signer);
    sign_envelope(&payload, AION_ATTESTATION_TYPE, signer, key)
}

/// Wrap an artifact manifest into a DSSE envelope signed by `signer`.
#[must_use]
pub fn wrap_manifest(
    manifest: &ArtifactManifest,
    signer: AuthorId,
    key: &SigningKey,
) -> DsseEnvelope {
    let payload = manifest_payload(manifest);
    sign_envelope(&payload, AION_MANIFEST_TYPE, signer, key)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::key_registry::KeyRegistry;

    /// Build a registry pinning one signer at epoch 0 with `key` as its
    /// operational pubkey. Master key is throwaway.
    fn reg_pinning(signer: AuthorId, key: &SigningKey) -> KeyRegistry {
        let mut reg = KeyRegistry::new();
        let master = SigningKey::generate();
        reg.register_author(signer, master.verifying_key(), key.verifying_key(), 0)
            .unwrap_or_else(|_| std::process::abort());
        reg
    }

    /// Build a registry pinning every `(signer, key)` pair at epoch 0.
    fn reg_pinning_multi(pairs: &[(AuthorId, SigningKey)]) -> KeyRegistry {
        let mut reg = KeyRegistry::new();
        for (signer, key) in pairs {
            let master = SigningKey::generate();
            reg.register_author(*signer, master.verifying_key(), key.verifying_key(), 0)
                .unwrap_or_else(|_| std::process::abort());
        }
        reg
    }

    /// RFC-0023 Appendix vector: PAE("test", "hello").
    #[test]
    fn pae_matches_spec_vector() {
        let out = pae("test", b"hello");
        assert_eq!(out.as_slice(), b"DSSEv1 4 test 5 hello");
    }

    #[test]
    fn pae_empty_body_is_well_formed() {
        let out = pae("x", b"");
        assert_eq!(out.as_slice(), b"DSSEv1 1 x 0 ");
    }

    #[test]
    fn keyid_round_trip() {
        let a = AuthorId::new(12345);
        let k = keyid_for(a);
        assert_eq!(k, "aion:author:12345");
        let parsed = author_from_keyid(&k).unwrap();
        assert_eq!(parsed, a);
    }

    #[test]
    fn keyid_rejects_wrong_prefix() {
        assert!(author_from_keyid("not-aion:42").is_err());
        assert!(author_from_keyid("aion:author:xyz").is_err());
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key = SigningKey::generate();
        let signer = AuthorId::new(7);
        let envelope = sign_envelope(b"hello world", "text/plain", signer, &key);
        let reg = reg_pinning(signer, &key);
        let verified = verify_envelope(&envelope, &reg, 1).unwrap();
        assert_eq!(verified, vec![keyid_for(signer)]);
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let key = SigningKey::generate();
        let signer = AuthorId::new(7);
        let mut envelope = sign_envelope(b"hello", "text/plain", signer, &key);
        envelope.payload[0] ^= 0x01;
        let reg = reg_pinning(signer, &key);
        assert!(verify_envelope(&envelope, &reg, 1).is_err());
    }

    #[test]
    fn multi_signature_all_verify() {
        let k1 = SigningKey::generate();
        let k2 = SigningKey::generate();
        let s1 = AuthorId::new(1);
        let s2 = AuthorId::new(2);
        let mut env = sign_envelope(b"payload", "text/plain", s1, &k1);
        add_signature(&mut env, s2, &k2);
        let reg = reg_pinning_multi(&[(s1, k1), (s2, k2)]);
        let verified = verify_envelope(&env, &reg, 1).unwrap();
        assert_eq!(verified.len(), 2);
    }

    #[test]
    fn verify_rejects_empty_signatures() {
        let env = DsseEnvelope {
            payload_type: "text/plain".to_string(),
            payload: b"x".to_vec(),
            signatures: Vec::new(),
        };
        let reg = KeyRegistry::new();
        assert!(verify_envelope(&env, &reg, 1).is_err());
    }

    #[test]
    fn json_roundtrip_preserves_envelope() {
        let key = SigningKey::generate();
        let signer = AuthorId::new(3);
        let env = sign_envelope(b"abc", "text/plain", signer, &key);
        let json = env.to_json().unwrap();
        let parsed = DsseEnvelope::from_json(&json).unwrap();
        assert_eq!(parsed, env);
    }

    #[test]
    fn json_payload_field_uses_base64() {
        let key = SigningKey::generate();
        let signer = AuthorId::new(3);
        let env = sign_envelope(b"\xff\x00\x7f", "text/plain", signer, &key);
        let json = env.to_json().unwrap();
        // Expect base64-standard-no-padding of [0xff, 0x00, 0x7f] = "/wB/"
        assert!(json.contains("\"payload\":\"/wB/\""));
    }

    mod properties {
        use super::*;
        use hegel::generators as gs;

        #[hegel::test]
        fn prop_dsse_sign_verify_roundtrip(tc: hegel::TestCase) {
            let payload = tc.draw(gs::binary().max_size(1024));
            let ptype = tc.draw(gs::text().min_size(1).max_size(64));
            let signer = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let key = SigningKey::generate();
            let env = sign_envelope(&payload, &ptype, signer, &key);
            let reg = reg_pinning(signer, &key);
            let verified = verify_envelope(&env, &reg, 1).unwrap_or_else(|_| std::process::abort());
            assert_eq!(verified.len(), 1);
        }

        #[hegel::test]
        fn prop_dsse_tampered_payload_rejects(tc: hegel::TestCase) {
            let payload = tc.draw(gs::binary().min_size(1).max_size(1024));
            let ptype = tc.draw(gs::text().min_size(1).max_size(64));
            let signer = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let key = SigningKey::generate();
            let mut env = sign_envelope(&payload, &ptype, signer, &key);
            let max_idx = env.payload.len().saturating_sub(1);
            let idx = tc.draw(gs::integers::<usize>().max_value(max_idx));
            if let Some(byte) = env.payload.get_mut(idx) {
                *byte ^= 0x01;
            }
            let reg = reg_pinning(signer, &key);
            assert!(verify_envelope(&env, &reg, 1).is_err());
        }

        #[hegel::test]
        fn prop_dsse_tampered_payload_type_rejects(tc: hegel::TestCase) {
            let payload = tc.draw(gs::binary().max_size(1024));
            let ptype = tc.draw(gs::text().min_size(1).max_size(64));
            let signer = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let key = SigningKey::generate();
            let mut env = sign_envelope(&payload, &ptype, signer, &key);
            env.payload_type.push('!');
            let reg = reg_pinning(signer, &key);
            assert!(verify_envelope(&env, &reg, 1).is_err());
        }

        #[hegel::test]
        fn prop_dsse_wrong_key_rejects(tc: hegel::TestCase) {
            let payload = tc.draw(gs::binary().max_size(1024));
            let ptype = tc.draw(gs::text().min_size(1).max_size(64));
            let signer = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let real_key = SigningKey::generate();
            let fake_key = SigningKey::generate();
            let env = sign_envelope(&payload, &ptype, signer, &real_key);
            // Pin the WRONG key for the signer — registry check rejects.
            let reg = reg_pinning(signer, &fake_key);
            assert!(verify_envelope(&env, &reg, 1).is_err());
        }

        #[hegel::test]
        fn prop_dsse_json_roundtrip(tc: hegel::TestCase) {
            let payload = tc.draw(gs::binary().max_size(1024));
            let ptype = tc.draw(gs::text().min_size(1).max_size(64));
            let signer = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let key = SigningKey::generate();
            let env = sign_envelope(&payload, &ptype, signer, &key);
            let json = env.to_json().unwrap_or_else(|_| std::process::abort());
            let parsed = DsseEnvelope::from_json(&json).unwrap_or_else(|_| std::process::abort());
            assert_eq!(parsed, env);
        }

        #[hegel::test]
        fn prop_dsse_multi_signature_all_verify(tc: hegel::TestCase) {
            let n = tc.draw(gs::integers::<u32>().min_value(2).max_value(6));
            let payload = tc.draw(gs::binary().max_size(512));
            let ptype = tc.draw(gs::text().min_size(1).max_size(32));
            // Build N distinct (author, key) pairs.
            let signers: Vec<(AuthorId, SigningKey)> = (0..n)
                .map(|i| (AuthorId::new(1_000 + u64::from(i)), SigningKey::generate()))
                .collect();
            // Start an envelope with signer 0, then add 1..n.
            let first = signers.first().unwrap_or_else(|| std::process::abort());
            let mut env = sign_envelope(&payload, &ptype, first.0, &first.1);
            for (who, key) in signers.iter().skip(1) {
                add_signature(&mut env, *who, key);
            }
            let reg = reg_pinning_multi(&signers);
            let verified = verify_envelope(&env, &reg, 1).unwrap_or_else(|_| std::process::abort());
            assert_eq!(verified.len(), n as usize);
        }

        #[hegel::test]
        fn prop_dsse_verify_dedups_repeated_keyid(tc: hegel::TestCase) {
            // RFC-0033 C6: an envelope with N entries under the same
            // keyid must yield exactly one element in `verified`.
            let payload = tc.draw(gs::binary().max_size(256));
            let ptype = tc.draw(gs::text().min_size(1).max_size(32));
            let signer = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let extra = tc.draw(gs::integers::<usize>().min_value(1).max_value(4));
            let key = SigningKey::generate();
            let mut env = sign_envelope(&payload, &ptype, signer, &key);
            for _ in 0..extra {
                add_signature(&mut env, signer, &key);
            }
            let reg = reg_pinning(signer, &key);
            let verified = verify_envelope(&env, &reg, 1).unwrap_or_else(|_| std::process::abort());
            assert_eq!(verified.len(), 1);
        }

        #[hegel::test]
        fn prop_dsse_pae_injective_on_body(tc: hegel::TestCase) {
            // Two payloads that differ in any byte must produce
            // different PAE output for the same payload_type.
            let ptype = tc.draw(gs::text().min_size(1).max_size(32));
            let mut body_a = tc.draw(gs::binary().min_size(1).max_size(512));
            let idx = tc.draw(gs::integers::<usize>().max_value(body_a.len().saturating_sub(1)));
            let mut body_b = body_a.clone();
            if let Some(b) = body_b.get_mut(idx) {
                *b ^= 0x01;
            }
            // make them definitely differ even if idx was out-of-range
            body_a.push(0);
            body_b.push(1);
            assert_ne!(pae(&ptype, &body_a), pae(&ptype, &body_b));
        }

        #[hegel::test]
        fn prop_dsse_registry_verify_accepts_pinned_signer(tc: hegel::TestCase) {
            use crate::key_registry::KeyRegistry;
            let payload = tc.draw(gs::binary().max_size(512));
            let ptype = tc.draw(gs::text().min_size(1).max_size(32));
            let signer =
                AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 32)));
            let master = SigningKey::generate();
            let op = SigningKey::generate();
            let mut reg = KeyRegistry::new();
            reg.register_author(signer, master.verifying_key(), op.verifying_key(), 0)
                .unwrap_or_else(|_| std::process::abort());
            let env = sign_envelope(&payload, &ptype, signer, &op);
            let at = tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 20));
            let verified =
                verify_envelope(&env, &reg, at).unwrap_or_else(|_| std::process::abort());
            assert_eq!(verified.len(), 1);
            assert_eq!(verified[0], keyid_for(signer));
        }

        #[hegel::test]
        fn prop_dsse_registry_verify_rejects_unknown_signer(tc: hegel::TestCase) {
            use crate::key_registry::KeyRegistry;
            let payload = tc.draw(gs::binary().max_size(256));
            let ptype = tc.draw(gs::text().min_size(1).max_size(32));
            let signer =
                AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 32)));
            let op = SigningKey::generate();
            // Registry is empty — `signer` is not registered.
            let reg = KeyRegistry::new();
            let env = sign_envelope(&payload, &ptype, signer, &op);
            let at = tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 20));
            assert!(verify_envelope(&env, &reg, at).is_err());
        }

        #[hegel::test]
        fn prop_dsse_registry_verify_rejects_revoked_signer(tc: hegel::TestCase) {
            use crate::key_registry::{sign_revocation_record, KeyRegistry, RevocationReason};
            let payload = tc.draw(gs::binary().max_size(256));
            let ptype = tc.draw(gs::text().min_size(1).max_size(32));
            let signer =
                AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 32)));
            let master = SigningKey::generate();
            let op = SigningKey::generate();
            let mut reg = KeyRegistry::new();
            reg.register_author(signer, master.verifying_key(), op.verifying_key(), 0)
                .unwrap_or_else(|_| std::process::abort());
            let effective = tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 20));
            let revocation = sign_revocation_record(
                signer,
                0,
                RevocationReason::Compromised,
                effective,
                &master,
            );
            reg.apply_revocation(&revocation)
                .unwrap_or_else(|_| std::process::abort());
            let env = sign_envelope(&payload, &ptype, signer, &op);
            let v_after = effective.saturating_add(1);
            assert!(verify_envelope(&env, &reg, v_after).is_err());
        }
    }
}
