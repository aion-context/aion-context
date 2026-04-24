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
//! use aion_context::types::AuthorId;
//!
//! let payload = br#"{"_type":"https://aion-context.dev/attestation/v1"}"#;
//! let signer = AuthorId::new(50001);
//! let key = SigningKey::generate();
//! let verifying = key.verifying_key();
//!
//! let envelope = sign_envelope(payload, AION_ATTESTATION_TYPE, signer, &key);
//! let verified = verify_envelope(&envelope, |keyid| {
//!     if keyid == "aion:author:50001" { Some(verifying.clone()) } else { None }
//! }).unwrap();
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

/// Verify every signature in `envelope`, returning the distinct
/// keyids of verified signatures in envelope order.
///
/// A given `keyid` contributes to the returned vector **at most
/// once** even if the envelope carries multiple signature entries
/// under the same keyid (RFC-0033 C6): callers counting
/// `verified.len()` for quorum cannot be tricked into double-
/// counting by a repeated signer. The second and subsequent
/// entries for the same keyid are silently skipped.
///
/// # Errors
///
/// Returns `Err` if the envelope carries zero signatures, if any
/// signature lacks a pinned key under `key_for`, or if any signature
/// fails to verify.
pub fn verify_envelope<F>(envelope: &DsseEnvelope, key_for: F) -> Result<Vec<String>>
where
    F: Fn(&str) -> Option<VerifyingKey>,
{
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
        let verifying_key = key_for(&sig_entry.keyid).ok_or_else(|| AionError::InvalidFormat {
            reason: format!("no pinned key for keyid: {}", sig_entry.keyid),
        })?;
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
        let verifying = key.verifying_key();
        let signer = AuthorId::new(7);
        let envelope = sign_envelope(b"hello world", "text/plain", signer, &key);
        let verified = verify_envelope(&envelope, |keyid| {
            if keyid == keyid_for(signer) {
                Some(verifying)
            } else {
                None
            }
        })
        .unwrap();
        assert_eq!(verified, vec![keyid_for(signer)]);
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let key = SigningKey::generate();
        let verifying = key.verifying_key();
        let signer = AuthorId::new(7);
        let mut envelope = sign_envelope(b"hello", "text/plain", signer, &key);
        envelope.payload[0] ^= 0x01;
        let result = verify_envelope(&envelope, |_| Some(verifying));
        assert!(result.is_err());
    }

    #[test]
    fn multi_signature_all_verify() {
        let s1 = (AuthorId::new(1), SigningKey::generate());
        let s2 = (AuthorId::new(2), SigningKey::generate());
        let k1 = s1.1.verifying_key();
        let k2 = s2.1.verifying_key();
        let mut env = sign_envelope(b"payload", "text/plain", s1.0, &s1.1);
        add_signature(&mut env, s2.0, &s2.1);
        let verified = verify_envelope(&env, |keyid| {
            if keyid == keyid_for(s1.0) {
                Some(k1)
            } else if keyid == keyid_for(s2.0) {
                Some(k2)
            } else {
                None
            }
        })
        .unwrap();
        assert_eq!(verified.len(), 2);
    }

    #[test]
    fn verify_rejects_empty_signatures() {
        let env = DsseEnvelope {
            payload_type: "text/plain".to_string(),
            payload: b"x".to_vec(),
            signatures: Vec::new(),
        };
        assert!(verify_envelope(&env, |_| None::<VerifyingKey>).is_err());
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
            let verifying = key.verifying_key();
            let env = sign_envelope(&payload, &ptype, signer, &key);
            let verified = verify_envelope(&env, |keyid| {
                if keyid == keyid_for(signer) {
                    Some(verifying)
                } else {
                    None
                }
            })
            .unwrap_or_else(|_| std::process::abort());
            assert_eq!(verified.len(), 1);
        }

        #[hegel::test]
        fn prop_dsse_tampered_payload_rejects(tc: hegel::TestCase) {
            let payload = tc.draw(gs::binary().min_size(1).max_size(1024));
            let ptype = tc.draw(gs::text().min_size(1).max_size(64));
            let signer = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let key = SigningKey::generate();
            let verifying = key.verifying_key();
            let mut env = sign_envelope(&payload, &ptype, signer, &key);
            let max_idx = env.payload.len().saturating_sub(1);
            let idx = tc.draw(gs::integers::<usize>().max_value(max_idx));
            if let Some(byte) = env.payload.get_mut(idx) {
                *byte ^= 0x01;
            }
            let result = verify_envelope(&env, |_| Some(verifying));
            assert!(result.is_err());
        }

        #[hegel::test]
        fn prop_dsse_tampered_payload_type_rejects(tc: hegel::TestCase) {
            let payload = tc.draw(gs::binary().max_size(1024));
            let ptype = tc.draw(gs::text().min_size(1).max_size(64));
            let signer = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let key = SigningKey::generate();
            let verifying = key.verifying_key();
            let mut env = sign_envelope(&payload, &ptype, signer, &key);
            env.payload_type.push('!');
            let result = verify_envelope(&env, |_| Some(verifying));
            assert!(result.is_err());
        }

        #[hegel::test]
        fn prop_dsse_wrong_key_rejects(tc: hegel::TestCase) {
            let payload = tc.draw(gs::binary().max_size(1024));
            let ptype = tc.draw(gs::text().min_size(1).max_size(64));
            let signer = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let real_key = SigningKey::generate();
            let fake_key = SigningKey::generate();
            let env = sign_envelope(&payload, &ptype, signer, &real_key);
            let result = verify_envelope(&env, |_| Some(fake_key.verifying_key()));
            assert!(result.is_err());
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
            // Build a lookup: keyid -> verifying key.
            let lookup: std::collections::HashMap<String, VerifyingKey> = signers
                .iter()
                .map(|(who, key)| (keyid_for(*who), key.verifying_key()))
                .collect();
            let verified = verify_envelope(&env, |keyid| lookup.get(keyid).copied())
                .unwrap_or_else(|_| std::process::abort());
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
            let verifying = key.verifying_key();
            let mut env = sign_envelope(&payload, &ptype, signer, &key);
            for _ in 0..extra {
                add_signature(&mut env, signer, &key);
            }
            let verified = verify_envelope(&env, |keyid| {
                if keyid == keyid_for(signer) {
                    Some(verifying)
                } else {
                    None
                }
            })
            .unwrap_or_else(|_| std::process::abort());
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
    }
}
