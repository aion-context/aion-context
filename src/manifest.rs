//! External artifact manifest — RFC-0022.
//!
//! `.aion` files attest to governance context (policy, approvals, audit).
//! Large artifacts the governance refers to — pretrained model weights,
//! datasets, firmware images — are too large to embed. This module lets
//! an `.aion` file bind to external binary blobs by their BLAKE3 hash,
//! carrying `(name, size, hash)` triples in a signed manifest.
//!
//! Phase A (this module) provides:
//!
//! - [`ArtifactEntry`]: 128-byte `#[repr(C)]` descriptor — name offset,
//!   size, hash algorithm, 32-byte BLAKE3 hash.
//! - [`ArtifactManifestBuilder`]: accumulates entries, computes hashes.
//! - [`ArtifactManifest`]: built manifest with canonical serialization.
//! - [`sign_manifest`] / [`verify_manifest_signature`]: signing path
//!   bound to the RFC-0021 attestation domain.
//!
//! Phase B (future RFC) will embed the manifest in the on-disk
//! `.aion` file format and add CLI / SLSA / AIBOM integration.
//!
//! # Example
//!
//! ```
//! use aion_context::manifest::{ArtifactManifestBuilder, sign_manifest, verify_manifest_signature};
//! use aion_context::crypto::SigningKey;
//! use aion_context::types::AuthorId;
//!
//! let mut builder = ArtifactManifestBuilder::new();
//! let weights: Vec<u8> = vec![0xAA; 128];
//! let _handle = builder.add("model.bin", &weights);
//! let manifest = builder.build();
//!
//! manifest.verify_artifact("model.bin", &weights).unwrap();
//!
//! let signer = AuthorId::new(1001);
//! let key = SigningKey::generate();
//! let sig = sign_manifest(&manifest, signer, &key);
//! assert!(verify_manifest_signature(&manifest, &sig).is_ok());
//! ```

use zerocopy::AsBytes;

use crate::crypto::{hash, SigningKey, VerifyingKey};
use crate::serializer::SignatureEntry;
use crate::types::AuthorId;
use crate::{AionError, Result};

/// Size of a serialized [`ArtifactEntry`] in bytes.
pub const ARTIFACT_ENTRY_SIZE: usize = 128;

/// Inner domain separator for canonical manifest bytes (RFC-0022).
///
/// Distinct from the attestation domain so a manifest signature cannot
/// collide with a version attestation even though both route through
/// `canonical_attestation_message`.
const MANIFEST_DOMAIN: &[u8] = b"AION_V2_MANIFEST_V1";

/// Hash algorithms recognized by an [`ArtifactEntry`].
///
/// Stored as a `u16` on disk so new algorithms can be added without a
/// struct layout change.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// BLAKE3-256, 32-byte digest.
    Blake3_256 = 1,
}

impl HashAlgorithm {
    /// Convert a raw `u16` back to a known algorithm.
    ///
    /// # Errors
    ///
    /// Returns `AionError::InvalidFormat` for unrecognized discriminants.
    pub fn from_u16(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::Blake3_256),
            other => Err(AionError::InvalidFormat {
                reason: format!("Unknown manifest hash algorithm: {other}"),
            }),
        }
    }
}

/// Fixed-size descriptor for a single external artifact — 128 bytes.
///
/// Field layout is stable and `#[repr(C)]` for zero-copy serialization.
#[repr(C)]
#[derive(Debug, Clone, Copy, AsBytes)]
pub struct ArtifactEntry {
    /// Offset of the artifact's name in the manifest's name table.
    pub name_offset: u64,
    /// Length of the artifact's name in bytes (UTF-8, no null).
    pub name_length: u32,
    /// Hash algorithm discriminant — see [`HashAlgorithm`].
    pub hash_algorithm: u16,
    /// Reserved; must be zero.
    pub reserved1: [u8; 2],
    /// Size of the external artifact in bytes.
    pub size: u64,
    /// 32-byte hash of the full artifact content.
    pub hash: [u8; 32],
    /// Reserved; must be zero. Space for future Merkle root, chunk
    /// size, or per-entry signature scope (Phase B).
    pub reserved2: [u8; 72],
}

const _: () = assert!(std::mem::size_of::<ArtifactEntry>() == ARTIFACT_ENTRY_SIZE);

impl ArtifactEntry {
    /// Build a new entry. The caller supplies offsets derived from the
    /// manifest's name table; prefer [`ArtifactManifestBuilder::add`].
    #[must_use]
    pub const fn new(name_offset: u64, name_length: u32, size: u64, hash: [u8; 32]) -> Self {
        Self {
            name_offset,
            name_length,
            hash_algorithm: HashAlgorithm::Blake3_256 as u16,
            reserved1: [0; 2],
            size,
            hash,
            reserved2: [0; 72],
        }
    }
}

/// Handle returned by [`ArtifactManifestBuilder::add`] — opaque for now.
///
/// Phase B may extend this with chunk offsets or Merkle-proof positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactHandle {
    index: usize,
}

impl ArtifactHandle {
    /// 0-based position of the artifact in the manifest's entry list.
    #[must_use]
    pub const fn index(self) -> usize {
        self.index
    }
}

/// Accumulator for building an [`ArtifactManifest`].
#[derive(Debug, Default)]
pub struct ArtifactManifestBuilder {
    entries: Vec<ArtifactEntry>,
    name_table: Vec<u8>,
}

impl ArtifactManifestBuilder {
    /// Construct an empty builder.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Vec::new() not const in MSRV 1.70
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            name_table: Vec::new(),
        }
    }

    /// Register an artifact by `name` and compute its BLAKE3 hash over
    /// `bytes`. Returns a handle; the manifest records the hash, not
    /// the bytes themselves.
    #[must_use = "the returned ArtifactHandle is the only way to refer to this artifact by index later"]
    #[allow(clippy::cast_possible_truncation)] // Name lengths capped by u32::MAX in practice
    pub fn add(&mut self, name: &str, bytes: &[u8]) -> ArtifactHandle {
        let name_offset = self.name_table.len() as u64;
        let name_length = name.len() as u32;
        self.name_table.extend_from_slice(name.as_bytes());
        self.name_table.push(0);

        let digest = hash(bytes);
        let entry = ArtifactEntry::new(name_offset, name_length, bytes.len() as u64, digest);
        let index = self.entries.len();
        self.entries.push(entry);
        ArtifactHandle { index }
    }

    /// Finalize the manifest. Computes the manifest-level hash over
    /// the canonical bytes.
    #[must_use]
    pub fn build(self) -> ArtifactManifest {
        let canonical = canonical_manifest_bytes(&self.entries, &self.name_table);
        let manifest_id = hash(&canonical);
        ArtifactManifest {
            manifest_id,
            entries: self.entries,
            name_table: self.name_table,
        }
    }
}

/// A built, attestable artifact manifest.
#[derive(Debug, Clone)]
pub struct ArtifactManifest {
    /// BLAKE3 hash of the canonical manifest bytes.
    manifest_id: [u8; 32],
    entries: Vec<ArtifactEntry>,
    name_table: Vec<u8>,
}

impl ArtifactManifest {
    /// Manifest-level identity hash.
    #[must_use]
    pub const fn manifest_id(&self) -> &[u8; 32] {
        &self.manifest_id
    }

    /// Entry list (stable order).
    #[must_use]
    pub fn entries(&self) -> &[ArtifactEntry] {
        &self.entries
    }

    /// Raw name-table bytes (null-terminated UTF-8).
    #[must_use]
    pub fn name_table(&self) -> &[u8] {
        &self.name_table
    }

    /// Canonical serialized form used for signing and hashing.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_manifest_bytes(&self.entries, &self.name_table)
    }

    /// Look up the name string for an entry.
    ///
    /// # Errors
    ///
    /// Returns `AionError::InvalidFormat` if `name_offset` + `name_length`
    /// fall outside the name table or the slice is not valid UTF-8.
    pub fn name_of(&self, entry: &ArtifactEntry) -> Result<&str> {
        slice_name(&self.name_table, entry.name_offset, entry.name_length)
    }

    /// Re-hash `bytes` and check it matches the recorded size and hash
    /// for `name`. First-match wins if duplicate names were added.
    ///
    /// # Errors
    ///
    /// Returns `AionError::InvalidFormat` if no entry matches the name,
    /// the byte length disagrees with the recorded size, or the BLAKE3
    /// digest differs.
    pub fn verify_artifact(&self, name: &str, bytes: &[u8]) -> Result<()> {
        for entry in &self.entries {
            let candidate = self.name_of(entry)?;
            if candidate != name {
                continue;
            }
            if bytes.len() as u64 != entry.size {
                return Err(AionError::InvalidFormat {
                    reason: format!(
                        "artifact '{name}': size mismatch (expected {}, got {})",
                        entry.size,
                        bytes.len()
                    ),
                });
            }
            let digest = hash(bytes);
            if digest != entry.hash {
                return Err(AionError::InvalidFormat {
                    reason: format!("artifact '{name}': hash mismatch"),
                });
            }
            return Ok(());
        }
        Err(AionError::InvalidFormat {
            reason: format!("artifact '{name}' not found in manifest"),
        })
    }
}

/// Extract a name slice from a name table.
fn slice_name(table: &[u8], offset: u64, length: u32) -> Result<&str> {
    let start = usize::try_from(offset).map_err(|_| AionError::InvalidFormat {
        reason: "manifest name_offset exceeds usize".to_string(),
    })?;
    let len = length as usize;
    let end = start
        .checked_add(len)
        .ok_or_else(|| AionError::InvalidFormat {
            reason: "manifest name_offset + name_length overflows".to_string(),
        })?;
    let slice = table
        .get(start..end)
        .ok_or_else(|| AionError::InvalidFormat {
            reason: "manifest name slice out of bounds".to_string(),
        })?;
    std::str::from_utf8(slice).map_err(|e| AionError::InvalidFormat {
        reason: format!("manifest name is not valid UTF-8: {e}"),
    })
}

/// Serialize the manifest to its canonical on-wire form:
/// `MANIFEST_DOMAIN || entry_count_le || entries || name_table`.
fn canonical_manifest_bytes(entries: &[ArtifactEntry], name_table: &[u8]) -> Vec<u8> {
    let entries_len = entries
        .len()
        .checked_mul(ARTIFACT_ENTRY_SIZE)
        .unwrap_or_else(|| std::process::abort());
    let capacity = MANIFEST_DOMAIN
        .len()
        .saturating_add(8)
        .saturating_add(entries_len)
        .saturating_add(name_table.len());
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(MANIFEST_DOMAIN);
    out.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for entry in entries {
        out.extend_from_slice(entry.as_bytes());
    }
    out.extend_from_slice(name_table);
    out
}

/// Domain separator for manifest-identity signatures.
///
/// Dedicated to manifest signing under RFC-0033 C7, so the bytes
/// signed are never confused with — nor replayable as — a
/// multi-party attestation produced by `signature_chain` under
/// `ATTESTATION_DOMAIN`. The trailing NUL forbids any other
/// aion domain from being constructed by appending bytes.
pub const MANIFEST_SIGNATURE_DOMAIN: &[u8] = b"AION_V2_MANIFEST_SIG_V1\0";

/// Build the canonical bytes signed by [`sign_manifest`] and
/// verified by [`verify_manifest_signature`]:
/// `MANIFEST_SIGNATURE_DOMAIN || manifest_id(32 B) || signer_le(8 B)`.
#[must_use]
pub fn canonical_manifest_signature_message(
    manifest: &ArtifactManifest,
    signer: AuthorId,
) -> Vec<u8> {
    let capacity = MANIFEST_SIGNATURE_DOMAIN
        .len()
        .saturating_add(32)
        .saturating_add(8);
    let mut msg = Vec::with_capacity(capacity);
    msg.extend_from_slice(MANIFEST_SIGNATURE_DOMAIN);
    msg.extend_from_slice(manifest.manifest_id());
    msg.extend_from_slice(&signer.as_u64().to_le_bytes());
    msg
}

/// Sign a manifest as `signer` using `signing_key`. The returned
/// [`SignatureEntry`] binds to the manifest-id under the dedicated
/// manifest-signature domain ([`MANIFEST_SIGNATURE_DOMAIN`]).
#[must_use]
pub fn sign_manifest(
    manifest: &ArtifactManifest,
    signer: AuthorId,
    signing_key: &SigningKey,
) -> SignatureEntry {
    let message = canonical_manifest_signature_message(manifest, signer);
    let signature = signing_key.sign(&message);
    let public_key = signing_key.verifying_key().to_bytes();
    SignatureEntry::new(signer, public_key, signature)
}

/// Verify a manifest signature against a pinned
/// [`KeyRegistry`](crate::key_registry::KeyRegistry) — RFC-0022 / RFC-0034.
///
/// Cross-checks `signature.public_key` against the active epoch
/// for `(signature.author_id, at_version)` in `registry` before
/// running the Ed25519 verify. Rejects signatures made by keys
/// that have been rotated out or revoked as of `at_version`, and
/// signatures whose embedded public key does not match the
/// registered active epoch (closing the `public_key`-substitution
/// gap).
///
/// # Errors
///
/// Returns `AionError::SignatureVerificationFailed { version: at_version, author }`
/// if the registry has no active epoch for the signer at
/// `at_version`, if the signature's embedded public key does not
/// match that epoch, or if the underlying Ed25519 verification
/// fails.
pub fn verify_manifest_signature(
    manifest: &ArtifactManifest,
    signature: &SignatureEntry,
    registry: &crate::key_registry::KeyRegistry,
    at_version: u64,
) -> Result<()> {
    let signer = AuthorId::new(signature.author_id);
    let epoch = registry.active_epoch_at(signer, at_version).ok_or(
        crate::AionError::SignatureVerificationFailed {
            version: at_version,
            author: signer,
        },
    )?;
    if signature.public_key != epoch.public_key {
        return Err(crate::AionError::SignatureVerificationFailed {
            version: at_version,
            author: signer,
        });
    }
    let message = canonical_manifest_signature_message(manifest, signer);
    let verifying_key = VerifyingKey::from_bytes(&signature.public_key)?;
    verifying_key.verify(&message, &signature.signature)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(deprecated)] // RFC-0034 Phase D: tests exercise the deprecated raw-key verify_manifest_signature contract
mod tests {
    use super::*;

    #[test]
    fn should_build_and_verify_single_artifact() {
        let bytes = b"payload bytes";
        let mut b = ArtifactManifestBuilder::new();
        let _h = b.add("payload.bin", bytes);
        let m = b.build();
        assert_eq!(m.entries().len(), 1);
        assert!(m.verify_artifact("payload.bin", bytes).is_ok());
    }

    #[test]
    fn should_reject_size_mismatch() {
        let mut b = ArtifactManifestBuilder::new();
        let _ = b.add("x", &[1, 2, 3]);
        let m = b.build();
        assert!(m.verify_artifact("x", &[1, 2, 3, 4]).is_err());
    }

    #[test]
    fn should_reject_hash_mismatch() {
        let mut b = ArtifactManifestBuilder::new();
        let _ = b.add("x", &[1, 2, 3]);
        let m = b.build();
        assert!(m.verify_artifact("x", &[3, 2, 1]).is_err());
    }

    #[test]
    fn should_reject_unknown_name() {
        let mut b = ArtifactManifestBuilder::new();
        let _ = b.add("x", &[1, 2, 3]);
        let m = b.build();
        assert!(m.verify_artifact("y", &[1, 2, 3]).is_err());
    }

    #[test]
    fn should_handle_empty_artifact() {
        let mut b = ArtifactManifestBuilder::new();
        let _ = b.add("empty", &[]);
        let m = b.build();
        assert!(m.verify_artifact("empty", &[]).is_ok());
    }

    use crate::key_registry::KeyRegistry;

    /// Minimal test fixture: pin `key` as the active op key for `author` at epoch 0.
    fn reg_pinning(author: AuthorId, key: &SigningKey) -> KeyRegistry {
        let mut reg = KeyRegistry::new();
        let master = SigningKey::generate();
        reg.register_author(author, master.verifying_key(), key.verifying_key(), 0)
            .unwrap_or_else(|_| std::process::abort());
        reg
    }

    #[test]
    fn should_sign_and_verify_manifest() {
        let mut b = ArtifactManifestBuilder::new();
        let _ = b.add("a", b"alpha");
        let _ = b.add("b", b"beta");
        let m = b.build();
        let signer = AuthorId::new(42);
        let key = SigningKey::generate();
        let sig = sign_manifest(&m, signer, &key);
        let reg = reg_pinning(signer, &key);
        assert!(verify_manifest_signature(&m, &sig, &reg, 1).is_ok());
    }

    #[test]
    fn should_reject_signature_for_different_manifest() {
        let key = SigningKey::generate();
        let signer = AuthorId::new(7);

        let mut b1 = ArtifactManifestBuilder::new();
        let _ = b1.add("a", b"alpha");
        let m1 = b1.build();

        let mut b2 = ArtifactManifestBuilder::new();
        let _ = b2.add("a", b"alpha-different");
        let m2 = b2.build();

        let sig = sign_manifest(&m1, signer, &key);
        let reg = reg_pinning(signer, &key);
        assert!(verify_manifest_signature(&m2, &sig, &reg, 1).is_err());
    }

    mod properties {
        use super::*;
        use hegel::generators as gs;

        /// Draw a list of (name, bytes) pairs with distinct names so
        /// `verify_artifact` can unambiguously look each entry up.
        fn draw_artifacts(tc: &hegel::TestCase) -> Vec<(String, Vec<u8>)> {
            let n = tc.draw(gs::integers::<usize>().min_value(1).max_value(6));
            let mut out: Vec<(String, Vec<u8>)> = Vec::with_capacity(n);
            let mut counter: u64 = 0;
            while out.len() < n {
                let bytes = tc.draw(gs::binary().max_size(512));
                // Synthetic distinct names: "a_0", "a_1", ...
                let name = format!("artifact_{counter}");
                counter = counter.saturating_add(1);
                out.push((name, bytes));
            }
            out
        }

        fn build_manifest(pairs: &[(String, Vec<u8>)]) -> ArtifactManifest {
            let mut b = ArtifactManifestBuilder::new();
            for (name, bytes) in pairs {
                let _ = b.add(name, bytes);
            }
            b.build()
        }

        #[hegel::test]
        fn prop_manifest_build_verify_roundtrip(tc: hegel::TestCase) {
            let pairs = draw_artifacts(&tc);
            let manifest = build_manifest(&pairs);
            for (name, bytes) in &pairs {
                manifest
                    .verify_artifact(name, bytes)
                    .unwrap_or_else(|_| std::process::abort());
            }
        }

        #[hegel::test]
        fn prop_manifest_byte_flip_rejects(tc: hegel::TestCase) {
            let pairs = draw_artifacts(&tc);
            let manifest = build_manifest(&pairs);
            // Pick an entry with at least one byte to tamper.
            let candidate = pairs.iter().find(|(_, b)| !b.is_empty());
            if let Some((name, bytes)) = candidate {
                let mut tampered = bytes.clone();
                let max_idx = tampered.len().saturating_sub(1);
                let idx = tc.draw(gs::integers::<usize>().max_value(max_idx));
                if let Some(b) = tampered.get_mut(idx) {
                    *b ^= 0x01;
                }
                assert!(manifest.verify_artifact(name, &tampered).is_err());
            }
        }

        #[hegel::test]
        fn prop_manifest_size_mismatch_rejects(tc: hegel::TestCase) {
            let pairs = draw_artifacts(&tc);
            let manifest = build_manifest(&pairs);
            for (name, bytes) in &pairs {
                let mut truncated = bytes.clone();
                let extra = tc.draw(gs::integers::<u8>().min_value(1).max_value(16));
                truncated.extend(std::iter::repeat(0u8).take(usize::from(extra)));
                assert!(manifest.verify_artifact(name, &truncated).is_err());
            }
        }

        #[hegel::test]
        fn prop_manifest_sign_verify_roundtrip(tc: hegel::TestCase) {
            let pairs = draw_artifacts(&tc);
            let manifest = build_manifest(&pairs);
            let signer = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let key = SigningKey::generate();
            let sig = sign_manifest(&manifest, signer, &key);
            let reg = reg_pinning(signer, &key);
            assert!(verify_manifest_signature(&manifest, &sig, &reg, 1).is_ok());
        }

        #[hegel::test]
        fn prop_manifest_signature_rebinds_after_mutation(tc: hegel::TestCase) {
            // A signature made for manifest M1 must not verify for any
            // manifest M2 that differs in entry content or name.
            let pairs = draw_artifacts(&tc);
            let m1 = build_manifest(&pairs);
            // Build m2 with one extra entry -> different manifest_id.
            let extra_bytes = tc.draw(gs::binary().min_size(1).max_size(32));
            let mut b2 = ArtifactManifestBuilder::new();
            for (name, bytes) in &pairs {
                let _ = b2.add(name, bytes);
            }
            let _ = b2.add("__tamper__", &extra_bytes);
            let m2 = b2.build();
            let signer = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let key = SigningKey::generate();
            let sig = sign_manifest(&m1, signer, &key);
            let reg = reg_pinning(signer, &key);
            assert!(verify_manifest_signature(&m2, &sig, &reg, 1).is_err());
        }

        #[hegel::test]
        fn prop_manifest_signature_rejects_wrong_signer(tc: hegel::TestCase) {
            let pairs = draw_artifacts(&tc);
            let m = build_manifest(&pairs);
            let real_signer =
                AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1).max_value(u64::MAX / 2)));
            let fake_signer = AuthorId::new(real_signer.as_u64().saturating_add(1));
            let key = SigningKey::generate();
            let mut sig = sign_manifest(&m, real_signer, &key);
            sig.author_id = fake_signer.as_u64();
            // Pin the real_signer; tamper claims fake_signer; not in registry → reject.
            let reg = reg_pinning(real_signer, &key);
            assert!(verify_manifest_signature(&m, &sig, &reg, 1).is_err());
        }

        #[hegel::test]
        fn prop_manifest_signature_domain_is_separated(tc: hegel::TestCase) {
            // RFC-0033 C7: manifest signing uses MANIFEST_SIGNATURE_DOMAIN,
            // which must differ from any other aion signing domain. A
            // raw Ed25519 signature produced directly over the
            // manifest_id — i.e. without MANIFEST_SIGNATURE_DOMAIN —
            // must not verify as a manifest signature.
            let pairs = draw_artifacts(&tc);
            let m = build_manifest(&pairs);
            let signer =
                AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1).max_value(u64::MAX / 2)));
            let key = SigningKey::generate();
            let raw_signature = key.sign(m.manifest_id());
            let entry = SignatureEntry::new(signer, key.verifying_key().to_bytes(), raw_signature);
            let reg = reg_pinning(signer, &key);
            assert!(verify_manifest_signature(&m, &entry, &reg, 1).is_err());
        }

        #[hegel::test]
        fn prop_manifest_registry_verify_accepts_active_epoch(tc: hegel::TestCase) {
            use crate::key_registry::{sign_rotation_record, KeyRegistry};
            let pairs = draw_artifacts(&tc);
            let m = build_manifest(&pairs);
            let signer =
                AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 32)));
            let master = SigningKey::generate();
            let op = SigningKey::generate();
            let mut reg = KeyRegistry::new();
            reg.register_author(signer, master.verifying_key(), op.verifying_key(), 0)
                .unwrap_or_else(|_| std::process::abort());
            let sig = sign_manifest(&m, signer, &op);
            let at = tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 20));
            assert!(verify_manifest_signature(&m, &sig, &reg, at).is_ok());
            let _ = sign_rotation_record; // keep import live in all test configs
        }

        #[hegel::test]
        fn prop_manifest_registry_verify_rejects_rotated_out_key(tc: hegel::TestCase) {
            use crate::key_registry::{sign_rotation_record, KeyRegistry};
            let pairs = draw_artifacts(&tc);
            let m = build_manifest(&pairs);
            let signer =
                AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 32)));
            let master = SigningKey::generate();
            let op0 = SigningKey::generate();
            let op1 = SigningKey::generate();
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
            // Sign the manifest with the rotated-OUT op0 key.
            let sig = sign_manifest(&m, signer, &op0);
            let v_after = effective.saturating_add(1);
            assert!(verify_manifest_signature(&m, &sig, &reg, v_after).is_err());
        }

        #[hegel::test]
        fn prop_manifest_registry_verify_rejects_pubkey_substitution(tc: hegel::TestCase) {
            use crate::key_registry::KeyRegistry;
            let pairs = draw_artifacts(&tc);
            let m = build_manifest(&pairs);
            let signer =
                AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 32)));
            let master = SigningKey::generate();
            let op = SigningKey::generate();
            let mut reg = KeyRegistry::new();
            reg.register_author(signer, master.verifying_key(), op.verifying_key(), 0)
                .unwrap_or_else(|_| std::process::abort());
            // Attacker mints a valid-shaped key and signs under the target AuthorId.
            let attacker = SigningKey::generate();
            let sig = sign_manifest(&m, signer, &attacker);
            let at = tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 20));
            // With only the registry-aware API remaining (Phase E), this
            // must reject because the attacker's pubkey does not match the
            // pinned active epoch.
            assert!(verify_manifest_signature(&m, &sig, &reg, at).is_err());
        }
    }
}
