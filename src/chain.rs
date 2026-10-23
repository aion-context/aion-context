// SPDX-License-Identifier: MIT OR Apache-2.0
//! Verified chains: the only way to read rules from a verified file
//! (RFC-0039).
//!
//! A [`VerifiedChain`] can only come from successful verification
//! ([`verify_file_chain`] or [`VerifiedChain::from_bytes`]). It owns the
//! exact bytes it verified, and it hands out [`VerifiedEntry`] references
//! to its signature-checked version entries. Nothing in the public API
//! builds either type from raw fields, so:
//!
//! - a forged or unverified entry can never drive a read;
//! - replacing the file on disk after verification changes nothing,
//!   because reads come from the owned bytes, never from the path.
//!
//! [`RecipientKeys`] carries the identities a reader holds. Confidential
//! writers arrive in RFC-0039 Phase B; until then, [`RecipientKeys::none`]
//! opens public and format-v2 rules.
//!
//! # Example
//!
//! ```no_run
//! use aion_context::chain::{open_current_rules, verify_file_chain, RecipientKeys};
//! use aion_context::key_registry::KeyRegistry;
//! use std::path::Path;
//!
//! # fn example(registry: &KeyRegistry) -> aion_context::Result<()> {
//! let chain = verify_file_chain(Path::new("policy.aion"), registry)?;
//! let rules = open_current_rules(&chain, &RecipientKeys::none())?;
//! println!("{} bytes of rules at version {}", rules.len(), chain.head().version().as_u64());
//! # Ok(())
//! # }
//! ```
//!
//! A [`VerifiedEntry`] cannot be built outside the crate:
//!
//! ```compile_fail,E0451
//! use aion_context::chain::{VerifiedChain, VerifiedEntry};
//! use aion_context::serializer::VersionEntry;
//!
//! fn forge<'a>(chain: &'a VerifiedChain, entry: &'a VersionEntry) -> VerifiedEntry<'a> {
//!     VerifiedEntry { chain, checked: entry }
//! }
//! ```

use std::path::Path;

use zeroize::Zeroizing;

use crate::format::{rules_commitment, unframe_rules, FileContext, FormatVersion, RulesMode};
use crate::key_registry::KeyRegistry;
use crate::parser::AionParser;
use crate::serializer::VersionEntry;
use crate::types::{AuthorId, VersionNumber};
use crate::{AionError, Result};

/// A file that passed full verification, holding the verified entries and
/// the verified head rules section.
///
/// Built only by [`verify_file_chain`] or [`VerifiedChain::from_bytes`].
/// It is deliberately not `Clone`: the only way to get one is to verify.
#[derive(Debug)]
pub struct VerifiedChain {
    context: FileContext,
    entries: Vec<CheckedEntry>,
    head: CheckedEntry,
    head_section: Vec<u8>,
}

/// A version entry together with its rules mode and version hash, both
/// computed once during verification so no accessor ever has to drop a
/// decoding error.
#[derive(Debug, Clone, Copy)]
struct CheckedEntry {
    entry: VersionEntry,
    mode: Option<RulesMode>,
    version_hash: [u8; 32],
}

/// Read and fully verify a file, returning a [`VerifiedChain`] over the
/// bytes that were read.
///
/// Runs exactly the checks [`crate::operations::verify_file`] runs:
/// structure, integrity hash, content hash chain, signatures against
/// `registry`, and the audit chain.
///
/// # Errors
///
/// Returns [`AionError::FileReadError`] if the file cannot be read, or
/// [`AionError::ChainRejected`] with a bounded reason if it fails
/// verification for any reason, including malformed structure.
///
/// # Example
///
/// ```no_run
/// use aion_context::chain::verify_file_chain;
/// use aion_context::key_registry::KeyRegistry;
/// use std::path::Path;
///
/// # fn example(registry: &KeyRegistry) -> aion_context::Result<()> {
/// let chain = verify_file_chain(Path::new("policy.aion"), registry)?;
/// assert!(chain.version_count() >= 1);
/// # Ok(())
/// # }
/// ```
pub fn verify_file_chain(path: &Path, registry: &KeyRegistry) -> Result<VerifiedChain> {
    let bytes = std::fs::read(path).map_err(|e| AionError::FileReadError {
        path: path.to_path_buf(),
        source: e,
    })?;
    VerifiedChain::from_bytes(&bytes, registry)
}

impl VerifiedChain {
    /// Fully verify bytes already in memory.
    ///
    /// The returned chain keeps the verified entries and an owned copy of
    /// the verified head section; later reads never consult `bytes` again.
    ///
    /// # Errors
    ///
    /// Returns [`AionError::ChainRejected`] with a bounded reason if the
    /// bytes fail verification for any reason, including malformed
    /// structure (`structure_invalid`).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use aion_context::chain::VerifiedChain;
    /// use aion_context::key_registry::KeyRegistry;
    ///
    /// # fn example(bytes: &[u8], registry: &KeyRegistry) -> aion_context::Result<()> {
    /// let chain = VerifiedChain::from_bytes(bytes, registry)?;
    /// println!("head is version {}", chain.head().version().as_u64());
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_bytes(bytes: &[u8], registry: &KeyRegistry) -> Result<Self> {
        let report = crate::operations::verify_bytes(bytes, registry).map_err(|e| {
            tracing::debug!(event = "chain_structure_rejected", error = %e);
            AionError::ChainRejected {
                reason: "structure_invalid",
            }
        })?;
        if !report.is_valid {
            return Err(AionError::ChainRejected {
                reason: crate::operations::classify_verify_failure(&report),
            });
        }
        Self::index(bytes)
    }

    /// Index bytes that have just passed verification, through the same
    /// parser accessors the verifier used.
    fn index(bytes: &[u8]) -> Result<Self> {
        let parser = AionParser::new(bytes)?;
        let header = parser.header();
        let context = header.context()?;
        let count = usize::try_from(header.version_chain_count).map_err(|_| empty_chain())?;
        let entries = (0..count)
            .map(|index| {
                let entry = parser.get_version_entry(index)?;
                let mode = match context.format() {
                    FormatVersion::V2 => None,
                    FormatVersion::V3 => Some(RulesMode::of(&entry)?),
                };
                let version_hash = context.version_hash(&entry)?;
                Ok(CheckedEntry {
                    entry,
                    mode,
                    version_hash,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let head = *entries.last().ok_or_else(empty_chain)?;
        Ok(Self {
            context,
            entries,
            head,
            head_section: parser.encrypted_rules_bytes()?.to_vec(),
        })
    }

    /// The file's format and identifier.
    #[must_use]
    pub const fn context(&self) -> FileContext {
        self.context
    }

    /// Number of versions in the chain (at least 1).
    #[must_use]
    pub const fn version_count(&self) -> u64 {
        self.entries.len() as u64
    }

    /// The latest version.
    #[must_use]
    pub const fn head(&self) -> VerifiedEntry<'_> {
        VerifiedEntry {
            chain: self,
            checked: &self.head,
        }
    }

    /// The entry for `version`, if the chain contains it.
    #[must_use]
    pub fn entry(&self, version: VersionNumber) -> Option<VerifiedEntry<'_>> {
        let index = usize::try_from(version.as_u64().checked_sub(1)?).ok()?;
        self.entries.get(index).map(|checked| VerifiedEntry {
            chain: self,
            checked,
        })
    }

    /// Every verified entry, oldest first.
    pub fn entries(&self) -> impl Iterator<Item = VerifiedEntry<'_>> {
        self.entries.iter().map(move |checked| VerifiedEntry {
            chain: self,
            checked,
        })
    }
}

fn empty_chain() -> AionError {
    AionError::InvalidFormat {
        reason: "Version chain is empty".to_string(),
    }
}

/// A signature-checked version entry, borrowed from a [`VerifiedChain`].
///
/// Only a [`VerifiedChain`] hands these out; they cannot be built from
/// raw fields.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedEntry<'a> {
    chain: &'a VerifiedChain,
    checked: &'a CheckedEntry,
}

impl VerifiedEntry<'_> {
    /// The version number.
    #[must_use]
    pub const fn version(&self) -> VersionNumber {
        VersionNumber(self.checked.entry.version_number)
    }

    /// The author who signed this version.
    #[must_use]
    pub const fn author(&self) -> AuthorId {
        AuthorId::new(self.checked.entry.author_id)
    }

    /// The signed timestamp, in nanoseconds since the Unix epoch.
    #[must_use]
    pub const fn timestamp(&self) -> u64 {
        self.checked.entry.timestamp
    }

    /// The signed `rules_hash`: the rules commitment in format v3, the
    /// plaintext hash in format v2.
    #[must_use]
    pub const fn rules_commitment(&self) -> [u8; 32] {
        self.checked.entry.rules_hash
    }

    /// The signed rules mode for format v3, decoded during verification.
    /// `None` means format v2, which has no modes; a v3 entry whose mode
    /// cannot be decoded never reaches a [`VerifiedChain`].
    #[must_use]
    pub const fn rules_mode(&self) -> Option<RulesMode> {
        self.checked.mode
    }

    /// The format and identifier of the file this entry belongs to.
    #[must_use]
    pub const fn context(&self) -> FileContext {
        self.chain.context
    }

    /// This entry's version hash under its file's format: the value the
    /// next version's `parent_hash` links to. It identifies the version
    /// in acceptance records and archives.
    #[must_use]
    pub const fn version_hash(&self) -> [u8; 32] {
        self.checked.version_hash
    }
}

/// Identities a reader holds to open confidential rules (RFC-0039).
///
/// `#[non_exhaustive]`: RFC-0039 Phase B adds X25519 identities and
/// external unwrappers. Until then, [`RecipientKeys::none`] opens public
/// and format-v2 rules only.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct RecipientKeys {}

impl RecipientKeys {
    /// No identities: opens public and format-v2 rules only.
    #[must_use]
    pub const fn none() -> Self {
        Self {}
    }
}

/// Open the head version's rules from a verified chain.
///
/// Reads the rules section from the bytes the chain verified, never from
/// the file on disk.
///
/// # Errors
///
/// Returns [`AionError::RecipientKeyRequired`] for a confidential section
/// the supplied keys cannot open, or a decoding error for a malformed
/// section.
///
/// # Example
///
/// ```no_run
/// use aion_context::chain::{open_current_rules, verify_file_chain, RecipientKeys};
/// use aion_context::key_registry::KeyRegistry;
/// use std::path::Path;
///
/// # fn example(registry: &KeyRegistry) -> aion_context::Result<()> {
/// let chain = verify_file_chain(Path::new("policy.aion"), registry)?;
/// let rules = open_current_rules(&chain, &RecipientKeys::none())?;
/// println!("{}", String::from_utf8_lossy(&rules));
/// # Ok(())
/// # }
/// ```
pub fn open_current_rules(
    chain: &VerifiedChain,
    keys: &RecipientKeys,
) -> Result<Zeroizing<Vec<u8>>> {
    open_rules_section(&chain.head_section, chain.head(), keys)
}

/// Open an archived rules section against the verified entry it belongs
/// to, for example a historical version's section stored outside the file
/// under its rules commitment.
///
/// The section is bound to the entry first: format v3 recomputes the
/// commitment under the entry's signed mode; format v2 decrypts and checks
/// the signed plaintext hash.
///
/// # Errors
///
/// Returns [`AionError::HashMismatch`] if the section does not belong to
/// `entry`, [`AionError::RecipientKeyRequired`] for a confidential section
/// the keys cannot open, or a decoding error for a malformed section.
///
/// # Example
///
/// ```no_run
/// use aion_context::chain::{open_rules_section, verify_file_chain, RecipientKeys};
/// use aion_context::key_registry::KeyRegistry;
/// use aion_context::types::VersionNumber;
/// use std::path::Path;
///
/// # fn example(registry: &KeyRegistry, archived_v1: &[u8]) -> aion_context::Result<()> {
/// let chain = verify_file_chain(Path::new("policy.aion"), registry)?;
/// if let Some(v1) = chain.entry(VersionNumber(1)) {
///     let rules = open_rules_section(archived_v1, v1, &RecipientKeys::none())?;
///     println!("v1 had {} bytes of rules", rules.len());
/// }
/// # Ok(())
/// # }
/// ```
pub fn open_rules_section(
    section: &[u8],
    entry: VerifiedEntry<'_>,
    keys: &RecipientKeys,
) -> Result<Zeroizing<Vec<u8>>> {
    match entry.context().format() {
        FormatVersion::V2 => crate::operations::decrypt_rules(
            section,
            entry.context().file_id(),
            entry.version(),
            entry.rules_commitment(),
        )
        .map(Zeroizing::new),
        FormatVersion::V3 => open_v3_section(section, entry, keys),
    }
}

fn open_v3_section(
    section: &[u8],
    entry: VerifiedEntry<'_>,
    keys: &RecipientKeys,
) -> Result<Zeroizing<Vec<u8>>> {
    let mode = entry.rules_mode().ok_or_else(|| AionError::InvalidFormat {
        reason: "format-v3 entry without a rules mode".to_string(),
    })?;
    let commitment = rules_commitment(mode, section);
    if commitment != entry.rules_commitment() {
        return Err(AionError::HashMismatch {
            expected: entry.rules_commitment(),
            actual: commitment,
        });
    }
    match mode {
        RulesMode::Public => Ok(Zeroizing::new(unframe_rules(section)?.to_vec())),
        RulesMode::Confidential => open_confidential(section, entry, keys),
    }
}

/// Confidential envelopes are opened in RFC-0039 Phase B. Until then no
/// [`RecipientKeys`] can hold an identity, so every confidential section
/// needs one.
const fn open_confidential(
    _section: &[u8],
    _entry: VerifiedEntry<'_>,
    _keys: &RecipientKeys,
) -> Result<Zeroizing<Vec<u8>>> {
    Err(AionError::RecipientKeyRequired)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::crypto::{hash, SigningKey};
    use crate::format::{frame_rules, RulesProtection};
    use crate::operations::{commit_version, init_file, CommitOptions, InitOptions};
    use crate::serializer::{AionFile, AionSerializer};
    use crate::signature_chain::{create_genesis_version, sign_version};
    use crate::types::FileId;
    use tempfile::TempDir;

    fn ok<T, E>(result: std::result::Result<T, E>) -> T {
        result.unwrap_or_else(|_| std::process::abort())
    }

    fn registry_for(author: AuthorId, key: &SigningKey) -> KeyRegistry {
        let mut registry = KeyRegistry::new();
        let master = ok(SigningKey::generate());
        ok(registry.register_author(author, master.verifying_key(), key.verifying_key(), 0));
        registry
    }

    /// A v3 file at `path` holding one version per entry of `rules`.
    fn grow_v3(path: &Path, key: &SigningKey, author: AuthorId, rules: &[&[u8]]) -> KeyRegistry {
        let registry = registry_for(author, key);
        let mut drafts = rules.iter();
        let init = InitOptions {
            author_id: author,
            signing_key: key,
            message: "genesis",
            timestamp: None,
            protection: RulesProtection::Public,
        };
        ok(init_file(
            path,
            drafts.next().copied().unwrap_or_default(),
            &init,
        ));
        for next in drafts {
            let commit = CommitOptions {
                author_id: author,
                signing_key: key,
                message: "next",
                timestamp: None,
                protection: RulesProtection::Public,
            };
            ok(commit_version(path, next, &commit, &registry));
        }
        registry
    }

    #[test]
    fn verified_v3_chain_opens_its_head_rules() {
        let dir = ok(TempDir::new());
        let path = dir.path().join("chain.aion");
        let key = ok(SigningKey::generate());
        let author = AuthorId::new(90_001);
        let registry = grow_v3(&path, &key, author, &[b"one", b"two", b"three"]);

        let chain = ok(verify_file_chain(&path, &registry));
        assert_eq!(chain.version_count(), 3);
        assert_eq!(chain.head().version(), VersionNumber(3));
        assert_eq!(chain.head().author(), author);
        assert_eq!(chain.context().format(), FormatVersion::V3);
        assert!(chain
            .entries()
            .all(|entry| entry.rules_mode() == Some(RulesMode::Public)));
        let rules = ok(open_current_rules(&chain, &RecipientKeys::none()));
        assert_eq!(rules.as_slice(), b"three");
    }

    #[test]
    fn tampered_file_yields_no_chain() {
        let dir = ok(TempDir::new());
        let path = dir.path().join("tampered.aion");
        let key = ok(SigningKey::generate());
        let registry = grow_v3(&path, &key, AuthorId::new(90_002), &[b"rules"]);
        let mut bytes = ok(std::fs::read(&path));
        let last = bytes.len().saturating_sub(1);
        bytes[last] ^= 0x01;
        assert!(matches!(
            VerifiedChain::from_bytes(&bytes, &registry),
            Err(AionError::ChainRejected {
                reason: "integrity_hash_mismatch"
            })
        ));
    }

    #[test]
    fn swapped_section_with_recomputed_integrity_hash_yields_no_chain() {
        let dir = ok(TempDir::new());
        let path = dir.path().join("swapped-section.aion");
        let key = ok(SigningKey::generate());
        let registry = grow_v3(&path, &key, AuthorId::new(90_008), &[b"refund_limit: 100"]);
        let mut bytes = ok(std::fs::read(&path));
        let (offset, length) = {
            let parser = ok(AionParser::new(&bytes));
            let header = parser.header();
            (
                header.encrypted_rules_offset as usize,
                header.encrypted_rules_length as usize,
            )
        };
        let forged = ok(frame_rules(b"refund_limit: 999"));
        assert_eq!(forged.len(), length);
        bytes[offset..offset.saturating_add(length)].copy_from_slice(&forged);
        let body = bytes.len().saturating_sub(32);
        let integrity = hash(&bytes[..body]);
        bytes[body..].copy_from_slice(&integrity);
        assert!(matches!(
            VerifiedChain::from_bytes(&bytes, &registry),
            Err(AionError::ChainRejected {
                reason: "hash_chain_broken"
            })
        ));
    }

    #[test]
    fn malformed_bytes_are_rejected_as_structure_invalid() {
        let registry = KeyRegistry::new();
        assert!(matches!(
            VerifiedChain::from_bytes(b"not an aion file", &registry),
            Err(AionError::ChainRejected {
                reason: "structure_invalid"
            })
        ));
    }

    /// GHSA-9c6x-g6hv-mpvr: an entry count larger than the file must be
    /// rejected before any reader sizes a buffer from it.
    #[test]
    fn oversized_entry_counts_are_rejected_without_allocating() {
        let dir = ok(TempDir::new());
        let path = dir.path().join("counts.aion");
        let key = ok(SigningKey::generate());
        let registry = grow_v3(&path, &key, AuthorId::new(90_009), &[b"rules"]);
        let original = ok(std::fs::read(&path));
        for field in [128usize, 144, 160] {
            for count in [1u64 << 32, u64::MAX] {
                let mut bytes = original.clone();
                bytes[field..field.saturating_add(8)].copy_from_slice(&count.to_le_bytes());
                assert!(matches!(
                    VerifiedChain::from_bytes(&bytes, &registry),
                    Err(AionError::ChainRejected {
                        reason: "structure_invalid"
                    })
                ));
            }
        }
    }

    #[test]
    fn unpinned_signer_yields_no_chain() {
        let dir = ok(TempDir::new());
        let path = dir.path().join("unpinned.aion");
        let key = ok(SigningKey::generate());
        grow_v3(&path, &key, AuthorId::new(90_003), &[b"rules"]);
        let stranger = ok(SigningKey::generate());
        let other_registry = registry_for(AuthorId::new(90_003), &stranger);
        assert!(matches!(
            verify_file_chain(&path, &other_registry),
            Err(AionError::ChainRejected {
                reason: "signature_invalid"
            })
        ));
    }

    #[test]
    fn replacing_the_file_after_verification_changes_nothing() {
        let dir = ok(TempDir::new());
        let path = dir.path().join("swapped.aion");
        let key = ok(SigningKey::generate());
        let author = AuthorId::new(90_004);
        let registry = grow_v3(&path, &key, author, &[b"approved"]);
        let chain = ok(verify_file_chain(&path, &registry));

        let commit = CommitOptions {
            author_id: author,
            signing_key: &key,
            message: "later",
            timestamp: None,
            protection: RulesProtection::Public,
        };
        ok(commit_version(
            &path,
            b"changed on disk",
            &commit,
            &registry,
        ));

        let rules = ok(open_current_rules(&chain, &RecipientKeys::none()));
        assert_eq!(rules.as_slice(), b"approved");
        assert_eq!(chain.version_count(), 1);
    }

    #[test]
    fn archived_sections_open_only_against_their_own_entry() {
        let dir = ok(TempDir::new());
        let path = dir.path().join("archive.aion");
        let key = ok(SigningKey::generate());
        let registry = grow_v3(&path, &key, AuthorId::new(90_005), &[b"first", b"second"]);
        let chain = ok(verify_file_chain(&path, &registry));
        let first = ok(chain.entry(VersionNumber(1)).ok_or(()));
        let second = ok(chain.entry(VersionNumber(2)).ok_or(()));
        let archived = ok(frame_rules(b"first"));

        let opened = ok(open_rules_section(&archived, first, &RecipientKeys::none()));
        assert_eq!(opened.as_slice(), b"first");
        assert!(matches!(
            open_rules_section(&archived, second, &RecipientKeys::none()),
            Err(AionError::HashMismatch { .. })
        ));
        assert!(chain.entry(VersionNumber(0)).is_none());
        assert!(chain.entry(VersionNumber(3)).is_none());
    }

    fn write_v2(path: &Path, key: &SigningKey, author: AuthorId, rules: &[u8]) {
        let file_id = FileId::new(90_006);
        let timestamp = 1_700_000_000_000_000_000;
        let (section, rules_hash) = ok(crate::operations::encrypt_rules(
            rules,
            file_id,
            VersionNumber::GENESIS,
        ));
        let (string_table, _) = AionSerializer::build_string_table(&["genesis"]);
        let genesis = create_genesis_version(rules_hash, author, timestamp, 0, 7);
        let file = ok(AionFile::builder()
            .format(FormatVersion::V2)
            .file_id(file_id)
            .current_version(VersionNumber::GENESIS)
            .flags(0x0001)
            .root_hash(rules_hash)
            .current_hash(rules_hash)
            .created_at(timestamp)
            .modified_at(timestamp)
            .encrypted_rules(section)
            .add_signature(sign_version(&genesis, key))
            .add_version(genesis)
            .string_table(string_table)
            .build());
        ok(std::fs::write(path, ok(AionSerializer::serialize(&file))));
    }

    #[test]
    fn verified_v2_chain_opens_its_rules() {
        let dir = ok(TempDir::new());
        let path = dir.path().join("legacy.aion");
        let key = ok(SigningKey::generate());
        let author = AuthorId::new(90_006);
        write_v2(&path, &key, author, b"legacy rules");
        let chain = ok(verify_file_chain(&path, &registry_for(author, &key)));
        assert_eq!(chain.context().format(), FormatVersion::V2);
        assert_eq!(chain.head().rules_mode(), None);
        assert_eq!(chain.head().rules_commitment(), hash(b"legacy rules"));
        let rules = ok(open_current_rules(&chain, &RecipientKeys::none()));
        assert_eq!(rules.as_slice(), b"legacy rules");
    }

    #[test]
    fn confidential_head_needs_a_recipient_key() {
        let dir = ok(TempDir::new());
        let path = dir.path().join("confidential.aion");
        let key = ok(SigningKey::generate());
        let author = AuthorId::new(90_007);
        let context = FileContext::new(FormatVersion::V3, FileId::new(90_007));
        let section = b"AIONENV1 opaque stand-in".to_vec();
        let commitment = rules_commitment(RulesMode::Confidential, &section);
        let genesis = create_genesis_version(commitment, author, 1, 0, 0)
            .with_rules_mode(RulesMode::Confidential);
        let file = ok(AionFile::builder()
            .format(FormatVersion::V3)
            .file_id(context.file_id())
            .current_version(VersionNumber::GENESIS)
            .flags(1)
            .root_hash(commitment)
            .current_hash(commitment)
            .created_at(1)
            .modified_at(1)
            .encrypted_rules(section)
            .add_signature(ok(context.sign_version(&genesis, &key)))
            .add_version(genesis)
            .build());
        ok(std::fs::write(&path, ok(AionSerializer::serialize(&file))));

        let chain = ok(verify_file_chain(&path, &registry_for(author, &key)));
        assert_eq!(chain.head().rules_mode(), Some(RulesMode::Confidential));
        assert!(matches!(
            open_current_rules(&chain, &RecipientKeys::none()),
            Err(AionError::RecipientKeyRequired)
        ));
    }

    mod properties {
        use super::*;
        use hegel::generators as gs;

        #[hegel::test]
        fn prop_archived_sections_open_exactly_against_matching_entries(tc: hegel::TestCase) {
            let count = tc.draw(gs::integers::<usize>().min_value(1).max_value(4));
            let rules: Vec<Vec<u8>> = (0..count)
                .map(|_| tc.draw(gs::binary().max_size(256)))
                .collect();
            let dir = ok(TempDir::new());
            let path = dir.path().join("prop.aion");
            let key = ok(SigningKey::generate());
            let refs: Vec<&[u8]> = rules.iter().map(Vec::as_slice).collect();
            let registry = grow_v3(&path, &key, AuthorId::new(90_100), &refs);
            let chain = ok(verify_file_chain(&path, &registry));

            for (i, archived_rules) in rules.iter().enumerate() {
                let archived = ok(frame_rules(archived_rules));
                for entry in chain.entries() {
                    let opened = open_rules_section(&archived, entry, &RecipientKeys::none());
                    let same_section = ok(frame_rules(
                        &rules[(entry.version().as_u64() as usize).saturating_sub(1)],
                    )) == archived;
                    if same_section {
                        assert_eq!(ok(opened).as_slice(), archived_rules.as_slice(), "v{i}");
                    } else {
                        assert!(opened.is_err());
                    }
                }
            }
        }
    }
}
