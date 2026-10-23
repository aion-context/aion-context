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
//! [`RecipientKeys`] carries the encryption identities a reader holds.
//! [`RecipientKeys::none`] opens public and format-v2 rules; confidential
//! rules need an identity the head version lists as a recipient.
//! [`disclose_version_key`] and [`open_rules_section_with_key`] support
//! selective disclosure of one version.
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

use crate::confidential::{DekUnwrapper, EncryptionIdentity, VersionKey};
use crate::envelope::{Envelope, StanzaRecipient};
use crate::format::{
    rules_commitment, unframe_rules, FileContext, FormatVersion, Recipient, RulesMode,
};
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
    migration_details: Option<String>,
}

/// A version entry together with its rules mode and version hash, both
/// computed once during verification so no accessor ever has to drop a
/// decoding error.
#[derive(Debug, Clone)]
struct CheckedEntry {
    entry: VersionEntry,
    mode: Option<RulesMode>,
    version_hash: [u8; 32],
    message: String,
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
        let raw = (0..count)
            .map(|index| parser.get_version_entry(index))
            .collect::<Result<Vec<_>>>()?;
        let (messages, migration_details) = messages_of(&parser, context.format(), &raw)?;
        let entries = raw
            .into_iter()
            .zip(messages)
            .map(|(entry, message)| {
                let mode = match context.format() {
                    FormatVersion::V2 => None,
                    format @ (FormatVersion::V3 | FormatVersion::V4) => {
                        Some(RulesMode::of(&entry, format)?)
                    }
                };
                let version_hash = context.version_hash(&entry)?;
                Ok(CheckedEntry {
                    entry,
                    mode,
                    version_hash,
                    message,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let head = entries.last().cloned().ok_or_else(empty_chain)?;
        Ok(Self {
            context,
            entries,
            head,
            head_section: parser.encrypted_rules_bytes()?.to_vec(),
            migration_details,
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

    /// Whether this file's commit messages and audit trail are covered by
    /// its signatures (RFC-0040): true for format v4. For v2 and v3 the
    /// messages [`VerifiedEntry::message`] returns are unauthenticated
    /// (GHSA-69cp-fwrw-82vh).
    #[must_use]
    pub const fn metadata_signed(&self) -> bool {
        self.context.format().signs_metadata()
    }

    /// The signed details text of a format-v4 genesis whose audit action is
    /// `MigratedFrom`, unparsed. [`crate::migration::verify_migration`]
    /// parses and checks it.
    #[must_use]
    pub fn migration_details(&self) -> Option<&str> {
        self.migration_details.as_deref()
    }

    /// The head version's recipients, so the next version can be sealed to
    /// the same set. Read from the verified head section, never re-read.
    ///
    /// # Errors
    ///
    /// Returns [`AionError::NoRecipients`] if the head version is not
    /// confidential, and [`AionError::InvalidFormat`] if any of its
    /// recipients cannot be carried over from the file alone (an external
    /// wrapper or an unknown stanza kind).
    pub fn head_recipients(&self) -> Result<Vec<Recipient>> {
        if self.head.mode != Some(RulesMode::Confidential) {
            return Err(AionError::NoRecipients);
        }
        let envelope = crate::confidential::bounded_envelope(&self.head_section)?;
        envelope
            .stanzas()
            .iter()
            .map(|stanza| match stanza.recipient() {
                StanzaRecipient::X25519 { recipient_pk, .. } => {
                    Ok(Recipient::X25519(*recipient_pk))
                }
                StanzaRecipient::XWing { recipient_pk, .. } => {
                    Ok(Recipient::XWing(Box::new(*recipient_pk)))
                }
                _ => Err(AionError::InvalidFormat {
                    reason: "head version has a recipient that cannot be carried over".to_string(),
                }),
            })
            .collect()
    }
}

/// Each version's commit message, and the genesis migration details if
/// any. For v4, from the full metadata check, so every message is the
/// signed one. For v2 and v3, read leniently and unauthenticated; they
/// carry no migration details.
fn messages_of(
    parser: &AionParser<'_>,
    format: FormatVersion,
    entries: &[VersionEntry],
) -> Result<(Vec<String>, Option<String>)> {
    if format.signs_metadata() {
        let metadata = crate::metadata::verify_v4_metadata(parser, entries)?;
        let details = metadata
            .first()
            .filter(|genesis| {
                genesis.audit.action_code_raw() == crate::audit::ActionCode::MigratedFrom as u16
            })
            .map(|genesis| genesis.details.clone());
        let messages = metadata.into_iter().map(|m| m.message).collect();
        return Ok((messages, details));
    }
    let table = parser.string_table_bytes()?;
    let messages = entries
        .iter()
        .map(|entry| crate::operations::lossy_message(table, entry))
        .collect();
    Ok((messages, None))
}

/// The verified history of a chain, oldest first, for display.
///
/// For format v4 every message is covered by its version's signature. For
/// v2 and v3, check [`VerifiedChain::metadata_signed`]: their messages are
/// unauthenticated.
#[must_use]
pub fn verified_history(chain: &VerifiedChain) -> Vec<crate::operations::VersionInfo> {
    chain
        .entries
        .iter()
        .map(|checked| crate::operations::VersionInfo {
            version_number: checked.entry.version_number,
            author_id: checked.entry.author_id,
            timestamp: checked.entry.timestamp,
            message: checked.message.clone(),
            rules_hash: checked.entry.rules_hash,
            parent_hash: (checked.entry.version_number != 1).then_some(checked.entry.parent_hash),
        })
        .collect()
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

    /// The version's commit message: signed in format v4, unauthenticated
    /// in v2 and v3 (see [`VerifiedChain::metadata_signed`]).
    #[must_use]
    pub fn message(&self) -> &str {
        &self.checked.message
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
/// These are secret keys, not [`Recipient`]s (the public half a writer
/// seals to). Every held seed is zeroized on drop; `Clone` duplicates
/// them into zeroizing storage, and `Debug` never prints them.
///
/// `#[non_exhaustive]`: RFC-0039 Phase C adds external unwrappers.
///
/// # Example
///
/// ```
/// use aion_context::chain::RecipientKeys;
/// use aion_context::confidential::{EncryptionIdentity, EncryptionKem};
///
/// let auditor = EncryptionIdentity::generate(EncryptionKem::XWing)?;
/// let keys = RecipientKeys::from(auditor);
/// assert!(!keys.is_empty());
/// assert!(RecipientKeys::none().is_empty());
/// # Ok::<(), aion_context::AionError>(())
/// ```
#[derive(Default, Clone)]
#[non_exhaustive]
pub struct RecipientKeys {
    identities: Vec<EncryptionIdentity>,
    unwrappers: Vec<std::sync::Arc<dyn DekUnwrapper>>,
}

impl std::fmt::Debug for RecipientKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecipientKeys")
            .field("identities", &self.identities)
            .field("unwrappers", &self.unwrappers.len())
            .finish()
    }
}

impl RecipientKeys {
    /// No identities: opens public and format-v2 rules only.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            identities: Vec::new(),
            unwrappers: Vec::new(),
        }
    }

    /// Hold `identities`; opening tries each one listed by the section.
    #[must_use]
    pub const fn new(identities: Vec<EncryptionIdentity>) -> Self {
        Self {
            identities,
            unwrappers: Vec::new(),
        }
    }

    /// Add an external key-service unwrapper (RFC-0039 Phase C). Opening
    /// asks it about every external stanza it [`DekUnwrapper::accepts`].
    #[must_use]
    pub fn with_unwrapper(mut self, unwrapper: std::sync::Arc<dyn DekUnwrapper>) -> Self {
        self.unwrappers.push(unwrapper);
        self
    }

    /// Add one more identity.
    #[must_use]
    pub fn with(mut self, identity: EncryptionIdentity) -> Self {
        self.identities.push(identity);
        self
    }

    /// Whether no identity is held.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.identities.is_empty() && self.unwrappers.is_empty()
    }
}

impl From<EncryptionIdentity> for RecipientKeys {
    fn from(identity: EncryptionIdentity) -> Self {
        Self::new(vec![identity])
    }
}

impl From<&EncryptionIdentity> for RecipientKeys {
    fn from(identity: &EncryptionIdentity) -> Self {
        Self::new(vec![identity.clone()])
    }
}

/// Open the head version's rules from a verified chain.
///
/// Reads the rules section from the bytes the chain verified, never from
/// the file on disk.
///
/// # Errors
///
/// For a confidential head: [`AionError::RecipientKeyRequired`] if `keys`
/// holds no identity, [`AionError::NotARecipient`] if none of them is
/// listed, and [`AionError::RulesUnopenable`] if a listed one cannot open
/// it. A decoding error for a malformed section.
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
/// `entry`; for a confidential section [`AionError::RecipientKeyRequired`],
/// [`AionError::NotARecipient`], or [`AionError::RulesUnopenable`] as for
/// [`open_current_rules`]; or a decoding error for a malformed section.
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
        FormatVersion::V3 | FormatVersion::V4 => open_v3_section(section, entry, keys),
    }
}

fn open_v3_section(
    section: &[u8],
    entry: VerifiedEntry<'_>,
    keys: &RecipientKeys,
) -> Result<Zeroizing<Vec<u8>>> {
    match bound_mode(section, entry)? {
        RulesMode::Public => Ok(Zeroizing::new(unframe_rules(section)?.to_vec())),
        RulesMode::Confidential => open_confidential(section, entry, keys),
    }
}

/// Bind a format-v3 section to its verified entry: recompute the
/// commitment under the entry's signed mode and compare.
fn bound_mode(section: &[u8], entry: VerifiedEntry<'_>) -> Result<RulesMode> {
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
    Ok(mode)
}

/// A confidential section bound to `entry`, parsed and size-checked.
fn bound_confidential<'s>(section: &'s [u8], entry: VerifiedEntry<'_>) -> Result<Envelope<'s>> {
    if !entry.context().format().has_rules_modes()
        || bound_mode(section, entry)? != RulesMode::Confidential
    {
        return Err(AionError::InvalidFormat {
            reason: "only confidential format-v3 rules have a version key".to_string(),
        });
    }
    crate::confidential::bounded_envelope(section)
}

const fn binding_context(entry: VerifiedEntry<'_>) -> [u8; crate::confidential::CTX_LEN] {
    crate::confidential::binding_context(entry.context().file_id(), entry.author(), entry.version())
}

fn open_confidential(
    section: &[u8],
    entry: VerifiedEntry<'_>,
    keys: &RecipientKeys,
) -> Result<Zeroizing<Vec<u8>>> {
    let envelope = crate::confidential::bounded_envelope(section)?;
    if keys.is_empty() {
        return Err(AionError::RecipientKeyRequired);
    }
    let framed = crate::confidential::open_section(
        &envelope,
        &keys.identities,
        &keys.unwrappers,
        &binding_context(entry),
    )
    .inspect_err(|e| log_unopened(entry, e))?;
    unframed_secret(&framed).inspect_err(|e| log_unopened(entry, e))
}

/// Unframe decrypted rules. A bad frame behind a valid AEAD tag is still
/// `RulesUnopenable`, so the error never says which step failed.
fn unframed_secret(framed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    unframe_rules(framed)
        .map(|rules| Zeroizing::new(rules.to_vec()))
        .map_err(|_| AionError::RulesUnopenable)
}

fn log_unopened(entry: VerifiedEntry<'_>, error: &AionError) {
    let reason = match error {
        AionError::NotARecipient => "not_a_recipient",
        AionError::RulesUnopenable => "rules_unopenable",
        _ => "malformed_section",
    };
    tracing::warn!(
        event = "confidential_rules_not_opened",
        version = entry.version().as_u64(),
        author = %crate::obs::author_short(entry.author()),
        reason,
    );
}

/// Return the data-encryption key of one confidential version, for
/// selective disclosure (RFC-0039).
///
/// The key opens `section` and no other: each version's key is independent
/// random bytes. Give it to the party that should read this one version,
/// who opens the section with [`open_rules_section_with_key`].
///
/// # Errors
///
/// [`AionError::HashMismatch`] if `section` does not belong to `entry`;
/// [`AionError::InvalidFormat`] if the version is not confidential;
/// [`AionError::RecipientKeyRequired`], [`AionError::NotARecipient`], or
/// [`AionError::RulesUnopenable`] as for [`open_rules_section`].
///
/// # Example
///
/// ```no_run
/// use aion_context::chain::{disclose_version_key, open_rules_section_with_key, verify_file_chain, RecipientKeys};
/// use aion_context::key_registry::KeyRegistry;
/// use std::path::Path;
///
/// # fn example(registry: &KeyRegistry, keys: &RecipientKeys, section: &[u8]) -> aion_context::Result<()> {
/// let chain = verify_file_chain(Path::new("policy.aion"), registry)?;
/// let key = disclose_version_key(section, chain.head(), keys)?;
/// let rules = open_rules_section_with_key(section, chain.head(), &key)?;
/// # Ok(())
/// # }
/// ```
pub fn disclose_version_key(
    section: &[u8],
    entry: VerifiedEntry<'_>,
    keys: &RecipientKeys,
) -> Result<VersionKey> {
    let envelope = bound_confidential(section, entry)?;
    if keys.is_empty() {
        return Err(AionError::RecipientKeyRequired);
    }
    crate::confidential::unwrap_for(
        &envelope,
        &keys.identities,
        &keys.unwrappers,
        &binding_context(entry),
    )
    .map(VersionKey::from_dek)
    .inspect_err(|e| log_unopened(entry, e))
}

/// Open one confidential version's rules with a disclosed [`VersionKey`]
/// (RFC-0039).
///
/// The section is bound to `entry` first, and the key is checked against
/// the section's key commitment, so a key for any other version fails.
///
/// # Errors
///
/// [`AionError::HashMismatch`] if `section` does not belong to `entry`;
/// [`AionError::InvalidFormat`] if the version is not confidential;
/// [`AionError::RulesUnopenable`] if `key` is not this version's key.
pub fn open_rules_section_with_key(
    section: &[u8],
    entry: VerifiedEntry<'_>,
    key: &VersionKey,
) -> Result<Zeroizing<Vec<u8>>> {
    let envelope = bound_confidential(section, entry)?;
    let framed = crate::confidential::open_with_dek(&envelope, key.dek(), &binding_context(entry))
        .inspect_err(|e| log_unopened(entry, e))?;
    unframed_secret(&framed).inspect_err(|e| log_unopened(entry, e))
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::crypto::{hash, SigningKey};
    use crate::format::{frame_rules, RulesProtection};
    use crate::key_registry::KeyRegistry;
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
    fn verified_v4_chain_opens_its_head_rules() {
        let dir = ok(TempDir::new());
        let path = dir.path().join("chain.aion");
        let key = ok(SigningKey::generate());
        let author = AuthorId::new(90_001);
        let registry = grow_v3(&path, &key, author, &[b"one", b"two", b"three"]);

        let chain = ok(verify_file_chain(&path, &registry));
        assert_eq!(chain.version_count(), 3);
        assert_eq!(chain.head().version(), VersionNumber(3));
        assert_eq!(chain.head().author(), author);
        assert_eq!(chain.context().format(), FormatVersion::V4);
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
    fn a_malformed_confidential_envelope_fails_key_free_verification() {
        let dir = ok(TempDir::new());
        let path = dir.path().join("confidential.aion");
        let key = ok(SigningKey::generate());
        let author = AuthorId::new(90_007);
        write_single_confidential(
            &path,
            FileId::new(90_007),
            b"AIONENV1 opaque stand-in",
            author,
            &key,
        );
        assert!(verify_file_chain(&path, &registry_for(author, &key)).is_err());
    }

    /// A one-version v3 file whose head is `section`, signed as confidential
    /// by `author`. Builds what a malicious author could produce.
    fn write_single_confidential(
        path: &Path,
        file_id: FileId,
        section: &[u8],
        author: AuthorId,
        key: &SigningKey,
    ) {
        let context = FileContext::new(FormatVersion::V3, file_id);
        let section = section.to_vec();
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
            .add_signature(ok(context.sign_version(&genesis, key)))
            .add_version(genesis)
            .build());
        ok(std::fs::write(path, ok(AionSerializer::serialize(&file))));
    }

    /// RFC-0039: a malicious author copies a victim's confidential section
    /// verbatim and signs it under their own name. Verification passes,
    /// because the copier really signed those bytes, but no recipient can
    /// open it: `author_id` is in the binding context.
    #[test]
    fn a_section_re_signed_by_another_author_opens_for_no_recipient() {
        let dir = ok(TempDir::new());
        let victim_path = dir.path().join("victim.aion");
        let victim_key = ok(SigningKey::generate());
        let victim = AuthorId::new(90_015);
        let reader = identity(EncryptionKem::XWing);
        let registry = grow_confidential(
            &victim_path,
            &victim_key,
            victim,
            &[(b"victim's rules", vec![reader.recipient()])],
        );
        let original = ok(verify_file_chain(&victim_path, &registry));

        let copier_path = dir.path().join("copier.aion");
        let copier_key = ok(SigningKey::generate());
        let copier = AuthorId::new(90_016);
        write_single_confidential(
            &copier_path,
            original.context().file_id(),
            &original.head_section,
            copier,
            &copier_key,
        );
        let forged_chain = ok(verify_file_chain(
            &copier_path,
            &registry_for(copier, &copier_key),
        ));
        assert!(matches!(
            open_current_rules(&forged_chain, &RecipientKeys::from(reader)),
            Err(AionError::RulesUnopenable)
        ));
    }

    /// A confidential section sealed to `reader` from raw `framed` bytes,
    /// bound to `(file_id, author, version)`.
    fn sealed(
        framed: &[u8],
        reader: &EncryptionIdentity,
        file_id: FileId,
        author: AuthorId,
        version: VersionNumber,
    ) -> Vec<u8> {
        let ctx = crate::confidential::binding_context(file_id, author, version);
        let recipients = [reader.recipient()];
        ok(crate::confidential::seal_section(framed, &recipients, &ctx))
    }

    fn open_single(
        path: &Path,
        author: AuthorId,
        key: &SigningKey,
        reader: &EncryptionIdentity,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let chain = ok(verify_file_chain(path, &registry_for(author, key)));
        open_current_rules(&chain, &RecipientKeys::from(reader))
    }

    /// A signed section whose AEAD fails, or whose frame is non-canonical
    /// behind a valid tag, is `RulesUnopenable` like every other failure.
    #[test]
    fn a_bad_tag_and_a_bad_frame_are_the_same_unopenable() {
        let dir = ok(TempDir::new());
        let key = ok(SigningKey::generate());
        let author = AuthorId::new(90_018);
        let file_id = FileId::new(90_018);
        let reader = identity(EncryptionKem::XWing);
        let framed = ok(frame_rules(b"rules"));

        let mut bad_tag = sealed(&framed, &reader, file_id, author, VersionNumber::GENESIS);
        let last = bad_tag.len().saturating_sub(1);
        bad_tag[last] ^= 0x01;
        let tag_path = dir.path().join("tag.aion");
        write_single_confidential(&tag_path, file_id, &bad_tag, author, &key);

        let mut bad_frame = vec![0u8; 24];
        bad_frame[0] = 200;
        let bad_frame = sealed(&bad_frame, &reader, file_id, author, VersionNumber::GENESIS);
        let frame_path = dir.path().join("frame.aion");
        write_single_confidential(&frame_path, file_id, &bad_frame, author, &key);

        for path in [&tag_path, &frame_path] {
            assert!(matches!(
                open_single(path, author, &key, &reader),
                Err(AionError::RulesUnopenable)
            ));
        }
    }

    /// A section moved to another file or another version of the same
    /// file, re-signed by its own author, opens for no recipient.
    #[test]
    fn sections_moved_across_files_or_versions_open_for_no_one() {
        let dir = ok(TempDir::new());
        let key = ok(SigningKey::generate());
        let author = AuthorId::new(90_019);
        let reader = identity(EncryptionKem::X25519);
        let path = dir.path().join("source.aion");
        let to = || vec![reader.recipient()];
        let registry = grow_confidential(&path, &key, author, &[(b"v1", to()), (b"v2", to())]);
        let source = ok(verify_file_chain(&path, &registry));
        let file_id = source.context().file_id();

        let other_file = dir.path().join("other-file.aion");
        let moved_file_id = FileId::new(file_id.as_u64().wrapping_add(1));
        write_single_confidential(
            &other_file,
            moved_file_id,
            &source.head_section,
            author,
            &key,
        );
        let other_version = dir.path().join("other-version.aion");
        write_single_confidential(&other_version, file_id, &source.head_section, author, &key);

        for moved in [&other_file, &other_version] {
            assert!(matches!(
                open_single(moved, author, &key, &reader),
                Err(AionError::RulesUnopenable)
            ));
        }
    }

    #[test]
    fn an_oversized_confidential_head_fails_key_free_verification() {
        let dir = ok(TempDir::new());
        let key = ok(SigningKey::generate());
        let author = AuthorId::new(90_020);
        let stanza = (crate::envelope::STANZA_X25519, vec![9u8; 112]);
        let ciphertext = vec![0u8; crate::format::MAX_CONFIDENTIAL_RULES_LEN + 17];
        let section = ok(crate::envelope::encode_envelope(
            &[0; 32],
            vec![stanza],
            &[0; 12],
            &ciphertext,
        ));
        let path = dir.path().join("huge.aion");
        write_single_confidential(&path, FileId::new(90_020), &section, author, &key);
        assert!(verify_file_chain(&path, &registry_for(author, &key)).is_err());
        let report = crate::operations::verify_file(&path, &registry_for(author, &key));
        assert!(report.map_or(true, |r| !r.is_valid));
    }

    /// RFC-0038 external signers seal confidential versions under the
    /// same author they sign as, so recipients can open them.
    #[test]
    fn a_confidential_commit_through_an_external_signer_opens() {
        let dir = ok(TempDir::new());
        let path = dir.path().join("external.aion");
        let key = ok(SigningKey::generate());
        let author = AuthorId::new(90_021);
        let reader = identity(EncryptionKem::XWing);
        let registry = grow_confidential(&path, &key, author, &[(b"v1", vec![reader.recipient()])]);
        let options = crate::operations::ExternalCommitOptions {
            author_id: author,
            signer: &key,
            message: "v2 via provider",
            timestamp: None,
            protection: RulesProtection::Confidential {
                recipients: vec![reader.recipient()],
            },
        };
        ok(crate::operations::commit_version_with_signer(
            &path, b"v2", &options, &registry,
        ));
        let chain = ok(verify_file_chain(&path, &registry));
        assert_eq!(
            ok(open_current_rules(&chain, &RecipientKeys::from(&reader))).as_slice(),
            b"v2"
        );
    }

    /// RFC-0039 Phase C: a KMS recipient through the public API.
    #[test]
    fn a_kms_recipient_reads_through_recipient_keys() {
        use crate::confidential::DekUnwrapper;
        let dir = ok(TempDir::new());
        let path = dir.path().join("kms.aion");
        let key = ok(SigningKey::generate());
        let author = AuthorId::new(90_030);
        let vault = std::sync::Arc::new(crate::confidential::tests::LocalKms {
            key: [0x33; 32],
            key_ref: "projects/p/keys/policy",
        });
        let reader = identity(EncryptionKem::XWing);
        let recipients = vec![
            Recipient::external(vault.clone()),
            Recipient::external(vault.clone()),
            reader.recipient(),
        ];
        let registry = grow_confidential(&path, &key, author, &[(b"kms rules", recipients)]);
        let chain = ok(verify_file_chain(&path, &registry));

        let unwrapper: std::sync::Arc<dyn DekUnwrapper> = vault;
        let keys = RecipientKeys::none().with_unwrapper(unwrapper);
        assert!(!keys.is_empty());
        assert_eq!(
            ok(open_current_rules(&chain, &keys)).as_slice(),
            b"kms rules"
        );

        let envelope = ok(Envelope::parse(&chain.head_section));
        assert_eq!(
            envelope.stanzas().len(),
            2,
            "the repeated KMS recipient is written once"
        );
        assert!(matches!(
            chain.head_recipients(),
            Err(AionError::InvalidFormat { .. })
        ));
    }

    /// A provider failure, or two different handles naming the same key,
    /// refuses the commit and leaves the file byte-identical.
    #[test]
    fn external_wrapper_failures_leave_the_file_unchanged() {
        struct Failing;
        impl crate::confidential::DekWrapper for Failing {
            #[allow(clippy::unnecessary_literal_bound)] // the trait fixes the signature
            fn provider_id(&self) -> &str {
                "local-kms"
            }
            #[allow(clippy::unnecessary_literal_bound)] // the trait fixes the signature
            fn key_ref(&self) -> &str {
                "down"
            }
            fn wrap(&self, _dek: &[u8; 32], _context: &[u8]) -> Result<Vec<u8>> {
                Err(AionError::EncryptionFailed {
                    reason: "kms unavailable".to_string(),
                })
            }
        }
        let dir = ok(TempDir::new());
        let path = dir.path().join("unchanged.aion");
        let key = ok(SigningKey::generate());
        let author = AuthorId::new(90_031);
        let reader = identity(EncryptionKem::X25519);
        let registry = grow_confidential(&path, &key, author, &[(b"v1", vec![reader.recipient()])]);
        let before = ok(std::fs::read(&path));

        let twin = |key_ref: &'static str| {
            std::sync::Arc::new(crate::confidential::tests::LocalKms {
                key: [9; 32],
                key_ref,
            })
        };
        let attempts = [
            vec![Recipient::external(std::sync::Arc::new(Failing))],
            vec![
                Recipient::external(twin("same")),
                Recipient::external(twin("same")),
            ],
        ];
        for recipients in attempts {
            let commit = CommitOptions {
                author_id: author,
                signing_key: &key,
                message: "v2",
                timestamp: None,
                protection: RulesProtection::Confidential { recipients },
            };
            assert!(commit_version(&path, b"v2", &commit, &registry).is_err());
            assert_eq!(ok(std::fs::read(&path)), before);
        }
    }

    #[test]
    fn confidential_rules_over_the_size_limit_are_refused() {
        let dir = ok(TempDir::new());
        let key = ok(SigningKey::generate());
        let author = AuthorId::new(90_017);
        let reader = identity(EncryptionKem::X25519);
        let confidential = || RulesProtection::Confidential {
            recipients: vec![reader.recipient()],
        };
        let too_big = vec![b'x'; crate::format::MAX_CONFIDENTIAL_RULES_LEN];
        let init = InitOptions {
            author_id: author,
            signing_key: &key,
            message: "genesis",
            timestamp: None,
            protection: confidential(),
        };
        let result = init_file(&dir.path().join("big.aion"), &too_big, &init);
        assert!(
            matches!(&result, Err(AionError::InvalidFormat { reason }) if reason.contains("16 MiB")),
            "{result:?}"
        );
    }

    use crate::confidential::{EncryptionIdentity, EncryptionKem};

    fn identity(kem: EncryptionKem) -> EncryptionIdentity {
        ok(EncryptionIdentity::generate(kem))
    }

    /// A confidential v3 file: one version per `(rules, recipients)`.
    fn grow_confidential(
        path: &Path,
        key: &SigningKey,
        author: AuthorId,
        versions: &[(&[u8], Vec<Recipient>)],
    ) -> KeyRegistry {
        let registry = registry_for(author, key);
        for (index, (rules, recipients)) in versions.iter().enumerate() {
            let protection = if recipients.is_empty() {
                RulesProtection::Public
            } else {
                RulesProtection::Confidential {
                    recipients: recipients.clone(),
                }
            };
            if index == 0 {
                let init = InitOptions {
                    author_id: author,
                    signing_key: key,
                    message: "genesis",
                    timestamp: None,
                    protection,
                };
                ok(init_file(path, rules, &init));
            } else {
                let commit = CommitOptions {
                    author_id: author,
                    signing_key: key,
                    message: "next",
                    timestamp: None,
                    protection,
                };
                ok(commit_version(path, rules, &commit, &registry));
            }
        }
        registry
    }

    #[test]
    fn every_recipient_of_both_kems_opens_the_head() {
        let dir = ok(TempDir::new());
        let path = dir.path().join("confidential.aion");
        let key = ok(SigningKey::generate());
        let author = AuthorId::new(90_010);
        let (x, w) = (
            identity(EncryptionKem::X25519),
            identity(EncryptionKem::XWing),
        );
        let recipients = vec![x.recipient(), w.recipient()];
        let registry = grow_confidential(&path, &key, author, &[(b"refund: 5000", recipients)]);

        let chain = ok(verify_file_chain(&path, &registry));
        assert_eq!(chain.head().rules_mode(), Some(RulesMode::Confidential));
        for reader in [x, w] {
            let rules = ok(open_current_rules(&chain, &RecipientKeys::from(reader)));
            assert_eq!(rules.as_slice(), b"refund: 5000");
        }
    }

    #[test]
    fn readers_get_the_three_distinct_errors() {
        let dir = ok(TempDir::new());
        let path = dir.path().join("errors.aion");
        let key = ok(SigningKey::generate());
        let author = AuthorId::new(90_011);
        let reader = identity(EncryptionKem::XWing);
        let registry = grow_confidential(
            &path,
            &key,
            author,
            &[(b"secret", vec![reader.recipient()])],
        );
        let chain = ok(verify_file_chain(&path, &registry));

        assert!(matches!(
            open_current_rules(&chain, &RecipientKeys::none()),
            Err(AionError::RecipientKeyRequired)
        ));
        let stranger = RecipientKeys::from(identity(EncryptionKem::XWing));
        assert!(matches!(
            open_current_rules(&chain, &stranger),
            Err(AionError::NotARecipient)
        ));
        assert!(matches!(
            crate::operations::show_current_rules(&path),
            Err(AionError::RecipientKeyRequired)
        ));
        let both = RecipientKeys::from(identity(EncryptionKem::X25519)).with(reader);
        assert_eq!(ok(open_current_rules(&chain, &both)).as_slice(), b"secret");
    }

    #[test]
    fn a_disclosed_key_opens_exactly_its_own_version() {
        let dir = ok(TempDir::new());
        let path = dir.path().join("disclose.aion");
        let key = ok(SigningKey::generate());
        let author = AuthorId::new(90_012);
        let reader = identity(EncryptionKem::XWing);
        let to = || vec![reader.recipient()];
        let registry = grow_confidential(&path, &key, author, &[(b"v1 rules", to())]);
        let v1_section = ok(verify_file_chain(&path, &registry)).head_section;
        let commit = CommitOptions {
            author_id: author,
            signing_key: &key,
            message: "v2",
            timestamp: None,
            protection: RulesProtection::Confidential { recipients: to() },
        };
        ok(commit_version(&path, b"v2 rules", &commit, &registry));

        let chain = ok(verify_file_chain(&path, &registry));
        let keys = RecipientKeys::from(reader.clone());
        let v1 = chain
            .entry(VersionNumber(1))
            .unwrap_or_else(|| std::process::abort());
        let v1_key = ok(disclose_version_key(&v1_section, v1, &keys));
        let opened = ok(open_rules_section_with_key(&v1_section, v1, &v1_key));
        assert_eq!(opened.as_slice(), b"v1 rules");

        let v2_key = ok(disclose_version_key(
            &chain.head_section,
            chain.head(),
            &keys,
        ));
        assert!(matches!(
            open_rules_section_with_key(&v1_section, v1, &v2_key),
            Err(AionError::RulesUnopenable)
        ));
        assert!(open_rules_section_with_key(&v1_section, chain.head(), &v1_key).is_err());
        let rebuilt = VersionKey::from_bytes(v1_key.to_bytes());
        assert_eq!(
            ok(open_rules_section_with_key(&v1_section, v1, &rebuilt)).as_slice(),
            b"v1 rules"
        );
    }

    #[test]
    fn head_recipients_carry_over_and_public_heads_have_none() {
        let dir = ok(TempDir::new());
        let path = dir.path().join("keep.aion");
        let key = ok(SigningKey::generate());
        let author = AuthorId::new(90_013);
        let (x, w) = (
            identity(EncryptionKem::X25519),
            identity(EncryptionKem::XWing),
        );
        let registry = grow_confidential(
            &path,
            &key,
            author,
            &[
                (b"public", Vec::new()),
                (b"secret", vec![w.recipient(), x.recipient()]),
            ],
        );
        let chain = ok(verify_file_chain(&path, &registry));
        let kept = ok(chain.head_recipients());
        assert_eq!(kept.len(), 2);
        assert!(kept.contains(&x.recipient()) && kept.contains(&w.recipient()));
        assert_eq!(
            chain.entry(VersionNumber(1)).map(|e| e.rules_mode()),
            Some(Some(RulesMode::Public))
        );

        let public_path = dir.path().join("public.aion");
        let registry = grow_confidential(&public_path, &key, author, &[(b"public", Vec::new())]);
        let public = ok(verify_file_chain(&public_path, &registry));
        assert!(matches!(
            public.head_recipients(),
            Err(AionError::NoRecipients)
        ));
    }

    #[test]
    fn writers_refuse_empty_recipients_and_dedupe_repeats() {
        let dir = ok(TempDir::new());
        let key = ok(SigningKey::generate());
        let author = AuthorId::new(90_014);
        let init = |protection| InitOptions {
            author_id: author,
            signing_key: &key,
            message: "genesis",
            timestamp: None,
            protection,
        };
        let empty = RulesProtection::Confidential {
            recipients: Vec::new(),
        };
        assert!(matches!(
            init_file(&dir.path().join("empty.aion"), b"r", &init(empty)),
            Err(AionError::NoRecipients)
        ));
        let reader = identity(EncryptionKem::X25519);
        let repeated = RulesProtection::Confidential {
            recipients: vec![reader.recipient(), reader.recipient()],
        };
        let path = dir.path().join("dedupe.aion");
        ok(init_file(&path, b"r", &init(repeated)));
        let chain = ok(verify_file_chain(&path, &registry_for(author, &key)));
        assert_eq!(ok(chain.head_recipients()).len(), 1);
    }

    mod properties {
        use super::*;
        use hegel::generators as gs;

        #[hegel::test]
        fn prop_mixed_mode_chains_verify_key_free_and_open_for_every_recipient(
            tc: hegel::TestCase,
        ) {
            let count = tc.draw(gs::integers::<usize>().min_value(1).max_value(3));
            let readers = [
                identity(EncryptionKem::X25519),
                identity(EncryptionKem::XWing),
            ];
            let mut versions: Vec<(Vec<u8>, Vec<Recipient>)> = Vec::new();
            for _ in 0..count {
                let rules = tc.draw(gs::binary().max_size(256));
                let mask = tc.draw(gs::integers::<u8>().max_value(3));
                let recipients: Vec<Recipient> = readers
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| mask & (1 << i) != 0)
                    .map(|(_, r)| r.recipient())
                    .collect();
                versions.push((rules, recipients));
            }
            let dir = ok(TempDir::new());
            let path = dir.path().join("mixed.aion");
            let key = ok(SigningKey::generate());
            let author = AuthorId::new(90_100);
            let refs: Vec<(&[u8], Vec<Recipient>)> = versions
                .iter()
                .map(|(rules, recipients)| (rules.as_slice(), recipients.clone()))
                .collect();
            let registry = grow_confidential(&path, &key, author, &refs);

            let report = ok(crate::operations::verify_file(&path, &registry));
            assert!(report.is_valid, "{:?}", report.errors);
            let chain = ok(verify_file_chain(&path, &registry));
            for (entry, (_, recipients)) in chain.entries().zip(&versions) {
                let expected = if recipients.is_empty() {
                    RulesMode::Public
                } else {
                    RulesMode::Confidential
                };
                assert_eq!(entry.rules_mode(), Some(expected));
            }
            let (head_rules, head_recipients) =
                versions.last().unwrap_or_else(|| std::process::abort());
            if head_recipients.is_empty() {
                let rules = ok(open_current_rules(&chain, &RecipientKeys::none()));
                assert_eq!(rules.as_slice(), head_rules.as_slice());
                return;
            }
            assert!(matches!(
                crate::operations::show_current_rules(&path),
                Err(AionError::RecipientKeyRequired)
            ));
            for reader in &readers {
                let opened = open_current_rules(&chain, &RecipientKeys::from(reader.clone()));
                if head_recipients.contains(&reader.recipient()) {
                    assert_eq!(ok(opened).as_slice(), head_rules.as_slice());
                } else {
                    assert!(matches!(opened, Err(AionError::NotARecipient)));
                }
            }
        }

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
