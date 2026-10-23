// SPDX-License-Identifier: MIT OR Apache-2.0
//! Receiver-side acceptance with replay defense (RFC-0039).
//!
//! [`crate::operations::verify_file`] and [`crate::chain::verify_file_chain`]
//! answer a stateless question: is this file internally consistent and
//! correctly signed? They cannot tell an older, correctly signed file from
//! the current one. [`accept_file`] answers the receiver's question: may I
//! act on this file now?
//!
//! It verifies the chain, applies an [`AcceptPolicy`], and then consults
//! an [`AcceptedVersionStore`]. The store is mandatory, so replay defense
//! cannot be skipped by omission. The store:
//!
//! - **keys** records by `file_id`, because version numbers are file-wide,
//!   not per author;
//! - **advances** only along the chain it already accepted: the presented
//!   chain must contain the stored head as an ancestor;
//! - **rejects** rollbacks, forks or equivocations, and a different
//!   genesis under the same `file_id`;
//! - **writes** only after full verification, so invalid files never
//!   advance it, and fails closed on any store error.
//!
//! The decision table lives in one function, [`decide`], which every store
//! implementation calls inside its own compare-and-swap.
//!
//! # Example
//!
//! ```no_run
//! use aion_context::acceptance::{accept_file, AcceptPolicy, FileStore};
//! use aion_context::format::FormatVersion;
//! use aion_context::key_registry::KeyRegistry;
//! use std::path::Path;
//!
//! # fn example(registry: &KeyRegistry) -> aion_context::Result<()> {
//! let store = FileStore::open("accepted.json");
//! let policy = AcceptPolicy::new().min_format(FormatVersion::V3);
//! let chain = accept_file(Path::new("policy.aion"), registry, &policy, &store)?;
//! println!("accepted version {}", chain.head().version().as_u64());
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::chain::{verify_file_chain, VerifiedChain};
use crate::format::{FormatVersion, RulesMode};
use crate::key_registry::KeyRegistry;
use crate::types::{FileId, VersionNumber};
use crate::{AionError, Result};

/// Which versions an [`AcceptPolicy`] requires to be confidential.
///
/// Not `#[non_exhaustive]`: "the head" and "every version" are the only
/// scopes a linear chain has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfidentialScope {
    /// The latest version must be confidential.
    Head,
    /// Every version in the chain must be confidential.
    AllVersions,
}

/// What a receiver requires of a verified file before accepting it.
///
/// [`AcceptPolicy::new`] is permissive. Deployments that rely on
/// confidentiality should require it, and should set a minimum format so a
/// format-v2 file (which has no confidentiality) cannot stand in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AcceptPolicy {
    min_format: Option<FormatVersion>,
    require_confidential: Option<ConfidentialScope>,
}

impl AcceptPolicy {
    /// A permissive policy: any verified file is acceptable.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            min_format: None,
            require_confidential: None,
        }
    }

    /// Reject files older than `format`.
    #[must_use]
    pub const fn min_format(mut self, format: FormatVersion) -> Self {
        self.min_format = Some(format);
        self
    }

    /// Reject files whose rules are not confidential in `scope`.
    #[must_use]
    pub const fn require_confidential(mut self, scope: ConfidentialScope) -> Self {
        self.require_confidential = Some(scope);
        self
    }

    fn check(&self, chain: &VerifiedChain) -> Result<()> {
        if let Some(minimum) = self.min_format {
            if chain.context().format() < minimum {
                return Err(policy_rejected("format_below_minimum"));
            }
        }
        let confidential = |mode: Option<RulesMode>| mode == Some(RulesMode::Confidential);
        let violation = match self.require_confidential {
            Some(ConfidentialScope::Head) if !confidential(chain.head().rules_mode()) => {
                Some("head_not_confidential")
            }
            Some(ConfidentialScope::AllVersions)
                if !chain
                    .entries()
                    .all(|entry| confidential(entry.rules_mode())) =>
            {
                Some("version_not_confidential")
            }
            _ => None,
        };
        violation.map_or(Ok(()), |reason| Err(policy_rejected(reason)))
    }
}

const fn policy_rejected(reason: &'static str) -> AionError {
    AionError::PolicyRejected { reason }
}

/// Why an [`AcceptedVersionStore`] refused a verified chain.
///
/// Not `#[non_exhaustive]`: these are the three rejection rows of the
/// RFC-0039 decision table plus the RFC-0040 migration conflict, and
/// callers branch on them. A new rejection row would be an RFC change and
/// a major version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionRejectReason {
    /// The chain's head is older than the version already accepted.
    Replay,
    /// The chain does not extend the accepted head: a fork, or a
    /// different chain at the same version.
    Equivocation,
    /// The chain's genesis differs from the one recorded or pinned for
    /// this `file_id`.
    FileIdConflict,
    /// A different destination is already recorded as the migration of
    /// this source file (RFC-0040): the first verified claim wins.
    MigrationConflict,
}

impl VersionRejectReason {
    /// The bounded reason code used in errors and trace events.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Replay => "version_replay",
            Self::Equivocation => "version_equivocation",
            Self::FileIdConflict => "file_id_conflict",
            Self::MigrationConflict => "migration_conflict",
        }
    }
}

impl std::fmt::Display for VersionRejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

const fn version_rejected(reason: VersionRejectReason) -> AionError {
    AionError::VersionRejected { reason }
}

/// What a store remembers about one `file_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedRecord {
    genesis_hash: [u8; 32],
    head_version: u64,
    head_hash: Option<[u8; 32]>,
}

impl AcceptedRecord {
    /// A record that pins a genesis before any version is accepted.
    #[must_use]
    pub const fn pinned(genesis_hash: [u8; 32]) -> Self {
        Self {
            genesis_hash,
            head_version: 0,
            head_hash: None,
        }
    }

    /// Rebuild a record a store persisted. `head_version` 0 with no
    /// `head_hash` is a pin.
    ///
    /// For store implementations only. A record is the store's own claim
    /// about its state, and [`decide`] still checks every presented chain
    /// against it. A forged record can make that store more lenient, but
    /// the store is already trusted by whoever reads it.
    #[must_use]
    pub const fn from_parts(
        genesis_hash: [u8; 32],
        head_version: u64,
        head_hash: Option<[u8; 32]>,
    ) -> Self {
        Self {
            genesis_hash,
            head_version,
            head_hash,
        }
    }

    /// The accepted (or pinned) genesis version hash.
    #[must_use]
    pub const fn genesis_hash(&self) -> [u8; 32] {
        self.genesis_hash
    }

    /// The accepted head version, or 0 for a pin.
    #[must_use]
    pub const fn head_version(&self) -> u64 {
        self.head_version
    }

    /// The accepted head's version hash, or `None` for a pin.
    #[must_use]
    pub const fn head_hash(&self) -> Option<[u8; 32]> {
        self.head_hash
    }
}

/// The parts of a verified chain a store decision needs. Built only from a
/// [`VerifiedChain`], so every hash it reports was verified.
#[derive(Debug, Clone, Copy)]
pub struct ChainSummary<'a> {
    chain: &'a VerifiedChain,
}

impl<'a> ChainSummary<'a> {
    /// Summarise a verified chain.
    #[must_use]
    pub const fn new(chain: &'a VerifiedChain) -> Self {
        Self { chain }
    }

    /// The chain's `file_id`.
    #[must_use]
    pub const fn file_id(&self) -> FileId {
        self.chain.context().file_id()
    }

    /// The genesis version hash.
    ///
    /// # Errors
    ///
    /// Never fails for a verified chain, which always has a genesis.
    pub fn genesis_hash(&self) -> Result<[u8; 32]> {
        self.hash_at(1)
    }

    /// The head version number.
    #[must_use]
    pub const fn head_version(&self) -> u64 {
        self.chain.head().version().as_u64()
    }

    /// The head's version hash.
    #[must_use]
    pub const fn head_hash(&self) -> [u8; 32] {
        self.chain.head().version_hash()
    }

    /// The version hash at `version`.
    ///
    /// # Errors
    ///
    /// Returns [`AionError::MissingVersion`] if the chain has no such
    /// version. [`decide`] only asks for versions the chain contains.
    pub fn hash_at(&self, version: u64) -> Result<[u8; 32]> {
        self.chain
            .entry(VersionNumber(version))
            .map(|entry| entry.version_hash())
            .ok_or(AionError::MissingVersion { version })
    }
}

/// The outcome of a successful store check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreDecision {
    /// The chain was accepted and the store advanced to its head.
    Accepted,
    /// The chain's head is exactly the accepted head; nothing changed.
    AcceptedIdempotent,
}

/// A decision plus the record to persist, if any. Only [`decide`] builds
/// these; `#[non_exhaustive]` leaves room for more fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Transition {
    /// What to report to the caller.
    pub decision: StoreDecision,
    /// The record to write, or `None` when nothing changes.
    pub record: Option<AcceptedRecord>,
}

/// The RFC-0039 acceptance decision table. Store implementations call
/// this inside their compare-and-swap, between reading the current
/// record and writing the returned one.
///
/// Rows, in order:
///
/// 1. No record: accept and record the chain's head.
/// 2. Different genesis: reject as [`VersionRejectReason::FileIdConflict`].
/// 3. A pin (head version 0): accept and record the head.
/// 4. Head older than the record: reject as [`VersionRejectReason::Replay`].
/// 5. The chain's hash at the recorded version differs: reject as
///    [`VersionRejectReason::Equivocation`]. Row 4 guarantees the version
///    exists in the chain.
/// 6. Same head: accept idempotently, without writing.
/// 7. Otherwise: accept and advance.
///
/// # Errors
///
/// Returns [`AionError::VersionRejected`] per the rows above, or
/// [`AionError::StoreUnavailable`] for an inconsistent stored record.
pub fn decide(record: Option<&AcceptedRecord>, chain: ChainSummary<'_>) -> Result<Transition> {
    let head = AcceptedRecord::from_parts(
        chain.genesis_hash()?,
        chain.head_version(),
        Some(chain.head_hash()),
    );
    let advance = Transition {
        decision: StoreDecision::Accepted,
        record: Some(head),
    };
    let Some(stored) = record else {
        return Ok(advance);
    };
    if stored.genesis_hash != head.genesis_hash {
        return Err(version_rejected(VersionRejectReason::FileIdConflict));
    }
    if stored.head_version == 0 {
        if stored.head_hash.is_some() {
            return Err(AionError::StoreUnavailable {
                reason: "record_corrupt",
            });
        }
        return Ok(advance);
    }
    if head.head_version < stored.head_version {
        return Err(version_rejected(VersionRejectReason::Replay));
    }
    let stored_hash = stored.head_hash.ok_or(AionError::StoreUnavailable {
        reason: "record_without_head_hash",
    })?;
    if chain.hash_at(stored.head_version)? != stored_hash {
        return Err(version_rejected(VersionRejectReason::Equivocation));
    }
    if head.head_version == stored.head_version {
        return Ok(Transition {
            decision: StoreDecision::AcceptedIdempotent,
            record: None,
        });
    }
    Ok(advance)
}

/// Which file a store accepted as the migration of a source file
/// (RFC-0040), keyed by the source's `file_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationRecord {
    dest_file_id: FileId,
    dest_genesis_hash: [u8; 32],
}

impl MigrationRecord {
    /// Rebuild a record a store persisted. For store implementations only.
    #[must_use]
    pub const fn from_parts(dest_file_id: FileId, dest_genesis_hash: [u8; 32]) -> Self {
        Self {
            dest_file_id,
            dest_genesis_hash,
        }
    }

    /// The accepted destination's `file_id`.
    #[must_use]
    pub const fn dest_file_id(&self) -> FileId {
        self.dest_file_id
    }

    /// The accepted destination's genesis version hash.
    #[must_use]
    pub const fn dest_genesis_hash(&self) -> [u8; 32] {
        self.dest_genesis_hash
    }
}

/// The RFC-0040 migration decision, which stores call inside the same
/// compare-and-swap as [`decide`] for the destination.
///
/// No record: record this destination. The same destination: nothing to
/// write. Any other destination: [`VersionRejectReason::MigrationConflict`].
///
/// # Errors
///
/// Returns [`AionError::VersionRejected`] for a conflicting destination.
///
/// # Example
///
/// ```no_run
/// use aion_context::acceptance::{decide_migration, ChainSummary, MigrationRecord};
/// use aion_context::chain::VerifiedChain;
///
/// # fn example(dest: &VerifiedChain, stored: Option<MigrationRecord>) -> aion_context::Result<()> {
/// if let Some(record) = decide_migration(stored.as_ref(), ChainSummary::new(dest))? {
///     println!("record destination {}", record.dest_file_id().as_u64());
/// }
/// # Ok(())
/// # }
/// ```
pub fn decide_migration(
    record: Option<&MigrationRecord>,
    dest: ChainSummary<'_>,
) -> Result<Option<MigrationRecord>> {
    let claim = MigrationRecord::from_parts(dest.file_id(), dest.genesis_hash()?);
    match record {
        None => Ok(Some(claim)),
        Some(existing) if *existing == claim => Ok(None),
        Some(_) => Err(version_rejected(VersionRejectReason::MigrationConflict)),
    }
}

/// Durable memory of which version a receiver accepted for each file.
///
/// # Compatibility
///
/// RFC-0040 added [`AcceptedVersionStore::check_and_advance_migration`] and
/// [`AcceptedVersionStore::clear_migration`] with defaults that fail closed
/// (`migration_unsupported`). A store written for 2.x still compiles, but
/// [`accept_migration`] refuses until it overrides both.
///
/// Implementations must make [`AcceptedVersionStore::check_and_advance`]
/// atomic, as a compare-and-swap: read the record, call [`decide`], and
/// write the returned record, so that concurrent acceptances of the same
/// `file_id` cannot both win. Any storage error must fail closed with
/// [`AionError::StoreUnavailable`]. `Send + Sync` so one store can serve
/// a multi-threaded receiver.
pub trait AcceptedVersionStore: Send + Sync {
    /// Pin the expected genesis for `file_id` before anything is
    /// accepted. Pinning the same genesis again is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`AionError::VersionRejected`] with
    /// [`VersionRejectReason::FileIdConflict`] if a different genesis is
    /// already recorded, or [`AionError::StoreUnavailable`].
    fn pin(&self, file_id: FileId, genesis_hash: [u8; 32]) -> Result<()>;

    /// Atomically apply [`decide`] to the stored record for
    /// `chain.file_id()` and persist the result.
    ///
    /// # Errors
    ///
    /// Returns the [`decide`] rejection, or
    /// [`AionError::StoreUnavailable`].
    fn check_and_advance(&self, chain: ChainSummary<'_>) -> Result<StoreDecision>;

    /// Atomically, in one compare-and-swap: check `source` against its own
    /// record if the store has one (read-only: a replayed, forked, or
    /// foreign source is refused), apply [`decide_migration`] to `source`'s
    /// migration record and [`decide`] to `dest`'s record, and persist both
    /// or neither. A `dest` sharing `source`'s `file_id` is refused.
    ///
    /// The default fails closed with `migration_unsupported`, so a store
    /// that predates RFC-0040 refuses migrations instead of accepting them
    /// without a record.
    ///
    /// # Errors
    ///
    /// Returns either decision's rejection, or
    /// [`AionError::StoreUnavailable`].
    fn check_and_advance_migration(
        &self,
        dest: ChainSummary<'_>,
        source: ChainSummary<'_>,
    ) -> Result<StoreDecision> {
        let _ = (dest, source);
        Err(store_error("migration_unsupported"))
    }

    /// Remove `source`'s migration record, so a different destination can
    /// be accepted: the explicit recovery from a mistaken migration.
    /// Returns whether a record was removed. The destination's own version
    /// record is kept.
    ///
    /// # Errors
    ///
    /// Returns [`AionError::StoreUnavailable`]; the default fails closed
    /// with `migration_unsupported`.
    fn clear_migration(&self, source: FileId) -> Result<bool> {
        let _ = source;
        Err(store_error("migration_unsupported"))
    }
}

/// Remove `source`'s migration record. Lifting first-claim protection is
/// an operator decision, so it is always traced.
fn clear_migration_record(state: &mut StoreState, source: FileId) -> bool {
    let removed = state.migrations.remove(&source).is_some();
    tracing::warn!(
        event = "migration_cleared",
        source_file_id = %crate::obs::short_hex(&source.as_u64().to_le_bytes()),
        removed,
    );
    removed
}

/// Everything a store keeps, under one lock: version records and migration
/// records change together when a migration is accepted.
#[derive(Debug, Default)]
struct StoreState {
    records: HashMap<FileId, AcceptedRecord>,
    migrations: HashMap<FileId, MigrationRecord>,
}

fn advance_migration(
    state: &mut StoreState,
    dest: ChainSummary<'_>,
    source: ChainSummary<'_>,
) -> Result<(StoreDecision, bool)> {
    if dest.file_id() == source.file_id() {
        return Err(AionError::MigrationRejected {
            reason: "self_migration",
        });
    }
    if let Some(record) = state.records.get(&source.file_id()) {
        decide(Some(record), source)?;
    }
    let source = source.file_id();
    let migration = decide_migration(state.migrations.get(&source), dest)?;
    let transition = decide(state.records.get(&dest.file_id()), dest)?;
    let changed = migration.is_some() || transition.record.is_some();
    if let Some(record) = migration {
        state.migrations.insert(source, record);
    }
    if let Some(record) = transition.record {
        state.records.insert(dest.file_id(), record);
    }
    Ok((transition.decision, changed))
}

fn pin_record(
    records: &mut HashMap<FileId, AcceptedRecord>,
    file_id: FileId,
    genesis_hash: [u8; 32],
) -> Result<bool> {
    match records.get(&file_id) {
        Some(existing) if existing.genesis_hash == genesis_hash => Ok(false),
        Some(_) => Err(version_rejected(VersionRejectReason::FileIdConflict)),
        None => {
            records.insert(file_id, AcceptedRecord::pinned(genesis_hash));
            Ok(true)
        }
    }
}

fn advance_records(
    records: &mut HashMap<FileId, AcceptedRecord>,
    chain: ChainSummary<'_>,
) -> Result<(StoreDecision, bool)> {
    let transition = decide(records.get(&chain.file_id()), chain)?;
    let changed = transition.record.is_some();
    if let Some(record) = transition.record {
        records.insert(chain.file_id(), record);
    }
    Ok((transition.decision, changed))
}

const fn lock_poisoned() -> AionError {
    AionError::StoreUnavailable {
        reason: "store_lock_poisoned",
    }
}

/// An in-memory [`AcceptedVersionStore`]. It forgets everything when
/// dropped, so it only defends against replay within one process run.
#[derive(Debug, Default)]
pub struct MemoryStore {
    state: Mutex<StoreState>,
}

impl MemoryStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The record for `file_id`, if any.
    ///
    /// # Errors
    ///
    /// Returns [`AionError::StoreUnavailable`] if the lock is poisoned.
    pub fn record(&self, file_id: FileId) -> Result<Option<AcceptedRecord>> {
        let state = self.state.lock().map_err(|_| lock_poisoned())?;
        Ok(state.records.get(&file_id).copied())
    }

    /// The migration record for `source`, if any.
    ///
    /// # Errors
    ///
    /// Returns [`AionError::StoreUnavailable`] if the lock is poisoned.
    pub fn migration(&self, source: FileId) -> Result<Option<MigrationRecord>> {
        let state = self.state.lock().map_err(|_| lock_poisoned())?;
        Ok(state.migrations.get(&source).copied())
    }
}

impl AcceptedVersionStore for MemoryStore {
    fn pin(&self, file_id: FileId, genesis_hash: [u8; 32]) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| lock_poisoned())?;
        pin_record(&mut state.records, file_id, genesis_hash).map(|_| ())
    }

    fn check_and_advance(&self, chain: ChainSummary<'_>) -> Result<StoreDecision> {
        let mut state = self.state.lock().map_err(|_| lock_poisoned())?;
        advance_records(&mut state.records, chain).map(|(decision, _)| decision)
    }

    fn check_and_advance_migration(
        &self,
        dest: ChainSummary<'_>,
        source: ChainSummary<'_>,
    ) -> Result<StoreDecision> {
        let mut state = self.state.lock().map_err(|_| lock_poisoned())?;
        advance_migration(&mut state, dest, source).map(|(decision, _)| decision)
    }

    fn clear_migration(&self, source: FileId) -> Result<bool> {
        let mut state = self.state.lock().map_err(|_| lock_poisoned())?;
        Ok(clear_migration_record(&mut state, source))
    }
}

/// A JSON-file [`AcceptedVersionStore`].
///
/// - **No silent restart.** [`FileStore::open`] requires the file to
///   exist, so a typo or a deleted state file cannot quietly turn replay
///   defense off. [`FileStore::create`] makes a new, empty one, and
///   refuses to overwrite.
/// - **One writer at a time.** Every change takes an exclusive
///   `<state>.lock` file, created atomically. A concurrent writer, in this
///   process or another, fails closed with `store_locked` instead of
///   racing. A lock left by a crashed process makes later writes fail
///   closed until an operator removes it.
/// - **Crash-safe writes.** Changes go to a new temporary file (created
///   exclusively, mode 0600 on Unix, so a planted symlink is refused).
///   The file is fsynced, renamed over the old one, and the directory is
///   fsynced.
///
/// - **Format.** Version records and RFC-0040 migration records are saved
///   together as `{"records": …, "migrations": …}`. The flat record map
///   written by 2.x is still read; once saved here, a 2.x reader reports
///   `store_corrupt`, failing closed.
///
/// For many concurrent receivers, implement [`AcceptedVersionStore`] over
/// a database with compare-and-swap instead.
#[derive(Debug)]
pub struct FileStore {
    path: PathBuf,
    guard: Mutex<()>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredRecord {
    genesis_hash: String,
    head_version: u64,
    head_hash: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredMigration {
    dest_file_id: String,
    dest_genesis_hash: String,
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredState {
    #[serde(default)]
    records: std::collections::BTreeMap<String, StoredRecord>,
    #[serde(default)]
    migrations: std::collections::BTreeMap<String, StoredMigration>,
}

impl FileStore {
    /// Use the existing state file at `path`. A missing file is reported
    /// as `store_missing` on first use, never treated as empty.
    #[must_use]
    pub fn open(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            guard: Mutex::new(()),
        }
    }

    /// Create a new, empty state file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`AionError::StoreUnavailable`] (`store_exists`) if the file
    /// already exists, or `store_write_failed` if it cannot be written.
    pub fn create(path: impl Into<PathBuf>) -> Result<Self> {
        let store = Self::open(path);
        create_exclusive(&store.path, b"{}").map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                store_error("store_exists")
            } else {
                store_error("store_write_failed")
            }
        })?;
        Ok(store)
    }

    /// The record for `file_id`, if any.
    ///
    /// # Errors
    ///
    /// Returns [`AionError::StoreUnavailable`] if the file is missing or
    /// cannot be read or parsed.
    pub fn record(&self, file_id: FileId) -> Result<Option<AcceptedRecord>> {
        let _guard = self.guard.lock().map_err(|_| lock_poisoned())?;
        Ok(self.load()?.records.get(&file_id).copied())
    }

    /// The migration record for `source`, if any.
    ///
    /// # Errors
    ///
    /// Returns [`AionError::StoreUnavailable`] if the file is missing or
    /// cannot be read or parsed.
    pub fn migration(&self, source: FileId) -> Result<Option<MigrationRecord>> {
        let _guard = self.guard.lock().map_err(|_| lock_poisoned())?;
        Ok(self.load()?.migrations.get(&source).copied())
    }

    fn load(&self) -> Result<StoreState> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(store_error("store_missing"))
            }
            Err(_) => return Err(store_error("store_read_failed")),
        };
        let stored = serde_json::from_str::<StoredState>(&text)
            .or_else(|_| {
                serde_json::from_str(&text).map(|records| StoredState {
                    records,
                    migrations: std::collections::BTreeMap::new(),
                })
            })
            .map_err(|_| store_error("store_corrupt"))?;
        decode_state(&stored)
    }

    fn save(&self, state: &StoreState) -> Result<()> {
        let text = serde_json::to_string_pretty(&encode_state(state))
            .map_err(|_| store_error("store_write_failed"))?;
        write_durably(&self.path, text.as_bytes())
    }

    /// Run `change` with the in-process guard and the cross-process lock
    /// file both held, saving only if it reports a change.
    fn locked_update<T>(
        &self,
        change: impl FnOnce(&mut StoreState) -> Result<(T, bool)>,
    ) -> Result<T> {
        let _guard = self.guard.lock().map_err(|_| lock_poisoned())?;
        let _lock = StateLock::acquire(&self.path)?;
        let mut state = self.load()?;
        let (value, changed) = change(&mut state)?;
        if changed {
            self.save(&state)?;
        }
        Ok(value)
    }
}

impl AcceptedVersionStore for FileStore {
    fn pin(&self, file_id: FileId, genesis_hash: [u8; 32]) -> Result<()> {
        self.locked_update(|state| {
            pin_record(&mut state.records, file_id, genesis_hash).map(|changed| ((), changed))
        })
    }

    fn check_and_advance(&self, chain: ChainSummary<'_>) -> Result<StoreDecision> {
        self.locked_update(|state| advance_records(&mut state.records, chain))
    }

    fn check_and_advance_migration(
        &self,
        dest: ChainSummary<'_>,
        source: ChainSummary<'_>,
    ) -> Result<StoreDecision> {
        self.locked_update(|state| advance_migration(state, dest, source))
    }

    fn clear_migration(&self, source: FileId) -> Result<bool> {
        self.locked_update(|state| {
            let removed = clear_migration_record(state, source);
            Ok((removed, removed))
        })
    }
}

/// An exclusive lock on a state file, held while it exists.
struct StateLock {
    path: PathBuf,
}

impl StateLock {
    fn acquire(state: &Path) -> Result<Self> {
        let mut name = state.as_os_str().to_owned();
        name.push(".lock");
        let path = PathBuf::from(name);
        let pid = std::process::id().to_string();
        create_exclusive(&path, pid.as_bytes()).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                store_error("store_locked")
            } else {
                store_error("store_lock_failed")
            }
        })?;
        Ok(Self { path })
    }
}

impl Drop for StateLock {
    fn drop(&mut self) {
        // Nothing useful can be done if removal fails here; the next writer
        // then fails closed with `store_locked`, which is the safe outcome.
        let _ = std::fs::remove_file(&self.path);
    }
}

const fn store_error(reason: &'static str) -> AionError {
    AionError::StoreUnavailable { reason }
}

/// Only the canonical decimal spelling, so two keys can never name the
/// same `file_id`.
fn parse_file_id(text: &str) -> Result<FileId> {
    let id = text
        .parse::<u64>()
        .map_err(|_| store_error("store_corrupt"))?;
    if id.to_string() != text {
        return Err(store_error("store_corrupt"));
    }
    Ok(FileId::new(id))
}

fn decode_hash(text: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(text).map_err(|_| store_error("store_corrupt"))?;
    bytes.try_into().map_err(|_| store_error("store_corrupt"))
}

fn decode_record(record: &StoredRecord) -> Result<AcceptedRecord> {
    let head_hash = record.head_hash.as_deref().map(decode_hash).transpose()?;
    Ok(AcceptedRecord::from_parts(
        decode_hash(&record.genesis_hash)?,
        record.head_version,
        head_hash,
    ))
}

fn decode_state(stored: &StoredState) -> Result<StoreState> {
    let records = stored
        .records
        .iter()
        .map(|(id, record)| Ok((parse_file_id(id)?, decode_record(record)?)))
        .collect::<Result<_>>()?;
    let migrations = stored
        .migrations
        .iter()
        .map(|(source, record)| {
            let dest = parse_file_id(&record.dest_file_id)?;
            let genesis = decode_hash(&record.dest_genesis_hash)?;
            Ok((
                parse_file_id(source)?,
                MigrationRecord::from_parts(dest, genesis),
            ))
        })
        .collect::<Result<_>>()?;
    Ok(StoreState {
        records,
        migrations,
    })
}

fn encode_state(state: &StoreState) -> StoredState {
    StoredState {
        records: state
            .records
            .iter()
            .map(|(id, record)| (id.as_u64().to_string(), encode_record(record)))
            .collect(),
        migrations: state
            .migrations
            .iter()
            .map(|(source, record)| {
                let stored = StoredMigration {
                    dest_file_id: record.dest_file_id.as_u64().to_string(),
                    dest_genesis_hash: hex::encode(record.dest_genesis_hash),
                };
                (source.as_u64().to_string(), stored)
            })
            .collect(),
    }
}

fn encode_record(record: &AcceptedRecord) -> StoredRecord {
    StoredRecord {
        genesis_hash: hex::encode(record.genesis_hash),
        head_version: record.head_version,
        head_hash: record.head_hash.map(hex::encode),
    }
}

/// Create `path` exclusively (never following or replacing an existing
/// entry, including a symlink), owner-only on Unix, write `bytes`, and
/// fsync it.
fn create_exclusive(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Write `bytes` to `path` so that a crash leaves either the old or the
/// new contents: exclusive temp file, fsync, rename, fsync the directory.
fn write_durably(path: &Path, bytes: &[u8]) -> Result<()> {
    let directory = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let temp = directory.join(format!(".aion-accepted-{}-{nanos}.tmp", std::process::id()));
    let write = || -> std::io::Result<()> {
        create_exclusive(&temp, bytes)?;
        std::fs::rename(&temp, path)?;
        std::fs::File::open(directory)?.sync_all()
    };
    write().map_err(|_| {
        // Best-effort cleanup of the temp file; the error that matters is
        // reported below.
        let _ = std::fs::remove_file(&temp);
        store_error("store_write_failed")
    })
}

/// Verify a file, apply `policy`, and record it in `store` (RFC-0039).
///
/// Order matters: the store is consulted only after full verification and
/// the policy pass, so an invalid or disallowed file can never advance it.
///
/// # Errors
///
/// Returns [`AionError::ChainRejected`] if verification fails,
/// [`AionError::PolicyRejected`] if the policy is violated,
/// [`AionError::VersionRejected`] for a replay, fork, or conflicting
/// genesis, or [`AionError::StoreUnavailable`] if the store fails.
pub fn accept_file(
    path: &Path,
    registry: &KeyRegistry,
    policy: &AcceptPolicy,
    store: &dyn AcceptedVersionStore,
) -> Result<VerifiedChain> {
    let chain = verify_file_chain(path, registry).inspect_err(|e| {
        tracing::warn!(event = "file_not_accepted", reason = rejection_reason(e));
    })?;
    let file_id = crate::obs::short_hex(&chain.context().file_id().as_u64().to_le_bytes());
    let outcome = policy
        .check(&chain)
        .and_then(|()| store.check_and_advance(ChainSummary::new(&chain)));
    match outcome {
        Ok(decision) => {
            tracing::info!(
                event = "file_accepted",
                file_id = %file_id,
                version = chain.head().version().as_u64(),
                idempotent = decision == StoreDecision::AcceptedIdempotent,
            );
            Ok(chain)
        }
        Err(e) => {
            tracing::warn!(
                event = "file_not_accepted",
                file_id = %file_id,
                version = chain.head().version().as_u64(),
                reason = rejection_reason(&e),
            );
            Err(e)
        }
    }
}

/// Accept `dest_path` as the migration of the already-verified `source`
/// (RFC-0040).
///
/// In order, before anything is written:
///
/// 1. fully verify `dest_path` with `registry`;
/// 2. [`crate::migration::verify_migration`] against `source` under
///    `migration_policy`;
/// 3. `policy`, as for [`accept_file`];
/// 4. then, in one store compare-and-swap, record `source → dest` and
///    advance `dest`'s own record.
///
/// The first verified claim for a source wins; presenting the same
/// destination again is idempotent. Recovering from a mistaken migration
/// is [`AcceptedVersionStore::clear_migration`].
///
/// # Errors
///
/// Returns [`AionError::ChainRejected`], [`AionError::MigrationRejected`],
/// [`AionError::PolicyRejected`], [`AionError::VersionRejected`]
/// (including [`VersionRejectReason::MigrationConflict`], or a replay or
/// fork of `source` when the store tracks it), or
/// [`AionError::StoreUnavailable`].
///
/// # Example
///
/// ```no_run
/// use aion_context::acceptance::{accept_file, accept_migration, AcceptPolicy, FileStore};
/// use aion_context::format::FormatVersion;
/// use aion_context::key_registry::KeyRegistry;
/// use aion_context::migration::MigrationPolicy;
/// use std::path::Path;
///
/// # fn example(registry: &KeyRegistry) -> aion_context::Result<()> {
/// let store = FileStore::open("accepted.json");
/// let policy = AcceptPolicy::new().min_format(FormatVersion::V4);
/// let source = accept_file(Path::new("policy.aion"), registry, &AcceptPolicy::new(), &store)?;
/// let migrated = accept_migration(
///     Path::new("policy-v4.aion"),
///     &source,
///     registry,
///     &policy,
///     &MigrationPolicy::SameAuthor,
///     &store,
/// )?;
/// assert!(migrated.metadata_signed());
/// # Ok(())
/// # }
/// ```
pub fn accept_migration(
    dest_path: &Path,
    source: &VerifiedChain,
    registry: &KeyRegistry,
    policy: &AcceptPolicy,
    migration_policy: &crate::migration::MigrationPolicy,
    store: &dyn AcceptedVersionStore,
) -> Result<VerifiedChain> {
    let source_file_id = crate::obs::short_hex(&source.context().file_id().as_u64().to_le_bytes());
    let dest = verify_file_chain(dest_path, registry).inspect_err(|e| {
        tracing::warn!(
            event = "migration_not_accepted",
            source_file_id = %source_file_id,
            reason = rejection_reason(e)
        );
    })?;
    let file_id = crate::obs::short_hex(&dest.context().file_id().as_u64().to_le_bytes());
    let outcome = crate::migration::verify_migration(&dest, source, migration_policy)
        .and_then(|_| policy.check(&dest))
        .and_then(|()| {
            store.check_and_advance_migration(ChainSummary::new(&dest), ChainSummary::new(source))
        });
    match outcome {
        Ok(decision) => {
            tracing::info!(
                event = "migration_accepted",
                file_id = %file_id,
                source_file_id = %source_file_id,
                version = dest.head().version().as_u64(),
                idempotent = decision == StoreDecision::AcceptedIdempotent,
            );
            Ok(dest)
        }
        Err(e) => {
            tracing::warn!(
                event = "migration_not_accepted",
                file_id = %file_id,
                source_file_id = %source_file_id,
                reason = rejection_reason(&e),
            );
            Err(e)
        }
    }
}

const fn rejection_reason(error: &AionError) -> &'static str {
    match error {
        AionError::PolicyRejected { reason }
        | AionError::StoreUnavailable { reason }
        | AionError::MigrationRejected { reason }
        | AionError::ChainRejected { reason } => reason,
        AionError::VersionRejected { reason } => reason.as_str(),
        _ => "unknown",
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::chain::VerifiedChain;
    use crate::crypto::SigningKey;
    use crate::format::RulesProtection;
    use crate::operations::{commit_version, init_file, CommitOptions, InitOptions};
    use crate::types::AuthorId;
    use tempfile::TempDir;

    fn ok<T, E>(result: std::result::Result<T, E>) -> T {
        result.unwrap_or_else(|_| std::process::abort())
    }

    struct Fixture {
        _dir: TempDir,
        registry: KeyRegistry,
        /// main[i] is the file at version i + 1 (v1..v4).
        main: Vec<PathBuf>,
        /// fork[0] is v3', fork[1] is v4'; both descend from main v2.
        fork: Vec<PathBuf>,
    }

    fn commit(path: &Path, key: &SigningKey, registry: &KeyRegistry, rules: &[u8]) {
        let options = CommitOptions {
            author_id: AuthorId::new(95_001),
            signing_key: key,
            message: "next",
            timestamp: None,
            protection: RulesProtection::Public,
        };
        ok(commit_version(path, rules, &options, registry));
    }

    fn snapshot(dir: &TempDir, from: &Path, name: &str) -> PathBuf {
        let to = dir.path().join(name);
        ok(std::fs::copy(from, &to));
        to
    }

    fn fixture() -> Fixture {
        let dir = ok(TempDir::new());
        let key = ok(SigningKey::generate());
        let author = AuthorId::new(95_001);
        let mut registry = KeyRegistry::new();
        let master = ok(SigningKey::generate());
        ok(registry.register_author(author, master.verifying_key(), key.verifying_key(), 0));
        let work = dir.path().join("work.aion");
        let init = InitOptions {
            author_id: author,
            signing_key: &key,
            message: "genesis",
            timestamp: None,
            protection: RulesProtection::Public,
        };
        ok(init_file(&work, b"v1", &init));
        let mut main = vec![snapshot(&dir, &work, "main1.aion")];
        for n in 2..=4 {
            commit(&work, &key, &registry, format!("v{n}").as_bytes());
            main.push(snapshot(&dir, &work, &format!("main{n}.aion")));
        }
        let fork_work = snapshot(&dir, &main[1], "fork-work.aion");
        let mut fork = Vec::new();
        for n in 3..=4 {
            commit(&fork_work, &key, &registry, format!("fork{n}").as_bytes());
            fork.push(snapshot(&dir, &fork_work, &format!("fork{n}.aion")));
        }
        Fixture {
            _dir: dir,
            registry,
            main,
            fork,
        }
    }

    fn accept(
        fx: &Fixture,
        path: &Path,
        store: &dyn AcceptedVersionStore,
    ) -> Result<VerifiedChain> {
        accept_file(path, &fx.registry, &AcceptPolicy::new(), store)
    }

    fn rejected(result: &Result<VerifiedChain>) -> Option<VersionRejectReason> {
        match result {
            Err(AionError::VersionRejected { reason }) => Some(*reason),
            _ => None,
        }
    }

    #[test]
    fn advances_along_the_chain_and_is_idempotent() {
        let fx = fixture();
        let store = MemoryStore::new();
        ok(accept(&fx, &fx.main[0], &store));
        ok(accept(&fx, &fx.main[2], &store));
        let again = ok(accept(&fx, &fx.main[2], &store));
        let record = ok(store.record(again.context().file_id()));
        assert_eq!(record.map(|r| r.head_version()), Some(3));
        let summary = ChainSummary::new(&again);
        assert_eq!(
            ok(decide(record.as_ref(), summary)).decision,
            StoreDecision::AcceptedIdempotent
        );
    }

    #[test]
    fn older_version_after_newer_is_a_replay() {
        let fx = fixture();
        let store = MemoryStore::new();
        ok(accept(&fx, &fx.main[2], &store));
        assert_eq!(
            rejected(&accept(&fx, &fx.main[1], &store)),
            Some(VersionRejectReason::Replay)
        );
    }

    #[test]
    fn forks_are_equivocation_at_and_above_the_accepted_head() {
        let fx = fixture();
        let store = MemoryStore::new();
        ok(accept(&fx, &fx.main[2], &store));
        assert_eq!(
            rejected(&accept(&fx, &fx.fork[0], &store)),
            Some(VersionRejectReason::Equivocation)
        );
        assert_eq!(
            rejected(&accept(&fx, &fx.fork[1], &store)),
            Some(VersionRejectReason::Equivocation)
        );
        ok(accept(&fx, &fx.main[3], &store));
    }

    #[test]
    fn pinned_genesis_admits_its_chain_and_refuses_another() {
        let fx = fixture();
        let chain = ok(verify_file_chain(&fx.main[0], &fx.registry));
        let file_id = chain.context().file_id();
        let genesis = chain.head().version_hash();

        let store = MemoryStore::new();
        ok(store.pin(file_id, genesis));
        ok(store.pin(file_id, genesis));
        ok(accept(&fx, &fx.main[1], &store));

        let wrong = MemoryStore::new();
        ok(wrong.pin(file_id, [0xEE; 32]));
        assert_eq!(
            rejected(&accept(&fx, &fx.main[1], &wrong)),
            Some(VersionRejectReason::FileIdConflict)
        );
        assert!(matches!(
            wrong.pin(file_id, genesis),
            Err(AionError::VersionRejected {
                reason: VersionRejectReason::FileIdConflict
            })
        ));
    }

    #[test]
    fn invalid_file_never_advances_the_store() {
        let fx = fixture();
        let store = MemoryStore::new();
        ok(accept(&fx, &fx.main[0], &store));
        let mut bytes = ok(std::fs::read(&fx.main[3]));
        let last = bytes.len().saturating_sub(1);
        bytes[last] ^= 0x01;
        let tampered = fx.main[0].with_file_name("tampered.aion");
        ok(std::fs::write(&tampered, &bytes));
        assert!(matches!(
            accept(&fx, &tampered, &store),
            Err(AionError::ChainRejected { .. })
        ));
        let file_id = ok(verify_file_chain(&fx.main[0], &fx.registry))
            .context()
            .file_id();
        assert_eq!(ok(store.record(file_id)).map(|r| r.head_version()), Some(1));
    }

    #[test]
    fn policy_rejects_before_the_store_is_touched() {
        let fx = fixture();
        let store = MemoryStore::new();
        let confidential = AcceptPolicy::new().require_confidential(ConfidentialScope::Head);
        assert!(matches!(
            accept_file(&fx.main[0], &fx.registry, &confidential, &store),
            Err(AionError::PolicyRejected {
                reason: "head_not_confidential"
            })
        ));
        let all = AcceptPolicy::new().require_confidential(ConfidentialScope::AllVersions);
        assert!(matches!(
            accept_file(&fx.main[0], &fx.registry, &all, &store),
            Err(AionError::PolicyRejected {
                reason: "version_not_confidential"
            })
        ));
        let file_id = ok(verify_file_chain(&fx.main[0], &fx.registry))
            .context()
            .file_id();
        assert_eq!(ok(store.record(file_id)), None);
        let v3 = AcceptPolicy::new().min_format(FormatVersion::V3);
        ok(accept_file(&fx.main[0], &fx.registry, &v3, &store));
    }

    /// A chain of `modes` (true = confidential), oldest first.
    fn chain_of(dir: &TempDir, name: &str, modes: &[bool]) -> (std::path::PathBuf, KeyRegistry) {
        use crate::confidential::{EncryptionIdentity, EncryptionKem};
        let key = ok(SigningKey::generate());
        let author = AuthorId::new(95_001);
        let master = ok(SigningKey::generate());
        let mut registry = KeyRegistry::new();
        ok(registry.register_author(author, master.verifying_key(), key.verifying_key(), 0));
        let reader = ok(EncryptionIdentity::generate(EncryptionKem::XWing));
        let protection = |confidential: bool| {
            if confidential {
                RulesProtection::Confidential {
                    recipients: vec![reader.recipient()],
                }
            } else {
                RulesProtection::Public
            }
        };
        let path = dir.path().join(name);
        for (index, confidential) in modes.iter().enumerate() {
            if index == 0 {
                let init = InitOptions {
                    author_id: author,
                    signing_key: &key,
                    message: "v1",
                    timestamp: None,
                    protection: protection(*confidential),
                };
                ok(init_file(&path, b"rules", &init));
            } else {
                let commit = CommitOptions {
                    author_id: author,
                    signing_key: &key,
                    message: "next",
                    timestamp: None,
                    protection: protection(*confidential),
                };
                ok(commit_version(&path, b"rules", &commit, &registry));
            }
        }
        (path, registry)
    }

    #[test]
    fn confidentiality_policy_reads_the_signed_modes_of_real_files() {
        let dir = ok(TempDir::new());
        let head = AcceptPolicy::new().require_confidential(ConfidentialScope::Head);
        let all = AcceptPolicy::new().require_confidential(ConfidentialScope::AllVersions);

        let (mixed, registry) = chain_of(&dir, "mixed.aion", &[false, true]);
        ok(accept_file(&mixed, &registry, &head, &MemoryStore::new()));
        assert!(matches!(
            accept_file(&mixed, &registry, &all, &MemoryStore::new()),
            Err(AionError::PolicyRejected {
                reason: "version_not_confidential"
            })
        ));

        let (sealed, registry) = chain_of(&dir, "sealed.aion", &[true, true]);
        ok(accept_file(&sealed, &registry, &all, &MemoryStore::new()));

        let (reopened, registry) = chain_of(&dir, "reopened.aion", &[true, false]);
        assert!(matches!(
            accept_file(&reopened, &registry, &head, &MemoryStore::new()),
            Err(AionError::PolicyRejected {
                reason: "head_not_confidential"
            })
        ));
    }

    fn store_failure(result: &Result<VerifiedChain>) -> Option<&'static str> {
        match result {
            Err(AionError::StoreUnavailable { reason }) => Some(reason),
            _ => None,
        }
    }

    #[test]
    fn file_store_survives_reopening_and_fails_closed_when_corrupt() {
        let fx = fixture();
        let state = fx.main[0].with_file_name("accepted.json");
        ok(accept(&fx, &fx.main[2], &ok(FileStore::create(&state))));
        assert_eq!(
            rejected(&accept(&fx, &fx.main[1], &FileStore::open(&state))),
            Some(VersionRejectReason::Replay)
        );
        ok(std::fs::write(&state, b"{ not json"));
        assert_eq!(
            store_failure(&accept(&fx, &fx.main[3], &FileStore::open(&state))),
            Some("store_corrupt")
        );
    }

    #[test]
    fn file_store_never_treats_a_missing_or_locked_state_as_empty() {
        let fx = fixture();
        let state = fx.main[0].with_file_name("missing.json");
        assert_eq!(
            store_failure(&accept(&fx, &fx.main[0], &FileStore::open(&state))),
            Some("store_missing")
        );
        let store = ok(FileStore::create(&state));
        assert!(matches!(
            FileStore::create(&state),
            Err(AionError::StoreUnavailable {
                reason: "store_exists"
            })
        ));
        let lock = fx.main[0].with_file_name("missing.json.lock");
        ok(std::fs::write(&lock, b"held"));
        assert_eq!(
            store_failure(&accept(&fx, &fx.main[0], &store)),
            Some("store_locked")
        );
        ok(std::fs::remove_file(&lock));
        ok(accept(&fx, &fx.main[0], &store));
        assert!(!lock.exists(), "lock released after the update");
    }

    #[test]
    fn a_pin_record_with_a_head_hash_is_treated_as_corrupt() {
        let fx = fixture();
        let chain = ok(verify_file_chain(&fx.main[0], &fx.registry));
        let summary = ChainSummary::new(&chain);
        let corrupt = AcceptedRecord::from_parts(ok(summary.genesis_hash()), 0, Some([1; 32]));
        assert!(matches!(
            decide(Some(&corrupt), summary),
            Err(AionError::StoreUnavailable {
                reason: "record_corrupt"
            })
        ));
    }

    mod properties {
        use super::*;
        use hegel::generators as gs;

        /// Reference model of the RFC-0039 decision table over the fixture:
        /// `(on_fork, version)` identifies each presented file. The fork
        /// shares only versions 1 and 2 with the main chain.
        fn model(
            stored: Option<(bool, u64)>,
            presented: (bool, u64),
        ) -> std::result::Result<(StoreDecision, Option<(bool, u64)>), VersionRejectReason>
        {
            let Some((stored_fork, stored_version)) = stored else {
                return Ok((StoreDecision::Accepted, Some(presented)));
            };
            let (fork, version) = presented;
            if version < stored_version {
                return Err(VersionRejectReason::Replay);
            }
            let contains_stored_head = stored_version <= 2 || fork == stored_fork;
            if !contains_stored_head {
                return Err(VersionRejectReason::Equivocation);
            }
            if version == stored_version {
                return Ok((StoreDecision::AcceptedIdempotent, stored));
            }
            Ok((StoreDecision::Accepted, Some(presented)))
        }

        #[hegel::test(test_cases = 20)]
        fn prop_store_matches_the_reference_model(tc: hegel::TestCase) {
            let fx = fixture();
            let mut files: Vec<((bool, u64), VerifiedChain)> = Vec::new();
            for (i, path) in fx.main.iter().enumerate() {
                let version = (i as u64).saturating_add(1);
                files.push(((false, version), ok(verify_file_chain(path, &fx.registry))));
            }
            for (i, path) in fx.fork.iter().enumerate() {
                let version = (i as u64).saturating_add(3);
                files.push(((true, version), ok(verify_file_chain(path, &fx.registry))));
            }
            let store = MemoryStore::new();
            let mut state: Option<(bool, u64)> = None;
            let steps = tc.draw(gs::integers::<usize>().min_value(1).max_value(12));
            for _ in 0..steps {
                let pick =
                    tc.draw(gs::integers::<usize>().max_value(files.len().saturating_sub(1)));
                let (presented, chain) = &files[pick];
                let file_id = chain.context().file_id();
                let actual = store.check_and_advance(ChainSummary::new(chain));
                match model(state, *presented) {
                    Ok((decision, next)) => {
                        assert_eq!(ok(actual), decision, "{presented:?} after {state:?}");
                        state = next;
                    }
                    Err(reason) => assert!(matches!(
                        actual,
                        Err(AionError::VersionRejected { reason: r }) if r == reason
                    )),
                }
                let recorded = ok(store.record(file_id)).map(|r| r.head_version());
                assert_eq!(recorded, state.map(|(_, version)| version));
            }
        }
    }

    mod migration {
        use super::*;
        use crate::chain::{open_current_rules, RecipientKeys};
        use crate::migration::MigrationPolicy;
        use crate::operations::migrate_file;

        struct World {
            dir: TempDir,
            registry: KeyRegistry,
            key: SigningKey,
            stranger: SigningKey,
            source: PathBuf,
        }

        const AUTHOR: u64 = 96_001;
        const STRANGER: u64 = 96_002;

        fn world() -> World {
            let dir = ok(TempDir::new());
            let mut registry = KeyRegistry::new();
            let key = ok(SigningKey::generate());
            let stranger = ok(SigningKey::generate());
            for (id, signing) in [(AUTHOR, &key), (STRANGER, &stranger)] {
                let master = ok(SigningKey::generate());
                ok(registry.register_author(
                    AuthorId::new(id),
                    master.verifying_key(),
                    signing.verifying_key(),
                    0,
                ));
            }
            let source = dir.path().join("source.aion");
            let init = InitOptions {
                author_id: AuthorId::new(AUTHOR),
                signing_key: &key,
                message: "genesis",
                timestamp: None,
                protection: RulesProtection::Public,
            };
            ok(init_file(&source, b"r", &init));
            World {
                dir,
                registry,
                key,
                stranger,
                source,
            }
        }

        fn source_chain(w: &World) -> VerifiedChain {
            ok(verify_file_chain(&w.source, &w.registry))
        }

        fn migrated(w: &World, name: &str, author: u64, key: &SigningKey) -> PathBuf {
            let source = source_chain(w);
            let rules = ok(open_current_rules(&source, &RecipientKeys::none()));
            let dest = w.dir.path().join(name);
            let options = InitOptions {
                author_id: AuthorId::new(author),
                signing_key: key,
                message: "migrate",
                timestamp: None,
                protection: RulesProtection::Public,
            };
            ok(migrate_file(&source, &rules, &dest, &options, &w.registry));
            dest
        }

        fn accept_as(
            w: &World,
            dest: &Path,
            policy: &AcceptPolicy,
            store: &dyn AcceptedVersionStore,
        ) -> Result<VerifiedChain> {
            accept_migration(
                dest,
                &source_chain(w),
                &w.registry,
                policy,
                &MigrationPolicy::SameAuthor,
                store,
            )
        }

        fn conflict(result: &Result<VerifiedChain>) -> bool {
            matches!(
                result,
                Err(AionError::VersionRejected {
                    reason: VersionRejectReason::MigrationConflict
                })
            )
        }

        #[test]
        fn first_verified_claim_wins_and_repeats_are_idempotent() {
            let w = world();
            let first = migrated(&w, "first.aion", AUTHOR, &w.key);
            let second = migrated(&w, "second.aion", AUTHOR, &w.key);
            let store = MemoryStore::new();
            let accepted = ok(accept_as(&w, &first, &AcceptPolicy::new(), &store));
            let source_id = source_chain(&w).context().file_id();
            let record = ok(ok(store.migration(source_id)).ok_or(()));
            assert_eq!(record.dest_file_id(), accepted.context().file_id());
            assert!(ok(store.record(accepted.context().file_id())).is_some());
            assert!(accept_as(&w, &first, &AcceptPolicy::new(), &store).is_ok());
            assert!(conflict(&accept_as(
                &w,
                &second,
                &AcceptPolicy::new(),
                &store
            )));
            assert_eq!(ok(store.migration(source_id)), Some(record));
        }

        #[test]
        fn a_failed_check_writes_no_record() {
            let w = world();
            let by_stranger = migrated(&w, "stranger.aion", STRANGER, &w.stranger);
            let store = MemoryStore::new();
            let source_id = source_chain(&w).context().file_id();
            let unmet = accept_as(&w, &by_stranger, &AcceptPolicy::new(), &store);
            assert!(matches!(
                unmet,
                Err(AionError::MigrationRejected {
                    reason: "policy_unmet"
                })
            ));
            let real = migrated(&w, "real.aion", AUTHOR, &w.key);
            let strict = AcceptPolicy::new().require_confidential(ConfidentialScope::Head);
            assert!(matches!(
                accept_as(&w, &real, &strict, &store),
                Err(AionError::PolicyRejected { .. })
            ));
            let mut bytes = ok(std::fs::read(&real));
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
            let corrupt = w.dir.path().join("corrupt.aion");
            ok(std::fs::write(&corrupt, &bytes));
            assert!(accept_as(&w, &corrupt, &AcceptPolicy::new(), &store).is_err());
            assert_eq!(ok(store.migration(source_id)), None);
            assert!(ok(store.record(
                ok(verify_file_chain(&real, &w.registry))
                    .context()
                    .file_id()
            ))
            .is_none());
        }

        #[test]
        fn clearing_a_migration_lets_another_destination_in() {
            let w = world();
            let first = migrated(&w, "first.aion", AUTHOR, &w.key);
            let second = migrated(&w, "second.aion", AUTHOR, &w.key);
            let store = MemoryStore::new();
            let source_id = source_chain(&w).context().file_id();
            ok(accept_as(&w, &first, &AcceptPolicy::new(), &store));
            assert!(ok(store.clear_migration(source_id)));
            assert!(!ok(store.clear_migration(source_id)));
            let accepted = ok(accept_as(&w, &second, &AcceptPolicy::new(), &store));
            let record = ok(ok(store.migration(source_id)).ok_or(()));
            assert_eq!(record.dest_file_id(), accepted.context().file_id());
        }

        #[test]
        fn file_store_keeps_migrations_and_reads_the_2x_layout() {
            let w = world();
            let first = migrated(&w, "first.aion", AUTHOR, &w.key);
            let second = migrated(&w, "second.aion", AUTHOR, &w.key);
            let state = w.dir.path().join("accepted.json");
            ok(accept_as(
                &w,
                &first,
                &AcceptPolicy::new(),
                &ok(FileStore::create(&state)),
            ));
            let reopened = FileStore::open(&state);
            let source_id = source_chain(&w).context().file_id();
            assert!(ok(reopened.migration(source_id)).is_some());
            assert!(conflict(&accept_as(
                &w,
                &second,
                &AcceptPolicy::new(),
                &reopened
            )));

            let legacy = w.dir.path().join("legacy.json");
            let genesis = hex::encode([7u8; 32]);
            let text = format!(
                r#"{{"42": {{"genesis_hash": "{genesis}", "head_version": 1, "head_hash": "{genesis}"}}}}"#
            );
            ok(std::fs::write(&legacy, text));
            let old = FileStore::open(&legacy);
            assert_eq!(
                ok(old.record(FileId::new(42))).map(|r| r.head_version()),
                Some(1)
            );
            ok(accept_as(&w, &first, &AcceptPolicy::new(), &old));
            assert!(ok(old.record(FileId::new(42))).is_some());
            assert!(ok(old.migration(source_id)).is_some());
        }

        /// A store tracking the source refuses a migration anchored on a
        /// stale copy of it, and writes nothing.
        #[test]
        fn a_stale_source_is_refused_when_the_store_tracks_it() {
            let w = world();
            let stale = w.dir.path().join("stale.aion");
            ok(std::fs::copy(&w.source, &stale));
            commit(&w, &w.source);
            let store = MemoryStore::new();
            ok(accept_file(
                &w.source,
                &w.registry,
                &AcceptPolicy::new(),
                &store,
            ));
            let old = ok(verify_file_chain(&stale, &w.registry));
            let rules = ok(open_current_rules(&old, &RecipientKeys::none()));
            let dest = w.dir.path().join("from-stale.aion");
            let options = InitOptions {
                author_id: AuthorId::new(AUTHOR),
                signing_key: &w.key,
                message: "migrate",
                timestamp: None,
                protection: RulesProtection::Public,
            };
            ok(migrate_file(&old, &rules, &dest, &options, &w.registry));
            let accepted = accept_migration(
                &dest,
                &old,
                &w.registry,
                &AcceptPolicy::new(),
                &MigrationPolicy::SameAuthor,
                &store,
            );
            assert!(matches!(
                accepted,
                Err(AionError::VersionRejected {
                    reason: VersionRejectReason::Replay
                })
            ));
            assert_eq!(ok(store.migration(old.context().file_id())), None);
            let dest_id = ok(verify_file_chain(&dest, &w.registry))
                .context()
                .file_id();
            assert_eq!(ok(store.record(dest_id)), None);
        }

        fn commit(w: &World, path: &Path) {
            let options = CommitOptions {
                author_id: AuthorId::new(AUTHOR),
                signing_key: &w.key,
                message: "next",
                timestamp: None,
                protection: RulesProtection::Public,
            };
            ok(commit_version(path, b"r2", &options, &w.registry));
        }

        mod properties {
            use super::*;
            use hegel::generators as gs;

            /// RFC-0040 store model: per source, the first accepted
            /// destination is recorded; the same one again is idempotent;
            /// any other conflicts until the record is cleared.
            #[hegel::test]
            fn prop_migration_records_follow_a_first_claim_model(tc: hegel::TestCase) {
                let w = world();
                let dests: Vec<PathBuf> = (0..3)
                    .map(|i| migrated(&w, &format!("d{i}.aion"), AUTHOR, &w.key))
                    .collect();
                let ids: Vec<FileId> = dests
                    .iter()
                    .map(|d| ok(verify_file_chain(d, &w.registry)).context().file_id())
                    .collect();
                let source_id = source_chain(&w).context().file_id();
                let store = MemoryStore::new();
                let mut model: Option<usize> = None;
                let steps = tc.draw(gs::integers::<usize>().min_value(1).max_value(8));
                for _ in 0..steps {
                    let op = tc.draw(gs::integers::<usize>().max_value(3));
                    if let Some(dest) = dests.get(op) {
                        let result = accept_as(&w, dest, &AcceptPolicy::new(), &store);
                        match model {
                            None => {
                                assert!(result.is_ok());
                                model = Some(op);
                            }
                            Some(held) if held == op => assert!(result.is_ok()),
                            Some(_) => assert!(conflict(&result)),
                        }
                    } else {
                        assert_eq!(ok(store.clear_migration(source_id)), model.is_some());
                        model = None;
                    }
                    let recorded = ok(store.migration(source_id)).map(|r| r.dest_file_id());
                    assert_eq!(recorded, model.and_then(|i| ids.get(i).copied()));
                }
            }
        }

        /// A store that predates RFC-0040 refuses migrations.
        #[test]
        fn stores_without_migration_support_fail_closed() {
            struct Legacy(MemoryStore);
            impl AcceptedVersionStore for Legacy {
                fn pin(&self, file_id: FileId, genesis_hash: [u8; 32]) -> Result<()> {
                    self.0.pin(file_id, genesis_hash)
                }
                fn check_and_advance(&self, chain: ChainSummary<'_>) -> Result<StoreDecision> {
                    self.0.check_and_advance(chain)
                }
            }
            let w = world();
            let first = migrated(&w, "first.aion", AUTHOR, &w.key);
            let store = Legacy(MemoryStore::new());
            assert!(matches!(
                accept_as(&w, &first, &AcceptPolicy::new(), &store),
                Err(AionError::StoreUnavailable {
                    reason: "migration_unsupported"
                })
            ));
            assert!(store.clear_migration(FileId::new(1)).is_err());
            let dest_id = ok(verify_file_chain(&first, &w.registry))
                .context()
                .file_id();
            assert!(ok(store.0.record(dest_id)).is_none());
        }
    }
}
