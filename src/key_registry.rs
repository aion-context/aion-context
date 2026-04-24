//! Key rotation and revocation registry — RFC-0028.
//!
//! Each author has:
//!
//! - A long-lived **master key** that authorizes epoch changes.
//! - A sequence of **operational key epochs** — the keys that
//!   actually sign versions and attestations.
//!
//! [`KeyRegistry`] holds both and resolves `(author, version_number)`
//! to the epoch that was active at sign time. Verification helpers
//! in [`crate::signature_chain`] use the registry to reject
//! signatures made by rotated-out or revoked keys.
//!
//! This module does not touch the on-disk file format; RFC-0028
//! Phase B covers embedding the registry in `.aion` files.
//!
//! # Example
//!
//! ```
//! use aion_context::crypto::SigningKey;
//! use aion_context::key_registry::{KeyRegistry, sign_rotation_record};
//! use aion_context::types::AuthorId;
//!
//! let author = AuthorId::new(42);
//! let master = SigningKey::generate();
//! let op0 = SigningKey::generate();
//! let op1 = SigningKey::generate();
//!
//! let mut reg = KeyRegistry::new();
//! reg.register_author(author, master.verifying_key(), op0.verifying_key(), 0).unwrap();
//!
//! let rotation = sign_rotation_record(
//!     author,
//!     0, 1,
//!     op1.verifying_key().to_bytes(),
//!     5,
//!     &master,
//! );
//! reg.apply_rotation(&rotation).unwrap();
//!
//! let at_v1 = reg.active_epoch_at(author, 1).unwrap();
//! assert_eq!(at_v1.epoch, 0);
//! let at_v7 = reg.active_epoch_at(author, 7).unwrap();
//! assert_eq!(at_v7.epoch, 1);
//! ```

use std::collections::HashMap;

use crate::crypto::{SigningKey, VerifyingKey};
use crate::types::AuthorId;
use crate::{AionError, Result};

/// Domain separator for rotation-record signatures.
pub(crate) const ROTATION_DOMAIN: &[u8] = b"AION_V2_ROTATION_V1";

/// Domain separator for revocation-record signatures.
pub(crate) const REVOCATION_DOMAIN: &[u8] = b"AION_V2_REVOCATION_V1";

/// Reason code carried in a revocation record.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RevocationReason {
    /// Key material is known or suspected to be compromised.
    Compromised = 1,
    /// Routine rotation; the prior key is not believed compromised.
    Superseded = 2,
    /// Signer leaves the org; no successor epoch.
    Retired = 3,
    /// Reason not recorded at protocol level.
    Unspecified = 255,
}

impl RevocationReason {
    /// Convert a raw `u16` back to a known reason.
    ///
    /// # Errors
    ///
    /// Returns `Err` for discriminants that are not defined by this
    /// enum. Unknown values must not be silently mapped onto
    /// [`Self::Unspecified`] — that would let an attacker forge a
    /// weaker reason.
    pub fn from_u16(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::Compromised),
            2 => Ok(Self::Superseded),
            3 => Ok(Self::Retired),
            255 => Ok(Self::Unspecified),
            other => Err(AionError::InvalidFormat {
                reason: format!("Unknown revocation reason: {other}"),
            }),
        }
    }
}

/// Lifecycle state of a single [`KeyEpoch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    /// The epoch is currently usable.
    Active,
    /// A rotation record has moved authority to `successor_epoch`.
    Rotated {
        /// Next epoch in the sequence.
        successor_epoch: u32,
        /// Version number at which the rotation takes effect.
        effective_from_version: u64,
    },
    /// An explicit revocation record has invalidated this epoch.
    Revoked {
        /// Reason carried by the revocation record.
        reason: RevocationReason,
        /// Version number at which the revocation takes effect.
        effective_from_version: u64,
    },
}

/// One epoch for one author. Epochs are append-only per author.
#[derive(Debug, Clone)]
pub struct KeyEpoch {
    /// Which author this epoch belongs to.
    pub author_id: AuthorId,
    /// Monotonic per-author epoch number, starting at 0.
    pub epoch: u32,
    /// 32-byte Ed25519 verifying key for this epoch.
    pub public_key: [u8; 32],
    /// First version number at which this epoch is valid.
    pub created_at_version: u64,
    /// Current lifecycle state.
    pub status: KeyStatus,
}

impl KeyEpoch {
    /// Return `true` if `version_number` falls within this epoch's
    /// valid window (inclusive lower bound, exclusive upper bound
    /// on the effective-from of the next rotation or revocation).
    #[must_use]
    pub const fn is_valid_for(&self, version_number: u64) -> bool {
        if version_number < self.created_at_version {
            return false;
        }
        match self.status {
            KeyStatus::Active => true,
            KeyStatus::Rotated {
                effective_from_version,
                ..
            }
            | KeyStatus::Revoked {
                effective_from_version,
                ..
            } => version_number < effective_from_version,
        }
    }
}

/// Rotation record — signed by the author's master key.
#[derive(Debug, Clone)]
pub struct KeyRotationRecord {
    /// Author whose epoch sequence is being extended.
    pub author_id: AuthorId,
    /// Currently-active epoch being rotated out.
    pub from_epoch: u32,
    /// New epoch being added (must be `from_epoch + 1`).
    pub to_epoch: u32,
    /// Public key for the new epoch.
    pub to_public_key: [u8; 32],
    /// Version number at which the rotation takes effect.
    pub effective_from_version: u64,
    /// Ed25519 signature by the author's master key over the
    /// canonical rotation message.
    pub master_signature: [u8; 64],
}

/// Revocation record — signed by the author's master key.
#[derive(Debug, Clone)]
pub struct RevocationRecord {
    /// Author whose epoch is being revoked.
    pub author_id: AuthorId,
    /// Epoch being revoked.
    pub revoked_epoch: u32,
    /// Why the epoch is being revoked.
    pub reason: RevocationReason,
    /// Version number at which the revocation takes effect.
    pub effective_from_version: u64,
    /// Ed25519 signature by the author's master key over the
    /// canonical revocation message.
    pub master_signature: [u8; 64],
}

/// Canonical bytes signed by the master key when producing a
/// rotation record.
#[must_use]
#[allow(clippy::arithmetic_side_effects)] // fixed-size add over constants
pub fn canonical_rotation_message(record: &KeyRotationRecord) -> Vec<u8> {
    let mut msg = Vec::with_capacity(ROTATION_DOMAIN.len() + 8 + 4 + 4 + 32 + 8);
    msg.extend_from_slice(ROTATION_DOMAIN);
    msg.extend_from_slice(&record.author_id.as_u64().to_le_bytes());
    msg.extend_from_slice(&record.from_epoch.to_le_bytes());
    msg.extend_from_slice(&record.to_epoch.to_le_bytes());
    msg.extend_from_slice(&record.to_public_key);
    msg.extend_from_slice(&record.effective_from_version.to_le_bytes());
    msg
}

/// Canonical bytes signed by the master key when producing a
/// revocation record.
#[must_use]
#[allow(clippy::arithmetic_side_effects)] // fixed-size add over constants
pub fn canonical_revocation_message(record: &RevocationRecord) -> Vec<u8> {
    let mut msg = Vec::with_capacity(REVOCATION_DOMAIN.len() + 8 + 4 + 2 + 8);
    msg.extend_from_slice(REVOCATION_DOMAIN);
    msg.extend_from_slice(&record.author_id.as_u64().to_le_bytes());
    msg.extend_from_slice(&record.revoked_epoch.to_le_bytes());
    msg.extend_from_slice(&(record.reason as u16).to_le_bytes());
    msg.extend_from_slice(&record.effective_from_version.to_le_bytes());
    msg
}

/// Build a rotation record signed by the supplied master key.
///
/// The caller is responsible for ensuring `to_epoch == from_epoch + 1`
/// and `effective_from_version` is at or after the current active
/// epoch's `created_at_version`; the registry enforces both on
/// [`KeyRegistry::apply_rotation`].
#[must_use]
pub fn sign_rotation_record(
    author: AuthorId,
    from_epoch: u32,
    to_epoch: u32,
    to_public_key: [u8; 32],
    effective_from_version: u64,
    master_key: &SigningKey,
) -> KeyRotationRecord {
    let mut record = KeyRotationRecord {
        author_id: author,
        from_epoch,
        to_epoch,
        to_public_key,
        effective_from_version,
        master_signature: [0u8; 64],
    };
    let message = canonical_rotation_message(&record);
    record.master_signature = master_key.sign(&message);
    record
}

/// Build a revocation record signed by the supplied master key.
#[must_use]
pub fn sign_revocation_record(
    author: AuthorId,
    revoked_epoch: u32,
    reason: RevocationReason,
    effective_from_version: u64,
    master_key: &SigningKey,
) -> RevocationRecord {
    let mut record = RevocationRecord {
        author_id: author,
        revoked_epoch,
        reason,
        effective_from_version,
        master_signature: [0u8; 64],
    };
    let message = canonical_revocation_message(&record);
    record.master_signature = master_key.sign(&message);
    record
}

/// Per-author registry entry — the master key plus the append-only
/// epoch sequence.
#[derive(Debug, Clone)]
struct AuthorRecord {
    master_key: VerifyingKey,
    epochs: Vec<KeyEpoch>,
}

/// Authoritative registry of master keys and operational-key epochs.
#[derive(Debug, Default)]
pub struct KeyRegistry {
    authors: HashMap<AuthorId, AuthorRecord>,
}

impl KeyRegistry {
    /// Construct an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new author with a master key and an initial
    /// operational key (epoch 0).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the author is already registered.
    pub fn register_author(
        &mut self,
        author: AuthorId,
        master_key: VerifyingKey,
        initial_operational_key: VerifyingKey,
        created_at_version: u64,
    ) -> Result<()> {
        if self.authors.contains_key(&author) {
            return Err(AionError::InvalidFormat {
                reason: format!("author {author} already registered"),
            });
        }
        let epoch = KeyEpoch {
            author_id: author,
            epoch: 0,
            public_key: initial_operational_key.to_bytes(),
            created_at_version,
            status: KeyStatus::Active,
        };
        let record = AuthorRecord {
            master_key,
            epochs: vec![epoch],
        };
        self.authors.insert(author, record);
        Ok(())
    }

    /// Apply a rotation record to the registry.
    ///
    /// # Errors
    ///
    /// Returns `Err` if:
    /// - the author is unknown,
    /// - `from_epoch` is not the current active epoch,
    /// - `to_epoch != from_epoch + 1`,
    /// - `effective_from_version` precedes the current active
    ///   epoch's `created_at_version`,
    /// - the master signature does not verify.
    pub fn apply_rotation(&mut self, record: &KeyRotationRecord) -> Result<()> {
        let author_record =
            self.authors
                .get_mut(&record.author_id)
                .ok_or_else(|| AionError::InvalidFormat {
                    reason: format!("author {} not registered", record.author_id),
                })?;
        let active_epoch_number = validate_rotation_preconditions(record, &author_record.epochs)?;
        let message = canonical_rotation_message(record);
        author_record
            .master_key
            .verify(&message, &record.master_signature)?;
        mark_epoch_rotated(
            &mut author_record.epochs,
            active_epoch_number,
            record.to_epoch,
            record.effective_from_version,
        );
        author_record.epochs.push(KeyEpoch {
            author_id: record.author_id,
            epoch: record.to_epoch,
            public_key: record.to_public_key,
            created_at_version: record.effective_from_version,
            status: KeyStatus::Active,
        });
        Ok(())
    }

    /// Apply a revocation record to the registry.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the author / epoch is unknown, the epoch is
    /// already revoked, or the master signature does not verify.
    pub fn apply_revocation(&mut self, record: &RevocationRecord) -> Result<()> {
        let author_record =
            self.authors
                .get_mut(&record.author_id)
                .ok_or_else(|| AionError::InvalidFormat {
                    reason: format!("author {} not registered", record.author_id),
                })?;

        let message = canonical_revocation_message(record);
        author_record
            .master_key
            .verify(&message, &record.master_signature)?;

        let mut updated = false;
        for epoch in &mut author_record.epochs {
            if epoch.epoch != record.revoked_epoch {
                continue;
            }
            if matches!(epoch.status, KeyStatus::Revoked { .. }) {
                return Err(AionError::InvalidFormat {
                    reason: format!(
                        "epoch {} for author {} already revoked",
                        record.revoked_epoch, record.author_id
                    ),
                });
            }
            epoch.status = KeyStatus::Revoked {
                reason: record.reason,
                effective_from_version: record.effective_from_version,
            };
            updated = true;
            break;
        }
        if !updated {
            return Err(AionError::InvalidFormat {
                reason: format!(
                    "epoch {} not found for author {}",
                    record.revoked_epoch, record.author_id
                ),
            });
        }
        Ok(())
    }

    /// Return the operational epoch that was valid for `author` at
    /// `version_number`, or `None` if no epoch covers that version.
    #[must_use]
    pub fn active_epoch_at(&self, author: AuthorId, version_number: u64) -> Option<&KeyEpoch> {
        let record = self.authors.get(&author)?;
        record
            .epochs
            .iter()
            .find(|epoch| epoch.is_valid_for(version_number))
    }

    /// Return the registered master key for `author`, if any.
    #[must_use]
    pub fn master_key(&self, author: AuthorId) -> Option<&VerifyingKey> {
        self.authors.get(&author).map(|record| &record.master_key)
    }

    /// Return every recorded epoch for `author`, in insertion order.
    #[must_use]
    pub fn epochs_for(&self, author: AuthorId) -> &[KeyEpoch] {
        self.authors
            .get(&author)
            .map_or(&[][..], |record| record.epochs.as_slice())
    }

    /// Append an epoch to `author` without verifying a signed
    /// rotation record.
    ///
    /// The caller is asserting that this registry is itself the
    /// trust anchor — e.g. a pinning file the operator brings to
    /// verification. [`Self::apply_rotation`] is the signed-record
    /// path and is the correct choice when the rotation arrives
    /// from an untrusted source (transparency log, network peer).
    ///
    /// The prior active epoch is transitioned to
    /// [`KeyStatus::Rotated`] at `active_from_version`. The new
    /// epoch is inserted with [`KeyStatus::Active`] status.
    ///
    /// # Errors
    ///
    /// Returns `Err` if:
    /// - the author is not registered,
    /// - `epoch` is not strictly greater than every existing epoch
    ///   for this author,
    /// - `active_from_version` is not strictly greater than the
    ///   prior active epoch's `created_at_version`,
    /// - the author currently has no active epoch (i.e. the prior
    ///   epoch is already revoked or rotated).
    pub fn insert_epoch_unchecked(
        &mut self,
        author: AuthorId,
        epoch: u32,
        public_key: [u8; 32],
        active_from_version: u64,
    ) -> Result<()> {
        let record = self
            .authors
            .get_mut(&author)
            .ok_or_else(|| AionError::InvalidFormat {
                reason: format!("author {author} not registered"),
            })?;
        let max_epoch = record.epochs.iter().map(|e| e.epoch).max().unwrap_or(0);
        if epoch <= max_epoch {
            return Err(AionError::InvalidFormat {
                reason: format!(
                    "epoch {epoch} not strictly greater than existing max {max_epoch} for author {author}"
                ),
            });
        }
        let active = find_active_epoch(&record.epochs).ok_or_else(|| AionError::InvalidFormat {
            reason: format!("author {author} has no active epoch to rotate from"),
        })?;
        if active_from_version <= active.created_at_version {
            return Err(AionError::InvalidFormat {
                reason: format!(
                    "active_from_version {active_from_version} does not strictly follow prior epoch at version {}",
                    active.created_at_version
                ),
            });
        }
        let active_epoch_number = active.epoch;
        mark_epoch_rotated(
            &mut record.epochs,
            active_epoch_number,
            epoch,
            active_from_version,
        );
        record.epochs.push(KeyEpoch {
            author_id: author,
            epoch,
            public_key,
            created_at_version: active_from_version,
            status: KeyStatus::Active,
        });
        Ok(())
    }

    /// Mark `epoch` as revoked for `author` without verifying a
    /// signed revocation record.
    ///
    /// See [`Self::insert_epoch_unchecked`] for when this is the
    /// correct path vs. [`Self::apply_revocation`].
    ///
    /// # Errors
    ///
    /// Returns `Err` if the author / epoch is unknown or already
    /// revoked.
    pub fn insert_revocation_unchecked(
        &mut self,
        author: AuthorId,
        epoch: u32,
        reason: RevocationReason,
        effective_from_version: u64,
    ) -> Result<()> {
        let record = self
            .authors
            .get_mut(&author)
            .ok_or_else(|| AionError::InvalidFormat {
                reason: format!("author {author} not registered"),
            })?;
        for existing in &mut record.epochs {
            if existing.epoch != epoch {
                continue;
            }
            if matches!(existing.status, KeyStatus::Revoked { .. }) {
                return Err(AionError::InvalidFormat {
                    reason: format!("epoch {epoch} for author {author} already revoked"),
                });
            }
            existing.status = KeyStatus::Revoked {
                reason,
                effective_from_version,
            };
            return Ok(());
        }
        Err(AionError::InvalidFormat {
            reason: format!("epoch {epoch} not found for author {author}"),
        })
    }

    /// Load a trusted registry from the CLI JSON file format.
    ///
    /// The on-disk shape is:
    ///
    /// ```json
    /// {
    ///   "version": 1,
    ///   "authors": [
    ///     {
    ///       "author_id": 50001,
    ///       "master_key": "<base64-32-bytes>",
    ///       "epochs": [
    ///         { "epoch": 0, "public_key": "<base64-32-bytes>", "active_from_version": 0 }
    ///       ],
    ///       "revocations": []
    ///     }
    ///   ]
    /// }
    /// ```
    ///
    /// This is a *trusted* load: every epoch and revocation is
    /// inserted via the `_unchecked` path. Use it for operator-
    /// supplied pinning files; use [`Self::apply_rotation`] and
    /// [`Self::apply_revocation`] for records that arrived from
    /// an untrusted source.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the JSON is malformed, the format version
    /// is not 1, any base64 field does not decode to exactly 32
    /// bytes, any author appears twice, any epoch number repeats
    /// or is non-monotonic within an author, or any revocation
    /// points at an unknown epoch.
    pub fn from_trusted_json(input: &str) -> Result<Self> {
        let file: TrustedRegistryFile =
            serde_json::from_str(input).map_err(|e| AionError::InvalidFormat {
                reason: format!("registry JSON parse failed: {e}"),
            })?;
        if file.version != 1 {
            return Err(AionError::InvalidFormat {
                reason: format!(
                    "unsupported registry file version: {} (expected 1)",
                    file.version
                ),
            });
        }
        let mut registry = Self::new();
        for author_entry in file.authors {
            registry.load_trusted_author(author_entry)?;
        }
        Ok(registry)
    }

    fn load_trusted_author(&mut self, entry: TrustedAuthorEntry) -> Result<()> {
        let author = AuthorId::new(entry.author_id);
        let master_bytes = decode_registry_key_bytes(&entry.master_key, "master_key")?;
        let master_key = VerifyingKey::from_bytes(&master_bytes)?;
        let first_epoch = entry
            .epochs
            .first()
            .ok_or_else(|| AionError::InvalidFormat {
                reason: format!("author {author} has no epochs"),
            })?;
        let first_pub = decode_registry_key_bytes(&first_epoch.public_key, "public_key")?;
        let first_pub_key = VerifyingKey::from_bytes(&first_pub)?;
        self.register_author(
            author,
            master_key,
            first_pub_key,
            first_epoch.active_from_version,
        )?;
        if first_epoch.epoch != 0 {
            return Err(AionError::InvalidFormat {
                reason: format!(
                    "first epoch for author {author} must be 0, got {}",
                    first_epoch.epoch
                ),
            });
        }
        for subsequent in entry.epochs.iter().skip(1) {
            let pub_bytes = decode_registry_key_bytes(&subsequent.public_key, "public_key")?;
            self.insert_epoch_unchecked(
                author,
                subsequent.epoch,
                pub_bytes,
                subsequent.active_from_version,
            )?;
        }
        for rev in entry.revocations {
            self.insert_revocation_unchecked(
                author,
                rev.epoch,
                rev.reason,
                rev.effective_from_version,
            )?;
        }
        Ok(())
    }

    /// Serialize the registry to the trusted-JSON format parsed by
    /// [`Self::from_trusted_json`]. Authors and epochs are emitted in
    /// stable, sorted order (`author_id` ascending, then epoch
    /// ascending) so output is deterministic.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `serde_json` fails to serialize — which in
    /// practice does not happen with the on-disk shape this method
    /// constructs.
    pub fn to_trusted_json(&self) -> Result<String> {
        let mut authors: Vec<(&AuthorId, &AuthorRecord)> = self.authors.iter().collect();
        authors.sort_by_key(|(id, _)| id.as_u64());
        let mut entries = Vec::with_capacity(authors.len());
        for (author, record) in authors {
            entries.push(serialize_author_entry(*author, record));
        }
        let file = TrustedRegistryFile {
            version: 1,
            authors: entries,
        };
        serde_json::to_string_pretty(&file).map_err(|e| AionError::InvalidFormat {
            reason: format!("registry JSON serialize failed: {e}"),
        })
    }
}

fn serialize_author_entry(author: AuthorId, record: &AuthorRecord) -> TrustedAuthorEntry {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;
    let mut sorted_epochs: Vec<&KeyEpoch> = record.epochs.iter().collect();
    sorted_epochs.sort_by_key(|e| e.epoch);
    let mut epochs = Vec::with_capacity(sorted_epochs.len());
    let mut revocations = Vec::new();
    for epoch in sorted_epochs {
        epochs.push(TrustedEpochEntry {
            epoch: epoch.epoch,
            public_key: engine.encode(epoch.public_key),
            active_from_version: epoch.created_at_version,
        });
        if let KeyStatus::Revoked {
            reason,
            effective_from_version,
        } = epoch.status
        {
            revocations.push(TrustedRevocationEntry {
                epoch: epoch.epoch,
                reason,
                effective_from_version,
            });
        }
    }
    TrustedAuthorEntry {
        author_id: author.as_u64(),
        master_key: engine.encode(record.master_key.to_bytes()),
        epochs,
        revocations,
    }
}

fn decode_registry_key_bytes(encoded: &str, field: &str) -> Result<[u8; 32]> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(encoded))
        .map_err(|e| AionError::InvalidFormat {
            reason: format!("registry {field} base64 decode failed: {e}"),
        })?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| AionError::InvalidFormat {
        reason: format!(
            "registry {field} must decode to exactly 32 bytes (got {})",
            bytes.len()
        ),
    })
}

#[derive(serde::Deserialize, serde::Serialize)]
struct TrustedRegistryFile {
    version: u32,
    authors: Vec<TrustedAuthorEntry>,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct TrustedAuthorEntry {
    author_id: u64,
    master_key: String,
    epochs: Vec<TrustedEpochEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    revocations: Vec<TrustedRevocationEntry>,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct TrustedEpochEntry {
    epoch: u32,
    public_key: String,
    active_from_version: u64,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct TrustedRevocationEntry {
    epoch: u32,
    reason: RevocationReason,
    effective_from_version: u64,
}

fn find_active_epoch(epochs: &[KeyEpoch]) -> Option<&KeyEpoch> {
    epochs
        .iter()
        .find(|epoch| matches!(epoch.status, KeyStatus::Active))
}

/// Validate the structural preconditions on a rotation record
/// against the current epoch list, without mutating state or
/// touching crypto. Returns the epoch number of the currently
/// active epoch (which the caller marks `Rotated` once the
/// master signature has also verified).
fn validate_rotation_preconditions(record: &KeyRotationRecord, epochs: &[KeyEpoch]) -> Result<u32> {
    let current_active = find_active_epoch(epochs).ok_or_else(|| AionError::InvalidFormat {
        reason: format!("author {} has no active epoch", record.author_id),
    })?;
    if current_active.epoch != record.from_epoch {
        return Err(AionError::InvalidFormat {
            reason: format!(
                "rotation from_epoch {} does not match current active epoch {}",
                record.from_epoch, current_active.epoch
            ),
        });
    }
    let expected_to =
        current_active
            .epoch
            .checked_add(1)
            .ok_or_else(|| AionError::InvalidFormat {
                reason: "epoch counter overflow".to_string(),
            })?;
    if record.to_epoch != expected_to {
        return Err(AionError::InvalidFormat {
            reason: format!(
                "rotation to_epoch {} must be {} (from_epoch + 1)",
                record.to_epoch, expected_to
            ),
        });
    }
    if record.effective_from_version < current_active.created_at_version {
        return Err(AionError::InvalidFormat {
            reason: "rotation effective_from_version precedes active epoch".to_string(),
        });
    }
    Ok(current_active.epoch)
}

/// Flip the previously-active epoch into the `Rotated` state. The
/// caller is responsible for pushing the new epoch afterwards.
fn mark_epoch_rotated(
    epochs: &mut [KeyEpoch],
    current_active_epoch_number: u32,
    successor_epoch: u32,
    effective_from_version: u64,
) {
    for epoch in epochs.iter_mut() {
        if epoch.epoch == current_active_epoch_number {
            epoch.status = KeyStatus::Rotated {
                successor_epoch,
                effective_from_version,
            };
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    fn setup() -> (AuthorId, SigningKey, SigningKey, KeyRegistry) {
        let author = AuthorId::new(42);
        let master = SigningKey::generate();
        let op0 = SigningKey::generate();
        let mut reg = KeyRegistry::new();
        reg.register_author(author, master.verifying_key(), op0.verifying_key(), 0)
            .unwrap();
        (author, master, op0, reg)
    }

    #[test]
    fn should_register_and_resolve_initial_epoch() {
        let (author, _, op0, reg) = setup();
        let epoch = reg.active_epoch_at(author, 1).unwrap();
        assert_eq!(epoch.epoch, 0);
        assert_eq!(epoch.public_key, op0.verifying_key().to_bytes());
    }

    #[test]
    fn should_reject_double_registration() {
        let (author, master, op0, mut reg) = setup();
        let result = reg.register_author(author, master.verifying_key(), op0.verifying_key(), 0);
        assert!(result.is_err());
    }

    #[test]
    fn should_apply_rotation_and_track_boundaries() {
        let (author, master, _op0, mut reg) = setup();
        let op1 = SigningKey::generate();
        let rec = sign_rotation_record(author, 0, 1, op1.verifying_key().to_bytes(), 10, &master);
        reg.apply_rotation(&rec).unwrap();

        let at_v1 = reg.active_epoch_at(author, 1).unwrap();
        assert_eq!(at_v1.epoch, 0);
        let at_v10 = reg.active_epoch_at(author, 10).unwrap();
        assert_eq!(at_v10.epoch, 1);
        assert_eq!(at_v10.public_key, op1.verifying_key().to_bytes());
    }

    #[test]
    fn should_reject_rotation_with_wrong_from_epoch() {
        let (author, master, _op0, mut reg) = setup();
        let op1 = SigningKey::generate();
        let rec = sign_rotation_record(
            author,
            5, // wrong: active is 0
            6,
            op1.verifying_key().to_bytes(),
            10,
            &master,
        );
        assert!(reg.apply_rotation(&rec).is_err());
    }

    #[test]
    fn should_reject_rotation_with_wrong_master_signature() {
        let (author, _master, _op0, mut reg) = setup();
        let other_master = SigningKey::generate();
        let op1 = SigningKey::generate();
        let rec = sign_rotation_record(
            author,
            0,
            1,
            op1.verifying_key().to_bytes(),
            10,
            &other_master,
        );
        assert!(reg.apply_rotation(&rec).is_err());
    }

    #[test]
    fn should_apply_revocation_and_invalidate_epoch() {
        let (author, master, _op0, mut reg) = setup();
        let rec = sign_revocation_record(author, 0, RevocationReason::Compromised, 10, &master);
        reg.apply_revocation(&rec).unwrap();

        let at_v1 = reg.active_epoch_at(author, 1).unwrap();
        assert_eq!(at_v1.epoch, 0);
        assert!(reg.active_epoch_at(author, 10).is_none());
    }

    #[test]
    fn should_reject_double_revocation() {
        let (author, master, _op0, mut reg) = setup();
        let rec = sign_revocation_record(author, 0, RevocationReason::Compromised, 10, &master);
        reg.apply_revocation(&rec).unwrap();
        assert!(reg.apply_revocation(&rec).is_err());
    }

    #[test]
    fn should_reject_revocation_of_unknown_epoch() {
        let (author, master, _op0, mut reg) = setup();
        let rec = sign_revocation_record(author, 99, RevocationReason::Retired, 10, &master);
        assert!(reg.apply_revocation(&rec).is_err());
    }

    #[test]
    fn revocation_reason_from_u16_round_trips() {
        assert_eq!(
            RevocationReason::from_u16(1).unwrap(),
            RevocationReason::Compromised
        );
        assert_eq!(
            RevocationReason::from_u16(255).unwrap(),
            RevocationReason::Unspecified
        );
        assert!(RevocationReason::from_u16(7).is_err());
    }

    mod properties {
        use super::*;
        use hegel::generators as gs;

        fn register_author(
            tc: &hegel::TestCase,
        ) -> (AuthorId, SigningKey, SigningKey, KeyRegistry) {
            let author = AuthorId::new(tc.draw(gs::integers::<u64>().min_value(1)));
            let master = SigningKey::generate();
            let op0 = SigningKey::generate();
            let mut reg = KeyRegistry::new();
            reg.register_author(author, master.verifying_key(), op0.verifying_key(), 0)
                .unwrap_or_else(|_| std::process::abort());
            (author, master, op0, reg)
        }

        #[hegel::test]
        fn prop_register_and_verify_active(tc: hegel::TestCase) {
            let (author, _master, op0, reg) = register_author(&tc);
            let v = tc.draw(gs::integers::<u64>().min_value(0).max_value(1 << 40));
            let epoch = reg
                .active_epoch_at(author, v)
                .unwrap_or_else(|| std::process::abort());
            assert_eq!(epoch.epoch, 0);
            assert_eq!(epoch.public_key, op0.verifying_key().to_bytes());
        }

        #[hegel::test]
        fn prop_sig_before_rotation_verifies(tc: hegel::TestCase) {
            let (author, master, _op0, mut reg) = register_author(&tc);
            let op1 = SigningKey::generate();
            let effective = tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 30));
            let rec = sign_rotation_record(
                author,
                0,
                1,
                op1.verifying_key().to_bytes(),
                effective,
                &master,
            );
            reg.apply_rotation(&rec)
                .unwrap_or_else(|_| std::process::abort());
            // any version strictly less than `effective` is still epoch 0
            let v = tc.draw(gs::integers::<u64>().max_value(effective.saturating_sub(1)));
            let epoch = reg
                .active_epoch_at(author, v)
                .unwrap_or_else(|| std::process::abort());
            assert_eq!(epoch.epoch, 0);
        }

        #[hegel::test]
        fn prop_sig_after_rotation_switches_to_new_epoch(tc: hegel::TestCase) {
            let (author, master, _op0, mut reg) = register_author(&tc);
            let op1 = SigningKey::generate();
            let effective = tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 30));
            let rec = sign_rotation_record(
                author,
                0,
                1,
                op1.verifying_key().to_bytes(),
                effective,
                &master,
            );
            reg.apply_rotation(&rec)
                .unwrap_or_else(|_| std::process::abort());
            let v = tc.draw(
                gs::integers::<u64>()
                    .min_value(effective)
                    .max_value(effective.saturating_add(1 << 20)),
            );
            let epoch = reg
                .active_epoch_at(author, v)
                .unwrap_or_else(|| std::process::abort());
            assert_eq!(epoch.epoch, 1);
            assert_eq!(epoch.public_key, op1.verifying_key().to_bytes());
        }

        #[hegel::test]
        fn prop_revocation_rejects_later_sigs(tc: hegel::TestCase) {
            let (author, master, _op0, mut reg) = register_author(&tc);
            let effective = tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 30));
            let rec = sign_revocation_record(
                author,
                0,
                RevocationReason::Compromised,
                effective,
                &master,
            );
            reg.apply_revocation(&rec)
                .unwrap_or_else(|_| std::process::abort());
            // Earlier versions still covered, later versions are not.
            let earlier = tc.draw(gs::integers::<u64>().max_value(effective.saturating_sub(1)));
            assert!(reg.active_epoch_at(author, earlier).is_some());
            let later = tc.draw(
                gs::integers::<u64>()
                    .min_value(effective)
                    .max_value(effective.saturating_add(1 << 20)),
            );
            assert!(reg.active_epoch_at(author, later).is_none());
        }

        #[hegel::test]
        fn prop_rotation_requires_valid_master_sig(tc: hegel::TestCase) {
            let (author, master, _op0, mut reg) = register_author(&tc);
            let op1 = SigningKey::generate();
            let mut rec =
                sign_rotation_record(author, 0, 1, op1.verifying_key().to_bytes(), 5, &master);
            // Flip a byte in the master signature → rejection.
            let idx = tc.draw(gs::integers::<usize>().max_value(rec.master_signature.len() - 1));
            if let Some(b) = rec.master_signature.get_mut(idx) {
                *b ^= 0x01;
            }
            assert!(reg.apply_rotation(&rec).is_err());
        }

        #[hegel::test]
        fn prop_epochs_are_monotonic(tc: hegel::TestCase) {
            let (author, master, _op0, mut reg) = register_author(&tc);
            let n = tc.draw(gs::integers::<u32>().min_value(1).max_value(8));
            let mut effective: u64 = 0;
            for i in 0..n {
                effective = effective
                    .saturating_add(tc.draw(gs::integers::<u64>().min_value(1).max_value(10_000)));
                let new_op = SigningKey::generate();
                let rec = sign_rotation_record(
                    author,
                    i,
                    i.saturating_add(1),
                    new_op.verifying_key().to_bytes(),
                    effective,
                    &master,
                );
                reg.apply_rotation(&rec)
                    .unwrap_or_else(|_| std::process::abort());
            }
            let epochs = reg.epochs_for(author);
            for pair in epochs.windows(2) {
                assert!(pair[1].epoch == pair[0].epoch.saturating_add(1));
                assert!(pair[1].created_at_version >= pair[0].created_at_version);
            }
        }

        #[hegel::test]
        fn prop_multi_hop_rotation_tracks_correctly(tc: hegel::TestCase) {
            // Three-epoch chain: op0 -> op1 at v_a -> op2 at v_b.
            let (author, master, op0, mut reg) = register_author(&tc);
            let op1 = SigningKey::generate();
            let op2 = SigningKey::generate();
            let v_a = tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 20));
            let v_b =
                v_a.saturating_add(tc.draw(gs::integers::<u64>().min_value(1).max_value(1 << 20)));
            let r1 =
                sign_rotation_record(author, 0, 1, op1.verifying_key().to_bytes(), v_a, &master);
            reg.apply_rotation(&r1)
                .unwrap_or_else(|_| std::process::abort());
            let r2 =
                sign_rotation_record(author, 1, 2, op2.verifying_key().to_bytes(), v_b, &master);
            reg.apply_rotation(&r2)
                .unwrap_or_else(|_| std::process::abort());

            // Probe three windows.
            let in_first = tc.draw(gs::integers::<u64>().max_value(v_a.saturating_sub(1)));
            assert_eq!(
                reg.active_epoch_at(author, in_first)
                    .unwrap_or_else(|| std::process::abort())
                    .public_key,
                op0.verifying_key().to_bytes()
            );
            let in_second = tc.draw(
                gs::integers::<u64>()
                    .min_value(v_a)
                    .max_value(v_b.saturating_sub(1)),
            );
            assert_eq!(
                reg.active_epoch_at(author, in_second)
                    .unwrap_or_else(|| std::process::abort())
                    .public_key,
                op1.verifying_key().to_bytes()
            );
            let in_third = tc.draw(
                gs::integers::<u64>()
                    .min_value(v_b)
                    .max_value(v_b.saturating_add(1 << 20)),
            );
            assert_eq!(
                reg.active_epoch_at(author, in_third)
                    .unwrap_or_else(|| std::process::abort())
                    .public_key,
                op2.verifying_key().to_bytes()
            );
        }

        #[hegel::test]
        fn prop_unknown_author_returns_none(tc: hegel::TestCase) {
            let reg = KeyRegistry::new();
            let author = AuthorId::new(tc.draw(gs::integers::<u64>()));
            let v = tc.draw(gs::integers::<u64>());
            assert!(reg.active_epoch_at(author, v).is_none());
        }

        #[hegel::test]
        fn prop_tampered_revocation_rejected(tc: hegel::TestCase) {
            let (author, master, _op0, mut reg) = register_author(&tc);
            let mut rec =
                sign_revocation_record(author, 0, RevocationReason::Superseded, 10, &master);
            // Tamper the effective_from_version after signing.
            rec.effective_from_version = rec
                .effective_from_version
                .checked_add(1)
                .unwrap_or_else(|| std::process::abort());
            assert!(reg.apply_revocation(&rec).is_err());
        }
    }

    mod trusted_json {
        use super::*;
        use base64::Engine;

        fn b64(bytes: &[u8; 32]) -> String {
            base64::engine::general_purpose::STANDARD.encode(bytes)
        }

        #[test]
        fn loads_single_author_single_epoch() {
            let master = SigningKey::generate();
            let op = SigningKey::generate();
            let json = format!(
                r#"{{"version":1,"authors":[{{
                    "author_id": 7,
                    "master_key": "{}",
                    "epochs": [{{"epoch":0,"public_key":"{}","active_from_version":0}}]
                }}]}}"#,
                b64(&master.verifying_key().to_bytes()),
                b64(&op.verifying_key().to_bytes()),
            );
            let reg =
                KeyRegistry::from_trusted_json(&json).unwrap_or_else(|_| std::process::abort());
            let author = AuthorId::new(7);
            let epoch = reg
                .active_epoch_at(author, 42)
                .unwrap_or_else(|| std::process::abort());
            assert_eq!(epoch.epoch, 0);
            assert_eq!(epoch.public_key, op.verifying_key().to_bytes());
        }

        #[test]
        fn loads_multi_epoch_with_revocation() {
            let master = SigningKey::generate();
            let op0 = SigningKey::generate();
            let op1 = SigningKey::generate();
            let json = format!(
                r#"{{"version":1,"authors":[{{
                    "author_id": 11,
                    "master_key": "{}",
                    "epochs": [
                        {{"epoch":0,"public_key":"{}","active_from_version":0}},
                        {{"epoch":1,"public_key":"{}","active_from_version":100}}
                    ],
                    "revocations": [
                        {{"epoch":1,"reason":"Compromised","effective_from_version":200}}
                    ]
                }}]}}"#,
                b64(&master.verifying_key().to_bytes()),
                b64(&op0.verifying_key().to_bytes()),
                b64(&op1.verifying_key().to_bytes()),
            );
            let reg =
                KeyRegistry::from_trusted_json(&json).unwrap_or_else(|_| std::process::abort());
            let author = AuthorId::new(11);
            assert_eq!(
                reg.active_epoch_at(author, 50)
                    .unwrap_or_else(|| std::process::abort())
                    .epoch,
                0
            );
            assert_eq!(
                reg.active_epoch_at(author, 150)
                    .unwrap_or_else(|| std::process::abort())
                    .epoch,
                1
            );
            assert!(reg.active_epoch_at(author, 300).is_none());
        }

        #[test]
        fn rejects_unsupported_version() {
            let err = KeyRegistry::from_trusted_json(r#"{"version":2,"authors":[]}"#);
            assert!(err.is_err());
        }

        #[test]
        fn rejects_malformed_base64() {
            let json = r#"{"version":1,"authors":[{
                "author_id": 1,
                "master_key": "not-base64!!!",
                "epochs": [{"epoch":0,"public_key":"also-bad","active_from_version":0}]
            }]}"#;
            assert!(KeyRegistry::from_trusted_json(json).is_err());
        }

        #[test]
        fn rejects_wrong_length_key() {
            use base64::engine::general_purpose::STANDARD;
            let short = STANDARD.encode([0u8; 16]);
            let json = format!(
                r#"{{"version":1,"authors":[{{
                    "author_id": 1,
                    "master_key": "{short}",
                    "epochs": [{{"epoch":0,"public_key":"{short}","active_from_version":0}}]
                }}]}}"#
            );
            assert!(KeyRegistry::from_trusted_json(&json).is_err());
        }
    }
}
