// SPDX-License-Identifier: MIT OR Apache-2.0
//! Migration links between files (RFC-0040, RFC-0039 Phase C2).
//!
//! `aion migrate` writes a new format-v4 file whose genesis audit entry is
//! [`crate::audit::ActionCode::MigratedFrom`], with a [`MigrationLink`] as
//! its details text. The genesis metadata commitment covers that entry, so
//! the link is signed by the migrating author.
//!
//! A link is the migrating author's signed claim that the new file
//! continues the source file as of the source's head version. It is not a
//! proof that the rules are the same, and the new file imports no history.
//! [`verify_migration`] checks the link against a verified source chain
//! and a mandatory [`MigrationPolicy`] that says who may migrate it.
//!
//! # Example
//!
//! ```no_run
//! use aion_context::chain::verify_file_chain;
//! use aion_context::key_registry::KeyRegistry;
//! use aion_context::migration::{verify_migration, MigrationPolicy};
//! use std::path::Path;
//!
//! # fn example(registry: &KeyRegistry) -> aion_context::Result<()> {
//! let migrated = verify_file_chain(Path::new("policy-v4.aion"), registry)?;
//! let original = verify_file_chain(Path::new("policy.aion"), registry)?;
//! let link = verify_migration(&migrated, &original, &MigrationPolicy::SameAuthor)?;
//! println!("continues version {}", link.source_head_version().as_u64());
//! # Ok(())
//! # }
//! ```

use crate::chain::VerifiedChain;
use crate::format::FormatVersion;
use crate::types::{AuthorId, FileId, VersionNumber};
use crate::{AionError, Result};

const LINK_TAG: &str = "aion-migrated-from";

/// What a migrated file's genesis claims to continue: the source file's
/// format, `file_id`, head version, and head version hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationLink {
    format: FormatVersion,
    file_id: FileId,
    head_version: VersionNumber,
    head_hash: [u8; 32],
}

impl MigrationLink {
    /// The link a file migrated from `source` carries.
    #[must_use]
    pub const fn of(source: &VerifiedChain) -> Self {
        Self {
            format: source.context().format(),
            file_id: source.context().file_id(),
            head_version: source.head().version(),
            head_hash: source.head().version_hash(),
        }
    }

    /// The source file's format.
    #[must_use]
    pub const fn source_format(&self) -> FormatVersion {
        self.format
    }

    /// The source file's `file_id`.
    #[must_use]
    pub const fn source_file_id(&self) -> FileId {
        self.file_id
    }

    /// The source head version the new file continues.
    #[must_use]
    pub const fn source_head_version(&self) -> VersionNumber {
        self.head_version
    }

    /// The source head's version hash.
    #[must_use]
    pub const fn source_head_hash(&self) -> [u8; 32] {
        self.head_hash
    }

    /// The canonical details text:
    /// `aion-migrated-from:v<format>:<file_id hex>:<version>:<hash hex>`.
    ///
    /// # Example
    ///
    /// ```
    /// use aion_context::migration::MigrationLink;
    ///
    /// let text = format!("aion-migrated-from:v3:{:016x}:7:{}", 0xABCDu64, "ab".repeat(32));
    /// let link = MigrationLink::parse(&text)?;
    /// assert_eq!(link.to_details(), text);
    /// # Ok::<(), aion_context::AionError>(())
    /// ```
    #[must_use]
    pub fn to_details(&self) -> String {
        format!(
            "{LINK_TAG}:v{}:{:016x}:{}:{}",
            self.format.as_u16(),
            self.file_id.as_u64(),
            self.head_version.as_u64(),
            hex::encode(self.head_hash)
        )
    }

    /// Parse details text strictly: exactly five fields, lowercase hex of
    /// the exact width, a canonical decimal version of at least 1, and
    /// nothing else.
    ///
    /// # Errors
    ///
    /// Returns [`AionError::MigrationRejected`] (`link_malformed`) for any
    /// other text.
    pub fn parse(text: &str) -> Result<Self> {
        let fields: Vec<&str> = text.split(':').collect();
        let [tag, format, file_id, version, hash] = fields.as_slice() else {
            return Err(malformed());
        };
        if *tag != LINK_TAG {
            return Err(malformed());
        }
        let source_format = match *format {
            "v2" => FormatVersion::V2,
            "v3" => FormatVersion::V3,
            "v4" => FormatVersion::V4,
            _ => return Err(malformed()),
        };
        let file_id = u64::from_be_bytes(lower_hex::<8>(file_id)?);
        Ok(Self {
            format: source_format,
            file_id: FileId::new(file_id),
            head_version: VersionNumber(canonical_version(version)?),
            head_hash: lower_hex::<32>(hash)?,
        })
    }
}

fn lower_hex<const N: usize>(text: &str) -> Result<[u8; N]> {
    let lowercase = text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !lowercase || text.len() != N.saturating_mul(2) {
        return Err(malformed());
    }
    let bytes = hex::decode(text).map_err(|_| malformed())?;
    bytes.try_into().map_err(|_| malformed())
}

fn canonical_version(text: &str) -> Result<u64> {
    let digits = !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    let version = if digits {
        text.parse::<u64>().map_err(|_| malformed())?
    } else {
        return Err(malformed());
    };
    if version == 0 || version.to_string() != text {
        return Err(malformed());
    }
    Ok(version)
}

const fn malformed() -> AionError {
    rejected("link_malformed")
}

const fn rejected(reason: &'static str) -> AionError {
    AionError::MigrationRejected { reason }
}

/// A non-empty set of authors, for [`MigrationPolicy::AnyOf`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorSet(Vec<AuthorId>);

impl AuthorSet {
    /// Build a set.
    ///
    /// # Errors
    ///
    /// Returns [`AionError::MigrationRejected`] (`empty_author_set`) if
    /// `authors` is empty: a policy no author can satisfy is a mistake.
    pub fn new(authors: Vec<AuthorId>) -> Result<Self> {
        if authors.is_empty() {
            return Err(rejected("empty_author_set"));
        }
        Ok(Self(authors))
    }

    /// Whether `author` is in the set.
    #[must_use]
    pub fn contains(&self, author: AuthorId) -> bool {
        self.0.contains(&author)
    }

    /// The authors, in the order given.
    #[must_use]
    pub fn as_slice(&self) -> &[AuthorId] {
        &self.0
    }
}

/// Who may migrate a file. There is no default: every caller of
/// [`verify_migration`] states one.
///
/// That the migrating author is pinned in the registry follows from the
/// destination having been verified with it; the policy only names who.
///
/// Not `#[non_exhaustive]`: callers match on it, and a new kind of policy
/// would be an RFC change and a major version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationPolicy {
    /// The migrating author authored the source's head version.
    SameAuthor,
    /// The migrating author is exactly this author.
    Author(AuthorId),
    /// The migrating author is one of these.
    AnyOf(AuthorSet),
}

impl MigrationPolicy {
    fn admits(&self, migrating: AuthorId, source_head_author: AuthorId) -> bool {
        match self {
            Self::SameAuthor => migrating == source_head_author,
            Self::Author(author) => migrating == *author,
            Self::AnyOf(authors) => authors.contains(migrating),
        }
    }
}

/// Check that `dest` is a migration of `source` that `policy` allows.
///
/// Both chains must already be verified. The link in `dest`'s genesis must
/// name `source`'s format, `file_id`, head version and head version hash
/// exactly, and the author who signed `dest`'s genesis must satisfy
/// `policy`. This does not compare rules: a migrating author may change
/// them.
///
/// # Errors
///
/// Returns [`AionError::MigrationRejected`] with `not_migrated`,
/// `self_migration` (both chains share a `file_id`), `link_malformed`,
/// `source_mismatch`, or `policy_unmet`.
///
/// # Example
///
/// ```no_run
/// use aion_context::chain::verify_file_chain;
/// use aion_context::key_registry::KeyRegistry;
/// use aion_context::migration::{verify_migration, MigrationPolicy};
/// use aion_context::types::AuthorId;
/// use std::path::Path;
///
/// # fn example(registry: &KeyRegistry) -> aion_context::Result<()> {
/// let migrated = verify_file_chain(Path::new("policy-v4.aion"), registry)?;
/// let original = verify_file_chain(Path::new("policy.aion"), registry)?;
/// let policy = MigrationPolicy::Author(AuthorId::new(42));
/// verify_migration(&migrated, &original, &policy)?;
/// # Ok(())
/// # }
/// ```
pub fn verify_migration(
    dest: &VerifiedChain,
    source: &VerifiedChain,
    policy: &MigrationPolicy,
) -> Result<MigrationLink> {
    let outcome = check_migration(dest, source, policy);
    let short = |chain: &VerifiedChain| {
        crate::obs::short_hex(&chain.context().file_id().as_u64().to_le_bytes())
    };
    let (file_id, source_file_id) = (short(dest), short(source));
    let author = dest
        .entry(VersionNumber::GENESIS)
        .map_or_else(String::new, |genesis| {
            crate::obs::author_short(genesis.author())
        });
    let reason = match &outcome {
        Ok(_) => {
            tracing::info!(
                event = "migration_verified",
                file_id = %file_id,
                source_file_id = %source_file_id,
                author = %author,
                source_version = source.head().version().as_u64(),
            );
            return outcome;
        }
        Err(AionError::MigrationRejected { reason }) => *reason,
        Err(_) => "error",
    };
    tracing::warn!(
        event = "migration_rejected",
        file_id = %file_id,
        source_file_id = %source_file_id,
        author = %author,
        reason,
    );
    outcome
}

fn check_migration(
    dest: &VerifiedChain,
    source: &VerifiedChain,
    policy: &MigrationPolicy,
) -> Result<MigrationLink> {
    let details = dest.migration_details().ok_or(rejected("not_migrated"))?;
    if dest.context().file_id() == source.context().file_id() {
        return Err(rejected("self_migration"));
    }
    let link = MigrationLink::parse(details)?;
    if link != MigrationLink::of(source) {
        return Err(rejected("source_mismatch"));
    }
    let genesis = dest
        .entry(VersionNumber::GENESIS)
        .ok_or(rejected("not_migrated"))?;
    if !policy.admits(genesis.author(), source.head().author()) {
        return Err(rejected("policy_unmet"));
    }
    Ok(link)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::chain::{open_current_rules, RecipientKeys};
    use crate::crypto::SigningKey;
    use crate::format::RulesProtection;
    use crate::key_registry::KeyRegistry;
    use crate::operations::{
        commit_version, init_file, migrate_file, verify_file, CommitOptions, InitOptions,
    };
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    fn ok<T, E>(result: std::result::Result<T, E>) -> T {
        result.unwrap_or_else(|_| std::process::abort())
    }

    struct Signer {
        author: AuthorId,
        key: SigningKey,
    }

    struct World {
        dir: TempDir,
        registry: KeyRegistry,
        alice: Signer,
        bob: Signer,
    }

    fn signer(registry: &mut KeyRegistry, id: u64) -> Signer {
        let key = ok(SigningKey::generate());
        let master = ok(SigningKey::generate());
        let author = AuthorId::new(id);
        ok(registry.register_author(author, master.verifying_key(), key.verifying_key(), 0));
        Signer { author, key }
    }

    fn world() -> World {
        let mut registry = KeyRegistry::new();
        let alice = signer(&mut registry, 60_001);
        let bob = signer(&mut registry, 60_002);
        World {
            dir: ok(TempDir::new()),
            registry,
            alice,
            bob,
        }
    }

    fn init_options<'a>(who: &'a Signer, message: &'a str) -> InitOptions<'a> {
        InitOptions {
            author_id: who.author,
            signing_key: &who.key,
            message,
            timestamp: None,
            protection: RulesProtection::Public,
        }
    }

    fn source(world: &World, name: &str) -> PathBuf {
        let path = world.dir.path().join(name);
        ok(init_file(
            &path,
            b"limit: 1",
            &init_options(&world.alice, "genesis"),
        ));
        let commit = CommitOptions {
            author_id: world.alice.author,
            signing_key: &world.alice.key,
            message: "raise",
            timestamp: None,
            protection: RulesProtection::Public,
        };
        ok(commit_version(&path, b"limit: 2", &commit, &world.registry));
        path
    }

    fn chain(world: &World, path: &Path) -> VerifiedChain {
        ok(crate::chain::verify_file_chain(path, &world.registry))
    }

    fn migrate(world: &World, from: &Path, name: &str, who: &Signer) -> PathBuf {
        let original = chain(world, from);
        let rules = ok(open_current_rules(&original, &RecipientKeys::none()));
        let dest = world.dir.path().join(name);
        ok(migrate_file(
            &original,
            &rules,
            &dest,
            &init_options(who, "migrate"),
            &world.registry,
        ));
        dest
    }

    #[test]
    fn a_migrated_file_verifies_and_links_to_its_source_head() {
        let world = world();
        let from = source(&world, "a.aion");
        let to = migrate(&world, &from, "b.aion", &world.alice);
        assert!(ok(verify_file(&to, &world.registry)).is_valid);
        let (dest, original) = (chain(&world, &to), chain(&world, &from));
        assert_ne!(dest.context().file_id(), original.context().file_id());
        assert_eq!(dest.version_count(), 1);
        let link = ok(verify_migration(
            &dest,
            &original,
            &MigrationPolicy::SameAuthor,
        ));
        assert_eq!(link, MigrationLink::of(&original));
        assert_eq!(link.source_head_version(), VersionNumber(2));
        let rules = ok(open_current_rules(&dest, &RecipientKeys::none()));
        assert_eq!(rules.as_slice(), b"limit: 2");
    }

    #[test]
    fn policies_admit_exactly_the_named_authors() {
        let world = world();
        let from = source(&world, "a.aion");
        let to = migrate(&world, &from, "b.aion", &world.bob);
        let (dest, original) = (chain(&world, &to), chain(&world, &from));
        let verdict = |policy: &MigrationPolicy| verify_migration(&dest, &original, policy);
        let unmet = |policy: &MigrationPolicy| {
            matches!(
                verdict(policy),
                Err(AionError::MigrationRejected {
                    reason: "policy_unmet"
                })
            )
        };
        assert!(unmet(&MigrationPolicy::SameAuthor));
        assert!(unmet(&MigrationPolicy::Author(world.alice.author)));
        assert!(verdict(&MigrationPolicy::Author(world.bob.author)).is_ok());
        let both = MigrationPolicy::AnyOf(ok(AuthorSet::new(vec![
            world.alice.author,
            world.bob.author,
        ])));
        assert!(verdict(&both).is_ok());
        let alice_only = MigrationPolicy::AnyOf(ok(AuthorSet::new(vec![world.alice.author])));
        assert!(unmet(&alice_only));
        assert!(matches!(
            AuthorSet::new(Vec::new()),
            Err(AionError::MigrationRejected {
                reason: "empty_author_set"
            })
        ));
    }

    #[test]
    fn a_link_matches_only_its_own_source_as_of_its_head() {
        let world = world();
        let from = source(&world, "a.aion");
        let other = source(&world, "c.aion");
        let to = migrate(&world, &from, "b.aion", &world.alice);
        let dest = chain(&world, &to);
        let mismatch = |source: &VerifiedChain| {
            matches!(
                verify_migration(&dest, source, &MigrationPolicy::SameAuthor),
                Err(AionError::MigrationRejected {
                    reason: "source_mismatch"
                })
            )
        };
        assert!(mismatch(&chain(&world, &other)));
        let commit = CommitOptions {
            author_id: world.alice.author,
            signing_key: &world.alice.key,
            message: "after migration",
            timestamp: None,
            protection: RulesProtection::Public,
        };
        ok(commit_version(&from, b"limit: 3", &commit, &world.registry));
        assert!(mismatch(&chain(&world, &from)));
    }

    #[test]
    fn an_unmigrated_file_is_not_a_migration() {
        let world = world();
        let from = source(&world, "a.aion");
        let plain = source(&world, "c.aion");
        let verdict = verify_migration(
            &chain(&world, &plain),
            &chain(&world, &from),
            &MigrationPolicy::SameAuthor,
        );
        assert!(matches!(
            verdict,
            Err(AionError::MigrationRejected {
                reason: "not_migrated"
            })
        ));
    }

    /// The link text is signed: editing it, with every unkeyed hash
    /// recomputed, fails verification of the migrated file.
    #[test]
    fn a_rewritten_link_fails_verification() {
        let world = world();
        let from = source(&world, "a.aion");
        let other = source(&world, "c.aion");
        let to = migrate(&world, &from, "b.aion", &world.alice);
        let mut bytes = ok(std::fs::read(&to));
        let real = MigrationLink::of(&chain(&world, &from)).to_details();
        let forged = MigrationLink::of(&chain(&world, &other)).to_details();
        let at = ok(bytes
            .windows(real.len())
            .position(|w| w == real.as_bytes())
            .ok_or(()));
        bytes[at..at + forged.len()].copy_from_slice(forged.as_bytes());
        let body = bytes.len() - 32;
        let integrity = crate::crypto::hash(&bytes[..body]);
        bytes[body..].copy_from_slice(&integrity);
        ok(std::fs::write(&to, &bytes));
        assert!(!ok(verify_file(&to, &world.registry)).is_valid);
    }

    #[test]
    fn an_unpinned_migrating_key_writes_nothing() {
        let world = world();
        let from = source(&world, "a.aion");
        let original = chain(&world, &from);
        let rules = ok(open_current_rules(&original, &RecipientKeys::none()));
        let dest = world.dir.path().join("b.aion");
        let impostor = Signer {
            author: world.alice.author,
            key: ok(SigningKey::generate()),
        };
        let written = migrate_file(
            &original,
            &rules,
            &dest,
            &init_options(&impostor, "migrate"),
            &world.registry,
        );
        assert!(matches!(written, Err(AionError::KeyMismatch { .. })));
        assert!(!dest.exists());
    }

    #[test]
    fn a_migrated_file_can_be_migrated_again() {
        let world = world();
        let first = source(&world, "a.aion");
        let second = migrate(&world, &first, "b.aion", &world.alice);
        let third = migrate(&world, &second, "c.aion", &world.alice);
        let link = ok(verify_migration(
            &chain(&world, &third),
            &chain(&world, &second),
            &MigrationPolicy::SameAuthor,
        ));
        assert_eq!(link.source_format(), FormatVersion::V4);
        assert_eq!(link.source_head_version(), VersionNumber::GENESIS);
    }

    #[test]
    fn a_v3_file_migrates_to_v4() {
        use crate::format::RulesMode;
        use crate::operations::tests::format_v3_read_tests::{build_v3_file, v3_context};
        let mut world = world();
        let carol = signer(&mut world.registry, 60_003);
        let bytes = build_v3_file(
            &[(b"a", RulesMode::Public), (b"b", RulesMode::Public)],
            v3_context(),
            &carol.key,
            carol.author,
        );
        let from = world.dir.path().join("v3.aion");
        ok(std::fs::write(&from, bytes));
        let to = migrate(&world, &from, "v4.aion", &carol);
        let (dest, original) = (chain(&world, &to), chain(&world, &from));
        assert!(!original.metadata_signed());
        assert!(dest.metadata_signed());
        let link = ok(verify_migration(
            &dest,
            &original,
            &MigrationPolicy::SameAuthor,
        ));
        assert_eq!(link.source_format(), FormatVersion::V3);
        assert_eq!(
            ok(open_current_rules(&dest, &RecipientKeys::none())).as_slice(),
            b"b"
        );
    }

    #[test]
    fn details_text_matches_golden_layout() {
        let link = MigrationLink {
            format: FormatVersion::V3,
            file_id: FileId::new(0x00AB_CDEF_0123_4567),
            head_version: VersionNumber(12),
            head_hash: [0xC4; 32],
        };
        let expected = format!(
            "aion-migrated-from:v3:00abcdef01234567:12:{}",
            "c4".repeat(32)
        );
        assert_eq!(link.to_details(), expected);
        assert_eq!(ok(MigrationLink::parse(&expected)), link);
    }

    #[test]
    fn non_canonical_link_text_is_rejected() {
        let hash = "c4".repeat(32);
        let id = "00abcdef01234567";
        let bad = [
            format!("aion-migrated-from:v3:{}:12:{hash}", id.to_uppercase()),
            format!("aion-migrated-from:v3:{id}:012:{hash}"),
            format!("aion-migrated-from:v3:{id}:0:{hash}"),
            format!("aion-migrated-from:v3:{id}:+12:{hash}"),
            format!("aion-migrated-from:v3:{id}:12:{hash}:"),
            format!("aion-migrated-from:v3:{id}:12:{hash}0"),
            format!("aion-migrated-from:v5:{id}:12:{hash}"),
            format!("aion-migrated-from:V3:{id}:12:{hash}"),
            format!("aion-migrated-from:v3:abcdef01234567:12:{hash}"),
            format!("aion-migrated-from:v3:{id}:18446744073709551616:{hash}"),
            format!("aion-migrated-to:v3:{id}:12:{hash}"),
            format!(" aion-migrated-from:v3:{id}:12:{hash}"),
            String::new(),
        ];
        for text in &bad {
            assert!(
                matches!(
                    MigrationLink::parse(text),
                    Err(AionError::MigrationRejected {
                        reason: "link_malformed"
                    })
                ),
                "{text}"
            );
        }
    }

    mod properties {
        use super::*;
        use hegel::generators as gs;

        fn draw_link(tc: &hegel::TestCase) -> MigrationLink {
            let format = match tc.draw(gs::integers::<u8>().max_value(2)) {
                0 => FormatVersion::V2,
                1 => FormatVersion::V3,
                _ => FormatVersion::V4,
            };
            let hash: Vec<u8> = tc.draw(gs::binary().min_size(32).max_size(32));
            MigrationLink {
                format,
                file_id: FileId::new(tc.draw(gs::integers::<u64>())),
                head_version: VersionNumber(tc.draw(gs::integers::<u64>().min_value(1))),
                head_hash: ok(<[u8; 32]>::try_from(hash.as_slice())),
            }
        }

        /// `verify_migration` admits exactly the authors each policy names,
        /// and only against the true source.
        #[hegel::test]
        fn prop_policies_admit_exactly_their_authors(tc: hegel::TestCase) {
            let mut world = world();
            let carol = signer(&mut world.registry, 60_003);
            let signers = [&world.alice, &world.bob, &carol];
            let migrating = tc.draw(gs::integers::<usize>().max_value(2));
            let from = source(&world, "a.aion");
            let other = source(&world, "c.aion");
            let to = migrate(&world, &from, "b.aion", signers[migrating]);
            let named: Vec<usize> = tc.draw(
                gs::vecs(gs::integers::<usize>().max_value(2))
                    .min_size(1)
                    .max_size(3),
            );
            let authors: Vec<AuthorId> = named.iter().map(|&i| signers[i].author).collect();
            let (policy, admitted) = match tc.draw(gs::integers::<u8>().max_value(2)) {
                0 => (MigrationPolicy::SameAuthor, migrating == 0),
                1 => (MigrationPolicy::Author(authors[0]), named[0] == migrating),
                _ => (
                    MigrationPolicy::AnyOf(ok(AuthorSet::new(authors))),
                    named.contains(&migrating),
                ),
            };
            let true_source = tc.draw(gs::booleans());
            let claimed = chain(&world, if true_source { &from } else { &other });
            let verdict = verify_migration(&chain(&world, &to), &claimed, &policy);
            let expected = match (true_source, admitted) {
                (false, _) => Some("source_mismatch"),
                (true, false) => Some("policy_unmet"),
                (true, true) => None,
            };
            match (verdict, expected) {
                (Ok(_), None) => {}
                (Err(AionError::MigrationRejected { reason }), Some(want)) => {
                    assert_eq!(reason, want);
                }
                _ => std::process::abort(),
            }
        }

        #[hegel::test]
        fn prop_link_details_round_trip(tc: hegel::TestCase) {
            let link = draw_link(&tc);
            assert_eq!(ok(MigrationLink::parse(&link.to_details())), link);
        }

        fn draw_from(tc: &hegel::TestCase, alphabet: &[u8], min: usize, max: usize) -> String {
            let last = alphabet.len().saturating_sub(1);
            let picks: Vec<usize> = tc.draw(
                gs::vecs(gs::integers::<usize>().max_value(last))
                    .min_size(min)
                    .max_size(max),
            );
            picks.iter().map(|&i| char::from(alphabet[i])).collect()
        }

        /// A valid link with exactly one field replaced by a near miss: a
        /// wrong tag or format, hex with one case flip or one character
        /// more or less, or a short signed or zero-padded version. Whatever
        /// parses must be the canonical spelling of its link, and some
        /// near misses (another valid version) do parse.
        #[hegel::test]
        fn prop_near_miss_fields_parse_only_when_canonical(tc: hegel::TestCase) {
            let canonical = draw_link(&tc).to_details();
            let mut fields: Vec<String> = canonical.split(':').map(str::to_string).collect();
            let field = tc.draw(gs::integers::<usize>().max_value(fields.len().saturating_sub(1)));
            fields[field] = match field {
                0 => [
                    "aion-migrated-to",
                    "AION-MIGRATED-FROM",
                    "aion-migrated-from ",
                ][tc.draw(gs::integers::<usize>().max_value(2))]
                .to_string(),
                1 => ["v0", "v5", "V3", "3", "v03", "v2", "v4"]
                    [tc.draw(gs::integers::<usize>().max_value(6))]
                .to_string(),
                3 => draw_from(&tc, b"0123456789+-", 0, 4),
                _ => near_miss_hex(&tc, &fields[field]),
            };
            let text = fields.join(":");
            if let Ok(parsed) = MigrationLink::parse(&text) {
                assert_eq!(parsed.to_details(), text);
            }
        }

        fn near_miss_hex(tc: &hegel::TestCase, hex: &str) -> String {
            let mut chars: Vec<char> = hex.chars().collect();
            let at = tc.draw(gs::integers::<usize>().max_value(chars.len().saturating_sub(1)));
            match tc.draw(gs::integers::<u8>().max_value(2)) {
                0 => chars[at] = chars[at].to_ascii_uppercase(),
                1 => {
                    chars.remove(at);
                }
                _ => chars.insert(at, '0'),
            }
            chars.into_iter().collect()
        }

        /// Text that parses is the canonical text of what it parses to, so
        /// one link has exactly one accepted spelling.
        #[hegel::test]
        fn prop_any_edit_either_fails_or_is_canonical(tc: hegel::TestCase) {
            let mut text = draw_link(&tc).to_details().into_bytes();
            let index = tc.draw(gs::integers::<usize>().max_value(text.len().saturating_sub(1)));
            text[index] = tc.draw(gs::integers::<u8>().min_value(0x20).max_value(0x7E));
            let Ok(text) = String::from_utf8(text) else {
                return;
            };
            if let Ok(parsed) = MigrationLink::parse(&text) {
                assert_eq!(parsed.to_details(), text);
            }
        }
    }
}
