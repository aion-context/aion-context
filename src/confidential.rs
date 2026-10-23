// SPDX-License-Identifier: MIT OR Apache-2.0
//! Confidential-rules key schedule and recipient stanzas (RFC-0039).
//!
//! - A fresh 32-byte DEK per version and per attempt.
//! - `K_enc = HKDF-SHA256(ikm = DEK, salt = ctx, info = "AION_V3_RULES_KEY_V1\0")`
//!   seals the framed rules with ChaCha20-Poly1305 under
//!   `aad = "AION_V3_RULES_AAD_V1\0" ‖ ctx`.
//! - `dek_commitment = BLAKE3::derive_key("aion-context v3 2026-10 dek commitment", DEK)`
//!   binds every stanza to one DEK.
//! - Each recipient gets the DEK sealed with RFC 9180 HPKE base mode,
//!   `info = "AION_V3_DEK_WRAP_V1\0" ‖ ctx` and `aad = dek_commitment`:
//!   DHKEM(X25519) for stanza kind `0x01`, X-Wing for kind `0x03`.
//!
//! `ctx = file_id ‖ author_id ‖ version`, each `u64` little-endian.
//!
//! `hpke` takes an infallible RNG. Encapsulation randomness is therefore
//! drawn first through [`crate::crypto::fill_os_entropy`], so an OS RNG
//! failure is an error rather than a panic, and served to `hpke` from that
//! buffer. If `hpke` consumes anything other than exactly what was drawn,
//! the result is discarded.
//!
//! The public surface is the key material a caller handles:
//! [`EncryptionKem`], [`EncryptionIdentity`], and [`VersionKey`]. Sealing and
//! opening happen through `operations` (writing) and `chain` (reading), so a
//! caller never touches an unverified section.
//!
//! # Example
//!
//! ```
//! use aion_context::confidential::{EncryptionIdentity, EncryptionKem};
//!
//! let auditor = EncryptionIdentity::generate(EncryptionKem::XWing)?;
//! assert_eq!(auditor.public_key().len(), 1216);
//! let recipient = auditor.recipient();
//! assert_eq!(recipient.kem(), Some(EncryptionKem::XWing));
//! # Ok::<(), aion_context::AionError>(())
//! ```

use std::convert::Infallible;

use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::{X25519HkdfSha256, XWing};
use hpke::rand_core::{TryCryptoRng, TryRng};
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::envelope::{encode_envelope, Envelope, StanzaRecipient, STANZA_X25519, STANZA_XWING};
use crate::format::Recipient;
use crate::types::{AuthorId, FileId, VersionNumber};
use crate::{AionError, Result};

/// HKDF `info` for the content key.
const RULES_KEY_INFO: &[u8] = b"AION_V3_RULES_KEY_V1\0";

/// Prefix of the content AEAD's associated data.
const RULES_AAD_DOMAIN: &[u8] = b"AION_V3_RULES_AAD_V1\0";

/// BLAKE3 `derive_key` context for the DEK commitment.
const DEK_COMMITMENT_CONTEXT: &str = "aion-context v3 2026-10 dek commitment";

/// Prefix of the HPKE `info` for DEK wrapping.
const DEK_WRAP_INFO: &[u8] = b"AION_V3_DEK_WRAP_V1\0";

/// Length of `ctx`: `file_id ‖ author_id ‖ version`.
pub(crate) const CTX_LEN: usize = 24;

const NONCE_LEN: usize = 12;
const X25519_PK_LEN: usize = 32;
const XWING_PK_LEN: usize = 1216;

/// The binding context for one version: `file_id ‖ author_id ‖ version`.
pub(crate) const fn binding_context(
    file_id: FileId,
    author: AuthorId,
    version: VersionNumber,
) -> [u8; CTX_LEN] {
    let mut ctx = [0u8; CTX_LEN];
    let (file, rest) = ctx.split_at_mut(8);
    let (author_bytes, version_bytes) = rest.split_at_mut(8);
    file.copy_from_slice(&file_id.as_u64().to_le_bytes());
    author_bytes.copy_from_slice(&author.as_u64().to_le_bytes());
    version_bytes.copy_from_slice(&version.as_u64().to_le_bytes());
    ctx
}

/// A data-encryption key: 32 random bytes for one version's rules.
pub(crate) struct Dek(Zeroizing<[u8; 32]>);

impl Dek {
    /// Draw a fresh DEK from the OS RNG.
    pub(crate) fn generate() -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        crate::crypto::fill_os_entropy(bytes.as_mut())?;
        Ok(Self(bytes))
    }

    /// Wrap known DEK bytes, such as an unwrapped or disclosed DEK.
    pub(crate) const fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    /// The raw DEK bytes.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The BLAKE3 key commitment to this DEK.
    pub(crate) fn commitment(&self) -> [u8; 32] {
        blake3::derive_key(DEK_COMMITMENT_CONTEXT, self.0.as_ref())
    }

    fn content_key(&self, ctx: &[u8; CTX_LEN]) -> Result<Zeroizing<[u8; 32]>> {
        let mut key = Zeroizing::new([0u8; 32]);
        crate::crypto::derive_key(self.0.as_ref(), ctx, RULES_KEY_INFO, key.as_mut())?;
        Ok(key)
    }
}

fn content_aad(ctx: &[u8; CTX_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(RULES_AAD_DOMAIN.len().saturating_add(CTX_LEN));
    aad.extend_from_slice(RULES_AAD_DOMAIN);
    aad.extend_from_slice(ctx);
    aad
}

fn wrap_info(ctx: &[u8; CTX_LEN]) -> Vec<u8> {
    let mut info = Vec::with_capacity(DEK_WRAP_INFO.len().saturating_add(CTX_LEN));
    info.extend_from_slice(DEK_WRAP_INFO);
    info.extend_from_slice(ctx);
    info
}

/// Seal framed rules under the DEK's content key with a fresh nonce.
pub(crate) fn seal_content(
    dek: &Dek,
    ctx: &[u8; CTX_LEN],
    framed: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    let mut nonce = [0u8; NONCE_LEN];
    crate::crypto::fill_os_entropy(&mut nonce)?;
    let ciphertext = seal_content_with_nonce(dek, ctx, &nonce, framed)?;
    Ok((nonce, ciphertext))
}

fn seal_content_with_nonce(
    dek: &Dek,
    ctx: &[u8; CTX_LEN],
    nonce: &[u8; NONCE_LEN],
    framed: &[u8],
) -> Result<Vec<u8>> {
    let key = dek.content_key(ctx)?;
    crate::crypto::encrypt(&key, nonce, framed, &content_aad(ctx))
}

/// Open the content ciphertext, returning the framed rules.
pub(crate) fn open_content(
    dek: &Dek,
    ctx: &[u8; CTX_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let key = dek.content_key(ctx)?;
    crate::crypto::decrypt(&key, nonce, ciphertext, &content_aad(ctx)).map(Zeroizing::new)
}

/// Which HPKE KEM an encryption identity uses (RFC-0039).
///
/// `#[non_exhaustive]`: a later, incompatible X-Wing or HPKE-PQ revision
/// becomes a new stanza kind and a new variant here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EncryptionKem {
    /// DHKEM(X25519, HKDF-SHA256); stanza kind `0x01`.
    X25519,
    /// X-Wing (ML-KEM-768 + X25519); stanza kind `0x03`.
    XWing,
}

impl EncryptionKem {
    /// The envelope stanza kind byte for this KEM.
    pub(crate) const fn stanza_kind(self) -> u8 {
        match self {
            Self::X25519 => STANZA_X25519,
            Self::XWing => STANZA_XWING,
        }
    }

    /// The KEM whose stanza kind byte is `kind`, if any.
    pub(crate) const fn from_stanza_kind(kind: u8) -> Option<Self> {
        match kind {
            STANZA_X25519 => Some(Self::X25519),
            STANZA_XWING => Some(Self::XWing),
            _ => None,
        }
    }

    /// The stable lowercase name: `"x25519"` or `"xwing"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X25519 => "x25519",
            Self::XWing => "xwing",
        }
    }

    /// Length in bytes of this KEM's public key: 32 for X25519, 1216 for
    /// X-Wing.
    #[must_use]
    pub const fn public_key_len(self) -> usize {
        match self {
            Self::X25519 => X25519_PK_LEN,
            Self::XWing => XWING_PK_LEN,
        }
    }

    /// Bytes of randomness one encapsulation consumes.
    const fn encap_randomness_len(self) -> usize {
        match self {
            Self::X25519 => 32,
            Self::XWing => 64,
        }
    }
}

impl std::fmt::Display for EncryptionKem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for EncryptionKem {
    type Err = AionError;

    fn from_str(name: &str) -> Result<Self> {
        match name {
            "x25519" => Ok(Self::X25519),
            "xwing" => Ok(Self::XWing),
            _ => Err(AionError::InvalidFormat {
                reason: "unknown KEM name (expected x25519 or xwing)".to_string(),
            }),
        }
    }
}

/// A reader's encryption identity: `(kind, seed, recipient_pk)` (RFC-0039).
///
/// The seed is the X25519 secret key for [`EncryptionKem::X25519`] and the
/// X-Wing decapsulation-key seed for [`EncryptionKem::XWing`], loaded raw.
/// One seed serves exactly one kind. The seed is zeroized on drop and never
/// printed; the public key is cached so matching stanzas never repeats a key
/// generation.
#[derive(Clone)]
pub struct EncryptionIdentity {
    kind: EncryptionKem,
    seed: Zeroizing<[u8; 32]>,
    public_key: Vec<u8>,
    recipient: Recipient,
}

impl std::fmt::Debug for EncryptionIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionIdentity")
            .field("kind", &self.kind)
            .field("recipient", &self.recipient)
            .finish_non_exhaustive()
    }
}

impl EncryptionIdentity {
    /// Generate a fresh identity of `kind` from the OS RNG.
    ///
    /// # Errors
    ///
    /// Returns [`AionError::EntropyUnavailable`] if the OS RNG fails.
    pub fn generate(kind: EncryptionKem) -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);
        crate::crypto::fill_os_entropy(seed.as_mut())?;
        Self::from_seed(kind, seed)
    }

    /// Rebuild an identity from its stored seed.
    ///
    /// The caller must pass the kind the seed was generated for: a seed
    /// serves exactly one KEM, and nothing in the seed records which. A
    /// wrong kind usually yields a *valid but different* identity, which
    /// then fails later as `NotARecipient`; store the kind with the seed.
    ///
    /// # Errors
    ///
    /// Returns [`AionError::InvalidPrivateKey`] if the seed is not a valid
    /// key for `kind`.
    pub fn from_seed(kind: EncryptionKem, seed: Zeroizing<[u8; 32]>) -> Result<Self> {
        let public_key = match kind {
            EncryptionKem::X25519 => public_key_from_seed::<X25519HkdfSha256>(&seed)?,
            EncryptionKem::XWing => public_key_from_seed::<XWing>(&seed)?,
        };
        let recipient = Recipient::from_public_key(kind, &public_key)?;
        Ok(Self {
            kind,
            seed,
            public_key,
            recipient,
        })
    }

    /// The identity's KEM.
    #[must_use]
    pub const fn kind(&self) -> EncryptionKem {
        self.kind
    }

    /// The identity's public key: 32 bytes for X25519, 1216 for X-Wing.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// This identity as a writer's recipient.
    #[must_use]
    pub fn recipient(&self) -> Recipient {
        self.recipient.clone()
    }

    /// The seed, for the keystore to persist next to the kind.
    pub(crate) const fn seed(&self) -> &Zeroizing<[u8; 32]> {
        &self.seed
    }

    /// Whether `stanza` is addressed to this identity: same KEM and the
    /// same public key, compared in constant time.
    pub(crate) fn matches(&self, stanza: StanzaRecipient<'_>) -> bool {
        let recipient_pk: &[u8] = match (self.kind, stanza) {
            (EncryptionKem::X25519, StanzaRecipient::X25519 { recipient_pk, .. }) => recipient_pk,
            (EncryptionKem::XWing, StanzaRecipient::XWing { recipient_pk, .. }) => recipient_pk,
            _ => return false,
        };
        recipient_pk.ct_eq(&self.public_key).into()
    }
}

fn public_key_from_seed<K: KemTrait>(seed: &[u8; 32]) -> Result<Vec<u8>> {
    let secret = K::PrivateKey::from_bytes(seed).map_err(|_| AionError::InvalidPrivateKey {
        reason: "encryption seed is not a valid key for its KEM".to_string(),
    })?;
    Ok(K::sk_to_pk(&secret).to_bytes().to_vec())
}

/// Wrap `dek` for one recipient. Returns the stanza `(kind, body)`, where
/// `body = recipient_pk ‖ enc ‖ wrapped_dek`.
pub(crate) fn wrap_dek(
    kind: EncryptionKem,
    recipient_pk: &[u8],
    dek: &Dek,
    ctx: &[u8; CTX_LEN],
) -> Result<(u8, Vec<u8>)> {
    let mut randomness = Zeroizing::new(vec![0u8; kind.encap_randomness_len()]);
    crate::crypto::fill_os_entropy(&mut randomness)?;
    wrap_dek_with_randomness(kind, recipient_pk, dek, ctx, &randomness)
}

fn wrap_dek_with_randomness(
    kind: EncryptionKem,
    recipient_pk: &[u8],
    dek: &Dek,
    ctx: &[u8; CTX_LEN],
    randomness: &[u8],
) -> Result<(u8, Vec<u8>)> {
    if recipient_pk.len() != kind.public_key_len() {
        return Err(AionError::InvalidPublicKey {
            reason: "recipient public key has the wrong length for its KEM".to_string(),
        });
    }
    let info = wrap_info(ctx);
    let aad = dek.commitment();
    let (enc, wrapped) = match kind {
        EncryptionKem::X25519 => {
            seal_dek::<X25519HkdfSha256>(recipient_pk, dek, &info, &aad, randomness)?
        }
        EncryptionKem::XWing => seal_dek::<XWing>(recipient_pk, dek, &info, &aad, randomness)?,
    };
    let mut body = Vec::with_capacity(
        recipient_pk
            .len()
            .saturating_add(enc.len())
            .saturating_add(wrapped.len()),
    );
    body.extend_from_slice(recipient_pk);
    body.extend_from_slice(&enc);
    body.extend_from_slice(&wrapped);
    Ok((kind.stanza_kind(), body))
}

fn seal_dek<K: KemTrait>(
    recipient_pk: &[u8],
    dek: &Dek,
    info: &[u8],
    aad: &[u8; 32],
    randomness: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let pk = K::PublicKey::from_bytes(recipient_pk).map_err(|_| AionError::InvalidPublicKey {
        reason: "recipient public key is not valid for its KEM".to_string(),
    })?;
    let mut rng = PrefilledRng::new(randomness);
    let sealed = hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, K>(
        &OpModeS::Base,
        &pk,
        info,
        dek.as_bytes(),
        aad,
        &mut rng,
    );
    if rng.overdrawn || !rng.remaining.is_empty() {
        return Err(AionError::EntropyUnavailable {
            reason: "HPKE did not consume exactly the randomness drawn for it".to_string(),
        });
    }
    let (enc, wrapped) = sealed.map_err(|_| AionError::EncryptionFailed {
        reason: "HPKE seal failed".to_string(),
    })?;
    Ok((enc.to_bytes().to_vec(), wrapped))
}

/// Unwrap the DEK from a stanza addressed to `identity`, and check it
/// against the envelope's DEK commitment before returning it.
///
/// Every failure after the stanza matched is the same
/// [`AionError::RulesUnopenable`], so a caller cannot tell a bad `enc`, a
/// bad tag, and a wrong DEK apart.
pub(crate) fn unwrap_dek(
    identity: &EncryptionIdentity,
    stanza: StanzaRecipient<'_>,
    ctx: &[u8; CTX_LEN],
    dek_commitment: &[u8; 32],
) -> Result<Dek> {
    if !identity.matches(stanza) {
        return Err(unopenable());
    }
    let info = wrap_info(ctx);
    let opened = match stanza {
        StanzaRecipient::X25519 {
            enc, wrapped_dek, ..
        } => open_dek::<X25519HkdfSha256>(&identity.seed, enc, wrapped_dek, &info, dek_commitment),
        StanzaRecipient::XWing {
            enc, wrapped_dek, ..
        } => open_dek::<XWing>(&identity.seed, enc, wrapped_dek, &info, dek_commitment),
        _ => Err(unopenable()),
    }?;
    if opened.len() != 32 {
        return Err(unopenable());
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&opened);
    let dek = Dek::from_bytes(bytes);
    if bool::from(dek.commitment().ct_eq(dek_commitment)) {
        Ok(dek)
    } else {
        Err(unopenable())
    }
}

fn open_dek<K: KemTrait>(
    seed: &[u8; 32],
    enc: &[u8],
    wrapped: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let secret = K::PrivateKey::from_bytes(seed).map_err(|_| unopenable())?;
    let encapped = K::EncappedKey::from_bytes(enc).map_err(|_| unopenable())?;
    hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, K>(
        &OpModeR::Base,
        &secret,
        &encapped,
        info,
        wrapped,
        aad,
    )
    .map(Zeroizing::new)
    .map_err(|_| unopenable())
}

const fn unopenable() -> AionError {
    AionError::RulesUnopenable
}

/// Seal framed rules to `recipients` as a complete envelope.
///
/// Draws a fresh DEK and nonce, so a retried attempt never reuses either.
pub(crate) fn seal_section(
    framed: &[u8],
    recipients: &[Recipient],
    ctx: &[u8; CTX_LEN],
) -> Result<Vec<u8>> {
    let dek = Dek::generate()?;
    let stanzas = recipients
        .iter()
        .map(|recipient| match recipient {
            Recipient::External(wrapper) => wrap_external(wrapper.as_ref(), &dek, ctx),
            Recipient::X25519(pk) => wrap_dek(EncryptionKem::X25519, pk, &dek, ctx),
            Recipient::XWing(pk) => wrap_dek(EncryptionKem::XWing, pk.as_slice(), &dek, ctx),
        })
        .collect::<Result<Vec<_>>>()?;
    let (nonce, ciphertext) = seal_content(&dek, ctx, framed)?;
    encode_envelope(&dek.commitment(), stanzas, &nonce, &ciphertext)
}

/// One external (KMS) stanza as a reader sees it (RFC-0039 kind `0x02`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalStanza<'a> {
    provider_id: &'a str,
    key_ref: &'a str,
    blob: &'a [u8],
}

impl<'a> ExternalStanza<'a> {
    /// The provider name the writer's [`DekWrapper`] reported.
    #[must_use]
    pub const fn provider_id(&self) -> &'a str {
        self.provider_id
    }

    /// The provider key reference the writer's [`DekWrapper`] reported.
    #[must_use]
    pub const fn key_ref(&self) -> &'a str {
        self.key_ref
    }

    /// The provider's opaque wrapped DEK.
    #[must_use]
    pub const fn blob(&self) -> &'a [u8] {
        self.blob
    }
}

/// Wraps a version's DEK with an external key service such as a KMS
/// (RFC-0039 stanza kind `0x02`).
///
/// `context` is `"AION_V3_DEK_WRAP_V1\0" ‖ ctx ‖ dek_commitment`. Pass it as
/// the service's encryption context or associated data where it supports
/// one, so a blob cannot be replayed into another file, version, or
/// author's section. The implementation owns its timeouts and retries:
/// this crate is synchronous and never calls a provider concurrently.
///
/// `provider_id` and `key_ref` **identify the recipient**: they must be
/// stable for the life of the handle, and two handles that report the same
/// pair are the same recipient. A writer given two *different* handles
/// with the same pair refuses to seal rather than silently dropping one.
/// The encoded stanza (`5 + provider_id + key_ref + blob` bytes) must fit
/// in 4096 bytes.
///
/// # Example
///
/// A demonstration only: a real provider encrypts under its own key.
///
/// ```
/// use aion_context::confidential::DekWrapper;
///
/// struct Escrow;
/// impl DekWrapper for Escrow {
///     fn provider_id(&self) -> &str { "example-escrow" }
///     fn key_ref(&self) -> &str { "policy-key-1" }
///     fn wrap(&self, dek: &[u8; 32], _context: &[u8]) -> aion_context::Result<Vec<u8>> {
///         Ok(dek.to_vec())
///     }
/// }
/// ```
pub trait DekWrapper: Send + Sync {
    /// Provider name, 1–64 bytes, for example `"gcp-kms"`.
    fn provider_id(&self) -> &str;

    /// Provider key reference, 1–1024 bytes.
    fn key_ref(&self) -> &str;

    /// Wrap `dek`, bound to `context`. The blob must be 1–4096 bytes.
    ///
    /// # Errors
    ///
    /// Return [`AionError::EncryptionFailed`] for any provider failure;
    /// the commit then writes nothing.
    fn wrap(&self, dek: &[u8; 32], context: &[u8]) -> Result<Vec<u8>>;
}

/// Unwraps DEKs from external (KMS) stanzas (RFC-0039 kind `0x02`).
///
/// The returned DEK is always checked against the section's DEK commitment
/// before use, so a provider bug or a substituted blob cannot make readers
/// see different rules.
///
/// # Example
///
/// ```
/// use aion_context::confidential::{DekUnwrapper, ExternalStanza};
/// use zeroize::Zeroizing;
///
/// struct Escrow;
/// impl DekUnwrapper for Escrow {
///     fn accepts(&self, stanza: &ExternalStanza<'_>) -> bool {
///         stanza.provider_id() == "example-escrow" && stanza.key_ref() == "policy-key-1"
///     }
///     fn unwrap_dek(&self, stanza: &ExternalStanza<'_>, _context: &[u8])
///         -> aion_context::Result<Zeroizing<[u8; 32]>> {
///         let mut dek = Zeroizing::new([0u8; 32]);
///         let blob = stanza.blob();
///         if blob.len() != 32 {
///             return Err(aion_context::AionError::DecryptionFailed { reason: "bad blob".into() });
///         }
///         dek.copy_from_slice(blob);
///         Ok(dek)
///     }
/// }
/// ```
pub trait DekUnwrapper: Send + Sync {
    /// Whether this unwrapper handles `stanza`. Match the provider and key
    /// reference **exactly**: both come from the file. Do not treat
    /// `key_ref` as a resource path without validating it, since every
    /// accepted stanza costs a provider call.
    fn accepts(&self, stanza: &ExternalStanza<'_>) -> bool;

    /// Unwrap the DEK from `stanza`, bound to the same `context` the writer
    /// used (see [`DekWrapper`]).
    ///
    /// # Errors
    ///
    /// Return [`AionError::DecryptionFailed`] for any provider failure. The
    /// reader sees it as `RulesUnopenable`; the cause is logged.
    fn unwrap_dek(
        &self,
        stanza: &ExternalStanza<'_>,
        context: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>>;
}

/// The context an external wrapper binds: `info ‖ ctx ‖ dek_commitment`.
fn external_context(ctx: &[u8; CTX_LEN], dek_commitment: &[u8; 32]) -> Vec<u8> {
    let mut context = wrap_info(ctx);
    context.extend_from_slice(dek_commitment);
    context
}

/// Wrap the DEK with an external provider into a kind-`0x02` stanza body:
/// `provider_id_len u8 ‖ provider_id ‖ key_ref_len u16 ‖ key_ref ‖ blob_len u16 ‖ blob`.
fn wrap_external(
    wrapper: &dyn DekWrapper,
    dek: &Dek,
    ctx: &[u8; CTX_LEN],
) -> Result<(u8, Vec<u8>)> {
    let invalid = |reason: &str| AionError::EncryptionFailed {
        reason: reason.to_string(),
    };
    let provider_id = wrapper.provider_id().as_bytes();
    let key_ref = wrapper.key_ref().as_bytes();
    let provider_len = u8::try_from(provider_id.len())
        .ok()
        .filter(|len| (1..=64).contains(len))
        .ok_or_else(|| invalid("external provider_id must be 1-64 bytes"))?;
    let key_ref_len = u16::try_from(key_ref.len())
        .ok()
        .filter(|len| (1..=1024).contains(len))
        .ok_or_else(|| invalid("external key_ref must be 1-1024 bytes"))?;
    let header_len = 5usize
        .saturating_add(provider_id.len())
        .saturating_add(key_ref.len());
    if header_len >= crate::envelope::MAX_STANZA_BODY {
        return Err(invalid(
            "external provider_id and key_ref leave no room for a blob",
        ));
    }
    let blob = wrapper.wrap(dek.as_bytes(), &external_context(ctx, &dek.commitment()))?;
    let blob_len = u16::try_from(blob.len())
        .ok()
        .filter(|len| (1..=4096).contains(len))
        .ok_or_else(|| invalid("external wrapper returned a blob outside 1-4096 bytes"))?;
    if header_len.saturating_add(blob.len()) > crate::envelope::MAX_STANZA_BODY {
        return Err(invalid("external stanza exceeds 4096 bytes"));
    }
    let mut body = Vec::with_capacity(
        5usize
            .saturating_add(provider_id.len())
            .saturating_add(key_ref.len())
            .saturating_add(blob.len()),
    );
    body.push(provider_len);
    body.extend_from_slice(provider_id);
    body.extend_from_slice(&key_ref_len.to_le_bytes());
    body.extend_from_slice(key_ref);
    body.extend_from_slice(&blob_len.to_le_bytes());
    body.extend_from_slice(&blob);
    Ok((crate::envelope::STANZA_EXTERNAL, body))
}

/// Unwrap with an external provider and check the DEK commitment.
fn unwrap_external(
    unwrapper: &dyn DekUnwrapper,
    stanza: &ExternalStanza<'_>,
    ctx: &[u8; CTX_LEN],
    dek_commitment: &[u8; 32],
) -> Result<Dek> {
    let bytes = unwrapper
        .unwrap_dek(stanza, &external_context(ctx, dek_commitment))
        .map_err(|_| {
            tracing::warn!(event = "external_unwrap_failed", reason = "provider_error");
            unopenable()
        })?;
    let dek = Dek::from_bytes(bytes);
    if bool::from(dek.commitment().ct_eq(dek_commitment)) {
        Ok(dek)
    } else {
        tracing::warn!(
            event = "external_unwrap_failed",
            reason = "commitment_mismatch"
        );
        Err(unopenable())
    }
}

/// Parse a confidential section and refuse one whose ciphertext exceeds the
/// rules-size limit, before any decryption allocates. Key-free, so
/// verification uses it too.
///
/// # Errors
///
/// [`AionError::InvalidFormat`] for a malformed envelope or one over
/// [`crate::format::MAX_CONFIDENTIAL_RULES_LEN`].
pub(crate) fn bounded_envelope(section: &[u8]) -> Result<Envelope<'_>> {
    let envelope = Envelope::parse(section)?;
    let tag = 16usize;
    let limit = crate::format::MAX_CONFIDENTIAL_RULES_LEN.saturating_add(tag);
    if envelope.ciphertext().len() > limit {
        return Err(AionError::InvalidFormat {
            reason: "confidential rules exceed the 16 MiB limit".to_string(),
        });
    }
    Ok(envelope)
}

/// Find a stanza addressed to one of `identities` and unwrap the DEK.
///
/// Tries every `(identity, stanza)` pair that matches, in order, and
/// returns the first DEK that passes the commitment check.
///
/// # Errors
///
/// [`AionError::NotARecipient`] if no stanza is addressed to any identity;
/// [`AionError::RulesUnopenable`] if every matching stanza fails.
pub(crate) fn unwrap_for(
    envelope: &Envelope<'_>,
    identities: &[EncryptionIdentity],
    unwrappers: &[std::sync::Arc<dyn DekUnwrapper>],
    ctx: &[u8; CTX_LEN],
) -> Result<Dek> {
    let mut matched = false;
    for identity in identities {
        for stanza in envelope.stanzas() {
            if !identity.matches(stanza.recipient()) {
                continue;
            }
            matched = true;
            if let Ok(dek) =
                unwrap_dek(identity, stanza.recipient(), ctx, envelope.dek_commitment())
            {
                return Ok(dek);
            }
        }
    }
    for unwrapper in unwrappers {
        for stanza in envelope.stanzas() {
            let StanzaRecipient::External {
                provider_id,
                key_ref,
                blob,
            } = stanza.recipient()
            else {
                continue;
            };
            let external = ExternalStanza {
                provider_id,
                key_ref,
                blob,
            };
            if !unwrapper.accepts(&external) {
                continue;
            }
            matched = true;
            let unwrapped = unwrap_external(
                unwrapper.as_ref(),
                &external,
                ctx,
                envelope.dek_commitment(),
            );
            if let Ok(dek) = unwrapped {
                return Ok(dek);
            }
        }
    }
    Err(if matched {
        AionError::RulesUnopenable
    } else {
        AionError::NotARecipient
    })
}

/// Open an envelope with one of `identities`, returning the framed rules.
///
/// # Errors
///
/// As [`unwrap_for`], plus [`AionError::RulesUnopenable`] if the content
/// does not decrypt.
pub(crate) fn open_section(
    envelope: &Envelope<'_>,
    identities: &[EncryptionIdentity],
    unwrappers: &[std::sync::Arc<dyn DekUnwrapper>],
    ctx: &[u8; CTX_LEN],
) -> Result<Zeroizing<Vec<u8>>> {
    let dek = unwrap_for(envelope, identities, unwrappers, ctx)?;
    open_with_dek(envelope, &dek, ctx)
}

/// Open an envelope with a known DEK, after checking it against the
/// envelope's commitment.
///
/// # Errors
///
/// [`AionError::RulesUnopenable`] if the DEK is not this envelope's, or the
/// content does not decrypt.
pub(crate) fn open_with_dek(
    envelope: &Envelope<'_>,
    dek: &Dek,
    ctx: &[u8; CTX_LEN],
) -> Result<Zeroizing<Vec<u8>>> {
    if !bool::from(dek.commitment().ct_eq(envelope.dek_commitment())) {
        return Err(unopenable());
    }
    open_content(dek, ctx, envelope.nonce(), envelope.ciphertext()).map_err(|_| unopenable())
}

/// The data-encryption key of one confidential version, for selective
/// disclosure (RFC-0039).
///
/// Each version's key is independent random bytes, so a disclosed key
/// opens that one rules section and no other. Zeroized on drop; `Debug`
/// never prints it.
pub struct VersionKey(Dek);

impl std::fmt::Debug for VersionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VersionKey(..)")
    }
}

impl VersionKey {
    /// Rebuild a disclosed key from its 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(Dek::from_bytes(bytes))
    }

    /// The key's 32 bytes, to hand to the party it is disclosed to.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(self.0.as_bytes());
        bytes
    }

    pub(crate) const fn from_dek(dek: Dek) -> Self {
        Self(dek)
    }

    pub(crate) const fn dek(&self) -> &Dek {
        &self.0
    }
}

/// Serves pre-drawn randomness to `hpke`, whose RNG cannot fail.
///
/// Running past the buffer sets `overdrawn` and yields zeros; the caller
/// then discards the result instead of using it.
struct PrefilledRng<'a> {
    remaining: &'a [u8],
    overdrawn: bool,
}

impl<'a> PrefilledRng<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self {
            remaining: bytes,
            overdrawn: false,
        }
    }

    fn fill(&mut self, dst: &mut [u8]) {
        if dst.len() > self.remaining.len() {
            self.overdrawn = true;
            dst.fill(0);
            return;
        }
        let (head, tail) = self.remaining.split_at(dst.len());
        dst.copy_from_slice(head);
        self.remaining = tail;
    }
}

impl TryRng for PrefilledRng<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> std::result::Result<u32, Infallible> {
        let mut bytes = [0u8; 4];
        self.fill(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> std::result::Result<u64, Infallible> {
        let mut bytes = [0u8; 8];
        self.fill(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> std::result::Result<(), Infallible> {
        self.fill(dst);
        Ok(())
    }
}

impl TryCryptoRng for PrefilledRng<'_> {}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
pub(crate) mod tests {
    use super::*;
    use crate::envelope::Envelope;

    fn ok<T>(result: Result<T>) -> T {
        result.unwrap_or_else(|_| std::process::abort())
    }

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap_or_else(|_| std::process::abort())
    }

    fn ctx() -> [u8; CTX_LEN] {
        binding_context(FileId(0x0102_0304), AuthorId(77), VersionNumber(3))
    }

    fn seed(byte: u8) -> Zeroizing<[u8; 32]> {
        Zeroizing::new([byte; 32])
    }

    struct Vector {
        sk: Vec<u8>,
        pk: Vec<u8>,
        enc: Vec<u8>,
        info: Vec<u8>,
        aad: Vec<u8>,
        pt: Vec<u8>,
        ct: Vec<u8>,
    }

    fn vector(json: &str) -> Vector {
        let v: serde_json::Value =
            serde_json::from_str(json).unwrap_or_else(|_| std::process::abort());
        let field = |k: &str| unhex(v[k].as_str().unwrap_or_default());
        Vector {
            sk: field("skRm"),
            pk: field("pkRm"),
            enc: field("enc"),
            info: field("info"),
            aad: field("aad"),
            pt: field("pt"),
            ct: field("ct"),
        }
    }

    fn check_vector(kind: EncryptionKem, v: &Vector) {
        let seed: [u8; 32] =
            v.sk.as_slice()
                .try_into()
                .unwrap_or_else(|_| std::process::abort());
        let identity = ok(EncryptionIdentity::from_seed(kind, Zeroizing::new(seed)));
        assert_eq!(
            identity.public_key(),
            v.pk.as_slice(),
            "public key from raw seed"
        );
        let opened = match kind {
            EncryptionKem::X25519 => {
                open_dek::<X25519HkdfSha256>(&seed, &v.enc, &v.ct, &v.info, &v.aad)
            }
            EncryptionKem::XWing => open_dek::<XWing>(&seed, &v.enc, &v.ct, &v.info, &v.aad),
        };
        assert_eq!(ok(opened).as_slice(), v.pt.as_slice());
    }

    #[test]
    fn rfc9180_x25519_vector_opens() {
        let v = vector(include_str!(
            "../tests/fixtures/hpke/x25519-base-chacha.json"
        ));
        check_vector(EncryptionKem::X25519, &v);
    }

    #[test]
    fn hpke_pq_xwing_vector_opens_with_the_raw_seed() {
        let v = vector(include_str!(
            "../tests/fixtures/hpke/xwing-base-chacha.json"
        ));
        check_vector(EncryptionKem::XWing, &v);
    }

    #[test]
    fn binding_context_is_little_endian_file_author_version() {
        let ctx = binding_context(FileId(1), AuthorId(2), VersionNumber(3));
        assert_eq!(&ctx[..8], &1u64.to_le_bytes());
        assert_eq!(&ctx[8..16], &2u64.to_le_bytes());
        assert_eq!(&ctx[16..], &3u64.to_le_bytes());
    }

    #[test]
    fn dek_commitment_and_content_seal_are_pinned() {
        let dek = Dek::from_bytes(Zeroizing::new([0x42; 32]));
        assert_eq!(hex::encode(dek.commitment()), GOLDEN_DEK_COMMITMENT);
        let ct = ok(seal_content_with_nonce(
            &dek,
            &ctx(),
            &[0x0E; NONCE_LEN],
            b"framed rules",
        ));
        assert_eq!(hex::encode(&ct), GOLDEN_CONTENT_CT);
    }

    #[test]
    fn x25519_stanza_is_pinned() {
        let identity = ok(EncryptionIdentity::from_seed(
            EncryptionKem::X25519,
            seed(0x01),
        ));
        let dek = Dek::from_bytes(Zeroizing::new([0x42; 32]));
        let (kind, body) = ok(wrap_dek_with_randomness(
            EncryptionKem::X25519,
            identity.public_key(),
            &dek,
            &ctx(),
            &[0x07; 32],
        ));
        assert_eq!(kind, STANZA_X25519);
        assert_eq!(body.len(), 112);
        assert_eq!(hex::encode(&body), GOLDEN_X25519_STANZA);
    }

    #[test]
    fn xwing_stanza_is_pinned() {
        let identity = ok(EncryptionIdentity::from_seed(
            EncryptionKem::XWing,
            seed(0x03),
        ));
        let dek = Dek::from_bytes(Zeroizing::new([0x42; 32]));
        let (kind, body) = ok(wrap_dek_with_randomness(
            EncryptionKem::XWing,
            identity.public_key(),
            &dek,
            &ctx(),
            &[0x07; 64],
        ));
        assert_eq!(kind, STANZA_XWING);
        assert_eq!(body.len(), 2384);
        assert_eq!(
            hex::encode(blake3::hash(&body).as_bytes()),
            GOLDEN_XWING_STANZA_HASH
        );
    }

    #[test]
    fn too_little_randomness_is_an_error_not_a_weak_stanza() {
        let identity = ok(EncryptionIdentity::from_seed(
            EncryptionKem::XWing,
            seed(0x03),
        ));
        let dek = Dek::from_bytes(Zeroizing::new([0x42; 32]));
        let result = wrap_dek_with_randomness(
            EncryptionKem::XWing,
            identity.public_key(),
            &dek,
            &ctx(),
            &[7; 63],
        );
        assert!(matches!(result, Err(AionError::EntropyUnavailable { .. })));
    }

    #[test]
    fn wrong_length_or_invalid_recipient_keys_are_rejected() {
        let dek = Dek::from_bytes(Zeroizing::new([0x42; 32]));
        assert!(wrap_dek(EncryptionKem::X25519, &[1; 31], &dek, &ctx()).is_err());
        assert!(wrap_dek(EncryptionKem::XWing, &[1; 32], &dek, &ctx()).is_err());
        assert!(wrap_dek(EncryptionKem::XWing, &[0xFF; XWING_PK_LEN], &dek, &ctx()).is_err());
    }

    fn two_identities() -> (EncryptionIdentity, EncryptionIdentity) {
        (
            ok(EncryptionIdentity::generate(EncryptionKem::X25519)),
            ok(EncryptionIdentity::generate(EncryptionKem::XWing)),
        )
    }

    fn seal_for(ids: &[&EncryptionIdentity], ctx: &[u8; CTX_LEN], rules: &[u8]) -> Vec<u8> {
        let recipients: Vec<Recipient> = ids.iter().map(|id| id.recipient()).collect();
        let framed = ok(crate::format::frame_rules(rules));
        ok(seal_section(&framed, &recipients, ctx))
    }

    fn open_rules(
        envelope: &Envelope<'_>,
        id: &EncryptionIdentity,
        ctx: &[u8; CTX_LEN],
    ) -> Result<Vec<u8>> {
        let framed = open_section(envelope, std::slice::from_ref(id), &[], ctx)?;
        Ok(crate::format::unframe_rules(&framed)?.to_vec())
    }

    #[test]
    fn every_recipient_opens_the_same_rules() {
        let (x, w) = two_identities();
        let bytes = seal_for(&[&x, &w], &ctx(), b"refund_limit: 5000");
        let envelope = ok(Envelope::parse(&bytes));
        assert_eq!(ok(open_rules(&envelope, &x, &ctx())), b"refund_limit: 5000");
        assert_eq!(ok(open_rules(&envelope, &w, &ctx())), b"refund_limit: 5000");
    }

    #[test]
    fn an_unlisted_identity_cannot_open() {
        let (x, w) = two_identities();
        let stranger = ok(EncryptionIdentity::generate(EncryptionKem::XWing));
        let bytes = seal_for(&[&x, &w], &ctx(), b"rules");
        let envelope = ok(Envelope::parse(&bytes));
        assert!(open_section(&envelope, std::slice::from_ref(&stranger), &[], &ctx()).is_err());
    }

    #[test]
    fn a_section_moved_to_another_version_or_author_does_not_open() {
        let (x, w) = two_identities();
        let bytes = seal_for(&[&x, &w], &ctx(), b"rules");
        let envelope = ok(Envelope::parse(&bytes));
        let other_version = binding_context(FileId(0x0102_0304), AuthorId(77), VersionNumber(4));
        let other_author = binding_context(FileId(0x0102_0304), AuthorId(78), VersionNumber(3));
        let other_file = binding_context(FileId(0x0102_0305), AuthorId(77), VersionNumber(3));
        for moved in [other_version, other_author, other_file] {
            assert!(open_section(&envelope, std::slice::from_ref(&x), &[], &moved).is_err());
            assert!(open_section(&envelope, std::slice::from_ref(&w), &[], &moved).is_err());
        }
    }

    #[test]
    fn a_stanza_under_another_commitment_fails_hpke_open() {
        let (x, _) = two_identities();
        let honest = Dek::generate().unwrap_or_else(|_| std::process::abort());
        let other = Dek::generate().unwrap_or_else(|_| std::process::abort());
        let stanza = ok(wrap_dek(
            EncryptionKem::X25519,
            x.public_key(),
            &other,
            &ctx(),
        ));
        let framed = ok(crate::format::frame_rules(b"rules"));
        let (nonce, ct) = ok(seal_content(&honest, &ctx(), &framed));
        let bytes = ok(encode_envelope(
            &honest.commitment(),
            vec![stanza],
            &nonce,
            &ct,
        ));
        let envelope = ok(Envelope::parse(&bytes));
        assert!(open_section(&envelope, std::slice::from_ref(&x), &[], &ctx()).is_err());
    }

    /// A malicious sealer's stanza: HPKE-sealed under the envelope's own
    /// commitment, so the HPKE open succeeds, but wrapping a different DEK.
    /// Only the key-commitment check can reject it.
    #[test]
    fn a_stanza_wrapping_a_different_dek_under_the_honest_commitment_is_rejected() {
        let (x, w) = two_identities();
        let honest = ok(Dek::generate());
        let other = ok(Dek::generate());
        let info = wrap_info(&ctx());
        for id in [&x, &w] {
            let mut randomness = Zeroizing::new(vec![0u8; id.kind().encap_randomness_len()]);
            ok(crate::crypto::fill_os_entropy(&mut randomness));
            let (enc, wrapped) = ok(match id.kind() {
                EncryptionKem::X25519 => seal_dek::<X25519HkdfSha256>(
                    id.public_key(),
                    &other,
                    &info,
                    &honest.commitment(),
                    &randomness,
                ),
                EncryptionKem::XWing => seal_dek::<XWing>(
                    id.public_key(),
                    &other,
                    &info,
                    &honest.commitment(),
                    &randomness,
                ),
            });
            let mut body = id.public_key().to_vec();
            body.extend_from_slice(&enc);
            body.extend_from_slice(&wrapped);
            let framed = ok(crate::format::frame_rules(b"rules"));
            let (nonce, ct) = ok(seal_content(&honest, &ctx(), &framed));
            let stanzas = vec![(id.kind().stanza_kind(), body)];
            let bytes = ok(encode_envelope(&honest.commitment(), stanzas, &nonce, &ct));
            let envelope = ok(Envelope::parse(&bytes));
            let stanza = envelope.stanzas()[0].recipient();
            let unwrapped = unwrap_dek(id, stanza, &ctx(), envelope.dek_commitment());
            assert!(matches!(unwrapped, Err(AionError::RulesUnopenable)));
        }
    }

    #[test]
    fn randomness_must_be_consumed_exactly() {
        let dek = Dek::from_bytes(Zeroizing::new([0x42; 32]));
        let (x, w) = two_identities();
        for (id, exact) in [(&x, 32usize), (&w, 64)] {
            for len in [exact - 1, exact + 1] {
                let result = wrap_dek_with_randomness(
                    id.kind(),
                    id.public_key(),
                    &dek,
                    &ctx(),
                    &vec![7; len],
                );
                assert!(
                    matches!(result, Err(AionError::EntropyUnavailable { .. })),
                    "{len}"
                );
            }
            assert!(wrap_dek_with_randomness(
                id.kind(),
                id.public_key(),
                &dek,
                &ctx(),
                &vec![7; exact]
            )
            .is_ok());
        }
    }

    #[test]
    fn corrupted_enc_fails_the_same_way_for_both_kems() {
        let (x, w) = two_identities();
        for (identity, enc_at) in [(&x, 40usize), (&w, 1216 + 500)] {
            let bytes = seal_for(&[identity], &ctx(), b"rules");
            let mut tampered = bytes.clone();
            let body_start = 8 + 1 + 32 + 2 + 3;
            tampered[body_start + enc_at] ^= 0x01;
            let envelope = ok(Envelope::parse(&tampered));
            let err = open_section(&envelope, std::slice::from_ref(identity), &[], &ctx());
            assert!(matches!(err, Err(AionError::RulesUnopenable)));
        }
    }

    const GOLDEN_DEK_COMMITMENT: &str =
        "2b03373b2cf99c1213e7bd0d19691c26cc3c20a6463476fc65bf841f6d3a46c4";
    const GOLDEN_CONTENT_CT: &str = "9665a2fddbc0e7335c2ca4d8144bdb7c2b4c08a048a002dae3df86ad";
    const GOLDEN_X25519_STANZA: &str = "a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a2095fd47633b5e43fca7bad1bfbe424feacb175d9d4d4a30f166dbd30636f0b446bb7ea17e3487e2a920485087edf5341d6b86ce621c42d3b11ac64409ba41ee26c2ae7291aa52329e1a423fb40d8999958";
    const GOLDEN_XWING_STANZA_HASH: &str =
        "399eb899ac0f9e5cf166ca2c34d4054f1ce74a6e0cb067faf90658ada0607e73";

    /// A stand-in KMS: ChaCha20-Poly1305 under a local key, with the
    /// binding context as associated data, as a real KMS binds it as
    /// encryption context.
    pub struct LocalKms {
        pub key: [u8; 32],
        pub key_ref: &'static str,
    }

    impl DekWrapper for LocalKms {
        #[allow(clippy::unnecessary_literal_bound)] // the trait fixes the signature
        fn provider_id(&self) -> &str {
            "local-kms"
        }
        fn key_ref(&self) -> &str {
            self.key_ref
        }
        fn wrap(&self, dek: &[u8; 32], context: &[u8]) -> Result<Vec<u8>> {
            let mut nonce = [0u8; NONCE_LEN];
            crate::crypto::fill_os_entropy(&mut nonce)?;
            let mut blob = nonce.to_vec();
            blob.extend_from_slice(&crate::crypto::encrypt(&self.key, &nonce, dek, context)?);
            Ok(blob)
        }
    }

    impl DekUnwrapper for LocalKms {
        fn accepts(&self, stanza: &ExternalStanza<'_>) -> bool {
            stanza.provider_id() == "local-kms" && stanza.key_ref() == self.key_ref
        }
        fn unwrap_dek(
            &self,
            stanza: &ExternalStanza<'_>,
            context: &[u8],
        ) -> Result<Zeroizing<[u8; 32]>> {
            let (nonce, sealed) = stanza.blob().split_at(NONCE_LEN.min(stanza.blob().len()));
            let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| unopenable())?;
            let opened =
                Zeroizing::new(crate::crypto::decrypt(&self.key, &nonce, sealed, context)?);
            let mut dek = Zeroizing::new([0u8; 32]);
            if opened.len() != 32 {
                return Err(unopenable());
            }
            dek.copy_from_slice(&opened);
            Ok(dek)
        }
    }

    /// An unwrapper that returns a DEK of its choosing.
    struct LyingKms;

    impl DekUnwrapper for LyingKms {
        fn accepts(&self, _stanza: &ExternalStanza<'_>) -> bool {
            true
        }
        fn unwrap_dek(
            &self,
            _stanza: &ExternalStanza<'_>,
            _context: &[u8],
        ) -> Result<Zeroizing<[u8; 32]>> {
            Ok(Zeroizing::new([0x42; 32]))
        }
    }

    /// A wrapper whose blob or names are out of range.
    struct BadWrapper {
        provider_id: String,
        blob_len: usize,
    }

    impl DekWrapper for BadWrapper {
        fn provider_id(&self) -> &str {
            &self.provider_id
        }
        #[allow(clippy::unnecessary_literal_bound)] // the trait fixes the signature
        fn key_ref(&self) -> &str {
            "key"
        }
        fn wrap(&self, _dek: &[u8; 32], _context: &[u8]) -> Result<Vec<u8>> {
            Ok(vec![7; self.blob_len])
        }
    }

    fn kms(key_ref: &'static str) -> std::sync::Arc<LocalKms> {
        std::sync::Arc::new(LocalKms {
            key: [0x5A; 32],
            key_ref,
        })
    }

    fn seal_to(recipients: &[Recipient], ctx: &[u8; CTX_LEN]) -> Vec<u8> {
        let framed = ok(crate::format::frame_rules(b"kms rules"));
        ok(seal_section(&framed, recipients, ctx))
    }

    fn open_with(
        bytes: &[u8],
        identities: &[EncryptionIdentity],
        unwrappers: &[std::sync::Arc<dyn DekUnwrapper>],
        ctx: &[u8; CTX_LEN],
    ) -> Result<Vec<u8>> {
        let envelope = Envelope::parse(bytes)?;
        let framed = open_section(&envelope, identities, unwrappers, ctx)?;
        Ok(crate::format::unframe_rules(&framed)?.to_vec())
    }

    #[test]
    fn a_kms_recipient_and_an_xwing_recipient_both_open() {
        let reader = ok(EncryptionIdentity::generate(EncryptionKem::XWing));
        let vault = kms("policy-key");
        let bytes = seal_to(
            &[reader.recipient(), Recipient::external(vault.clone())],
            &ctx(),
        );
        let envelope = ok(Envelope::parse(&bytes));
        assert!(envelope
            .stanzas()
            .iter()
            .any(|s| s.kind() == crate::envelope::STANZA_EXTERNAL));
        let unwrappers: Vec<std::sync::Arc<dyn DekUnwrapper>> = vec![vault];
        assert_eq!(
            ok(open_with(&bytes, &[], &unwrappers, &ctx())),
            b"kms rules"
        );
        assert_eq!(
            ok(open_with(
                &bytes,
                std::slice::from_ref(&reader),
                &[],
                &ctx()
            )),
            b"kms rules"
        );
    }

    #[test]
    fn a_kms_stanza_moved_to_another_context_does_not_open() {
        let vault = kms("policy-key");
        let bytes = seal_to(&[Recipient::external(vault.clone())], &ctx());
        let moved = binding_context(FileId(0x0102_0304), AuthorId(77), VersionNumber(4));
        let unwrappers: Vec<std::sync::Arc<dyn DekUnwrapper>> = vec![vault];
        assert!(matches!(
            open_with(&bytes, &[], &unwrappers, &moved),
            Err(AionError::RulesUnopenable)
        ));
    }

    #[test]
    fn a_lying_provider_is_caught_by_the_key_commitment() {
        let bytes = seal_to(&[Recipient::external(kms("policy-key"))], &ctx());
        let liar: Vec<std::sync::Arc<dyn DekUnwrapper>> = vec![std::sync::Arc::new(LyingKms)];
        assert!(matches!(
            open_with(&bytes, &[], &liar, &ctx()),
            Err(AionError::RulesUnopenable)
        ));
    }

    #[test]
    fn an_unwrapper_that_declines_is_not_a_recipient() {
        let bytes = seal_to(&[Recipient::external(kms("policy-key"))], &ctx());
        let other: Vec<std::sync::Arc<dyn DekUnwrapper>> = vec![kms("other-key")];
        assert!(matches!(
            open_with(&bytes, &[], &other, &ctx()),
            Err(AionError::NotARecipient)
        ));
    }

    #[test]
    fn out_of_range_provider_output_refuses_to_seal() {
        let framed = ok(crate::format::frame_rules(b"r"));
        for (provider_id, blob_len) in [
            (String::new(), 16),
            ("p".repeat(65), 16),
            ("ok".to_string(), 0),
            ("ok".to_string(), 4097),
        ] {
            let wrapper = std::sync::Arc::new(BadWrapper {
                provider_id,
                blob_len,
            });
            assert!(seal_section(&framed, &[Recipient::external(wrapper)], &ctx()).is_err());
        }
    }

    /// A provider that stores the DEK in the clear and ignores the context.
    struct CarelessKms;

    impl DekWrapper for CarelessKms {
        #[allow(clippy::unnecessary_literal_bound)] // the trait fixes the signature
        fn provider_id(&self) -> &str {
            "careless"
        }
        #[allow(clippy::unnecessary_literal_bound)] // the trait fixes the signature
        fn key_ref(&self) -> &str {
            "k"
        }
        fn wrap(&self, dek: &[u8; 32], _context: &[u8]) -> Result<Vec<u8>> {
            Ok(dek.to_vec())
        }
    }

    impl DekUnwrapper for CarelessKms {
        fn accepts(&self, stanza: &ExternalStanza<'_>) -> bool {
            stanza.provider_id() == "careless"
        }
        fn unwrap_dek(
            &self,
            stanza: &ExternalStanza<'_>,
            _context: &[u8],
        ) -> Result<Zeroizing<[u8; 32]>> {
            let mut dek = Zeroizing::new([0u8; 32]);
            if stanza.blob().len() != 32 {
                return Err(unopenable());
            }
            dek.copy_from_slice(stanza.blob());
            Ok(dek)
        }
    }

    /// An unwrapper whose provider always fails.
    struct DownKms;

    impl DekUnwrapper for DownKms {
        fn accepts(&self, _stanza: &ExternalStanza<'_>) -> bool {
            true
        }
        fn unwrap_dek(
            &self,
            _stanza: &ExternalStanza<'_>,
            _context: &[u8],
        ) -> Result<Zeroizing<[u8; 32]>> {
            Err(AionError::DecryptionFailed {
                reason: "kms throttled".to_string(),
            })
        }
    }

    #[test]
    fn a_failing_unwrapper_is_unopenable_and_the_next_one_is_tried() {
        let vault = kms("policy-key");
        let bytes = seal_to(&[Recipient::external(vault.clone())], &ctx());
        let down: Vec<std::sync::Arc<dyn DekUnwrapper>> = vec![std::sync::Arc::new(DownKms)];
        assert!(matches!(
            open_with(&bytes, &[], &down, &ctx()),
            Err(AionError::RulesUnopenable)
        ));
        let both: Vec<std::sync::Arc<dyn DekUnwrapper>> = vec![std::sync::Arc::new(DownKms), vault];
        assert_eq!(ok(open_with(&bytes, &[], &both, &ctx())), b"kms rules");
    }

    /// A provider that ignores the context only weakens its own stanza:
    /// the content AEAD still binds `ctx`, so a moved section fails.
    #[test]
    fn a_context_ignoring_provider_still_cannot_open_a_moved_section() {
        let careless = std::sync::Arc::new(CarelessKms);
        let bytes = seal_to(&[Recipient::external(careless.clone())], &ctx());
        let unwrappers: Vec<std::sync::Arc<dyn DekUnwrapper>> = vec![careless];
        assert_eq!(
            ok(open_with(&bytes, &[], &unwrappers, &ctx())),
            b"kms rules"
        );
        let moved = binding_context(FileId(1), AuthorId(77), VersionNumber(3));
        assert!(matches!(
            open_with(&bytes, &[], &unwrappers, &moved),
            Err(AionError::RulesUnopenable)
        ));
    }

    #[test]
    fn key_ref_and_total_size_bounds_are_enforced_before_encoding() {
        struct Sized(String, usize);
        impl DekWrapper for Sized {
            #[allow(clippy::unnecessary_literal_bound)] // the trait fixes the signature
            fn provider_id(&self) -> &str {
                "p"
            }
            fn key_ref(&self) -> &str {
                &self.0
            }
            fn wrap(&self, _dek: &[u8; 32], _context: &[u8]) -> Result<Vec<u8>> {
                Ok(vec![1; self.1])
            }
        }
        let framed = ok(crate::format::frame_rules(b"r"));
        let seal = |key_ref: usize, blob: usize| {
            let wrapper = std::sync::Arc::new(Sized("k".repeat(key_ref), blob));
            seal_section(&framed, &[Recipient::external(wrapper)], &ctx())
        };
        assert!(seal(0, 16).is_err());
        assert!(seal(1025, 16).is_err());
        assert!(seal(1024, 16).is_ok());
        assert!(matches!(
            seal(1024, 4096),
            Err(AionError::EncryptionFailed { .. })
        ));
        assert!(seal(1024, 4096 - 5 - 1 - 1024).is_ok());
    }

    mod properties {
        use super::*;
        use hegel::generators as gs;

        #[hegel::test]
        fn prop_seal_open_round_trip_for_mixed_recipients(tc: hegel::TestCase) {
            let rules = tc.draw(gs::binary().max_size(2048));
            let xs = tc.draw(gs::integers::<u8>().max_value(2));
            let ws = tc.draw(gs::integers::<u8>().max_value(2));
            if xs == 0 && ws == 0 {
                return;
            }
            let ids: Vec<EncryptionIdentity> = (0..xs)
                .map(|_| ok(EncryptionIdentity::generate(EncryptionKem::X25519)))
                .chain((0..ws).map(|_| ok(EncryptionIdentity::generate(EncryptionKem::XWing))))
                .collect();
            let refs: Vec<&EncryptionIdentity> = ids.iter().collect();
            let bytes = seal_for(&refs, &ctx(), &rules);
            let envelope = ok(Envelope::parse(&bytes));
            for id in &ids {
                assert_eq!(ok(open_rules(&envelope, id, &ctx())), rules);
            }
        }

        #[hegel::test]
        fn prop_any_byte_flip_in_a_single_recipient_envelope_fails_to_open(tc: hegel::TestCase) {
            let xwing = tc.draw(gs::booleans());
            let kind = if xwing {
                EncryptionKem::XWing
            } else {
                EncryptionKem::X25519
            };
            let id = ok(EncryptionIdentity::generate(kind));
            let bytes = seal_for(&[&id], &ctx(), b"rules");
            let index = tc.draw(gs::integers::<usize>().max_value(bytes.len().saturating_sub(1)));
            let flip = tc.draw(gs::integers::<u8>().min_value(1));
            let mut tampered = bytes;
            tampered[index] ^= flip;
            if let Ok(envelope) = Envelope::parse(&tampered) {
                assert!(open_section(&envelope, std::slice::from_ref(&id), &[], &ctx()).is_err());
            }
        }
    }
}
