// SPDX-License-Identifier: MIT OR Apache-2.0
//! The confidential-rules envelope codec (RFC-0039 Phase B1).
//!
//! A confidential rules section is an envelope:
//!
//! ```text
//! magic[8] = "AIONENV1" ‖ suite u8 = 0x01 ‖ dek_commitment[32] ‖
//! stanza_count u16 (1..=64) ‖ stanzas ‖ nonce[12] ‖ ct_len u64 ‖ ciphertext
//!
//! stanza = kind u8 ‖ body_len u16 (≤ 4096) ‖ body
//! ```
//!
//! This module only parses and encodes bytes. It holds no keys and does
//! no cryptography: opening an envelope is a later layer.
//!
//! [`Envelope::parse`] accepts exactly one encoding for a given envelope:
//! stanzas strictly ascending by `kind ‖ body`, no two stanzas for the
//! same recipient identity, every known kind at its exact length, and no
//! trailing bytes. So `parse(b)?.to_bytes() == b` for every accepted `b`.
//! It borrows from its input and never allocates more than the bounded
//! stanza list, so it is safe on adversary-controlled bytes.
//!
//! # Example
//!
//! ```
//! use aion_context::envelope::Envelope;
//!
//! assert!(Envelope::parse(b"not an envelope").is_err());
//! ```

use crate::format::FRAME_HEADER_LEN;
use crate::{AionError, Result};

/// The 8-byte magic that opens every envelope.
pub const ENVELOPE_MAGIC: [u8; 8] = *b"AIONENV1";

/// The content key schedule this crate writes and reads (RFC-0039 suite
/// `0x01`: HKDF-SHA256 content key, ChaCha20-Poly1305).
pub const CONTENT_SUITE_V1: u8 = 0x01;

/// Most stanzas one envelope may carry.
pub const MAX_STANZAS: usize = 64;

/// Largest single stanza body, in bytes.
pub const MAX_STANZA_BODY: usize = 4096;

/// Largest total size of all stanzas, headers included, in bytes.
pub const MAX_STANZA_TOTAL: usize = 160 * 1024;

/// Stanza kind: HPKE recipient with DHKEM(X25519).
pub const STANZA_X25519: u8 = 0x01;

/// Stanza kind: external DEK wrapper (RFC-0039 Phase C).
pub const STANZA_EXTERNAL: u8 = 0x02;

/// Stanza kind: HPKE recipient with the X-Wing KEM (ML-KEM-768 + X25519).
pub const STANZA_XWING: u8 = 0x03;

/// Exact body length of an X25519 stanza: `pk[32] ‖ enc[32] ‖ wrapped[48]`.
pub const X25519_BODY_LEN: usize = 112;

/// Exact body length of an X-Wing stanza: `pk[1216] ‖ enc[1120] ‖ wrapped[48]`.
pub const XWING_BODY_LEN: usize = 2384;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const STANZA_HEADER_LEN: usize = 3;
const WRAPPED_DEK_LEN: usize = 48;
const MAX_PROVIDER_ID: usize = 64;
const MAX_KEY_REF: usize = 1024;
/// Magic, suite, DEK commitment, stanza count, nonce, and `ct_len`.
const FIXED_LEN: usize = 8 + 1 + 32 + 2 + NONCE_LEN + 8;

/// Shortest valid ciphertext: an empty frame header plus the AEAD tag.
pub const MIN_CIPHERTEXT_LEN: usize = FRAME_HEADER_LEN + TAG_LEN;

/// One recipient's wrapping of the DEK, as typed fields.
///
/// `#[non_exhaustive]` because RFC-0039 reserves kinds `0x04`–`0xFF` for
/// future recipient types; until a kind is defined it parses as
/// [`StanzaRecipient::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StanzaRecipient<'a> {
    /// Kind `0x01`: HPKE with DHKEM(X25519).
    X25519 {
        /// The recipient's X25519 public key.
        recipient_pk: &'a [u8; 32],
        /// The HPKE encapsulated key.
        enc: &'a [u8; 32],
        /// The DEK sealed under the HPKE context, tag included.
        wrapped_dek: &'a [u8; WRAPPED_DEK_LEN],
    },
    /// Kind `0x02`: a DEK wrapped by an external provider such as a KMS.
    External {
        /// Provider name, 1–64 bytes of UTF-8.
        provider_id: &'a str,
        /// Provider key reference, 1–1024 bytes of UTF-8.
        key_ref: &'a str,
        /// The provider's opaque wrapped DEK, at least one byte.
        blob: &'a [u8],
    },
    /// Kind `0x03`: HPKE with the X-Wing KEM.
    XWing {
        /// The recipient's X-Wing public key.
        recipient_pk: &'a [u8; 1216],
        /// The X-Wing ciphertext.
        enc: &'a [u8; 1120],
        /// The DEK sealed under the HPKE context, tag included.
        wrapped_dek: &'a [u8; WRAPPED_DEK_LEN],
    },
    /// A reserved kind this crate does not define. Readers skip it.
    Unknown {
        /// The stanza kind byte.
        kind: u8,
    },
}

/// One parsed stanza: its typed recipient and its exact body bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stanza<'a> {
    kind: u8,
    body: &'a [u8],
    recipient: StanzaRecipient<'a>,
}

impl<'a> Stanza<'a> {
    /// Validate a stanza body against its kind's layout.
    fn new(kind: u8, body: &'a [u8]) -> Result<Self> {
        if body.len() > MAX_STANZA_BODY {
            return Err(envelope_error("stanza body exceeds 4096 bytes"));
        }
        let recipient = match kind {
            STANZA_X25519 => parse_x25519(body)?,
            STANZA_EXTERNAL => parse_external(body)?,
            STANZA_XWING => parse_xwing(body)?,
            _ => StanzaRecipient::Unknown { kind },
        };
        Ok(Self {
            kind,
            body,
            recipient,
        })
    }

    /// The stanza kind byte.
    #[must_use]
    pub const fn kind(&self) -> u8 {
        self.kind
    }

    /// The stanza body exactly as stored.
    #[must_use]
    pub const fn body(&self) -> &'a [u8] {
        self.body
    }

    /// The stanza's typed fields.
    #[must_use]
    pub const fn recipient(&self) -> StanzaRecipient<'a> {
        self.recipient
    }

    /// The recipient identity used for duplicate detection: `(kind, pk)`
    /// for HPKE kinds, `(provider_id, key_ref)` for external wrappers,
    /// and `(kind, body)` for unknown kinds.
    const fn identity(&self) -> (u8, &'a [u8], &'a [u8]) {
        match self.recipient {
            StanzaRecipient::X25519 { recipient_pk, .. } => (self.kind, recipient_pk, &[]),
            StanzaRecipient::XWing { recipient_pk, .. } => (self.kind, recipient_pk, &[]),
            StanzaRecipient::External {
                provider_id,
                key_ref,
                ..
            } => (self.kind, provider_id.as_bytes(), key_ref.as_bytes()),
            StanzaRecipient::Unknown { .. } => (self.kind, self.body, &[]),
        }
    }
}

/// A parsed confidential envelope, borrowing from the section bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope<'a> {
    dek_commitment: &'a [u8; 32],
    stanzas: Vec<Stanza<'a>>,
    nonce: &'a [u8; NONCE_LEN],
    ciphertext: &'a [u8],
}

impl<'a> Envelope<'a> {
    /// Parse an envelope, accepting only its canonical encoding.
    ///
    /// # Errors
    ///
    /// Returns [`AionError::InvalidFormat`] for a wrong magic or suite, a
    /// stanza count outside `1..=64`, a stanza over its size limits or at
    /// the wrong length for its kind, stanzas out of canonical order or
    /// repeating a recipient identity, a ciphertext shorter than the
    /// frame header plus tag, truncation, or trailing bytes.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        if reader.array::<8>()? != &ENVELOPE_MAGIC {
            return Err(envelope_error("envelope magic is not AIONENV1"));
        }
        if reader.u8()? != CONTENT_SUITE_V1 {
            return Err(envelope_error("unknown envelope suite"));
        }
        let dek_commitment = reader.array::<32>()?;
        let count = usize::from(reader.u16()?);
        if count == 0 || count > MAX_STANZAS {
            return Err(envelope_error("stanza count outside 1..=64"));
        }
        let stanzas = parse_stanzas(&mut reader, count)?;
        let nonce = reader.array::<NONCE_LEN>()?;
        let ct_len = usize::try_from(reader.u64()?)
            .map_err(|_| envelope_error("ciphertext length overflows"))?;
        if ct_len < MIN_CIPHERTEXT_LEN {
            return Err(envelope_error("ciphertext shorter than frame and tag"));
        }
        let ciphertext = reader.take(ct_len)?;
        if !reader.is_empty() {
            return Err(envelope_error("trailing bytes after ciphertext"));
        }
        Ok(Self {
            dek_commitment,
            stanzas,
            nonce,
            ciphertext,
        })
    }

    /// The BLAKE3 commitment to this envelope's DEK.
    #[must_use]
    pub const fn dek_commitment(&self) -> &'a [u8; 32] {
        self.dek_commitment
    }

    /// The stanzas, in canonical order.
    #[must_use]
    pub fn stanzas(&self) -> &[Stanza<'a>] {
        &self.stanzas
    }

    /// The content AEAD nonce.
    #[must_use]
    pub const fn nonce(&self) -> &'a [u8; NONCE_LEN] {
        self.nonce
    }

    /// The content ciphertext, AEAD tag included.
    #[must_use]
    pub const fn ciphertext(&self) -> &'a [u8] {
        self.ciphertext
    }

    /// Serialize the envelope. For a parsed envelope this returns exactly
    /// the bytes it was parsed from.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let stanza_bytes: usize = self
            .stanzas
            .iter()
            .map(|s| s.body.len().saturating_add(STANZA_HEADER_LEN))
            .sum();
        let capacity = FIXED_LEN
            .saturating_add(stanza_bytes)
            .saturating_add(self.ciphertext.len());
        let mut out = Vec::with_capacity(capacity);
        out.extend_from_slice(&ENVELOPE_MAGIC);
        out.push(CONTENT_SUITE_V1);
        out.extend_from_slice(self.dek_commitment);
        // `parse` bounds the count to 64 and each body to 4096 bytes, so
        // neither conversion can saturate.
        out.extend_from_slice(
            &u16::try_from(self.stanzas.len())
                .unwrap_or(u16::MAX)
                .to_le_bytes(),
        );
        for stanza in &self.stanzas {
            out.push(stanza.kind);
            let body_len = u16::try_from(stanza.body.len()).unwrap_or(u16::MAX);
            out.extend_from_slice(&body_len.to_le_bytes());
            out.extend_from_slice(stanza.body);
        }
        out.extend_from_slice(self.nonce);
        out.extend_from_slice(&(self.ciphertext.len() as u64).to_le_bytes());
        out.extend_from_slice(self.ciphertext);
        out
    }
}

/// Encode an envelope from raw stanzas in any order.
///
/// Sorts the stanzas into canonical order, serializes, and re-parses the
/// result, so every [`Envelope::parse`] rule is enforced on what writers
/// produce.
///
/// # Errors
///
/// Returns [`AionError::InvalidFormat`] for any input that would not
/// parse: a bad count, size, kind layout, a duplicate recipient identity,
/// or a too-short ciphertext.
#[cfg_attr(not(test), allow(dead_code))] // RFC-0039 B3 writers are the first non-test caller.
pub(crate) fn encode_envelope(
    dek_commitment: &[u8; 32],
    mut stanzas: Vec<(u8, Vec<u8>)>,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let count =
        u16::try_from(stanzas.len()).map_err(|_| envelope_error("stanza count outside 1..=64"))?;
    stanzas.sort_by(|(ka, ba), (kb, bb)| ka.cmp(kb).then_with(|| ba.cmp(bb)));
    let mut out = Vec::new();
    out.extend_from_slice(&ENVELOPE_MAGIC);
    out.push(CONTENT_SUITE_V1);
    out.extend_from_slice(dek_commitment);
    out.extend_from_slice(&count.to_le_bytes());
    for (kind, body) in &stanzas {
        let body_len = u16::try_from(body.len())
            .map_err(|_| envelope_error("stanza body exceeds 4096 bytes"))?;
        out.push(*kind);
        out.extend_from_slice(&body_len.to_le_bytes());
        out.extend_from_slice(body);
    }
    out.extend_from_slice(nonce);
    out.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    out.extend_from_slice(ciphertext);
    Envelope::parse(&out)?;
    Ok(out)
}

fn parse_stanzas<'a>(reader: &mut Reader<'a>, count: usize) -> Result<Vec<Stanza<'a>>> {
    let mut stanzas: Vec<Stanza<'a>> = Vec::with_capacity(count);
    let mut total = 0usize;
    for _ in 0..count {
        let kind = reader.u8()?;
        let body_len = usize::from(reader.u16()?);
        if body_len > MAX_STANZA_BODY {
            return Err(envelope_error("stanza body exceeds 4096 bytes"));
        }
        total = total.saturating_add(STANZA_HEADER_LEN.saturating_add(body_len));
        if total > MAX_STANZA_TOTAL {
            return Err(envelope_error("stanzas exceed 160 KiB in total"));
        }
        let stanza = Stanza::new(kind, reader.take(body_len)?)?;
        if let Some(previous) = stanzas.last() {
            if (previous.kind, previous.body) >= (stanza.kind, stanza.body) {
                return Err(envelope_error("stanzas are not in canonical order"));
            }
            if previous.identity() == stanza.identity() {
                return Err(envelope_error("two stanzas for one recipient"));
            }
        }
        stanzas.push(stanza);
    }
    Ok(stanzas)
}

fn parse_x25519(body: &[u8]) -> Result<StanzaRecipient<'_>> {
    if body.len() != X25519_BODY_LEN {
        return Err(envelope_error("X25519 stanza body is not 112 bytes"));
    }
    let mut reader = Reader::new(body);
    Ok(StanzaRecipient::X25519 {
        recipient_pk: reader.array()?,
        enc: reader.array()?,
        wrapped_dek: reader.array()?,
    })
}

fn parse_xwing(body: &[u8]) -> Result<StanzaRecipient<'_>> {
    if body.len() != XWING_BODY_LEN {
        return Err(envelope_error("X-Wing stanza body is not 2384 bytes"));
    }
    let mut reader = Reader::new(body);
    Ok(StanzaRecipient::XWing {
        recipient_pk: reader.array()?,
        enc: reader.array()?,
        wrapped_dek: reader.array()?,
    })
}

fn parse_external(body: &[u8]) -> Result<StanzaRecipient<'_>> {
    let mut reader = Reader::new(body);
    let provider_len = usize::from(reader.u8()?);
    let provider_id = utf8_field(reader.take(provider_len)?, MAX_PROVIDER_ID)?;
    let key_ref_len = usize::from(reader.u16()?);
    let key_ref = utf8_field(reader.take(key_ref_len)?, MAX_KEY_REF)?;
    let blob_len = usize::from(reader.u16()?);
    let blob = reader.take(blob_len)?;
    if blob.is_empty() {
        return Err(envelope_error("external stanza blob is empty"));
    }
    if !reader.is_empty() {
        return Err(envelope_error("external stanza has trailing bytes"));
    }
    Ok(StanzaRecipient::External {
        provider_id,
        key_ref,
        blob,
    })
}

fn utf8_field(bytes: &[u8], max: usize) -> Result<&str> {
    if bytes.is_empty() || bytes.len() > max {
        return Err(envelope_error("external stanza field length out of range"));
    }
    std::str::from_utf8(bytes).map_err(|_| envelope_error("external stanza field is not UTF-8"))
}

fn envelope_error(reason: &str) -> AionError {
    AionError::InvalidFormat {
        reason: reason.to_string(),
    }
}

/// A bounds-checked cursor over adversary-controlled bytes.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        if len > self.rest.len() {
            return Err(envelope_error("envelope is truncated"));
        }
        let (head, tail) = self.rest.split_at(len);
        self.rest = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<&'a [u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| envelope_error("envelope is truncated"))
    }

    fn u8(&mut self) -> Result<u8> {
        let [byte] = *self.array::<1>()?;
        Ok(byte)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(*self.array::<2>()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(*self.array::<8>()?))
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    const COMMITMENT: [u8; 32] = [0xC0; 32];
    const NONCE: [u8; NONCE_LEN] = [0x0E; NONCE_LEN];

    fn ok<T>(result: Result<T>) -> T {
        result.unwrap_or_else(|_| std::process::abort())
    }

    fn hpke_body(len: usize, id: u8, fill: u8) -> Vec<u8> {
        let mut body = vec![fill; len];
        body[0] = id;
        body
    }

    fn x25519(id: u8) -> (u8, Vec<u8>) {
        (STANZA_X25519, hpke_body(X25519_BODY_LEN, id, 0x11))
    }

    fn xwing(id: u8) -> (u8, Vec<u8>) {
        (STANZA_XWING, hpke_body(XWING_BODY_LEN, id, 0x33))
    }

    fn external(provider: &str, key_ref: &str, blob: &[u8]) -> (u8, Vec<u8>) {
        let mut body = vec![u8::try_from(provider.len()).unwrap_or(u8::MAX)];
        body.extend_from_slice(provider.as_bytes());
        body.extend_from_slice(&u16::try_from(key_ref.len()).unwrap_or(0).to_le_bytes());
        body.extend_from_slice(key_ref.as_bytes());
        body.extend_from_slice(&u16::try_from(blob.len()).unwrap_or(0).to_le_bytes());
        body.extend_from_slice(blob);
        (STANZA_EXTERNAL, body)
    }

    fn ciphertext() -> Vec<u8> {
        vec![0xCC; MIN_CIPHERTEXT_LEN]
    }

    fn encode(stanzas: Vec<(u8, Vec<u8>)>) -> Result<Vec<u8>> {
        encode_envelope(&COMMITMENT, stanzas, &NONCE, &ciphertext())
    }

    #[test]
    fn layout_matches_the_rfc_byte_for_byte() {
        let bytes = ok(encode(vec![x25519(7)]));
        let ct_at = FIXED_LEN - 8 + STANZA_HEADER_LEN + X25519_BODY_LEN;
        assert_eq!(&bytes[..8], b"AIONENV1");
        assert_eq!(bytes[8], CONTENT_SUITE_V1);
        assert_eq!(&bytes[9..41], &COMMITMENT);
        assert_eq!(&bytes[41..43], &1u16.to_le_bytes());
        assert_eq!(bytes[43], STANZA_X25519);
        assert_eq!(&bytes[44..46], &112u16.to_le_bytes());
        assert_eq!(bytes[46], 7);
        assert_eq!(&bytes[158..170], &NONCE);
        assert_eq!(&bytes[ct_at..ct_at + 8], &24u64.to_le_bytes());
        assert_eq!(bytes.len(), ct_at + 8 + MIN_CIPHERTEXT_LEN);

        let envelope = ok(Envelope::parse(&bytes));
        assert_eq!(envelope.dek_commitment(), &COMMITMENT);
        assert_eq!(envelope.nonce(), &NONCE);
        assert_eq!(envelope.ciphertext(), ciphertext().as_slice());
        assert!(matches!(
            envelope.stanzas()[0].recipient(),
            StanzaRecipient::X25519 { recipient_pk, .. } if recipient_pk[0] == 7
        ));
    }

    #[test]
    fn writers_emit_canonical_order_whatever_the_input_order() {
        let stanzas = vec![
            xwing(1),
            (0x7F, vec![9]),
            x25519(2),
            external("kms", "key", b"blob"),
            x25519(1),
        ];
        let bytes = ok(encode(stanzas));
        let envelope = ok(Envelope::parse(&bytes));
        let kinds: Vec<u8> = envelope.stanzas().iter().map(Stanza::kind).collect();
        assert_eq!(kinds, vec![0x01, 0x01, 0x02, 0x03, 0x7F]);
        assert_eq!(envelope.stanzas()[0].body()[0], 1);
        assert_eq!(envelope.to_bytes(), bytes);
    }

    #[test]
    fn one_recipient_twice_is_rejected_even_with_different_enc() {
        let first = x25519(5);
        let mut second = x25519(5);
        second.1[40] ^= 0xFF;
        assert!(encode(vec![first, second]).is_err());

        let first = xwing(5);
        let mut second = xwing(5);
        second.1[2000] ^= 0xFF;
        assert!(encode(vec![first, second]).is_err());

        let first = external("kms", "key", b"a");
        let second = external("kms", "key", b"b");
        assert!(encode(vec![first, second]).is_err());
    }

    #[test]
    fn the_same_key_bytes_under_two_kinds_are_two_recipients() {
        assert!(encode(vec![x25519(5), (0x09, hpke_body(X25519_BODY_LEN, 5, 0x11))]).is_ok());
    }

    #[test]
    fn hpke_kinds_must_have_their_exact_length() {
        for len in [0, X25519_BODY_LEN - 1, X25519_BODY_LEN + 1] {
            assert!(encode(vec![(STANZA_X25519, vec![1; len])]).is_err());
        }
        for len in [X25519_BODY_LEN, XWING_BODY_LEN - 1, XWING_BODY_LEN + 1] {
            assert!(encode(vec![(STANZA_XWING, vec![1; len])]).is_err());
        }
    }

    #[test]
    fn external_stanzas_are_strict() {
        assert!(encode(vec![external("kms", "key", b"blob")]).is_ok());
        assert!(encode(vec![external("", "key", b"blob")]).is_err());
        assert!(encode(vec![external("kms", "", b"blob")]).is_err());
        assert!(encode(vec![external("kms", "key", b"")]).is_err());
        assert!(encode(vec![external(&"p".repeat(65), "key", b"blob")]).is_err());
        let (kind, mut body) = external("kms", "key", b"blob");
        body.push(0);
        assert!(encode(vec![(kind, body)]).is_err());
        let (kind, mut body) = external("kms", "key", b"blob");
        body[1] = 0xFF;
        assert!(encode(vec![(kind, body)]).is_err());
    }

    #[test]
    fn stanza_count_and_size_limits_hold() {
        assert!(encode(Vec::new()).is_err());
        let many: Vec<_> = (0..=64u8).map(x25519).collect();
        assert!(encode(many).is_err());
        let most: Vec<_> = (0..64u8).map(xwing).collect();
        assert!(encode(most).is_ok());
        let big = |n: u8| (0x80u8, hpke_body(MAX_STANZA_BODY, n, 0));
        assert!(encode((0..39u8).map(big).collect()).is_ok());
        assert!(encode((0..40u8).map(big).collect()).is_err());
        assert!(encode(vec![(0x80, vec![0; MAX_STANZA_BODY + 1])]).is_err());
    }

    #[test]
    fn short_ciphertext_and_trailing_bytes_are_rejected() {
        let short = encode_envelope(&COMMITMENT, vec![x25519(1)], &NONCE, &[0; 23]);
        assert!(short.is_err());
        let mut bytes = ok(encode(vec![x25519(1)]));
        bytes.push(0);
        assert!(Envelope::parse(&bytes).is_err());
    }

    #[test]
    fn wrong_magic_or_suite_is_rejected() {
        let bytes = ok(encode(vec![x25519(1)]));
        for index in [0usize, 7, 8] {
            let mut tampered = bytes.clone();
            tampered[index] ^= 0x01;
            assert!(Envelope::parse(&tampered).is_err());
        }
    }

    #[test]
    fn every_strict_prefix_is_rejected() {
        let bytes = ok(encode(vec![x25519(1), external("kms", "key", b"blob")]));
        for len in 0..bytes.len() {
            assert!(Envelope::parse(&bytes[..len]).is_err(), "prefix {len}");
        }
    }

    #[test]
    fn swapped_stanzas_are_not_canonical() {
        let bytes = ok(encode(vec![x25519(1), x25519(2)]));
        let start = FIXED_LEN - 8 - NONCE_LEN;
        let stanza_len = STANZA_HEADER_LEN + X25519_BODY_LEN;
        let mut swapped = bytes.clone();
        swapped[start..start + stanza_len]
            .copy_from_slice(&bytes[start + stanza_len..start + 2 * stanza_len]);
        swapped[start + stanza_len..start + 2 * stanza_len]
            .copy_from_slice(&bytes[start..start + stanza_len]);
        assert_ne!(swapped, bytes);
        assert!(Envelope::parse(&swapped).is_err());
    }

    mod properties {
        use super::*;
        use hegel::generators as gs;

        #[hegel::test]
        fn prop_envelope_parse_never_panics_on_arbitrary_bytes(tc: hegel::TestCase) {
            let bytes = tc.draw(gs::binary().max_size(8192));
            if let Ok(envelope) = Envelope::parse(&bytes) {
                assert_eq!(envelope.to_bytes(), bytes);
            }
        }

        fn draw_stanza(tc: &hegel::TestCase, id: u8) -> (u8, Vec<u8>) {
            let choice = tc.draw(gs::integers::<u8>().max_value(3));
            let (kind, len) = match choice {
                0 => (STANZA_X25519, X25519_BODY_LEN),
                1 => (STANZA_XWING, XWING_BODY_LEN),
                2 => (STANZA_EXTERNAL, 0),
                _ => (tc.draw(gs::integers::<u8>().min_value(4)), 0),
            };
            if kind == STANZA_EXTERNAL {
                let blob = tc.draw(gs::binary().min_size(1).max_size(64));
                return external(&format!("p{id}"), "key", &blob);
            }
            let mut body = if len == 0 {
                tc.draw(gs::binary().max_size(64))
            } else {
                tc.draw(gs::binary().min_size(len).max_size(len))
            };
            body.insert(0, id);
            if len != 0 {
                body.truncate(len);
            }
            (kind, body)
        }

        #[hegel::test]
        fn prop_encode_parse_round_trip_in_canonical_order(tc: hegel::TestCase) {
            let n = tc.draw(gs::integers::<u8>().min_value(1).max_value(8));
            let stanzas: Vec<_> = (0..n).map(|id| draw_stanza(&tc, id)).collect();
            let ct = tc.draw(gs::binary().min_size(MIN_CIPHERTEXT_LEN).max_size(256));
            let bytes = encode_envelope(&COMMITMENT, stanzas.clone(), &NONCE, &ct)
                .unwrap_or_else(|_| std::process::abort());
            let envelope = Envelope::parse(&bytes).unwrap_or_else(|_| std::process::abort());

            let mut expected = stanzas;
            expected.sort();
            let parsed: Vec<(u8, Vec<u8>)> = envelope
                .stanzas()
                .iter()
                .map(|s| (s.kind(), s.body().to_vec()))
                .collect();
            assert_eq!(parsed, expected);
            assert_eq!(envelope.ciphertext(), ct.as_slice());
            assert_eq!(envelope.to_bytes(), bytes);
        }

        #[hegel::test]
        fn prop_a_mutated_envelope_is_rejected_or_still_canonical(tc: hegel::TestCase) {
            let bytes = encode(vec![x25519(1), x25519(2), external("kms", "key", b"blob")])
                .unwrap_or_else(|_| std::process::abort());
            let index = tc.draw(gs::integers::<usize>().max_value(bytes.len().saturating_sub(1)));
            let flip = tc.draw(gs::integers::<u8>().min_value(1));
            let mut mutated = bytes;
            mutated[index] ^= flip;
            if let Ok(envelope) = Envelope::parse(&mutated) {
                assert_eq!(envelope.to_bytes(), mutated);
            }
        }
    }
}
