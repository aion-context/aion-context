// SPDX-License-Identifier: MIT OR Apache-2.0
//! Internal helpers for structured tracing emits.
//!
//! Per `.claude/rules/observability.md`, every tracing field has bounded
//! cardinality. Hashes and pubkeys are truncated to a 16-hex-char prefix
//! (64 bits) — enough for log correlation, small enough to keep lines
//! scannable. This module centralizes the formatting so every emit
//! across the crate uses the same shape.
//!
//! Library code never installs a `tracing` subscriber. The `aion` CLI
//! binary owns subscriber configuration via `AION_LOG` /
//! `AION_LOG_FORMAT`.

use crate::types::AuthorId;

/// Number of hex characters retained when truncating a hash or pubkey
/// for a log field. 16 chars = 64 bits of entropy — collision-resistant
/// for correlation, well-bounded for log-store cardinality.
pub const SHORT_HEX_LEN: usize = 16;

/// Format the leading bytes of a hash or pubkey as a stable
/// 16-hex-char string. Always returns exactly `SHORT_HEX_LEN` chars
/// regardless of input length: shorter inputs are zero-padded on the
/// right, longer inputs are truncated.
///
/// Use this in any `tracing::*!` field that would otherwise contain
/// 64 hex chars of a BLAKE3 digest or pubkey — see the cardinality
/// section of the observability rule.
pub fn short_hex(bytes: &[u8]) -> String {
    let take = bytes.len().min(SHORT_HEX_LEN / 2);
    let mut s = hex::encode(bytes.get(..take).unwrap_or(&[]));
    while s.len() < SHORT_HEX_LEN {
        s.push('0');
    }
    s
}

/// Format an `AuthorId` for a tracing field. Renders the lower 64 bits
/// as 16 hex chars so the field shape matches the convention used for
/// pubkeys and hashes.
pub fn author_short(author: AuthorId) -> String {
    format!("{:016x}", author.as_u64())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_hex_truncates_long_input() {
        let bytes = [0xAB; 32];
        let s = short_hex(&bytes);
        assert_eq!(s.len(), SHORT_HEX_LEN);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn short_hex_pads_short_input() {
        let s = short_hex(&[0x12, 0x34]);
        assert_eq!(s.len(), SHORT_HEX_LEN);
        assert!(s.starts_with("1234"));
    }

    #[test]
    fn short_hex_handles_empty() {
        let s = short_hex(&[]);
        assert_eq!(s.len(), SHORT_HEX_LEN);
        assert_eq!(s, "0".repeat(SHORT_HEX_LEN));
    }

    #[test]
    fn author_short_is_16_chars() {
        let s = author_short(AuthorId::new(0x12_34_56_78_9A_BC_DE_F0));
        assert_eq!(s, "123456789abcdef0");
    }
}
