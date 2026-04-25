// SPDX-License-Identifier: MIT OR Apache-2.0
//! RFC 8785 JSON Canonicalization Scheme — RFC-0031.
//!
//! Thin wrapper around [`serde_jcs`] with aion-typed errors. Use
//! this module when you need JSON bytes that are identical
//! across Rust, Go, Python, JavaScript, and any other JCS-conformant
//! implementation for the same logical document.
//!
//! This module is **additive**. Existing `canonical_bytes()` methods
//! on [`crate::slsa::InTotoStatement`], [`crate::aibom::AiBom`], and
//! [`crate::oci::OciArtifactManifest`] keep their current
//! (serde-declaration-order) semantics so historical DSSE-signed
//! envelopes continue to verify. Reach for JCS at new call sites —
//! content-addressed catalogs, transparency-log entries, multi-
//! implementation reproducibility audits.
//!
//! # Example
//!
//! ```
//! use aion_context::jcs;
//! use serde_json::json;
//!
//! let v = json!({ "b": 1, "a": 2 });
//! let bytes = jcs::to_jcs_bytes(&v).unwrap();
//! // Keys emerge in lexicographic UTF-16 order.
//! assert_eq!(bytes, b"{\"a\":2,\"b\":1}");
//! ```

use serde::Serialize;

use crate::{AionError, Result};

/// Serialize any `serde::Serialize` value to RFC 8785 canonical
/// JSON bytes.
///
/// # Errors
///
/// Returns `Err` if the value fails to serialize via serde.
pub fn to_jcs_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_jcs::to_vec(value).map_err(|e| AionError::InvalidFormat {
        reason: format!("JCS serialization failed: {e}"),
    })
}

/// Canonicalize existing JSON bytes.
///
/// Parses `bytes` into a `serde_json::Value` and re-emits it in
/// RFC 8785 canonical form. Safe to feed any UTF-8 JSON document.
///
/// # Errors
///
/// Returns `Err` if the input is not valid JSON or the canonical
/// re-emission fails.
pub fn canonicalize_json_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| AionError::InvalidFormat {
            reason: format!("JCS input is not valid JSON: {e}"),
        })?;
    to_jcs_bytes(&value)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_are_sorted_lex() {
        let v = json!({ "c": 3, "a": 1, "b": 2 });
        let bytes = to_jcs_bytes(&v).unwrap();
        assert_eq!(bytes, br#"{"a":1,"b":2,"c":3}"#);
    }

    #[test]
    fn arrays_preserve_order() {
        let v = json!([3, 1, 2]);
        let bytes = to_jcs_bytes(&v).unwrap();
        assert_eq!(bytes, b"[3,1,2]");
    }

    #[test]
    fn empty_object_and_array() {
        assert_eq!(to_jcs_bytes(&json!({})).unwrap(), b"{}");
        assert_eq!(to_jcs_bytes(&json!([])).unwrap(), b"[]");
    }

    #[test]
    fn canonicalize_bytes_round_trip_reorders_keys() {
        let raw = br#"{"z":1,"a":2}"#;
        let canonical = canonicalize_json_bytes(raw).unwrap();
        assert_eq!(canonical, br#"{"a":2,"z":1}"#);
    }

    #[test]
    fn canonicalize_rejects_invalid_json() {
        assert!(canonicalize_json_bytes(b"{not json").is_err());
    }

    #[test]
    fn idempotent_on_already_canonical_json() {
        let v = json!({"a": 1, "b": [true, false, null]});
        let once = to_jcs_bytes(&v).unwrap();
        let twice = canonicalize_json_bytes(&once).unwrap();
        assert_eq!(once, twice);
    }

    mod properties {
        use super::*;
        use hegel::generators as gs;

        /// Largest integer safely representable in an ECMAScript
        /// `Number` (`2^53 - 1`). JCS formats numbers through
        /// ECMAScript rules, so integers outside this range do not
        /// survive a JCS → parse round-trip as the same `i64` value.
        const JS_MAX_SAFE_INTEGER: i64 = (1_i64 << 53) - 1;
        const JS_MIN_SAFE_INTEGER: i64 = -JS_MAX_SAFE_INTEGER;

        fn draw_value(tc: &hegel::TestCase) -> serde_json::Value {
            // Build an object with 0..6 string-keyed primitive entries.
            let n = tc.draw(gs::integers::<usize>().max_value(6));
            let mut map = serde_json::Map::new();
            let mut counter: u64 = 0;
            for _ in 0..n {
                let key = format!("k_{counter}");
                counter = counter.saturating_add(1);
                let pick = tc.draw(gs::integers::<u8>().max_value(3));
                let value = match pick {
                    0 => serde_json::Value::Null,
                    1 => serde_json::Value::Bool(tc.draw(gs::booleans())),
                    2 => serde_json::Value::String(tc.draw(gs::text().max_size(16))),
                    _ => serde_json::Value::from(
                        tc.draw(
                            gs::integers::<i64>()
                                .min_value(JS_MIN_SAFE_INTEGER)
                                .max_value(JS_MAX_SAFE_INTEGER),
                        ),
                    ),
                };
                map.insert(key, value);
            }
            serde_json::Value::Object(map)
        }

        #[hegel::test]
        fn prop_jcs_idempotent(tc: hegel::TestCase) {
            let value = draw_value(&tc);
            let once = to_jcs_bytes(&value).unwrap_or_else(|_| std::process::abort());
            let twice = canonicalize_json_bytes(&once).unwrap_or_else(|_| std::process::abort());
            assert_eq!(once, twice);
        }

        #[hegel::test]
        fn prop_jcs_keys_sorted(tc: hegel::TestCase) {
            let value = draw_value(&tc);
            let bytes = to_jcs_bytes(&value).unwrap_or_else(|_| std::process::abort());
            // Parse back and verify top-level keys in lex order.
            let parsed: serde_json::Value =
                serde_json::from_slice(&bytes).unwrap_or_else(|_| std::process::abort());
            if let serde_json::Value::Object(map) = parsed {
                let keys: Vec<&String> = map.keys().collect();
                for window in keys.windows(2) {
                    assert!(window[0] <= window[1]);
                }
            }
        }

        #[hegel::test]
        fn prop_jcs_no_whitespace_between_tokens(tc: hegel::TestCase) {
            // Build a nested object to expose any inter-token whitespace.
            let value = serde_json::json!({
                "outer": draw_value(&tc),
                "array": [1, "two", true, null],
            });
            let bytes = to_jcs_bytes(&value).unwrap_or_else(|_| std::process::abort());
            // Track whether we're inside a string.
            let mut in_string = false;
            let mut escaped = false;
            for &byte in &bytes {
                if in_string {
                    if escaped {
                        escaped = false;
                    } else if byte == b'\\' {
                        escaped = true;
                    } else if byte == b'"' {
                        in_string = false;
                    }
                    continue;
                }
                if byte == b'"' {
                    in_string = true;
                    continue;
                }
                // Outside a string, RFC 8785 forbids whitespace.
                assert!(
                    byte != b' ' && byte != b'\t' && byte != b'\n' && byte != b'\r',
                    "found whitespace outside string at byte {byte}"
                );
            }
        }

        #[hegel::test]
        fn prop_jcs_parse_roundtrip_semantic(tc: hegel::TestCase) {
            let value = draw_value(&tc);
            let bytes = to_jcs_bytes(&value).unwrap_or_else(|_| std::process::abort());
            let parsed: serde_json::Value =
                serde_json::from_slice(&bytes).unwrap_or_else(|_| std::process::abort());
            assert_eq!(parsed, value);
        }

        #[hegel::test]
        fn prop_jcs_reordering_input_preserves_output(tc: hegel::TestCase) {
            // Same Value built two different ways:
            //   forward:  inserted in lex order
            //   reverse:  inserted in reverse lex order
            // JCS must produce the same bytes.
            let n = tc.draw(gs::integers::<usize>().min_value(1).max_value(6));
            let pairs: Vec<(String, i64)> = (0..n)
                .map(|i| {
                    (
                        format!("k_{i:02}"),
                        tc.draw(
                            gs::integers::<i64>()
                                .min_value(JS_MIN_SAFE_INTEGER)
                                .max_value(JS_MAX_SAFE_INTEGER),
                        ),
                    )
                })
                .collect();

            let mut forward = serde_json::Map::new();
            for (k, v) in &pairs {
                forward.insert(k.clone(), serde_json::Value::from(*v));
            }
            let mut reverse = serde_json::Map::new();
            for (k, v) in pairs.iter().rev() {
                reverse.insert(k.clone(), serde_json::Value::from(*v));
            }
            let a = to_jcs_bytes(&serde_json::Value::Object(forward))
                .unwrap_or_else(|_| std::process::abort());
            let b = to_jcs_bytes(&serde_json::Value::Object(reverse))
                .unwrap_or_else(|_| std::process::abort());
            assert_eq!(a, b);
        }
    }
}
