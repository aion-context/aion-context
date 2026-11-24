// SPDX-License-Identifier: MIT OR Apache-2.0
//! Hybrid-signature verify fuzz target (RFC-0041).
//!
//! Feeds arbitrary payload, Ed25519 and ML-DSA-65 signature bytes to
//! `HybridVerifyingKey::verify` under a fixed key pair. The claim is
//! that verification is total: it never panics, whatever the
//! signature bytes. If the fuzzer ever produces an accepted input, the
//! target also checks that a fresh signature over that payload
//! verifies. It is not a forgery oracle.
//!
//! The key is derived from constant seeds, so it is public by
//! construction and proves nothing outside this target (see the
//! fuzz-only key exception in `.claude/rules/crypto.md`).
//!
//! Input layout: 2-byte payload length (little-endian, capped at the
//! input), the payload, 64 Ed25519 bytes, then the ML-DSA bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;

use aion_context::crypto::SigningKey;
use aion_context::hybrid_sig::{HybridSignature, HybridSigningKey, PqAlgorithm};

const CLASSICAL_SEED: [u8; 32] = [0xF0; 32];
const PQ_SEED: [u8; 32] = [0x0F; 32];

fuzz_target!(|data: &[u8]| {
    let Some((len, rest)) = data.split_first_chunk::<2>() else {
        return;
    };
    let payload_len = usize::from(u16::from_le_bytes(*len)).min(rest.len());
    let (payload, rest) = rest.split_at(payload_len);
    let Some((classical, pq)) = rest.split_first_chunk::<64>() else {
        return;
    };
    let Ok(classical_key) = SigningKey::from_bytes(&CLASSICAL_SEED) else {
        return;
    };
    let key = HybridSigningKey::from_seeds(classical_key, &PQ_SEED);
    let sig = HybridSignature {
        algorithm: PqAlgorithm::MlDsa65,
        classical: *classical,
        pq: pq.to_vec(),
    };
    if key.verifying_key().verify(payload, &sig).is_ok() {
        let Ok(fresh) = key.sign(payload) else {
            return;
        };
        assert!(key.verifying_key().verify(payload, &fresh).is_ok());
    }
});
