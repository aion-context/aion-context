// SPDX-License-Identifier: MIT OR Apache-2.0
//! Verified-chain totality fuzz target (RFC-0039).
//!
//! `VerifiedChain::from_bytes` runs every `verify_file` check: the
//! format-v2 and format-v3 signed messages, version hashes, the v3
//! rules commitment, and the v3 rules framing. It must return `Ok` or
//! `Err` on adversary bytes, never panic.
//!
//! The registry pins one fixed fuzz-only key, so the seeds in
//! `corpus/fuzz_verify_chain` (signed with that key) reach the checks
//! that run after signature verification. Mutations then explore the
//! commitment, framing, and mode-byte checks.
//!
//! Exercises:
//!   1. `format::unframe_rules(arbitrary)`.
//!   2. `VerifiedChain::from_bytes(arbitrary, &registry)`.
//!   3. On `Ok`, every `VerifiedEntry` accessor and
//!      `open_current_rules`.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

use aion_context::chain::{open_current_rules, RecipientKeys, VerifiedChain};
use aion_context::crypto::SigningKey;
use aion_context::format::unframe_rules;
use aion_context::key_registry::KeyRegistry;
use aion_context::types::AuthorId;

/// Fuzz-only key material. Never use outside this target.
const FUZZ_OPERATIONAL_SEED: [u8; 32] = [0x11; 32];
const FUZZ_MASTER_SEED: [u8; 32] = [0x22; 32];
const FUZZ_AUTHOR: u64 = 1;

fn registry() -> Option<&'static KeyRegistry> {
    static REGISTRY: OnceLock<Option<KeyRegistry>> = OnceLock::new();
    REGISTRY
        .get_or_init(|| {
            let op = SigningKey::from_bytes(&FUZZ_OPERATIONAL_SEED).ok()?;
            let master = SigningKey::from_bytes(&FUZZ_MASTER_SEED).ok()?;
            let mut reg = KeyRegistry::new();
            reg.register_author(
                AuthorId::new(FUZZ_AUTHOR),
                master.verifying_key(),
                op.verifying_key(),
                0,
            )
            .ok()?;
            Some(reg)
        })
        .as_ref()
}

fuzz_target!(|data: &[u8]| {
    let _ = unframe_rules(data);

    let Some(registry) = registry() else {
        return;
    };
    let Ok(chain) = VerifiedChain::from_bytes(data, registry) else {
        return;
    };

    let _ = chain.context();
    let _ = chain.version_count();
    for entry in chain.entries() {
        let _ = entry.version();
        let _ = entry.author();
        let _ = entry.timestamp();
        let _ = entry.rules_commitment();
        let _ = entry.rules_mode();
        let _ = entry.version_hash();
    }
    let _ = open_current_rules(&chain, &RecipientKeys::none());
});
