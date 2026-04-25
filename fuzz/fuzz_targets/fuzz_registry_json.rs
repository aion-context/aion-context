//! `KeyRegistry::from_trusted_json` totality fuzz target.
//!
//! Loads operator-supplied registry JSON (the same format
//! `aion registry pin` writes). Adversary control over this file
//! is realistic — registries are often passed across trust
//! boundaries — so the parser must reject every malformed input
//! cleanly rather than panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

use aion_context::key_registry::KeyRegistry;
use aion_context::types::AuthorId;

fuzz_target!(|data: &[u8]| {
    // Convert bytes to UTF-8 — non-UTF-8 should reject at the
    // `from_str` stage. The `from_trusted_json` boundary takes
    // `&str`, so feeding non-UTF-8 isn't part of the contract.
    let s = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    let reg = match KeyRegistry::from_trusted_json(s) {
        Ok(r) => r,
        Err(_) => return,
    };

    // On Ok, accessors must be panic-free for arbitrary author / version queries.
    let _ = reg.master_key(AuthorId::new(0));
    let _ = reg.master_key(AuthorId::new(u64::MAX));
    let _ = reg.active_epoch_at(AuthorId::new(0), 0);
    let _ = reg.active_epoch_at(AuthorId::new(u64::MAX), u64::MAX);

    // Round-trip — to_trusted_json must succeed and re-parse to
    // an equivalent registry (existence, no panics).
    if let Ok(out) = reg.to_trusted_json() {
        let _ = KeyRegistry::from_trusted_json(&out);
    }
});
