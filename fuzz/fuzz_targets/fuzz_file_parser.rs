//! Parser-totality fuzz target.
//!
//! Pairs with the Hegel property
//! `prop_parser_new_never_panics_on_arbitrary_bytes` in
//! `src/parser.rs`: both make the same claim — `AionParser::new()`
//! must never panic on adversary-supplied bytes. Property tests
//! shrink to minimal counterexamples on every commit; fuzz drives
//! deeper for minutes-to-hours.
//!
//! Exercises:
//!   1. `AionParser::new(arbitrary)` — must return `Ok` or `Err`,
//!      never panic.
//!   2. On `Ok`, every accessor (header, integrity_hash,
//!      audit_trail_bytes, get_version_entry, get_signature_entry)
//!      must also be panic-free.
//!   3. `verify_integrity` must be panic-free.
//!
//! Tiger Style claim: the entire parser surface is total over `&[u8]`.

#![no_main]

use libfuzzer_sys::fuzz_target;

use aion_context::parser::AionParser;

fuzz_target!(|data: &[u8]| {
    let parser = match AionParser::new(data) {
        Ok(p) => p,
        Err(_) => return,
    };

    // Header is always available on a constructed parser.
    let _ = parser.header();

    // Integrity hash + verify must not panic even when payloads disagree.
    let _ = parser.integrity_hash();
    let _ = parser.verify_integrity();

    // Audit-trail bytes — variable length, drives the parser's
    // bounds checks.
    let _ = parser.audit_trail_bytes();

    // Iterate version + signature entries within the declared count.
    // Cap the loop at a sane upper bound so the fuzzer doesn't get
    // stuck on a header that claims billions of versions.
    let header = parser.header();
    let cap = (header.version_chain_count as usize).min(64);
    for i in 0..cap {
        let _ = parser.get_version_entry(i);
        let _ = parser.get_signature_entry(i);
    }

    // Also probe one out-of-bounds access — must Err, not panic.
    let _ = parser.get_version_entry(usize::MAX);
    let _ = parser.get_signature_entry(usize::MAX);
});
