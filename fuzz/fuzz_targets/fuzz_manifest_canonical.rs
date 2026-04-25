//! `ArtifactManifest::from_canonical_bytes` totality fuzz target.
//!
//! The function was added in PR #32 (issue #28) for sealed-release
//! reconstruction and parses a `MANIFEST_DOMAIN || entry_count_le ||
//! entries || name_table` layout. Like every other parse path in
//! aion-context, it must return `Err` on adversary input — never
//! panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

use aion_context::manifest::ArtifactManifest;

fuzz_target!(|data: &[u8]| {
    let manifest = match ArtifactManifest::from_canonical_bytes(data) {
        Ok(m) => m,
        Err(_) => return,
    };

    // Accessor sweep — totality. None may panic on adversary input.
    let _ = manifest.entries();
    let _ = manifest.name_table();
    let _ = manifest.manifest_id();
    for entry in manifest.entries() {
        let _ = manifest.name_of(entry);
    }
    // Re-serialise and re-parse — must not panic in either direction.
    // Round-trip identity is intentionally NOT asserted here; the
    // parser silently zeros reserved fields, so input bytes with
    // non-zero reserved produce a different manifest_id on re-parse.
    // That correctness gap is tracked separately; fuzz only checks
    // totality.
    let bytes = manifest.canonical_bytes();
    let _ = ArtifactManifest::from_canonical_bytes(&bytes);
});
