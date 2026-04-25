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
    // Round-trip identity (post-#40): every Ok parse must
    // canonicalise, re-parse, and yield identical bytes AND
    // identical manifest_id. The strict reserved-field validation
    // closed the previous round-trip gap.
    let bytes = manifest.canonical_bytes();
    let reparsed = ArtifactManifest::from_canonical_bytes(&bytes)
        .expect("re-parse of canonical bytes must succeed");
    assert_eq!(
        manifest.manifest_id(),
        reparsed.manifest_id(),
        "round-trip must preserve manifest_id (#40)"
    );
    assert_eq!(
        bytes,
        reparsed.canonical_bytes(),
        "round-trip must be byte-identical (#40)"
    );
});
