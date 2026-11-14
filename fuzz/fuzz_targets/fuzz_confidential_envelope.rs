// SPDX-License-Identifier: MIT OR Apache-2.0
//! Confidential-envelope parser fuzz target (RFC-0039 Phase B1).
//!
//! Pairs with the Hegel property
//! `prop_envelope_parse_never_panics_on_arbitrary_bytes` in
//! `src/envelope.rs`. Both claim that `Envelope::parse` is total over
//! `&[u8]` and accepts only canonical encodings: any accepted input
//! re-serializes to exactly the same bytes.
//!
//! Seeds in `fuzz/seeds/fuzz_confidential_envelope/` cover every stanza
//! kind.

#![no_main]

use libfuzzer_sys::fuzz_target;

use aion_context::envelope::{Envelope, StanzaRecipient};

fuzz_target!(|data: &[u8]| {
    let Ok(envelope) = Envelope::parse(data) else {
        return;
    };
    assert_eq!(envelope.to_bytes(), data, "accepted a non-canonical envelope");
    for stanza in envelope.stanzas() {
        if let StanzaRecipient::External { provider_id, key_ref, blob } = stanza.recipient() {
            assert!(!provider_id.is_empty() && !key_ref.is_empty() && !blob.is_empty());
        }
    }
});
