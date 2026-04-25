// SPDX-License-Identifier: MIT OR Apache-2.0
//! Federated Model Exchange — cross-organization aion deployments
//! with hardware-attestation-bound signing keys (RFC-0026), each
//! maintaining its own `KeyRegistry`, cross-verifying joint
//! releases across trust domains.
//!
//! Scenario:
//!   - **Helios Labs** (Singapore) runs its own aion deployment.
//!     Its signers' operational keys live in TPM2 quotes.
//!   - **Polaris Research** (Berlin) runs an independent aion
//!     deployment. Its keys live in Intel TDX reports.
//!   - The two labs co-publish a joint foundation model. Each lab
//!     signs its OWN attestation of the release. Each lab's verifier
//!     loads the OTHER lab's registry (out-of-band trust bootstrap)
//!     and cross-verifies.
//!
//! Phases:
//!   A. Helios bootstraps: master + op keys + TPM2 attestation binding
//!      for 2 signers; registers them in helios_registry.
//!   B. Polaris bootstraps: master + op keys + TDX binding for 2
//!      signers; registers them in polaris_registry.
//!   C. Joint release — 1 signer from each lab attests. Helios uses
//!      polaris_registry (out-of-band) to verify the Polaris sig;
//!      Polaris uses helios_registry to verify Helios's sig. Both
//!      independently confirm validity.
//!   D. Firmware vulnerability disclosed for Helios's TPM batch.
//!      A verifier that now REJECTS the TPM evidence (simulating
//!      Polaris's policy update) refuses Helios's binding →
//!      the joint release is no longer trusted by Polaris even
//!      though the signatures still verify cryptographically.
//!
//! This is the RFC-0026 + RFC-0028 + federated-trust story in one
//! runnable narrative.
//!
//! Run:
//!
//! ```text
//! cargo run --release --example federation_hw_attest --features test-helpers
//! ```
//!
//! The `test-helpers` feature gates the `PubkeyPrefixEvidenceVerifier`
//! and `RejectAllEvidenceVerifier` test doubles used here as
//! stand-ins for real platform verifiers (NRAS, DCAP, Azure
//! Attestation, ...).

// Examples are demonstrations, not production code — match the
// benches/integration-tests posture on Tiger Style lints. The library
// itself remains panic-free.
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::useless_vec)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::doc_markdown)]

use aion_context::crypto::{hash, SigningKey};
use aion_context::hw_attestation::{
    sign_binding, verify_binding, verify_binding_signature, AttestationEvidence, AttestationKind,
    KeyAttestationBinding, PubkeyPrefixEvidenceVerifier, RejectAllEvidenceVerifier,
};
use aion_context::key_registry::KeyRegistry;
use aion_context::serializer::VersionEntry;
use aion_context::signature_chain::{sign_attestation, verify_attestation};
use aion_context::types::{AuthorId, VersionNumber};

fn banner(s: &str) {
    println!();
    println!("╔═══════════════════════════════════════════════════════════════════════╗");
    println!("║ {s:<69} ║");
    println!("╚═══════════════════════════════════════════════════════════════════════╝");
}

fn step(s: &str) {
    println!("  • {s}");
}

struct Signer {
    role: &'static str,
    author: AuthorId,
    master: SigningKey,
    operational: SigningKey,
    kind: AttestationKind,
}

impl Signer {
    fn new(role: &'static str, author_id: u64, kind: AttestationKind) -> Self {
        Self {
            role,
            author: AuthorId::new(author_id),
            master: SigningKey::generate(),
            operational: SigningKey::generate(),
            kind,
        }
    }

    /// Build evidence whose first 32 bytes are the operational
    /// public key — the `PubkeyPrefixEvidenceVerifier` accepts this
    /// shape as a stand-in for "the TEE quote contains the attested
    /// pubkey."
    fn evidence(&self) -> AttestationEvidence {
        let pk = self.operational.verifying_key().to_bytes();
        let mut bytes = pk.to_vec();
        bytes.extend_from_slice(b"--tee-quote-body--");
        AttestationEvidence {
            kind: self.kind,
            nonce: [0u8; 32],
            evidence: bytes,
        }
    }

    fn binding(&self) -> KeyAttestationBinding {
        sign_binding(
            self.author,
            0,
            self.operational.verifying_key().to_bytes(),
            self.evidence(),
            &self.master,
        )
    }
}

fn make_version(n: u64, author: AuthorId, rules_hash: [u8; 32]) -> VersionEntry {
    VersionEntry::new(
        VersionNumber(n),
        [0u8; 32],
        rules_hash,
        author,
        1_700_000_000_000_000_000u64,
        0,
        0,
    )
}

fn build_registry(signers: &[&Signer]) -> KeyRegistry {
    let mut reg = KeyRegistry::new();
    for s in signers {
        reg.register_author(
            s.author,
            s.master.verifying_key(),
            s.operational.verifying_key(),
            0,
        )
        .unwrap_or_else(|e| {
            eprintln!("register_author({}): {e}", s.role);
            std::process::exit(1);
        });
    }
    reg
}

fn main() {
    // ---------- Phase A: Helios Labs bootstraps ---------------------
    banner("Phase A — Helios Labs (Singapore) bootstrap");
    let helios_lead = Signer::new("Helios Research Lead", 700_001, AttestationKind::Tpm2Quote);
    let helios_sec = Signer::new("Helios Security Eng", 700_002, AttestationKind::Tpm2Quote);

    let helios_registry = build_registry(&[&helios_lead, &helios_sec]);
    let helios_bindings = vec![helios_lead.binding(), helios_sec.binding()];
    step("Registered 2 authors in Helios registry");
    for (s, b) in [&helios_lead, &helios_sec]
        .iter()
        .zip(helios_bindings.iter())
    {
        step(&format!(
            "  {} | author={} | kind={:?} | evidence {} B | master sig verifies: {}",
            s.role,
            s.author.as_u64(),
            b.evidence.kind,
            b.evidence.evidence.len(),
            verify_binding_signature(b, &s.master.verifying_key()).is_ok()
        ));
    }

    // ---------- Phase B: Polaris Research bootstraps ----------------
    banner("Phase B — Polaris Research (Berlin) bootstrap");
    let polaris_lead = Signer::new(
        "Polaris Chief Scientist",
        800_001,
        AttestationKind::IntelTdxReport,
    );
    let polaris_sec = Signer::new(
        "Polaris Security Lead",
        800_002,
        AttestationKind::IntelTdxReport,
    );

    let polaris_registry = build_registry(&[&polaris_lead, &polaris_sec]);
    let polaris_bindings = vec![polaris_lead.binding(), polaris_sec.binding()];
    step("Registered 2 authors in Polaris registry");
    for (s, b) in [&polaris_lead, &polaris_sec]
        .iter()
        .zip(polaris_bindings.iter())
    {
        step(&format!(
            "  {} | author={} | kind={:?} | master sig verifies: {}",
            s.role,
            s.author.as_u64(),
            b.evidence.kind,
            verify_binding_signature(b, &s.master.verifying_key()).is_ok()
        ));
    }

    // ---------- Phase C: Joint release, cross-domain verify ---------
    banner("Phase C — Joint release attested by one signer from each lab");
    let release_payload = b"Joint Foundation Model: HELIX-65B (Helios + Polaris co-release)";
    let rules_hash = hash(release_payload);
    step(&format!(
        "Release payload hash: blake3 {}...",
        &hex::encode(rules_hash)[..16]
    ));

    // Helios attests at version 1 in its own numbering; Polaris at
    // version 1 in its own numbering. In real federation both sides
    // coordinate on an agreed version. Use v1 for both here.
    let helios_version = make_version(1, helios_lead.author, rules_hash);
    let polaris_version = make_version(1, polaris_lead.author, rules_hash);

    let helios_sig = sign_attestation(
        &helios_version,
        helios_lead.author,
        &helios_lead.operational,
    );
    let polaris_sig = sign_attestation(
        &polaris_version,
        polaris_lead.author,
        &polaris_lead.operational,
    );

    step("Helios's sig verifies against Helios registry (in-domain):");
    verify_attestation(&helios_version, &helios_sig, &helios_registry)
        .expect("helios in-domain verify");
    step("  ✅ OK");

    step("Polaris's sig verifies against Polaris registry (in-domain):");
    verify_attestation(&polaris_version, &polaris_sig, &polaris_registry)
        .expect("polaris in-domain verify");
    step("  ✅ OK");

    step("Helios verifies Polaris's sig using the FOREIGN registry (cross-domain):");
    verify_attestation(&polaris_version, &polaris_sig, &polaris_registry)
        .expect("helios cross-domain verify of polaris sig");
    step("  ✅ OK — Helios's verifier uses Polaris's registry JSON for this check");

    step("Polaris verifies Helios's sig using the FOREIGN registry (cross-domain):");
    verify_attestation(&helios_version, &helios_sig, &helios_registry)
        .expect("polaris cross-domain verify of helios sig");
    step("  ✅ OK");

    // Cross-domain negative check: Polaris's sig must NOT verify
    // against Helios's registry (Polaris signer is unknown to Helios).
    step("Polaris's sig attempted against Helios registry (must reject):");
    match verify_attestation(&polaris_version, &polaris_sig, &helios_registry) {
        Ok(()) => {
            eprintln!("  ❌ SECURITY FAILURE: cross-registry sig accepted");
            std::process::exit(1);
        }
        Err(_) => step("  ✅ REJECTED — Polaris signer has no entry in Helios registry"),
    }

    // ---------- Phase D: HW attestation binding verification --------
    banner("Phase D — TEE-bound key verification with platform verifier");

    // Use the PubkeyPrefixEvidenceVerifier as the stand-in for a real
    // TPM2 / TDX attestation-service verifier. Each lab's bindings
    // must pass.
    let prefix_verifier = PubkeyPrefixEvidenceVerifier;
    for s in [&helios_lead, &helios_sec] {
        let b = s.binding();
        match verify_binding(&b, &helios_registry, 1, &prefix_verifier) {
            Ok(()) => step(&format!("Helios {}: HW binding ✅ VALID", s.role)),
            Err(e) => {
                eprintln!("Helios {}: binding failed — {e}", s.role);
                std::process::exit(1);
            }
        }
    }
    for s in [&polaris_lead, &polaris_sec] {
        let b = s.binding();
        match verify_binding(&b, &polaris_registry, 1, &prefix_verifier) {
            Ok(()) => step(&format!("Polaris {}: HW binding ✅ VALID", s.role)),
            Err(e) => {
                eprintln!("Polaris {}: binding failed — {e}", s.role);
                std::process::exit(1);
            }
        }
    }

    // ---------- Phase E: firmware-vuln event — Polaris distrusts Helios ----
    banner("Phase E — TPM firmware vulnerability → Polaris distrusts Helios bindings");
    step("Polaris's security team updates policy: Helios's TPM2 batch is");
    step("on the vulnerability list (CVE-2027-XXXXX). Polaris's verifier");
    step("is swapped to reject ALL bindings from that kind until a reissue.");

    // Swap in a verifier that always rejects — simulates the updated
    // platform policy.
    let distrust_verifier = RejectAllEvidenceVerifier;
    for s in [&helios_lead, &helios_sec] {
        let b = s.binding();
        match verify_binding(&b, &helios_registry, 1, &distrust_verifier) {
            Ok(()) => {
                eprintln!("❌ distrusted verifier accepted binding");
                std::process::exit(1);
            }
            Err(_) => step(&format!(
                "Helios {}: binding under distrust policy ❌ REJECTED (as required)",
                s.role
            )),
        }
    }
    step("Meanwhile Polaris's own bindings still pass under the normal verifier:");
    for s in [&polaris_lead, &polaris_sec] {
        let b = s.binding();
        match verify_binding(&b, &polaris_registry, 1, &prefix_verifier) {
            Ok(()) => step(&format!("  Polaris {}: binding still ✅ VALID", s.role)),
            Err(e) => {
                eprintln!("polaris binding unexpectedly failed: {e}");
                std::process::exit(1);
            }
        }
    }

    // ---------- Phase F: tamper scenarios on bindings ----------------
    banner("Phase F — Adversarial binding mutations");

    // Tamper the binding's pubkey field after signing.
    let mut bad_binding = helios_lead.binding();
    bad_binding.public_key[0] ^= 0xFF;
    match verify_binding(&bad_binding, &helios_registry, 1, &prefix_verifier) {
        Ok(()) => {
            eprintln!("❌ tampered pubkey accepted");
            std::process::exit(1);
        }
        Err(_) => step("Tampered binding.public_key → ❌ REJECTED"),
    }

    // Tamper the evidence body.
    let mut bad_ev = helios_lead.binding();
    if !bad_ev.evidence.evidence.is_empty() {
        let last = bad_ev.evidence.evidence.len() - 1;
        bad_ev.evidence.evidence[last] ^= 0xFF;
    }
    match verify_binding(&bad_ev, &helios_registry, 1, &prefix_verifier) {
        Ok(()) => {
            eprintln!("❌ tampered evidence accepted");
            std::process::exit(1);
        }
        Err(_) => step("Tampered binding.evidence → ❌ REJECTED"),
    }

    // Swap the master signature for garbage.
    let mut bad_sig = helios_lead.binding();
    bad_sig.master_signature[0] ^= 0xFF;
    match verify_binding(&bad_sig, &helios_registry, 1, &prefix_verifier) {
        Ok(()) => {
            eprintln!("❌ tampered master sig accepted");
            std::process::exit(1);
        }
        Err(_) => step("Tampered master_signature → ❌ REJECTED"),
    }

    // ---------- Summary ---------------------------------------------
    banner("Summary");
    println!("  ✅ Two independent aion deployments — Helios (SG), Polaris (DE)");
    println!("  ✅ 4 signers total, each bound to a (simulated) TEE quote");
    println!("  ✅ In-domain attestations verify under each lab's own registry");
    println!("  ✅ Cross-domain verify works with out-of-band registry exchange");
    println!("  ✅ Signer from org A rejected against org B's registry");
    println!("  ✅ HW-attestation bindings pass the pubkey-prefix TEE verifier");
    println!("  ✅ Polaris distrust policy (RejectAll verifier) refuses Helios bindings");
    println!("  ✅ Polaris's own bindings still valid under the normal verifier");
    println!("  ✅ Tampered pubkey, evidence, master signature — all REJECTED");
    println!();
    println!("  RFC-0026 (hardware attestation) + RFC-0028 (registry) + federation.");
}
