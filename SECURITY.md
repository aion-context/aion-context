# Security Policy

`aion-context` ships an on-disk cryptographic file format. Bugs in
signing, verification, hashing, key management, or the audit chain
matter to people who have not yet downloaded a release. We treat
security reports as the highest-priority class of issue.

## Reporting a vulnerability

**Do not file public GitHub issues for security bugs.** Use one of
the private channels below.

### Preferred — GitHub private vulnerability reporting

Open a private advisory directly from the repository:

> https://github.com/aion-context/aion-context/security/advisories/new

(or, after the org transfer, the equivalent path under the new org)

This routes the report to maintainers privately, gives the report
a stable identifier, and lets us coordinate fixes and CVE assignment
in one thread. It is the path we recommend.

### Alternate — email

> **TODO(launch):** dedicated `security@…` mailbox + GPG key go
> here once the project's org is set up. Until then, please prefer
> the GitHub private-advisory flow above.

When emailing, include enough detail for us to reproduce, and please
do not include third-party PII or information from real `.aion`
files in the report.

## What's in scope

| Area | In scope |
|---|---|
| `src/crypto.rs` — Ed25519 / BLAKE3 / ChaCha20-Poly1305 wrappers | yes |
| `src/signature_chain.rs` — per-version signing & verification | yes |
| `src/multisig.rs` — quorum verification (RFC-0021) | yes |
| `src/key_registry.rs` — registry-aware verify, rotation, revocation (RFC-0028 / RFC-0034) | yes |
| `src/parser.rs` — file-format parsing on adversary-controlled bytes | yes |
| `src/audit.rs` — audit-chain integrity | yes |
| `src/keystore.rs` — key material lifecycle | yes |
| `src/transparency_log.rs` — RFC 6962 Merkle log + STH | yes |
| `src/hw_attestation.rs`, `src/hybrid_sig.rs` — RFC-0026 / RFC-0027 | yes |
| `src/release.rs`, `src/manifest.rs`, `src/dsse.rs`, `src/slsa.rs`, `src/aibom.rs`, `src/oci.rs` — supply-chain glue | yes |
| `src/jcs.rs` — RFC 8785 canonical JSON | yes |
| `aion` CLI binary (`src/bin/aion.rs`) | yes |
| `test_helpers` (cfg-gated, not in production builds) | no |
| Examples under `examples/` | no — these are demonstrations, not production code |
| Downstream applications consuming aion-context | no — file with the downstream |

If you're unsure, err on the side of reporting privately. We can
move it to a public issue if it turns out to be out of scope.

## What we'll do

1. **Acknowledge** within 3 business days that we received the report.
2. **Triage** within 7 business days — confirm reproducibility,
   assess severity, and either accept or explain why we believe
   it's out of scope.
3. **Fix** in private. Patch lands on a non-public branch; we may
   ask for your help validating it.
4. **Coordinate disclosure**. By default we publish a GitHub
   advisory and request a CVE. You receive named credit unless you
   ask otherwise. If we and you both agree the bug is low-severity,
   we may skip CVE assignment but always publish the advisory.
5. **Release**. We cut a patch release within a target of 30 days
   of triage for high-severity issues. Lower-severity issues may
   wait for the next routine release; we'll tell you the plan.

## Severity

We use the [CVSS 3.1] calculator as a starting point but reserve
judgement on what counts as critical for this codebase
specifically. The classes that we consider load-bearing:

- **Crypto break** — anything that allows producing a `(file, signature)`
  pair an honest verifier accepts, without holding the corresponding
  signing key, or that breaks the hash-chain integrity invariants
- **Replay / equivocation** — anything that lets an attacker make
  two distinct files both verify against the same `(author, version)`
- **Parser DoS / RCE** — adversary-controlled bytes that crash, hang,
  or escape the parser's invariants
- **Key material exfiltration** — any path through the keystore or
  hardware-attestation modules that exposes private bytes

If your finding is in one of those classes, please prioritize the
private path even if you're unsure of full impact.

[CVSS 3.1]: https://www.first.org/cvss/calculator/3.1

## What we ask

- **Don't** test against systems you don't own, or against `.aion`
  files containing real third-party data.
- **Don't** publish the bug or share it with others until we've had
  a chance to ship a fix.
- **Do** keep credentials and key material out of the report.
- **Do** be patient with the triage timeline — this is a small
  maintainer team, and we will reply.

Thank you for helping keep `aion-context` secure.
