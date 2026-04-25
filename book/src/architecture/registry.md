# Key Registry (RFC-0028 / RFC-0034)

The trusted-key registry is a JSON file pinning, for each
AuthorId, a master verifying key plus an append-only list of
operational-key epochs. Verifiers consult it to resolve which
key was active for which signer at which version.

The registry is the answer to: **how does the verifier know
who's allowed to sign?**

## Two-tier key model

```text
┌─────────────────────────────────────────────┐
│  Author 50001                                │
│                                              │
│  master_key:    a5cfc10031a2e52b...         │
│                 (long-lived, rarely used —  │
│                  authorizes rotations and    │
│                  revocations)                │
│                                              │
│  epoch[0]                                    │
│    public_key: 38adddc322a5900b...          │
│    active_from_version: 0                    │
│    status: rotated                           │
│  epoch[1]                                    │
│    public_key: d9c7a1e7f69f96b2...          │
│    active_from_version: 9                    │
│    status: active                            │
│                                              │
│  revocations: []                             │
└─────────────────────────────────────────────┘
```

The **master key** is the trust anchor. It signs:
- Rotation records that mint a new operational epoch
- Revocation records that close an epoch's window

The **operational keys** are the ones that actually sign
versions and attestations. They rotate; they get compromised;
they retire with their owner. The master key keeps the
registry honest through every transition.

## Active-epoch resolution

`KeyRegistry::active_epoch_at(author, version_number) -> Option<&KeyEpoch>`
returns the epoch that was active for the author at the given
version. It walks the author's epochs and returns the first
one whose `is_valid_for(version)` predicate holds:

```text
epoch.is_valid_for(v) iff
    epoch.created_at_version <= v
    AND
    (epoch.status == Active
     OR (epoch.status == Rotated/Revoked
         AND v < effective_from_version))
```

So an epoch's window is `[created_at, effective_from)` once
rotated/revoked, and `[created_at, ∞)` while still active.

## Rotation semantics

A rotation record signed by the master key transitions the
registry: the OLD epoch's status becomes `Rotated` with
`effective_from_version = V`, and a NEW epoch is appended
with `created_at_version = V` and status `Active`.

After rotation:

| Version | Active epoch |
|---|---|
| `< V` | OLD (epoch `from_epoch`) |
| `>= V` | NEW (epoch `to_epoch`) |

The CLI's `aion registry rotate` warns when `V` matches the
current active epoch's `created_at_version` — that would
collapse the OLD epoch's window to zero length and
retroactively invalidate every prior `v=V` signature. See
[RFC-0035](../operations/chain-architecture.md) for the
operational implications.

## Revocation semantics

A revocation record signed by the master key transitions an
epoch to `Revoked { reason, effective_from_version }`. The
epoch's window closes at `effective_from_version`. Signatures
made BEFORE that version remain valid; signatures AT OR AFTER
fail.

Revocation reasons:

- `Compromised` — key material is known or suspected compromised
- `Superseded` — routine; predecessor not believed compromised
- `Retired` — signer leaves; no successor
- `Unspecified` — reason not recorded at protocol level

## Trusted JSON format

The on-disk format (output of `KeyRegistry::to_trusted_json`,
input of `from_trusted_json`):

```json
{
  "version": 1,
  "authors": [
    {
      "author_id": 50001,
      "master_key": "<base64-32-bytes>",
      "epochs": [
        {
          "epoch": 0,
          "public_key": "<base64-32-bytes>",
          "active_from_version": 0,
          "status": "rotated"
        },
        {
          "epoch": 1,
          "public_key": "<base64-32-bytes>",
          "active_from_version": 9,
          "status": "active"
        }
      ],
      "revocations": []
    }
  ]
}
```

The `status` field (added in PR #46) is for operator
readability — an auditor diffing two registry files sees at
a glance which keys are still in force. The in-memory status
is reconstructed independently from epoch ordering and the
revocations array, so a malformed JSON status field cannot
elevate a rotated key back to Active.

## Registry-aware verify (RFC-0034)

Every signature verification path takes a `&KeyRegistry`
reference. The library has no raw-key verify_* variants
anymore — that was PR #22's removal. Every consumer must
supply a registry, and the registry resolves which public
key to expect for `(author, version)`.

This closed the `SignatureEntry::public_key` substitution
attack: pre-RFC-0034, an attacker could rewrite a signed
file's `public_key` field to match a key they controlled,
producing a self-consistent but trust-anchorless file. With
the registry, the verifier ignores the file's embedded
public_key and uses the registry's pinned epoch instead.

## See also

- The CLI's `aion registry` page covers `pin` / `rotate` /
  `revoke` invocations.
- `examples/aegis_consortium.rs` exercises the full rotation
  + revocation lifecycle programmatically.
- RFC-0028 in `rfcs/` is authoritative for protocol details.
