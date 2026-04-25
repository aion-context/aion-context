# Auditor Workflow

You are an external compliance auditor (SEC, HHS-OCR, FDA,
internal audit, third-party assessor). A regulated firm has
handed you a directory of `.aion` files plus a registry JSON.
You have a finite window — say 72 hours — to produce a
findings report. This is the playbook.

## Inputs

You should receive, out of band:

1. **The archive** — a directory of `.aion` files. Could be
   a single growing-chain file (`policy.aion`) or a per-file
   genesis directory (`week-01.aion ... week-N.aion`).
2. **The registry** — `registry.json` pinning master + epochs
   for each authorised signer.
3. **Operator metadata** — who's the CCO, who's the Risk
   Officer, who's the Release Manager. The author IDs in the
   registry should map to roles you understand.

## The walk

### Step 1: bulk-verify

```bash
aion archive verify ./archive \
    --registry ./registry.json \
    --format json > audit-report.json
echo "exit=$?"
```

Exit `0` means every file VALID. Exit `1` means at least one
file failed; read on.

### Step 2: read the dashboard

For human review, run text format:

```bash
aion archive verify ./archive --registry ./registry.json
```

The output has three passes:

1. Per-file VALID/INVALID + the failure reason for each
   INVALID file.
2. Signer breakdown — per-author distinct pubkeys observed
   across the archive. `⚙ ROTATED` flags any author with
   more than one operational key.
3. Findings — aggregate summary with the list of failed
   files.

### Step 3: classify failures

Each failure has a specific reason. Map it to action:

| Reason | What it means | Action |
|---|---|---|
| `File integrity hash mismatch` | Bytes have been tampered with after signing. | Demand the original file from the firm. If unavailable, treat as a tamper finding. |
| `Signature verification failed for version V by author A` | The signature at v=V doesn't match the registry's pinned key for author A. | Could be (a) registry-mismatch (the firm sent the wrong registry), (b) signed with a rotated-out key, or (c) actual forgery. Cross-reference with the registry's epoch windows. |
| `Hash chain verification failed at version V` | A `parent_hash` link is broken. Some intermediate version was tampered with. | Definitely a tamper finding. |
| `Structure / parse error` | The file is malformed. | Demand a clean copy; could be transmission corruption, could be deliberate. |

### Step 4: cross-reference with the rotation log

The signer-breakdown table tells you whether keys rotated.
Cross-reference with the registry:

```bash
python3 -c "
import json
r = json.load(open('registry.json'))
for a in r['authors']:
    print(f\"author {a['author_id']}:\")
    for e in a['epochs']:
        status = e.get('status', 'unknown')
        print(f\"  epoch {e['epoch']} active_from_version={e['active_from_version']} status={status}\")
    for rev in a.get('revocations', []):
        print(f\"  revocation: epoch {rev['epoch']} reason={rev['reason']} effective_from_version={rev['effective_from_version']}\")
"
```

For each rotation in the registry: confirm the firm
documented a corresponding event (staff departure, scheduled
rotation, compromise response). Undocumented rotations are a
finding.

For each revocation: ask the firm for the incident report
referenced.

### Step 5: produce the report

Compliance frameworks vary; a generic template:

```markdown
# Quarterly Audit — [firm name] Q3 [year]

## Summary

- Archive: 13 files, dated [start] through [end]
- Registry: 2 authors, 1 rotation observed (CCO mid-quarter)
- Verification: 10/13 VALID, 3 INVALID

## Findings

### Finding 1 — week-05.aion (HIGH)

File integrity hash mismatch: expected
0939cb6a52366aed6cd403d01dfb218d... got
9b85a511e9a585ad7d3b4e6285fdf9b4...

Indicates byte-level tampering after the file was signed.
Firm must produce the original signed bytes or accept this as
a tamper finding.

### Finding 2 — week-11.aion, week-13.aion (MEDIUM)

Signature verification failed under post-rotation registry.
Both files sign with the new CCO operational key, but the
files are at v1 and the registry's rotation effective-from-
version is set to a value that excludes v1.

This is a structural issue with the firm's chain architecture
(per-file genesis) — see RFC-0035. Recommendation: migrate
to a growing-chain layout to avoid this class of failure
going forward.

### Finding 3 — Author 401001 rotation (INFORMATIONAL)

The CCO operational key rotated mid-quarter. Registry
records the event with effective_from_version=2 and
reason=Superseded. Firm should produce the corresponding
HR / change-management ticket for the mid-quarter
transition.

## Conclusion

Quarter has 1 HIGH finding (verifiable tampering), 2 MEDIUM
findings (structural rotation incompatibility), and 1
INFORMATIONAL finding (documented rotation event). Firm has
30 days to respond.
```

## What aion-context can NOT tell you

- **Whether the rules content is correct.** aion-context
  signs and verifies; it does not evaluate the rules' meaning
  against external policy.
- **Whether the signer was the legitimate human.** The
  registry pins keys, not identities. If the firm distributed
  the master key to a third party, the registry doesn't know.
- **Whether the timestamps are honest.** Wall-clock timestamps
  in version entries are operator-supplied. The transparency-
  log timestamp is more trustworthy because it's bound to a
  global ordering.
- **Whether the audit-trail message strings reflect reality.**
  They're free-form text. A tamperer can't change them after
  signing without breaking the integrity hash, but the
  original signer can lie about what they were doing.

## See also

- [The CLI's `archive verify`](../cli/archive.md) — every flag
  and the JSON output schema
- [Chain Architecture](./chain-architecture.md) — why Finding
  2 above is structural, not a tamper
- [Rotation Playbook](./rotation.md) — the publisher side of
  rotation, useful context for what the firm should have done
