---
description: List files in the current diff (or working tree) that trigger a crypto-auditor review.
---

Identify candidate files for the `crypto-auditor` agent. Read-only.

## Target set

Any file whose path matches:

- `src/crypto.rs`
- `src/signature_chain.rs`
- `src/multisig.rs`
- `src/keystore.rs`
- `src/audit.rs`
- `**/crypto*.rs`
- `**/sign*.rs`
- `**/verify*.rs`

## Steps

1. If on a feature branch, run
   `git diff --name-only main...HEAD` — the set to scan is the
   intersection of that diff with the target set above. If on `main`,
   scan the full target set.
2. For each matching file, grep for any of:
   - `==` used on `&[u8]` (candidate non-constant-time compare)
   - `Vec<u8>` / `String` used for key material (missing `Zeroizing`)
   - Raw `unwrap()` / `expect()` on crypto operations (panics on
     adversary input)
   - New `impl` of `Hasher`, `Signer`, `Verifier`, or anything
     matching `/fn *_sign|fn *_verify|fn *_hash/`
   - BLAKE3 calls without a `keyed_hash` key or prefix byte (missing
     domain separation)
3. Report each file with the hits and a recommendation:
   - Call `crypto-auditor` agent → pass this file list
   - OR "no crypto-audit needed" if the diff only touches trivial
     paths (comments, tests, docs)

## Output format

```
CRYPTO SCAN

Files in scope (N):
  src/crypto.rs
    - line 142: ==  on [u8] (possible non-CT compare)
    - line 201: unwrap() in verify path
  src/signature_chain.rs
    - line 55:  new impl Hasher

Recommendation: run crypto-auditor on the above files.
```

If no files in scope, output:
`No crypto-sensitive files in diff — crypto-auditor not required.`

Do not modify files.
