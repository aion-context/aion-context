#!/usr/bin/env bash
#
# add-spdx-headers.sh — prepend an SPDX license header to every Rust
# source file in the project tree.
#
# Idempotent: files that already begin with an SPDX line are left
# alone. Run again at any time after adding new files.
#
# The header is placed as the very first line of each file (before
# any module-doc `//!` block or `#![...]` attribute), which is the
# placement most tooling (`cargo about`, `reuse`, FOSSA, etc.)
# expects.

set -euo pipefail

readonly SPDX_LINE='// SPDX-License-Identifier: MIT OR Apache-2.0'

# Roots scanned. Anything under these directories with a `.rs`
# extension gets the header. Add or remove paths here if the layout
# changes — the script is intentionally explicit rather than walking
# the whole repo.
readonly ROOTS=(
    "src"
    "examples"
    "benches"
    "tests"
    "fuzz/fuzz_targets"
)

added=0
skipped=0

for root in "${ROOTS[@]}"; do
    if [ ! -d "$root" ]; then
        continue
    fi
    while IFS= read -r -d '' file; do
        first_line="$(head -n 1 "$file")"
        if [[ "$first_line" == *"SPDX-License-Identifier"* ]]; then
            skipped=$((skipped + 1))
            continue
        fi
        # Prepend in-place via a temp file. We avoid `sed -i` to keep
        # behaviour identical between GNU and BSD sed.
        tmp="$(mktemp)"
        {
            printf '%s\n' "$SPDX_LINE"
            cat "$file"
        } > "$tmp"
        mv "$tmp" "$file"
        added=$((added + 1))
    done < <(find "$root" -type f -name "*.rs" -print0)
done

echo "SPDX headers added: $added"
echo "Already had header: $skipped"
