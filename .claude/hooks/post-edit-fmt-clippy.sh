#!/usr/bin/env bash
# PostToolUse: after Edit/Write lands in a library .rs file, format the
# touched crate and run clippy scoped to it. Advisory unless
# AION_STRICT_POST=1 — we want fast feedback without blocking every edit.

export AION_HOOK_NAME="post-edit-fmt-clippy"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

aion_bypass_active && exit 0

payload="$(aion_read_hook_input)"
path="$(printf '%s' "$payload" | aion_extract_path)"

[ -z "$path" ] && exit 0
aion_is_rust_file "$path" || exit 0

relpath="${path#"$AION_REPO_ROOT/"}"
crate="$(aion_crate_for "$relpath")"
[ -z "$crate" ] && exit 0

cd "$AION_REPO_ROOT" || exit 0

if ! cargo fmt -p "$crate" >/dev/null 2>&1; then
  aion_warn "cargo fmt failed for $crate"
fi

if ! out="$(cargo clippy -p "$crate" --no-deps --quiet -- -D warnings 2>&1)"; then
  aion_log "clippy failures in $crate:"
  printf '%s\n' "$out" | tail -40 | while IFS= read -r line; do aion_log "  $line"; done
  [ "${AION_STRICT_POST:-0}" = "1" ] && aion_block "clippy gate failed (strict mode)"
fi

exit 0
