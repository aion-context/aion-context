#!/usr/bin/env bash
# PreToolUse gate for Edit/Write on *.rs files under library crates.
# Blocks edits that introduce Tiger Style violations in the new content.
#
# Scan scope: the proposed new_string / content only. Pre-existing
# violations are handled by /tiger-audit, not this hook — we don't want
# to block legitimate fixes that touch a file already under water.

export AION_HOOK_NAME="pre-edit-rust-gate"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

aion_bypass_active && { aion_log "bypass via AION_SKIP_GATES=1"; exit 0; }

payload="$(aion_read_hook_input)"
path="$(printf '%s' "$payload" | aion_extract_path)"
content="$(printf '%s' "$payload" | aion_extract_content)"

[ -z "$path" ] && exit 0
aion_is_rust_file "$path" || exit 0

relpath="${path#"$AION_REPO_ROOT/"}"
aion_is_library_rust "$relpath" || exit 0

[ -z "$content" ] && exit 0

# Strip comments and string literals so we don't flag legitimate text
# like "no unwrap()" in a doc comment. Line-oriented and conservative:
#   - drop everything from `//` to end-of-line
#   - replace "..." with ""
# Block comments (/* ... */) are rare in this codebase and would only
# cause false positives; we leave them alone.
scrubbed="$(printf '%s' "$content" | awk '
  {
    p = index($0, "//")
    if (p > 0) $0 = substr($0, 1, p - 1)
    gsub(/"[^"]*"/, "\"\"")
    print
  }
')"

banned_pattern='(^|[^A-Za-z_])(unwrap|expect)\(|(^|[^A-Za-z_])(panic|todo|unreachable)!'
if printf '%s' "$scrubbed" | grep -nE "$banned_pattern" >/dev/null; then
  hits="$(printf '%s' "$scrubbed" | grep -nE "$banned_pattern" | head -5)"
  aion_log "Tiger Style: no unwrap/expect/panic!/todo!/unreachable! in library code"
  aion_log "offending lines (scrubbed view):"
  printf '%s\n' "$hits" | while IFS= read -r line; do aion_log "  $line"; done
  aion_block "edit rejected — see CLAUDE.md 'ABSOLUTE REQUIREMENTS'"
fi

# Function length check: any fn that exceeds 60 body lines.
over_limit="$(printf '%s' "$content" | awk '
  /^[[:space:]]*(pub[[:space:]]+(\([a-z()]+\)[[:space:]]+)?)?(async[[:space:]]+)?(unsafe[[:space:]]+)?(const[[:space:]]+)?fn[[:space:]]/ {
    if (depth == 0) { fn_line = NR; fn_name = $0; in_fn = 1 }
  }
  {
    for (i = 1; i <= length($0); i++) {
      c = substr($0, i, 1)
      if (c == "{") depth++
      else if (c == "}") {
        depth--
        if (in_fn && depth == 0) {
          body = NR - fn_line + 1
          if (body > 60) printf "line %d: %d lines — %s\n", fn_line, body, fn_name
          in_fn = 0
        }
      }
    }
  }')"

if [ -n "$over_limit" ]; then
  aion_log "Tiger Style: functions must be <= 60 lines"
  printf '%s\n' "$over_limit" | while IFS= read -r line; do aion_log "  $line"; done
  aion_block "edit rejected — split the function"
fi

exit 0
