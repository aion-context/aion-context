#!/usr/bin/env bash
# Stop hook: when Claude finishes a turn that touched Rust, run the
# drift comparison against the checked-in baseline. Output is
# advisory — it does not block Stop. If no baseline exists yet, the
# hook is a no-op (baseline is generated from a clean `main`).

export AION_HOOK_NAME="stop-drift-check"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

aion_bypass_active && exit 0

cd "$AION_REPO_ROOT" || exit 0

# Skip if no Rust was touched since HEAD.
if ! git status --porcelain 2>/dev/null | grep -qE '\.rs($|[[:space:]])'; then
  exit 0
fi

gen="$SCRIPT_DIR/../drift/generate.sh"
baseline="$SCRIPT_DIR/../drift/baseline.json"
[ -f "$gen" ] || exit 0
if [ ! -f "$baseline" ]; then
  aion_log "no baseline yet — generate one from clean main:"
  aion_log "  bash .claude/drift/generate.sh > .claude/drift/baseline.json"
  exit 0
fi

current_json="$(bash "$gen" 2>/dev/null)"
[ -z "$current_json" ] && exit 0

regressions="$(jq -r --argjson cur "$current_json" '
  . as $base
  | ($base.crates | to_entries[]) as $e
  | $cur.crates[$e.key] as $c
  | select($c != null)
  | [
      (if $c.panics   > $e.value.panics   then "panics:\($e.key) \($e.value.panics)→\($c.panics)"     else empty end),
      (if $c.tests    < $e.value.tests    then "tests:\($e.key) \($e.value.tests)→\($c.tests)"         else empty end),
      (if $c.max_fn   > ($e.value.max_fn + 5) then "max_fn:\($e.key) \($e.value.max_fn)→\($c.max_fn)" else empty end)
    ]
  | .[]' "$baseline" 2>/dev/null)"

if [ -n "$regressions" ]; then
  aion_log "drift detected vs baseline:"
  printf '%s\n' "$regressions" | while IFS= read -r r; do aion_log "  $r"; done
  aion_log "run /drift-check to investigate, /quality-gate to verify fix"
else
  aion_log "no drift against baseline"
fi

exit 0
