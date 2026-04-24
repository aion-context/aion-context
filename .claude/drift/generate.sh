#!/usr/bin/env bash
# Emit the masterpiece snapshot for aion-context as JSON on stdout.
# Called by .claude/hooks/stop-drift-check.sh and /drift-check.
#
# Output shape:
#   { "version": "1", "generated_at": "<iso>", "crates": { "<name>": { ... } } }

set -u -o pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT" || exit 1

# Tuple: <crate-name>:<src-dir>:<tests-dir-or-empty>
CRATES=(
  "aion-context:src:tests"
)

max_fn_len() {
  local dir="$1"
  [ -d "$dir" ] || { echo 0; return; }
  find "$dir" -name '*.rs' 2>/dev/null | while IFS= read -r f; do
    awk '
      BEGIN { depth = 0; in_fn = 0; fn_depth = -1; max = 0 }
      /^[ \t]*(pub[ \t]+(\([a-z()]+\)[ \t]+)?)?(async[ \t]+)?(unsafe[ \t]+)?(const[ \t]+)?fn[ \t]/ {
        if (!in_fn) { fn_start = NR; fn_depth = depth; in_fn = 1 }
      }
      {
        for (i = 1; i <= length($0); i++) {
          c = substr($0, i, 1)
          if (c == "{") depth++
          else if (c == "}") {
            depth--
            if (in_fn && depth == fn_depth) {
              body = NR - fn_start + 1
              if (body > max) max = body
              in_fn = 0
              fn_depth = -1
            }
          }
        }
      }
      END { print max + 0 }
    ' "$f"
  done | sort -rn | head -1
}

count_panics() {
  local dir="$1"
  [ -d "$dir" ] || { echo 0; return; }
  grep -rnE '\.unwrap\(\)|\.expect\(|panic!\(|todo!\(|unreachable!\(' "$dir" 2>/dev/null \
    | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' \
    | wc -l | awk '{print $1}'
}

count_tests() {
  local src="$1"; local tests="$2"
  local total=0
  for d in "$src" "$tests"; do
    [ -n "$d" ] && [ -d "$d" ] || continue
    local n
    n=$(grep -rnE '#\[(tokio::)?test\]' "$d" 2>/dev/null | wc -l | awk '{print $1}')
    total=$((total + n))
  done
  echo "$total"
}

count_pub_items() {
  local dir="$1"
  [ -d "$dir" ] || { echo 0; return; }
  grep -rnE '^[[:space:]]*pub[[:space:]]+(fn|struct|enum|trait|type|const|static|union|mod)[[:space:]]' "$dir" 2>/dev/null \
    | wc -l | awk '{print $1}'
}

count_loc() {
  local dir="$1"
  [ -d "$dir" ] || { echo 0; return; }
  find "$dir" -name '*.rs' -exec cat {} + 2>/dev/null | wc -l | awk '{print $1}'
}

now_iso() {
  date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo ""
}

printf '{\n'
printf '  "version": "1",\n'
printf '  "generated_at": "%s",\n' "$(now_iso)"
printf '  "crates": {\n'

first=1
for tuple in "${CRATES[@]}"; do
  name="${tuple%%:*}"
  rest="${tuple#*:}"
  src="${rest%%:*}"
  tests="${rest#*:}"

  [ -d "$src" ] || continue

  panics=$(count_panics "$src")
  test_count=$(count_tests "$src" "$tests")
  pub_items=$(count_pub_items "$src")
  loc=$(count_loc "$src")
  max_fn=$(max_fn_len "$src")
  [ -z "$max_fn" ] && max_fn=0

  if [ $first -eq 0 ]; then printf ',\n'; fi
  first=0
  printf '    "%s": { "panics": %s, "tests": %s, "pub_items": %s, "loc": %s, "max_fn": %s }' \
    "$name" "$panics" "$test_count" "$pub_items" "$loc" "$max_fn"
done

printf '\n  }\n}\n'
