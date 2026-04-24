#!/usr/bin/env bash
# Shared helpers for aion-context quality gate hooks.
# Sourced by every hook in .claude/hooks/. No stdout except via aion_log.

set -u -o pipefail

AION_HOOK_NAME="${AION_HOOK_NAME:-hook}"
AION_REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

aion_log() {
  printf '[aion:%s] %s\n' "$AION_HOOK_NAME" "$*" >&2
}

aion_block() {
  aion_log "BLOCKED: $*"
  exit 2
}

aion_warn() {
  aion_log "WARN: $*"
}

aion_is_rust_file() {
  case "$1" in
    *.rs) return 0 ;;
    *)    return 1 ;;
  esac
}

# Library Rust under this crate. Binaries, fuzz, examples are excluded
# from the hard gate.
aion_is_library_rust() {
  case "$1" in
    */target/*|*/.venv/*|*/doc/*|*/fuzz/*|*/examples/*|*/src/bin/*) return 1 ;;
    src/*) return 0 ;;
    *) return 1 ;;
  esac
}

# Map a path to its cargo package name. This crate is the whole repo.
aion_crate_for() {
  case "$1" in
    *) echo "aion-context" ;;
  esac
}

aion_bypass_active() {
  [ "${AION_SKIP_GATES:-0}" = "1" ]
}

aion_read_hook_input() {
  if [ -t 0 ]; then
    echo '{}'
  else
    cat
  fi
}

aion_extract_path() {
  jq -r '.tool_input.file_path // .tool_input.path // empty' 2>/dev/null
}

aion_extract_content() {
  jq -r '.tool_input.content // .tool_input.new_string // empty' 2>/dev/null
}
