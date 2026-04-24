#!/usr/bin/env bash
# PreToolUse on `git commit` / `git push`: enforce CLAUDE.md branch
# policy for aion-context.
#
# Allowed prefixes (CLAUDE.md Branch Management Workflow):
#   feature/<issue>-<desc>   — new functionality
#   fix/<issue>-<desc>       — bug fixes
#   chore/<desc>             — tooling, CI, dep bumps
#   docs/<desc>              — docs only
#   rfc/<number>-<slug>      — RFC additions/edits
#   release/<version>        — release branches
#
# main/master always refused.

export AION_HOOK_NAME="pre-commit-branch-name"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

aion_bypass_active && exit 0

payload="$(aion_read_hook_input)"
cmd="$(printf '%s' "$payload" | jq -r '.tool_input.command // empty' 2>/dev/null)"
[ -z "$cmd" ] && exit 0

# Only trigger when `git commit` or `git push` is an actual command,
# not a substring of an echo/grep. Match at start, after shell
# separators (&& || ; | &), or after an opening paren.
if ! printf '%s' "$cmd" | grep -qE '(^|[;&|(]|&&|\|\|)[[:space:]]*git[[:space:]]+(commit|push)([[:space:]]|$)'; then
  exit 0
fi

cd "$AION_REPO_ROOT" || exit 0
branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo '')"
[ -z "$branch" ] && exit 0

if [ "$branch" = "main" ] || [ "$branch" = "master" ]; then
  aion_log "refusing to $cmd on $branch — create a feature/<issue>-<desc> branch first"
  aion_block "branch policy: CLAUDE.md Branch Management Workflow step 2"
fi

case "$branch" in
  feature/*|fix/*|chore/*|docs/*|rfc/*|release/*) exit 0 ;;
  *)
    aion_log "branch '$branch' does not match feature/*, fix/*, chore/*, docs/*, rfc/*, release/*"
    aion_block "rename the branch to match CLAUDE.md convention"
    ;;
esac
