#!/usr/bin/env bash
# Emit an SBOM snapshot for aion-context as JSON on stdout.
# Uses `cargo metadata`; filters to the resolved dependency closure of
# the workspace members and emits { name, version, source, license }.
#
# Requires: cargo, jq.

set -u -o pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT" || exit 1

if ! command -v cargo >/dev/null 2>&1; then
  echo "{\"error\": \"cargo not available\"}" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "{\"error\": \"jq not available\"}" >&2
  exit 1
fi

now_iso="$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "")"

cargo metadata --format-version 1 --all-features --locked 2>/dev/null \
  | jq --arg ts "$now_iso" '
      {
        version: "1",
        generated_at: $ts,
        workspace_members: (.workspace_members | map(split(" ")[0])),
        packages: (
          .packages
          | map({
              name: .name,
              version: .version,
              source: (.source // "workspace"),
              license: (.license // "UNKNOWN"),
              license_file: (.license_file // null)
            })
          | sort_by(.name)
        )
      }
    '
