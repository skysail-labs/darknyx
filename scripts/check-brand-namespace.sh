#!/usr/bin/env bash
set -euo pipefail

# Search tracked text only. Historical evidence and the externally-owned
# icicle-snark branch name intentionally retain the former namespace;
# docs/brand-namespace.md records why.
if matches=$(git grep -nI -P '\b(?:Nyx|NYX|nyx)' -- \
  ':!audit_1/**' \
  ':!audit_2/**' \
  ':!docs/audit-*.md' \
  ':!docs/security-remediation-tracker.md' \
  ':!docs/brand-namespace.md' \
  ':!packages/sdk/tests/fixtures/dstack-eventlog.json' \
  ':!.gitmodules' \
  ':!scripts/check-brand-namespace.sh'); then
  printf '%s\n' 'stale pre-Darknyx namespace found:' "$matches" >&2
  exit 1
fi

echo 'Darknyx namespace check passed'
