#!/usr/bin/env bash
set -euo pipefail

# Search tracked text only. Historical evidence and the externally-owned
# icicle-snark branch name intentionally retain the former namespace;
# docs/brand-namespace.md records why.
#
# The one ALLOWED live occurrence is `NYX_ICICLE_CUDA_ARCH` — the deprecated
# spelling of the icicle CUDA-arch build knob. The vendored fork still accepts it
# as a warning fallback (so a stale submodule pointer cannot silently drop the
# setting), which means the name must remain documentable in the Dockerfile and
# the GPU runbook. The negative lookahead allows exactly that token and nothing
# else — `nyx-anything-else` is still rejected. See docs/brand-namespace.md.
if matches=$(git grep -nI -P '\b(?:Nyx|NYX|nyx)(?!_ICICLE_CUDA_ARCH)' -- \
  ':!audits/**' \
  ':!docs/brand-namespace.md' \
  ':!packages/sdk/tests/fixtures/dstack-eventlog.json' \
  ':!.gitmodules' \
  ':!scripts/check-brand-namespace.sh'); then
  printf '%s\n' 'stale pre-Darknyx namespace found:' "$matches" >&2
  exit 1
fi

echo 'Darknyx namespace check passed'
