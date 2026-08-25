#!/usr/bin/env bash
# Compose only forwards variables explicitly listed under `environment:`.
# Declaring a secret in `phala deploy -e` is insufficient unless every deploy
# boundary names it, so enforce the active governed fee-key path here.
set -euo pipefail

key=DARKNYX_TEE_FEE_EPOCH_KEY
expected="      ${key}: \${${key}}"

for file in deploy/docker-compose.yaml deploy/docker-compose.gpu.yaml; do
  count=$(grep -Fxc "$expected" "$file" || true)
  if [[ "$count" -ne 1 ]]; then
    echo "ERROR: $file must forward $key exactly once from the encrypted deploy env" >&2
    exit 1
  fi
done

# The scheduled workflow has three independent deploy-env builders: initial
# RA-TLS boot, per-suite fresh-tree redeploy, and the legacy transport smoke.
count=$(grep -Fc "echo \"${key}=\$DARKNYX_NIGHTLY_FEE_EPOCH_KEY\"" .github/workflows/cvm-e2e.yml || true)
if [[ "$count" -ne 3 ]]; then
  echo "ERROR: cvm-e2e.yml must forward $key in all three deploy-env builders (found $count)" >&2
  exit 1
fi

echo "required encrypted deploy secrets are forwarded at every CVM boundary"
