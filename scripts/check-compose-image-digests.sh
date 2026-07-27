#!/usr/bin/env bash
set -euo pipefail

files=(
  deploy/docker-compose.yaml
  deploy/docker-compose.gpu.yaml
)

failed=0
for file in "${files[@]}"; do
  image_lines=$(grep -Ec '^[[:space:]]+image:' "$file" || true)
  if [[ "$image_lines" -ne 1 ]]; then
    echo "ERROR: $file must contain exactly one service image (found $image_lines)" >&2
    failed=1
    continue
  fi

  image=$(sed -nE 's#^[[:space:]]+image:[[:space:]]+([^[:space:]#]+).*$#\1#p' "$file")
  if [[ ! "$image" =~ ^ghcr\.io/skysail-labs/darknyx-tee@sha256:[0-9a-f]{64}$ ]]; then
    echo "ERROR: $file uses mutable or malformed image identity: $image" >&2
    echo "       expected ghcr.io/skysail-labs/darknyx-tee@sha256:<64 lowercase hex>" >&2
    failed=1
  else
    echo "$file: immutable image identity OK"
  fi
done

exit "$failed"
