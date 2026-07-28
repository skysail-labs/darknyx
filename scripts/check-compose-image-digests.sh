#!/usr/bin/env bash
# Every container image in every deployment compose must be pinned by immutable
# digest, and must come from a repository we have deliberately approved.
#
# WHY THIS GATE EXISTS (audit finding T-04)
#
# `compose_hash` is a hash of the compose TEXT, and that hash is what RTMR3
# measures, what dstack governance allowlists, and what every client pins. If the
# text names a mutable tag, the measurement binds only "run whatever is at that
# tag" — anyone able to re-point it swaps the code the enclave runs while RTMR3,
# the allowlist entry, and every client's expected compose_hash stay
# byte-identical. Attestation keeps passing, and it is attesting to the wrong
# thing. A digest makes compose_hash transitively bind the exact image bytes,
# which is what the measurement is already universally assumed to mean.
#
# WHY IT CHECKS EVERY IMAGE, NOT THE FIRST ONE
#
# This script used to assert "exactly one image per file" and match it against a
# single hardcoded repository. That was adequate while the compose ran one
# service and actively harmful the moment it did not: a second service — an
# ingress sidecar, a log shipper, anything — is precisely the case where an
# unpinned image would slip in, and the old shape either refused to look at it or
# rejected the file for the wrong reason. The property is per-image, so the check
# is per-image.
#
# ADDING A SERVICE
#
# Adding a repository here is the deliberate approval step, not a formality. The
# image joins compose_hash, and therefore joins what the governance ceremony
# signs and what clients pin. Add it to APPROVED_REPOS in the same change that
# adds the service, and record the source→tag→digest mapping in the release
# evidence.
set -euo pipefail

files=(
  deploy/docker-compose.yaml
  deploy/docker-compose.gpu.yaml
)

# Repositories permitted to appear in a deployment compose. Digest-pinning alone
# is not enough: a digest-pinned image from an unexpected repository is still an
# unexpected image, and the point is that every byte in these files is reviewed.
APPROVED_REPOS=(
  ghcr.io/skysail-labs/darknyx-tee
)

repo_approved() {
  local candidate="$1"
  for approved in "${APPROVED_REPOS[@]}"; do
    if [[ "$candidate" == "$approved" ]]; then
      return 0
    fi
  done
  return 1
}

failed=0
for file in "${files[@]}"; do
  if [[ ! -f "$file" ]]; then
    echo "ERROR: $file is missing" >&2
    failed=1
    continue
  fi

  # Every `image:` value, comments and inline trailing comments stripped.
  mapfile -t images < <(sed -nE 's#^[[:space:]]*image:[[:space:]]+([^[:space:]#]+).*$#\1#p' "$file")

  if [[ "${#images[@]}" -eq 0 ]]; then
    echo "ERROR: $file declares no image — a deployment compose with no image is" >&2
    echo "       almost certainly a parsing failure in this check, not an empty file" >&2
    failed=1
    continue
  fi

  for image in "${images[@]}"; do
    if [[ ! "$image" =~ ^([^@[:space:]]+)@sha256:[0-9a-f]{64}$ ]]; then
      echo "ERROR: $file pins a mutable or malformed image: $image" >&2
      echo "       expected <repository>@sha256:<64 lowercase hex>" >&2
      echo "       a tag lets the image change underneath an unchanged compose_hash" >&2
      failed=1
      continue
    fi
    repo="${BASH_REMATCH[1]}"
    if ! repo_approved "$repo"; then
      echo "ERROR: $file uses unapproved image repository: $repo" >&2
      echo "       add it to APPROVED_REPOS in $0 in the same change that adds the" >&2
      echo "       service, and record its source→tag→digest in the release evidence" >&2
      failed=1
      continue
    fi
    echo "$file: $repo pinned by digest OK"
  done
done

exit "$failed"
