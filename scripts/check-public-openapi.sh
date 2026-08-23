#!/usr/bin/env bash
# The published OpenAPI spec must be a faithful, admin-free derivative of the
# internal wire contract.
#
# `docs/gitbook/api-reference/openapi/darknyx-public.yaml` is what the public
# docs render. It is GENERATED from `docs/tee-api-openapi.yaml`. Two ways that
# goes wrong, both of which this guard catches:
#
#   1. The source spec gains an endpoint and the checked-in artifact is not
#      regenerated, so the published reference documents a stale API.
#   2. Someone edits the artifact by hand; the next regeneration silently
#      reverts it.
#
# It also asserts the two properties the generator exists to provide, rather
# than trusting the generator: no admin surface, and the bearer scheme intact.
# The second is not paranoia — a `$ref`-only reachability prune deletes
# `BearerAuth` (named by `security:` blocks, never `$ref`d) and the published
# spec then stops saying the API needs a token at all.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ART="$ROOT/docs/gitbook/api-reference/openapi/darknyx-public.yaml"

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required to verify the public OpenAPI spec" >&2
  exit 2
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cp "$ART" "$tmp/committed.yaml"

python3 "$ROOT/scripts/build-public-openapi.py" >/dev/null

if ! diff -q "$tmp/committed.yaml" "$ART" >/dev/null; then
  echo "ERROR: the public OpenAPI spec is out of date." >&2
  echo >&2
  diff -u "$tmp/committed.yaml" "$ART" | head -40 >&2 || true
  echo >&2
  echo "Regenerate and commit:  python3 scripts/build-public-openapi.py" >&2
  cp "$tmp/committed.yaml" "$ART"
  exit 1
fi

python3 - "$ART" <<'PY'
import sys, yaml
spec = yaml.safe_load(open(sys.argv[1]))
errs = []

admin = [f"{m.upper()} {p}"
         for p, item in (spec.get("paths") or {}).items()
         for m, op in item.items()
         if isinstance(op, dict) and "admin" in (op.get("tags") or [])]
if admin:
    errs.append("admin operations present in the PUBLIC spec: " + ", ".join(admin))

if [p for p in (spec.get("paths") or {}) if p.startswith("/admin")]:
    errs.append("a path under /admin survived into the public spec")

schemes = (spec.get("components") or {}).get("securitySchemes") or {}
if "BearerAuth" not in schemes:
    errs.append("BearerAuth securityScheme was pruned; authenticated endpoints "
                "would render as though they need no token")

methods = {"get", "post", "put", "delete", "patch", "options", "head"}
expected_bearer = {
    ("post", "/auth/token/revoke"),
    ("post", "/orders"),
    ("get", "/orders/{order_id}"),
    ("delete", "/orders/{order_id}"),
    ("put", "/orders/{order_id}"),
    ("get", "/account"),
    ("get", "/account/settings"),
    ("put", "/account/settings"),
    ("get", "/tree/inclusion"),
    ("get", "/tree/leaves"),
    ("get", "/settlement/status/{batch_id}"),
}
seen_bearer = set()
for path, item in (spec.get("paths") or {}).items():
    for method, op in item.items():
        if method not in methods or not isinstance(op, dict):
            continue
        security = op.get("security")
        has_bearer = any(
            isinstance(requirement, dict) and "BearerAuth" in requirement
            for requirement in (security or [])
        )
        key = (method, path)
        if has_bearer:
            seen_bearer.add(key)
        if key not in expected_bearer and security not in (None, []):
            errs.append(f"unexpected authentication requirement on {method.upper()} {path}")
        if op.get("x-hideTryItPanel") is not True:
            errs.append(f"GitBook Test it panel is enabled on {method.upper()} {path}")

missing_bearer = sorted(expected_bearer - seen_bearer)
unexpected_bearer = sorted(seen_bearer - expected_bearer)
if missing_bearer:
    errs.append("protected operations lost BearerAuth: " + ", ".join(
        f"{method.upper()} {path}" for method, path in missing_bearer))
if unexpected_bearer:
    errs.append("public operations unexpectedly require BearerAuth: " + ", ".join(
        f"{method.upper()} {path}" for method, path in unexpected_bearer))
if spec.get("security") not in (None, []):
    errs.append("global security is unsupported; public operations must remain unambiguous")

if not (spec.get("paths") or {}):
    errs.append("the public spec has no paths at all")

if errs:
    for e in errs:
        print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)

ops = sum(1 for i in spec["paths"].values() for k in i
          if k in ("get", "post", "put", "delete", "patch"))
print(f"check-public-openapi: OK ({len(spec['paths'])} paths, {ops} operations, admin-free)")
PY
