#!/usr/bin/env python3
"""Derive the PUBLIC OpenAPI spec from the internal wire contract.

`docs/tee-api-openapi.yaml` documents the whole enclave surface, operator
endpoints included. Publishing it as-is would hand every reader the admin
control surface (`/admin/drain`, account disable/enable, token revocation).
This script strips those and prunes any component they alone referenced, so
the published reference cannot describe an endpoint the public may not call.

Two properties worth stating, because both have a failure mode:

* An operation is dropped if it carries the `admin` tag AT ALL, not if `admin`
  is its only tag. `GET /admin/metrics/settlement` is tagged both `settlement`
  and `admin`; a filter keyed on the primary tag would publish it.
* Component pruning is REACHABILITY-based from the surviving operations, so an
  admin-only schema cannot linger in `components` for a curious reader to find.
  Unreferenced schemas are removed even if they were never admin-related.
* `securitySchemes` are reachable by NAME through `security:` blocks, never by
  `$ref`. A purely `$ref`-based walk therefore deletes `BearerAuth` — which 19
  operations declare — and the published reference silently stops saying that
  the API needs a bearer token. They are collected separately below.
* Public GitBook embeds are reference-only. Every surviving operation receives
  `x-hideTryItPanel: true` so a browser control cannot send credentials or order
  data outside the Node RA-TLS verification adapter.

Run via `bash scripts/check-public-openapi.sh` in CI, which regenerates and
diffs; a drifted checked-in artifact fails the build rather than going stale.
"""

import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip3 install pyyaml")

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "tee-api-openapi.yaml"
OUT = ROOT / "docs" / "mintlify" / "api-reference" / "openapi" / "darknyx-public.yaml"
EXCLUDE_TAG = "admin"
METHODS = ("get", "post", "put", "delete", "patch", "options", "head")


def security_scheme_names(node):
    """Scheme names named by any `security:` block, at any depth.

    These are plain map keys, not `$ref`s, so `refs_in` cannot see them.
    """
    out = set()
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "security" and isinstance(v, list):
                for entry in v:
                    if isinstance(entry, dict):
                        out |= set(entry)
            else:
                out |= security_scheme_names(v)
    elif isinstance(node, list):
        for v in node:
            out |= security_scheme_names(v)
    return out


def refs_in(node):
    """Every `$ref` target name reachable from `node`, at any depth."""
    out = set()
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "$ref" and isinstance(v, str):
                out.add(v)
            else:
                out |= refs_in(v)
    elif isinstance(node, list):
        for v in node:
            out |= refs_in(v)
    return out


def main():
    spec = yaml.safe_load(SRC.read_text())

    # 1. Drop every operation carrying the excluded tag, then any path left empty.
    kept_paths, dropped = {}, []
    for path, item in (spec.get("paths") or {}).items():
        keep = {}
        for key, val in item.items():
            if key in METHODS and EXCLUDE_TAG in (val.get("tags") or []):
                dropped.append(f"{key.upper()} {path}")
                continue
            keep[key] = val
        if any(k in METHODS for k in keep):
            kept_paths[path] = keep
    spec["paths"] = kept_paths

    # The published reference explains how to call the API through a verified
    # programmatic transport. A GitBook browser control cannot perform that
    # actual-socket RA-TLS verification, so it must never become an alternate
    # credential/order path.
    for item in kept_paths.values():
        for key, operation in item.items():
            if key in METHODS:
                operation["x-hideTryItPanel"] = True

    # 2. Drop the tag itself so it cannot appear as an empty group in the nav.
    if isinstance(spec.get("tags"), list):
        spec["tags"] = [t for t in spec["tags"] if t.get("name") != EXCLUDE_TAG]

    # 3. Prune components to what the surviving document actually reaches.
    #    Iterate to a fixed point: a kept schema may reference further schemas.
    comps = spec.get("components") or {}
    body = {k: v for k, v in spec.items() if k != "components"}
    reachable = refs_in(body)
    reachable |= {
        f"#/components/securitySchemes/{n}" for n in security_scheme_names(body)
    }
    seen = set()
    while reachable - seen:
        for ref in list(reachable - seen):
            seen.add(ref)
            m = re.fullmatch(r"#/components/([^/]+)/(.+)", ref)
            if not m:
                continue
            bucket, name = m.groups()
            target = (comps.get(bucket) or {}).get(name)
            if target is not None:
                reachable |= refs_in(target)

    removed_components = []
    for bucket, entries in list(comps.items()):
        if not isinstance(entries, dict):
            continue
        for name in list(entries):
            if f"#/components/{bucket}/{name}" not in reachable:
                del entries[name]
                removed_components.append(f"{bucket}/{name}")
        if not entries:
            del comps[bucket]

    header = (
        "# GENERATED — DO NOT EDIT.\n"
        "# Source: docs/tee-api-openapi.yaml\n"
        "# Regenerate: python3 scripts/build-public-openapi.py\n"
        "#\n"
        "# Operator/admin endpoints are stripped here. Edit the source spec.\n"
    )
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(header + yaml.dump(spec, sort_keys=False, width=100, allow_unicode=True))

    ops = sum(1 for i in kept_paths.values() for k in i if k in METHODS)
    print(f"wrote {OUT.relative_to(ROOT)}")
    print(f"  public operations : {ops}")
    print(f"  dropped operations: {len(dropped)}")
    for d in dropped:
        print(f"      - {d}")
    print(f"  pruned components : {len(removed_components)}")


if __name__ == "__main__":
    main()
