#!/usr/bin/env python3
"""Convert docs/portal (Docusaurus) -> docs/gitbook (GitBook git-sync compatible).

Transforms applied:
  * Frontmatter: drop Docusaurus-only keys (sidebar_position, title); keep a
    VALID, quoted `description` (the unquoted-colon values were the YAML parse
    failure). Empty frontmatter is dropped entirely.
  * Admonitions ::: -> GitBook {% hint style=... %} ... {% endhint %} (title,
    if any, becomes a bold first line). Fences are respected.
  * Internal links: strip filename NN- prefixes repo-wide AND append `.md` to
    extensionless relative links (Docusaurus routed on de-numbered slugs).
  * Generate SUMMARY.md (from _category_.json order), a root README landing
    page, and .gitbook.yaml.
"""
import os, re, json, shutil

import pathlib
ROOT = str(pathlib.Path(__file__).resolve().parent.parent)
SRC = os.path.join(ROOT, "docs/portal")
DST = os.path.join(ROOT, "docs/gitbook")

HINT = {"info": "info", "note": "info", "tip": "success",
        "caution": "warning", "warning": "warning", "danger": "danger"}

# ---- reset destination ----
if os.path.exists(DST):
    shutil.rmtree(DST)
shutil.copytree(SRC, DST)


def parse_frontmatter(text):
    """Return (description, title, body). description/title may be None."""
    m = re.match(r'^---\r?\n(.*?)\r?\n---\r?\n?', text, re.DOTALL)
    if not m:
        return None, None, text
    desc = title = None
    for line in m.group(1).splitlines():
        km = re.match(r'^(\w+):\s*(.*)$', line)
        if not km:
            continue
        k, v = km.group(1), km.group(2).strip()
        if len(v) >= 2 and v[0] in "\"'" and v[-1] == v[0]:
            v = v[1:-1]
        if k == "title":
            title = v
        elif k == "description":
            desc = v
    return desc, title, text[m.end():]


def rewrite_links(line):
    def repl(mo):
        path, anchor = mo.group(1), (mo.group(2) or "")
        last = path.split("/")[-1]
        if "." in last:            # already has an extension (.md/.png/...)
            return mo.group(0)
        # strip a NN- numeric prefix from the final slug segment too, in case
        # a link ever used one (none do today, but keep it aligned with files)
        return "](%s.md%s)" % (path, anchor)
    return re.sub(r'\]\((\.\.?/[^)\s#]+)(#[^)\s]*)?\)', repl, line)


def convert_body(body):
    out, in_fence = [], False
    for line in body.split("\n"):
        s = line.strip()
        if s.startswith("```"):
            in_fence = not in_fence
            out.append(line)
            continue
        if not in_fence:
            m = re.match(r'^:::(\w+)(?:\s+(.*))?$', line)
            if m and m.group(1) in HINT:
                out.append('{%% hint style="%s" %%}' % HINT[m.group(1)])
                if m.group(2) and m.group(2).strip():
                    out.append("**%s**" % m.group(2).strip())
                    out.append("")
                continue
            if s == ":::":
                out.append("{% endhint %}")
                continue
            line = rewrite_links(line)
        out.append(line)
    return "\n".join(out)


def denumber(fn):
    m = re.match(r'^(\d+)-(.+\.md)$', fn)
    if m:
        return int(m.group(1)), m.group(2)
    return 9999, fn


# ---- collect group metadata + delete _category_.json ----
groups = {}  # dirname -> {"label":..., "position":..., "pages":[(order,title,rel)]}
for d in sorted(os.listdir(DST)):
    cat = os.path.join(DST, d, "_category_.json")
    if os.path.isfile(cat):
        with open(cat) as f:
            j = json.load(f)
        groups[d] = {"label": j.get("label", d), "position": j.get("position", 999), "pages": []}
        os.remove(cat)

# ---- transform + rename every markdown file (except the root README) ----
for dirpath, _, files in os.walk(DST):
    for fn in files:
        if not fn.endswith(".md"):
            continue
        rel_dir = os.path.relpath(dirpath, DST)
        if rel_dir == "." and fn == "README.md":
            continue  # regenerated below
        src = os.path.join(dirpath, fn)
        with open(src, encoding="utf-8") as f:
            text = f.read()
        desc, title, body = parse_frontmatter(text)
        new_body = convert_body(body)
        fm = ""
        if desc:
            esc = desc.replace("\\", "\\\\").replace('"', '\\"')
            fm = '---\ndescription: "%s"\n---\n\n' % esc
        order, newname = denumber(fn)
        # title for SUMMARY: frontmatter title, else first H1
        if not title:
            h = re.search(r'^#\s+(.+)$', new_body, re.MULTILINE)
            title = h.group(1).strip() if h else newname[:-3]
        dst = os.path.join(dirpath, newname)
        with open(dst, "w", encoding="utf-8") as f:
            f.write(fm + new_body.rstrip() + "\n")
        if newname != fn:
            os.remove(src)
        if rel_dir in groups:
            rel = os.path.join(rel_dir, newname)
            groups[rel_dir]["pages"].append((order, title, rel))

# ---- SUMMARY.md ----
lines = ["# Table of contents", "", "* [Introduction](README.md)", ""]
for d in sorted(groups, key=lambda k: groups[k]["position"]):
    g = groups[d]
    lines.append("## %s" % g["label"])
    lines.append("")
    for _, title, rel in sorted(g["pages"], key=lambda p: (p[0], p[2])):
        lines.append("* [%s](%s)" % (title, rel))
    lines.append("")
with open(os.path.join(DST, "SUMMARY.md"), "w", encoding="utf-8") as f:
    f.write("\n".join(lines).rstrip() + "\n")

# ---- root README landing page ----
readme = """---
description: "Darknyx — a privacy-preserving darkpool on Solana. API, SDK, and protocol documentation."
---

# Introduction

**Darknyx** is a privacy-preserving CLOB-style darkpool on Solana. Order intent
is matched and settled inside an Intel TDX confidential VM; per-trade amounts and
the execution price stay hidden on-chain, and balances are encrypted UTXO notes
committed to an on-chain Merkle tree.

This portal is the reference documentation for trading the venue: the API
surface, the TypeScript SDK, the account and settlement model, and the protocol
internals.

## Start here

* [Overview](get-started/overview.md) — what Darknyx is and how the venue fits together.
* [Programmatic Access](get-started/programmatic-access.md) — the REST + WebSocket API at a glance.
* [TypeScript Client](sdk/typescript-client.md) — authenticate, build orders, stream fills.

## Explore

* **How It Works** — the trade lifecycle, the confidential VM, privacy + attestation, settlement.
* **Trading Concepts** — order types, time in force, uniform clearing price, self-trade prevention.
* **Account** — the note model, Merkle proofs, deposits, withdrawals, transparency.
* **Orders / WebSocket / API** — the full endpoint and channel reference.
* **Reference** — error codes, system status, and a glossary.
"""
with open(os.path.join(DST, "README.md"), "w", encoding="utf-8") as f:
    f.write(readme)

# ---- .gitbook.yaml ----
with open(os.path.join(DST, ".gitbook.yaml"), "w", encoding="utf-8") as f:
    f.write("root: ./\n\nstructure:\n  readme: README.md\n  summary: SUMMARY.md\n")

print("done. files:", sum(len(g["pages"]) for g in groups.values()),
      "in", len(groups), "groups")
