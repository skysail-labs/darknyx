# Nyx documentation portal — content source

This directory holds the **public-facing documentation content** for the
Nyx docs site. It is the curated, narrative version meant for technical
readers arriving from the landing page — traders, integrators, and
engineers getting their first real hold on how Nyx works.

It is **not** the engineer-facing reference. The deep implementation
material (`ARCHITECTURE.md`, `CRYPTOGRAPHY.md`, `docs/tee-architecture.md`,
`docs/tee-api-openapi.yaml`) lives elsewhere and is the source of truth for
the technical claims here; this directory restates them for a reader, not a
contributor.

---

## Target: Docusaurus

These pages are written to drop into a **Docusaurus** site. Each is a
self-contained Markdown page with:

- **Frontmatter** — `sidebar_position`, `title`, and `description` (used for
  the sidebar order, the page `<title>`, and SEO/social meta).
- A **hero TL;DR** at the top (a `:::info` admonition) the reader can grasp
  with no prior context.
- A consistent heading hierarchy (`#` title → `##` sections → `###`
  subsections) the right-rail "On this page" TOC consumes verbatim.
- **Admonitions** for callouts: `:::note` (context), `:::tip` (do this),
  `:::caution` (gotcha), `:::info` (key fact).
- **ASCII diagrams** in fenced ```` ```text ```` blocks (no Mermaid) so the
  conversion is zero-friction; wrap in a styled component later if desired.
- **Relative cross-links** between pages (`./trust-model`).

### What this content deliberately omits

This is reader-facing, so it leaves out everything that only matters to a
contributor: commit/PR references, "shipped in X" changelog notes, internal
file paths, dated "last updated" footers, and design choices that don't
change what the reader can do or trust. Architectural choices are explained
only where they help the reader's mental model.

---

## Sitemap & sidebar

Group the pages into these Docusaurus categories (suggested
`_category_.json` labels in **bold**):

```text
Introduction
  └─ 01-introduction

Architecture
  ├─ 02-architecture-overview
  ├─ 03-custody-layer
  ├─ 04-matching-layer
  ├─ 05-cryptography
  └─ 06-trust-model

Settlement
  └─ 07-settlement-pipeline

Integration
  ├─ 08-integration
  └─ 09-api-reference

Reference
  ├─ 10-differentiation
  ├─ 11-roadmap
  └─ 12-glossary
```

| # | File | Purpose |
|---|---|---|
| 01 | `introduction` | Vision, the problem, the three privacy properties, who it's for |
| 02 | `architecture-overview` | The three layers + the system map |
| 03 | `custody-layer` | The vault, notes, the sharded Merkle tree, on-chain state |
| 04 | `matching-layer` | The in-TEE matcher, the batch auction, the oracle, continuations |
| 05 | `cryptography` | Keys, the note model, the ZK circuits, replay protection |
| 06 | `trust-model` | Attestation, governance, what a malicious operator can/can't do |
| 07 | `settlement-pipeline` | The batched, tree-sharded, concurrent settle path |
| 08 | `integration` | The deposit → trade → withdraw lifecycle, the SDK |
| 09 | `api-reference` | The TEE HTTP + WebSocket API, distilled |
| 10 | `differentiation` | How Nyx compares to other private/dark venues |
| 11 | `roadmap` | Where it is and where it's going (forward-looking, no changelog) |
| 12 | `glossary` | Terms + acronyms |

---

## Authoring conventions

- **No emojis** in prose. The site theme can add icons.
- **Numbers are real** — circuit counts, the 1232-byte tx cap, batch sizes
  all match the protocol as built.
- **Voice**: professional but approachable; short paragraphs; lead with the
  "why it matters to you," then the mechanism.
- **Frontmatter template**:

  ```md
  ---
  sidebar_position: 1
  title: Introduction
  description: A one-line summary used for the sidebar tooltip + SEO.
  ---
  ```
</content>
