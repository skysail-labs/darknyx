# Nyx documentation portal — content source

This directory holds the **public-facing documentation portal**
content. The other docs at the repo root and `docs/` (e.g.
`ARCHITECTURE.md`, `tee-architecture.md`,
`tee-attestation-flow.md`) are engineer-facing reference material;
this directory is the curated, narrative-led version meant for
investors, partners, integrators, and serious technical readers
encountering Nyx for the first time.

---

## Intended target

The content is structured for an MDX-based documentation site
(Next.js App Router + GitBook / Mintlify / Vercel Docs aesthetic).
Each file is a self-contained page that:

- Opens with a one-line "TL;DR" the reader can grasp without
  prior context.
- Uses `# H1` for the page title, `##` for sections, `###` for
  subsections — a consistent hierarchy the right-sidebar TOC can
  consume verbatim.
- Uses fenced code blocks with language hints (`rust`, `ts`,
  `bash`, `text`, `json`, `solidity`-style for Anchor where it
  helps).
- Uses ASCII diagrams (no Mermaid) so the conversion is
  zero-friction; an MDX-side `<Diagram>` component can wrap them
  later if needed.
- Cross-links sibling pages by relative path (`./trust-model`)
  rather than by anchor.

---

## Sitemap

| # | File | Purpose |
|---|---|---|
| 01 | `introduction.md` | Vision, problem, who Nyx is for, headline architecture |
| 02 | `architecture-overview.md` | The three-layer model + system map |
| 03 | `custody-layer.md` | The Solana vault, notes, Merkle tree, on-chain state |
| 04 | `matching-layer.md` | In-TEE matcher, oracle, order book, why TEE |
| 05 | `cryptography.md` | Keys, note system, ZK circuits, replay protection |
| 06 | `trust-model.md` | Attestation, multisig rotation, threat model |
| 07 | `settlement-pipeline.md` | The five-transaction v3.5 batched flow |
| 08 | `api-and-integration.md` | Wire contract, auth model, order lifecycle |
| 09 | `roadmap-and-status.md` | Shipped vs in-flight vs future, the six v2 decisions |
| 10 | `differentiation.md` | Vs MagicBlock PER, godarkdex, Renegade, Penumbra |
| 11 | `glossary.md` | Terms + acronyms |

---

## Recommended sidebar grouping for the MDX site

```text
Introduction
  └─ 01-introduction

Architecture
  ├─ 02-architecture-overview
  ├─ 03-custody-layer
  ├─ 04-matching-layer
  ├─ 05-cryptography
  └─ 06-trust-model

Pipeline
  ├─ 07-settlement-pipeline
  └─ 08-api-and-integration

Status & Roadmap
  ├─ 09-roadmap-and-status
  └─ 10-differentiation

Reference
  └─ 11-glossary
```

For the search index, the H2/H3 anchors give natural fuzzy match
targets without further tagging.

---

## Authoring conventions

- **Inline links to the engineer-facing docs** use the form
  `[Architecture reference](../ARCHITECTURE.md)` so they resolve
  on both GitHub (for source review) and the docs site (where the
  MDX agent will rewrite them to the site's internal routing).
- **Code blocks** show real on-chain types / function signatures
  where they aid the explanation; nothing here is invented.
- **Numbers are real.** Constraint counts, transaction sizes,
  decision dates — all match the source code as of the date in
  the page footer.
- **No emojis** in the prose. The MDX site can add icons as part
  of theming if desired.
</content>
