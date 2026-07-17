# Nyx documentation portal (content source)

This directory holds the **public-facing, reference-grade documentation** for
the Nyx protocol: the verbose, grouped API + concepts + "how it works" portal a
trader, integrator, or engineer reads to build against the venue.

It is written to drop into a **Docusaurus** site. Each group is a directory with
a `_category_.json` (the sidebar label + order); each page is a self-contained
Markdown file with frontmatter (`sidebar_position`, `title`, `description`), a
hero TL;DR (`:::info`), a consistent heading hierarchy the right-rail TOC
consumes, admonitions for callouts, and ASCII diagrams in fenced ```text```
blocks (no Mermaid, for zero-friction conversion).

## Information architecture

The portal follows a product-first path: establish the problem and trust model,
explain how trading works, then move into task guides and exact wire references.
This gives a technical evaluator a coherent narrative without forcing an
integrator to read internal implementation notes before finding an endpoint.

`docs/portal/` and `docs/tee-api-openapi.yaml` are the only public-documentation
sources of truth in this repository. Keep conceptual motivation in the portal
and exact request/response shapes in the OpenAPI contract.

```text
Get Started        - product thesis, trust model, and first integration map
How It Works       - trade flow, TEE architecture, privacy, settlement, and fees
Trading Concepts   - order semantics, time in force, clearing, and compatibility
Account            - custody, deposits, withdrawals, recovery, and chain reads
Reference Data     - market configuration and instruments
Orders             - place, cancel, modify, and inspect
SDK                - TypeScript integration path
API                - base URLs, authentication, transport, and attestation
WebSocket API      - one session stream, order updates, fills, and tree events
Reference          - error codes, status, and glossary
```

## Authoring conventions

- **No emojis** in prose. The theme can add icons.
- **No em dashes** in prose. Use a comma, a colon, parentheses, or a separate
  sentence instead.
- **Numbers and field names are real.** They match the protocol as built (the
  `tee-api-openapi.yaml` wire contract and the in-TEE handlers are the source of
  truth; where the two differ, the handler wins).
- **Reader-facing**: no commit/PR references, no "shipped in X" notes, no
  internal file paths, no dated footers, no roadmap or "coming next" language.
  Explain a design choice only where it changes what the reader can do or trust.
- **Voice**: professional, concrete, lead with "why it matters to you," then the
  mechanism.

The retired `docs/site/` tree was removed so public behavior is never maintained
in two places.
