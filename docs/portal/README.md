# Nyx documentation portal — content source

This directory holds the **public-facing, reference-grade documentation** for
the Nyx protocol: the verbose, grouped API + concepts + "how it works" portal a
trader, integrator, or engineer reads to build against the venue.

It is written to drop into a **Docusaurus** site. Each group is a directory with
a `_category_.json` (the sidebar label + order); each page is a self-contained
Markdown file with frontmatter (`sidebar_position`, `title`, `description`), a
hero TL;DR (`:::info`), a consistent heading hierarchy the right-rail TOC
consumes, admonitions for callouts, and ASCII diagrams in fenced ```text```
blocks (no Mermaid — zero-friction conversion).

## Sidebar groups

```text
Get Started        — what Nyx is, the network, programmatic access
API                — base URLs, authentication, transport & attestation
Reference Data     — instruments
Account            — account model, Merkle proofs, transparency, settlement status
Orders             — place / cancel / modify / get / anchor top-up
WebSocket API      — trading socket, orders channel, fills channel
Trading Concepts   — order types, TIF, execution attributes, clearing price,
                     STP, the anchor pool, order compatibility
SDK                — TypeScript client example
How It Works       — trade flow, TEE architecture, privacy & attestation,
                     shielded pool, settlement, fee structure
Reference          — error codes, system status, glossary
```

## Authoring conventions

- **No emojis** in prose. The theme can add icons.
- **Numbers and field names are real** — they match the protocol as built (the
  `tee-api-openapi.yaml` wire contract and the in-TEE handlers are the source of
  truth; where the two differ, the handler wins).
- **Reader-facing**: no commit/PR references, no "shipped in X" notes, no
  internal file paths, no dated footers. Explain a design choice only where it
  changes what the reader can do or trust.
- **Voice**: professional, concrete, lead with "why it matters to you," then the
  mechanism.

> This portal supersedes the thin flat pages under `docs/site/`. The conceptual
> deep-dives there were the first pass; the content here is the verbose,
> reference-grade version grouped for the public site.
