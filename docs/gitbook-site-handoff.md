# Handoff — publishing the two-tab GitBook site

This file exists to be **copied into the public docs repo alongside the content**,
and its "Prompt" section pasted to the agent working there. Everything under
`docs/gitbook/` in this repo is authored to be transferred as-is.

## What was built here

`docs/gitbook/` is no longer a single space. It is a **site-wide Git Sync
layout**: one `docs.yaml` at the top, and two self-contained space directories,
each published as a tab.

```
docs/gitbook/
  docs.yaml                     site structure -> two tabs
  documentation/                TAB 1 "Documentation"
    .gitbook.yaml
    README.md  SUMMARY.md
    get-started/ how-it-works/ trading-concepts/ account/ sdk/ reference/
  api-reference/                TAB 2 "API Reference"
    .gitbook.yaml
    README.md  SUMMARY.md
    openapi/darknyx-public.yaml GENERATED, admin-stripped
    getting-started/ orders/ instruments/ account/ tree/ settlement/
    system/ websocket/
```

The split follows where the difficulty is. Pages that must *explain* something —
why an order carries a ZK proof, what attestation does and does not guarantee —
stay in Documentation as prose. Pages that describe a wire surface live in API
Reference, where an `{% openapi %}` block renders the parameters, schema and
response interactively from the spec.

## Three properties that are easy to break

**1. Cross-space links must be site-absolute.** A space cannot read a sibling
directory, so `../trading-concepts/order-types.md` resolves to nothing once
published. Every such link is written `/documentation/trading-concepts/order-types`
(no `.md`). There are ~72 of them. They depend on the `path:` values in
`docs.yaml`; changing a `path` breaks all of them at once.

**2. The OpenAPI file is generated, not authored.**
`api-reference/openapi/darknyx-public.yaml` is derived from the internal spec by
`scripts/build-public-openapi.py`, which drops every operation tagged `admin` and
prunes components nothing reachable references. Editing it by hand is reverted on
the next regeneration. `scripts/check-public-openapi.sh` fails CI on drift.

Two traps are already encoded there, both of which bit during construction:
`GET /admin/metrics/settlement` carries **both** `settlement` and `admin` tags, so
a filter keyed on the primary tag publishes the operator surface; and
`securitySchemes` are referenced **by name** from `security:` blocks, never by
`$ref`, so a `$ref`-only prune deletes `BearerAuth` and the published reference
stops saying the API needs a token at all.

**3. The `src` URL must be reachable by GitBook.** Every block points at the raw
URL of the generated spec in the public `skysail-labs/darknyx` repo. GitBook
re-fetches it roughly every 6 hours. If the spec is instead hosted in the docs
repo, rewrite the URL in all 34 blocks consistently — they are the only thing
tying the rendered reference to the schema.

## Prompt for the agent on the site repo

> The docs content in this repo is a GitBook **site-wide Git Sync** layout: a
> `docs.yaml` at the docs root defining two spaces — `documentation` and
> `api-reference` — each with its own `.gitbook.yaml`, `README.md` and
> `SUMMARY.md`. Publish it as a two-tab site.
>
> Please do the following, and do not restructure the content to achieve it:
>
> 1. **Wire up the two sections.** In GitBook, configure site sections so
>    `documentation` publishes at `/documentation` and `api-reference` at
>    `/api-reference`, titled "Documentation" and "API Reference". These paths are
>    load-bearing: roughly 72 cross-space links are written site-absolute against
>    them (`](/api-reference/orders/place-order)`). If you must use different
>    slugs, rewrite those links in the same change. Note that top-level sections
>    require GitBook's Ultimate site plan; if that is not active, say so and stop
>    rather than flattening the two spaces into one.
>
> 2. **Do not hand-edit `api-reference/openapi/darknyx-public.yaml`.** It is
>    generated upstream with operator/admin endpoints stripped. If the API changes,
>    the regenerated file arrives with the next content transfer.
>
> 3. **Confirm the OpenAPI blocks render.** Each endpoint page embeds
>    `{% openapi src="..." path="..." method="..." %}`. Verify a few render as
>    interactive operations rather than as raw text or an error box. If GitBook
>    requires the spec to be registered in its UI as a named specification rather
>    than fetched from the `src` URL, register it and report back what you had to
>    change — do not silently rewrite every block.
>    After synchronization, open the deployed GitBook URL itself and inspect at
>    least one public read and one authenticated operation. Confirm the published
>    blocks render as API operations rather than stale content, raw template text,
>    or an error box; a successful sync command alone is not publication evidence.
>
> 4. **Turn the "Test it" panel OFF for these endpoints, or gate it.** This is
>    important and non-obvious. The engine terminates TLS itself with a
>    self-signed, boot-random, quote-bound certificate that clients verify against
>    `GET /transport-attestation`, not against a public CA. A browser-based try-it
>    panel calling the live enclave will fail TLS, and the apparent "fix" —
>    disabling certificate verification — is exactly what our docs tell readers
>    never to do. Also, `servers:` in the spec currently lists placeholder hosts
>    (`api.darknyx.example.com`). Do not point a try-it panel at a real host until
>    those are replaced with a genuine origin.
>
> 5. **Check the API Reference sidebar** matches `api-reference/SUMMARY.md`:
>    bold non-clickable group headings (`## Trading API`, `## Account API`, ...)
>    with collapsible parent entries beneath them (Orders, Instruments, Account,
>    Merkle Tree, Session Stream) that expand to their child endpoint pages. The
>    intent is a compact, scannable sidebar, not a flat list of 26 endpoints.
>
> Report anything that did not render as described rather than working around it
> by changing the content structure.

## Known gaps, deliberately left

- **`servers:` are placeholders.** They need a real origin before any try-it panel
  is meaningful.
- **The WebSocket API is not generated.** `/v1/stream` is described by a custom
  `x-websocket` extension that GitBook does not render, and GitBook does not
  support AsyncAPI. Those four pages stay hand-written.
- **`RaTlsEvidence` is an orphan schema** in the internal spec — defined, never
  referenced, so the generator prunes it. Either wire it into
  `/transport-attestation`'s response or delete it upstream.
