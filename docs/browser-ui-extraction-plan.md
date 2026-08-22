# Extracting the browser trader UI into its own repository

> **Status:** plan, not yet executed. Written 2026-08-22.
> **Scope:** move the *presentational* layer of `packages/browser-client` into a
> standalone repo for UI/design iteration, leaving custody, proving, transport,
> and the signed-release pipeline in this monorepo.

---

## 1. Why this shape, and not a whole-package copy

The original idea was to copy `packages/browser-client` wholesale into a new
repo, keep this copy untouched, and periodically re-sync. The investigation
below changed the recommended cut.

### 1.1 The UI is already a clean seam

`src/ui/` has **no dependency on any security code in the package**. Its entire
outside import surface is:

```text
react, react-dom, lucide-react
./types.js, ./trader-shell.js, ./mark.js, ./trader-product.js, ./styles.css
import type { ... } from "@darknyx/client-core"     <- TYPE-ONLY, 4 names
```text

It imports nothing from `custody/`, `prover/`, `inventory/`, `venue/`,
`wallet/`, or `account/`. The contract is explicit and already named:
`TraderShellProps` / `TraderShellActions` / `TraderShellSnapshot` in
`src/ui/types.ts`. `trader/controller.ts` implements one side; `app/main.tsx`
wires them together.

### 1.2 The UI is 10% of the package

| directory | lines | nature |
|---|---:|---|
| `src/inventory/` | 1,957 | note tracking |
| `src/custody/` | 1,752 | **WebAuthn-PRF, key handling** |
| `src/trader/` | 1,396 | controller |
| **`src/ui/`** | **1,181** | **← the target** |
| `src/prover/` | 1,052 | in-browser proving |
| `src/venue/` `src/account/` `src/app/` `src/wallet/` | 1,467 | transport, release verification |
| **total** | **11,687** | |

A whole-package copy forks ~10,500 lines of security-relevant code to reach
1,181 lines of React.

### 1.3 Three concrete costs of the whole-package copy

1. **Drift on a surface with no gate.** `browser-client` consumes **nine**
   deliberately browser-safe SDK subpaths — `browser-orders`,
   `browser-inventory-crypto`, `browser-attestation`, `browser-recovery`,
   `browser-account`, `api-url`, `slot`, `merkle-root-ring`, and the root
   barrel. The `@solana/web3.js` v1→v3 port (#186) is exactly the class of
   change that desyncs a fork, and "copy it over now and then" is manual review
   of crypto plumbing rather than a check that can fail.

2. **Two repos that can both emit a signed release.** `scripts/` holds
   `sign-artifact-manifest.mjs`, `assemble-production-release.mjs`,
   `release-assembly-guards.mjs`, and `verify-production-app.mjs`. SRI pinning
   assumes one canonical build. Forking makes "which build do the pins describe"
   an open question at exactly the wrong moment.

3. **Timing against T-03B.** `docs/transport-integrity-remediation-plan.md`
   Phase 4 (`remediation/browser-release-integrity`) makes `release.json`
   non-retargetable to close R-01, and Phase 6 retires the plaintext proxy.
   Both land in `venue/`, `app/`, and the release scripts. Under the UI-only
   cut, **T-03B does not touch the new repo at all.**

### 1.4 The decision, in one line

Cut at `TraderShellSnapshot`. The new repo owns pixels; the monorepo owns keys.

---

## 2. Decisions taken

| # | Decision | Rationale |
|---|---|---|
| **D1** | New repo starts as a **UI workshop**, not the future home of the whole browser client | Workshop → full app is additive and cheap later. Full fork → back is reconciling drifted crypto by hand. |
| **D2** | **The monorepo stays the only release-producing repo** | One signing identity, one build, one artifact. Also: R-01 hardening of the release mechanism is in flight. |
| **D3** | The new repo produces **no signed artifact** | It builds a dev preview against fixtures only. |
| **D4** | Sync via `git subtree` on a shared root-level branch | Real 3-way merges with history, not clobbering copies. |
| **D5** | `tsc` against the real `client-core` on merge-back is **the** drift gate | A gate that can fail, unlike manual review. |

**D1 re-entry trigger:** revisit the workshop/full-app split when the new repo
needs to own something *outside* `TraderShellProps` — routing, auth, multiple
pages, or its own transport. Until then the workshop cut is doing its job.

---

## 3. What moves, what stays

### 3.1 Moves (synced, lives in both)

```text
packages/browser-client/src/ui/index.ts            20 lines
packages/browser-client/src/ui/types.ts           143 lines   <- the contract
packages/browser-client/src/ui/trader-shell.tsx   965 lines
packages/browser-client/src/ui/trader-product.tsx  27 lines
packages/browser-client/src/ui/mark.tsx            26 lines
packages/browser-client/src/ui/styles.css          24 KB
```text

### 3.2 Copied once, then diverges freely (new repo owns it)

```text
packages/browser-client/tests/ui-preview.tsx      118 lines   <- fixture harness, ALREADY EXISTS
packages/browser-client/tests/ui-preview.html      16 lines
packages/browser-client/tests/trader-shell.test.tsx 174 lines
```text

> **A fixture harness already exists.** `tests/ui-preview.tsx` renders
> `<TraderShell snapshot={snapshot} actions={actions} />` against a static
> `TraderShellSnapshot` with `noop` actions, and `npm run build:preview`
> (`DARKNYX_UI_PREVIEW=1`) already bundles it. This is most of the new repo's
> dev loop, working today. The new repo grows it into fixture *sets*
> (empty / funded / mid-order / error / proving) rather than inventing one.

### 3.3 Stays in the monorepo, unmoved

Everything else — `custody/`, `prover/`, `inventory/`, `venue/`, `wallet/`,
`account/`, `app/`, `trader/`, all of `scripts/`, and
`tests/bundle-boundary.test.ts` (a custody guard that needs `src/index.js` and
the built `dist/*.worker.js`, and is not a UI test despite matching on `ui`).

---

## 4. The `@darknyx/client-core` dependency

`src/ui/types.ts` imports **four type-only names**, all from the single file
`packages/client-core/src/types.ts`:

```ts
import type {
  EncryptedSeedBackupV2,   // types.ts:81
  ProofReadinessView,      // types.ts:31
  SubmitIntentResult,      // types.ts:50
  VaultStatus,             // types.ts:76
} from "@darknyx/client-core";
```text

Type-only means **no runtime code is duplicated** — the new repo carries nothing
that can drift into a security bug.

**Approach:** the new repo vendors a small `types/client-core-shim.d.ts`
declaring `module "@darknyx/client-core"` with just those four. It is explicitly
a *shim, not truth* — if it drifts, the merge-back typecheck (§6.3) against the
real package is what catches it.

Rejected alternatives: publishing `client-core` to GitHub Packages (real
release plumbing for four interfaces), and a git dependency on this private
monorepo (forces every UI contributor to have monorepo access).

---

## 5. Repository layout

```text
darknyx-trader-ui/
├── src/ui/                    <- SUBTREE. Do not restructure; see §6.
│   ├── index.ts
│   ├── types.ts
│   ├── trader-shell.tsx
│   ├── trader-product.tsx
│   ├── mark.tsx
│   └── styles.css
├── src/fixtures/              <- new repo owns
│   ├── empty.ts
│   ├── funded.ts
│   ├── mid-order.ts
│   ├── proving.ts
│   └── error.ts
├── src/preview/               <- new repo owns: fixture switcher, theme toggle
│   ├── main.tsx
│   └── index.html
├── types/client-core-shim.d.ts
├── tests/trader-shell.test.tsx
├── package.json               <- React/design deps live HERE
├── vite.config.ts
└── README.md                  <- MUST carry the §7 warning
```text

> **`src/ui/` is subtree-managed.** Renaming, splitting, or moving files inside
> it breaks the sync path mapping. Reorganising is a deliberate, coordinated
> change made on both sides at once — not something to do casually mid-design.
> Everything outside `src/ui/` is the new repo's own and may be restructured
> freely.

---

## 6. Sync mechanism

Path mapping (both sides carry a prefix; the shared branch is the root-level
canonical form):

```text
monorepo  packages/browser-client/src/ui/   <──> ui-sync branch (files at root) <──>  src/ui/  ui repo
```text

### 6.1 Seeding (once)

```sh
# --- in the monorepo ---
cd /path/to/darknyx
git checkout main && git pull
git subtree split --prefix=packages/browser-client/src/ui -b ui-sync
git push origin ui-sync

# --- create the empty GitHub repo, then ---
cd /path/to/darknyx-trader-ui
git init && git commit --allow-empty -m "chore: initial commit"
git remote add monorepo git@github.com:skysail-labs/darknyx.git
git fetch monorepo ui-sync
git subtree add --prefix=src/ui monorepo ui-sync
```text

`src/ui/` now carries its real per-file history, not one squashed import.

### 6.2 Monorepo → UI repo (pick up upstream UI changes)

```sh
# monorepo: refresh the sync branch
git checkout main && git pull
git subtree split --prefix=packages/browser-client/src/ui -b ui-sync
git push origin ui-sync --force-with-lease

# ui repo
git fetch monorepo ui-sync
git subtree pull --prefix=src/ui monorepo ui-sync
```text

### 6.3 UI repo → monorepo (bring design work home) — **the gated direction**

```sh
# ui repo
git subtree split --prefix=src/ui -b ui-sync
git push monorepo ui-sync --force-with-lease

# monorepo, on a branch — never straight to main
git checkout -b ui/sync-$(date +%Y-%m-%d)
git fetch origin ui-sync
git subtree merge --prefix=packages/browser-client/src/ui origin/ui-sync
```text

Then **the gate** — this is what makes the shim in §4 safe:

```sh
./node_modules/.bin/tsc -p packages/client-core/tsconfig.json     # emits dist/
./node_modules/.bin/tsc -p packages/sdk/tsconfig.json             # emits dist/
./node_modules/.bin/tsc -p packages/browser-client/tsconfig.json --noEmit
( cd packages/browser-client && npm run build && npm run test:unit )
```text

If the shim drifted from real `client-core`, the third line fails here. Open a
normal PR; the existing `pr-checks` browser-client jobs run on it.

> `--force-with-lease` on `ui-sync` is correct and safe: it is a generated
> branch, never worked on directly, and `git subtree split` recomputes it
> deterministically. Do not treat it as a normal branch.

### 6.4 Fallback if subtree proves awkward

`rsync -a --delete` of the directory plus a `sha256` manifest committed on both
sides, with CI failing when the manifests disagree. Simpler to operate; loses
per-file history and does real clobbering instead of 3-way merges. Only fall
back if §6.2/§6.3 causes repeated conflict pain.

---

## 7. Rules for the new repo

Put these in its `README.md` verbatim. They are the whole reason the split is
safe:

1. **No keys, no seeds, no signing.** If a change wants a private key, a
   passphrase, a WebAuthn credential, or a real signature, it belongs in the
   monorepo. There is no exception.
2. **No real network.** Fixtures only. No CVM gateway, no Solana RPC, no
   devnet. If a change needs live data, the contract in `types.ts` is wrong —
   fix the contract, in the monorepo, first.
3. **This repo ships no signed release.** `npm run build` produces a dev
   preview. Production artifacts come from the monorepo, always.
4. **`src/ui/` is subtree-managed** — see §5.
5. **Contract changes are monorepo-first.** Adding a field to
   `TraderShellSnapshot` means `trader/controller.ts` must populate it. Change
   `types.ts` here and the merge-back typecheck fails — by design.

---

## 8. Execution steps

> **Do not run any step below until §9 is answered.** These commands create a
> repository and start syncing code; the direction of that sync is the open
> question in §9. Seeding before it is decided commits you to a topology that
> is awkward to reverse once design work exists in the new repo.

| # | Step | Where |
|---|---|---|
| 1 | Create empty private repo `skysail-labs/darknyx-trader-ui` | GitHub |
| 2 | Seed `src/ui/` per §6.1 | both |
| 3 | Copy the three harness files (§3.2), adapt import paths | ui repo |
| 4 | Write `types/client-core-shim.d.ts` (§4) | ui repo |
| 5 | `package.json` + Vite + vitest; confirm `TraderShell` renders from a fixture | ui repo |
| 6 | Split `ui-preview.tsx`'s single snapshot into the five fixture sets (§5) | ui repo |
| 7 | Build the preview shell: fixture switcher, theme toggle, viewport sizes | ui repo |
| 8 | `README.md` carrying §7 verbatim | ui repo |
| 9 | CI: typecheck + `trader-shell.test.tsx` on PR | ui repo |
| 10 | Dry-run a full round trip — trivial UI edit → §6.3 → PR → green | both |
| 11 | Note the sync procedure in `packages/browser-client/README.md`, link here | monorepo |

**Step 10 is not optional.** The sync path is the part of this plan most likely
to be wrong, and the cheapest moment to find that out is against a one-line
change, before any real design work exists to lose.

---

## 9. Open question for the owner

**Does refined UI come back to the monorepo, or does `packages/browser-client/src/ui`
eventually become a stub?**

The original framing was "update the separate repo with changes we make here"
— monorepo → UI repo. But the point of the split is that *design work happens
in the new repo*, so that work has to travel the other way (§6.3) or this
repo's UI goes stale and the shipped product stops matching the design.

This plan assumes **bidirectional, with the monorepo remaining canonical for
what ships**. The alternative — the new repo eventually becomes the source of
truth for the UI and the monorepo consumes it as a package — is coherent, but
it is D1's promotion path and should be a deliberate decision, not a drift.

---

## 10. What this plan does not do

- Does not move, modify, or fork `custody/`, `prover/`, `inventory/`, or any
  SDK subpath consumer.
- Does not change the release pipeline, `release.json`, or SRI pinning.
- Does not touch T-03B. Phases 4–6 proceed in the monorepo unaffected.
- Does not remove anything from this repo. `packages/browser-client` remains
  complete and buildable throughout.
