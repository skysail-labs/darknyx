# Brand — Darknyx

_Status: active — adopted from `design-system/` identity system v2.0._

Darknyx is a privacy-preserving darkpool on Solana: hidden intent and
TEE-attested matching, with zero-knowledge settlement. The product promise is
“Settle in the dark. Prove in the light.”

## Direction

Darknyx should feel serious, technical, and quietly premium. It is an execution
surface, not a casino dashboard: dense information is welcome when hierarchy is
clear, decoration is not. Warm near-black ground makes the restrained gold read
as light rather than as a generic fintech accent.

Gold means **live**—the selected market, the action currently available, or a
verified active state. It does not draw borders, grids, or ornamental emphasis.
Structural rules stay neutral. Product state uses green for healthy/confirmed,
amber for pending/attesting, and red for failed/cancelled; state is always paired
with text or an icon and never communicated by color alone.

Copy is concise, specific, and calm. Name the operation and its consequence:
“Waiting for an accepted root,” “Order pending settlement,” “Attestation
failed.” Avoid hype, cute language, and claims that exceed the verified privacy
or trust boundary.

## Palette

Palette name: **Warm Horizon** (the shipped Darknyx v2 system).

| Token                  | Value                   | Use                                  |
| ---------------------- | ----------------------- | ------------------------------------ |
| Ink                    | `#0a0908`               | Primary dark ground                  |
| Ink deep               | `#060505`               | Deepest trough                       |
| Raised                 | `#100e0c`               | First elevation                      |
| Surface                | `#14120f`               | Cards and panels                     |
| Surface 2              | `#1a1713`               | Raised controls/popovers             |
| Surface 3              | `#221e19`               | Highest surface, rare                |
| Chalk                  | `#f4f1eb`               | Primary text                         |
| Chalk 2                | `rgba(244,241,235,.66)` | Running text                         |
| Chalk 3                | `rgba(244,241,235,.52)` | Labels/captions; 5.2:1 on ink        |
| Chalk 4                | `rgba(244,241,235,.26)` | Decoration only; never required text |
| Gold                   | `#e0a94a`               | Live/primary signal                  |
| Gold bright            | `#f0cd8e`               | Gold highlight, not body text        |
| Gold deep              | `#a97a2c`               | Gold on light surfaces               |
| Steel                  | `#8b9bb0`               | Explicitly not-live state            |
| Line / line 2 / line 3 | chalk at 7% / 13% / 22% | Neutral structure                    |
| Signal green           | `#5fb85f`               | Healthy, matched, confirmed          |
| Signal amber           | `#d9a441`               | Pending, attesting                   |
| Signal red             | `#c84545`               | Failed, rejected, cancelled          |

Primary controls use ink text on a gold ground. Required text never uses Chalk
4, gold wash, or faint signal colors. Light mode uses Chalk as ground, white as
the elevated surface, Ink as text, `#6b6b74` as muted text, and Gold Deep for
live text/rules. Every foreground/background pair must pass WCAG AA; focus rings
must pass 3:1 against their adjacent surface.

## Typography

- **Display — Newsreader 400/500/600:** page titles, section titles, and
  ornamental numerals only. Never running UI copy.
- **Text — Inter 400/500/600:** every running word, input, button, navigation
  item, and error message.
- **Mono/label — IBM Plex Mono 400/500:** prices, token amounts, addresses,
  proof/root identifiers, status keys, and tracked uppercase labels.

Display maximum is weight 600. UI numbers use tabular figures. Labels are
uppercase with approximately `0.22em` tracking and never smaller than 9.5px;
ordinary readable text is at least 12px.

## Shape, spacing, and motion

- 4px spacing base; standard card padding 16–24px.
- Public and reading shells max out at 1240px; the dense three-pane trader may
  extend to 1440px so the order table and ticket remain legible. Both use a
  responsive gutter below their maximum width.
- Cards/panels use 6px radius; large plates 10px; buttons may be pill-shaped.
  Controls are rounded, containers remain near-square.
- Structure uses a 1px neutral border or a shadow, not both by default.
- Pointer state changes use 280ms `cubic-bezier(0.22, 1, 0.36, 1)`; fast
  feedback uses 160ms. Narrative 900ms motion does not belong in trading flows.
- All non-essential motion is disabled under `prefers-reduced-motion`.

## Logo

Use the Horizon mark with its documented clearspace. Minimum size is 16px; use
the micro mark below 24px. Do not stretch, rotate, flip, gradient-fill, shadow,
or place it on low-contrast ground. Product code may implement the mark as an
inline current-color SVG so it does not depend on the uncommitted reference
directory.

## Product usage

Do:

- keep order entry and market state legible before adding visual flourish;
- reserve gold for verified/live/primary states;
- show venue-wide and market-local health separately;
- pair every pending/failed/confirmed color with a word and symbol;
- use aggregate balances and opaque readiness handles in page-facing code.

Do not:

- use gradients on the mark or generic purple/blue crypto gradients;
- make every metric gold;
- hide degraded trust, stale proofs, or ambiguous settlement behind a toast;
- expose raw seeds, openings, witnesses, proof bytes, or generic signing APIs to
  the trader UI;
- describe TEE execution as trustless or gross deposit/withdraw amounts as
  private.
