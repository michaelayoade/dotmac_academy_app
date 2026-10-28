# ADR 0006 — Adopt the shared UI contract without transferring product identity

**Status:** Accepted
**Date:** 2026-08-11

## Context

Academy maintained a hand-written Tailwind colour map while `dotmac-ui` already
owned the fleet-wide token roles, compiled stylesheet, focus contract and theme
attribute. A dependency declaration alone would not make Academy a consumer:
its pages could still omit the asset and its build could keep baking independent
colour literals.

Academy's emerald, sand/ink and clay palette is intentional product identity.
The generic blue/cyan values in `dotmac-ui` are placeholders, not a mandate to
rebrand a product. Academy also supports only a light visual mode today.

## Decision

Academy is an external consumer of `dotmac-ui==0.1.0a3`, UI contract 1.

- `dotmac-ui` owns public token names, the generated Tailwind preset, compiled
  asset path/digest, focus-visible base rule and theme attribute.
- `app/ui.py` is Academy's single composition boundary. It mounts the installed
  package asset before the `/static` catch-all and supplies template globals.
  Academy never checks in a copy of the package stylesheet or preset.
- `src/input.css` owns Academy's product values by re-declaring shared variables.
  The old `brand`, `sand`, `ink` and `clay` utilities remain temporary
  compatibility aliases backed by those variables. New markup uses role names
  from the preset (`surface-*`, `content-*`, `stroke-*`, `action-*`, `status-*`).
- Full-colour variables retain Oklch authoring values. The a3 preset needs sRGB
  channels for opacity modifiers, so Academy publishes paired, clipped sRGB
  channels. Brand 600–800 exceed sRGB slightly; clipping them is accepted for
  utility output rather than growing a second preset or breaking alpha support.
- Academy pins `data-dmui-theme="light"`. It will adopt the package's pre-paint
  theme bootstrap only after public and authenticated surfaces have complete
  dark role values and visual-contract tests. An OS preference must not activate
  a partial dark theme.

## Enforcement and cutover

`tests/architecture/test_dotmac_ui_adoption.py` ratchets the dependency, mount
order, all full-page templates, installed preset resolution, complete product
ramps, key contrast pairs and alpha-capable compiled output. CI rebuilds the
tracked Academy stylesheet and fails on drift.

The legacy aliases can be removed only after an inventory finds no remaining
`brand`/`sand`/`ink`/`clay` utility consumers. That deletion is a later focused
slice; this ADR makes the shared role layer the only forward path now.

## Consequences

Academy becomes the first maintained external `dotmac-ui` consumer without a
visible rebrand or a Tailwind-major migration. Package upgrades are deliberate
exact-pin changes. Token/API drift and a missing asset link become CI failures
instead of browser-only regressions.
