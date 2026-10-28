---
name: "Dotmac Academy — Academic Modernist"
description: "A calm, rigorous operations workspace for learning, teaching, and academy administration."
colors:
  forest-50: "#eef7f0"
  forest-100: "#dcefe1"
  forest-200: "#b8dec4"
  forest-300: "#87c39c"
  forest-400: "#4e9b6d"
  forest-500: "#226b47"
  forest-600: "#0d5a34"
  forest-700: "#084728"
  forest-800: "#003b20"
  forest-900: "#002f18"
  forest-950: "#001d0f"
  paper-white: "#ffffff"
  sage-canvas: "#f8faf4"
  sage-soft: "#f4f6f0"
  warm-line: "#e2e5dc"
  neutral-400: "#c0c9bf"
  neutral-500: "#919b91"
  neutral-600: "#6b756d"
  neutral-700: "#404942"
  neutral-800: "#2b312c"
  ink: "#191c19"
  ink-deep: "#0e100e"
  clay-50: "oklch(0.98 0.02 80)"
  clay-100: "oklch(0.95 0.04 78)"
  clay-200: "oklch(0.90 0.07 72)"
  clay-300: "oklch(0.83 0.09 67)"
  clay-400: "oklch(0.76 0.11 62)"
  clay-500: "oklch(0.70 0.125 58)"
  clay-600: "#8a3d16"
  clay-700: "oklch(0.54 0.12 46)"
  clay-800: "oklch(0.45 0.10 42)"
  clay-900: "oklch(0.37 0.075 39)"
  clay-950: "oklch(0.25 0.05 36)"
typography:
  display:
    fontFamily: "Domine, ui-serif, Georgia, serif"
    fontSize: "clamp(1.75rem, 2.5vw, 2.25rem)"
    fontWeight: 700
    lineHeight: 1.15
    letterSpacing: "-0.025em"
  headline:
    fontFamily: "Domine, ui-serif, Georgia, serif"
    fontSize: "1.125rem"
    fontWeight: 600
    lineHeight: 1.35
    letterSpacing: "-0.025em"
  body:
    fontFamily: "Hanken Grotesk, ui-sans-serif, system-ui, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: "normal"
  label:
    fontFamily: "Hanken Grotesk, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.6875rem"
    fontWeight: 700
    lineHeight: 1.4
    letterSpacing: "0.15em"
  data:
    fontFamily: "Hanken Grotesk, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.25
    letterSpacing: "normal"
rounded:
  control: "4px"
  surface: "8px"
  code: "5.6px"
  pill: "9999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "16px"
  lg: "24px"
  xl: "32px"
components:
  button-primary:
    backgroundColor: "{colors.forest-700}"
    textColor: "{colors.paper-white}"
    typography: "{typography.body}"
    rounded: "{rounded.control}"
    padding: "8px 16px"
    height: "44px"
  button-primary-hover:
    backgroundColor: "{colors.forest-800}"
    textColor: "{colors.paper-white}"
  button-ghost:
    backgroundColor: "{colors.paper-white}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    padding: "8px 16px"
    height: "44px"
  surface-card:
    backgroundColor: "{colors.paper-white}"
    textColor: "{colors.ink}"
    rounded: "{rounded.surface}"
  status-badge:
    typography: "{typography.data}"
    rounded: "{rounded.pill}"
    padding: "2.88px 9.6px"
---

# Design System: Dotmac Academy — Academic Modernist

## Overview

**Creative North Star: “The Academic Operations Desk”**

Dotmac Academy is a calm Academic Modernist workspace: pale sage canvas, white working surfaces, Oxford-forest controls, emerald progress signals, warm-grey structure, sturdy editorial headings, and crisp grotesk data text. It is intentionally compact and architectural rather than decorative, nostalgic, or built from generic floating cards.

This is an Operate system. Scanability, complete data visibility, predictable navigation, and explicit state outrank ornament. The shipped Stitch direction is the visual authority; the existing Dotmac Academy fiber/node logo and product name remain in the header.

**Key Characteristics:**

- Forest-led state and action language on a pale sage/white field.
- Domine for editorial hierarchy; Hanken Grotesk for controls, prose, and dense data.
- 4px controls, 8px surfaces, hairline borders, and restrained forest-tinted elevation.
- One consistent active-navigation rule across role tabs and the contextual sidebar.
- Full keyboard, reduced-motion, narrow-screen, and wide-table access.

## Colors

The normative palette is the frontmatter above and the final Academic Modernist `:root` overrides in `src/input.css`. Forest is for actions, active state, focus, progress, and selected navigation; it is not a decorative wash.

### Primary

- **Oxford Forest** (`forest-700`, `#084728`): primary buttons and active area tabs.
- **Deep Forest** (`forest-800`, `#003b20`): hover; `forest-900` (`#002f18`) is the darkest branded field.
- **Emerald Signal** (`forest-500`, `#226b47`): progress, active markers, and page labels; `forest-600` (`#0d5a34`) is the focus-ring color.
- **Sage Highlight** (`forest-50`, `#eef7f0`): active sidebar rows and low-intensity positive state.

### Secondary

- **Clay** (`clay-50`–`clay-950`): sparse warning/accent and notification use. `clay-600` is the shipped hex override `#8a3d16`; the remaining steps retain their canonical OKLCH values from the token source.

### Neutral

- **Sage Canvas** (`#f8faf4`): application background.
- **Paper White** (`#ffffff`): primary/elevated working surfaces.
- **Sage Soft** (`#f4f6f0`): secondary surface and table head.
- **Warm Line** (`#e2e5dc`): default borders and dividers; `#c0c9bf` is the strong control border.
- **Ink** (`#191c19`): primary copy; `#404942` secondary; `#6b756d` tertiary/placeholder.

**The Signal Rule.** Reserve forest and clay for action, selection, progress, and status. Never use color alone to communicate state; pair it with visible text, iconography, or semantics.

## Typography

**Display Font:** Domine (self-hosted variable 400–700; Georgia fallback)
**Body Font:** Hanken Grotesk (self-hosted 400–700; system sans fallback)
**Code Font:** ui-monospace, SFMono-Regular, Menlo, monospace

**Character:** Domine supplies sturdy academic authority without nostalgia. Hanken Grotesk keeps operational labels, controls, and tables compact and legible.

### Hierarchy

- **Page title:** Domine 700, `clamp(1.75rem, 2.5vw, 2.25rem)`, 1.15, `-0.025em`.
- **Section title:** Domine 600, `1.125rem`, 1.35.
- **Body:** Hanken Grotesk 400, `1rem`; long-form chapter copy is `1.02rem`/1.72 with a `68ch` measure.
- **Data:** Hanken Grotesk `0.875rem`/1.25; times and numbers stay on one line and use tabular numerals when the class is present.
- **Architectural label:** Hanken Grotesk 700, `0.6875rem`, `0.15em`, uppercase. Use only for functional categories/status, never as a decorative substitute for a heading.

## Layout

The desktop shell begins at `768px`: a sticky 64px header, a persistent 240px (`15rem`) sidebar, and a fluid content column. The default content measure is `max-w-5xl`; primary shell padding is 16/28/40px by breakpoint. Role-area tabs, search, notifications, and account remain in the header. The contextual sidebar remains independently scrollable and uses the header offset.

Below `768px`, the header becomes a 172px, three-row composition. The sidebar is a fixed off-canvas drawer, `min(17rem, 86vw)`. At the 390px review width it is 272px wide, opens over a dark forest scrim, locks body scrolling, and leaves all underlying content intact. At `480px` and below, filters stack to full width. At `640px` and below, wide tables display a sticky “Scroll to see all columns” instruction.

Opening the drawer records focus and moves it to its first focusable item. Tab and Shift+Tab are trapped within it; Escape, the scrim, or the close control dismisses it and restores focus to the menu toggle. Closed mobile navigation is `inert` and `aria-hidden`; at desktop sizes those attributes are removed and the navigation is persistently available.

## Elevation & Depth

Depth is quiet and structural. Borders and tonal changes do most of the work; ordinary table frames are flat. Cards use `0 1px 3px rgb(0 47 24 / 0.05)`. The token vocabulary also includes `sm: 0 1px 2px rgb(0 47 24 / 0.04)`, `md: 0 1px 3px rgb(0 47 24 / 0.06)`, `lg: 0 8px 20px -12px rgb(0 47 24 / 0.22)`, and `xl: 0 12px 28px -16px rgb(0 47 24 / 0.28)` for genuinely elevated menus/media.

## Shapes

Controls, tabs, nav rows, fields, and action rows use 4px corners. Cards, table frames, media, and working surfaces use 8px corners. Pills (`9999px`) are reserved for compact badges, chips, avatars, and bounded status—not buttons, fields, cards, or general containers. Structure uses 1px warm-grey borders.

## Components

### Buttons

- **Primary:** 44px minimum height, 4px radius, 8px × 16px padding, forest-700 on white; hover forest-800 on precise pointers.
- **Ghost:** white with neutral-400 border and ink; hover moves border to forest-400 and text to forest-700.
- **Pressed / disabled:** press scales to `0.98`; disabled uses `cursor-not-allowed`, 50% opacity, and no transform.
- **Focus:** 2px forest-600 outline with 3px offset. Icon-only controls remain at least 44×44px.

### Badges and Chips

Status badges are compact pills: `0.75rem`, weight 650, `0.18rem 0.6rem` padding. Use them only for short state/category text. Notification counts may use a pill/circle; do not make prose, primary actions, or arbitrary containers pill-shaped.

### Cards and Fields

Cards are white, 8px, one warm-line border, and the low card shadow. Inputs/selects/textareas are at least 44px high, white, 4px, with a 1px default border. Focus changes the border to forest-500 and adds a 3px translucent forest ring. Placeholder text is neutral-600 at full opacity.

### Navigation

The existing Dotmac Academy fiber/node SVG and name are retained. Active role tabs are forest-700/white. Active sidebar links are forest-50/forest-700 with a 3px forest-500 edge marker; `aria-current="page"` carries the semantic state. Navigation icons are authored SVGs with a consistent 1.7px rounded stroke.

### Operational Tables

Table frames are focusable scroll regions with stable scrollbar gutters, inline overscroll containment, and a subtle right-edge overflow cue. Data tables have a `42rem` minimum width, 44px headers, roughly 52px rows, 16px horizontal padding, warm-line row rules, and no zebra striping in the final world. Never hide or collapse columns on narrow screens.

Matrix tables have a `52rem` minimum width and a `min(70vh, 44rem)` viewport. Header cells stick to the top; first-column cells stick left with a restrained divider shadow; the top-left cell receives the highest stacking order. This preserves labels while both axes scroll.

### Motion

State changes use 150ms fast and 220ms standard durations with `cubic-bezier(0.22, 1, 0.36, 1)`. Press feedback is the only general transform. Public pages may use the shipped single orchestrated hero reveal and carousel fade; do not scatter entrance effects across app screens. Under `prefers-reduced-motion: reduce`, scrolling becomes immediate and transitions/animations collapse to `0.01ms` with one iteration.

## Do's and Don'ts

### Do:

- **Do** preserve every route, permission, form, link, field, table column, status, factual string, data value, and HTMX behavior. The design changes presentation, never the application contract.
- **Do** keep `hx-post="/logout"`, `hx-swap="none"`, CSRF header injection, current URLs, and role-aware Jinja conditions intact.
- **Do** preserve complete horizontal table access, sticky matrix context, visible focus, semantic landmarks, labels, `aria-current`, `aria-expanded`, `aria-controls`, `inert`, and focus restoration.
- **Do** retain the existing Dotmac Academy logo/name and self-host Domine and Hanken Grotesk.

### Don't:

- **Don't** replace dense operational data with summaries, mobile cards, hidden columns, or ellipsized evidence.
- **Don't** introduce generic floating-card dashboards, decorative academic nostalgia, gradients, glass effects, or oversized radii.
- **Don't** use pills beyond compact status, count, chip, or avatar roles.
- **Don't** communicate state through color alone or remove hover, focus, disabled, empty, error, loading, or reduced-motion behavior.
