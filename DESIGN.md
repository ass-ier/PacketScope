---
name: PacketScope
description: A cool white investigation ledger with ink navigation and restrained teal actions.
colors:
  action: "#08766d"
  action-hover: "#065c56"
  surface: "#ffffff"
  canvas: "#f4f6f8"
  ink: "#20303d"
  muted: "#536773"
  caption: "#627480"
  border: "#dce2e7"
  divider: "#e3e8ec"
  row-divider: "#e9edf0"
  field-border: "#b6c2cb"
  placeholder: "#66747e"
  control-ink: "#263846"
  control-border: "#cbd3da"
  control-hover: "#edf3f3"
  table-heading: "#f8fafb"
  table-ink: "#5c6b76"
  row-hover: "#f7fafb"
  nav-bg: "#192c39"
  nav-text: "#d1dce3"
  nav-hover: "#294453"
  nav-current: "#30535b"
  nav-signal: "#70d9c7"
  tab-current: "#e2efeb"
  tab-ink: "#08695f"
  focus: "#168cbd"
  badge-bg: "#e9eef2"
  badge-ink: "#4b5c69"
  observed-bg: "#dff3eb"
  observed-ink: "#176445"
  caution-bg: "#fff0cf"
  caution-ink: "#79530d"
  alert-bg: "#fce9e7"
  alert-ink: "#9f3027"
  error-bg: "#fff0ee"
  error-border: "#f1c4bd"
  error-ink: "#902b21"
  warning-bg: "#fff5dd"
  warning-border: "#e7d6ac"
  warning-ink: "#695019"
  loading-bg: "#e8eef2"
  loading-ink: "#475d6b"
typography:
  headline:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif"
    fontSize: "26px"
    fontWeight: 650
    lineHeight: 1.25
    letterSpacing: "-.025em"
  headline-mobile:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif"
    fontSize: "23px"
    fontWeight: 650
    lineHeight: 1.25
    letterSpacing: "-.025em"
  title:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif"
    fontSize: "16px"
    fontWeight: 650
  subheading:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif"
    fontSize: "15px"
    fontWeight: 650
  body:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif"
    fontSize: "14px"
  label:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif"
    fontSize: "12px"
    fontWeight: 600
  data:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif"
    fontSize: "12px"
  navigation:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif"
    fontSize: "13px"
  badge:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif"
    fontSize: "11px"
  metric:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif"
    fontSize: "29px"
    fontWeight: 600
  control:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif"
    fontSize: "14px"
    fontWeight: 600
  mono:
    fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace"
rounded:
  badge: "3px"
  field: "4px"
  panel: "5px"
spacing:
  label-gap: "6px"
  tight: "8px"
  small: "10px"
  compact: "12px"
  inset: "14px"
  control-group: "16px"
  row: "18px"
  panel: "20px"
  section: "24px"
  heading: "28px"
  page: "32px"
components:
  button-primary:
    backgroundColor: "{colors.action}"
    textColor: "{colors.surface}"
    typography: "{typography.control}"
    rounded: "{rounded.panel}"
    padding: "8px 14px"
  button-primary-hover:
    backgroundColor: "{colors.action-hover}"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.control-ink}"
    typography: "{typography.control}"
    rounded: "{rounded.panel}"
    padding: "8px 14px"
  button-secondary-hover:
    backgroundColor: "{colors.control-hover}"
  button-text:
    textColor: "{colors.action}"
    typography: "{typography.label}"
    padding: "2px 0"
  input:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.label}"
    rounded: "{rounded.field}"
    padding: "9px 11px"
  navigation-link:
    textColor: "{colors.nav-text}"
    typography: "{typography.navigation}"
    rounded: "{rounded.field}"
    padding: "9px 12px"
  navigation-current:
    backgroundColor: "{colors.nav-current}"
    textColor: "{colors.surface}"
  badge:
    backgroundColor: "{colors.badge-bg}"
    textColor: "{colors.badge-ink}"
    typography: "{typography.badge}"
    rounded: "{rounded.badge}"
    padding: "3px 7px"
  badge-observed:
    backgroundColor: "{colors.observed-bg}"
    textColor: "{colors.observed-ink}"
  badge-caution:
    backgroundColor: "{colors.caution-bg}"
    textColor: "{colors.caution-ink}"
  badge-alert:
    backgroundColor: "{colors.alert-bg}"
    textColor: "{colors.alert-ink}"
  panel:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.panel}"
  evidence-table:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.data}"
  metrics:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
  capture-tab:
    textColor: "#5c6f7b"
    typography: "{typography.navigation}"
    padding: "12px 14px"
  capture-tab-current:
    backgroundColor: "{colors.tab-current}"
    textColor: "{colors.tab-ink}"
---

# Design System: PacketScope

## Overview

**Creative North Star: "The Cool White Investigation Ledger"**

PacketScope's built interface is a quiet, dense evidence workspace: cool white
working surfaces, ink navigation, restrained teal actions, and tabular
measurements. Its visual hierarchy comes from headings, divided registers, and
explicit labels rather than decorative dashboard imagery. The direction recorded
in `frontend/index.html` is realized by the shipped frontend, not a new design
proposal.

Evidence and analyst judgment occupy distinct, clearly titled sections. An
observation, a visibility limit, and an assessment remain distinguishable through
copy, structure, and controls; color supports those distinctions but cannot make
a verdict. This preserves the binding evidence-before-claims principle in
`PRODUCT.md` without turning it into a new visual theme.

**Key Characteristics:**
- Cool canvas and white, lightly bordered working surfaces.
- Ink navigation with restrained teal action and selection states.
- Compact tables, tabular measurements, and inspectable evidence.
- Explicit separation of analyst assessment, linked evidence, and notes.
- Horizontal mobile navigation and locally scrollable dense content.

**Recorded boundary.** This is the built system, extracted from
`frontend/src/style.css`, `App.tsx`, `components/Common.tsx`, and representative
Explore, Cases, and Graph pages. Frontmatter names are documentation aliases for
existing CSS literals, not newly implemented CSS custom properties. Only recurring
roles are promoted; this is not an inventory of every declaration or a redesign.
The current visual record is `docs/screenshots/dashboard.png`,
`mobile-workspace.png`, `findings.png`, `investigation-graph.png`, and
`analyst-case.png` in the same directory. This recording did not rerun browser or
accessibility validation.

The `.impeccable/design.json` sidecar adds self-contained component previews,
breakpoints, focus/state details, and the same narrative. Its derived tonal ramps
are preview swatches required by the documenter format, **not additional shipped
palette tokens or a license to recolor the UI**.

## Colors

The palette is cool, low-chroma, and light-first; the dark navigation anchors the
workspace without turning evidence surfaces into a dark theme.

### Primary

- **Action teal** (`action`, `action-hover`) is the shared link, primary-button,
  progress-accent, and active-tab underline family. Primary buttons darken on
  hover; ordinary links underline on hover.
- **Selection wash** (`tab-current`, `tab-ink`) marks the active capture tab.
  Main navigation uses the darker `nav-current` selection surface.
- **Navigation signal** (`nav-signal`) is the small brand stroke and local-storage
  dot on the ink rail, not a general page accent.

### Neutral

- **Cool canvas / white surface** (`canvas`, `surface`) separate the application
  background from the top bar, panels, fields, and totals strip.
- **Reading ink** (`ink`), **supporting text** (`muted`), and **caption gray**
  (`caption`) distinguish evidence, explanatory prose, and compact metadata.
- **Structural strokes** (`border`, `divider`, `row-divider`) articulate panel
  boundaries, internal sections, and table/detail rows.
- **Control neutrals** (`control-ink`, `control-border`, `control-hover`,
  `field-border`, `placeholder`) give white controls visible boundaries and a
  quiet hover response.
- **Register neutrals** (`table-heading`, `table-ink`, `row-hover`) separate table
  headings and hovered records without striping or lifting every row.
- **Ink navigation** (`nav-bg`, `nav-text`, `nav-hover`, `nav-current`) establishes
  the persistent application rail and its current location.

### Functional states

- **Focus blue** (`focus`) is reserved for the visible keyboard outline, not a
  second action color.
- **Neutral badges** use `badge-bg` / `badge-ink`.
- **Observed/completed badges** use `observed-bg` / `observed-ink`.
- **Caution badges** use `caution-bg` / `caution-ink`.
- **Alert badges** use `alert-bg` / `alert-ink`.
- **Failure, visibility, and loading surfaces** respectively use the `error-*`,
  `warning-*`, and `loading-*` families. Their text names the actual condition.

These are state roles, not secondary or tertiary brand palettes. Graph node-type
tints and chart fills stay local to their evidence visualization; their exact
source styles do not establish a new system-wide accent scale.

**The Restrained Action Rule.** Use teal for actions and current context; keep
registers and reading surfaces neutral.

**The Labels Before Color Rule.** Keep status, severity, confidence, and evidence
type readable as text; no fill alone expresses an analyst verdict.

## Typography

**Interface font:** the platform system sans stack in the frontmatter. There are
no downloaded font files or separate display face. The exact rendered face
depends on the operating system.

**Evidence mono:** the `mono` stack for capture hashes and raw hexadecimal
evidence. Monospace is targeted, not the default for every record.

The type ramp is compact and role-based, not a prescribed mathematical scale.
Weight and placement do most of the work; it does not use oversized marketing
headlines. Font synthesis is disabled at the root.

### Hierarchy

| Role | Use |
| --- | --- |
| `headline` / `headline-mobile` | Page and capture titles; only this heading role changes size at the small breakpoint. |
| `title` | Panel and major section headings. |
| `subheading` | Empty-state titles and subordinate sections. |
| `body` | General reading and field text. Paragraphs use line-height 1.6; this is not a blanket control line-height. |
| `label` | Form labels and other semibold compact labels. |
| `data` | Tables, metadata, footnotes, detail labels, and raw-text blocks. |
| `navigation` | Main links and capture tabs; current links add weight 600. |
| `badge` | Short, nonwrapping state labels. |
| `metric` | Real totals in the shared metrics strip. |
| `control` | Standard action labels. |
| `mono` | Hashes and raw bytes, inheriting the surrounding size. |

The brand and case title have a local intermediate heading size (20px). They are
not a new display hierarchy. Table and detail labels capitalize humanized field
names; technical acronyms retain their supplied text.

Native buttons and fields inherit their surrounding font. Labeled fields inherit
the compact label size and weight; global-search fields inherit the top bar's
compact text. The control token describes the standard body-context button, not
an override of smaller toolbar, pagination, or form-action contexts.

**The Measured Evidence Rule.** Use tabular numerals for table cells, totals,
capture measurements, detail values, and quantitative bar labels; reserve
monospace for identifiers or raw evidence where the source uses it.

Readable prose is bounded by context rather than one universal measure:
empty-state explanations (64ch), analyst notes (75ch), and footnotes (90ch).
Detail values wrap long content; preformatted evidence wraps and scrolls within a
bounded block rather than enlarging the entire page.

## Layout

### Workspace frame

The desktop shell is a flex row with a sticky, viewport-height navigation rail
(218px wide) and a flexible main area with `min-width: 0`. The rail can scroll
vertically. A white top bar has a bottom rule, minimum height (64px), and padding
(16px 32px). The page is bounded at (1800px) and padded (30px 32px 60px); it is not
a centered marketing column.

Page headings pair title/context with the capture-import action. Their gap
(20px) and lower separation (`spacing.heading`) give orientation without a large
hero. Panels separate sections at `spacing.section`. A shared section heading
uses padding (18px 20px); form and table toolbars use (16px 20px) with wrapping
controls and a (12px) gap.

The spacing aliases describe a practical compact rhythm, not a strict
single-base spacing scale. Existing compound insets and specialized dimensions
remain in component CSS.

### Registers and evidence inspection

- Totals form one divided white strip, not individually elevated cards. The
  default grid auto-fits columns with a minimum (120px); each total has (20px)
  padding.
- Overview panels form two equal columns with a (24px) gap. Detail definitions
  use two equal columns inside one panel. Comparison content uses three columns.
- Evidence tables retain their column structure inside a horizontal scroll
  container. Cell padding is (13px 18px); long values can wrap, and cells have a
  declared maximum width (360px). Title/summary columns have a minimum (220px);
  IP and capture-name columns have a minimum (125px).
- Filters wrap instead of forcing a fixed toolbar width. Growing filter fields
  start at a minimum (160px); form-row labels at (140px).
- Relationship inspection pairs a flexible canvas with a (250px) detail rail.
  The canvas and detail maximum height are (550px).

### Responsive rules

All breakpoints below are inclusive `max-width` rules, not mobile-first
`min-width` tokens.

| At or below | Actual changes |
| --- | --- |
| 1000px | Navigation rail narrows to 175px; page padding becomes 24px 20px; overview panels stack with no grid gap; totals use three columns and gain row dividers. |
| 900px | Graph detail moves below the canvas with a top border; canvas height becomes 400px and detail maximum height becomes 240px. |
| 680px | Shell becomes a block layout. Navigation is a static full-width top band with 14px padding and horizontally scrollable links; the workspace label and local-storage footer are hidden. Page padding becomes 22px 14px; top bar padding becomes 14px and its content stacks. Search input fills its available width. |
| 680px, content | Detail and comparison grids become one column; search results become a single column; pagination wraps; job status and time-range controls stack; page headings top-align; headline uses `headline-mobile`; total-cell padding becomes 14px and table-cell padding becomes 12px. |

Capture tabs stay a horizontal scrolling strip. Dense tables scroll within their
own wrapper. Mobile does not replace the main navigation with a hamburger menu
or collapse the totals to a one-column stack.

**The Local Overflow Rule.** Keep the page frame flexible and scroll dense
navigation, tabs, tables, and bounded evidence locally rather than widening the
workspace.

## Elevation & Depth

Application-owned panels and controls are flat. White-on-cool tonal layering,
thin borders, and divided sections establish depth; the application stylesheet
defines no box-shadow vocabulary. Focus is an outline, not a glow. The graph
imports React Flow's stylesheet and controls; package-provided shadows or
interaction affordances are not evidence for a general card-elevation scale.

**The Flat Ledger Rule.** Separate application surfaces with tone and a single
thin boundary instead of introducing floating, shadowed cards.

There are no application-authored transition durations or keyframe animations
to standardize. Hover and selection changes are direct; graph manipulation is
an interaction, not decorative motion. The reduced-motion media rule disables
animations and transitions on all elements and their pseudo-elements.

## Shapes

Small, utilitarian corners carry the form language: `rounded.panel` for buttons,
panels, and the case-attachment band; `rounded.field` for fields, main navigation
links, and graph nodes; `rounded.badge` for state tags. These are rectangles with
small corner softening, not pill controls.

Most structural and control boundaries are solid (1px). Panels clip their
contents at the rounded boundary. Metrics and table geometry remain square;
capture tabs are square with an active bottom rule (2px). The small local-state
dot is circular; its shape is a status marker, not a prohibition on all circles.

## Components

### Buttons

Compact, labeled controls; the text explains the operation.

- **Primary:** white text on action teal, shared panel radius, padding
  (8px 14px), and a matching (1px) border. Hover uses `action-hover`.
- **Secondary:** white with a control-neutral border and text; hover uses
  `control-hover`. The same treatment is used for button-shaped download links.
- **Text action:** teal, no border or resting fill, padding (2px 0), compact label
  type, and minimum height (30px); it retains the global button hover wash.
- **Sizing:** standard controls have minimum height (36px), not a fixed height.
  Icon/text gaps are (8px) when content requires them.
- **Disabled/busy:** opacity (.55) and a not-allowed cursor accompany actual
  disabled controls. Import additionally changes its label to “Importing…”.
  The hidden native file input remains inside the visible button-shaped label.
- **Keyboard focus:** an external solid focus outline (3px) with offset (3px);
  the upload label receives the same outline through `focus-within`.

### Inputs / Fields

White, visibly bordered native controls rather than floating placeholders.

Fields use the field radius, padding (9px 11px), minimum height (38px), and a
maximum width of their container. Labels are above their controls with
`spacing.label-gap`; checkbox labels run alongside the checkbox. Textareas begin
at (100px) minimum height and resize vertically. Placeholders supplement labels,
not replace them; global search has an accessible label.

Fields retain native selection and validation behavior plus the shared focus
outline. The implementation does not define a custom per-field invalid border
or a separate disabled-input skin; do not infer one from the error banner.

### Navigation

A stable ink rail anchors the investigation. Links use compact navigation type,
field-radius corners, and padding (9px 12px), separated by a (3px) gap. Hover has
a lighter ink fill without an underline. The current route uses
`aria-current="page"`, a selection fill, white text, and weight (600).

The capture navigation is a separate square-edged tab strip with padding
(12px 14px). Its current tab combines a soft teal fill, dark teal text, and an
action-teal underline. Both navigation contexts keep their labels visible and
scroll horizontally where needed. The skip link appears on focus and moves
focus to the main investigation area.

### Badges

Small, noninteractive, nonwrapping rectangular labels. Padding is (3px 7px);
type and radius use the badge tokens. These are not selectable filter chips.

The shared badge maps the supplied text to a lowercase, hyphenated class:

| Supplied value | Actual visual family |
| --- | --- |
| completed; observed behavior | observed |
| medium; possible; processing; parsing | caution |
| high; failed; critical | alert |
| Other values, including low, queued, stored, or unknown | neutral fallback |

This mapping is presentation, not domain logic. In particular, “High” confidence
and “High” severity share the same badge treatment; the surrounding column label
must disambiguate them. Do not turn the red fill into a universal “malicious”
verdict or the green fill into a “safe capture” claim.

### Panels / Containers

Quiet white sections, each with a clear heading or purpose. The shared panel has
a light boundary, panel-radius corners, bottom separation (24px), and clipped
contents. Divided section headings, toolbars, and table rows provide structure
inside the container rather than nesting additional cards.

Padded reading/forms use (20px) insets. The totals strip is the square, divided
variant, with compact caption labels and tabular metric values. Observed
protocol bars pair labels and counts with a thin track (8px); they supplement
actual totals rather than stand in for a risk score.

### Evidence tables and inspectors

Tables use semantic headers, a pale heading row, thin row dividers, tabular
values, and a quiet row-hover wash. The action column exposes an explicit
“Inspect” button with a screen-reader row label; the entire row is not treated
as the only click target. Pagination shows totals and the displayed range,
disabling Previous or Next at the bounds.

Null and empty values display “Not observed”. Protocol identification can carry
a visible “port hint” qualifier. A detail inspector uses labeled values,
expandable nested field trees, and explicit links to captures, flows, or frames.
The raw-byte view is opt-in, monospace, and bounded; nested fields and long
identifiers remain readable without silently hiding their content.

### Analyst assessment and linked evidence

The case view deliberately separates three white sections: **Analyst
assessment**, **Linked evidence**, and **Analyst notes**. Assessment uses labeled
status/verdict/confidence selects, a full reasoning textarea, a primary save
action, and a status message. Linked evidence stays in the same register/table
language as the rest of the workspace. Notes preserve line breaks and have a
bounded reading measure.

The attachment control is a lightly tinted bordered band with a case selector
and an explicit attach action. It does not visually merge observations with the
editable assessment.

**The Separate Judgment Rule.** Keep analyst assessment controls and reasoning
in their own titled section, distinct from observed records and linked evidence.

### Relationship graph

The graph is an evidence canvas with a neighboring inspector, not decorative
network imagery. It retains React Flow pan/zoom controls, a light dotted
background, directional connections, and labels. Node types have restrained
local tints: green-teal internal hosts, blue external hosts, lavender domains and
ATT&CK nodes, amber findings, and pale blue-teal IOCs. Type labels and inspect
links accompany those distinctions.

Nodes use compact type (12px), field-radius corners, padding (13px), and width
(210px). Selecting a node or edge populates “Selected evidence”; unselected
state tells the analyst what to choose. Counts and visibility limits remain
captioned outside the canvas. See Layout for the narrower-screen inspector
stacking behavior.

### Loading, empty, error, and visibility states

- **Loading:** a blue-gray block with (25px) padding and `role="status"` announces
  “Loading evidence…”. It is not a skeleton animation.
- **Empty:** centered explanatory text with padding (50px 28px), a subordinate
  heading, and a bounded paragraph. Guidance names a next action and avoids
  equating no matches with benign traffic.
- **Error:** a light red, thin-bordered message with (14px) padding, field-radius
  corners, wrapping text, and `role="alert"` where the shared state is used.
- **Visibility warning:** an amber bordered block with padding (12px 16px);
  capture notices expand through native details/summary.
- **Analysis progress:** a native labeled progress element alongside stage and
  percentage in a tinted status band. A failed analysis exposes “Retry analysis”.
- **Completion feedback:** save and attachment messages use status regions;
  retain explicit success/failure text rather than relying on a color change.

## Do's and Don'ts

### Do:
- **Do** reuse the cool canvas, white sections, ink navigation, and restrained teal actions.
- **Do** keep compact tabular registers and explicit Inspect actions as the evidence-reading pattern.
- **Do** preserve labeled status, confidence, visibility, and empty-state explanations.
- **Do** keep analyst assessment, linked evidence, and notes in separately titled sections.
- **Do** preserve keyboard outlines, native controls, and the focused skip link.
- **Do** keep mobile navigation and dense content locally scrollable, with the documented grid stacking.

### Don't:
- **Don't** replace the built light evidence workspace with a decorative dark security dashboard.
- **Don't** introduce pill cards, oversized display typography, or a new shadow scale into the flat ledger.
- **Don't** use badge or graph colors alone to imply maliciousness, safety, or an analyst verdict.
- **Don't** turn derived sidecar ramps or local graph tints into new global palette commitments.
- **Don't** hide long evidence identifiers through visual truncation where the current system wraps or scrolls.
- **Don't** invent font assets, animation timings, dark-mode variants, or custom field states absent from the build.
