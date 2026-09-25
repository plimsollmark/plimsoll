# plimsoll trainers

This directory is a dependency-free interactive field guide to plimsoll. Open
[`index.html`](index.html) directly in a browser, or serve the directory with any
static file server. No build step is required.

## Serving them locally

The pages are static and make no runtime API calls, so any static file server
works:

    python3 -m http.server 48173 --bind 127.0.0.1 --directory docs/trainers
    # open http://127.0.0.1:48173/

Start with **Plain English** (`plain-english.html`) if the vocabulary is new. It is a
zero-jargon on-ramp that decodes WASM/container/gVisor/VM/RPC and teaches the one idea
behind the whole model (how many walls stand between untrusted code and the host). It
hands off to the Architecture trainer, which walks the same trip with the real gate names.

The curriculum then flows in two tracks:

1. Learn the system: concepts, architecture, providers, and dependencies.
2. Build with it: client integrations, MCP/agent product design, making that surface
   self-describing (schemas, annotations, typed sandbox globals, a drift test), and
   customer recipes.
3. Go deeper: compare provider-specific broker transports, run the two-sided private
   API lab against the fictional inventory API, and inspect the shipped metadata-only
   efficiency advisor plus the E2B guard-backed grant path.

Every trainer is one HTML file on the shared base `plain.css`, with its own markup,
its own `<style>` for whatever makes it itself, and its own script when it has an
instrument to drive (a load-line console, a route checker, a breaker strip chart, a
call ledger). The one exception is the Architecture explorer, which is an interactive
map with its own model and script. See **Page shapes** below.

No page in the catalog calls a network API at runtime. Every number a lesson shows
is either part of its embedded lesson model or computed in the page, so a trainer
cannot present fixture output as if it were a live run.

## Page shapes

Which shape a page uses is declared in `pageShape` in
[`trainer_test.go`](trainer_test.go), and the structural checks follow that
declaration, so a page that is deliberately different is a row of data rather than an
exception inside each test.

| Shape | What it is | Pages |
| --- | --- | --- |
| `plain` (default) | One scrolling document on the shared base `plain.css` (palette, type, section rhythm with the draft numerals, cards, native disclosures, segmented controls, sliders, tone chips, reading list, footer), with its own markup, its own `<style>` for whatever makes it itself, and its own script if it has an instrument to drive. Everything the page computes, it computes in the page from the daemon's published rules; nothing calls a network. | every page but one |
| `explorer` | `trainerData` in `path-explorer` mode plus a page-local interactive map (`architecture.css`, `architecture.mjs`, `architecture-model.mjs`). | `architecture.html` |

The chapter renderer (`trainer.js`, `trainer.css`) was the default until 2026-09-19.
No catalog page uses it now: eleven pages were rebuilt as plain pages with their own
instruments, because a chapter-at-a-time renderer could not draw the picture each
subject needed. `trainer.css` still styles the catalog and the quick start,
and `trainer.js` still drives the private positioning page (see **Pages that are
not in this directory**), which is why both are kept.

A `plain` page is checked for what that shape promises: it loads `plain.css` and not
the lesson stylesheet, it has one `<h1>`, it links back to the catalog, and its own
markup uses neither a fixed position nor `100vw`, the two things that make a page
awkward on a phone. `plain.css` itself is checked once for being mobile first (the
narrow layout is the base, a `min-width` media query is the enhancement, no
`prefers-color-scheme`). Adding a plain page means adding its row to `pageShape`;
nothing else.

## Editing a trainer

- Give each page one instrument that shows the subject's own mechanism (the floor
  against the evidence, the route check, the breaker, the detector), computed in the
  page from the daemon's published rules, and keep the rest short enough to read on a
  phone. Section numbers are the faint draft numerals; headings state a fact, never a
  play on words.
- Keep learner-controlled text as `textContent`. Page copy is trusted and may use
  small amounts of HTML for code and links; anything a reader types (the route
  checker's path) is never placed with `innerHTML`.
- Update the catalog when adding or renaming a page, and regenerate the social cards
  when a title or description changes (`docs/social/gen-cards.mjs`).
- Run `go test ./docs/trainers`. To see a page at phone and desktop width with a
  check for page errors and horizontal overflow, render it headless (a script for
  this lives under the gitignored `tmp/` while a session is open; the shape is six
  lines of Playwright).

The facts about providers and grants follow [`AGENTS.md`](../../AGENTS.md), not the
older archived architecture HTML. In particular, WASM is only process-tier;
Docker/runc is container-tier; Docker/runsc reaches kernel-tier only with current
Preflight evidence; E2B is VM-tier; Docker and WASM JavaScript snippets support
host-API grants through one shared broker core; and E2B supports grants only through
its configured egress guard. Project support is provider-specific: Docker projects
take grants, WASM projects reject them.


## Pages that are not in this directory

One related page deliberately lives elsewhere, because it is not a lesson about
plimsoll:

- `../positioning/docker-agent-boundaries.html` is a competitive comparison of Docker
  Offload, Docker Sandboxes and the MCP Toolkit against plimsoll. It is commercial
  positioning, it dates fast, and it is private. It still renders with the shared
  chrome here, borrowing `trainer.css` and `trainer.js` across the directory boundary
  and setting `data-trainer-base="../trainers/"` so the reference shelf's internal
  links resolve. `TestPositioningTrainerResolvesSharedAssets` guards that wiring.
