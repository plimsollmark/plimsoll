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

1. Learn the system: concepts, architecture, providers, capabilities, operations,
   and dependencies.
2. Build with it: client integrations, MCP/agent product design, making that surface
   self-describing (schemas, annotations, typed sandbox globals, a drift test), and
   customer recipes.
3. Go deeper: compare provider-specific broker transports, run the two-sided private
   API lab against the fictional inventory API, and inspect the shipped metadata-only
   efficiency advisor plus the E2B guard-backed grant path.

Most trainers are one HTML file containing an embedded JSON lesson model. Shared
rendering and styles live in `trainer.js` and `trainer.css`. The Private API Lab
is intentionally a page-local experience: its process graph, wire inspector, and
two trace modes live in `private-api.js` and `private-api.css` because a chapter
renderer would hide the process ownership the lesson is trying to make obvious.

No page in the catalog calls a network API at runtime. Every number a lesson shows
is either part of its embedded lesson model or computed in the page, so a trainer
cannot present fixture output as if it were a live run.

## Editing a trainer

- Keep one decision or mental model per chapter, unless a process graph makes
  the boundary clearer as one continuous experience.
- Use one of the renderer kinds declared in `trainer.js`: `scenario`, `quiz`,
  `pipeline`, `matrix`, `budget`, `checklist`, or `sim`. Simulators are
  named entries in a small registry and keep their behavior in page-local assets.
- Keep learner-controlled text escaped. The embedded lesson copy is trusted and
  may use small amounts of HTML for code and links.
- Update the catalog when adding or renaming a page.
- Run `go test ./docs/trainers` and `node --check docs/trainers/trainer.js`.
  For the Flight Recorder, also run `node --check docs/trainers/private-api.js`.

The facts about providers and grants follow [`AGENTS.md`](../../AGENTS.md), not the
older archived architecture HTML. In particular, WASM is only process-tier;
Docker/runc is container-tier; Docker/runsc reaches kernel-tier only with current
Preflight evidence; E2B is VM-tier; Docker and WASM JavaScript snippets support
host-API grants through one shared broker core; and E2B supports grants only through
its configured egress guard. Project support is provider-specific: Docker projects
take grants, WASM projects reject them.


## Pages that are not in this directory

Two related pages deliberately live elsewhere, because neither is a lesson about
plimsoll:

- `../positioning/docker-agent-boundaries.html` is a competitive comparison of Docker
  Offload, Docker Sandboxes and the MCP Toolkit against plimsoll. It is commercial
  positioning, it dates fast, and it is private. It still renders with the shared
  chrome here, borrowing `trainer.css` and `trainer.js` across the directory boundary
  and setting `data-trainer-base="../trainers/"` so the reference shelf's internal
  links resolve. `TestPositioningTrainerResolvesSharedAssets` guards that wiring.
- `../dev-mode-trainer.html` documents the commercial site's dev mode.
