# plimsoll trainers

This directory is a set of interactive lessons about plimsoll that needs no dependencies
and no build step. Serve it with any static file server, as below. Opened straight from
disk, most pages work, but the architecture explorer stays blank: browsers refuse to load
its module script from a `file://` address.

## Serving them locally

The pages are static and make no API calls while you read them, so any static file server
works:

    python3 -m http.server 48173 --bind 127.0.0.1 --directory docs
    # open http://127.0.0.1:48173/trainers/

Serve `docs`, not `docs/trainers`: some pages link up a level, to the architecture
drawings and the examples, and those links break when the server's root is this
directory.

Start with **Plain English** (`plain-english.html`) if the vocabulary is new. It explains,
without jargon, the words the other lessons lean on: <dfn>*WebAssembly*</dfn> (a portable
bytecode that runs inside a host program), container, <dfn>*gVisor*</dfn> (a stand-in
kernel that runs as an ordinary program), virtual machine and RPC. It also teaches the one
idea behind the whole model: how many walls stand between untrusted code and the host. It
hands off to the Architecture trainer, which walks the same trip with the real names of
the checks.

The lessons then run in this order:

1. Learn the system: concepts, architecture, <dfn>*providers*</dfn> (the backends that
   run the code), and dependencies.
2. Build with it: client integrations; designing a product in which an AI agent reaches
   plimsoll through <dfn>*MCP*</dfn> (Model Context Protocol, the standard an AI
   application uses to offer tools to a model); making that tool describe itself (schemas,
   annotations, typed sandbox globals, a test that catches drift); and customer recipes.
3. Go deeper: compare how each provider carries a sandboxed program's API calls to the
   <dfn>*broker*</dfn>, the part of plimsoll that makes those calls and holds the
   credential; run the two-sided private API lab against the fictional inventory API; and
   inspect the shipped efficiency advisor, which sees only metadata. This track also
   covers <dfn>*E2B*</dfn>, a hosted service that runs code in small virtual machines:
   there a run's <dfn>*grant*</dfn> (its permission to call listed routes of one API)
   works only through the <dfn>*guard*</dfn>, the one address on the plimsoll daemon that
   such a virtual machine may reach.

Every trainer is one HTML file on the shared base `plain.css`, with its own markup, its own
`<style>` for whatever makes it itself, and its own script when it has an interactive
instrument to drive (a ship's-hull console, a route checker, a live chart of the breaker
that pauses calls to a struggling API, a call ledger). The one exception is the
Architecture explorer, an interactive map with its own data model and script. See **Page
shapes** below.

No page in the catalog calls a network API while it runs. Every number a lesson shows is
either part of the lesson's own embedded data or computed in the page, so a trainer cannot
present canned example output as if it were a live run.

## Page shapes

Which shape a page uses is declared in `pageShape` in
[`trainer_test.go`](trainer_test.go), and the structural checks follow that declaration,
so a page that is deliberately different is a row of data rather than an exception inside
each test.

| Shape | What it is | Pages |
| --- | --- | --- |
| `plain` (default) | One scrolling document on the shared base `plain.css` (colours, type, section spacing with the faint large section numbers, cards, `<details>` disclosures, segmented controls, sliders, coloured tone labels, reading list, footer), with its own markup, its own `<style>` for whatever makes it itself, and its own script if it has an instrument to drive. Everything the page computes, it computes in the page from the daemon's published rules; nothing calls a network. | every page but one |
| `explorer` | `trainerData` in `path-explorer` mode plus an interactive map of its own (`architecture.css`, `architecture.mjs`, `architecture-model.mjs`). | `architecture.html` |

The architecture explorer builds its component cards, its arrows between components, its
provider descriptions and its worked request paths from one data model in
`architecture-model.mjs`. Change a path there: a separate hand-written arrow or
explanation can disagree with the step-by-step navigator. One of its paths shows how a
caller's token identifies the caller: the operator gives the caller a token, plimsolld
hashes whatever token a request presents and looks the hash up among the configured
callers (so whoever holds the token is that caller), and the credential for the
downstream API stays a separate thing. The page illustrates this flow; it does not issue
tokens. When you change the map or its navigation, run both of its checks from the
repository root.

The data model's own test needs only Node:

```sh
node docs/trainers/architecture-model.test.mjs
```

The browser check, [`check-architecture.mjs`](check-architecture.mjs), drives the page in
a headless Chromium through Playwright. It steps through every worked path for each
provider, follows every connection between components, checks every link on the page,
and checks the map at four widths from 390 to 1512 pixels. It fails on a page error, a
failed request, a request that leaves the local server, or an arrow whose endpoints are
cut off, and writes screenshots and a JSON summary to `tmp/`. Playwright is not a dependency of this repository, so install it
once under `tmp/` (ignored by git). The version below is the one the check was last run
with:

```sh
npm install --prefix tmp/playwright playwright@1.60.0
tmp/playwright/node_modules/.bin/playwright install chromium   # downloads the browser once
```

On Linux, Chromium also needs some system libraries; `playwright install-deps chromium`
installs them and needs root. Then serve `docs/` on the port the check expects, and run
it:

```sh
python3 -m http.server 8766 --bind 127.0.0.1 --directory docs &
PLAYWRIGHT_MODULE=$PWD/tmp/playwright/node_modules/playwright node docs/trainers/check-architecture.mjs
```

It prints each worked path it verified, then the summary, and exits 0 when every check
passes; the first failed check stops it with a non-zero exit and the reason. Pass another
local URL as its argument to check a server on a different port.

The chapter renderer (`trainer.js`, `trainer.css`) was the default until 2026-09-19. No
catalog page uses it now: eleven pages were rebuilt as plain pages with their own
instruments, because a renderer that shows one chapter at a time could not draw the
picture each subject needed. `trainer.css` still styles the catalog and the quick start,
and `trainer.js` still drives one page that lives outside this directory, which is why
both are kept.

A `plain` page is checked for what that shape promises: it loads `plain.css` and not the
lesson stylesheet, it has one `<h1>`, it links back to the catalog, and its own markup
uses neither a fixed position nor `100vw`, the two things that make a page awkward on a
phone. `plain.css` itself is checked once for being mobile first (the narrow layout is
the base, a `min-width` media query adds the wider one, no `prefers-color-scheme`).
Adding a plain page means adding its row to `pageShape`; nothing else.

## Editing a trainer

- Give each page one instrument that shows the subject's own mechanism (the minimum wall
  strength a request demands against what the provider proved, the route check, the
  breaker, the advisor's pattern detector), computed in the page from the daemon's
  published rules, and keep the rest short enough to read on a phone. Section numbers are
  the faint large numerals; headings state a fact, never a play on words.
- Keep learner-controlled text as `textContent`. Page copy is trusted and may use small
  amounts of HTML for code and links; anything a reader types (the route checker's path)
  is never placed with `innerHTML`.
- Label invented values as examples. A simulated call log or latency must not be
  presented as a recording of an actual run.
- Update the catalog when adding or renaming a page. A page's social card (its Open
  Graph tags and picture) is generated from its title and description by a tool the
  maintainers keep outside this repository, so if you change either, say so in the
  pull request and a maintainer regenerates the card.
- Define every registered term where the page first uses it (see **Terms and the
  glossary** below).
- Run `go test ./docs/trainers`. To see a page at phone and desktop width, with a check
  for page errors and for content wider than the screen, render it in a headless browser
  (such a script is kept in the gitignored `tmp/`, never committed; it takes about six
  lines of Playwright).

The facts about providers and grants follow [`AGENTS.md`](../../AGENTS.md), not the older
archived architecture HTML. Each provider reports an <dfn>*isolation tier*</dfn>, how
strong the wall around a run is, and the pages state them this way:

- `wasm` is only `process` tier.
- `docker` with <dfn>*runc*</dfn>, docker's default runtime, is `container`
  tier.
- `docker` with <dfn>*runsc*</dfn>, gVisor's runtime, reaches `kernel` tier only with
  current <dfn>*preflight*</dfn> evidence (preflight is the check a provider runs at
  startup and on every readiness poll).
- `e2b` and `dockercloud` are `vm` tier.
- `openshell` is `container` tier: the gateway of <dfn>*OpenShell*</dfn>, NVIDIA's agent
  sandbox runtime, runs each sandbox through docker, and no OpenShell API reports which
  runtime that docker uses.
- Grants to a host API all go through one shared broker core. `docker` and `openshell`
  take them on snippets and projects; `wasm` on snippets only, since it runs no projects;
  `e2b` and `dockercloud` only through their configured guard, and on `dockercloud` the
  <dfn>*guest*</dfn>, the code in the sandbox, holds its own run's short-lived guard
  credential. `openshell` reaches the broker
  through a relay inside the sandbox that plimsoll connects to from outside, so the
  sandbox keeps no network rules.
- <dfn>*Sessions*</dfn>, one sandbox kept for many calls, exist on `docker` with a project
  image, on `openshell` and on `e2b`, nowhere else. A <dfn>*cell*</dfn>, code run in the interpreter a
  session keeps alive, carries no grant, and in a docker session the broker serves the grant of the call in
  progress to anything in the container.

## Terms and the glossary

The public pages share one list of terms, and a test holds pages to it. The facts below
come from the header of [`terms_test.go`](terms_test.go), which is the reference.

- **[`terms.json`](terms.json) is the registry.** Each entry is a term, the other forms
  it takes, one plain sentence defining it, and its anchor in the glossary. A term marked
  `assumed` (container, process, RPC, sandbox, kernel, virtual machine) is one the reader
  is expected to know: it is listed in the glossary, but its first use is not enforced.
  The file also holds `enforced_pages`, the pages the first-use rule applies to.
- **[`glossary.html`](glossary.html) is generated from it**, and so are the definitions
  the Plain English decoder shows. After editing `terms.json`, run
  `go test ./docs/trainers -run TestGeneratedBlocks -update` to rewrite those blocks, and
  commit them with it; without `-update`, `TestGeneratedBlocks` fails whenever a
  generated block and the registry disagree.
- **`TestRegisteredTermsAreDefinedAtFirstUse` holds every page in `enforced_pages` to one
  rule:** the first time a registered term appears in the page's prose, it is a marked
  definition or a link to its glossary entry. Replacing the word with plain words is the
  third way to pass, and often the best one.
- **How to mark a definition.** In HTML, `<dfn>broker</dfn>`, followed in the same
  sentence by a plain definition. In markdown, `<dfn>*broker*</dfn>`: GitHub strips the
  `<dfn>` tag and keeps the italics inside it (checked against GitHub's renderer on
  2026-09-29), so a GitHub reader sees the term in italics and the tag stays in the
  source for the test. A link counts when its href ends in `glossary.html#<anchor>` for
  that term; a markdown page that links a term uses the published copy,
  `https://plimsollmark.github.io/plimsoll/trainers/glossary.html#<anchor>`, because
  GitHub shows an `.html` file in the repository as source.
- **What the test reads as prose:** the page body without code (`<code>`, `<pre>`,
  backticks, fenced blocks), headings, SVG drawings, scripts, styles, image alt text,
  HTML comments, link text that is a bare file path, and the generated glossary list.
  Headings are skipped because a definition cannot sit inside one; the first sentence
  under the heading defines the term instead. Text a page builds in its own script is
  not checked, a known gap, so read it by hand.
- **The `data-terms="off"` opt-out.** An HTML element marked `data-terms="off"` is
  skipped. Use it only where a registered word appears in its everyday sense, such as
  the security guard in the glossary's housing analogy, and say why in a comment beside
  it.
- **Adding a term.** Keep the list in alphabetical order, one entry per anchor, no form
  claimed by two terms, and each definition one plain sentence ending in a full stop,
  with no dash punctuation; `TestTermRegistryIsWellFormed` checks all of it.
