# Module identity and versions

## The module path

The module path is `github.com/plimsollmark/plimsoll`. The GitHub organization
`plimsollmark` was registered on 2026-09-09, so the name cannot be taken by someone
else and used to serve a substitute module.

That changed how the name is protected, not just what it is. The path used to be a
private module path under `.localhost`, a top-level domain reserved by an internet
standard (an RFC), which means it could never resolve publicly: no registration, no
ownership, and nothing to keep renewed. The public path swapped that built-in
guarantee for one that rests on holding an account. It is the right trade for a module people are meant to `go get`,
but it is a weaker kind of guarantee, and it is only as good as the organization
staying registered and its owning account staying secure.

## Resolution and checksums

Outside a Go workspace (`go mod tidy`, `go mod vendor`, Docker builds), Go fetches
this module's versions from `proxy.golang.org`, the public module proxy, and checks
them against `sum.golang.org`, the public checksum database, like any other public
module. There is nothing to configure.

## Why public releases start at v0.2.0

Versions v0.1.0 through v0.1.7 were tagged on this module before publication and
resolve only from a local file proxy; the code they name is not this code. A module version
is global and immutable, so those numbers are spent: reusing one publicly would mean
one version string naming two different artifacts, and any consumer holding the older
hash would hit a checksum mismatch. The first public tag is therefore numbered above
the whole retired line.

## Why there is no checksum exemption

While consumers still required a pre-publication v0.1.x, this module had to be
exempted from `sum.golang.org` (a `GONOSUMDB` entry): a checksum lookup for a version
with no public tag behind it returns `not found`, so enforcing verification would
have made every `go mod tidy` fail for no real reason. The exemption was always
temporary.

It was removed on 2026-09-10, once every consumer required v0.2.0. `sum.golang.org`
now holds v0.2.0 (entry 62818162 in its transparency log, a public record that can
only be appended to) and verifies every later fetch against the hash it recorded, which is what replaces the guarantee the `.localhost`
path gave for free. Re-adding the exemption would leave this module, whose job is
running hostile code, as the one dependency in a consumer's graph that nothing
cross-checks. If a future pre-publication tag ever needs the file proxy again, scope
the exemption to that work and remove it with the tag.

## The client packages

The TypeScript client (`@plimsollmark/client` on npm) and the Python client
(`plimsoll-client` on PyPI, first uploaded at 0.19.0 on 2026-10-05) carry the version of
the plimsoll release they ship in, without the `v`. `TestClientVersionsAgree` in
`clients/typescript` fails when `package.json`, its lockfile, `pyproject.toml` and the
Python client's `_version.py` disagree, so a release sets all four before its tag.

The npm package is published by
[publish-npm.yml](../.github/workflows/publish-npm.yml) when a GitHub release is
published, from the commit the release tag names, so the package and the tagged source
are the same code. It uses npm's trusted publishing: npm accepts the workflow's
short-lived GitHub identity token, so no npm access token exists to store or expire, and
npm attaches a <dfn>*provenance*</dfn> statement, a signed record naming the repository,
commit and workflow run that built the package. Its
checks match the Python workflow's (the release's tag is `v` plus the client's version,
and `clients/typescript` is the same as at that tag). One job runs the compiler and packs
the package; a second job, the only one holding the identity token, publishes that packed
file after checking its SHA-256.

npm's side is a trusted publisher on the package (owner `plimsollmark`, repository
`plimsoll`, workflow `publish-npm.yml`, environment `npm`). Its allowed actions must include
`npm publish`: npm always allows a trusted publisher `npm stage publish`, which waits for a
maintainer's approval, and the workflow publishes directly. npm expires a trusted
publisher whose first publish has not succeeded within 2 days, so add it shortly before
the first release that uses it. Once a publish has gone through it, npm recommends setting
the package's publishing access to "Require two-factor authentication and disallow
tokens", which leaves trusted publishing working.

The Python client is published by
[publish-python.yml](../.github/workflows/publish-python.yml) when a GitHub release is
published. It uses PyPI's trusted publishing: PyPI accepts the workflow's short-lived
GitHub identity token, so no PyPI password or API token exists to store, and PyPI records
which repository and workflow run uploaded each file. The workflow publishes only a tagged version: the
release's tag must be `v` plus the client's version, and `clients/python` must be the same
as at that tag. A release made before the workflow existed is published by running the
workflow by hand on `main`.

The CrewAI package `crewai-plimsoll` (clients/python/crewai-plimsoll, which gives a CrewAI agent a function that runs code in plimsoll) carries the same version and requires
the `plimsoll-client` of the same number. It is published by its own workflow,
[publish-crewai.yml](../.github/workflows/publish-crewai.yml), with the same checks, and its PyPI trusted publisher
names that workflow. A project's trusted-publishing token covers only the projects of the publisher its workflow
matched, so sharing `publish-python.yml` left this package's uploads refused.

The LangChain package `langchain-plimsoll` (clients/python/langchain-plimsoll, which gives a LangChain agent a function that
runs code in plimsoll, and a Deep Agents agent one sandbox kept for its whole run) works the same way: the same version, the
`plimsoll-client` of the same number, and its own workflow, [publish-langchain.yml](../.github/workflows/publish-langchain.yml),
which its PyPI trusted publisher names.

The Microsoft Agent Framework package `agent-framework-plimsoll` (clients/python/agent-framework-plimsoll, which gives an
Agent Framework agent a shell in one plimsoll sandbox kept for its conversation, and a function that runs code in
plimsoll) works the same way: the same version, the `plimsoll-client` of the same number, and its own workflow,
[publish-agent-framework.yml](../.github/workflows/publish-agent-framework.yml), which its PyPI trusted publisher names
(environment `pypi`, as the others). It also requires one exact version of `agent-framework-tools`, the Agent Framework
package that holds its shell support, which is a beta released about weekly, so each release checks the newest beta
first: its framework suite runs against that version, and a test fails when the package and the suite's lock name
different ones.

The smolagents package `smolagents-plimsoll` (clients/python/smolagents-plimsoll, which runs the Python a smolagents
`CodeAgent` writes in one plimsoll sandbox kept for the agent's run) works the same way: the same version, the
`plimsoll-client` of the same number, and its own workflow,
[publish-smolagents.yml](../.github/workflows/publish-smolagents.yml), which its PyPI trusted publisher names
(environment `pypi`, as the others). It requires exactly the smolagents its suite is locked to (`smolagents==1.26.0`),
and its framework suite holds the SHA-256 of the source of each part of smolagents the executor's final-answer protocol
is copied from, so requiring a newer smolagents starts with that suite: a smolagents that changed any of them
fails it. One test, `TestAdaptersPinTheVersionTheirLockInstalls`, fails when any framework package under
`clients/python/*-plimsoll` declares a framework version other than exactly the one its suite's lock file installs.

The PydanticAI package `pydantic-ai-plimsoll` (clients/python/pydantic-ai-plimsoll, which gives a PydanticAI agent
the files of one plimsoll sandbox kept for its conversation, a shell in that sandbox, and a function that runs code in
plimsoll) works the same way: the same version, the `plimsoll-client` of the same number, and its own workflow,
[publish-pydantic-ai.yml](../.github/workflows/publish-pydantic-ai.yml), which its PyPI trusted publisher names
(environment `pypi`, as the others). It requires one exact version of `pydantic-ai-slim`, because PydanticAI's guide
says new or stricter rules for workspace backends may come in minor releases, so each release checks the newest
PydanticAI first: PydanticAI's conformance suite runs against that version in real docker sandboxes
(`TestPydanticAIDocker`), with every rule it skips compared with the list the package does not promise, and a test
fails when the package and the suite's lock name different versions.

## Freezing the record vectors at a release

A <dfn>*run record*</dfn> (the daemon's signed statement of what it ran and where, which
comes back with every result) is worth keeping only if it can be checked later, so every
record version a release has written stays readable (AGENTS.md, the one exception to no
backward compatibility), and each is tied to what its own release produced. The first
release that writes a new record version freezes its vectors: copy that release's
`record/testdata/golden.json` to `record/testdata/published/<tag>-golden.json` and a
bundle it wrote to `attest/testdata/published/<tag>-<name>/`, with the public key that
signed it, and run
`go test ./record ./attest`: `TestPublishedVectors` requires a frozen vector for every
published version below the live one (version 1's is the v0.11.1 bundle). Until then the
live version's only vector is `golden.json`, which changes with the encoding.
