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
module. There is nothing to configure. The `make modproxy` target publishes a module
proxy made of local files, which Go can use as its `GOPROXY`; it is how a
pre-publication tag would be served, and no released version needs it.

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
