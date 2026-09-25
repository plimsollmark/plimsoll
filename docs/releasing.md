# Module identity and versions

## The module path

The module path is `github.com/plimsollmark/plimsoll`. The GitHub organization
`plimsollmark` was registered on 2026-09-09, so the name cannot be taken by someone
else and used to serve a substitute module.

That is a change of protection model, not a restatement. The path used to be a
private module path under the RFC-reserved `.localhost` top-level domain, which could
never resolve publicly by construction: no registration, no ownership, and nothing to
keep renewed. The public path swapped that structural guarantee for one that rests on
holding an account. It is the right trade for a module people are meant to `go get`,
but it is a weaker kind of guarantee, and it is only as good as the organization
staying registered and its owning account staying secure.

## Resolution and checksums

Version resolution outside a Go workspace (`go mod tidy`, `go mod vendor`, Docker
builds) comes from `proxy.golang.org` and is checked against `sum.golang.org`, like
any other public module. There is nothing to configure. The `make modproxy` target
publishes a local file-based GOPROXY; it is how a pre-publication tag would be
served, and no released version needs it.

## Why public releases start at v0.2.0

Versions v0.1.0 through v0.1.7 were tagged on this module before publication and
resolve only from a local file proxy; their trees are not this tree. A module version
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
now holds v0.2.0 (transparency-log index 62818162) and verifies every later fetch
against the hash it recorded, which is what replaces the guarantee the `.localhost`
path gave for free. Re-adding the exemption would leave this module, whose job is
running hostile code, as the one dependency in a consumer's graph that nothing
cross-checks. If a future pre-publication tag ever needs the file proxy again, scope
the exemption to that work and remove it with the tag.
