# plimsoll E2B template

A custom E2B sandbox template that **bakes the TypeScript toolchain** (tsc, tsx,
eslint) into the image, mirroring [docker/Dockerfile](../docker/Dockerfile).

## Why it exists

For the e2b provider, plimsoll disables outbound internet by default
(`network.denyOut: ["0.0.0.0/0"]`) so untrusted code has no network, matching wasm and
docker. A run with a host-API grant may reach only its configured external guard;
that guard keeps credentials and route enforcement outside the hostile VM. E2B's
default `base` template only ships `node`, so a project step that needs
`tsc`/`tsx`/`eslint` would fail with general internet access off (it can't `npm install`
at runtime). Baking the toolchain removes that need, exactly like the docker
provider's `--network none` image.

Snippet runs never need this; they work on `base` with internet off.

## Build & use

Requires the [E2B CLI](https://e2b.dev/docs/cli) and `E2B_API_KEY` set.

```sh
cd e2b
e2b template build          # builds + pushes to your E2B account; fills e2b.toml
```

Then point plimsolld at it:

```sh
export E2B_TEMPLATE=plimsoll-toolchain   # or the template ID the build prints
```

Toolchain versions are the single source of truth in
[../toolchain.versions](../toolchain.versions); both this template and
[docker/Dockerfile](../docker/Dockerfile) pin those versions, and the
`internal/toolchain` test fails if either drifts. To bump a version, edit
`toolchain.versions` and both Dockerfiles.

## Note on egress

- General internet access is off (`network.denyOut: ["0.0.0.0/0"]`) and public
  sandbox traffic is disabled. Host-API grants require `E2B_GUARD_URL`; their one
  allowed destination is the authenticated external guard, which delegates to the
  shared host-side broker. Without that setting, grants fail with `ErrUnsupported`.
