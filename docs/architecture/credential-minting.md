# Credential minting

plimsoll authenticates the caller, authorizes a server-held grant profile, and
obtains that run's downstream API credential. Guest code receives a calling
interface, not the credential. The built-in JWT mode creates a fresh token;
static mode returns the configured bearer unchanged.

![How plimsoll authorizes a grant, obtains its credential, and brokers API calls](credential-minting.svg)

[INTERNAL · full-size credential diagram →](credential-minting.svg) ·
[INTERNAL · system topology diagram →](topology.svg)

## What exists today

- **Identity and authority come from the server.** The RPC layer takes the caller
  identity from authentication and checks the profile's allowed callers. It refuses
  a subject-bound JWT grant without an authenticated identity. The caller can select
  a profile name, but cannot replace its routes, scopes, audience, or signing key.
- **Mint once, use throughout the run.** `TokenMinter.Mint` receives caller identity,
  allowed routes, declared scopes, and the run budget. JWT mode signs with HS256,
  meaning HMAC-SHA256 with a secret shared by the issuer and target API. It emits
  identity (`sub`), audience (`aud`), optional scopes, validity times, and a random
  token ID (`jti`). Issuer (`iss`) and key identifier (`kid`) are configurable.
- **The broker carries the credential.** It freezes the grant, checks the exact
  route and traffic budgets, and adds the bearer header on approved upstream calls.
  Exact routes are broker policy; the built-in JWT does not encode its `Allow` list.
  The target API remains responsible for verifying the JWT and enforcing its own
  permissions. In particular, an audience claim protects the intended recipient
  only when the recipient checks it:
  [EXTERNAL · official JWT security guidance ↗](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.9).
- **Expiry bounds validity, not run completion.** For a positive run budget, JWT
  lifetime is the smaller of the configured token lifetime and the run budget plus
  the implementation's five-second grace margin. The configured lifetime defaults
  to 60 seconds, a fallback ceiling on token validity; neither constant is a measured
  optimum for a customer's API. The broker rejects an already-expired minted token
  at setup; the API must enforce expiry on subsequent calls. Ending the run does
  not revoke a JWT. Static mode adds no expiry of its own.

A random token ID supplies an identifier for replay controls; it does not implement
those controls. A run legitimately reuses its token across multiple API calls, so
rejecting every repeated `jti` would break that flow. See
[EXTERNAL · official JWT claim definitions ↗](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.7).

## Possible enhancements, not implemented commitments

| Proposal | Benefit and cost |
|---|---|
| **First: a reusable verifier example and contract tests.** | Make the API's signature, audience, time, identity, and scope checks executable. Requires integration work for each API's permission model. |
| **Asymmetric signing when APIs should only verify.** | Give APIs public verification keys without giving them the ability to mint tokens. Requires key distribution, rotation, and a new minter implementation. |
| **Per-run revocation when expiry is too slow.** | Let the API refuse a revoked token ID while allowing repeated legitimate calls. Requires shared revocation state and a defined caching and outage policy. |

My recommendation is the verifier contract first: it targets a responsibility
already required of every JWT-consuming API. The other changes depend on deployment
needs; none is necessary just to explain the existing flow.

## Implementation evidence

- [INTERNAL · source: caller identity and grant authorization →](../../internal/rpc/sandbox_service.go)
- [INTERNAL · source: minter contract, static reuse, and setup expiry check →](../../sandbox/capability.go)
- [INTERNAL · source: JWT claims, signing, and lifetime →](../../internal/grants/jwt.go)
- [INTERNAL · source: per-run credential storage and header injection →](../../sandbox/broker.go)
- [INTERNAL · source: existing JWT tests →](../../internal/grants/jwt_test.go)
