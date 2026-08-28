# ibm-verify-lab

An OpenID Connect **relying party** built against an **IBM Verify (SaaS)** tenant.

The application is deliberately small. Its purpose is to make the identity
provider's behaviour *observable*: change a setting in the IBM Verify console,
sign in again, and see exactly what changed in the issued token.

## What this demonstrates

**IBM Verify tenant configuration**

- Custom OIDC application onboarding — grant types, redirect URIs, client
  authentication method, PKCE enforcement
- Entitlements (coarse application access) as a gate distinct from
  authentication and from access policy
- Cloud Directory users, groups, and a custom attribute schema
- Outbound attribute mapping: releasing selected directory attributes as
  token claims, per application

**OIDC relying-party implementation**

- Authorization Code flow with PKCE (S256)
- `state` — login-CSRF defence, single-use by construction
- `nonce` — token replay defence
- ID token validation against the tenant JWKS, resolving the signing key by `kid`
- Pinned signing algorithm (see Security notes)
- Back-channel token exchange using `client_secret_basic`
- RP-initiated logout via `end_session_endpoint` with `id_token_hint`

## Security notes

**The signing algorithm is pinned, not negotiated.**

This tenant's discovery document advertises RS256 through RS512, the PS and ES
families, HS256 through HS512, and `none` in
`id_token_signing_alg_values_supported`.

That list is a *capability* statement, not a policy. Passing it to a JWT
validator would accept unsigned tokens (`alg: none`) and enable RS256 to
HS256 algorithm-confusion attacks, where a forged token is signed with the
provider's own public key used as an HMAC secret.

The relying party therefore pins `algorithms=["RS256"]`.

**Endpoints are read from discovery, never constructed.**

On this tenant the issuer path and the endpoint path differ — the issuer sits
under `/oidc/endpoint/default` while the authorization and token endpoints sit
under `/v1.0/endpoint/default`. Building the issuer by hand would fail every
token validation.

**Secrets never enter source control.** `.env` is git-ignored from the first
commit; `.env.example` documents the required configuration.

## Routes

| Route            | Purpose                                                 |
|------------------|---------------------------------------------------------|
| `/`              | Sign-in prompt, or the signed-in user's claims           |
| `/config`        | Live view of the tenant's OIDC capabilities and JWKS     |
| `/pkce-demo`     | Generates a PKCE pair and verifies the hash relationship |
| `/login-preview` | Shows the authorization request before it is sent        |
| `/login`         | Redirects to IBM Verify                                  |
| `/callback`      | Code exchange and ID token validation                    |
| `/userinfo`      | Calls the UserInfo endpoint with the access token        |
| `/raw-token`     | Raw ID token for inspection (lab only)                   |
| `/logout`        | Local session clear plus RP-initiated IdP logout         |
| `/healthz`       | Liveness probe                                           |

## Running it

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

    cp .env.example .env      # then fill in from your Verify tenant
    python app.py

Open http://127.0.0.1:8000

Port 8000 rather than Flask's default 5000: on macOS, port 5000 is held by
the AirPlay Receiver service.

## Not production code

Flask's development server, `debug=True`, and `/raw-token` are lab
affordances. A production deployment would run under a WSGI server behind
TLS, with `SESSION_COOKIE_SECURE` enabled, generic error pages, and no
token ever rendered to a page.
