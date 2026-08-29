# ibm-verify-lab

An end-to-end **IBM Verify** integration: a live SaaS tenant driving a purpose-built
OpenID Connect relying party, plus **JavaScript mapping rules and a custom
authentication module** written for IBM Verify Identity Access (on-premises).

Two halves, deliberately:

| | |
|---|---|
| **`app.py`** | An OIDC relying party built to make the identity provider's behaviour *observable*. Change a setting in the Verify console, sign in again, see exactly what changed in the token. |
| **`verify-identity-access/`** | Mapping rules and an InfoMap authentication module — the on-premises product's imperative equivalent of the SaaS console, with a local test harness and 26 passing tests. |

---

## Evidence

The point of building the relying party was to be able to *prove* what a
console change does. Two sign-ins, same code, no redeploy:

| Claim | Before the policy | After the policy |
|---|---|---|
| `acr` | `urn:ibm:security:policy:id:1` — the tenant default | `urn:ibm:security:policy:id:1567828` — **a policy I wrote** |
| `amr` | `[]` — single factor | `['totp', '2fa']` — **second factor enforced** |
| `groupIds` | not released | `['admin', 'application owners', 'Lab-Admins']` |

The `acr` claim names the access policy that governed the authentication.
That is what makes the change verifiable from the application side rather
than only from the console — and it is what I used to diagnose, from the
token alone, that the policy was published but not yet attached.

---

## IBM Verify SaaS — what was configured

**Application onboarding** — a custom OIDC application: grant types, exact-match
redirect URI registration, client authentication method, PKCE enforcement,
token lifetimes, signing algorithm.

**Three gates, kept distinct.** Authentication, entitlement, and access policy
are separate decisions in Verify and fail with different signals:

| Gate | Question | Failure |
|---|---|---|
| Authentication | Who are you? | `CSIAH0303E` |
| Entitlement | May you use this application at all? | `CSIAQ0279E` |
| Access policy | Under what conditions? | `access_denied`, or an MFA challenge |

**Directory** — Cloud Directory users and groups, plus a custom attribute
added to the tenant schema.

**Outbound attribute mapping** — releasing selected directory attributes as
token claims, per application, rather than releasing everything Verify holds.

**Access policy** — a federated sign-on policy, `MFA always`, with the
acceptable factors named explicitly (TOTP, IBM Verify app) rather than
accepting any enrolled method. Published through the draft/publish
lifecycle, then attached to the application.

**Identity providers** — Cloud Directory and IBMid federation. Every identity
in this tenant is federated through IBMid: Verify holds profile, groups and
attributes for authorization while the credential lives at the external
provider, which is why password reset is unavailable for these accounts and
why the second factor had to be enforced by Verify rather than inherited
from the upstream provider.

---

## Security notes

**The signing algorithm is pinned, not negotiated.**

This tenant's discovery document advertises RS256 through RS512, the PS and
ES families, HS256 through HS512, and **`none`**.

That list is a *capability* statement, not a policy. Passing it to a JWT
validator would accept unsigned tokens (`alg: none`) and enable RS256→HS256
algorithm confusion, where a forged token is signed with the provider's own
published public key used as an HMAC secret.

```python
algorithms=["RS256"]     # pinned. never read from discovery or the token header.
```

**Endpoints are read from discovery, never constructed.**

On this tenant the issuer path and the endpoint path differ — the issuer sits
under `/oidc/endpoint/default` while authorization and token sit under
`/v1.0/endpoint/default`. Building the issuer by hand fails every validation.

**Signing keys are resolved by `kid` at validation time**, not pinned, so
provider key rotation requires no change here.

**Secrets never enter source control.** `.env` is git-ignored from the first
commit; `.env.example` documents the contract. The full history was audited
for committed credentials before the repository was made public.

---

## Verify Identity Access — mapping rules

`verify-identity-access/` holds JavaScript that runs inside the on-premises
product, with a shim that executes it locally.

```
node verify-identity-access/test/run-tests.js
26 passed, 0 failed
```

A declarative attribute-mapping table can only release attributes already
stored on the user. It cannot compute a value from several inputs, apply
precedence between sources, or refuse to emit a privileged claim when the
authentication was weak. Those are the cases these rules cover:

| Rule | Does |
|---|---|
| `oidc-idtoken-claims.js` | Controlled claim release — only what the release policy names |
| `oidc-pretoken-derived.js` | Derives clearance from group membership with precedence, then **downscopes it when the session carried no second factor** |
| `infomap-stepup-clearance.js` | Custom authentication module: fail-closed, no user-enumeration oracle, refuses ambiguous email aliases, requires step-up before privilege |

See [`verify-identity-access/README.md`](verify-identity-access/README.md).

---

## Application routes

| Route | Purpose |
|---|---|
| `/` | Sign-in prompt, or the signed-in user's claims |
| `/config` | Live view of the tenant's OIDC capabilities and JWKS |
| `/pkce-demo` | Generates a PKCE pair and verifies the hash relationship |
| `/login-preview` | Shows the authorization request before it is sent |
| `/login` | Redirects to IBM Verify |
| `/callback` | Code exchange and ID token validation |
| `/userinfo` | Calls the UserInfo endpoint with the access token |
| `/raw-token` | Raw ID token for inspection (lab only) |
| `/logout` | Local session clear plus RP-initiated IdP logout |
| `/healthz` | Liveness probe |

The relying party implements the authorization code flow with PKCE (S256),
`state` for login-CSRF defence, `nonce` for token replay defence,
back-channel token exchange with `client_secret_basic`, ID token validation
against the tenant JWKS, and RP-initiated logout with `id_token_hint`.

---

## Running it

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env      # fill in from your Verify tenant
python app.py
```

Open <http://127.0.0.1:8000>

Port 8000 rather than Flask's default 5000: on macOS, port 5000 is held by
the AirPlay Receiver service.

---

## Scope

Flask's development server, `debug=True`, and `/raw-token` are lab
affordances. A production deployment would run under a WSGI server behind
TLS, with `SESSION_COOKIE_SECURE` enabled, generic error pages, and no token
rendered to a page.

The Verify Identity Access rules are written against IBM's documented
mapping-rule API and unit-tested against the local shim. They have not been
deployed to a physical appliance — the tenant available for this work is
Verify SaaS, which does not expose the STS chain. What is verified is the
rule logic and its security properties.
