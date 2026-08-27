"""
IBM Verify Lab — an OpenID Connect relying party (RP).

A "relying party" is the application that RELIES ON an identity
provider to authenticate users. IBM Verify is the identity provider
(the OP, or OpenID Provider). This app is the RP.

This app is an INSTRUMENT: it makes IBM Verify's behaviour visible.
Change a setting in the Verify console, sign in again, and see
exactly what changed in the token.

Run:
    source .venv/bin/activate
    python app.py
Then open http://127.0.0.1:8000
"""

import base64
import hashlib
import html
import json
import os
import secrets
from urllib.parse import urlencode

import jwt
import requests
from dotenv import load_dotenv
from flask import Flask, redirect, request, session, url_for

# =====================================================================
# 1. CONFIGURATION
# =====================================================================
# Read the .env file into the process environment, so secrets never
# appear in source code and .env stays git-ignored.
load_dotenv()


def required_env(name: str) -> str:
    """Read an environment variable, refusing to continue if it's absent.

    Fail-fast: a misconfigured app should refuse to start rather than
    run in a half-configured state and fail confusingly later.
    """
    value = os.environ.get(name)
    if not value or value.startswith("paste_") or value.startswith("change_me"):
        raise RuntimeError(
            f"Environment variable {name} is missing or still a placeholder. "
            f"Check your .env file."
        )
    return value


DISCOVERY_URL = required_env("VERIFY_DISCOVERY_URL")
CLIENT_ID = required_env("VERIFY_CLIENT_ID")
CLIENT_SECRET = required_env("VERIFY_CLIENT_SECRET")
REDIRECT_URI = required_env("VERIFY_REDIRECT_URI")

# This tenant advertises: openid, profile, email, phone.
# Request only what the application needs (data minimisation).
SCOPES = "openid profile email"

app = Flask(__name__)

# Flask signs the session cookie with this key. That signature is what
# makes the state / nonce / PKCE checks below trustworthy — without it
# a user could edit their own session.
app.secret_key = required_env("FLASK_SECRET_KEY")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,    # JavaScript cannot read it (XSS defence)
    SESSION_COOKIE_SAMESITE="Lax",   # not sent on cross-site POSTs (CSRF defence)
    # SESSION_COOKIE_SECURE=True,    # required in production (HTTPS only)
)


# =====================================================================
# 2. OIDC DISCOVERY AND JWKS
# =====================================================================
# Never hard-code endpoint URLs. Read them from the provider's
# discovery document. On this tenant the issuer path (/oidc/) differs
# from the endpoint path (/v1.0/) — constructing URLs by hand would
# break every token validation.

_discovery_cache = None
_jwks_cache = None


def oidc_config() -> dict:
    """Fetch and cache the tenant's OIDC discovery document."""
    global _discovery_cache
    if _discovery_cache is None:
        response = requests.get(DISCOVERY_URL, timeout=10)
        response.raise_for_status()
        _discovery_cache = response.json()
    return _discovery_cache


def jwks_client() -> jwt.PyJWKClient:
    """Cached client for the tenant's PUBLIC token-signing keys.

    JWKS = JSON Web Key Set. Public keys only. Resolving keys by their
    `kid` at validation time is what lets IBM rotate signing keys
    without every relying party redeploying.
    """
    global _jwks_cache
    if _jwks_cache is None:
        _jwks_cache = jwt.PyJWKClient(oidc_config()["jwks_uri"])
    return _jwks_cache


# =====================================================================
# 3. PKCE — RFC 7636
# =====================================================================
# Required: this application has "Require proof key for code exchange
# (PKCE) verification" enabled on its Verify Sign-on tab.


def _b64url(raw: bytes) -> str:
    """Base64url-encode with padding stripped, as the OAuth specs require."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def make_pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge).

    verifier  — high-entropy secret kept in the session, sent only at
                token redemption
    challenge — SHA-256 of the verifier, sent up front to Verify

    Hashing is one-way, so an attacker who intercepts the challenge
    cannot derive the verifier, and a stolen code cannot be redeemed.
    """
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


# =====================================================================
# 4. AUTHORIZATION REQUEST — step 1 of the code flow
# =====================================================================


def build_auth_request() -> tuple[str, dict]:
    """Build the authorization request; stash its secrets in the session.

    Three one-time random values, each defending a different attack:
      verifier — code interception (PKCE)
      state    — login CSRF
      nonce    — token replay
    """
    config = oidc_config()

    verifier, challenge = make_pkce_pair()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    session["pkce_verifier"] = verifier
    session["oidc_state"] = state
    session["oidc_nonce"] = nonce

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",          # code flow, not implicit
        "scope": SCOPES,
        "redirect_uri": REDIRECT_URI,     # exact-match against Verify
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",  # never "plain"
    }

    url = f"{config['authorization_endpoint']}?{urlencode(params)}"
    return url, params


# =====================================================================
# 5. ROUTES
# =====================================================================


@app.route("/")
def home():
    """Landing page: sign-in prompt, or the signed-in user's claims."""
    claims = session.get("claims")

    if not claims:
        return f"""
        <h1>IBM Verify Lab</h1>
        <p>Relying party for tenant <code>{os.environ.get('VERIFY_TENANT')}</code></p>
        <p>Not signed in.</p>
        <p>
          <a href="{url_for('login_preview')}">Inspect the authorization request</a> &nbsp;|&nbsp;
          <a href="{url_for('login')}">Sign in with IBM Verify</a>
        </p>
        <p>
          <a href="/config">Tenant configuration</a> &nbsp;|&nbsp;
          <a href="/pkce-demo">PKCE demo</a>
        </p>
        """

    # amr is specified as an array, but some providers return a bare
    # string when only one method was used. Defend against both.
    amr = claims.get("amr", [])
    if isinstance(amr, str):
        amr = [amr]
    factor_note = "MULTIPLE FACTORS" if len(amr) > 1 else "SINGLE FACTOR"

    # groupIds, not groups — IBM Verify names the group claim this way.
    # Confirmed from claims_supported in the discovery document.
    interesting = [
        ("sub", claims.get("sub")),
        ("name", claims.get("name")),
        ("preferred_username", claims.get("preferred_username")),
        ("email", claims.get("email")),
        ("groupIds", claims.get("groupIds", "(not released)")),
        ("department", claims.get("department", "(not released)")),
        ("job_title", claims.get("job_title", "(not released)")),
        ("amr", f"{amr} -- {factor_note}"),
        ("acr", claims.get("acr", "(none)")),
        ("iss", claims.get("iss")),
        ("aud", claims.get("aud")),
    ]

    rows = ""
    for label, value in interesting:
        rows += f"<tr><th>{label}</th><td><code>{html.escape(str(value))}</code></td></tr>"

    # Claims are external data. Escape before rendering — an IdP
    # validating a token correctly does not make the claims inside it
    # safe to inject into a page.
    dump = html.escape(json.dumps(claims, indent=2, sort_keys=True))

    return f"""
    <h1>Signed in</h1>
    <p>Claims below came from a signature-verified ID token.</p>
    <table border="1" cellpadding="6" cellspacing="0">{rows}</table>

    <h2>Full ID token payload</h2>
    <pre>{dump}</pre>

    <p>
      <a href="{url_for('userinfo')}">Call /userinfo</a> &nbsp;|&nbsp;
      <a href="{url_for('raw_token')}">Raw ID token</a> &nbsp;|&nbsp;
      <a href="/config">Tenant configuration</a> &nbsp;|&nbsp;
      <a href="{url_for('logout')}">Sign out</a>
    </p>
    """


@app.route("/config")
def show_config():
    """Inspect what this Verify tenant supports."""
    config = oidc_config()

    interesting = [
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "jwks_uri",
        "end_session_endpoint",
        "grant_types_supported",
        "scopes_supported",
        "claims_supported",
        "token_endpoint_auth_methods_supported",
        "id_token_signing_alg_values_supported",
        "code_challenge_methods_supported",
    ]

    rows = ""
    for key in interesting:
        value = config.get(key, "(not advertised)")
        rows += f"<tr><td><code>{key}</code></td><td><code>{html.escape(str(value))}</code></td></tr>"

    keys = requests.get(config["jwks_uri"], timeout=10).json().get("keys", [])
    key_rows = ""
    for k in keys:
        key_rows += (
            f"<tr><td><code>{k.get('kid')}</code></td>"
            f"<td><code>{k.get('kty')}</code></td>"
            f"<td><code>{k.get('alg', '-')}</code></td>"
            f"<td><code>{k.get('use', '-')}</code></td></tr>"
        )

    return f"""
    <h1>Tenant OIDC configuration</h1>
    <p>Read live from <code>{DISCOVERY_URL}</code></p>
    <table border="1" cellpadding="6" cellspacing="0">{rows}</table>

    <h2>Signing keys (JWKS)</h2>
    <p>{len(keys)} public key(s) published by this tenant.</p>
    <table border="1" cellpadding="6" cellspacing="0">
      <tr><th>kid</th><th>kty</th><th>alg</th><th>use</th></tr>
      {key_rows}
    </table>
    <p><a href="/">Back</a></p>
    """


@app.route("/pkce-demo")
def pkce_demo():
    """Lab route: generate a PKCE pair and prove the hash relationship."""
    verifier, challenge = make_pkce_pair()
    recomputed = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    matches = "YES" if recomputed == challenge else "NO"

    return f"""
    <h1>PKCE pair</h1>
    <table border="1" cellpadding="8" cellspacing="0">
      <tr><th>code_verifier</th><td><code>{verifier}</code></td></tr>
      <tr><th>length</th><td>{len(verifier)} chars (spec requires 43-128)</td></tr>
      <tr><th>code_challenge</th><td><code>{challenge}</code></td></tr>
      <tr><th>method</th><td><code>S256</code></td></tr>
      <tr><th>Challenge recomputes from verifier?</th><td><b>{matches}</b></td></tr>
    </table>
    <p>Reload for a fresh pair - every login attempt gets its own.</p>
    <p><a href="/">Back</a></p>
    """


@app.route("/login-preview")
def login_preview():
    """Lab route: show the authorization request before sending it."""
    url, params = build_auth_request()

    rows = ""
    for key, value in params.items():
        rows += f"<tr><td><code>{key}</code></td><td><code>{html.escape(str(value))}</code></td></tr>"

    return f"""
    <h1>Authorization request</h1>
    <p>What your browser is about to send to IBM Verify.</p>
    <table border="1" cellpadding="6" cellspacing="0">{rows}</table>
    <h3>Full URL</h3>
    <p style="word-break:break-all"><code>{html.escape(url)}</code></p>
    <p><a href="{url}">Continue to IBM Verify &rarr;</a></p>
    <p><a href="/">Back</a></p>
    """


@app.route("/login")
def login():
    """Redirect the browser to IBM Verify to authenticate."""
    url, _ = build_auth_request()
    return redirect(url)


@app.route("/callback")
def callback():
    """Step 2 of the code flow: redeem the code, validate the ID token.

    Order matters: the cheap local checks (error, state) run BEFORE any
    network call. A request that will be rejected should never cost an
    outbound HTTP round trip.
    """
    # -----------------------------------------------------------------
    # 5a. Did IBM Verify report a problem instead of returning a code?
    # -----------------------------------------------------------------
    # Verify signals failure by redirecting here with ?error=...
    # An access policy denial, a declined consent, or a misconfigured
    # client all arrive this way.
    if "error" in request.args:
        return f"""<h1>IBM Verify returned an error</h1>
          <pre>error: {html.escape(request.args.get('error', ''))}
description: {html.escape(request.args.get('error_description', '(none)'))}</pre>
          <p><a href="/">Back</a></p>""", 400

    # -----------------------------------------------------------------
    # 5b. Validate `state` — the login-CSRF defence
    # -----------------------------------------------------------------
    # pop() reads AND removes, so a given state can never be accepted
    # twice: single-use by construction rather than by convention.
    expected_state = session.pop("oidc_state", None)
    if not expected_state or request.args.get("state") != expected_state:
        return """<h1>State mismatch - request rejected</h1>
          <p>The state returned by IBM Verify did not match this session's
          value. This is the defence against login CSRF.</p>
          <p><a href="/">Back</a></p>""", 403

    code = request.args.get("code")
    if not code:
        return "<h1>No authorization code returned</h1>", 400

    verifier = session.pop("pkce_verifier", None)
    expected_nonce = session.pop("oidc_nonce", None)

    # Only now do we touch the network.
    config = oidc_config()

    # -----------------------------------------------------------------
    # 5c. Redeem the code — BACK CHANNEL, server to server
    # -----------------------------------------------------------------
    # The browser is not involved here and never sees the client secret
    # or the tokens. That separation is why the code flow is preferred
    # over implicit.
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,   # re-sent so Verify re-checks it
        "code_verifier": verifier,      # the PKCE proof
    }

    # This tenant advertises client_secret_basic, so credentials go in
    # the HTTP Authorization header rather than the form body.
    token_response = requests.post(
        config["token_endpoint"],
        data=payload,
        auth=(CLIENT_ID, CLIENT_SECRET),
        timeout=15,     # never leave an outbound call unbounded
    )

    if token_response.status_code != 200:
        return f"""<h1>Token exchange failed</h1>
          <p>HTTP {token_response.status_code}</p>
          <pre>{html.escape(token_response.text)}</pre>
          <p><a href="/">Back</a></p>""", 400

    tokens = token_response.json()
    id_token = tokens.get("id_token")
    if not id_token:
        return (
            f"<h1>No ID token</h1><pre>{html.escape(json.dumps(tokens, indent=2))}</pre>",
            400,
        )

    # -----------------------------------------------------------------
    # 5d. Validate the ID token — the security core of this file
    # -----------------------------------------------------------------
    # An unverified JWT is just a string an attacker could have typed.
    try:
        # Reads `kid` from the token header, fetches the matching PUBLIC
        # key from the tenant's JWKS.
        signing_key = jwks_client().get_signing_key_from_jwt(id_token)

        claims = jwt.decode(
            id_token,
            signing_key.key,
            # PINNED. This tenant advertises 'none' and the HMAC family
            # in id_token_signing_alg_values_supported. Trusting that
            # list would allow unsigned tokens and RS256->HS256
            # algorithm-confusion attacks.
            algorithms=["RS256"],
            # Minted for US, not for some other application.
            audience=CLIENT_ID,
            # From discovery. On this tenant the issuer uses /oidc/
            # while the endpoints use /v1.0/ — never build it by hand.
            issuer=config["issuer"],
        )
    except Exception as exc:
        # Broad catch is deliberate in a lab: PyJWT raises several
        # distinct exceptions and we want to see which one.
        # In production: log this, show the user something generic.
        return f"""<h1>ID token validation failed</h1>
          <pre>{html.escape(f'{type(exc).__name__}: {exc}')}</pre>
          <p><a href="/">Back</a></p>""", 403

    # -----------------------------------------------------------------
    # 5e. Check the nonce — the token-replay defence
    # -----------------------------------------------------------------
    # state protects the REQUEST; nonce protects the TOKEN.
    if expected_nonce and claims.get("nonce") != expected_nonce:
        return """<h1>Nonce mismatch - token rejected</h1>
          <p>The nonce in the ID token did not match this login attempt.</p>
          <p><a href="/">Back</a></p>""", 403

    # -----------------------------------------------------------------
    # 5f. Only now is a session established — fail-closed by design
    # -----------------------------------------------------------------
    session["claims"] = claims
    session["access_token"] = tokens.get("access_token")
    session["id_token"] = id_token

    return redirect(url_for("home"))


@app.route("/userinfo")
def userinfo():
    """Call the UserInfo endpoint with the access token.

    Shows the difference between the two tokens:
      ID token     — proves WHO the user is, consumed by THIS app
      access token — a key to call an API, consumed by a RESOURCE server
    """
    access_token = session.get("access_token")
    if not access_token:
        return redirect(url_for("home"))

    response = requests.get(
        oidc_config()["userinfo_endpoint"],
        # "Bearer" means: whoever bears this token may use it. No
        # further proof required — hence short lifetimes and TLS only.
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=15,
    )
    try:
        pretty = json.dumps(response.json(), indent=2, sort_keys=True)
    except ValueError:
        pretty = response.text

    return f"""
    <h1>UserInfo endpoint</h1>
    <p>Called with the access token as a Bearer credential. HTTP {response.status_code}</p>
    <pre>{html.escape(pretty)}</pre>
    <p><a href="/">Back</a></p>
    """


@app.route("/raw-token")
def raw_token():
    """Lab only: show the raw ID token for inspection at jwt.io."""
    id_token = session.get("id_token")
    if not id_token:
        return redirect(url_for("home"))

    return f"""
    <h1>Raw ID token</h1>
    <p><b>Lab use only.</b> Production apps never render tokens to a page.
       Paste this at <a href="https://jwt.io" target="_blank">jwt.io</a> to see
       header, payload and signature.</p>
    <pre style="white-space:pre-wrap;word-break:break-all">{html.escape(id_token)}</pre>
    <p><a href="/">Back</a></p>
    """


@app.route("/logout")
def logout():
    """Clear the local session, then end the SSO session at IBM Verify.

    Two sessions always exist in SSO: the application's, and the
    identity provider's. Clearing only the first means the next login
    succeeds silently, which users experience as "logout didn't work".
    """
    id_token = session.get("id_token")
    session.clear()

    end_session = oidc_config().get("end_session_endpoint")
    if end_session and id_token:
        params = {
            "id_token_hint": id_token,                        # which session to end
            "post_logout_redirect_uri": "http://localhost:8000/",
        }
        return redirect(f"{end_session}?{urlencode(params)}")

    return redirect(url_for("home"))


@app.route("/healthz")
def health():
    """Liveness probe — what a load balancer or monitor would call."""
    return {"status": "ok"}


# =====================================================================
# 6. ENTRY POINT
# =====================================================================
if __name__ == "__main__":
    # Port 8000: on macOS, 5000 is held by AirPlay Receiver.
    # host 127.0.0.1: reachable only from this machine.
    # debug=True: auto-reload + tracebacks. NEVER in production —
    # the Werkzeug debugger is remote code execution if exposed.
    app.run(host="127.0.0.1", port=8000, debug=True)