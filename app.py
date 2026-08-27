"""
IBM Verify Lab — an OpenID Connect relying party (RP).

A "relying party" is the application that RELIES ON an identity
provider to authenticate users. IBM Verify is the identity provider
(the OP, or OpenID Provider). This app is the RP.
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

# ---------------------------------------------------------------
# Read the .env file into the process environment.
# ---------------------------------------------------------------
load_dotenv()


def required_env(name: str) -> str:
    """Read an environment variable, refusing to continue if it's absent."""
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

SCOPES = "openid profile email"

app = Flask(__name__)
app.secret_key = required_env("FLASK_SECRET_KEY")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


@app.route("/")
def home():
    return f"""
    <h1>IBM Verify Lab</h1>
    <p>Relying party for tenant <code>{os.environ.get('VERIFY_TENANT')}</code></p>
    <p>
      <a href="{url_for('login_preview')}">Inspect the authorization request</a> &nbsp;|&nbsp;
      <a href="{url_for('login')}">Sign in with IBM Verify</a>
    </p>
    <p>
      <a href="/config">Tenant configuration</a> &nbsp;|&nbsp;
      <a href="/pkce-demo">PKCE demo</a>
    </p>
    """
# ---------------------------------------------------------------
# OIDC discovery — read the tenant's configuration from Verify
# ---------------------------------------------------------------

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
    """Cached client for the tenant's PUBLIC token-signing keys."""
    global _jwks_cache
    if _jwks_cache is None:
        _jwks_cache = jwt.PyJWKClient(oidc_config()["jwks_uri"])
    return _jwks_cache


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
        "token_endpoint_auth_methods_supported",
        "id_token_signing_alg_values_supported",
        "code_challenge_methods_supported",
    ]

    rows = ""
    for key in interesting:
        value = config.get(key, "(not advertised)")
        rows += f"<tr><td><code>{key}</code></td><td><code>{value}</code></td></tr>"

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
# ---------------------------------------------------------------
# PKCE — RFC 7636. Required: your app has PKCE enabled in Verify.
# ---------------------------------------------------------------


def _b64url(raw: bytes) -> str:
    """Base64url-encode with padding stripped, as the OAuth specs require."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def make_pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge)."""
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


@app.route("/pkce-demo")
def pkce_demo():
    """Lab route: generate a pair and prove the hash relationship."""
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


# ---------------------------------------------------------------
# Authorization request - step 1 of the code flow
# ---------------------------------------------------------------


def build_auth_request() -> tuple[str, dict]:
    """Build the authorization request; stash its secrets in the session."""
    config = oidc_config()

    verifier, challenge = make_pkce_pair()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    session["pkce_verifier"] = verifier
    session["oidc_state"] = state
    session["oidc_nonce"] = nonce

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "scope": SCOPES,
        "redirect_uri": REDIRECT_URI,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }

    url = f"{config['authorization_endpoint']}?{urlencode(params)}"
    return url, params


@app.route("/login-preview")
def login_preview():
    """Lab route: show the authorization request before sending it."""
    url, params = build_auth_request()

    rows = ""
    for key, value in params.items():
        rows += f"<tr><td><code>{key}</code></td><td><code>{value}</code></td></tr>"

    return f"""
    <h1>Authorization request</h1>
    <p>What your browser is about to send to IBM Verify.</p>
    <table border="1" cellpadding="6" cellspacing="0">{rows}</table>
    <h3>Full URL</h3>
    <p style="word-break:break-all"><code>{url}</code></p>
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
    """Placeholder - Block 5 implements the token exchange."""
    rows = ""
    for k, v in request.args.items():
        rows += f"<tr><td><code>{k}</code></td><td><code>{v[:60]}...</code></td></tr>"

    return f"""
    <h1>Callback reached</h1>
    <p>IBM Verify redirected here. Raw query parameters:</p>
    <table border="1" cellpadding="6" cellspacing="0">{rows}</table>
    <p>Block 5 will exchange this code for tokens.</p>
    <p><a href="/">Back</a></p>
    """
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True)