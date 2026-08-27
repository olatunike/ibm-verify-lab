"""
IBM Verify Lab — an OpenID Connect relying party (RP).

A "relying party" is the application that RELIES ON an identity
provider to authenticate users. IBM Verify is the identity provider
(the OP, or OpenID Provider). This app is the RP.
"""

import os

import jwt
import requests
from dotenv import load_dotenv
from flask import Flask

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
    return f"<h1>IBM Verify Lab</h1><p>Config loaded. Client ID ends in: <code>...{CLIENT_ID[-6:]}</code></p>"

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
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True)