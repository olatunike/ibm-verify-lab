"""
IBM Verify Lab — an OpenID Connect relying party (RP).

A "relying party" is the application that RELIES ON an identity
provider to authenticate users. IBM Verify is the identity provider
(the OP, or OpenID Provider). This app is the RP.
"""

import os

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


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True)